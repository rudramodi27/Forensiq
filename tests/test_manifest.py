"""
Integration tests — forensiq.core.manifest_service (Phase 4: Case Evidence
Manifest) and its integration points in reporter.py.

Covers:
  - all required manifest fields present per item
  - multiple devices, multiple acquisition sessions resolved correctly
    (Case -> Device -> Acquisition Session -> Evidence)
  - integrity statuses (MATCH / MISMATCH / NOT_VERIFIED) never
    misreported — an item is never MATCH unless actually verified
  - legacy evidence with no device/session is flagged, never invented
  - JSON export
  - CSV export
  - PDF report includes a Case Evidence Manifest section
  - standalone Case Evidence Manifest HTML report
  - empty case (no evidence at all)
"""

import csv
import json
import os

import pytest

from forensiq.core.case_manager import CaseManager
from forensiq.core.hasher import sha256_file
from forensiq.core.integrity_engine import IntegrityEngine, MATCH, MISMATCH, NOT_VERIFIED
from forensiq.core.manifest_service import (
    build_manifest,
    export_manifest_json,
    export_manifest_csv,
    CSV_COLUMNS,
)
from forensiq.core.reporter import (
    generate_case_evidence_manifest_report,
    generate_pdf_report,
)


class _FakeDevice:
    def __init__(self, serial="DEV001", model="Pixel 7", manufacturer="Google",
                 android_version="13", sdk_version="33", build_number="TQ3A",
                 cpu_abi="arm64-v8a", usb_debugging=True):
        self.serial = serial
        self.model = model
        self.manufacturer = manufacturer
        self.android_version = android_version
        self.sdk_version = sdk_version
        self.build_number = build_number
        self.cpu_abi = cpu_abi
        self.usb_debugging = usb_debugging


REQUIRED_ITEM_KEYS = {
    "case_id", "case_number", "evidence_id", "filename", "category",
    "file_size", "recorded_sha256", "acquired_at", "device_serial",
    "session_id", "collector", "storage_location", "integrity_status",
    "verified_sha256", "last_verified_at",
}


# ── Basic single-item manifest (via `populated` fixture) ───────────────────

class TestManifestBasic:
    def test_build_manifest_returns_all_items(self, populated):
        m = build_manifest(populated.cid, populated.db)
        assert m["total_items"] == 3  # eid_pass, eid_fail, eid_null

    def test_case_fields_present(self, populated):
        m = build_manifest(populated.cid, populated.db)
        assert m["case_id"] == populated.cid
        assert m["case_number"] == "TC-001"
        assert m["case_investigator"] == "Det. Jones"

    def test_required_fields_present_per_item(self, populated):
        m = build_manifest(populated.cid, populated.db)
        for item in m["items"]:
            missing = REQUIRED_ITEM_KEYS - set(item.keys())
            assert not missing, f"Missing fields: {missing}"

    def test_filename_category_size_hash_present(self, populated):
        m = build_manifest(populated.cid, populated.db)
        by_id = {it["evidence_id"]: it for it in m["items"]}
        item = by_id[populated.eid_pass]
        assert item["filename"] == "report.txt"
        assert item["category"] == "acquisition"
        assert item["file_size"] == 44
        assert item["recorded_sha256"] == populated.h_pass

    def test_null_file_size_does_not_crash(self, populated):
        """Regression guard mirroring reporter.py BUG#1 — file_size may be
        NULL for evidence added without a size."""
        m = build_manifest(populated.cid, populated.db)
        by_id = {it["evidence_id"]: it for it in m["items"]}
        assert by_id[populated.eid_null]["file_size"] == 0


# ── Device + Session resolution ─────────────────────────────────────────────

class TestDeviceSessionResolution:
    def test_evidence_resolves_to_its_device(self, populated):
        m = build_manifest(populated.cid, populated.db)
        by_id = {it["evidence_id"]: it for it in m["items"]}
        item = by_id[populated.eid_pass]
        assert item["device_id"] == populated.did
        assert item["device_serial"] == "DEV001"
        assert item["device_model"] == "Pixel 7"

    def test_multiple_devices_resolved_independently(self, db):
        cid = db.create_case("MAN-DEV", "T", "I")
        dev_a = db.add_device(cid, _FakeDevice(serial="A-SER"))
        dev_b = db.add_device(cid, _FakeDevice(serial="B-SER", model="Galaxy S23",
                                                manufacturer="Samsung"))
        e_a = db.add_evidence(cid, dev_a, "Photos", "a.jpg", "/tmp/a.jpg", "hashA", 10)
        e_b = db.add_evidence(cid, dev_b, "Videos", "b.mp4", "/tmp/b.mp4", "hashB", 20)

        m = build_manifest(cid, db)
        by_id = {it["evidence_id"]: it for it in m["items"]}
        assert by_id[e_a]["device_serial"] == "A-SER"
        assert by_id[e_b]["device_serial"] == "B-SER"
        assert by_id[e_b]["device_model"] == "Galaxy S23"
        assert m["devices_referenced"] == 2

    def test_multiple_sessions_same_device_resolved_independently(self, db):
        cid = db.create_case("MAN-SESS", "T", "I")
        did = db.add_device(cid, _FakeDevice())
        s1 = db.start_acquisition_session(cid, did, targets=["Photos"])
        db.end_acquisition_session(s1, status="completed")
        s2 = db.start_acquisition_session(cid, did, targets=["Videos"])
        db.end_acquisition_session(s2, status="completed")

        e1 = db.add_evidence(cid, did, "Photos", "p1.jpg", "/tmp/p1.jpg", "h1", 10,
                              session_id=s1)
        e2 = db.add_evidence(cid, did, "Videos", "v1.mp4", "/tmp/v1.mp4", "h2", 20,
                              session_id=s2)

        m = build_manifest(cid, db)
        by_id = {it["evidence_id"]: it for it in m["items"]}
        assert by_id[e1]["session_id"] == s1
        assert by_id[e2]["session_id"] == s2
        assert by_id[e1]["session_id"] != by_id[e2]["session_id"]
        assert m["sessions_referenced"] == 2
        # Same device throughout — Phase 3 stability guarantee
        assert by_id[e1]["device_id"] == by_id[e2]["device_id"] == did

    def test_legacy_evidence_no_device_no_session(self, db):
        """Evidence added without device_id/session_id (pre-Phase-3 or
        manual import) must be reported as unresolved, never invented."""
        cid = db.create_case("MAN-LEGACY", "T", "I")
        eid = db.add_evidence(cid, None, "Documents", "old.pdf",
                              "/legacy/old.pdf", "deadbeef", 100, session_id=None)

        m = build_manifest(cid, db)
        item = m["items"][0]
        assert item["evidence_id"] == eid
        assert item["device_id"] is None
        assert item["device_serial"] == ""
        assert item["session_id"] is None
        assert item["is_legacy"] is True
        assert m["legacy_items"] == 1

    def test_mixed_legacy_and_tracked_evidence(self, db):
        cid = db.create_case("MAN-MIXED", "T", "I")
        did = db.add_device(cid, _FakeDevice())
        sid = db.start_acquisition_session(cid, did, targets=["Photos"])
        e_tracked = db.add_evidence(cid, did, "Photos", "new.jpg", "/tmp/new.jpg",
                                    "hnew", 10, session_id=sid)
        e_legacy = db.add_evidence(cid, None, "Documents", "old.pdf",
                                   "/legacy/old.pdf", "hold", 5, session_id=None)

        m = build_manifest(cid, db)
        assert m["total_items"] == 2
        assert m["legacy_items"] == 1
        by_id = {it["evidence_id"]: it for it in m["items"]}
        assert by_id[e_tracked]["is_legacy"] is False
        assert by_id[e_legacy]["is_legacy"] is True


# ── Integrity status ─────────────────────────────────────────────────────────

class TestIntegrityStatus:
    def test_never_verified_item_is_not_verified(self, populated):
        m = build_manifest(populated.cid, populated.db)
        by_id = {it["evidence_id"]: it for it in m["items"]}
        # eid_null has never had a verification_results row written
        assert by_id[populated.eid_null]["integrity_status"] == NOT_VERIFIED
        assert by_id[populated.eid_null]["verified_sha256"] == ""

    def test_match_reflects_real_verification(self, populated):
        m = build_manifest(populated.cid, populated.db)
        by_id = {it["evidence_id"]: it for it in m["items"]}
        item = by_id[populated.eid_pass]
        # `populated` fixture writes a legacy "PASS" row — normalize_status
        # must map it to canonical MATCH.
        assert item["integrity_status"] == MATCH
        assert item["verified_sha256"] == populated.h_pass

    def test_mismatch_reflects_real_verification(self, populated):
        m = build_manifest(populated.cid, populated.db)
        by_id = {it["evidence_id"]: it for it in m["items"]}
        item = by_id[populated.eid_fail]
        assert item["integrity_status"] == MISMATCH

    def test_not_verified_never_reported_as_match(self, db, ev_dir):
        """An item with no verification_results row must never be
        reported as MATCH/verified."""
        cid = db.create_case("MAN-NV", "T", "I")
        path = os.path.join(ev_dir, "report.txt")
        h = sha256_file(path)
        eid = db.add_evidence(cid, None, "acquisition", "report.txt", path, h, 44)
        m = build_manifest(cid, db)
        item = m["items"][0]
        assert item["integrity_status"] == NOT_VERIFIED
        assert item["integrity_status"] != MATCH

    def test_live_verification_updates_manifest(self, db, ev_dir):
        """Actually running IntegrityEngine.verify_single must be reflected
        (real re-hash, not a fabricated status)."""
        cid = db.create_case("MAN-LIVE", "T", "I")
        path = os.path.join(ev_dir, "report.txt")
        h = sha256_file(path)
        eid = db.add_evidence(cid, None, "acquisition", "report.txt", path, h, 44)

        engine = IntegrityEngine(db)
        engine.verify_single(eid, case_id=cid)

        m = build_manifest(cid, db)
        item = m["items"][0]
        assert item["integrity_status"] == MATCH
        assert item["verified_sha256"] == h
        assert item["last_verified_at"] != ""

    def test_integrity_counts_aggregate_correctly(self, populated):
        m = build_manifest(populated.cid, populated.db)
        counts = m["integrity_counts"]
        assert counts.get(MATCH, 0) == 1
        assert counts.get(MISMATCH, 0) == 1
        assert counts.get(NOT_VERIFIED, 0) == 1


# ── Collector / Investigator resolution ─────────────────────────────────────

class TestCollector:
    def test_collector_from_custody_event(self, populated):
        """populated fixture logs an ACQUIRED custody event via
        audit.log_evidence_added(..., 'Det. Jones', ...) for eid_pass."""
        m = build_manifest(populated.cid, populated.db)
        by_id = {it["evidence_id"]: it for it in m["items"]}
        item = by_id[populated.eid_pass]
        assert item["collector"] == "Det. Jones"
        assert item["collector_source"] == "custody_event"

    def test_collector_falls_back_to_case_investigator(self, populated):
        """eid_fail has no ACQUIRED custody event — must fall back to the
        case's investigator of record, not be fabricated as blank."""
        m = build_manifest(populated.cid, populated.db)
        by_id = {it["evidence_id"]: it for it in m["items"]}
        item = by_id[populated.eid_fail]
        assert item["collector"] == "Det. Jones"  # case investigator
        assert item["collector_source"] == "case_investigator"


# ── Storage location / recorded hash ────────────────────────────────────────

class TestStorageAndHash:
    def test_storage_location_is_filepath(self, populated):
        m = build_manifest(populated.cid, populated.db)
        by_id = {it["evidence_id"]: it for it in m["items"]}
        item = by_id[populated.eid_pass]
        assert item["storage_location"] == os.path.join(populated.ev_dir, "report.txt")

    def test_recorded_hash_never_overwritten_by_verification(self, populated):
        """Recorded SHA-256 (acquisition-time) must stay distinct from
        verified SHA-256 even after re-verification."""
        m = build_manifest(populated.cid, populated.db)
        by_id = {it["evidence_id"]: it for it in m["items"]}
        item = by_id[populated.eid_fail]
        assert item["recorded_sha256"] == "WRONGHASH" * 4
        assert item["verified_sha256"] != item["recorded_sha256"]


# ── Empty case ────────────────────────────────────────────────────────────────

class TestEmptyCase:
    def test_empty_case_manifest(self, db):
        cid = db.create_case("MAN-EMPTY", "Empty", "I")
        m = build_manifest(cid, db)
        assert m["total_items"] == 0
        assert m["items"] == []
        assert m["legacy_items"] == 0
        assert m["devices_referenced"] == 0
        assert m["sessions_referenced"] == 0

    def test_unknown_case_raises(self, db):
        with pytest.raises(ValueError):
            build_manifest(999999, db)

    def test_empty_case_html_report(self, db, tmp_path):
        cid = db.create_case("MAN-EMPTY-HTML", "Empty", "I")
        p = str(tmp_path / "manifest_empty.html")
        generate_case_evidence_manifest_report(cid, db, p)
        assert os.path.exists(p)
        html = open(p).read()
        assert "No evidence items in this case." in html

    def test_empty_case_pdf_report(self, db, tmp_path):
        cid = db.create_case("MAN-EMPTY-PDF", "Empty", "I")
        p = str(tmp_path / "report_empty.pdf")
        generate_pdf_report(cid, db, p)
        assert os.path.exists(p)
        assert os.path.getsize(p) > 0


# ── JSON export ───────────────────────────────────────────────────────────────

class TestJsonExport:
    def test_export_creates_file(self, populated, tmp_path):
        m = build_manifest(populated.cid, populated.db)
        p = str(tmp_path / "manifest.json")
        export_manifest_json(m, p)
        assert os.path.exists(p)

    def test_export_is_valid_json_with_all_items(self, populated, tmp_path):
        m = build_manifest(populated.cid, populated.db)
        p = str(tmp_path / "manifest.json")
        export_manifest_json(m, p)
        with open(p) as fh:
            data = json.load(fh)
        assert data["case_number"] == "TC-001"
        assert len(data["items"]) == 3

    def test_export_json_matches_manifest_dict(self, populated, tmp_path):
        m = build_manifest(populated.cid, populated.db)
        p = str(tmp_path / "manifest.json")
        export_manifest_json(m, p)
        with open(p) as fh:
            data = json.load(fh)
        assert data["total_items"] == m["total_items"]
        assert data["integrity_counts"] == m["integrity_counts"]


# ── CSV export ────────────────────────────────────────────────────────────────

class TestCsvExport:
    def test_export_creates_file(self, populated, tmp_path):
        m = build_manifest(populated.cid, populated.db)
        p = str(tmp_path / "manifest.csv")
        export_manifest_csv(m, p)
        assert os.path.exists(p)

    def test_csv_header_matches_columns(self, populated, tmp_path):
        m = build_manifest(populated.cid, populated.db)
        p = str(tmp_path / "manifest.csv")
        export_manifest_csv(m, p)
        with open(p, newline="") as fh:
            reader = csv.reader(fh)
            header = next(reader)
        assert header == [label for _, label in CSV_COLUMNS]

    def test_csv_row_count_matches_items(self, populated, tmp_path):
        m = build_manifest(populated.cid, populated.db)
        p = str(tmp_path / "manifest.csv")
        export_manifest_csv(m, p)
        with open(p, newline="") as fh:
            reader = csv.DictReader(fh)
            rows = list(reader)
        assert len(rows) == 3

    def test_csv_contains_expected_values(self, populated, tmp_path):
        m = build_manifest(populated.cid, populated.db)
        p = str(tmp_path / "manifest.csv")
        export_manifest_csv(m, p)
        with open(p, newline="") as fh:
            reader = csv.DictReader(fh)
            rows = {r["Evidence ID"]: r for r in reader}
        row = rows[str(populated.eid_pass)]
        assert row["Filename"] == "report.txt"
        assert row["Integrity Status"] == MATCH
        assert row["SHA-256 (Recorded)"] == populated.h_pass

    def test_csv_empty_case_has_header_only(self, db, tmp_path):
        cid = db.create_case("MAN-CSV-EMPTY", "Empty", "I")
        m = build_manifest(cid, db)
        p = str(tmp_path / "manifest_empty.csv")
        export_manifest_csv(m, p)
        with open(p, newline="") as fh:
            rows = list(csv.reader(fh))
        assert len(rows) == 1  # header only


# ── PDF report integration ──────────────────────────────────────────────────

class TestPdfManifestSection:
    def test_pdf_report_includes_manifest_section(self, populated, tmp_path):
        p = str(tmp_path / "report.pdf")
        generate_pdf_report(populated.cid, populated.db, p)
        assert os.path.exists(p)
        assert os.path.getsize(p) > 0

    def test_pdf_report_still_has_original_sections(self, populated, tmp_path):
        """Adding the manifest section must not remove/break any existing
        PDF report content (Phase 1-3 regression guard)."""
        p = str(tmp_path / "report.pdf")
        generate_pdf_report(populated.cid, populated.db, p)
        # Basic sanity: file is a real PDF of plausible size (not truncated
        # by an exception mid-build).
        with open(p, "rb") as fh:
            header = fh.read(5)
        assert header == b"%PDF-"
        assert os.path.getsize(p) > 2000


# ── Standalone HTML manifest report ─────────────────────────────────────────

class TestManifestHtmlReport:
    def test_creates_file(self, populated, tmp_path):
        p = str(tmp_path / "manifest.html")
        generate_case_evidence_manifest_report(populated.cid, populated.db, p)
        assert os.path.exists(p)

    def test_contains_case_number(self, populated, tmp_path):
        p = str(tmp_path / "manifest.html")
        generate_case_evidence_manifest_report(populated.cid, populated.db, p)
        html = open(p).read()
        assert "TC-001" in html

    def test_contains_all_evidence_filenames(self, populated, tmp_path):
        p = str(tmp_path / "manifest.html")
        generate_case_evidence_manifest_report(populated.cid, populated.db, p)
        html = open(p).read()
        assert "report.txt" in html
        assert "malware.apk" in html
        assert "messages.db" in html

    def test_contains_integrity_statuses(self, populated, tmp_path):
        p = str(tmp_path / "manifest.html")
        generate_case_evidence_manifest_report(populated.cid, populated.db, p)
        html = open(p).read()
        assert MATCH in html
        assert MISMATCH in html
        assert NOT_VERIFIED in html

    def test_legacy_note_shown_when_legacy_items_exist(self, db, tmp_path):
        cid = db.create_case("MAN-HTML-LEGACY", "T", "I")
        db.add_evidence(cid, None, "Documents", "old.pdf", "/legacy/old.pdf",
                        "deadbeef", 100, session_id=None)
        p = str(tmp_path / "manifest_legacy.html")
        generate_case_evidence_manifest_report(cid, db, p)
        html = open(p).read()
        assert "legacy" in html.lower()

    def test_unknown_case_raises(self, db, tmp_path):
        p = str(tmp_path / "manifest_bad.html")
        with pytest.raises(ValueError):
            generate_case_evidence_manifest_report(999999, db, p)


# ── No duplication / reuse guarantee ────────────────────────────────────────

class TestNoDuplication:
    def test_manifest_does_not_create_evidence_rows(self, populated):
        """Building (and exporting) a manifest must never write new
        evidence records — it is a read-only, generated view."""
        before = populated.db.get_evidence_count(populated.cid)
        build_manifest(populated.cid, populated.db)
        after = populated.db.get_evidence_count(populated.cid)
        assert before == after

    def test_manifest_reflects_live_evidence_table(self, db):
        """The manifest is generated fresh from `evidence` each call, not
        cached/duplicated — adding evidence after one build() call must
        show up in the next."""
        cid = db.create_case("MAN-LIVE-REFLECT", "T", "I")
        m1 = build_manifest(cid, db)
        assert m1["total_items"] == 0
        db.add_evidence(cid, None, "Photos", "new.jpg", "/tmp/new.jpg", "h", 10)
        m2 = build_manifest(cid, db)
        assert m2["total_items"] == 1
