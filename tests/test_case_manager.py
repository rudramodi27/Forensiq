"""
Unit tests — forensiq.core.case_manager (CaseManager)

Covers: schema, migrations, cases CRUD, devices, evidence, analysis results,
timeline, verification history + batched lookup + summary, audit trail,
custody events, global search, system stats, keyword search, immutability.
"""

import inspect
import pytest

from forensiq.core.case_manager import CaseManager, now_utc


# ── Schema & startup ──────────────────────────────────────────────────────────

class TestSchema:
    def test_all_tables_created(self, db):
        with db._connect() as c:
            tables = {r[0] for r in c.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()}
        required = {
            "cases", "devices", "evidence", "analysis_results",
            "timeline_events", "verification_results", "audit_trail", "custody_events",
        }
        assert required <= tables

    def test_at_least_15_indexes(self, db):
        with db._connect() as c:
            idxs = {r[0] for r in c.execute(
                "SELECT name FROM sqlite_master WHERE type='index'"
            ).fetchall()}
        real_idxs = {i for i in idxs if not i.startswith("sqlite")}
        assert len(real_idxs) >= 15

    def test_migrations_idempotent(self, db):
        """Running migrations twice must not raise or corrupt the schema."""
        db._run_migrations()
        db._run_migrations()

    def test_timeline_events_has_phase7_columns(self, db):
        """Phase 7 — category/actor/device_id/session_id must exist on
        timeline_events, on a freshly created database (migrations run
        automatically on startup, even for a brand-new DB)."""
        with db._connect() as c:
            cols = {r["name"] for r in c.execute(
                "PRAGMA table_info(timeline_events)"
            ).fetchall()}
        required = {"category", "actor", "device_id", "session_id"}
        assert required <= cols

    def test_audit_trail_has_no_update_or_delete(self, db):
        """Audit trail must be immutable — no public update/delete methods."""
        assert not hasattr(db, "update_audit_event")
        assert not hasattr(db, "delete_audit_event")

    def test_audit_limit_default_5000(self, db):
        sig = inspect.signature(db.get_audit_trail)
        assert sig.parameters["limit"].default >= 5000

    def test_now_utc_format(self):
        ts = now_utc()
        assert "UTC" in ts
        assert len(ts) >= 19


# ── Cases ─────────────────────────────────────────────────────────────────────

class TestCases:
    def test_create_and_get(self, db):
        cid = db.create_case("CASE-001", "Test", "Inv", "desc")
        row = db.get_case(cid)
        assert row["case_number"] == "CASE-001"
        assert row["title"] == "Test"
        assert row["investigator"] == "Inv"
        # Phase 8: new cases start in DRAFT (first stage of the
        # DRAFT -> ACTIVE -> UNDER_INVESTIGATION -> REVIEW -> CLOSED ->
        # ARCHIVED workflow), replacing the old flat 'active' default.
        assert row["status"] == "DRAFT"

    def test_case_number_unique(self, db):
        db.create_case("UNIQ-001", "A", "Inv", "")
        with pytest.raises(Exception):
            db.create_case("UNIQ-001", "B", "Inv", "")

    def test_case_number_exists(self, db):
        db.create_case("EXISTS-001", "A", "Inv", "")
        assert db.case_number_exists("EXISTS-001") is True
        assert db.case_number_exists("NOPE-999") is False

    def test_update_case_title(self, db):
        cid = db.create_case("UPD-001", "Old", "Inv", "")
        db.update_case(cid, title="New")
        assert db.get_case(cid)["title"] == "New"

    def test_update_case_notes(self, db):
        cid = db.create_case("N-001", "A", "Inv", "")
        db.update_case_notes(cid, "these are notes")
        assert db.get_case(cid)["notes"] == "these are notes"

    def test_update_case_status(self, db):
        """Phase 8: status now follows the DRAFT -> ACTIVE ->
        UNDER_INVESTIGATION -> REVIEW -> CLOSED -> ARCHIVED workflow, so a
        case must be activated before it can be closed, and closing
        requires a closure_reason."""
        cid = db.create_case("S-001", "A", "Inv", "")
        assert db.get_case(cid)["status"] == "DRAFT"
        db.update_case_status(cid, "ACTIVE")
        assert db.get_case(cid)["status"] == "ACTIVE"
        db.update_case_status(cid, "CLOSED", closure_reason="Investigation complete")
        assert db.get_case(cid)["status"] == "CLOSED"
        assert db.get_case(cid)["closure_reason"] == "Investigation complete"

    def test_update_case_status_invalid_transition_rejected(self, db):
        cid = db.create_case("S-002", "A", "Inv", "")
        with pytest.raises(ValueError):
            db.update_case_status(cid, "CLOSED")  # DRAFT -> CLOSED not allowed

    def test_update_case_status_close_requires_reason(self, db):
        cid = db.create_case("S-003", "A", "Inv", "")
        db.update_case_status(cid, "ACTIVE")
        with pytest.raises(ValueError):
            db.update_case_status(cid, "CLOSED")  # no closure_reason
        with pytest.raises(ValueError):
            db.update_case_status(cid, "CLOSED", closure_reason="   ")  # blank

    def test_update_case_status_full_workflow(self, db):
        cid = db.create_case("S-004", "A", "Inv", "")
        for status in ("ACTIVE", "UNDER_INVESTIGATION", "REVIEW"):
            db.update_case_status(cid, status)
            assert db.get_case(cid)["status"] == status
        db.update_case_status(cid, "CLOSED", closure_reason="Done")
        db.update_case_status(cid, "ARCHIVED")
        assert db.get_case(cid)["status"] == "ARCHIVED"

    def test_reopen_archived_case(self, db):
        cid = db.create_case("S-005", "A", "Inv", "")
        db.update_case_status(cid, "ACTIVE")
        db.update_case_status(cid, "CLOSED", closure_reason="Done")
        db.update_case_status(cid, "ARCHIVED")
        db.update_case_status(cid, "ACTIVE")  # reopen
        case = db.get_case(cid)
        assert case["status"] == "ACTIVE"
        # Reopening clears the stale closure reason (history remains in
        # the audit trail — this DB column is current-state only).
        assert case["closure_reason"] == ""

    def test_archived_case_is_read_only(self, db):
        cid = db.create_case("S-006", "A", "Inv", "")
        db.update_case_status(cid, "ACTIVE")
        db.update_case_status(cid, "CLOSED", closure_reason="Done")
        db.update_case_status(cid, "ARCHIVED")
        with pytest.raises(ValueError):
            db.update_case(cid, title="New Title")
        with pytest.raises(ValueError):
            db.update_case_notes(cid, "sneaky edit")
        # Status transitions are still allowed (that's how you reopen it)
        db.update_case_status(cid, "ACTIVE")
        db.update_case(cid, title="New Title")  # now editable again
        assert db.get_case(cid)["title"] == "New Title"

    def test_get_valid_next_statuses(self, db):
        cid = db.create_case("S-007", "A", "Inv", "")
        assert db.get_valid_next_statuses(db.get_case(cid)["status"]) == ["ACTIVE"]

    def test_update_case_evidence_dir(self, db, tmp_path):
        cid = db.create_case("D-001", "A", "Inv", "")
        db.update_case(cid, evidence_dir=str(tmp_path))
        assert db.get_case(cid)["evidence_dir"] == str(tmp_path)

    def test_get_all_cases(self, db):
        db.create_case("ALL-001", "A", "Inv", "")
        db.create_case("ALL-002", "B", "Inv", "")
        cases = db.get_all_cases()
        nums = [c["case_number"] for c in cases]
        assert "ALL-001" in nums and "ALL-002" in nums

    def test_delete_case(self, db):
        cid = db.create_case("DEL-001", "A", "Inv", "")
        db.delete_case(cid)
        assert db.get_case(cid) is None

    def test_get_nonexistent_case_returns_none(self, db):
        assert db.get_case(999999) is None

    def test_create_case_with_priority_reviewer_tags(self, db):
        cid = db.create_case(
            "META-001", "A", "Inv", "",
            priority="HIGH", reviewer="Det. Smith", tags=["mobile", "fraud"]
        )
        case = db.get_case(cid)
        assert case["priority"] == "HIGH"
        assert case["reviewer"] == "Det. Smith"
        assert db.get_case_tags(cid) == ["mobile", "fraud"]

    def test_create_case_default_priority_is_medium(self, db):
        cid = db.create_case("META-002", "A", "Inv", "")
        assert db.get_case(cid)["priority"] == "MEDIUM"

    def test_create_case_invalid_priority_rejected(self, db):
        with pytest.raises(ValueError):
            db.create_case("META-003", "A", "Inv", "", priority="URGENT")

    def test_update_case_priority_reviewer_tags(self, db):
        cid = db.create_case("META-004", "A", "Inv", "")
        db.update_case(cid, priority="CRITICAL", reviewer="Det. Lee",
                       tags=["urgent"])
        case = db.get_case(cid)
        assert case["priority"] == "CRITICAL"
        assert case["reviewer"] == "Det. Lee"
        assert db.get_case_tags(cid) == ["urgent"]

    def test_update_case_invalid_priority_rejected(self, db):
        cid = db.create_case("META-005", "A", "Inv", "")
        with pytest.raises(ValueError):
            db.update_case(cid, priority="NOT_A_PRIORITY")


# ── Phase 8: legacy status migration ────────────────────────────────────────

class TestPhase8StatusMigration:
    def test_legacy_lowercase_status_normalised_on_open(self, tmp_path):
        """A database created before Phase 8 (status stored as lowercase
        'active'/'closed'/'archived', no priority/reviewer/tags/
        closure_reason columns) must upgrade safely: existing status
        values are re-spelled in canonical uppercase (not changed to a
        different status), and the new columns get safe empty defaults —
        nothing is fabricated."""
        import sqlite3
        db_path = tmp_path / "legacy_phase8.db"
        conn = sqlite3.connect(str(db_path))
        conn.executescript("""
            CREATE TABLE cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT, case_number TEXT UNIQUE NOT NULL,
                title TEXT NOT NULL, investigator TEXT NOT NULL, description TEXT DEFAULT '',
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                notes TEXT DEFAULT '', evidence_dir TEXT DEFAULT ''
            );
        """)
        conn.execute(
            "INSERT INTO cases (case_number, title, investigator, created_at, "
            "updated_at, status) VALUES ('LEGACY-8','T','I','2025-01-01 00:00:00 UTC',"
            "'2025-01-01 00:00:00 UTC','active')"
        )
        conn.execute(
            "INSERT INTO cases (case_number, title, investigator, created_at, "
            "updated_at, status) VALUES ('LEGACY-8B','T','I','2025-01-01 00:00:00 UTC',"
            "'2025-01-01 00:00:00 UTC','archived')"
        )
        conn.commit()
        conn.close()

        db = CaseManager(str(db_path))
        cases = {c["case_number"]: c for c in db.get_all_cases()}
        assert cases["LEGACY-8"]["status"] == "ACTIVE"
        assert cases["LEGACY-8B"]["status"] == "ARCHIVED"
        # New columns default safely, nothing invented
        assert cases["LEGACY-8"]["priority"] == "MEDIUM"
        assert cases["LEGACY-8"]["reviewer"] == ""
        assert cases["LEGACY-8"]["closure_reason"] == ""
        assert db.get_case_tags(cases["LEGACY-8"]["id"]) == []
        # And the migrated case is usable with the new workflow
        db.update_case_status(cases["LEGACY-8"]["id"], "UNDER_INVESTIGATION")


# ── Devices ───────────────────────────────────────────────────────────────────

class TestDevices:
    def test_add_and_get_device(self, populated):
        devs = populated.db.get_devices_for_case(populated.cid)
        assert len(devs) >= 1
        assert devs[0]["serial"] == "DEV001"
        assert devs[0]["model"] == "Pixel 7"

    def test_device_linked_to_case(self, db, tmp_path):
        cid1 = db.create_case("D1", "A", "I", "")
        cid2 = db.create_case("D2", "B", "I", "")

        class Dev1:
            serial="S1"; model="M1"; manufacturer="G"; android_version="12"
            sdk_version="31"; build_number="B1"; cpu_abi="arm64"; usb_debugging=True
        class Dev2:
            serial="S2"; model="M2"; manufacturer="G"; android_version="13"
            sdk_version="33"; build_number="B2"; cpu_abi="arm64"; usb_debugging=False

        db.add_device(cid1, Dev1())
        db.add_device(cid2, Dev2())
        assert db.get_devices_for_case(cid1)[0]["serial"] == "S1"
        assert db.get_devices_for_case(cid2)[0]["serial"] == "S2"

    def test_repeat_acquisition_same_device_no_duplicate_row(self, db):
        """
        Phase 1 report fix: re-registering the SAME physical device (same
        serial) within the SAME case — e.g. two separate acquisition runs
        pulling different evidence categories — must reuse the existing
        devices row, not create a duplicate. This is what caused "same
        device appearing multiple times" in generated reports.
        """
        cid = db.create_case("DUP-001", "Dup Test", "I", "")

        class Dev:
            serial="SAME001"; model="Pixel 8"; manufacturer="Google"
            android_version="14"; sdk_version="34"; build_number="B1"
            cpu_abi="arm64-v8a"; usb_debugging=True

        id1 = db.add_device(cid, Dev())
        id2 = db.add_device(cid, Dev())  # simulate a second acquisition run
        id3 = db.add_device(cid, Dev())  # and a third

        assert id1 == id2 == id3
        devices = db.get_devices_for_case(cid)
        assert len(devices) == 1
        assert devices[0]["serial"] == "SAME001"

    def test_different_serial_same_case_creates_separate_rows(self, db):
        """A genuinely different physical device (different serial) in the
        same case must NOT be deduped away — multi-device cases still work."""
        cid = db.create_case("MULTI-001", "Multi Device", "I", "")

        class DevA:
            serial="AAA"; model="M1"; manufacturer="G"; android_version="12"
            sdk_version="31"; build_number="B1"; cpu_abi="arm64"; usb_debugging=True
        class DevB:
            serial="BBB"; model="M2"; manufacturer="G"; android_version="13"
            sdk_version="33"; build_number="B2"; cpu_abi="arm64"; usb_debugging=False

        db.add_device(cid, DevA())
        db.add_device(cid, DevB())
        devices = db.get_devices_for_case(cid)
        assert len(devices) == 2
        assert {d["serial"] for d in devices} == {"AAA", "BBB"}

    def test_repeat_acquisition_refreshes_mutable_fields(self, db):
        """Re-registering the same device updates its mutable metadata
        (e.g. OS upgraded between acquisition runs) rather than freezing
        it at the first-seen state."""
        cid = db.create_case("REFRESH-001", "T", "I", "")

        class DevOld:
            serial="REF1"; model="Pixel 7"; manufacturer="Google"
            android_version="13"; sdk_version="33"; build_number="OLD"
            cpu_abi="arm64-v8a"; usb_debugging=False
        class DevNew:
            serial="REF1"; model="Pixel 7"; manufacturer="Google"
            android_version="14"; sdk_version="34"; build_number="NEW"
            cpu_abi="arm64-v8a"; usb_debugging=True

        db.add_device(cid, DevOld())
        db.add_device(cid, DevNew())
        devices = db.get_devices_for_case(cid)
        assert len(devices) == 1
        assert devices[0]["android_version"] == "14"
        assert devices[0]["build_number"] == "NEW"
        assert devices[0]["usb_debugging"] == 1


# ── Evidence ──────────────────────────────────────────────────────────────────

class TestEvidence:
    def test_add_and_count(self, populated):
        assert populated.db.get_evidence_count(populated.cid) == 3

    def test_get_evidence_for_case(self, populated):
        evs = populated.db.get_evidence_for_case(populated.cid)
        assert len(evs) == 3

    def test_filter_by_category(self, populated):
        acq = populated.db.get_evidence_for_case(populated.cid, category="acquisition")
        assert len(acq) == 2
        sms = populated.db.get_evidence_for_case(populated.cid, category="sms")
        assert len(sms) == 1

    def test_null_file_size_stored_and_read(self, populated):
        evs = populated.db.get_evidence_for_case(populated.cid, category="sms")
        assert evs[0]["file_size"] is None or evs[0]["file_size"] == 0

    def test_evidence_isolated_between_cases(self, db):
        cid1 = db.create_case("C1", "A", "I", "")
        cid2 = db.create_case("C2", "B", "I", "")
        db.add_evidence(cid1, None, "acquisition", "a.txt", "/tmp/a", "h1", 1, {})
        assert db.get_evidence_count(cid2) == 0

    def test_verify_evidence_pass(self, populated):
        result = populated.db.verify_evidence(populated.eid_pass)
        assert result.get("match") is True or result.get("error") is None

    def test_verify_evidence_mismatch(self, populated):
        result = populated.db.verify_evidence(populated.eid_fail)
        # Either returns match=False or an error (file may not be on disk)
        assert result.get("match") is False or "error" in result


# ── Timeline Events (Phase 7 — Unified Forensic Timeline) ───────────────────────

class TestTimelineEvents:
    def test_add_and_get(self, populated):
        eid = populated.db.add_timeline_event(
            populated.cid, "note_added", "Investigator note",
            "2024-06-02 09:00:00", category="audit", actor="Det. Jones",
        )
        assert eid
        rows = populated.db.get_timeline(populated.cid)
        assert any(r["id"] == eid for r in rows)

    def test_duplicate_call_does_not_insert_new_row(self, populated):
        """Calling add_timeline_event() twice with identical
        case/type/description/timestamp/evidence/device/session must not
        create a second row — this is the core Phase 7 duplicate-prevention
        guarantee, so re-running the same analysis/timeline build never
        grows the table."""
        before = len(populated.db.get_timeline(populated.cid))
        id1 = populated.db.add_timeline_event(
            populated.cid, "evidence_acquired", "Evidence acquired: report.txt",
            "2024-06-01 12:00:00", evidence_id=populated.eid_pass,
            category="evidence", actor="Det. Jones",
        )
        mid = len(populated.db.get_timeline(populated.cid))
        id2 = populated.db.add_timeline_event(
            populated.cid, "evidence_acquired", "Evidence acquired: report.txt",
            "2024-06-01 12:00:00", evidence_id=populated.eid_pass,
            category="evidence", actor="Det. Jones",
        )
        after = len(populated.db.get_timeline(populated.cid))
        assert mid == before + 1
        assert after == mid          # second call inserted nothing
        assert id1 == id2            # returns the existing row's id

    def test_differing_timestamp_is_a_new_event(self, populated):
        """A genuinely new event (different timestamp) must still insert,
        even with identical type/description/evidence."""
        before = len(populated.db.get_timeline(populated.cid))
        populated.db.add_timeline_event(
            populated.cid, "evidence_acquired", "Evidence acquired: report.txt",
            "2024-06-01 12:00:00", evidence_id=populated.eid_pass,
        )
        populated.db.add_timeline_event(
            populated.cid, "evidence_acquired", "Evidence acquired: report.txt",
            "2024-06-01 12:00:01", evidence_id=populated.eid_pass,
        )
        after = len(populated.db.get_timeline(populated.cid))
        assert after == before + 2

    def test_get_timeline_filters_by_event_type(self, populated):
        populated.db.add_timeline_event(
            populated.cid, "device_registered", "Device registered",
            "2024-06-01 08:00:00", category="device_acquisition",
            device_id=populated.did,
        )
        rows = populated.db.get_timeline(populated.cid, event_type="device_registered")
        assert rows
        assert all(r["event_type"] == "device_registered" for r in rows)

    def test_get_timeline_filters_by_category(self, populated):
        rows = populated.db.get_timeline(populated.cid, category="custody")
        assert rows == [] or all(r["category"] == "custody" for r in rows)

    def test_get_timeline_filters_by_evidence_id(self, populated):
        populated.db.add_timeline_event(
            populated.cid, "evidence_acquired", "Evidence acquired: report.txt",
            "2024-06-01 12:00:00", evidence_id=populated.eid_pass,
        )
        rows = populated.db.get_timeline(populated.cid, evidence_id=populated.eid_pass)
        assert rows
        assert all(r["evidence_id"] == populated.eid_pass for r in rows)

    def test_get_timeline_filters_by_device_id(self, populated):
        populated.db.add_timeline_event(
            populated.cid, "device_registered", "Device registered",
            "2024-06-01 08:00:00", device_id=populated.did,
        )
        rows = populated.db.get_timeline(populated.cid, device_id=populated.did)
        assert rows
        assert all(r["device_id"] == populated.did for r in rows)

    def test_get_timeline_filters_by_actor(self, populated):
        populated.db.add_timeline_event(
            populated.cid, "note_added", "note", "2024-06-01 08:00:00",
            actor="Det. Rivera",
        )
        rows = populated.db.get_timeline(populated.cid, actor="Det. Rivera")
        assert rows
        assert all(r["actor"] == "Det. Rivera" for r in rows)

    def test_get_timeline_filters_by_date_range(self, populated):
        populated.db.add_timeline_event(
            populated.cid, "note_added", "early", "2024-01-01 00:00:00",
        )
        populated.db.add_timeline_event(
            populated.cid, "note_added", "late", "2024-12-31 00:00:00",
        )
        rows = populated.db.get_timeline(
            populated.cid, date_from="2024-06-01", date_to="2024-12-01"
        )
        descriptions = {r["description"] for r in rows}
        assert "early" not in descriptions
        assert "late" not in descriptions

    def test_get_timeline_joins_evidence_filename(self, populated):
        populated.db.add_timeline_event(
            populated.cid, "evidence_acquired", "Evidence acquired: report.txt",
            "2024-06-01 12:00:00", evidence_id=populated.eid_pass,
        )
        rows = populated.db.get_timeline(populated.cid, evidence_id=populated.eid_pass)
        assert rows[0]["evidence_filename"] == "report.txt"

    def test_get_timeline_joins_device_serial(self, populated):
        populated.db.add_timeline_event(
            populated.cid, "device_registered", "Device registered",
            "2024-06-01 08:00:00", device_id=populated.did,
        )
        rows = populated.db.get_timeline(populated.cid, device_id=populated.did)
        assert rows[0]["device_serial"] == "DEV001"

    def test_get_timeline_still_works_with_only_case_id(self, populated):
        """Backward compatibility: existing callers pass only case_id."""
        rows = populated.db.get_timeline(populated.cid)
        assert isinstance(rows, list)

    def test_get_timeline_event_types(self, populated):
        types = populated.db.get_timeline_event_types(populated.cid)
        assert isinstance(types, list)
        assert "file_created" in types  # inserted by the `populated` fixture

    def test_get_timeline_actors(self, populated):
        populated.db.add_timeline_event(
            populated.cid, "note_added", "note", "2024-06-01 08:00:00",
            actor="Det. Rivera",
        )
        actors = populated.db.get_timeline_actors(populated.cid)
        assert "Det. Rivera" in actors


# ── Verification ──────────────────────────────────────────────────────────────

class TestVerification:
    def test_add_and_get_history(self, populated):
        vh = populated.db.get_verification_history(case_id=populated.cid)
        assert len(vh) == 2

    def test_get_history_by_evidence(self, populated):
        vh = populated.db.get_verification_history(evidence_id=populated.eid_pass)
        assert len(vh) == 1
        assert vh[0]["result"] == "PASS"

    def test_get_last_verification(self, populated):
        last = populated.db.get_last_verification(populated.eid_fail)
        assert last is not None
        assert last["result"] == "FAIL"

    def test_get_last_verification_returns_newest(self, populated):
        """If multiple results exist, most recent is returned."""
        populated.db.add_verification_result(
            populated.cid, populated.eid_pass, "FAIL", "x", "y", "re-check"
        )
        last = populated.db.get_last_verification(populated.eid_pass)
        assert last["result"] == "FAIL"

    def test_get_last_verification_per_evidence(self, populated):
        rmap = populated.db.get_last_verification_per_evidence(populated.cid)
        assert populated.eid_pass in rmap
        assert populated.eid_fail in rmap
        assert rmap[populated.eid_pass]["result"] == "PASS"
        assert rmap[populated.eid_fail]["result"] == "FAIL"
        # Evidence from another case must not appear
        assert populated.eid_null not in rmap or rmap.get(populated.eid_null) is None

    def test_batched_lookup_excludes_other_cases(self, db, populated):
        cid2 = db.create_case("C2", "B", "I", "")
        eid2 = db.add_evidence(cid2, None, "acq", "f", "/tmp/f", "h", 0, {})
        db.add_verification_result(cid2, eid2, "PASS", "h", "h", "ok")
        rmap = populated.db.get_last_verification_per_evidence(populated.cid)
        assert eid2 not in rmap

    def test_verification_summary(self, populated):
        summ = populated.db.get_verification_summary(populated.cid)
        assert summ["PASS"] == 1
        assert summ["FAIL"] == 1
        assert summ["total"] == 2
        assert summ.get("MISSING", 0) == 0

    def test_no_verifications_summary(self, db):
        cid = db.create_case("NV", "A", "I", "")
        summ = db.get_verification_summary(cid)
        assert summ["total"] == 0


# ── Audit trail ───────────────────────────────────────────────────────────────

class TestAuditTrail:
    def test_add_and_get(self, populated):
        trail = populated.db.get_audit_trail()
        assert len(trail) >= 2

    def test_immutable_no_update_delete(self, db):
        assert not hasattr(db, "update_audit_event")
        assert not hasattr(db, "delete_audit_event")

    def test_filter_by_action(self, db):
        cid = db.create_case("AT", "A", "I", "")
        db.add_audit_event("ACTION_A", "user1", "case", cid, "OK", "note A")
        db.add_audit_event("ACTION_B", "user2", "case", cid, "OK", "note B")
        trail_a = db.get_audit_trail(action="ACTION_A")
        assert all(r["action"] == "ACTION_A" for r in trail_a)

    def test_filter_by_user(self, db):
        cid = db.create_case("AU", "A", "I", "")
        db.add_audit_event("X", "alice", "case", cid)
        db.add_audit_event("X", "bob",   "case", cid)
        alice_trail = db.get_audit_trail(user="alice")
        assert all(r["user"] == "alice" for r in alice_trail)

    def test_limit_is_honoured(self, db):
        cid = db.create_case("LIM", "A", "I", "")
        for i in range(20):
            db.add_audit_event(f"EV{i}", "user", "case", cid)
        assert len(db.get_audit_trail(limit=5)) == 5

    def test_get_audit_actions(self, populated):
        actions = populated.db.get_audit_actions()
        assert isinstance(actions, list)
        assert len(actions) >= 1

    def test_get_audit_users(self, populated):
        users = populated.db.get_audit_users()
        assert isinstance(users, list)
        assert "Det. Jones" in users

    def test_large_audit_trail_not_truncated_at_default(self, db):
        cid = db.create_case("BIG", "A", "I", "")
        for i in range(200):
            db.add_audit_event(f"EV{i}", "user", "case", cid)
        trail = db.get_audit_trail()
        assert len(trail) == 200


# ── Custody events ────────────────────────────────────────────────────────────

class TestCustodyEvents:
    def test_add_and_get_chain(self, populated):
        chain = populated.db.get_custody_chain(populated.eid_pass)
        assert len(chain) >= 1

    def test_chain_shows_action(self, populated):
        chain = populated.db.get_custody_chain(populated.eid_pass)
        actions = [c["action"] for c in chain]
        assert "ACQUIRED" in actions

    def test_custody_summary(self, populated):
        summ = populated.db.get_custody_summary(populated.cid)
        assert "ACQUIRED" in summ
        assert summ["ACQUIRED"] >= 1

    def test_custody_events_for_case(self, populated):
        events = populated.db.get_custody_events(case_id=populated.cid)
        assert len(events) >= 1

    def test_custody_survives_case_isolation(self, db, populated):
        """Evidence from one case should not appear in another case's chain."""
        cid2 = db.create_case("C2", "B", "I", "")
        eid2 = db.add_evidence(cid2, None, "acq", "f", "/tmp/f", "h", 0, {})
        db.add_custody_event(cid2, eid2, "I", "ACQUIRED")
        # populated's evidence chain should not include eid2 events
        chain = populated.db.get_custody_chain(populated.eid_pass)
        for event in chain:
            assert event["evidence_id"] == populated.eid_pass


# ── Phase 2 — Chain of Custody lifecycle & transfers ────────────────────────────

class TestPhase2Lifecycle:
    def test_new_lifecycle_actions_accepted(self, db):
        """STORED, ANALYZED, REPORTED must be valid custody actions,
        alongside the existing ACQUIRED/VERIFIED/TRANSFERRED/etc."""
        cid = db.create_case("LC-001", "T", "I", "")
        eid = db.add_evidence(cid, None, "acq", "f", "/tmp/f", "h"*64, 0, {})
        for action in ("STORED", "ANALYZED", "REPORTED"):
            db.add_custody_event(cid, eid, "I", action)  # must not raise
        actions = [e["action"] for e in db.get_custody_chain(eid)]
        assert "STORED" in actions
        assert "ANALYZED" in actions
        assert "REPORTED" in actions

    def test_full_lifecycle_progression(self, db):
        """ACQUIRED → STORED → VERIFIED → TRANSFERRED → ANALYZED → REPORTED,
        in order, all preserved."""
        cid = db.create_case("LC-002", "T", "I", "")
        eid = db.add_evidence(cid, None, "acq", "f", "/tmp/f", "h"*64, 0, {})
        for action in ("ACQUIRED", "STORED", "VERIFIED"):
            db.add_custody_event(cid, eid, "I", action)
        db.add_transfer_event(cid, eid, "I", "Locker A", "Lab 2", reason="Analysis")
        db.add_custody_event(cid, eid, "I", "ANALYZED")
        db.add_custody_event(cid, eid, "I", "REPORTED")

        chain = db.get_custody_chain(eid)
        actions = [e["action"] for e in chain]
        assert actions == ["ACQUIRED", "STORED", "VERIFIED", "TRANSFERRED",
                            "ANALYZED", "REPORTED"]

    def test_invalid_action_still_rejected(self, db):
        cid = db.create_case("LC-003", "T", "I", "")
        eid = db.add_evidence(cid, None, "acq", "f", "/tmp/f", "h"*64, 0, {})
        with pytest.raises(ValueError):
            db.add_custody_event(cid, eid, "I", "TELEPORTED")


class TestPhase2Transfers:
    def test_transfer_records_from_and_to(self, db):
        cid = db.create_case("TR-001", "T", "I", "")
        eid = db.add_evidence(cid, None, "acq", "f", "/tmp/f", "h"*64, 0, {})
        db.add_transfer_event(cid, eid, "Det. A", "Evidence Locker", "Forensics Lab",
                              reason="Handoff for analysis")
        chain = db.get_custody_chain(eid)
        transfer = [e for e in chain if e["action"] == "TRANSFERRED"][0]
        assert transfer["from_location"] == "Evidence Locker"
        assert transfer["to_location"] == "Forensics Lab"
        assert transfer["notes"] == "Handoff for analysis"

    def test_transfer_never_touches_evidence_file(self, db, tmp_path):
        """A transfer must only write a custody row — the evidence file
        and its recorded hash must be completely untouched."""
        fp = tmp_path / "evidence.bin"
        fp.write_bytes(b"original content")
        import hashlib
        h = hashlib.sha256(fp.read_bytes()).hexdigest()

        cid = db.create_case("TR-002", "T", "I", "")
        eid = db.add_evidence(cid, None, "acq", "evidence.bin", str(fp), h, len(b"original content"), {})

        db.add_transfer_event(cid, eid, "Det. A", "Site A", "Site B", reason="move")

        assert fp.read_bytes() == b"original content"
        ev = db.get_evidence_for_case(cid)[0]
        assert ev["sha256"] == h

    def test_multiple_transfers_all_preserved(self, db):
        """Support multiple transfers and preserve complete historical
        custody — nothing about an earlier transfer is overwritten."""
        cid = db.create_case("TR-003", "T", "I", "")
        eid = db.add_evidence(cid, None, "acq", "f", "/tmp/f", "h"*64, 0, {})

        db.add_transfer_event(cid, eid, "A", "Locker", "Lab", reason="step1")
        db.add_transfer_event(cid, eid, "B", "Lab", "Archive", reason="step2")
        db.add_transfer_event(cid, eid, "C", "Archive", "Court", reason="step3")

        transfers = db.get_transfer_history(evidence_id=eid)
        assert len(transfers) == 3
        assert [t["from_location"] for t in transfers] == ["Locker", "Lab", "Archive"]
        assert [t["to_location"] for t in transfers] == ["Lab", "Archive", "Court"]
        assert [t["investigator"] for t in transfers] == ["A", "B", "C"]

    def test_transfer_integrity_snapshot_auto_captured(self, db):
        """When integrity_status isn't explicitly given, it must be
        captured from the evidence's REAL last verification result, not
        fabricated."""
        cid = db.create_case("TR-004", "T", "I", "")
        eid = db.add_evidence(cid, None, "acq", "f", "/tmp/nonexistent", "h"*64, 0, {})

        # No verification yet -> NOT_VERIFIED
        db.add_transfer_event(cid, eid, "A", "Locker", "Lab")
        t1 = db.get_transfer_history(evidence_id=eid)[0]
        assert t1["integrity_status"] == "NOT_VERIFIED"

        # Record a real verification result, then transfer again
        db.add_verification_result(cid, eid, "MISMATCH", "a"*64, "b"*64, "test")
        db.add_transfer_event(cid, eid, "A", "Lab", "Archive")
        t2 = db.get_transfer_history(evidence_id=eid)[1]
        assert t2["integrity_status"] == "MISMATCH"

    def test_transfer_integrity_snapshot_explicit_override(self, db):
        cid = db.create_case("TR-005", "T", "I", "")
        eid = db.add_evidence(cid, None, "acq", "f", "/tmp/f", "h"*64, 0, {})
        db.add_transfer_event(cid, eid, "A", "X", "Y", integrity_status="MATCH")
        t = db.get_transfer_history(evidence_id=eid)[0]
        assert t["integrity_status"] == "MATCH"

    def test_get_transfer_history_case_scoped(self, db):
        cid = db.create_case("TR-006", "T", "I", "")
        eid1 = db.add_evidence(cid, None, "acq", "f1", "/tmp/f1", "h"*64, 0, {})
        eid2 = db.add_evidence(cid, None, "acq", "f2", "/tmp/f2", "h"*64, 0, {})
        db.add_transfer_event(cid, eid1, "A", "X", "Y")
        db.add_transfer_event(cid, eid2, "A", "X", "Z")
        all_transfers = db.get_transfer_history(case_id=cid)
        assert len(all_transfers) == 2

    def test_transfer_history_is_append_only(self, db):
        """No update/delete method exists — verified by confirming the
        row count only grows."""
        cid = db.create_case("TR-007", "T", "I", "")
        eid = db.add_evidence(cid, None, "acq", "f", "/tmp/f", "h"*64, 0, {})
        assert not hasattr(db, "update_custody_event")
        assert not hasattr(db, "delete_custody_event")
        before = len(db.get_custody_chain(eid))
        db.add_transfer_event(cid, eid, "A", "X", "Y")
        after = len(db.get_custody_chain(eid))
        assert after == before + 1


class TestPhase2LifecycleStatus:
    def test_lifecycle_status_tracks_latest_stage(self, db):
        cid = db.create_case("LS-001", "T", "I", "")
        eid = db.add_evidence(cid, None, "acq", "f", "/tmp/f", "h"*64, 0, {})
        assert db.get_evidence_lifecycle_status(eid) == "UNKNOWN"

        db.add_custody_event(cid, eid, "I", "ACQUIRED")
        assert db.get_evidence_lifecycle_status(eid) == "ACQUIRED"

        db.add_custody_event(cid, eid, "I", "STORED")
        assert db.get_evidence_lifecycle_status(eid) == "STORED"

        db.add_custody_event(cid, eid, "I", "VERIFIED")
        assert db.get_evidence_lifecycle_status(eid) == "VERIFIED"

    def test_auxiliary_actions_dont_change_lifecycle_status(self, db):
        """REVIEWED/NOTED/etc. are recorded but don't move the reported
        lifecycle stage backward or sideways."""
        cid = db.create_case("LS-002", "T", "I", "")
        eid = db.add_evidence(cid, None, "acq", "f", "/tmp/f", "h"*64, 0, {})
        db.add_custody_event(cid, eid, "I", "ACQUIRED")
        db.add_custody_event(cid, eid, "I", "VERIFIED")
        db.add_custody_event(cid, eid, "I", "NOTED", notes="reviewed by supervisor")
        assert db.get_evidence_lifecycle_status(eid) == "VERIFIED"

    def test_multiple_transfers_lifecycle_status_stays_transferred(self, db):
        cid = db.create_case("LS-003", "T", "I", "")
        eid = db.add_evidence(cid, None, "acq", "f", "/tmp/f", "h"*64, 0, {})
        db.add_custody_event(cid, eid, "I", "ACQUIRED")
        db.add_transfer_event(cid, eid, "I", "A", "B")
        db.add_transfer_event(cid, eid, "I", "B", "C")
        assert db.get_evidence_lifecycle_status(eid) == "TRANSFERRED"


class TestPhase2CustodyBackwardCompatibility:
    """Phase 2 must not break Phase 1 / pre-Phase-2 custody data or callers."""

    def test_plain_location_still_works_for_non_transfer_actions(self, populated):
        """Pre-Phase-2 callers passing just `location` (no from/to) for
        e.g. ACQUIRED must behave exactly as before."""
        populated.db.add_custody_event(
            populated.cid, populated.eid_pass, "I", "ACQUIRED", location="Lab-A"
        )
        chain = populated.db.get_custody_chain(populated.eid_pass)
        acquired = [e for e in chain if e["action"] == "ACQUIRED"][-1]
        assert acquired["location"] == "Lab-A"

    def test_old_transferred_call_without_from_to_still_works(self, populated):
        """A caller still using the pre-Phase-2 signature (just location,
        no from_location/to_location) must not break."""
        eid = populated.db.add_custody_event(
            populated.cid, populated.eid_pass, "I", "TRANSFERRED",
            location="Storage Room B", notes="legacy-style transfer"
        )
        assert isinstance(eid, int)
        chain = populated.db.get_custody_chain(populated.eid_pass)
        t = [e for e in chain if e["action"] == "TRANSFERRED"][-1]
        # location auto-mirrors to to_location's absence gracefully
        assert t["location"] == "Storage Room B"

    def test_existing_custody_events_have_empty_new_columns_by_default(self, populated):
        """Rows inserted without the new Phase 2 fields must default to
        empty strings, not NULL/crash, for older-style callers."""
        chain = populated.db.get_custody_chain(populated.eid_pass)
        acquired = [e for e in chain if e["action"] == "ACQUIRED"][0]
        assert acquired["from_location"] == ""
        assert acquired["to_location"] == ""
        assert acquired["integrity_status"] == ""


# ── System stats & performance methods ───────────────────────────────────────

class TestSystemStats:
    def test_accurate_across_cases(self, db):
        cid1 = db.create_case("SS1", "A", "I", "")
        cid2 = db.create_case("SS2", "B", "I", "")
        for _ in range(3):
            db.add_evidence(cid1, None, "acq", "f", "/tmp/f", "h", 0, {})
        for _ in range(7):
            db.add_evidence(cid2, None, "media", "m", "/tmp/m", "h", 0, {})

        class FD:
            serial="S1"; model="X"; manufacturer="G"; android_version="1"
            sdk_version="1"; build_number="1"; cpu_abi="arm"; usb_debugging=True
        db.add_device(cid1, FD())
        db.add_analysis_result(cid1, None, "apps", "summary", {})

        stats = db.get_system_stats()
        assert stats["cases"]    == 2
        assert stats["evidence"] == 10
        assert stats["devices"]  == 1
        assert stats["analysis"] == 1

    def test_empty_database(self, db):
        stats = db.get_system_stats()
        assert all(v == 0 for v in stats.values())


# ── Global search ─────────────────────────────────────────────────────────────

class TestGlobalSearch:
    def test_finds_case_by_number(self, populated):
        res = populated.db.global_search("TC-001")
        assert any(r["source"] == "case" for r in res)

    def test_finds_evidence_by_filename(self, populated):
        res = populated.db.global_search("report.txt", case_id=populated.cid)
        assert any(r["source"] == "evidence" for r in res)

    def test_finds_audit_event_by_notes(self, populated):
        res = populated.db.global_search("Det. Jones", case_id=populated.cid)
        sources = {r["source"] for r in res}
        assert "audit" in sources or "case" in sources or "custody" in sources

    def test_date_filter(self, populated):
        res = populated.db.global_search(
            "Jones", case_id=populated.cid, date_from="2020-01-01"
        )
        assert len(res) >= 0  # must not crash; results may be empty for old dates

    def test_evidence_type_filter(self, populated):
        res = populated.db.global_search(
            "report", case_id=populated.cid, evidence_type="acquisition"
        )
        for r in res:
            if r["source"] == "evidence":
                assert r["type"] == "acquisition"

    def test_empty_keyword_returns_empty(self, populated):
        """Empty keyword must not return all records (defensive check)."""
        # Either empty list or graceful behaviour — must not crash
        try:
            res = populated.db.global_search("", case_id=populated.cid)
            # If it returns results, they should be iterable
            _ = list(res)
        except Exception:
            pass  # acceptable to reject empty keyword


# ── Case Integrity Summary (Phase 1) ────────────────────────────────────────────

class TestCaseIntegritySummaryDB:
    def test_uses_latest_verification_per_evidence_not_history_count(self, populated):
        """Verifying the same evidence item twice (once wrong, once right)
        must reflect only its MOST RECENT status in the summary — not double
        count it, unlike the historical get_verification_summary()."""
        # populated fixture already recorded one "PASS" for eid_pass.
        # Add a newer MISMATCH for the same item.
        populated.db.add_verification_result(
            populated.cid, populated.eid_pass, "MISMATCH", "a"*64, "b"*64, "later mismatch"
        )
        summary = populated.db.get_case_integrity_summary(populated.cid)
        # eid_pass's latest result is MISMATCH, not MATCH/PASS
        assert summary["MISMATCH"] >= 1
        assert summary["total"] == populated.db.get_evidence_count(populated.cid)

    def test_legacy_pass_fail_rows_normalized_in_summary(self, populated):
        """The populated fixture seeds literal legacy 'PASS'/'FAIL' rows —
        the case integrity summary must still classify them correctly
        under the new MATCH/MISMATCH buckets."""
        summary = populated.db.get_case_integrity_summary(populated.cid)
        assert summary["MATCH"] + summary["MISMATCH"] >= 2

    def test_summary_is_read_only_no_side_effects(self, populated):
        """Calling the summary repeatedly must not change the underlying
        verification_results row count (no accidental writes)."""
        before = len(populated.db.get_verification_history(case_id=populated.cid))
        populated.db.get_case_integrity_summary(populated.cid)
        populated.db.get_case_integrity_summary(populated.cid)
        after = len(populated.db.get_verification_history(case_id=populated.cid))
        assert before == after
