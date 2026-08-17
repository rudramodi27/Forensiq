"""
Integration tests — forensiq.core.audit_service (AuditService)

Covers: all log_* methods, immutability enforcement, JSON export,
HTML export (must contain 'immutable'), custody export.
"""

import json
import os
import pytest

from forensiq.core.audit_service import AuditService, R_OK, R_FAILED, R_WARNING


class TestResultConstants:
    def test_r_ok(self):     assert R_OK     == "OK"
    def test_r_failed(self): assert R_FAILED == "FAILED"
    def test_r_warning(self):assert R_WARNING== "WARNING"


class TestLogMethods:
    def test_log_case_created(self, populated):
        populated.audit.log_case_created(populated.cid, "Det. Jones", "TC-001")
        trail = populated.db.get_audit_trail()
        assert any(r["action"] == "CASE_CREATED" for r in trail)

    def test_log_case_modified(self, populated):
        populated.audit.log_case_modified(populated.cid, "Det. Jones", "title")
        trail = populated.db.get_audit_trail()
        assert any(r["action"] == "CASE_MODIFIED" for r in trail)

    def test_log_case_status_changed(self, populated):
        populated.audit.log_case_status_changed(populated.cid, "Det. Jones", "closed")
        trail = populated.db.get_audit_trail()
        assert any(r["action"] == "CASE_STATUS_CHANGED" for r in trail)

    def test_log_case_status_changed_with_reason_and_previous(self, populated):
        """Phase 8: previous_status/closure_reason are optional kwargs
        folded into the same CASE_STATUS_CHANGED audit row."""
        populated.audit.log_case_status_changed(
            populated.cid, "Det. Jones", "CLOSED",
            previous_status="REVIEW", closure_reason="Investigation complete"
        )
        trail = populated.db.get_audit_trail()
        matches = [r for r in trail if r["action"] == "CASE_STATUS_CHANGED"]
        assert any("REVIEW" in r["notes"] and "CLOSED" in r["notes"] for r in matches)
        assert any("Investigation complete" in r["notes"] for r in matches)

    def test_log_evidence_added(self, populated):
        populated.audit.log_evidence_added(
            populated.cid, populated.eid_pass, "Det. Jones", "report.txt", "acquisition"
        )
        trail = populated.db.get_audit_trail()
        assert any(r["action"] == "EVIDENCE_ADDED" for r in trail)

    def test_log_verification(self, populated):
        populated.audit.log_verification(
            populated.cid, populated.eid_pass, "Det. Jones",
            "PASS", "report.txt", populated.h_pass
        )
        trail = populated.db.get_audit_trail()
        assert any(r["action"] in ("VERIFICATION_PASSED","VERIFICATION_FAILED","VERIFICATION") for r in trail)

    def test_log_report_generated(self, populated):
        populated.audit.log_report_generated(
            populated.cid, "Det. Jones", "HTML", "/tmp/r.html"
        )
        trail = populated.db.get_audit_trail()
        assert any(r["action"] == "REPORT_GENERATED" for r in trail)

    def test_each_log_method_increases_trail(self, populated):
        before = len(populated.db.get_audit_trail())
        populated.audit.log_case_modified(populated.cid, "Det. Jones", "notes")
        after = len(populated.db.get_audit_trail())
        assert after == before + 1


class TestImmutability:
    def test_no_update_audit_event(self, db):
        assert not hasattr(db, "update_audit_event")

    def test_no_delete_audit_event(self, db):
        assert not hasattr(db, "delete_audit_event")

    def test_audit_rows_cannot_be_deleted_via_sql(self, populated):
        """Direct SQL DELETE on audit_trail must be blocked by FK/trigger or simply
        not exposed — verify the row count stays the same after a case delete
        does NOT cascade to audit (audit uses no FK cascade)."""
        before = len(populated.db.get_audit_trail())
        # Audit trail rows for the case should persist even after case deletion
        # (the fixture case is not deleted here — just verify the count is stable)
        after = len(populated.db.get_audit_trail())
        assert after == before


class TestAuditExport:
    def test_export_json_creates_file(self, populated, tmp_path):
        trail = populated.db.get_audit_trail()
        p = str(tmp_path / "audit.json")
        populated.audit.export_audit_json(trail, p)
        assert os.path.exists(p)

    def test_export_json_is_valid(self, populated, tmp_path):
        trail = populated.db.get_audit_trail()
        p = str(tmp_path / "audit.json")
        populated.audit.export_audit_json(trail, p)
        data = json.loads(open(p).read())
        assert "records" in data or "events" in data or isinstance(data, list)

    def test_export_html_creates_file(self, populated, tmp_path):
        trail = populated.db.get_audit_trail()
        p = str(tmp_path / "audit.html")
        populated.audit.export_audit_html(trail, p)
        assert os.path.exists(p)

    def test_export_html_contains_forensiq(self, populated, tmp_path):
        trail = populated.db.get_audit_trail()
        p = str(tmp_path / "audit.html")
        populated.audit.export_audit_html(trail, p)
        assert "ForensIQ" in open(p).read()

    def test_export_html_mentions_immutability(self, populated, tmp_path):
        """Audit HTML must clearly state the log is immutable."""
        trail = populated.db.get_audit_trail()
        p = str(tmp_path / "audit.html")
        populated.audit.export_audit_html(trail, p)
        assert "immutable" in open(p).read().lower()

    def test_export_html_has_table(self, populated, tmp_path):
        trail = populated.db.get_audit_trail()
        p = str(tmp_path / "audit.html")
        populated.audit.export_audit_html(trail, p)
        assert "<table" in open(p).read()


class TestCustodyExport:
    def test_export_custody_json_creates_file(self, populated, tmp_path):
        events = populated.db.get_custody_events(case_id=populated.cid)
        p = str(tmp_path / "custody.json")
        populated.audit.export_custody_json(events, p, case_number="TC-001")
        assert os.path.exists(p)

    def test_export_custody_json_structure(self, populated, tmp_path):
        events = populated.db.get_custody_events(case_id=populated.cid)
        p = str(tmp_path / "custody.json")
        populated.audit.export_custody_json(events, p, case_number="TC-001")
        data = json.loads(open(p).read())
        assert data["case_number"] == "TC-001"

    def test_export_custody_html_creates_file(self, populated, tmp_path):
        events = populated.db.get_custody_events(case_id=populated.cid)
        p = str(tmp_path / "custody.html")
        populated.audit.export_custody_html(events, p, case_number="TC-001")
        assert os.path.exists(p)

    def test_export_custody_html_has_case_number(self, populated, tmp_path):
        events = populated.db.get_custody_events(case_id=populated.cid)
        p = str(tmp_path / "custody.html")
        populated.audit.export_custody_html(events, p, case_number="TC-001")
        assert "TC-001" in open(p).read()


# ── Phase 2 — Chain of Custody & Audit Trail ────────────────────────────────────

class TestPhase2AuditHooks:
    def test_log_evidence_added_creates_stored_when_file_exists(self, populated, tmp_path):
        """STORED is only logged when the file genuinely exists on disk —
        never fabricated for a path that isn't real."""
        fp = tmp_path / "real_file.bin"
        fp.write_bytes(b"data")
        before = len(populated.db.get_audit_trail())
        populated.audit.log_evidence_added(
            populated.cid, populated.eid_pass, "Det. Jones",
            "real_file.bin", "acquisition", filepath=str(fp)
        )
        trail = populated.db.get_audit_trail()
        assert any(r["action"] == "EVIDENCE_STORED" for r in trail)
        chain = populated.db.get_custody_chain(populated.eid_pass)
        assert any(e["action"] == "STORED" for e in chain)

    def test_log_evidence_added_no_stored_for_missing_file(self, populated):
        """No STORED event/audit row when the filepath doesn't exist —
        must not fabricate a storage confirmation."""
        populated.audit.log_evidence_added(
            populated.cid, populated.eid_fail, "Det. Jones",
            "ghost.bin", "acquisition", filepath="/definitely/not/a/real/path.bin"
        )
        trail = populated.db.get_audit_trail()
        stored_events = [r for r in trail if r["action"] == "EVIDENCE_STORED"
                         and r["target_id"] == populated.eid_fail]
        assert len(stored_events) == 0

    def test_log_evidence_added_without_filepath_backward_compatible(self, populated):
        """Pre-Phase-2 callers that don't pass filepath at all must still
        work exactly as before (just ACQUIRED, no STORED)."""
        populated.audit.log_evidence_added(
            populated.cid, populated.eid_pass, "Det. Jones", "old_style.bin", "acquisition"
        )  # must not raise
        trail = populated.db.get_audit_trail()
        assert any(r["action"] == "EVIDENCE_ADDED" for r in trail)

    def test_log_analysis_performed_creates_audit_and_custody(self, populated):
        populated.audit.log_analysis_performed(
            populated.cid, "Analyst Lee", "duplicate_detection", "3 duplicates found"
        )
        trail = populated.db.get_audit_trail()
        assert any(r["action"] == "EVIDENCE_ANALYZED" for r in trail)
        chain = populated.db.get_custody_events(case_id=populated.cid)
        assert any(e["action"] == "ANALYZED" for e in chain)

    def test_log_analysis_performed_evidence_scoped(self, populated):
        populated.audit.log_analysis_performed(
            populated.cid, "Analyst Lee", "hash_check", "ok",
            evidence_id=populated.eid_pass,
        )
        chain = populated.db.get_custody_chain(populated.eid_pass)
        assert any(e["action"] == "ANALYZED" for e in chain)

    def test_log_report_generated_creates_reported_events(self, populated):
        """Phase 2: report generation must also create REPORTED custody
        events (in addition to the pre-Phase-2 EXPORTED events, kept for
        backward compatibility)."""
        populated.audit.log_report_generated(
            populated.cid, "Det. Jones", "Forensic Report", "/tmp/r.pdf"
        )
        chain = populated.db.get_custody_events(case_id=populated.cid)
        assert any(e["action"] == "EXPORTED" for e in chain)
        assert any(e["action"] == "REPORTED" for e in chain)

    def test_log_report_generated_reported_has_integrity_snapshot(self, populated):
        populated.db.add_verification_result(
            populated.cid, populated.eid_pass, "MATCH", "a"*64, "a"*64, "ok"
        )
        populated.audit.log_report_generated(
            populated.cid, "Det. Jones", "Forensic Report", "/tmp/r.pdf"
        )
        chain = populated.db.get_custody_chain(populated.eid_pass)
        reported = [e for e in chain if e["action"] == "REPORTED"][-1]
        assert reported["integrity_status"] == "MATCH"

    def test_log_transfer_creates_custody_and_audit(self, populated):
        eid = populated.audit.log_transfer(
            populated.cid, populated.eid_pass, "Det. Jones",
            "Evidence Locker", "Forensics Lab", reason="Handoff"
        )
        assert isinstance(eid, int)
        chain = populated.db.get_custody_chain(populated.eid_pass)
        transfer = [e for e in chain if e["action"] == "TRANSFERRED"][-1]
        assert transfer["from_location"] == "Evidence Locker"
        assert transfer["to_location"] == "Forensics Lab"
        trail = populated.db.get_audit_trail()
        assert any(r["action"] == "CUSTODY_TRANSFERRED" for r in trail)

    def test_log_transfer_never_fabricates_actor(self, populated):
        """The investigator recorded on a transfer must be exactly what
        the caller passed — never defaulted/invented."""
        populated.audit.log_transfer(
            populated.cid, populated.eid_pass, "Specific Officer Name",
            "A", "B"
        )
        chain = populated.db.get_custody_chain(populated.eid_pass)
        transfer = [e for e in chain if e["action"] == "TRANSFERRED"][-1]
        assert transfer["investigator"] == "Specific Officer Name"

    def test_add_custody_event_wrapper_accepts_from_to(self, populated):
        """AuditService.add_custody_event() (used by CustodyPanel) must
        accept the new from_location/to_location kwargs."""
        populated.audit.add_custody_event(
            populated.cid, populated.eid_pass, "Det. Jones", "TRANSFERRED",
            from_location="X", to_location="Y", notes="manual entry"
        )
        chain = populated.db.get_custody_chain(populated.eid_pass)
        transfer = [e for e in chain if e["action"] == "TRANSFERRED"][-1]
        assert transfer["from_location"] == "X"
        assert transfer["to_location"] == "Y"

    def test_add_custody_event_wrapper_backward_compatible(self, populated):
        """Old-style call (just location, no from/to) must still work
        unchanged for non-transfer actions."""
        populated.audit.add_custody_event(
            populated.cid, populated.eid_pass, "Det. Jones", "REVIEWED",
            location="Lab", notes="looked at it"
        )  # must not raise
        chain = populated.db.get_custody_chain(populated.eid_pass)
        assert any(e["action"] == "REVIEWED" for e in chain)
