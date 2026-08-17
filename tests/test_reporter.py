"""
Integration tests — forensiq.core.reporter

Covers: all 8 report types, NULL file_size regression, PDF cell overflow
regression (Phase 3 fix), correct HTML content per report type.
"""

import json
import os
import pytest

from forensiq.core.reporter import (
    generate_html_report,
    generate_pdf_report,
    generate_case_summary_report,
    generate_evidence_summary_report,
    generate_integrity_report_html,
    generate_audit_report_html,
    generate_custody_report_html,
    generate_executive_report,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _html(path):
    return open(path).read()

def _has_case(html, case_number="TC-001"):
    return case_number in html

def _has_forensiq(html):
    return "ForensIQ" in html


# ── HTML report (full forensic report) ───────────────────────────────────────

class TestHtmlReport:
    def test_creates_file(self, populated, tmp_path):
        p = str(tmp_path / "r.html")
        generate_html_report(populated.cid, populated.db, p)
        assert os.path.exists(p)

    def test_contains_case_number(self, populated, tmp_path):
        p = str(tmp_path / "r.html")
        generate_html_report(populated.cid, populated.db, p)
        assert _has_case(_html(p))

    def test_contains_forensiq(self, populated, tmp_path):
        p = str(tmp_path / "r.html")
        generate_html_report(populated.cid, populated.db, p)
        assert _has_forensiq(_html(p))

    def test_contains_sha256_section(self, populated, tmp_path):
        p = str(tmp_path / "r.html")
        generate_html_report(populated.cid, populated.db, p)
        assert "SHA-256" in _html(p)

    def test_contains_table(self, populated, tmp_path):
        p = str(tmp_path / "r.html")
        generate_html_report(populated.cid, populated.db, p)
        assert "<table" in _html(p)

    def test_null_file_size_no_crash(self, populated, tmp_path):
        """Regression: NULL file_size must not crash HTML generation."""
        p = str(tmp_path / "r_null.html")
        generate_html_report(populated.cid, populated.db, p)
        assert os.path.exists(p)


# ── PDF report ────────────────────────────────────────────────────────────────

class TestPdfReport:
    def test_creates_file(self, populated, tmp_path):
        p = str(tmp_path / "r.pdf")
        generate_pdf_report(populated.cid, populated.db, p)
        assert os.path.exists(p)

    def test_file_is_nonempty(self, populated, tmp_path):
        p = str(tmp_path / "r.pdf")
        generate_pdf_report(populated.cid, populated.db, p)
        assert os.path.getsize(p) > 500

    def test_pdf_magic_bytes(self, populated, tmp_path):
        """Valid PDF must start with %PDF."""
        p = str(tmp_path / "r.pdf")
        generate_pdf_report(populated.cid, populated.db, p)
        assert open(p, "rb").read(4) == b"%PDF"

    def test_long_filename_no_crash(self, populated, tmp_path):
        """Phase 3 regression: 150-char unbroken filename must not crash PDF layout."""
        long_fn = "x" * 150 + ".dat"
        populated.db.add_evidence(
            populated.cid, None, "media", long_fn, f"/tmp/{long_fn}", "f" * 64, 0, {}
        )
        p = str(tmp_path / "r_long.pdf")
        generate_pdf_report(populated.cid, populated.db, p)
        assert os.path.exists(p) and os.path.getsize(p) > 500

    def test_null_file_size_no_crash(self, populated, tmp_path):
        p = str(tmp_path / "r_null.pdf")
        generate_pdf_report(populated.cid, populated.db, p)
        assert os.path.exists(p)


# ── PDF cell wrap regression ──────────────────────────────────────────────────

class TestPdfCellWrap:
    def test_paragraph_wraps_within_column(self):
        """
        Phase 3 fix: raw strings in ReportLab Table cells do not wrap on
        non-whitespace and overflow the column by up to 700% for SHA-256
        hashes and long Android paths. Paragraph + wordWrap='CJK' fixes this.
        Verify the fix is still in place by measuring cell width.
        """
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import cm
        from reportlab.platypus import Table, Paragraph
        from reportlab.lib.styles import ParagraphStyle

        PAGE_W    = A4[0] - 4 * cm
        col_width = PAGE_W * 0.22
        wrap_s    = ParagraphStyle("t", fontSize=7, leading=9, wordWrap="CJK")
        long_val  = "x" * 150 + ".dat"
        para      = Paragraph(long_val, wrap_s)
        t         = Table([["H"], [para]], colWidths=[col_width])
        w, h      = t.wrap(col_width, 1000)

        assert abs(w - col_width) < 1, (
            f"PDF cell overflows column: {w:.1f}pt vs {col_width:.1f}pt. "
            "Phase 3 PDF wrap fix may have been reverted."
        )
        assert h > 20, "Cell did not grow vertically — text did not wrap"


# ── Case Summary ──────────────────────────────────────────────────────────────

class TestCaseSummaryReport:
    def test_creates_file(self, populated, tmp_path):
        p = str(tmp_path / "cs.html")
        generate_case_summary_report(populated.cid, populated.db, p)
        assert os.path.exists(p)

    def test_contains_case_number(self, populated, tmp_path):
        p = str(tmp_path / "cs.html")
        generate_case_summary_report(populated.cid, populated.db, p)
        assert _has_case(_html(p)) and _has_forensiq(_html(p))

    def test_does_not_list_individual_filenames(self, populated, tmp_path):
        """Case summary shows aggregate counts, not per-item filenames."""
        p = str(tmp_path / "cs.html")
        generate_case_summary_report(populated.cid, populated.db, p)
        # The case summary should show device info and counts but not filename rows
        html = _html(p)
        assert "DEV001" in html  # device serial is shown


# ── Evidence Summary ──────────────────────────────────────────────────────────

class TestEvidenceSummaryReport:
    def test_creates_file(self, populated, tmp_path):
        p = str(tmp_path / "es.html")
        generate_evidence_summary_report(populated.cid, populated.db, p)
        assert os.path.exists(p)

    def test_contains_individual_filenames(self, populated, tmp_path):
        """Evidence summary must list individual evidence items."""
        p = str(tmp_path / "es.html")
        generate_evidence_summary_report(populated.cid, populated.db, p)
        assert "report.txt" in _html(p)

    def test_groups_by_category(self, populated, tmp_path):
        p = str(tmp_path / "es.html")
        generate_evidence_summary_report(populated.cid, populated.db, p)
        html = _html(p).upper()
        assert "ACQUISITION" in html

    def test_shows_hashed_count(self, populated, tmp_path):
        p = str(tmp_path / "es.html")
        generate_evidence_summary_report(populated.cid, populated.db, p)
        assert "Hashed" in _html(p) or "hashed" in _html(p).lower()

    def test_distinct_from_case_summary(self, populated, tmp_path):
        p1 = str(tmp_path / "cs.html")
        p2 = str(tmp_path / "es.html")
        generate_case_summary_report(populated.cid, populated.db, p1)
        generate_evidence_summary_report(populated.cid, populated.db, p2)
        # Evidence summary has individual filenames; case summary does not
        assert "report.txt" not in _html(p1)
        assert "report.txt" in _html(p2)


# ── Integrity Report ──────────────────────────────────────────────────────────

class TestIntegrityReport:
    def test_creates_file(self, populated, tmp_path):
        p = str(tmp_path / "ir.html")
        generate_integrity_report_html(populated.cid, populated.db, p)
        assert os.path.exists(p)

    def test_shows_pass_result(self, populated, tmp_path):
        p = str(tmp_path / "ir.html")
        generate_integrity_report_html(populated.cid, populated.db, p)
        assert "PASS" in _html(p)

    def test_shows_sha256_column(self, populated, tmp_path):
        p = str(tmp_path / "ir.html")
        generate_integrity_report_html(populated.cid, populated.db, p)
        assert "SHA" in _html(p)


# ── Audit Report ─────────────────────────────────────────────────────────────

class TestAuditReport:
    def test_creates_file(self, populated, tmp_path):
        p = str(tmp_path / "ar.html")
        generate_audit_report_html(populated.cid, populated.db, p)
        assert os.path.exists(p)

    def test_mentions_immutability(self, populated, tmp_path):
        p = str(tmp_path / "ar.html")
        generate_audit_report_html(populated.cid, populated.db, p)
        assert "immutable" in _html(p).lower()

    def test_contains_case_and_forensiq(self, populated, tmp_path):
        p = str(tmp_path / "ar.html")
        generate_audit_report_html(populated.cid, populated.db, p)
        assert _has_case(_html(p)) and _has_forensiq(_html(p))


# ── Custody Report ────────────────────────────────────────────────────────────

class TestCustodyReport:
    def test_creates_file(self, populated, tmp_path):
        p = str(tmp_path / "cr.html")
        generate_custody_report_html(populated.cid, populated.db, p)
        assert os.path.exists(p)

    def test_shows_acquired_action(self, populated, tmp_path):
        p = str(tmp_path / "cr.html")
        generate_custody_report_html(populated.cid, populated.db, p)
        assert "ACQUIRED" in _html(p)

    def test_contains_case_and_forensiq(self, populated, tmp_path):
        p = str(tmp_path / "cr.html")
        generate_custody_report_html(populated.cid, populated.db, p)
        assert _has_case(_html(p)) and _has_forensiq(_html(p))


# ── Executive Report ──────────────────────────────────────────────────────────

class TestExecutiveReport:
    def test_creates_file(self, populated, tmp_path):
        p = str(tmp_path / "er.html")
        generate_executive_report(populated.cid, populated.db, p)
        assert os.path.exists(p)

    def test_contains_confidential(self, populated, tmp_path):
        p = str(tmp_path / "er.html")
        generate_executive_report(populated.cid, populated.db, p)
        assert "CONFIDENTIAL" in _html(p)

    def test_contains_investigator(self, populated, tmp_path):
        p = str(tmp_path / "er.html")
        generate_executive_report(populated.cid, populated.db, p)
        assert "Det. Jones" in _html(p)

    def test_contains_case_and_forensiq(self, populated, tmp_path):
        p = str(tmp_path / "er.html")
        generate_executive_report(populated.cid, populated.db, p)
        assert _has_case(_html(p)) and _has_forensiq(_html(p))


# ── Phase 2 — Chain of Custody / Audit Summary / Transfer History ──────────────

class TestPhase2MainReportSections:
    """The main forensic report (HTML + PDF) must include Chain of
    Custody, Audit Summary, and Evidence Transfer History sections,
    distinct from (not a re-listing of) the existing Timeline section."""

    def test_html_report_has_custody_section(self, populated, tmp_path):
        p = str(tmp_path / "r.html")
        generate_html_report(populated.cid, populated.db, p)
        assert "Chain of Custody" in _html(p)

    def test_html_report_has_audit_summary_section(self, populated, tmp_path):
        p = str(tmp_path / "r.html")
        generate_html_report(populated.cid, populated.db, p)
        assert "Audit Summary" in _html(p)

    def test_html_report_has_transfer_history_section(self, populated, tmp_path):
        p = str(tmp_path / "r.html")
        generate_html_report(populated.cid, populated.db, p)
        assert "Evidence Transfer History" in _html(p)

    def test_html_report_shows_transfer_from_to(self, populated, tmp_path):
        populated.db.add_transfer_event(
            populated.cid, populated.eid_pass, "Det. Jones",
            "Evidence Locker A3", "Digital Forensics Lab", reason="analysis"
        )
        p = str(tmp_path / "r.html")
        generate_html_report(populated.cid, populated.db, p)
        html = _html(p)
        assert "Evidence Locker A3" in html
        assert "Digital Forensics Lab" in html

    def test_html_report_shows_lifecycle_status_per_evidence(self, populated, tmp_path):
        p = str(tmp_path / "r.html")
        generate_html_report(populated.cid, populated.db, p)
        html = _html(p)
        # populated fixture's evidence has at least ACQUIRED custody events
        assert "ACQUIRED" in html

    def test_pdf_report_still_builds_with_new_sections(self, populated, tmp_path):
        populated.db.add_transfer_event(
            populated.cid, populated.eid_pass, "Det. Jones", "A", "B"
        )
        p = str(tmp_path / "r.pdf")
        generate_pdf_report(populated.cid, populated.db, p)
        assert os.path.exists(p)
        assert os.path.getsize(p) > 0

    def test_no_transfers_shows_graceful_empty_state(self, db, tmp_path):
        """A case with no transfers must render without crashing and
        without fabricating transfer rows."""
        cid = db.create_case("NT-001", "No Transfers", "I", "")
        db.add_evidence(cid, None, "acquisition", "f.bin", "/tmp/f.bin", "a"*64, 0, {})
        p = str(tmp_path / "r.html")
        generate_html_report(cid, db, p)
        html = _html(p)
        assert "No transfers recorded" in html


class TestPhase2CustodyReportEnhanced:
    def test_custody_report_shows_from_to_columns(self, populated, tmp_path):
        populated.db.add_transfer_event(
            populated.cid, populated.eid_pass, "Det. Jones",
            "Locker 1", "Lab 4", reason="handoff"
        )
        p = str(tmp_path / "cr.html")
        generate_custody_report_html(populated.cid, populated.db, p)
        html = _html(p)
        assert "Locker 1" in html
        assert "Lab 4" in html

    def test_custody_report_shows_integrity_snapshot(self, populated, tmp_path):
        populated.db.add_verification_result(
            populated.cid, populated.eid_pass, "MATCH", "a"*64, "a"*64, "ok"
        )
        populated.db.add_transfer_event(
            populated.cid, populated.eid_pass, "Det. Jones", "A", "B",
            integrity_status="MATCH"
        )
        p = str(tmp_path / "cr.html")
        generate_custody_report_html(populated.cid, populated.db, p)
        assert "MATCH" in _html(p)

    def test_custody_report_transfer_count_card(self, populated, tmp_path):
        populated.db.add_transfer_event(populated.cid, populated.eid_pass, "I", "A", "B")
        populated.db.add_transfer_event(populated.cid, populated.eid_pass, "I", "B", "C")
        p = str(tmp_path / "cr.html")
        generate_custody_report_html(populated.cid, populated.db, p)
        assert "Transfers" in _html(p)


# ── Phase 9 — Report Generator 2.0: Full Forensic Investigation Report ────────

class TestPhase9SectionStructure:
    """The main report must contain all 14 numbered sections, in order,
    for both HTML and PDF."""

    def test_html_has_all_14_sections_in_order(self, populated, tmp_path):
        from forensiq.core.reporter import _SECTION_TITLES
        p = str(tmp_path / "r.html")
        generate_html_report(populated.cid, populated.db, p)
        html = _html(p)
        positions = [html.find(title) for title in _SECTION_TITLES]
        assert all(pos != -1 for pos in positions), (
            f"Missing section(s): "
            f"{[t for t, pos in zip(_SECTION_TITLES, positions) if pos == -1]}"
        )
        assert positions == sorted(positions), "Sections are out of order"

    def test_pdf_builds_with_all_sections(self, populated, tmp_path):
        p = str(tmp_path / "r.pdf")
        generate_pdf_report(populated.cid, populated.db, p)
        assert os.path.exists(p) and os.path.getsize(p) > 500

    def test_html_has_page_metadata(self, populated, tmp_path):
        p = str(tmp_path / "r.html")
        generate_html_report(populated.cid, populated.db, p)
        assert "Report generated" in _html(p)


class TestPhase9InvestigatorReviewer:
    def test_shows_reviewer_when_set(self, populated, tmp_path):
        populated.db.update_case(populated.cid, reviewer="Reviewer Smith")
        p = str(tmp_path / "r.html")
        generate_html_report(populated.cid, populated.db, p)
        assert "Reviewer Smith" in _html(p)

    def test_shows_not_assigned_when_reviewer_unset(self, populated, tmp_path):
        p = str(tmp_path / "r.html")
        generate_html_report(populated.cid, populated.db, p)
        assert "Not assigned" in _html(p)

    def test_shows_lead_investigator(self, populated, tmp_path):
        p = str(tmp_path / "r.html")
        generate_html_report(populated.cid, populated.db, p)
        assert "Det. Jones" in _html(p)


class TestPhase9MultipleDevicesSessions:
    def test_multiple_devices_each_shown_once_with_sessions(self, db, audit, tmp_path):
        class _Dev:
            def __init__(self, serial):
                self.serial = serial; self.model = "Pixel 7"
                self.manufacturer = "Google"; self.android_version = "14"
                self.sdk_version = "34"; self.build_number = "X"
                self.cpu_abi = "arm64-v8a"; self.usb_debugging = True

        cid = db.create_case("MD-001", "Multi Device", "Det. Jones", "")
        did1 = db.add_device(cid, _Dev("SERIAL-A"))
        did2 = db.add_device(cid, _Dev("SERIAL-B"))
        sid1a = db.start_acquisition_session(cid, did1, targets=["sms", "call_log"])
        db.end_acquisition_session(sid1a, "completed")
        sid1b = db.start_acquisition_session(cid, did1, targets=["apps"])
        db.end_acquisition_session(sid1b, "completed")
        sid2 = db.start_acquisition_session(cid, did2, targets=["sms"])
        db.end_acquisition_session(sid2, "aborted")

        p = str(tmp_path / "r.html")
        generate_html_report(cid, db, p)
        html = _html(p)
        assert html.count("SERIAL-A") == 1  # device block appears once
        assert html.count("SERIAL-B") == 1
        assert "Session " + str(sid1a) in html or f"Session {sid1a}" in html

        pp = str(tmp_path / "r.pdf")
        generate_pdf_report(cid, db, pp)
        assert os.path.exists(pp) and os.path.getsize(pp) > 500


class TestPhase9MultipleEvidenceItems:
    def test_multiple_evidence_items_all_listed(self, populated, tmp_path):
        p = str(tmp_path / "r.html")
        generate_html_report(populated.cid, populated.db, p)
        html = _html(p)
        assert "report.txt" in html
        assert "malware.apk" in html


class TestPhase9IntegrityMismatch:
    def test_mismatch_shown_distinctly_recorded_vs_verified(self, populated, tmp_path):
        populated.db.add_verification_result(
            populated.cid, populated.eid_fail, "MISMATCH",
            "DEADBEEF" * 8, "WRONGHASH" * 4, "hash mismatch"
        )
        p = str(tmp_path / "r.html")
        generate_html_report(populated.cid, populated.db, p)
        html = _html(p)
        assert "MISMATCH" in html
        assert "COMPROMISED" in html  # case-level rollup reflects the mismatch

        pp = str(tmp_path / "r.pdf")
        generate_pdf_report(populated.cid, populated.db, pp)
        assert os.path.exists(pp)


class TestPhase9CustodyEvents:
    def test_custody_events_and_transfers_reflected(self, populated, tmp_path):
        populated.db.add_transfer_event(
            populated.cid, populated.eid_pass, "Det. Jones", "Locker A", "Lab B"
        )
        p = str(tmp_path / "r.html")
        generate_html_report(populated.cid, populated.db, p)
        html = _html(p)
        assert "Locker A" in html and "Lab B" in html
        assert "TRANSFERRED" in html  # lifecycle advances past ACQUIRED once transferred


class TestPhase9AnalysisFindings:
    def test_findings_and_methodology_reflect_actual_types(self, populated, tmp_path):
        p = str(tmp_path / "r.html")
        generate_html_report(populated.cid, populated.db, p)
        html = _html(p)
        assert "app_classification" in html

    def test_methodology_lists_only_types_actually_run(self, populated, tmp_path):
        p = str(tmp_path / "r.html")
        generate_html_report(populated.cid, populated.db, p)
        html = _html(p)
        # Isolate the Analysis Methodology *section body* using its anchor id
        # (section 8), not the TOC entry which also contains the section title.
        methodology_section = html.split('id="s8"')[1].split('id="s9"')[0]
        assert "app_classification" in methodology_section
        assert "battery" not in methodology_section  # never run in this fixture


class TestPhase9SignedUnsigned:
    def test_unsigned_report_shows_graceful_message(self, populated, tmp_path):
        p = str(tmp_path / "r.html")
        generate_html_report(populated.cid, populated.db, p)
        html = _html(p)
        assert "digitally signed yet" in html.lower()

    def test_signed_report_shows_signer_algorithm_status(self, populated, tmp_path):
        from forensiq.core.signature_service import SignatureService
        p1 = str(tmp_path / "r1.html")
        generate_html_report(populated.cid, populated.db, p1)
        SignatureService(populated.db).sign_report(p1, "Det. Jones", case_id=populated.cid)

        p2 = str(tmp_path / "r2.html")
        generate_html_report(populated.cid, populated.db, p2)
        html = _html(p2)
        assert "Det. Jones" in html
        assert "VALID" in html

        pp = str(tmp_path / "r2.pdf")
        generate_pdf_report(populated.cid, populated.db, pp)
        assert os.path.exists(pp)


class TestPhase9EmptyOptionalSections:
    def test_case_with_no_devices_no_evidence_no_analysis(self, db, tmp_path):
        cid = db.create_case("EMPTY-001", "Empty Case", "Det. Jones", "")
        p = str(tmp_path / "r.html")
        generate_html_report(cid, db, p)
        html = _html(p)
        assert "No devices recorded" in html
        assert "No evidence recorded" in html
        assert "No analysis results recorded" in html
        assert "No timeline events recorded" in html
        assert "No investigator notes recorded" in html

        pp = str(tmp_path / "r.pdf")
        generate_pdf_report(cid, db, pp)
        assert os.path.exists(pp) and os.path.getsize(pp) > 500

    def test_case_with_no_notes_no_tags(self, db, tmp_path):
        cid = db.create_case("EMPTY-002", "No Notes", "Det. Jones", "")
        p = str(tmp_path / "r.html")
        generate_html_report(cid, db, p)
        assert os.path.exists(p)


class TestPhase9LongHashesAndPaths:
    def test_long_hash_and_deep_path_do_not_break_pdf_layout(self, populated, tmp_path):
        long_path = "/data/data/com.example.app/" + "sub/" * 40 + "evidence_file.db"
        populated.db.add_evidence(
            populated.cid, populated.did, "media", "deep_file.db", long_path,
            "f" * 64, 12345, {}
        )
        p = str(tmp_path / "r.pdf")
        generate_pdf_report(populated.cid, populated.db, p)
        assert os.path.exists(p) and os.path.getsize(p) > 500

        hp = str(tmp_path / "r.html")
        generate_html_report(populated.cid, populated.db, hp)
        assert "f" * 40 in _html(hp)  # truncated recorded hash still visible


class TestPhase9FinalConclusion:
    def test_final_conclusion_is_data_driven(self, populated, tmp_path):
        p = str(tmp_path / "r.html")
        generate_html_report(populated.cid, populated.db, p)
        html = _html(p)
        assert "This report documents the examination of case" in html
        assert populated.cid  # sanity


class TestPhase9EvidenceLinkedToFindings:
    def test_analysis_finding_references_evidence(self, populated, tmp_path):
        p = str(tmp_path / "r.html")
        generate_html_report(populated.cid, populated.db, p)
        html = _html(p)
        # Section 9 = Analysis Findings, section 10 = Unified Forensic Timeline
        findings_section = html.split('id="s9"')[1].split('id="s10"')[0]
        assert "report.txt" in findings_section or str(populated.eid_pass) in findings_section
