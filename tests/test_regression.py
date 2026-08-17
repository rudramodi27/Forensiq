"""
Regression tests — cross-phase end-to-end workflows.

Each test reproduces a specific bug that was found and fixed during
development phases 1–5. If any of these tests fail, a previously fixed
bug has been reintroduced.
"""

import json
import os
import pytest


# ── Phase 1 regressions ───────────────────────────────────────────────────────

class TestPhase1Regressions:
    def test_acquisition_panel_no_dead_also_code(self):
        """P1-FIX: dead .also() guarded by 'if False else' removed from acquisition_panel."""
        import pathlib
        src = pathlib.Path("forensiq/ui/panels/acquisition_panel.py").read_text()
        assert ".also(" not in src, "Dead .also() code reintroduced"
        assert "if False else self._titled_label" not in src

    def test_cases_panel_no_row_get_in_build_detail(self):
        """P1-FIX: sqlite3.Row.get() calls removed from _build_case_detail."""
        import pathlib
        src = pathlib.Path("forensiq/ui/panels/cases_panel.py").read_text()
        start = src.find("def _build_case_detail(")
        end   = src.find("\n    def ", start + 1)
        body  = src[start:end]
        assert 'case.get("description"' not in body
        assert 'case.get("evidence_dir"' not in body
        assert 'case.get("notes"'        not in body

    def test_build_case_detail_does_not_crash(self, populated):
        """P1-FIX: _build_case_detail crashed with AttributeError on sqlite3.Row.get()."""
        import os
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        try:
            from PyQt6.QtWidgets import QApplication
            app = QApplication.instance() or QApplication([])
        except Exception:
            pytest.skip("Qt display not available in this environment")
        from forensiq.ui.panels.cases_panel import CasesPanel
        panel = CasesPanel(populated.db)
        panel.on_shown()
        panel._build_case_detail(populated.cid)   # must not raise

    def test_dashboard_buttons_wired(self):
        """P1-FIX: + New Case and Detect Device buttons were created but never connected."""
        import pathlib
        src = pathlib.Path("forensiq/ui/panels/dashboard.py").read_text()
        assert "btn_new_case.clicked.connect" in src
        assert "btn_detect" in src and "clicked.connect" in src

    def test_verify_all_persists_to_db(self, populated):
        """P1-FIX: _verify_all() called db.verify_evidence() but never persisted results."""
        import pathlib
        src = pathlib.Path("forensiq/ui/panels/cases_panel.py").read_text()
        assert "VerificationWorker" in src, \
            "_verify_all must use VerificationWorker (not synchronous db.verify_evidence loop)"
        start = src.find("def _verify_all(")
        end   = src.find("def _on_verify_all_done(")
        body  = src[start:end]
        assert "self.db.verify_evidence(" not in body

    def test_audit_trail_limit_at_least_5000(self):
        """P1-FIX: default limit raised from 1000 to 5000."""
        import inspect
        from forensiq.core.case_manager import CaseManager
        sig = inspect.signature(CaseManager.get_audit_trail)
        assert sig.parameters["limit"].default >= 5000


# ── Phase 2 regressions ───────────────────────────────────────────────────────

class TestPhase2Regressions:
    def test_audit_evidence_links_populated(self, populated):
        """P2-FIX: audit_evidence_links was always [] — fix populates it from audit_trail."""
        from forensiq.core.analyzer import correlate_artifacts
        corr = correlate_artifacts(populated.ev_dir, populated.db, populated.cid)
        assert len(corr["audit_evidence_links"]) >= 1, \
            "audit_evidence_links is still always empty"

    def test_file_type_filter_implemented(self, populated):
        """P2-FIX: file_type filter was documented but silently ignored."""
        from forensiq.core.analyzer import keyword_search_global
        # Filter by .apk — only eid_fail (malware.apk) should match
        res = keyword_search_global(
            "acquisition", populated.db, populated.cid, {"file_type": "apk"}
        )
        ev_res = [r for r in res if r["source"] == "evidence"]
        assert all(r["id"] == populated.eid_fail for r in ev_res), \
            "file_type filter not filtering correctly"

    def test_file_type_dot_prefix_works(self, populated):
        """P2-FIX: both 'apk' and '.apk' must work identically."""
        from forensiq.core.analyzer import keyword_search_global
        r1 = keyword_search_global(
            "acquisition", populated.db, populated.cid, {"file_type": "apk"}
        )
        r2 = keyword_search_global(
            "acquisition", populated.db, populated.cid, {"file_type": ".apk"}
        )
        assert len(r1) == len(r2)

    def test_suspicious_substring_matching(self):
        """P2-FIX: com.magisk variant not in exact SUSPICIOUS_PACKAGES set."""
        from forensiq.core.analyzer import classify_app
        assert classify_app("com.magisk", "unknown") == "suspicious"
        assert classify_app("com.topjohnwu.magisk", "unknown") == "suspicious"


# ── Phase 3 regressions ───────────────────────────────────────────────────────

class TestPhase3Regressions:
    def test_evidence_summary_report_exists(self):
        """P3-FIX: Evidence Summary report was entirely missing."""
        from forensiq.core.reporter import generate_evidence_summary_report
        assert callable(generate_evidence_summary_report)

    def test_evidence_summary_lists_filenames(self, populated, tmp_path):
        from forensiq.core.reporter import generate_evidence_summary_report
        p = str(tmp_path / "es.html")
        generate_evidence_summary_report(populated.cid, populated.db, p)
        assert "report.txt" in open(p).read()

    def test_pdf_long_filename_no_crash(self, populated, tmp_path):
        """P3-FIX: 150-char filename crashed PDF layout via column overflow."""
        long_fn = "a" * 150 + ".txt"
        populated.db.add_evidence(
            populated.cid, None, "media", long_fn, f"/tmp/{long_fn}", "a" * 64, 0, {}
        )
        from forensiq.core.reporter import generate_pdf_report
        p = str(tmp_path / "long.pdf")
        generate_pdf_report(populated.cid, populated.db, p)
        assert os.path.exists(p) and os.path.getsize(p) > 500

    def test_pdf_cell_wraps_within_column(self):
        """P3-FIX: raw string cells overflowed column by 681pt. Paragraph fixes it."""
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import cm
        from reportlab.platypus import Table, Paragraph
        from reportlab.lib.styles import ParagraphStyle
        PAGE_W    = A4[0] - 4 * cm
        col_width = PAGE_W * 0.22
        wrap_s    = ParagraphStyle("t", fontSize=7, leading=9, wordWrap="CJK")
        para      = Paragraph("x" * 150, wrap_s)
        t         = Table([["H"], [para]], colWidths=[col_width])
        w, _      = t.wrap(col_width, 1000)
        assert abs(w - col_width) < 1, f"PDF overflow not fixed: {w:.0f}pt vs {col_width:.0f}pt"

    def test_null_file_size_no_crash_in_all_reports(self, populated, tmp_path):
        """P3-FIX: NULL file_size crashed multiple report generators."""
        from forensiq.core.reporter import (
            generate_html_report, generate_pdf_report,
            generate_evidence_summary_report,
        )
        for gen, fname in [
            (lambda p: generate_html_report(populated.cid, populated.db, p),     "null.html"),
            (lambda p: generate_pdf_report(populated.cid, populated.db, p),      "null.pdf"),
            (lambda p: generate_evidence_summary_report(populated.cid, populated.db, p), "null_es.html"),
        ]:
            path = str(tmp_path / fname)
            gen(path)
            assert os.path.exists(path), f"{fname} not generated"


# ── Phase 4 regressions ───────────────────────────────────────────────────────

class TestPhase4Regressions:
    def test_get_system_stats_exists(self, db):
        """P4-FIX: dashboard used N+1 query loop; get_system_stats() replaces it."""
        assert hasattr(db, "get_system_stats")
        stats = db.get_system_stats()
        for key in ("cases", "devices", "evidence", "analysis"):
            assert key in stats

    def test_system_stats_counts_all_cases(self, db):
        """P4-FIX: dashboard totals only summed first 5 cases."""
        for i in range(8):
            cid = db.create_case(f"STAT-{i:03d}", "A", "I", "")
            db.add_evidence(cid, None, "acq", "f", "/tmp/f", "h", 0, {})
        stats = db.get_system_stats()
        assert stats["cases"]    == 8
        assert stats["evidence"] == 8

    def test_get_last_verification_per_evidence_exists(self, db):
        """P4-FIX: integrity panel used N+1 per-row get_last_verification()."""
        assert hasattr(db, "get_last_verification_per_evidence")

    def test_batched_verification_correct(self, populated):
        """P4-FIX: batched lookup must return same results as per-item call."""
        rmap = populated.db.get_last_verification_per_evidence(populated.cid)
        assert populated.eid_pass in rmap
        assert rmap[populated.eid_pass]["result"] == "PASS"
        assert populated.eid_fail in rmap
        assert rmap[populated.eid_fail]["result"] == "FAIL"

    def test_batched_verification_single_execute(self):
        """P4-FIX: method must use 1 SQL execute call, not N calls."""
        import pathlib, re
        src = pathlib.Path("forensiq/core/case_manager.py").read_text()
        m = re.search(
            r"def get_last_verification_per_evidence\(self.*?\)(.*?)def \w",
            src, re.DOTALL
        )
        assert m, "get_last_verification_per_evidence not found"
        body = re.sub(r'""".*?"""', "", m.group(1), flags=re.DOTALL)
        assert body.count(".execute(") == 1, \
            f"Expected 1 .execute() call, found {body.count('.execute(')}"
        assert "get_last_verification(" not in body


# ── Phase 5 regressions ───────────────────────────────────────────────────────

class TestPhase5Regressions:
    def test_no_duplicate_sidebar_icons(self):
        """P5-FIX: ⬡ used for Device + Integrity, ◈ for Dashboard + Audit Trail."""
        import pathlib, re
        src = pathlib.Path("forensiq/ui/main_window.py").read_text()
        start = src.find("NAV_ITEMS = ["); end = src.find("]", start) + 1
        labels = re.findall(r'"([^"]+)",\s*"([^"]+)"', src[start:end])
        icons = [lbl.split()[0] for _, lbl in labels if lbl.strip()]
        assert len(icons) == len(set(icons)), \
            f"Duplicate sidebar icons: {[c for c in icons if icons.count(c) > 1]}"

    def test_filter_rows_split_into_two(self):
        """P5-FIX: single filter row overflowed 712px available width by 308px."""
        import pathlib
        src = pathlib.Path("forensiq/ui/panels/analysis_panel.py").read_text()
        assert "# Filter row 1:" in src, "Search filters must be split into 2 rows"
        assert "# Filter row 2:" in src

    def test_status_lbl_has_wordwrap(self):
        """P5-FIX: long error messages clipped in analysis_panel status label."""
        import pathlib
        src = pathlib.Path("forensiq/ui/panels/analysis_panel.py").read_text()
        idx = src.find("self.status_lbl = QLabel(")
        assert idx >= 0
        block = src[idx:idx + 300]
        assert "setWordWrap(True)" in block

    def test_tables_have_minimum_height(self):
        """P5-FIX: 8 tables had minimumHeight=0 and could collapse to invisible."""
        import pathlib
        for fname, min_count in [
            ("analysis_panel.py",    6),
            ("acquisition_panel.py", 1),
            ("cases_panel.py",       1),
        ]:
            src = pathlib.Path(f"forensiq/ui/panels/{fname}").read_text()
            count = src.count("setMinimumHeight(")
            assert count >= min_count, \
                f"{fname}: expected >= {min_count} setMinimumHeight calls, got {count}"

    def test_stylesheet_improvements(self):
        """P5-FIX: sidebar font-weight, header min-height, tab min-width added."""
        import pathlib
        s = pathlib.Path("forensiq/ui/styles.py").read_text()
        assert "font-weight: 500" in s,    "sidebar font-weight: 500 missing"
        assert "min-height: 32px" in s,    "QHeaderView min-height: 32px missing"
        assert "min-width: 80px"  in s,    "QTabBar min-width: 80px missing"


# ── Phase 1 (Evidence Integrity Upgrade) regressions ────────────────────────────

class TestPhase1IntegrityUpgradeRegressions:
    def test_on_progress_no_longer_references_undefined_results(self):
        """
        PRE-EXISTING BUG FIX: IntegrityPanel._on_progress() referenced a
        variable named `results` that was never defined in that scope —
        a NameError waiting to happen on every progress tick once
        `mw.audit` was present. Audit logging belongs only in
        _on_finished(), which already receives `results` as a parameter.
        """
        import pathlib
        src = pathlib.Path("forensiq/ui/panels/integrity_panel.py").read_text()
        start = src.find("def _on_progress(")
        end = src.find("\n    def ", start + 1)
        body = src[start:end]
        assert "for _r in results" not in body
        assert "mw.audit.log_verification" not in body

    def test_device_dedup_present(self):
        """Report fix: add_device() must check for an existing
        (case_id, serial) row before inserting, instead of always
        inserting a new device row on every acquisition run."""
        import pathlib
        src = pathlib.Path("forensiq/core/case_manager.py").read_text()
        start = src.find("def add_device(")
        end = src.find("\n    def ", start + 1)
        body = src[start:end]
        assert "SELECT id FROM devices WHERE case_id = ? AND serial = ?" in body

    def test_analysis_result_dedup_present(self):
        """Report fix: _save_analysis_result() must skip inserting an
        identical (type, summary) result rather than always inserting a
        new row, which caused e.g. 'duplicate_detection' to appear twice
        in reports after re-running analysis with no change in outcome."""
        import pathlib
        src = pathlib.Path("forensiq/ui/panels/analysis_panel.py").read_text()
        start = src.find("def _save_analysis_result(")
        end = src.find("\n    def ", start + 1)
        body = src[start:end]
        assert "latest[\"result_summary\"] == summary" in body

    def test_report_timestamps_are_utc_not_naive_local(self):
        """
        Report fix: every DB-persisted timestamp uses now_utc() (labelled
        '... UTC'), but report "Generated at" timestamps previously used
        naive local datetime.now() with no timezone label — confusing in
        a forensic report. All report generation timestamps must now be
        explicit UTC.

        Phase 10 update: this test originally asserted
        `src.count('datetime.now(timezone.utc)') >= 8` — i.e. it locked
        in eight *separate* inline UTC-now calls. Phase 10 explicitly
        requires the opposite: one centralized timezone utility instead
        of timestamp logic scattered across modules (see
        forensiq/core/time_utils.py). reporter.py's seven
        `ts_gen = datetime.now(timezone.utc).strftime(...)` call sites
        were consolidated into now_utc_str() calls, so the invariant
        this test protects — reporter.py never falls back to naive
        local time — is now checked by asserting on now_utc_str(),
        not on a count of a pattern that no longer belongs in this file.
        """
        import pathlib
        src = pathlib.Path("forensiq/core/reporter.py").read_text()
        assert 'datetime.now().strftime(' not in src, \
            "Naive local datetime.now() reintroduced in reporter.py"
        assert 'datetime.now(timezone.utc)' not in src, (
            "reporter.py should delegate to the centralized "
            "time_utils.now_utc_str() instead of formatting UTC 'now' "
            "inline (Phase 10: no scattered timezone logic)"
        )
        assert src.count('now_utc_str(') >= 8

    def test_audit_export_timestamps_are_utc(self):
        import pathlib
        src = pathlib.Path("forensiq/core/audit_service.py").read_text()
        assert 'datetime.now().strftime(' not in src, \
            "Naive local datetime.now() reintroduced in audit_service.py"

    def test_integrity_engine_importable_without_pyqt6(self):
        """
        IntegrityEngine (pure verification logic) must not require PyQt6
        to import — only VerificationWorker (a QThread) should need it,
        and only when actually instantiated. This lets the engine be
        unit-tested headless / run in non-GUI environments.
        """
        import subprocess, sys
        code = (
            "import sys; sys.modules['PyQt6'] = None; "
            "from forensiq.core.integrity_engine import IntegrityEngine, MATCH; "
            "print('OK')"
        )
        # Simulate PyQt6 being unavailable by removing it from the import
        # path rather than sys.modules trickery (which would just raise
        # ImportError on `import PyQt6` — exactly what we want to confirm
        # IntegrityEngine survives).
        result = subprocess.run(
            [sys.executable, "-c",
             "import builtins; real_import = builtins.__import__\n"
             "def blocked(name, *a, **k):\n"
             "    if name == 'PyQt6' or name.startswith('PyQt6.'):\n"
             "        raise ImportError('blocked for test')\n"
             "    return real_import(name, *a, **k)\n"
             "builtins.__import__ = blocked\n"
             "from forensiq.core.integrity_engine import IntegrityEngine, MATCH\n"
             "print('OK')"],
            capture_output=True, text=True, cwd="."
        )
        assert "OK" in result.stdout, (
            f"IntegrityEngine import failed without PyQt6: {result.stderr}"
        )

    def test_status_vocabulary_upgraded(self):
        """The engine must expose the Phase 1 canonical vocabulary."""
        from forensiq.core.integrity_engine import (
            MATCH, MISMATCH, MISSING, CORRUPTED, NOT_VERIFIED, ERROR,
        )
        assert {MATCH, MISMATCH, MISSING, CORRUPTED, NOT_VERIFIED, ERROR} == {
            "MATCH", "MISMATCH", "MISSING", "CORRUPTED", "NOT_VERIFIED", "ERROR",
        }


# ── Phase 2 (Chain of Custody & Audit Trail) regressions ────────────────────────

class TestPhase2CustodyAuditRegressions:
    def test_lifecycle_actions_extended_not_replaced(self):
        """The Phase 1/pre-Phase-2 custody actions must still all be
        present — Phase 2 must ADD STORED/ANALYZED/REPORTED, not replace
        the existing action set."""
        import pathlib
        src = pathlib.Path("forensiq/core/case_manager.py").read_text()
        start = src.find("_CUSTODY_ACTIONS = frozenset(")
        end = src.find(")", start)
        body = src[start:end]
        for action in ("ACQUIRED", "STORED", "VERIFIED", "TRANSFERRED",
                       "ANALYZED", "REPORTED", "REVIEWED", "EXPORTED",
                       "ARCHIVED", "NOTED"):
            assert action in body, f"{action} missing from _CUSTODY_ACTIONS"

    def test_no_custody_event_update_or_delete_method_added(self):
        """Custody events must stay append-only — Phase 2 must not
        introduce any update/delete capability."""
        from forensiq.core.case_manager import CaseManager
        assert not hasattr(CaseManager, "update_custody_event")
        assert not hasattr(CaseManager, "delete_custody_event")
        assert not hasattr(CaseManager, "edit_custody_event")

    def test_migration_columns_present(self):
        """from_location/to_location/integrity_status must be registered
        in the migration list so existing (pre-Phase-2) databases upgrade
        safely without manual intervention."""
        import pathlib
        src = pathlib.Path("forensiq/core/case_manager.py").read_text()
        start = src.find("_MIGRATIONS = [")
        end = src.find("]", start)
        body = src[start:end]
        assert '"from_location"' in body
        assert '"to_location"' in body
        assert '"integrity_status"' in body
        assert '"custody_events"' in body

    def test_old_db_without_phase2_columns_upgrades_cleanly(self, tmp_path):
        """A database created before Phase 2 (no from_location/to_location/
        integrity_status columns) must be usable after upgrade without
        losing any existing custody data."""
        import sqlite3
        from forensiq.core.case_manager import CaseManager, SCHEMA

        db_path = tmp_path / "legacy.db"
        # Build a pre-Phase-2-shaped custody_events table manually
        conn = sqlite3.connect(str(db_path))
        conn.executescript("""
            CREATE TABLE cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT, case_number TEXT UNIQUE NOT NULL,
                title TEXT NOT NULL, investigator TEXT NOT NULL, description TEXT DEFAULT '',
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active',
                notes TEXT DEFAULT '', evidence_dir TEXT DEFAULT ''
            );
            CREATE TABLE custody_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER, evidence_id INTEGER,
                timestamp TEXT NOT NULL, investigator TEXT NOT NULL DEFAULT '',
                action TEXT NOT NULL, location TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT ''
            );
        """)
        cur = conn.execute(
            "INSERT INTO cases (case_number, title, investigator, created_at, updated_at) "
            "VALUES ('LEGACY-1','T','I','2025-01-01 00:00:00 UTC','2025-01-01 00:00:00 UTC')"
        )
        cid = cur.lastrowid
        conn.execute(
            "INSERT INTO custody_events (case_id, evidence_id, timestamp, investigator, action, location, notes) "
            "VALUES (?, NULL, '2025-01-01 00:00:00 UTC', 'Det. Old', 'ACQUIRED', 'Lab', 'pre-phase2 row')",
            (cid,)
        )
        conn.commit()
        conn.close()

        # Now open with CaseManager — should run migrations without error
        # and the pre-existing row must survive intact.
        db = CaseManager(str(db_path))
        events = db.get_custody_events(case_id=cid)
        assert len(events) == 1
        assert events[0]["action"] == "ACQUIRED"
        assert events[0]["notes"] == "pre-phase2 row"
        # New columns must default to empty string, not crash
        assert events[0]["from_location"] == ""
        assert events[0]["integrity_status"] == ""

        # And new Phase 2 functionality must work on the upgraded DB
        db.add_transfer_event(cid, None, "Det. New", "A", "B")
        events2 = db.get_custody_events(case_id=cid)
        assert len(events2) == 2

    def test_report_generated_creates_both_exported_and_reported(self):
        """log_report_generated() must be extended (not replaced) to also
        emit REPORTED custody events alongside the pre-existing EXPORTED
        ones."""
        import pathlib
        src = pathlib.Path("forensiq/core/audit_service.py").read_text()
        start = src.find("def log_report_generated(")
        end = src.find("\n    def ", start + 1)
        body = src[start:end]
        assert 'action="EXPORTED"' in body
        assert 'action="REPORTED"' in body

    def test_stored_event_gated_on_real_file_existence(self):
        """log_evidence_added() must only log STORED when os.path.exists()
        confirms the file is really there — not unconditionally."""
        import pathlib
        src = pathlib.Path("forensiq/core/audit_service.py").read_text()
        start = src.find("def log_evidence_added(")
        end = src.find("\n    def ", start + 1)
        body = src[start:end]
        assert "os.path.exists(filepath)" in body

    def test_transfer_integrity_never_fabricated_without_verification(self):
        """add_transfer_event() must default to NOT_VERIFIED (not MATCH
        or any other status) when the evidence has never been verified."""
        import pathlib
        src = pathlib.Path("forensiq/core/case_manager.py").read_text()
        start = src.find("def add_transfer_event(")
        end = src.find("\n    def ", start + 1)
        body = src[start:end]
        assert '"NOT_VERIFIED"' in body

    def test_custody_panel_filters_present(self):
        """CustodyPanel must expose event/actor/date filters per Phase 2
        requirement 4."""
        import pathlib
        src = pathlib.Path("forensiq/ui/panels/custody_panel.py").read_text()
        assert "filter_action" in src
        assert "filter_actor" in src
        assert "filter_date_from" in src
        assert "filter_date_to" in src

    def test_audit_panel_date_filters_present(self):
        import pathlib
        src = pathlib.Path("forensiq/ui/panels/audit_panel.py").read_text()
        assert "date_from_input" in src
        assert "date_to_input" in src

    def test_main_report_custody_sections_distinct_from_timeline(self):
        """The Chain of Custody / Transfer History / Audit Summary
        sections must exist separately from (not merged into) the
        Unified Forensic Timeline section.

        Phase 9 (Report Generator 2.0) restructures the main report into
        a fixed 14-section "Full Forensic Investigation Report" order
        (see reporter.py _SECTION_TITLES / _sh()), in which Chain of
        Custody (section 7) — with Evidence Transfer History and Audit
        Summary nested under it as <h3> subsections — now comes BEFORE
        Analysis Findings and the Unified Forensic Timeline (sections
        9-10), superseding the earlier Phase 2 ordering (Timeline before
        Custody) asserted here. The two sections remain just as distinct
        from one another as before — only their relative order changed,
        by explicit new requirement.
        """
        import pathlib
        src = pathlib.Path("forensiq/core/reporter.py").read_text()
        custody_idx  = src.find("_sh('Chain of Custody')")
        transfer_idx = src.find('Paragraph("Evidence Transfer History", h3_s)')
        audit_idx    = src.find('Paragraph("Audit Summary", h3_s)')
        timeline_idx = src.find('_sh("Unified Forensic Timeline")')
        assert custody_idx != -1 and timeline_idx != -1
        assert transfer_idx != -1 and audit_idx != -1
        assert custody_idx < transfer_idx < audit_idx < timeline_idx

    def test_evidence_file_never_written_during_transfer(self):
        """add_transfer_event()/add_custody_event() must not contain any
        file-write operation on the evidence path — custody is metadata
        only."""
        import pathlib
        src = pathlib.Path("forensiq/core/case_manager.py").read_text()
        start = src.find("def add_transfer_event(")
        end = src.find("\n    def get_custody_events", start)
        body = src[start:end]
        assert "open(" not in body
        assert "shutil" not in body
