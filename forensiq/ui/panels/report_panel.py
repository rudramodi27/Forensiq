"""
Phase 5 — Report Generation panel.

Reports available:
  ◩  HTML Report         — full forensic report (evidence, analysis, timeline)
  ⬡  PDF Report          — same content as PDF via ReportLab
  📋  Case Summary        — concise one-page case overview
  🔐  Integrity Report   — per-item hash verification status
  🗒️  Audit Report        — immutable audit trail for this case
  🔗  Custody Report     — complete chain of custody by evidence item
  📊  Executive Report   — non-technical summary for stakeholders
  🔬  Analysis Report    — full analysis engine output (JSON + HTML)

FIXES:
  - BUG#1: Progress bar range was 0,0 — now 0,100
  - BUG#2: _on_done re-enabled both buttons regardless of source — fixed
  - BUG#3: _open_in_browser silently failed if last report was PDF — fixed
  - BUG#4: preview HTML used f-string directly on sqlite3.Row — fixed
  - UI:  Export path label wraps; preview browser minimum height set
  - UI:  All 8 report type buttons visible; matched height and spacing
"""

import os
import webbrowser
from datetime import datetime

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QComboBox, QFrame, QFileDialog, QGroupBox,
    QTextBrowser, QProgressBar, QSizePolicy, QMessageBox,
    QGridLayout,
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont

from forensiq.core.case_manager import CaseManager
from forensiq.core.reporter import (
    generate_html_report,
    generate_pdf_report,
    generate_case_summary_report,
    generate_evidence_summary_report,
    generate_integrity_report_html,
    generate_audit_report_html,
    generate_custody_report_html,
    generate_executive_report,
    generate_case_evidence_manifest_report,
)
from forensiq.core.manifest_service import (
    build_manifest,
    export_manifest_json,
    export_manifest_csv,
)
from forensiq.core.analyzer import generate_analysis_report


class ReportWorker(QThread):
    finished = pyqtSignal(str, str)   # path, report_type
    error    = pyqtSignal(str)

    def __init__(self, report_type: str, case_id: int,
                 db: CaseManager, output_path: str,
                 evidence_dir: str = ""):
        super().__init__()
        self.report_type  = report_type
        self.case_id      = case_id
        self.db           = db
        self.output_path  = output_path
        self.evidence_dir = evidence_dir

    def run(self):
        try:
            rt = self.report_type
            if rt == "html":
                path = generate_html_report(self.case_id, self.db, self.output_path)
            elif rt == "pdf":
                path = generate_pdf_report(self.case_id, self.db, self.output_path)
            elif rt == "case_summary":
                path = generate_case_summary_report(self.case_id, self.db, self.output_path)
            elif rt == "evidence_summary":
                path = generate_evidence_summary_report(self.case_id, self.db, self.output_path)
            elif rt == "integrity":
                path = generate_integrity_report_html(self.case_id, self.db, self.output_path)
            elif rt == "audit":
                path = generate_audit_report_html(self.case_id, self.db, self.output_path)
            elif rt == "custody":
                path = generate_custody_report_html(self.case_id, self.db, self.output_path)
            elif rt == "executive":
                path = generate_executive_report(self.case_id, self.db, self.output_path)
            elif rt == "manifest":
                path = generate_case_evidence_manifest_report(self.case_id, self.db, self.output_path)
            elif rt == "analysis":
                out_dir = os.path.dirname(self.output_path)
                paths   = generate_analysis_report(
                    self.case_id, self.db, self.evidence_dir, out_dir
                )
                path = paths["html"]   # primary artefact is the HTML
            else:
                raise ValueError(f"Unknown report type: {rt!r}")
            self.finished.emit(path, rt)
        except Exception as e:
            self.error.emit(str(e))


class ReportPanel(QWidget):
    def __init__(self, db: CaseManager, parent=None):
        super().__init__(parent)
        self.db                    = db
        self._current_case_id: int | None = None
        self._current_evidence_dir: str   = ""
        self._worker               = None
        self._last_html: str | None       = None
        self._build()

    # ── Build ──────────────────────────────────────────────────────────────────

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(14)

        # Config card
        cfg = QFrame(); cfg.setObjectName("card")
        cl  = QVBoxLayout(cfg)
        cl.setContentsMargins(16, 14, 16, 14)
        cl.setSpacing(10)
        cl.addWidget(self._bold("Report Configuration"))

        r1 = QHBoxLayout()
        r1.addWidget(QLabel("Case:"))
        self.case_combo = QComboBox()
        self.case_combo.setMinimumWidth(340)
        self.case_combo.setPlaceholderText("Select case…")
        self.case_combo.currentIndexChanged.connect(self._on_case_changed)
        r1.addWidget(self.case_combo, 1)
        cl.addLayout(r1)

        r2 = QHBoxLayout()
        r2.addWidget(QLabel("Output:"))
        self.out_dir_lbl = QLabel(
            os.path.join(os.path.expanduser("~"), "ForensIQ", "reports")
        )
        self.out_dir_lbl.setObjectName("metaLabel")
        self.out_dir_lbl.setWordWrap(True)
        browse = QPushButton("Browse…")
        browse.setFixedWidth(80)
        browse.clicked.connect(self._browse)
        r2.addWidget(self.out_dir_lbl, 1)
        r2.addWidget(browse)
        cl.addLayout(r2)
        layout.addWidget(cfg)

        # Report types grid
        rg = QFrame(); rg.setObjectName("card")
        rl = QVBoxLayout(rg)
        rl.setContentsMargins(16, 14, 16, 14)
        rl.setSpacing(10)
        rl.addWidget(self._bold("Generate Report"))

        grid = QGridLayout()
        grid.setSpacing(8)

        BTN_H = 38
        self._report_buttons: dict[str, QPushButton] = {}
        report_defs = [
            ("html",             "◩  HTML Report",          "Full forensic report (HTML)",          0, 0),
            ("pdf",              "⬡  PDF Report",            "Full forensic report (PDF)",           0, 1),
            ("case_summary",     "📋  Case Summary",          "Concise one-page case overview",       0, 2),
            ("evidence_summary", "📦  Evidence Summary",      "Per-item evidence inventory",          1, 0),
            ("executive",        "📊  Executive Report",      "Non-technical summary",                1, 1),
            ("integrity",        "🔐  Integrity Report",      "Hash verification status per item",    1, 2),
            ("audit",            "🗒️  Audit Report",          "Immutable audit trail for this case",  2, 0),
            ("custody",          "🔗  Custody Report",        "Chain of custody by evidence item",    2, 1),
            ("analysis",         "🔬  Analysis Report",       "Full analysis engine output",          2, 2),
            ("manifest",         "🧾  Case Manifest",         "Case Evidence Manifest (Generate/View)", 3, 0),
        ]
        for rt, label, tooltip, row, col in report_defs:
            btn = QPushButton(label)
            btn.setObjectName("primaryBtn")
            btn.setFixedHeight(BTN_H)
            btn.setToolTip(tooltip)
            btn.clicked.connect(lambda checked, r=rt: self._generate(r))
            self._report_buttons[rt] = btn
            grid.addWidget(btn, row, col)

        rl.addLayout(grid)

        # Open / progress row
        bottom_row = QHBoxLayout()
        self.btn_open = QPushButton("↗  Open Last HTML")
        self.btn_open.setFixedHeight(BTN_H)
        self.btn_open.setEnabled(False)
        self.btn_open.clicked.connect(self._open_html)
        bottom_row.addWidget(self.btn_open)
        self.btn_manifest_json = QPushButton("⇩  Export Manifest JSON")
        self.btn_manifest_json.setFixedHeight(BTN_H)
        self.btn_manifest_json.setToolTip(
            "Export the Case Evidence Manifest as manifest.json"
        )
        self.btn_manifest_json.clicked.connect(lambda: self._export_manifest("json"))
        bottom_row.addWidget(self.btn_manifest_json)
        self.btn_manifest_csv = QPushButton("⇩  Export Manifest CSV")
        self.btn_manifest_csv.setFixedHeight(BTN_H)
        self.btn_manifest_csv.setToolTip(
            "Export the Case Evidence Manifest as manifest.csv"
        )
        self.btn_manifest_csv.clicked.connect(lambda: self._export_manifest("csv"))
        bottom_row.addWidget(self.btn_manifest_csv)
        bottom_row.addStretch()
        rl.addLayout(bottom_row)

        # Progress + status
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setVisible(False)
        rl.addWidget(self.progress)

        self.status_lbl = QLabel("Select a case and choose a report type.")
        self.status_lbl.setObjectName("metaLabel")
        self.status_lbl.setWordWrap(True)
        rl.addWidget(self.status_lbl)
        layout.addWidget(rg)

        # Preview
        pg = QGroupBox("Case Summary Preview")
        pl = QVBoxLayout(pg)
        self.preview = QTextBrowser()
        self.preview.setOpenExternalLinks(True)
        self.preview.setMinimumHeight(200)
        pl.addWidget(self.preview)
        layout.addWidget(pg, 1)

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _bold(self, text: str) -> QLabel:
        l = QLabel(text)
        l.setFont(QFont("Segoe UI", 13, QFont.Weight.Bold))
        return l

    def _set_buttons_enabled(self, enabled: bool):
        for btn in self._report_buttons.values():
            btn.setEnabled(enabled)

    # ── Lifecycle ──────────────────────────────────────────────────────────────

    def on_shown(self):
        self.case_combo.blockSignals(True)
        self.case_combo.clear()
        for case in self.db.get_all_cases():
            self.case_combo.addItem(
                f"{case['case_number']} — {case['title']}", userData=case["id"]
            )
        self.case_combo.blockSignals(False)
        if self.case_combo.count():
            self._on_case_changed(0)

    def _on_case_changed(self, idx: int):
        cid = self.case_combo.itemData(idx)
        if cid:
            self._current_case_id = cid
            case = self.db.get_case(cid)
            self._current_evidence_dir = (
                (case["evidence_dir"] or "").strip() if case else ""
            )
            self._refresh_preview(cid)

    def _refresh_preview(self, case_id: int):
        case = self.db.get_case(case_id)
        if not case:
            return
        cn   = str(case["case_number"] or "")
        ttl  = str(case["title"] or "")
        inv  = str(case["investigator"] or "")
        st   = str(case["status"] or "unknown")
        cat  = str(case["created_at"] or "")[:16]
        ev_dir = str(case["evidence_dir"] or "—")
        dev_list = self.db.get_devices_for_case(case_id)
        ev_count = self.db.get_evidence_count(case_id)
        an_count = len(self.db.get_analysis_results(case_id))
        tl_count = len(self.db.get_timeline(case_id))
        vr_summ  = self.db.get_verification_summary(case_id)
        st_color = "#3FB950" if st.upper() == "ACTIVE" else "#8B949E"

        pass_c   = vr_summ.get("PASS", 0)
        fail_c   = vr_summ.get("FAIL", 0) + vr_summ.get("MISSING", 0)

        html = f"""
        <h2 style="color:#1D9E75;margin:0 0 4px">{cn}</h2>
        <p style="color:#8B949E;margin:0 0 12px">{ttl}</p>
        <table style="width:100%;font-size:12px;border-collapse:collapse">
          <tr><td style="color:#8B949E;padding:4px 0;width:160px">Investigator</td>
              <td><b>{inv}</b></td></tr>
          <tr><td style="color:#8B949E;padding:4px 0">Created</td>
              <td>{cat}</td></tr>
          <tr><td style="color:#8B949E;padding:4px 0">Status</td>
              <td><span style="color:{st_color}">{st.upper()}</span></td></tr>
          <tr><td style="color:#8B949E;padding:4px 0">Devices</td>
              <td><b>{len(dev_list)}</b></td></tr>
          <tr><td style="color:#8B949E;padding:4px 0">Evidence Items</td>
              <td><b style="color:#E3B341">{ev_count}</b></td></tr>
          <tr><td style="color:#8B949E;padding:4px 0">Analysis Results</td>
              <td><b>{an_count}</b></td></tr>
          <tr><td style="color:#8B949E;padding:4px 0">Timeline Events</td>
              <td><b>{tl_count}</b></td></tr>
          <tr><td style="color:#8B949E;padding:4px 0">Hash Verification</td>
              <td><span style="color:#3FB950">{pass_c} PASS</span>
              {"  &nbsp;&nbsp;<span style='color:#F85149'>"+str(fail_c)+" ISSUE(S)</span>" if fail_c else ""}</td></tr>
          <tr><td style="color:#8B949E;padding:4px 0">Evidence Dir</td>
              <td style="font-size:11px;color:#8B949E">{ev_dir}</td></tr>
        </table>
        {f'<hr style="border:1px solid #21262D;margin:10px 0"><p style="color:#8B949E;font-size:12px"><b>Notes:</b> {str(case["notes"] or "")}</p>' if (case["notes"] or "").strip() else ""}
        """
        self.preview.setHtml(html)

    def _browse(self):
        path = QFileDialog.getExistingDirectory(
            self, "Output Directory", self.out_dir_lbl.text()
        )
        if path:
            self.out_dir_lbl.setText(path)

    # ── Generation ─────────────────────────────────────────────────────────────

    def _generate(self, report_type: str):
        if not self._current_case_id:
            self.status_lbl.setText("Select a case first.")
            return
        out_dir = self.out_dir_lbl.text().strip()
        if not out_dir:
            self.status_lbl.setText("Set an output directory first.")
            return
        try:
            os.makedirs(out_dir, exist_ok=True)
        except OSError as e:
            self.status_lbl.setText(f"Cannot create output directory: {e}")
            return

        case = self.db.get_case(self._current_case_id)
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        cn   = case["case_number"] if case else "case"

        ext_map = {
            "html":             "html", "pdf":              "pdf",
            "case_summary":     "html", "evidence_summary": "html",
            "integrity":        "html",
            "audit":            "html", "custody":          "html",
            "executive":        "html", "analysis":         "html",
            "manifest":         "html",
        }
        suffix_map = {
            "html":             "Report",          "pdf":              "Report",
            "case_summary":     "CaseSummary",     "evidence_summary": "EvidenceSummary",
            "integrity":        "Integrity",
            "audit":            "AuditTrail",      "custody":          "ChainOfCustody",
            "executive":        "Executive",       "analysis":         "Analysis",
            "manifest":         "EvidenceManifest",
        }
        ext    = ext_map.get(report_type, "html")
        suffix = suffix_map.get(report_type, report_type.title())
        path   = os.path.join(out_dir, f"ForensIQ_{cn}_{suffix}_{ts}.{ext}")

        self._set_buttons_enabled(False)
        self.btn_open.setEnabled(False)
        self.progress.setVisible(True)
        self.progress.setValue(20)
        self.status_lbl.setText(f"Generating {suffix} …")

        ev_dir = self._current_evidence_dir
        self._worker = ReportWorker(
            report_type, self._current_case_id, self.db, path,
            evidence_dir=ev_dir
        )
        self._worker.finished.connect(self._on_done)
        self._worker.error.connect(self._on_error)
        self._worker.start()

    def _on_done(self, path: str, report_type: str):
        self._set_buttons_enabled(True)
        self.progress.setValue(100)
        self.progress.setVisible(False)
        self.status_lbl.setText(f"✔ Saved: {path}")
        # Enable Open button for HTML outputs
        if path.endswith(".html") and os.path.exists(path):
            self._last_html = path
            self.btn_open.setEnabled(True)
        # Audit log
        mw = self.window()
        if hasattr(mw, "audit") and self._current_case_id:
            case = self.db.get_case(self._current_case_id)
            inv  = case["investigator"] if case else ""
            mw.audit.log_report_generated(
                self._current_case_id, inv, report_type.upper(), path
            )

    def _on_error(self, msg: str):
        self._set_buttons_enabled(True)
        self.progress.setVisible(False)
        self.status_lbl.setText(f"Error: {msg}")
        QMessageBox.critical(self, "Report Generation Failed", msg)

    def _export_manifest(self, fmt: str):
        """
        Case Evidence Manifest — Export JSON / Export CSV action.
        Runs synchronously (DB reads + a JSON/CSV dump — no ADB/hashing
        work, so no QThread needed here, unlike the report generators).
        """
        if not self._current_case_id:
            self.status_lbl.setText("Select a case first.")
            return
        out_dir = self.out_dir_lbl.text().strip()
        if not out_dir:
            self.status_lbl.setText("Set an output directory first.")
            return
        try:
            os.makedirs(out_dir, exist_ok=True)
        except OSError as e:
            self.status_lbl.setText(f"Cannot create output directory: {e}")
            return

        case = self.db.get_case(self._current_case_id)
        cn   = case["case_number"] if case else "case"
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        ext  = "json" if fmt == "json" else "csv"
        path = os.path.join(out_dir, f"ForensIQ_{cn}_EvidenceManifest_{ts}.{ext}")

        try:
            manifest = build_manifest(self._current_case_id, self.db)
            if fmt == "json":
                export_manifest_json(manifest, path)
            else:
                export_manifest_csv(manifest, path)
        except Exception as e:
            self.status_lbl.setText(f"Manifest export failed: {e}")
            QMessageBox.critical(self, "Manifest Export Failed", str(e))
            return

        self.status_lbl.setText(f"✔ Saved: {path}")
        mw = self.window()
        if hasattr(mw, "audit") and self._current_case_id:
            inv = case["investigator"] if case else ""
            mw.audit.log_report_generated(
                self._current_case_id, inv, f"MANIFEST_{fmt.upper()}", path
            )

    def _open_html(self):
        if self._last_html and os.path.exists(self._last_html):
            webbrowser.open(f"file://{os.path.abspath(self._last_html)}")
        else:
            QMessageBox.information(
                self, "No HTML Report",
                "Generate an HTML report first, then click Open."
            )
