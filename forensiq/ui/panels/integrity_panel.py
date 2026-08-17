"""
Integrity Verification Panel — Phase 6, upgraded in Phase 1 (Evidence
Integrity Upgrade).

Buttons:  Verify Selected | Verify Case | Verify All Evidence | Export JSON | Export HTML
Display:  MATCH / MISMATCH / MISSING / CORRUPTED / NOT_VERIFIED / ERROR per evidence item,
          original + current SHA-256, last verification time, case integrity summary
History:  verification_results table, newest-first, per-item detail on click
"""

import os
import json
import logging
from datetime import datetime

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QComboBox, QTableWidget, QTableWidgetItem, QFrame,
    QHeaderView, QProgressBar, QSplitter, QTextEdit,
    QFileDialog, QSizePolicy, QGroupBox, QScrollArea,
    QMessageBox,
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QColor, QBrush

from forensiq.core.case_manager import CaseManager
from forensiq.core.integrity_engine import (
    IntegrityEngine, VerificationWorker,
    MATCH, MISMATCH, MISSING, CORRUPTED, NOT_VERIFIED, ERROR,
    RESULT_COLORS, normalize_status,
    # Backward-compatible aliases, still importable by name:
    PASS, FAIL,
)
from forensiq.core.time_utils import format_dual_plain

logger = logging.getLogger("forensiq.integrity_panel")

# Status color map for table cells
_COL = {
    MATCH:        QColor("#3FB950"),
    MISMATCH:     QColor("#F85149"),
    MISSING:      QColor("#E3B341"),
    CORRUPTED:    QColor("#F85149"),
    NOT_VERIFIED: QColor("#8B949E"),
    ERROR:        QColor("#8B949E"),
}
_BG = {
    MATCH:        QColor("#3FB95015"),
    MISMATCH:     QColor("#F8514915"),
    MISSING:      QColor("#E3B34115"),
    CORRUPTED:    QColor("#F8514915"),
    NOT_VERIFIED: QColor("#8B949E15"),
    ERROR:        QColor("#8B949E15"),
}

# Statuses that warrant a prominent warning banner in the UI.
_WARNING_STATUSES = {MISMATCH, MISSING, CORRUPTED}


def _colored_item(text: str, result: str) -> QTableWidgetItem:
    """Color a table cell by verification status. Normalizes legacy
    PASS/FAIL rows (written before the Phase 1 vocabulary upgrade) to
    their canonical MATCH/MISMATCH equivalent so old data still colors
    correctly."""
    status = normalize_status(result)
    item = QTableWidgetItem(text)
    item.setForeground(QBrush(_COL.get(status, QColor("#E6EDF3"))))
    item.setBackground(QBrush(_BG.get(status, QColor("#00000000"))))
    return item


class IntegrityPanel(QWidget):
    def __init__(self, db: CaseManager, parent=None):
        super().__init__(parent)
        self.db      = db
        self.engine  = IntegrityEngine(db)
        self._worker: VerificationWorker | None = None
        self._current_case_id: int | None       = None
        self._results: list[dict]               = []
        self._build()

    # ── Layout ────────────────────────────────────────────────────────

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 24, 24, 24)
        root.setSpacing(14)

        # ── Top: case selector + summary cards ────────────────────────
        top_frame = QFrame(); top_frame.setObjectName("card")
        tf_l = QVBoxLayout(top_frame); tf_l.setContentsMargins(14, 12, 14, 12); tf_l.setSpacing(10)

        sel_row = QHBoxLayout()
        sel_row.addWidget(QLabel("Case:"))
        self.case_combo = QComboBox()
        self.case_combo.setMinimumWidth(320)
        self.case_combo.setPlaceholderText("Select case…")
        self.case_combo.currentIndexChanged.connect(self._on_case_changed)
        sel_row.addWidget(self.case_combo, 1)
        sel_row.addStretch()
        tf_l.addLayout(sel_row)

        # Case Integrity Summary banner — overall VERIFIED / COMPROMISED /
        # INCOMPLETE / NOT_VERIFIED status for the selected case, based on
        # each evidence item's most recent verification.
        self.overall_banner = QLabel("Select a case to see its integrity status.")
        self.overall_banner.setObjectName("metaLabel")
        self.overall_banner.setStyleSheet(
            "padding:8px 12px;border-radius:6px;font-weight:600;"
            "background:#8B949E15;color:#8B949E;"
        )
        tf_l.addWidget(self.overall_banner)

        # Summary cards — per-evidence CURRENT integrity status (Case
        # Integrity Summary), distinct from the historical "attempts"
        # summary shown further below the toolbar.
        cards_row = QHBoxLayout(); cards_row.setSpacing(10)
        self._summary_labels: dict[str, QLabel] = {}
        card_defs = [
            ("total",        "Total",        "#E6EDF3"),
            (MATCH,          "MATCH",        RESULT_COLORS[MATCH]),
            (MISMATCH,       "MISMATCH",     RESULT_COLORS[MISMATCH]),
            (MISSING,        "MISSING",      RESULT_COLORS[MISSING]),
            (CORRUPTED,      "CORRUPTED",    RESULT_COLORS[CORRUPTED]),
            (NOT_VERIFIED,   "NOT VERIFIED", RESULT_COLORS[NOT_VERIFIED]),
        ]
        for key, lbl, color in card_defs:
            box = QFrame(); box.setObjectName("card")
            bl  = QVBoxLayout(box); bl.setContentsMargins(12, 8, 12, 8); bl.setSpacing(2)
            num = QLabel("—")
            num.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
            num.setStyleSheet(f"color:{color};")
            nl  = QLabel(lbl); nl.setObjectName("metaLabel")
            bl.addWidget(num); bl.addWidget(nl)
            self._summary_labels[key] = num
            cards_row.addWidget(box)
        tf_l.addLayout(cards_row)
        root.addWidget(top_frame)

        # Warning banner for MISMATCH/MISSING/CORRUPTED — hidden by default,
        # shown after any verification run that finds a problem.
        self.warning_banner = QLabel("")
        self.warning_banner.setObjectName("dangerLabel")
        self.warning_banner.setStyleSheet(
            "padding:10px 14px;border-radius:6px;font-weight:700;"
            "background:#F8514920;color:#F85149;border:1px solid #F8514960;"
        )
        self.warning_banner.setVisible(False)
        root.addWidget(self.warning_banner)

        # ── Action toolbar ────────────────────────────────────────────
        tb = QHBoxLayout(); tb.setSpacing(8)

        self.btn_selected = QPushButton("⬡  Verify Evidence")
        self.btn_case     = QPushButton("◉  Verify Case")
        self.btn_all      = QPushButton("⬢  Verify All Evidence")
        self.btn_stop     = QPushButton("■  Stop")
        self.btn_json     = QPushButton("↓  Export JSON")
        self.btn_html     = QPushButton("↓  Export HTML")

        self.btn_selected.setObjectName("primaryBtn")
        self.btn_case.setObjectName("primaryBtn")
        self.btn_all.setObjectName("primaryBtn")
        self.btn_stop.setObjectName("dangerBtn"); self.btn_stop.setEnabled(False)

        self.btn_selected.clicked.connect(lambda: self._run("single"))
        self.btn_case.clicked.connect(lambda: self._run("case"))
        self.btn_all.clicked.connect(lambda: self._run("all"))
        self.btn_stop.clicked.connect(self._stop)
        self.btn_json.clicked.connect(self._export_json)
        self.btn_html.clicked.connect(self._export_html)

        for b in (self.btn_selected, self.btn_case, self.btn_all, self.btn_stop):
            tb.addWidget(b)
        tb.addSpacing(12)
        for b in (self.btn_json, self.btn_html):
            tb.addWidget(b)
        tb.addStretch()
        root.addLayout(tb)

        # Progress
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(False)
        root.addWidget(self.progress_bar)

        self.progress_lbl = QLabel("Select a case and run verification.")
        self.progress_lbl.setObjectName("metaLabel")
        root.addWidget(self.progress_lbl)

        # ── Main splitter: evidence table | history ────────────────────
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)

        # Left: evidence table
        left = QWidget()
        ll   = QVBoxLayout(left); ll.setContentsMargins(0, 0, 0, 0); ll.setSpacing(6)
        ev_lbl = QLabel("Evidence")
        ev_lbl.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        ll.addWidget(ev_lbl)

        self.ev_table = QTableWidget(0, 7)
        self.ev_table.setHorizontalHeaderLabels(
            ["ID", "Filename", "Category", "Original SHA-256",
             "Verified SHA-256", "Last Result", "Verified At"]
        )
        self.ev_table.setAlternatingRowColors(True)
        self.ev_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.ev_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.ev_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.ev_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch
        )
        self.ev_table.setColumnWidth(0, 40)
        self.ev_table.setColumnWidth(2, 90)
        self.ev_table.setColumnWidth(3, 150)
        self.ev_table.setColumnWidth(4, 150)
        self.ev_table.setColumnWidth(5, 90)
        self.ev_table.setColumnWidth(6, 130)
        self.ev_table.setMinimumHeight(200)
        self.ev_table.currentCellChanged.connect(self._on_ev_selected)
        ll.addWidget(self.ev_table, 1)
        splitter.addWidget(left)

        # Right: per-item history + detail
        right = QWidget()
        rl    = QVBoxLayout(right); rl.setContentsMargins(0, 0, 0, 0); rl.setSpacing(6)

        hist_lbl = QLabel("Verification History")
        hist_lbl.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        rl.addWidget(hist_lbl)

        self.hist_table = QTableWidget(0, 4)
        self.hist_table.setHorizontalHeaderLabels(["Result", "Verified At", "Stored Hash", "Notes"])
        self.hist_table.setAlternatingRowColors(True)
        self.hist_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.hist_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.hist_table.horizontalHeader().setSectionResizeMode(
            3, QHeaderView.ResizeMode.Stretch
        )
        self.hist_table.setColumnWidth(0, 70)
        self.hist_table.setColumnWidth(1, 130)
        self.hist_table.setColumnWidth(2, 140)
        self.hist_table.setMinimumHeight(200)
        rl.addWidget(self.hist_table, 1)

        # Detail pane for selected history row
        detail_grp = QGroupBox("Hash Detail")
        dg_l = QVBoxLayout(detail_grp)
        self.detail_txt = QTextEdit()
        self.detail_txt.setReadOnly(True)
        self.detail_txt.setFont(QFont("Courier New", 9))
        self.detail_txt.setMaximumHeight(110)
        dg_l.addWidget(self.detail_txt)
        rl.addWidget(detail_grp)

        self.hist_table.currentCellChanged.connect(self._on_hist_selected)
        splitter.addWidget(right)
        splitter.setSizes([560, 520])
        root.addWidget(splitter, 1)

    # ── Data helpers ──────────────────────────────────────────────────

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
            self._load_evidence_table(cid)
            self._update_summary(cid)

    def _load_evidence_table(self, case_id: int):
        """Populate ev_table with evidence + their last verification result,
        original SHA-256, and most recently verified SHA-256.
        PERF FIX: was calling db.get_last_verification(ev_id) once per row —
        an N+1 query pattern that issued one DB round-trip per evidence item
        (500 evidence items = 500 queries). Now fetches all latest results
        for the case in a single batched query before the loop.
        """
        self.ev_table.setRowCount(0)
        evidence = self.db.get_evidence_for_case(case_id)
        last_results = self.db.get_last_verification_per_evidence(case_id)
        for ev in evidence:
            last = last_results.get(ev["id"])
            result_str  = normalize_status(last["result"]) if last else NOT_VERIFIED
            vtime       = last["verification_time"] if last else "—"
            current_sha = (last["current_hash"] if last else "") or "—"

            row = self.ev_table.rowCount()
            self.ev_table.insertRow(row)

            id_item = QTableWidgetItem(str(ev["id"]))
            id_item.setData(Qt.ItemDataRole.UserRole, ev["id"])
            self.ev_table.setItem(row, 0, id_item)
            self.ev_table.setItem(row, 1, QTableWidgetItem(ev["filename"] or "—"))
            self.ev_table.setItem(row, 2, QTableWidgetItem(ev["category"] or "—"))

            orig_item = QTableWidgetItem((ev["sha256"] or "—"))
            orig_item.setFont(QFont("Courier New", 8))
            self.ev_table.setItem(row, 3, orig_item)

            cur_item = QTableWidgetItem(current_sha)
            cur_item.setFont(QFont("Courier New", 8))
            self.ev_table.setItem(row, 4, cur_item)

            self.ev_table.setItem(row, 5, _colored_item(result_str, result_str))
            self.ev_table.setItem(row, 6, QTableWidgetItem(
                format_dual_plain(vtime, sep=" / ") if vtime != "—" else "—"
            ))

        self._update_overall_banner(case_id)

    def _update_summary(self, case_id: int):
        """Update the Case Integrity Summary cards + overall status banner —
        the CURRENT status of each evidence item (its most recent
        verification), not a count of historical attempts."""
        summary = self.db.get_case_integrity_summary(case_id)
        self._summary_labels["total"].setText(str(summary.get("total", 0)))
        for key in (MATCH, MISMATCH, MISSING, CORRUPTED, NOT_VERIFIED):
            self._summary_labels[key].setText(str(summary.get(key, 0)))
        self._update_overall_banner(case_id, summary)

    def _update_overall_banner(self, case_id: int, summary: dict = None):
        """Show the case's overall integrity status, and a clear warning
        banner if anything mismatches, is missing, or is corrupted."""
        summary = summary or self.db.get_case_integrity_summary(case_id)
        overall = summary.get("overall_status", "NOT_VERIFIED")

        banner_style = {
            "VERIFIED":     ("#3FB95020", "#3FB950", "✔ VERIFIED — all evidence matches its recorded hash"),
            "COMPROMISED":  ("#F8514920", "#F85149", "✘ COMPROMISED — one or more evidence items mismatched or corrupted"),
            "INCOMPLETE":   ("#E3B34120", "#E3B341", "⚠ INCOMPLETE — one or more evidence files are missing from disk"),
            "NOT_VERIFIED": ("#8B949E20", "#8B949E", "○ NOT VERIFIED — this case has not been fully verified yet"),
        }
        bg, fg, text = banner_style.get(overall, banner_style["NOT_VERIFIED"])
        self.overall_banner.setText(f"Case Integrity Status:  {text}")
        self.overall_banner.setStyleSheet(
            f"padding:8px 12px;border-radius:6px;font-weight:600;background:{bg};color:{fg};"
        )

        if summary.get("MISMATCH", 0) or summary.get("MISSING", 0) or summary.get("CORRUPTED", 0):
            parts = []
            if summary.get("MISMATCH", 0):
                parts.append(f"{summary['MISMATCH']} MISMATCH")
            if summary.get("MISSING", 0):
                parts.append(f"{summary['MISSING']} MISSING")
            if summary.get("CORRUPTED", 0):
                parts.append(f"{summary['CORRUPTED']} CORRUPTED")
            self.warning_banner.setText(
                "⚠ Integrity issue detected: " + ", ".join(parts) +
                " — review the affected evidence before relying on this case."
            )
            self.warning_banner.setVisible(True)
        else:
            self.warning_banner.setVisible(False)

    def _update_ev_row(self, result: dict):
        """Update a single row in ev_table after a verification completes."""
        ev_id = result.get("evidence_id")
        for row in range(self.ev_table.rowCount()):
            item = self.ev_table.item(row, 0)
            if item and item.data(Qt.ItemDataRole.UserRole) == ev_id:
                res = result["result"]
                cur_item = QTableWidgetItem(result.get("current_hash") or "—")
                cur_item.setFont(QFont("Courier New", 8))
                self.ev_table.setItem(row, 4, cur_item)
                self.ev_table.setItem(row, 5, _colored_item(res, res))
                ts = format_dual_plain(result.get("verification_time"), sep=" / ")
                self.ev_table.setItem(row, 6, QTableWidgetItem(ts))
                if res in _WARNING_STATUSES:
                    for col in range(self.ev_table.columnCount()):
                        cell = self.ev_table.item(row, col)
                        if cell:
                            cell.setToolTip(
                                f"⚠ {res}: {result.get('notes', '')}"
                            )
                break

    # ── Verification flow ─────────────────────────────────────────────

    def _run(self, mode: str):
        if mode == "case" and not self._current_case_id:
            self.progress_lbl.setText("Select a case first.")
            return
        if mode == "single":
            row = self.ev_table.currentRow()
            if row < 0:
                self.progress_lbl.setText("Select an evidence item first.")
                return
            ev_id = self.ev_table.item(row, 0).data(Qt.ItemDataRole.UserRole)
        else:
            ev_id = None

        self._set_running(True)
        self._results = []
        self.progress_bar.setValue(0)

        self._worker = VerificationWorker(
            self.engine, mode,
            case_id=self._current_case_id,
            evidence_id=ev_id,
        )
        self._worker.progress.connect(self._on_progress)
        self._worker.item_done.connect(self._on_item_done)
        self._worker.finished.connect(self._on_finished)
        self._worker.error.connect(self._on_error)
        self._worker.start()

    def _stop(self):
        if self._worker and self._worker.isRunning():
            self._worker.abort()
            self.progress_lbl.setText("Stopping…")
            self.btn_stop.setEnabled(False)

    def _set_running(self, running: bool):
        for btn in (self.btn_selected, self.btn_case, self.btn_all,
                    self.btn_json, self.btn_html):
            btn.setEnabled(not running)
        self.btn_stop.setEnabled(running)
        self.progress_bar.setVisible(running)

    def _on_progress(self, current: int, total: int, msg: str):
        """
        FIX: this handler previously also tried to write audit events by
        iterating a variable named `results` that was never defined in
        this scope — a NameError waiting to happen on every progress tick
        once a `mw.audit` was present. Audit logging for a verification
        run belongs once, after the run completes, which is what
        _on_finished() already does — so it's removed from here.
        """
        if total > 0:
            self.progress_bar.setValue(int(current / total * 100))
        self.progress_lbl.setText(msg)
        mw = self.window()
        if hasattr(mw, "set_status"):
            mw.set_status(msg)

    def _on_item_done(self, result: dict):
        self._results.append(result)
        self._update_ev_row(result)

    def _on_finished(self, results: list):
        self._results = results
        self._set_running(False)
        self.progress_bar.setValue(100)

        if self._current_case_id:
            self._update_summary(self._current_case_id)
            self._load_evidence_table(self._current_case_id)

        matched   = sum(1 for r in results if r["result"] == MATCH)
        mismatch  = sum(1 for r in results if r["result"] == MISMATCH)
        missing   = sum(1 for r in results if r["result"] == MISSING)
        corrupted = sum(1 for r in results if r["result"] == CORRUPTED)

        msg = (f"Verification complete — {len(results)} items: "
               f"✔ {matched} MATCH  ✘ {mismatch} MISMATCH  "
               f"⚠ {missing} MISSING  ⚠ {corrupted} CORRUPTED")
        self.progress_lbl.setText(msg)
        logger.info(msg)

        mw = self.window()
        if hasattr(mw, "set_status"):
            mw.set_status(msg)
        if hasattr(mw, "audit") and self._current_case_id:
            case = self.db.get_case(self._current_case_id)
            inv  = case["investigator"] if case else ""
            for _r in results:
                mw.audit.log_verification(
                    _r.get("case_id") or self._current_case_id,
                    _r["evidence_id"], inv,
                    _r["result"], _r.get("filename",""),
                )

    def _on_error(self, msg: str):
        self._set_running(False)
        self.progress_lbl.setText(f"Error: {msg}")
        logger.error("Verification error: %s", msg)

    # ── History table ─────────────────────────────────────────────────

    def _on_ev_selected(self, row: int, *_):
        item = self.ev_table.item(row, 0)
        if not item:
            return
        ev_id = item.data(Qt.ItemDataRole.UserRole)
        if ev_id is None:
            return
        self._load_history(ev_id)

    def _load_history(self, evidence_id: int):
        self.hist_table.setRowCount(0)
        self.detail_txt.clear()
        history = self.db.get_verification_history(evidence_id=evidence_id)
        for h in history:
            row = self.hist_table.rowCount()
            self.hist_table.insertRow(row)
            res = h["result"]
            self.hist_table.setItem(row, 0, _colored_item(res, res))
            self.hist_table.setItem(row, 1,
                QTableWidgetItem(format_dual_plain(h["verification_time"], sep=" / ")))
            hi = QTableWidgetItem((h["stored_hash"] or "")[:24] + "…")
            hi.setFont(QFont("Courier New", 8))
            hi.setForeground(QBrush(QColor("#3FB950")))
            self.hist_table.setItem(row, 2, hi)
            self.hist_table.setItem(row, 3,
                QTableWidgetItem(h["notes"] or ""))
            # Store full data for detail pane
            self.hist_table.item(row, 0).setData(
                Qt.ItemDataRole.UserRole, dict(h)
            )

    def _on_hist_selected(self, row: int, *_):
        item = self.hist_table.item(row, 0)
        if not item:
            return
        data = item.data(Qt.ItemDataRole.UserRole)
        if not data:
            return
        self.detail_txt.setPlainText(
            f"Result:          {data.get('result','—')}\n"
            f"Verified At:     {data.get('verification_time','—')}\n"
            f"Evidence ID:     {data.get('evidence_id','—')}\n"
            f"Filename:        {data.get('filename','—')}\n\n"
            f"Stored SHA-256:\n  {data.get('stored_hash','—')}\n\n"
            f"Current SHA-256:\n  {data.get('current_hash','—')}\n\n"
            f"Notes:\n  {data.get('notes','—')}"
        )

    # ── Exports ───────────────────────────────────────────────────────

    def _export_json(self):
        if not self._results:
            QMessageBox.information(self, "No Data", "Run a verification first.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Save JSON Report", "verification_report.json",
            "JSON Files (*.json)"
        )
        if path:
            try:
                case_num = self._case_number()
                self.engine.export_json(
                    self._results, path,
                    case_id=self._current_case_id,
                    case_number=case_num,
                )
                self.progress_lbl.setText(f"JSON saved: {path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Failed", str(e))

    def _export_html(self):
        if not self._results:
            QMessageBox.information(self, "No Data", "Run a verification first.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Save HTML Report", "verification_report.html",
            "HTML Files (*.html)"
        )
        if path:
            try:
                case_num = self._case_number()
                self.engine.export_html(
                    self._results, path,
                    case_id=self._current_case_id,
                    case_number=case_num,
                )
                self.progress_lbl.setText(f"HTML saved: {path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Failed", str(e))

    def _case_number(self) -> str:
        idx = self.case_combo.currentIndex()
        text = self.case_combo.itemText(idx)
        return text.split(" — ")[0] if " — " in text else text
