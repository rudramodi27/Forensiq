"""
Audit Trail Panel — searchable, filterable, sortable view of audit_trail table.
"""

import os
from datetime import datetime

from forensiq.core.time_utils import format_dual_plain

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QComboBox, QTableWidget, QTableWidgetItem,
    QFrame, QHeaderView, QFileDialog, QMessageBox, QSplitter,
    QTextEdit, QGroupBox,
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QColor, QBrush

from forensiq.core.case_manager import CaseManager
from forensiq.core.audit_service import (
    AuditService, R_OK, R_FAILED, R_WARNING,
    _RESULT_COLOR,
)

_COL = {R_OK: QColor("#3FB950"), R_FAILED: QColor("#F85149"),
        R_WARNING: QColor("#E3B341")}
_ACTION_COL = QColor("#A5D6FF")


class AuditPanel(QWidget):
    def __init__(self, db: CaseManager, audit: AuditService, parent=None):
        super().__init__(parent)
        self.db    = db
        self.audit = audit
        self._all_records: list = []
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 24, 24, 24)
        root.setSpacing(14)

        # ── Filter bar ────────────────────────────────────────────────
        fbar = QFrame(); fbar.setObjectName("card")
        fl   = QVBoxLayout(fbar); fl.setContentsMargins(14, 12, 14, 12); fl.setSpacing(8)
        fl.addWidget(self._bold("Search & Filter"))

        row1 = QHBoxLayout(); row1.setSpacing(10)
        row1.addWidget(QLabel("Search:"))
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Filter by any field…")
        self.search_input.textChanged.connect(self._apply_filter)
        row1.addWidget(self.search_input, 1)

        row1.addWidget(QLabel("Action:"))
        self.action_combo = QComboBox(); self.action_combo.setMinimumWidth(170)
        self.action_combo.addItem("All Actions", "")
        self.action_combo.currentIndexChanged.connect(self._apply_filter)
        row1.addWidget(self.action_combo)

        row1.addWidget(QLabel("User:"))
        self.user_combo = QComboBox(); self.user_combo.setMinimumWidth(140)
        self.user_combo.addItem("All Users", "")
        self.user_combo.currentIndexChanged.connect(self._apply_filter)
        row1.addWidget(self.user_combo)

        row1.addWidget(QLabel("Result:"))
        self.result_combo = QComboBox()
        for lbl, val in [("All", ""), ("OK", R_OK), ("FAILED", R_FAILED), ("WARNING", R_WARNING)]:
            self.result_combo.addItem(lbl, val)
        self.result_combo.currentIndexChanged.connect(self._apply_filter)
        row1.addWidget(self.result_combo)

        btn_refresh = QPushButton("↻ Refresh")
        btn_refresh.clicked.connect(self.on_shown)
        row1.addWidget(btn_refresh)
        fl.addLayout(row1)

        # Phase 2 requirement 4 — filter by date range, alongside the
        # existing action/user/result filters above.
        row2 = QHBoxLayout(); row2.setSpacing(10)
        row2.addWidget(QLabel("Date From:"))
        self.date_from_input = QLineEdit(); self.date_from_input.setFixedWidth(100)
        self.date_from_input.setPlaceholderText("YYYY-MM-DD")
        self.date_from_input.textChanged.connect(self._apply_filter)
        row2.addWidget(self.date_from_input)

        row2.addWidget(QLabel("Date To:"))
        self.date_to_input = QLineEdit(); self.date_to_input.setFixedWidth(100)
        self.date_to_input.setPlaceholderText("YYYY-MM-DD")
        self.date_to_input.textChanged.connect(self._apply_filter)
        row2.addWidget(self.date_to_input)

        btn_clear_dates = QPushButton("Clear Dates")
        btn_clear_dates.clicked.connect(self._clear_date_filters)
        row2.addWidget(btn_clear_dates)
        row2.addStretch()
        fl.addLayout(row2)
        root.addWidget(fbar)

        # ── Toolbar ───────────────────────────────────────────────────
        tb = QHBoxLayout(); tb.setSpacing(8)
        self.count_lbl = QLabel("0 records")
        self.count_lbl.setObjectName("metaLabel")
        tb.addWidget(self.count_lbl)
        tb.addStretch()
        btn_json = QPushButton("↓ Export JSON")
        btn_html = QPushButton("↓ Export HTML")
        btn_json.clicked.connect(self._export_json)
        btn_html.clicked.connect(self._export_html)
        tb.addWidget(btn_json); tb.addWidget(btn_html)
        root.addLayout(tb)

        # ── Table + detail splitter ────────────────────────────────────
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setChildrenCollapsible(False)

        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(
            ["Timestamp", "User", "Action", "Target Type", "Target ID", "Result", "Notes"]
        )
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setSortingEnabled(True)
        self.table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        self.table.setColumnWidth(0, 155)
        self.table.setColumnWidth(1, 110)
        self.table.setColumnWidth(2, 165)
        self.table.setColumnWidth(3, 100)
        self.table.setColumnWidth(4, 70)
        self.table.setColumnWidth(5, 75)
        self.table.setMinimumHeight(300)
        self.table.currentCellChanged.connect(self._on_row_selected)
        splitter.addWidget(self.table)

        detail_grp = QGroupBox("Event Detail")
        dgl = QVBoxLayout(detail_grp)
        self.detail_txt = QTextEdit()
        self.detail_txt.setReadOnly(True)
        self.detail_txt.setFont(QFont("Courier New", 9))
        self.detail_txt.setMaximumHeight(100)
        dgl.addWidget(self.detail_txt)
        splitter.addWidget(detail_grp)
        splitter.setSizes([500, 120])
        root.addWidget(splitter, 1)

    def _bold(self, text: str) -> QLabel:
        l = QLabel(text); l.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        return l

    # ── Data ──────────────────────────────────────────────────────────

    def on_shown(self):
        # Refresh filter dropdowns
        actions = self.db.get_audit_actions()
        self.action_combo.blockSignals(True)
        current_action = self.action_combo.currentData()
        self.action_combo.clear()
        self.action_combo.addItem("All Actions", "")
        for a in actions:
            self.action_combo.addItem(a, a)
        # Restore selection
        for i in range(self.action_combo.count()):
            if self.action_combo.itemData(i) == current_action:
                self.action_combo.setCurrentIndex(i); break
        self.action_combo.blockSignals(False)

        users = self.db.get_audit_users()
        self.user_combo.blockSignals(True)
        current_user = self.user_combo.currentData()
        self.user_combo.clear()
        self.user_combo.addItem("All Users", "")
        for u in users:
            self.user_combo.addItem(u, u)
        for i in range(self.user_combo.count()):
            if self.user_combo.itemData(i) == current_user:
                self.user_combo.setCurrentIndex(i); break
        self.user_combo.blockSignals(False)

        # Load all records (limit 2000 for performance)
        self._all_records = self.db.get_audit_trail(limit=2000)
        self._apply_filter()

    def _apply_filter(self):
        keyword     = self.search_input.text().lower()
        action_filt = self.action_combo.currentData() or ""
        user_filt   = self.user_combo.currentData() or ""
        result_filt = self.result_combo.currentData() or ""
        date_from   = self.date_from_input.text().strip()
        date_to     = self.date_to_input.text().strip()

        filtered = []
        for r in self._all_records:
            if action_filt and r["action"] != action_filt:
                continue
            if user_filt and r["user"] != user_filt:
                continue
            if result_filt and r["result"] != result_filt:
                continue
            ts = str(r["timestamp"] or "")[:10]  # YYYY-MM-DD
            if date_from and ts < date_from:
                continue
            if date_to and ts > date_to:
                continue
            if keyword:
                row_text = " ".join(str(r[k] or "") for k in
                    ["timestamp", "user", "action", "target_type",
                     "target_id", "result", "notes"]).lower()
                if keyword not in row_text:
                    continue
            filtered.append(r)

        self._populate_table(filtered)

    def _clear_date_filters(self):
        self.date_from_input.clear()
        self.date_to_input.clear()

    def _populate_table(self, records: list):
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        for rec in records:
            row = self.table.rowCount()
            self.table.insertRow(row)

            # Phase 10: dual UTC/IST display (was raw truncated UTC with
            # no timezone label).
            ts_item = QTableWidgetItem(format_dual_plain(rec["timestamp"], sep=" / "))
            ts_item.setFont(QFont("Courier New", 9))
            ts_item.setForeground(QBrush(QColor("#8B949E")))
            ts_item.setData(Qt.ItemDataRole.UserRole, dict(rec))
            self.table.setItem(row, 0, ts_item)

            self.table.setItem(row, 1, QTableWidgetItem(str(rec["user"] or "")))

            act_item = QTableWidgetItem(str(rec["action"] or ""))
            act_item.setForeground(QBrush(_ACTION_COL))
            self.table.setItem(row, 2, act_item)

            self.table.setItem(row, 3, QTableWidgetItem(str(rec["target_type"] or "")))
            self.table.setItem(row, 4, QTableWidgetItem(str(rec["target_id"] or "")))

            result = str(rec["result"] or "")
            res_item = QTableWidgetItem(result)
            res_item.setForeground(QBrush(_COL.get(result, QColor("#E6EDF3"))))
            self.table.setItem(row, 5, res_item)

            self.table.setItem(row, 6, QTableWidgetItem(str(rec["notes"] or "")))

        self.table.setSortingEnabled(True)
        self.count_lbl.setText(f"{len(records):,} record(s)")

    def _on_row_selected(self, row: int, *_):
        item = self.table.item(row, 0)
        if not item:
            self.detail_txt.clear(); return
        data = item.data(Qt.ItemDataRole.UserRole)
        if not data:
            return
        self.detail_txt.setPlainText(
            f"ID:           {data.get('id','—')}\n"
            f"Timestamp:    {data.get('timestamp','—')}\n"
            f"User:         {data.get('user','—')}\n"
            f"Action:       {data.get('action','—')}\n"
            f"Target Type:  {data.get('target_type','—')}\n"
            f"Target ID:    {data.get('target_id','—')}\n"
            f"Result:       {data.get('result','—')}\n"
            f"Notes:        {data.get('notes','—')}"
        )

    # ── Exports ───────────────────────────────────────────────────────

    def _visible_records(self) -> list:
        """Return records currently shown in table (post-filter)."""
        out = []
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 0)
            if item:
                data = item.data(Qt.ItemDataRole.UserRole)
                if data:
                    out.append(data)
        return out

    def _export_json(self):
        records = self._visible_records()
        if not records:
            QMessageBox.information(self, "No Data", "No audit records to export.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Audit JSON", "audit_report.json", "JSON Files (*.json)"
        )
        if path:
            try:
                self.audit.export_audit_json(records, path, "ForensIQ Audit Trail")
                mw = self.window()
                if hasattr(mw, "set_status"):
                    mw.set_status(f"Audit JSON saved: {path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Failed", str(e))

    def _export_html(self):
        records = self._visible_records()
        if not records:
            QMessageBox.information(self, "No Data", "No audit records to export.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Audit HTML", "audit_report.html", "HTML Files (*.html)"
        )
        if path:
            try:
                self.audit.export_audit_html(records, path, "ForensIQ Audit Trail")
                mw = self.window()
                if hasattr(mw, "set_status"):
                    mw.set_status(f"Audit HTML saved: {path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Failed", str(e))
