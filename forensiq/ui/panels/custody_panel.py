"""
Chain of Custody Panel — complete evidence lifecycle tracking.
"""

import os
from datetime import datetime

from forensiq.core.time_utils import format_dual_plain

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QComboBox, QTableWidget, QTableWidgetItem, QFrame,
    QHeaderView, QSplitter, QGroupBox, QLineEdit,
    QTextEdit, QFileDialog, QMessageBox, QDialog,
    QFormLayout, QDialogButtonBox, QStackedWidget,
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QColor, QBrush

from forensiq.core.case_manager import CaseManager
from forensiq.core.audit_service import AuditService

_ACTION_COLORS = {
    "ACQUIRED":    QColor("#1D9E75"),
    "STORED":      QColor("#58A6FF"),
    "VERIFIED":    QColor("#3FB950"),
    "TRANSFERRED": QColor("#F0883E"),
    "ANALYZED":    QColor("#BC8CFF"),
    "REPORTED":    QColor("#D2A8FF"),
    "REVIEWED":    QColor("#A5D6FF"),
    "EXPORTED":    QColor("#E3B341"),
    "ARCHIVED":    QColor("#8B949E"),
    "NOTED":       QColor("#8B949E"),
}

_INTEGRITY_COLORS = {
    "MATCH":        QColor("#3FB950"),
    "MISMATCH":     QColor("#F85149"),
    "MISSING":      QColor("#E3B341"),
    "CORRUPTED":    QColor("#F85149"),
    "NOT_VERIFIED": QColor("#8B949E"),
    "ERROR":        QColor("#8B949E"),
}

# Phase 2 canonical lifecycle order, mirrors CaseManager.LIFECYCLE_ORDER —
# duplicated here only as a tiny display list, not a second source of
# truth (the actual stage is always computed by
# CaseManager.get_evidence_lifecycle_status()).
_LIFECYCLE_ORDER = (
    "ACQUIRED", "STORED", "VERIFIED", "TRANSFERRED", "ANALYZED", "REPORTED",
)


class TransferDialog(QDialog):
    """Manual custody event entry dialog."""

    ACTIONS = ["TRANSFERRED", "REVIEWED", "ARCHIVED", "ANALYZED", "REPORTED", "NOTED"]
    # Actions that represent a hand-off and need From/To locations rather
    # than a single Location field.
    TRANSFER_ACTIONS = {"TRANSFERRED"}

    def __init__(self, investigator: str = "", parent=None):
        super().__init__(parent)
        self.setWindowTitle("Record Custody Event")
        self.setMinimumWidth(440)
        self.setModal(True)
        self._build(investigator)

    def _build(self, investigator: str):
        layout = QVBoxLayout(self)
        layout.setSpacing(14)

        title = QLabel("Record Custody Event")
        title.setFont(QFont("Segoe UI", 13, QFont.Weight.Bold))
        layout.addWidget(title)

        form = QFormLayout()
        form.setSpacing(10)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

        self.action_combo = QComboBox()
        for a in self.ACTIONS:
            self.action_combo.addItem(a)
        self.action_combo.currentTextChanged.connect(self._on_action_changed)

        self.investigator_input = QLineEdit(investigator)
        self.investigator_input.setPlaceholderText("Full name")

        # Single-location field, used for non-transfer actions.
        self.location_input = QLineEdit()
        self.location_input.setPlaceholderText("e.g. Forensic Lab 2, Evidence Locker A3")

        # From/To fields, used only for TRANSFERRED — a transfer needs an
        # explicit source and destination, not one ambiguous "location".
        self.from_location_input = QLineEdit()
        self.from_location_input.setPlaceholderText("e.g. Evidence Locker A3")
        self.to_location_input = QLineEdit()
        self.to_location_input.setPlaceholderText("e.g. Digital Forensics Lab, Analyst Workstation 2")

        self.notes_input = QTextEdit()
        self.notes_input.setPlaceholderText("Transfer reason, recipient, conditions…")
        self.notes_input.setFixedHeight(70)

        form.addRow("Action:",       self.action_combo)
        form.addRow("Investigator:", self.investigator_input)
        self._location_row = form.rowCount()
        form.addRow("Location:",     self.location_input)
        self._from_row = form.rowCount()
        form.addRow("From:",         self.from_location_input)
        self._to_row = form.rowCount()
        form.addRow("To:",           self.to_location_input)
        form.addRow("Reason/Notes:", self.notes_input)
        self._form = form
        layout.addLayout(form)

        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        btns.accepted.connect(self._validate)
        btns.rejected.connect(self.reject)
        layout.addWidget(btns)

        self._on_action_changed(self.action_combo.currentText())

    def _on_action_changed(self, action: str):
        is_transfer = action in self.TRANSFER_ACTIONS
        self.location_input.setVisible(not is_transfer)
        self._form.labelForField(self.location_input).setVisible(not is_transfer)
        self.from_location_input.setVisible(is_transfer)
        self._form.labelForField(self.from_location_input).setVisible(is_transfer)
        self.to_location_input.setVisible(is_transfer)
        self._form.labelForField(self.to_location_input).setVisible(is_transfer)

    def _validate(self):
        if not self.investigator_input.text().strip():
            QMessageBox.warning(self, "Validation", "Investigator name is required.")
            return
        if self.action_combo.currentText() in self.TRANSFER_ACTIONS:
            if not self.to_location_input.text().strip():
                QMessageBox.warning(self, "Validation",
                                     "A transfer requires a destination (To).")
                return
        self.accept()

    def get_data(self) -> dict:
        return {
            "action":        self.action_combo.currentText(),
            "investigator":  self.investigator_input.text().strip(),
            "location":      self.location_input.text().strip(),
            "from_location": self.from_location_input.text().strip(),
            "to_location":   self.to_location_input.text().strip(),
            "notes":         self.notes_input.toPlainText().strip(),
        }


class CustodyPanel(QWidget):
    def __init__(self, db: CaseManager, audit: AuditService, parent=None):
        super().__init__(parent)
        self.db    = db
        self.audit = audit
        self._current_case_id: int | None       = None
        self._current_evidence_id: int | None   = None
        self._current_investigator: str         = ""
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 24, 24, 24)
        root.setSpacing(14)

        # ── Top: case selector + summary cards ────────────────────────
        top = QFrame(); top.setObjectName("card")
        tl  = QVBoxLayout(top); tl.setContentsMargins(14, 12, 14, 12); tl.setSpacing(8)
        tl.addWidget(self._bold("Case Selection"))

        sel = QHBoxLayout(); sel.setSpacing(10)
        sel.addWidget(QLabel("Case:"))
        self.case_combo = QComboBox(); self.case_combo.setMinimumWidth(320)
        self.case_combo.setPlaceholderText("Select case…")
        self.case_combo.currentIndexChanged.connect(self._on_case_changed)
        sel.addWidget(self.case_combo, 1)
        sel.addStretch()
        tl.addLayout(sel)

        # Action summary cards
        cards_row = QHBoxLayout(); cards_row.setSpacing(10)
        self._summary_labels: dict[str, QLabel] = {}
        for action, color in [
            ("ACQUIRED", "#1D9E75"), ("STORED", "#58A6FF"),
            ("VERIFIED", "#3FB950"), ("TRANSFERRED", "#F0883E"),
            ("ANALYZED", "#BC8CFF"), ("REPORTED", "#D2A8FF"),
        ]:
            box = QFrame(); box.setObjectName("card")
            bl  = QVBoxLayout(box); bl.setContentsMargins(10, 8, 10, 8); bl.setSpacing(2)
            num = QLabel("—")
            num.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
            num.setStyleSheet(f"color:{color};")
            nl  = QLabel(action.capitalize()); nl.setObjectName("metaLabel")
            bl.addWidget(num); bl.addWidget(nl)
            self._summary_labels[action] = num
            cards_row.addWidget(box)
        tl.addLayout(cards_row)
        root.addWidget(top)

        # ── Toolbar ───────────────────────────────────────────────────
        tb = QHBoxLayout(); tb.setSpacing(8)
        self.btn_transfer = QPushButton("⇄  Record Event")
        self.btn_transfer.setObjectName("primaryBtn")
        self.btn_transfer.setEnabled(False)
        self.btn_transfer.clicked.connect(self._record_event)

        btn_json = QPushButton("↓ Export JSON")
        btn_html = QPushButton("↓ Export HTML")
        btn_json.clicked.connect(self._export_json)
        btn_html.clicked.connect(self._export_html)

        tb.addWidget(self.btn_transfer)
        tb.addSpacing(16)
        tb.addWidget(btn_json); tb.addWidget(btn_html)
        tb.addStretch()
        root.addLayout(tb)

        # ── Main splitter: evidence list | custody chain ───────────────
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)

        # Left: evidence table
        left = QWidget()
        ll   = QVBoxLayout(left); ll.setContentsMargins(0, 0, 0, 0); ll.setSpacing(6)
        ll.addWidget(self._bold("Evidence"))

        self.ev_table = QTableWidget(0, 5)
        self.ev_table.setHorizontalHeaderLabels(
            ["ID", "Filename", "Category", "Status", "Events"]
        )
        self.ev_table.setAlternatingRowColors(True)
        self.ev_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.ev_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.ev_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.ev_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.ev_table.setColumnWidth(0, 40)
        self.ev_table.setColumnWidth(2, 90)
        self.ev_table.setColumnWidth(3, 100)
        self.ev_table.setColumnWidth(4, 55)
        self.ev_table.setMinimumHeight(280)
        self.ev_table.currentCellChanged.connect(self._on_ev_selected)
        ll.addWidget(self.ev_table, 1)
        splitter.addWidget(left)

        # Right: custody chain timeline + filters
        right = QWidget()
        rl    = QVBoxLayout(right); rl.setContentsMargins(0, 0, 0, 0); rl.setSpacing(6)
        rl.addWidget(self._bold("Custody Chain"))

        # Filters — by event (action), actor (investigator), and date
        # range. Filters the currently displayed chain client-side; no
        # extra DB round-trip needed since a chain is small per item.
        frow = QHBoxLayout(); frow.setSpacing(8)
        frow.addWidget(QLabel("Event:"))
        self.filter_action = QComboBox(); self.filter_action.setMinimumWidth(120)
        self.filter_action.addItem("All Events", "")
        for a in _LIFECYCLE_ORDER + ("REVIEWED", "EXPORTED", "ARCHIVED", "NOTED"):
            self.filter_action.addItem(a, a)
        self.filter_action.currentIndexChanged.connect(self._apply_chain_filter)
        frow.addWidget(self.filter_action)

        frow.addWidget(QLabel("Actor:"))
        self.filter_actor = QLineEdit(); self.filter_actor.setMinimumWidth(110)
        self.filter_actor.setPlaceholderText("Investigator…")
        self.filter_actor.textChanged.connect(self._apply_chain_filter)
        frow.addWidget(self.filter_actor)

        frow.addWidget(QLabel("From:"))
        self.filter_date_from = QLineEdit(); self.filter_date_from.setFixedWidth(90)
        self.filter_date_from.setPlaceholderText("YYYY-MM-DD")
        self.filter_date_from.textChanged.connect(self._apply_chain_filter)
        frow.addWidget(self.filter_date_from)

        frow.addWidget(QLabel("To:"))
        self.filter_date_to = QLineEdit(); self.filter_date_to.setFixedWidth(90)
        self.filter_date_to.setPlaceholderText("YYYY-MM-DD")
        self.filter_date_to.textChanged.connect(self._apply_chain_filter)
        frow.addWidget(self.filter_date_to)

        btn_clear = QPushButton("Clear")
        btn_clear.clicked.connect(self._clear_chain_filters)
        frow.addWidget(btn_clear)
        frow.addStretch()
        rl.addLayout(frow)

        self.chain_table = QTableWidget(0, 7)
        self.chain_table.setHorizontalHeaderLabels(
            ["Timestamp", "Investigator", "Action", "Location",
             "Integrity", "Notes", "id"]
        )
        self.chain_table.setAlternatingRowColors(True)
        self.chain_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.chain_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.chain_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self.chain_table.setColumnWidth(0, 145)
        self.chain_table.setColumnWidth(1, 110)
        self.chain_table.setColumnWidth(2, 100)
        self.chain_table.setColumnWidth(3, 160)
        self.chain_table.setColumnWidth(4, 90)
        self.chain_table.setColumnHidden(6, True)  # internal id, for filtering only
        self.chain_table.setMinimumHeight(280)
        rl.addWidget(self.chain_table, 1)

        # Integrity line below chain
        self.chain_status_lbl = QLabel("")
        self.chain_status_lbl.setObjectName("metaLabel")
        self.chain_status_lbl.setWordWrap(True)
        rl.addWidget(self.chain_status_lbl)

        splitter.addWidget(right)
        splitter.setSizes([380, 720])
        root.addWidget(splitter, 1)

    def _bold(self, text: str) -> QLabel:
        l = QLabel(text); l.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        return l

    # ── Data ──────────────────────────────────────────────────────────

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

    def select_case(self, case_id: int):
        """
        Programmatically select a case in the case combo — used by
        CasesPanel to jump straight to a case's evidence/custody chain
        (Phase 8 "navigate from case to its evidence").  Repopulates the
        combo first (in case the panel hasn't been shown yet this
        session), so this works whether or not on_shown() already ran.
        """
        self.case_combo.blockSignals(True)
        self.case_combo.clear()
        for case in self.db.get_all_cases():
            self.case_combo.addItem(
                f"{case['case_number']} — {case['title']}", userData=case["id"]
            )
        self.case_combo.blockSignals(False)
        for i in range(self.case_combo.count()):
            if self.case_combo.itemData(i) == case_id:
                self.case_combo.setCurrentIndex(i)
                self._on_case_changed(i)
                return

    def _on_case_changed(self, idx: int):
        cid = self.case_combo.itemData(idx)
        if not cid:
            return
        self._current_case_id = cid
        # Grab investigator from case for default in dialogs
        case = self.db.get_case(cid)
        if case:
            self._current_investigator = case["investigator"] or ""
        self._load_evidence(cid)
        self._update_summary(cid)

    def _load_evidence(self, case_id: int):
        self.ev_table.setRowCount(0)
        self.chain_table.setRowCount(0)
        self.chain_status_lbl.setText("")
        self._current_evidence_id = None
        self._current_chain: list = []
        self.btn_transfer.setEnabled(False)

        for ev in self.db.get_evidence_for_case(case_id):
            chain  = self.db.get_custody_chain(ev["id"])
            status = self.db.get_evidence_lifecycle_status(ev["id"])
            row    = self.ev_table.rowCount()
            self.ev_table.insertRow(row)
            id_item = QTableWidgetItem(str(ev["id"]))
            id_item.setData(Qt.ItemDataRole.UserRole, ev["id"])
            self.ev_table.setItem(row, 0, id_item)
            self.ev_table.setItem(row, 1, QTableWidgetItem(ev["filename"] or "—"))
            self.ev_table.setItem(row, 2, QTableWidgetItem(ev["category"] or "—"))

            status_item = QTableWidgetItem(status)
            status_item.setForeground(QBrush(_ACTION_COLORS.get(status, QColor("#8B949E"))))
            status_item.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
            self.ev_table.setItem(row, 3, status_item)

            cnt_item = QTableWidgetItem(str(len(chain)))
            cnt_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if len(chain) > 0:
                cnt_item.setForeground(QBrush(QColor("#1D9E75")))
            self.ev_table.setItem(row, 4, cnt_item)

    def _on_ev_selected(self, row: int, *_):
        item = self.ev_table.item(row, 0)
        if not item:
            return
        ev_id = item.data(Qt.ItemDataRole.UserRole)
        if ev_id is None:
            return
        self._current_evidence_id = ev_id
        self.btn_transfer.setEnabled(True)
        self._load_chain(ev_id)

    def _load_chain(self, evidence_id: int):
        self._current_chain = list(self.db.get_custody_chain(evidence_id))
        self._apply_chain_filter()

    def _apply_chain_filter(self):
        """
        Phase 2 requirement 4 — filter the displayed chain by event
        (action), actor (investigator), and date range. Filters only the
        display; the underlying chain in the DB is untouched.
        """
        chain = getattr(self, "_current_chain", [])
        action_filt = self.filter_action.currentData() or ""
        actor_filt  = self.filter_actor.text().strip().lower()
        date_from   = self.filter_date_from.text().strip()
        date_to     = self.filter_date_to.text().strip()

        filtered = []
        for ev in chain:
            if action_filt and str(ev["action"]) != action_filt:
                continue
            if actor_filt and actor_filt not in str(ev["investigator"] or "").lower():
                continue
            ts = str(ev["timestamp"] or "")[:10]  # YYYY-MM-DD
            if date_from and ts < date_from:
                continue
            if date_to and ts > date_to:
                continue
            filtered.append(ev)

        self._populate_chain_table(filtered)

    def _clear_chain_filters(self):
        self.filter_action.setCurrentIndex(0)
        self.filter_actor.clear()
        self.filter_date_from.clear()
        self.filter_date_to.clear()

    def _populate_chain_table(self, chain: list):
        self.chain_table.setRowCount(0)

        for ev in chain:
            row = self.chain_table.rowCount()
            self.chain_table.insertRow(row)

            # Phase 10: dual UTC/IST display (was raw truncated UTC with
            # no timezone label).
            ts_item = QTableWidgetItem(format_dual_plain(ev["timestamp"], sep=" / "))
            ts_item.setFont(QFont("Courier New", 9))
            ts_item.setForeground(QBrush(QColor("#8B949E")))
            self.chain_table.setItem(row, 0, ts_item)

            self.chain_table.setItem(row, 1, QTableWidgetItem(ev["investigator"] or ""))

            action = str(ev["action"] or "")
            act_item = QTableWidgetItem(action)
            act_item.setForeground(QBrush(_ACTION_COLORS.get(action, QColor("#E6EDF3"))))
            act_item.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
            self.chain_table.setItem(row, 2, act_item)

            # Phase 2: show explicit From → To for a transfer, otherwise
            # fall back to the general location field.
            from_loc = ev["from_location"] if "from_location" in ev.keys() else ""
            to_loc   = ev["to_location"] if "to_location" in ev.keys() else ""
            if from_loc or to_loc:
                loc_text = f"{from_loc or '?'} → {to_loc or '?'}"
            else:
                loc_text = ev["location"] or "—"
            self.chain_table.setItem(row, 3, QTableWidgetItem(loc_text))

            integrity = ev["integrity_status"] if "integrity_status" in ev.keys() else ""
            integ_item = QTableWidgetItem(integrity or "—")
            if integrity:
                integ_item.setForeground(QBrush(_INTEGRITY_COLORS.get(integrity, QColor("#8B949E"))))
            self.chain_table.setItem(row, 4, integ_item)

            self.chain_table.setItem(row, 5, QTableWidgetItem(ev["notes"] or ""))
            self.chain_table.setItem(row, 6, QTableWidgetItem(str(ev["id"])))

        # Integrity status line
        full_chain = getattr(self, "_current_chain", chain)
        acquired = any(str(e["action"]) == "ACQUIRED" for e in full_chain)
        verified = any(str(e["action"]) == "VERIFIED" for e in full_chain)
        transferred_n = sum(1 for e in full_chain if str(e["action"]) == "TRANSFERRED")
        if len(full_chain) == 0:
            self.chain_status_lbl.setText("No custody events recorded yet.")
        else:
            parts = []
            if acquired: parts.append("✔ Acquired")
            if verified: parts.append("✔ Verified")
            if transferred_n: parts.append(f"⇄ {transferred_n} transfer(s)")
            shown = f" ({len(chain)} shown)" if len(chain) != len(full_chain) else ""
            self.chain_status_lbl.setText(
                f"{len(full_chain)} event(s) in chain{shown} — " + "  ·  ".join(parts)
            )

    def _update_summary(self, case_id: int):
        summary = self.db.get_custody_summary(case_id)
        for action, lbl in self._summary_labels.items():
            lbl.setText(str(summary.get(action, 0)))

    # ── Manual event recording ────────────────────────────────────────

    def _record_event(self):
        if self._current_evidence_id is None or self._current_case_id is None:
            return
        dlg = TransferDialog(self._current_investigator, self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            data = dlg.get_data()
            try:
                self.audit.add_custody_event(
                    case_id=self._current_case_id,
                    evidence_id=self._current_evidence_id,
                    investigator=data["investigator"],
                    action=data["action"],
                    location=data["location"],
                    notes=data["notes"],
                    from_location=data.get("from_location", ""),
                    to_location=data.get("to_location", ""),
                )
                self._load_chain(self._current_evidence_id)
                self._update_summary(self._current_case_id)
                # Refresh event count + lifecycle status in evidence table
                row = self.ev_table.currentRow()
                if row >= 0:
                    chain = self.db.get_custody_chain(self._current_evidence_id)
                    status = self.db.get_evidence_lifecycle_status(self._current_evidence_id)
                    self.ev_table.item(row, 3).setText(status)
                    self.ev_table.item(row, 3).setForeground(
                        QBrush(_ACTION_COLORS.get(status, QColor("#8B949E")))
                    )
                    self.ev_table.item(row, 4).setText(str(len(chain)))
                mw = self.window()
                if hasattr(mw, "set_status"):
                    mw.set_status(f"Custody event recorded: {data['action']}")
            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))

    # ── Exports ───────────────────────────────────────────────────────

    def _get_case_number(self) -> str:
        idx = self.case_combo.currentIndex()
        txt = self.case_combo.itemText(idx)
        return txt.split(" — ")[0] if " — " in txt else txt

    def _get_events_for_export(self) -> list:
        if self._current_case_id:
            return list(self.db.get_custody_events(case_id=self._current_case_id))
        return []

    def _export_json(self):
        events = self._get_events_for_export()
        if not events:
            QMessageBox.information(self, "No Data", "No custody events to export.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Custody JSON", "chain_of_custody.json", "JSON Files (*.json)"
        )
        if path:
            try:
                self.audit.export_custody_json(events, path, self._get_case_number())
                mw = self.window()
                if hasattr(mw, "set_status"):
                    mw.set_status(f"Custody JSON saved: {path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Failed", str(e))

    def _export_html(self):
        events = self._get_events_for_export()
        if not events:
            QMessageBox.information(self, "No Data", "No custody events to export.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Custody HTML", "chain_of_custody.html", "HTML Files (*.html)"
        )
        if path:
            try:
                self.audit.export_custody_html(events, path, self._get_case_number())
                mw = self.window()
                if hasattr(mw, "set_status"):
                    mw.set_status(f"Custody HTML saved: {path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Failed", str(e))
