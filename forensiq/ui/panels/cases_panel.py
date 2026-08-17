"""
Phase 3 — Evidence Management panel.

FIXES:
  - BUG#1: Removed unused imports (QTreeWidget, QTreeWidgetItem, sha256_file)
  - BUG#2: Recent-cases widget cleanup leaked QLayoutItems (now properly deletes widgets)
  - BUG#3: case_number uniqueness not validated before DB insert — now shows error dialog
  - BUG#4: Evidence table had no minimum height — collapsed to zero on small windows
  - BUG#5: Notes save called window().set_status without guard — crashed outside MainWindow
  - BUG#6: Status dropdown missing — added close/archive actions
  - UI: Right panel now uses QScrollArea so content is never clipped
"""

import os
import json
from datetime import datetime

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QFrame, QDialog,
    QFormLayout, QLineEdit, QTextEdit, QDialogButtonBox,
    QHeaderView, QSplitter, QMessageBox, QFileDialog,
    QGroupBox, QScrollArea, QComboBox, QSizePolicy, QInputDialog,
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont, QColor

from forensiq.core.case_manager import (
    CaseManager, CASE_STATUSES, CASE_STATUS_LABELS, STATUS_COLORS,
    CASE_PRIORITIES, PRIORITY_COLORS, normalize_case_status,
)
from forensiq.core.integrity_engine import IntegrityEngine, VerificationWorker
from forensiq.core.analyzer import build_unified_timeline
from forensiq.core.time_utils import format_dual_plain


# ── New Case Dialog ────────────────────────────────────────────────────────────

class NewCaseDialog(QDialog):
    def __init__(self, db: CaseManager, parent=None):
        super().__init__(parent)
        self.db = db
        self.setWindowTitle("New Investigation Case")
        self.setMinimumWidth(500)
        self.setModal(True)
        self._build()

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(14)

        title = QLabel("Create New Case")
        title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        layout.addWidget(title)

        form = QFormLayout()
        form.setSpacing(10)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

        ts = datetime.now().strftime("CASE-%Y%m%d-%H%M")

        self.case_number  = QLineEdit(ts)
        self.title_input  = QLineEdit()
        self.title_input.setPlaceholderText("Brief case title")
        self.investigator = QLineEdit()
        self.investigator.setPlaceholderText("Full name")
        self.description  = QTextEdit()
        self.description.setPlaceholderText("Case summary…")
        self.description.setFixedHeight(70)
        self.evidence_dir = QLineEdit(
            os.path.join(os.path.expanduser("~"), "ForensIQ", "cases", ts)
        )

        browse = QPushButton("Browse…")
        browse.setFixedWidth(80)
        browse.clicked.connect(self._browse)

        dir_row = QHBoxLayout()
        dir_row.addWidget(self.evidence_dir, 1)
        dir_row.addWidget(browse)

        # Phase 8 — additional case metadata
        self.priority_combo = QComboBox()
        for p in CASE_PRIORITIES:
            self.priority_combo.addItem(p.capitalize(), p)
        self.priority_combo.setCurrentIndex(CASE_PRIORITIES.index("MEDIUM"))

        self.reviewer_input = QLineEdit()
        self.reviewer_input.setPlaceholderText("Optional — assign later")

        self.tags_input = QLineEdit()
        self.tags_input.setPlaceholderText("Comma-separated, e.g. mobile, fraud, urgent")

        form.addRow("Case Number:",  self.case_number)
        form.addRow("Title:",        self.title_input)
        form.addRow("Investigator:", self.investigator)
        form.addRow("Priority:",     self.priority_combo)
        form.addRow("Reviewer:",     self.reviewer_input)
        form.addRow("Tags:",         self.tags_input)
        form.addRow("Description:",  self.description)
        form.addRow("Evidence Dir:", dir_row)
        layout.addLayout(form)

        note = QLabel("New cases start in DRAFT status.")
        note.setObjectName("metaLabel")
        layout.addWidget(note)

        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        btns.accepted.connect(self._validate)
        btns.rejected.connect(self.reject)
        layout.addWidget(btns)

    def _browse(self):
        path = QFileDialog.getExistingDirectory(
            self, "Evidence Directory", self.evidence_dir.text()
        )
        if path:
            self.evidence_dir.setText(path)

    def _validate(self):
        cn = self.case_number.text().strip()
        if not cn:
            QMessageBox.warning(self, "Validation", "Case number is required.")
            return
        if not self.title_input.text().strip():
            QMessageBox.warning(self, "Validation", "Title is required.")
            return
        if not self.investigator.text().strip():
            QMessageBox.warning(self, "Validation", "Investigator name is required.")
            return
        # FIX: check uniqueness before attempting DB insert
        if self.db.case_number_exists(cn):
            QMessageBox.warning(
                self, "Duplicate Case",
                f"Case number '{cn}' already exists.\nChoose a different number."
            )
            return
        ev_dir = self.evidence_dir.text().strip()
        if ev_dir:
            try:
                os.makedirs(ev_dir, exist_ok=True)
            except OSError as e:
                QMessageBox.warning(self, "Directory Error",
                                    f"Cannot create evidence directory:\n{e}")
                return
        self.accept()

    def get_data(self) -> dict:
        tags = [t.strip() for t in self.tags_input.text().split(",") if t.strip()]
        return {
            "case_number":  self.case_number.text().strip(),
            "title":        self.title_input.text().strip(),
            "investigator": self.investigator.text().strip(),
            "description":  self.description.toPlainText().strip(),
            "evidence_dir": self.evidence_dir.text().strip(),
            "priority":     self.priority_combo.currentData(),
            "reviewer":     self.reviewer_input.text().strip(),
            "tags":         tags,
        }


# ── Cases Panel ────────────────────────────────────────────────────────────────

class CasesPanel(QWidget):
    case_selected = pyqtSignal(int, str)

    def __init__(self, db: CaseManager, parent=None):
        super().__init__(parent)
        self.db                  = db
        self._engine              = IntegrityEngine(db)
        self._verify_worker: VerificationWorker | None = None
        self._current_case_id: int | None = None
        self._notes_edit: QTextEdit | None = None
        self._build()

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(14)

        # Toolbar
        toolbar = QHBoxLayout()
        self.btn_new    = QPushButton("+ New Case")
        self.btn_new.setObjectName("primaryBtn")
        self.btn_delete = QPushButton("✕ Delete")
        self.btn_delete.setObjectName("dangerBtn")
        self.btn_delete.setEnabled(False)
        self.btn_new.clicked.connect(self._new_case)
        self.btn_delete.clicked.connect(self._delete_case)
        toolbar.addWidget(self.btn_new)
        toolbar.addWidget(self.btn_delete)
        toolbar.addStretch()
        layout.addLayout(toolbar)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)

        # ── Left: case list ────────────────────────────────────────────
        left = QWidget()
        ll   = QVBoxLayout(left)
        ll.setContentsMargins(0, 0, 0, 0)
        ll.setSpacing(6)

        lbl = QLabel("Cases")
        lbl.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        ll.addWidget(lbl)

        self.case_table = QTableWidget(0, 4)
        self.case_table.setMinimumHeight(160)
        self.case_table.setHorizontalHeaderLabels(["Case #", "Title", "Priority", "Status"])
        self.case_table.setAlternatingRowColors(True)
        self.case_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.case_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.case_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.case_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch
        )
        self.case_table.setColumnWidth(0, 130)
        self.case_table.setColumnWidth(2, 80)
        self.case_table.setColumnWidth(3, 130)
        self.case_table.currentCellChanged.connect(self._on_case_row_changed)
        ll.addWidget(self.case_table, 1)
        splitter.addWidget(left)

        # ── Right: detail ──────────────────────────────────────────────
        self._detail_scroll = QScrollArea()
        self._detail_scroll.setWidgetResizable(True)
        self._detail_scroll.setFrameShape(QFrame.Shape.NoFrame)

        self._detail_container = QWidget()
        self._detail_layout    = QVBoxLayout(self._detail_container)
        self._detail_layout.setContentsMargins(12, 0, 0, 12)
        self._detail_layout.setSpacing(14)
        self._detail_scroll.setWidget(self._detail_container)

        self._placeholder_lbl = QLabel("Select a case to view details.")
        self._placeholder_lbl.setObjectName("metaLabel")
        self._placeholder_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._detail_layout.addWidget(self._placeholder_lbl)
        self._detail_layout.addStretch()

        splitter.addWidget(self._detail_scroll)
        splitter.setSizes([360, 700])
        layout.addWidget(splitter, 1)

    # ── Detail pane helpers ────────────────────────────────────────────

    def _clear_detail(self):
        """FIX: properly delete all child widgets to avoid memory leaks."""
        while self._detail_layout.count():
            item = self._detail_layout.takeAt(0)
            w = item.widget()
            if w:
                w.setParent(None)
                w.deleteLater()
        self._notes_edit = None

    def _build_case_detail(self, case_id: int):
        self._clear_detail()
        case = self.db.get_case(case_id)
        if not case:
            return

        # ── Header card ────────────────────────────────────────────────
        hdr = QFrame()
        hdr.setObjectName("card")
        hl  = QVBoxLayout(hdr)
        hl.setContentsMargins(16, 14, 16, 14)
        hl.setSpacing(8)

        num_lbl = QLabel(case["case_number"])
        num_lbl.setObjectName("tealAccent")
        num_lbl.setFont(QFont("Segoe UI", 11))
        title_lbl = QLabel(case["title"])
        title_lbl.setFont(QFont("Segoe UI", 15, QFont.Weight.Bold))
        title_lbl.setWordWrap(True)

        hl.addWidget(num_lbl)
        hl.addWidget(title_lbl)

        meta_row = QHBoxLayout()
        meta_row.setSpacing(28)
        for k, v in [
            ("Investigator", case["investigator"]),
            ("Reviewer", case["reviewer"] or "—"),
            ("Created", (case["created_at"] or "")[:16]),
            ("Updated", (case["updated_at"] or "")[:16]),
        ]:
            col = QVBoxLayout()
            col.setSpacing(2)
            k_l = QLabel(k); k_l.setObjectName("metaLabel")
            v_l = QLabel(str(v) or "—")
            v_l.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
            col.addWidget(k_l); col.addWidget(v_l)
            meta_row.addLayout(col)

        # Priority badge
        pr_col = QVBoxLayout(); pr_col.setSpacing(2)
        pr_lbl = QLabel("Priority"); pr_lbl.setObjectName("metaLabel")
        priority = normalize_case_status(case["priority"]) or "MEDIUM"
        pr_val = QLabel(priority.capitalize())
        pr_val.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        pr_val.setStyleSheet(f"color:{PRIORITY_COLORS.get(priority, '#8B949E')};")
        pr_col.addWidget(pr_lbl); pr_col.addWidget(pr_val)
        meta_row.addLayout(pr_col)
        meta_row.addStretch()

        # Status control — only the case's current status plus valid next
        # statuses are offered, so the UI can never present a transition
        # CaseManager.update_case_status() would reject.
        status_col = QVBoxLayout()
        status_col.setSpacing(2)
        s_lbl = QLabel("Status"); s_lbl.setObjectName("metaLabel")
        self.status_combo = QComboBox()
        current_status = normalize_case_status(case["status"])
        choices = [current_status] + self.db.get_valid_next_statuses(current_status)
        for s in choices:
            self.status_combo.addItem(CASE_STATUS_LABELS.get(s, s), s)
        self.status_combo.setCurrentIndex(0)
        self.status_combo.currentIndexChanged.connect(
            lambda i: self._on_status_selected(case_id, self.status_combo.itemData(i))
        )
        status_col.addWidget(s_lbl); status_col.addWidget(self.status_combo)
        meta_row.addLayout(status_col)
        hl.addLayout(meta_row)

        tags = self.db.get_case_tags(case_id)
        if tags:
            tags_lbl = QLabel("🏷  " + ", ".join(tags))
            tags_lbl.setObjectName("metaLabel")
            tags_lbl.setWordWrap(True)
            hl.addWidget(tags_lbl)

        if (case["description"] or "").strip():
            desc = QLabel(case["description"])
            desc.setObjectName("metaLabel")
            desc.setWordWrap(True)
            hl.addWidget(desc)

        if (case["evidence_dir"] or "").strip():
            dir_lbl = QLabel(f"📁  {case['evidence_dir']}")
            dir_lbl.setObjectName("metaLabel")
            dir_lbl.setWordWrap(True)
            hl.addWidget(dir_lbl)

        if current_status == "CLOSED" and (case["closure_reason"] or "").strip():
            reason_lbl = QLabel(f"Closure reason: {case['closure_reason']}")
            reason_lbl.setObjectName("metaLabel")
            reason_lbl.setWordWrap(True)
            hl.addWidget(reason_lbl)

        self._detail_layout.addWidget(hdr)

        # ── Editable case details ─────────────────────────────────────
        edit_grp = QGroupBox("Case Details")
        eg_form  = QFormLayout(edit_grp)
        eg_form.setSpacing(8)

        self._edit_title = QLineEdit(case["title"] or "")
        self._edit_investigator = QLineEdit(case["investigator"] or "")
        self._edit_reviewer = QLineEdit(case["reviewer"] or "")
        self._edit_priority = QComboBox()
        for p in CASE_PRIORITIES:
            self._edit_priority.addItem(p.capitalize(), p)
        self._edit_priority.setCurrentIndex(
            CASE_PRIORITIES.index(priority) if priority in CASE_PRIORITIES else 1
        )
        self._edit_tags = QLineEdit(", ".join(tags))
        self._edit_description = QTextEdit(case["description"] or "")
        self._edit_description.setFixedHeight(60)

        eg_form.addRow("Title:", self._edit_title)
        eg_form.addRow("Investigator:", self._edit_investigator)
        eg_form.addRow("Reviewer:", self._edit_reviewer)
        eg_form.addRow("Priority:", self._edit_priority)
        eg_form.addRow("Tags:", self._edit_tags)
        eg_form.addRow("Description:", self._edit_description)

        save_details_btn = QPushButton("Save Case Details")
        save_details_btn.setObjectName("primaryBtn")
        save_details_btn.clicked.connect(lambda: self._save_case_details(case_id))
        eg_form.addRow(save_details_btn)

        if current_status == "ARCHIVED":
            for w in (self._edit_title, self._edit_investigator, self._edit_reviewer,
                      self._edit_priority, self._edit_tags, self._edit_description,
                      save_details_btn):
                w.setEnabled(False)
            eg_form.addRow(QLabel("Case is ARCHIVED — read-only. Reopen it to edit."))

        self._detail_layout.addWidget(edit_grp)

        # ── Devices ────────────────────────────────────────────────────
        devices = self.db.get_devices_for_case(case_id)
        dev_grp = QGroupBox(f"Devices  ({len(devices)})")
        dg_l    = QVBoxLayout(dev_grp)
        if devices:
            for d in devices:
                df = QFrame(); df.setObjectName("card")
                dfv = QVBoxLayout(df)
                dfv.setContentsMargins(12, 8, 12, 8)

                dfl = QHBoxLayout()
                info = QVBoxLayout()
                info.addWidget(QLabel(f"{d['manufacturer']} {d['model']}"))
                sub = QLabel(
                    f"Serial: {d['serial']}  ·  "
                    f"Android {d['android_version']}  ·  "
                    f"SDK {d['sdk_version']}  ·  "
                    f"CPU: {d['cpu_abi']}  ·  "
                    f"First seen: {d['first_connected'] or d['acquired_at']}  ·  "
                    f"Last seen: {d['last_connected'] or d['acquired_at']}"
                )
                sub.setObjectName("metaLabel")
                sub.setWordWrap(True)
                info.addWidget(sub)
                dfl.addLayout(info, 1)
                usb = QLabel("USB Debug ✔" if d["usb_debugging"] else "USB Debug ✘")
                usb.setStyleSheet(
                    "color:#3FB950;" if d["usb_debugging"] else "color:#F85149;"
                )
                dfl.addWidget(usb)
                dfv.addLayout(dfl)

                # Phase 3 — one device row, its acquisition sessions
                # nested underneath it (never a repeated device row).
                sessions = self.db.get_sessions_for_device(d["id"])
                sess_hdr = QLabel(f"└─ Acquisition Sessions ({len(sessions)})")
                sess_hdr.setObjectName("metaLabel")
                dfv.addWidget(sess_hdr)
                if sessions:
                    for s in sessions:
                        try:
                            targets_str = ", ".join(json.loads(s["targets"] or "[]"))
                        except (TypeError, ValueError):
                            targets_str = ""
                        ev_count = len(self.db.get_evidence_for_session(s["id"]))
                        sline = QLabel(
                            f"    Session #{s['id']}  ·  {s['status']}  ·  "
                            f"started {s['start_time']}"
                            + (f"  ·  ended {s['end_time']}" if s["end_time"] else "")
                            + f"  ·  targets: {targets_str or '—'}  ·  evidence: {ev_count}"
                        )
                        sline.setObjectName("metaLabel")
                        sline.setWordWrap(True)
                        dfv.addWidget(sline)
                else:
                    none_lbl = QLabel("    No acquisition sessions recorded for this device.")
                    none_lbl.setObjectName("metaLabel")
                    dfv.addWidget(none_lbl)

                dg_l.addWidget(df)
        else:
            dg_l.addWidget(QLabel("No devices linked yet. Run Phase 1 + 2."))
        self._detail_layout.addWidget(dev_grp)

        # ── Related Evidence ─────────────────────────────────────────────
        evidence = self.db.get_evidence_for_case(case_id)
        ev_list  = list(evidence)
        ev_grp   = QGroupBox(f"Related Evidence  ({len(ev_list)} items)")
        eg_l     = QVBoxLayout(ev_grp)

        if ev_list:
            ev_tbl = QTableWidget(len(ev_list), 4)
            ev_tbl.setHorizontalHeaderLabels(["Category", "Filename", "SHA-256", "Acquired"])
            ev_tbl.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
            ev_tbl.setAlternatingRowColors(True)
            ev_tbl.horizontalHeader().setSectionResizeMode(
                2, QHeaderView.ResizeMode.Stretch
            )
            ev_tbl.setColumnWidth(0, 90)
            ev_tbl.setColumnWidth(1, 150)
            ev_tbl.setColumnWidth(3, 130)
            # FIX: set minimum height so table doesn't collapse
            ev_tbl.setMinimumHeight(120)
            ev_tbl.setToolTip("Double-click an item to view it in Chain of Custody.")

            for r, ev in enumerate(ev_list):
                cat_item = QTableWidgetItem(ev["category"] or "")
                cat_item.setData(Qt.ItemDataRole.UserRole, ev["id"])
                ev_tbl.setItem(r, 0, cat_item)
                ev_tbl.setItem(r, 1, QTableWidgetItem(ev["filename"] or "—"))
                sha = (ev["sha256"] or "")
                hi  = QTableWidgetItem(sha[:32] + ("…" if sha else ""))
                hi.setForeground(QColor("#3FB950"))
                hi.setFont(QFont("Courier New", 8))
                ev_tbl.setItem(r, 2, hi)
                ev_tbl.setItem(r, 3, QTableWidgetItem((ev["acquired_at"] or "")[:16]))

            ev_tbl.cellDoubleClicked.connect(
                lambda row, _col: self._goto_evidence_in_custody(case_id)
            )
            eg_l.addWidget(ev_tbl)

            # Verify all hashes button
            self._verify_btn = QPushButton("✔  Verify All SHA-256 Hashes")
            self._verify_btn.clicked.connect(lambda: self._verify_all(case_id))
            eg_l.addWidget(self._verify_btn)
        else:
            eg_l.addWidget(QLabel("No evidence acquired yet."))

        self._detail_layout.addWidget(ev_grp)

        # ── Case Activity ─────────────────────────────────────────────
        # Reuses the existing Phase 7 Unified Timeline builder — the same
        # function the Analysis panel's Timeline tab and the forensic
        # reports use — so status changes, evidence actions, device/
        # acquisition activity, analysis runs, custody events, and
        # investigator/audit actions all show up here without a second,
        # duplicate activity feed being built.
        activity_grp = QGroupBox("Case Activity")
        ag_l = QVBoxLayout(activity_grp)
        try:
            events = build_unified_timeline(case["evidence_dir"] or "", self.db, case_id)
        except Exception:
            events = []
        events = sorted(events, key=lambda e: str(e.get("timestamp") or ""), reverse=True)[:50]

        if events:
            act_tbl = QTableWidget(len(events), 4)
            act_tbl.setHorizontalHeaderLabels(["Timestamp", "Category", "Actor", "Description"])
            act_tbl.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
            act_tbl.setAlternatingRowColors(True)
            act_tbl.horizontalHeader().setSectionResizeMode(
                3, QHeaderView.ResizeMode.Stretch
            )
            act_tbl.setColumnWidth(0, 150)
            act_tbl.setColumnWidth(1, 110)
            act_tbl.setColumnWidth(2, 110)
            act_tbl.setMinimumHeight(160)
            for r, ev in enumerate(events):
                # Phase 10: dual UTC/IST display (was raw truncated UTC
                # with no timezone label).
                act_tbl.setItem(r, 0, QTableWidgetItem(format_dual_plain(ev.get("timestamp"), sep=" / ")))
                act_tbl.setItem(r, 1, QTableWidgetItem(str(ev.get("category") or "")))
                act_tbl.setItem(r, 2, QTableWidgetItem(str(ev.get("actor") or "")))
                act_tbl.setItem(r, 3, QTableWidgetItem(str(ev.get("description") or "")))
            ag_l.addWidget(act_tbl)
            hint = QLabel("Showing the 50 most recent events. Full history: Audit Trail / Timeline tab.")
            hint.setObjectName("metaLabel")
            ag_l.addWidget(hint)
        else:
            ag_l.addWidget(QLabel("No recorded activity yet for this case."))

        self._detail_layout.addWidget(activity_grp)

        # ── Investigator notes ─────────────────────────────────────────
        notes_grp = QGroupBox("Investigator Notes / Chain of Custody")
        ng_l      = QVBoxLayout(notes_grp)

        self._notes_edit = QTextEdit()
        self._notes_edit.setPlaceholderText(
            "Record observations, chain of custody, findings…"
        )
        self._notes_edit.setPlainText(case["notes"] or "")
        self._notes_edit.setMinimumHeight(100)
        ng_l.addWidget(self._notes_edit)

        save_btn = QPushButton("Save Notes")
        save_btn.setObjectName("primaryBtn")
        save_btn.setFixedWidth(120)
        save_btn.clicked.connect(lambda: self._save_notes(case_id))
        ng_l.addWidget(save_btn)

        if current_status == "ARCHIVED":
            self._notes_edit.setEnabled(False)
            save_btn.setEnabled(False)

        self._detail_layout.addWidget(notes_grp)
        self._detail_layout.addStretch()

    # ── Slots ──────────────────────────────────────────────────────────

    def on_shown(self):
        self._refresh_table()

    def _refresh_table(self):
        prev_id = self._current_case_id
        self.case_table.setRowCount(0)
        for case in self.db.get_all_cases():
            row = self.case_table.rowCount()
            self.case_table.insertRow(row)
            num_item = QTableWidgetItem(case["case_number"])
            num_item.setData(Qt.ItemDataRole.UserRole, case["id"])
            self.case_table.setItem(row, 0, num_item)
            self.case_table.setItem(row, 1, QTableWidgetItem(case["title"] or ""))

            priority = normalize_case_status(case["priority"]) or "MEDIUM"
            pi = QTableWidgetItem(priority.capitalize())
            pi.setForeground(QColor(PRIORITY_COLORS.get(priority, "#8B949E")))
            self.case_table.setItem(row, 2, pi)

            status = normalize_case_status(case["status"])
            si = QTableWidgetItem(CASE_STATUS_LABELS.get(status, status))
            si.setForeground(QColor(STATUS_COLORS.get(status, "#8B949E")))
            self.case_table.setItem(row, 3, si)

        # Restore selection
        if prev_id:
            for row in range(self.case_table.rowCount()):
                item = self.case_table.item(row, 0)
                if item and item.data(Qt.ItemDataRole.UserRole) == prev_id:
                    self.case_table.selectRow(row)
                    return

    def _on_case_row_changed(self, row: int, *_):
        item = self.case_table.item(row, 0)
        if not item:
            return
        case_id = item.data(Qt.ItemDataRole.UserRole)
        if case_id and case_id != self._current_case_id:
            self._current_case_id = case_id
            self.btn_delete.setEnabled(True)
            self._build_case_detail(case_id)
            case = self.db.get_case(case_id)
            if case:
                self.case_selected.emit(case_id, case["case_number"])
                mw = self.window()
                if hasattr(mw, "set_active_case"):
                    mw.set_active_case(case["case_number"], case["investigator"])

    def _new_case(self):
        dlg = NewCaseDialog(self.db, self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            data = dlg.get_data()
            try:
                new_cid = self.db.create_case(**data)
                self._refresh_table()
                mw = self.window()
                if hasattr(mw, "audit"):
                    mw.audit.log_case_created(new_cid, data["investigator"], data["case_number"])
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Could not create case:\n{e}")

    def _delete_case(self):
        if not self._current_case_id:
            return
        case = self.db.get_case(self._current_case_id)
        if not case:
            return
        reply = QMessageBox.question(
            self, "Delete Case",
            f"Permanently delete '{case['case_number']}'?\n"
            "All linked devices, evidence and analysis will be removed.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            _case_to_del = self.db.get_case(self._current_case_id)
            self.db.delete_case(self._current_case_id)
            mw = self.window()
            if hasattr(mw, "audit") and _case_to_del:
                mw.audit.log_case_deleted(
                    _case_to_del["id"],
                    _case_to_del["investigator"],
                    _case_to_del["case_number"],
                )
            self._current_case_id = None
            self.btn_delete.setEnabled(False)
            self._clear_detail()
            self._placeholder_lbl = QLabel("Select a case to view details.")
            self._placeholder_lbl.setObjectName("metaLabel")
            self._placeholder_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self._detail_layout.addWidget(self._placeholder_lbl)
            self._detail_layout.addStretch()
            self._refresh_table()

    def _save_notes(self, case_id: int):
        if self._notes_edit is None:
            return
        notes_text = self._notes_edit.toPlainText()
        try:
            self.db.update_case_notes(case_id, notes_text)
        except ValueError as e:
            QMessageBox.warning(self, "Case is read-only", str(e))
            return
        # FIX: guard before calling parent window method
        mw = self.window()
        if hasattr(mw, "audit"):
            case = self.db.get_case(case_id)
            inv  = case["investigator"] if case else ""
            mw.audit.log_notes_edited(case_id, inv)
        if hasattr(mw, "set_status"):
            mw.set_status("Notes saved.")

    def _save_case_details(self, case_id: int):
        """Persist edits from the 'Case Details' group (title, investigator,
        reviewer, priority, tags, description)."""
        tags = [t.strip() for t in self._edit_tags.text().split(",") if t.strip()]
        try:
            changed = self.db.update_case(
                case_id,
                title=self._edit_title.text().strip(),
                investigator=self._edit_investigator.text().strip(),
                reviewer=self._edit_reviewer.text().strip(),
                priority=self._edit_priority.currentData(),
                tags=tags,
                description=self._edit_description.toPlainText().strip(),
            )
        except ValueError as e:
            QMessageBox.warning(self, "Case is read-only", str(e))
            return
        mw = self.window()
        if changed and hasattr(mw, "audit"):
            inv = self._edit_investigator.text().strip()
            mw.audit.log_case_modified(
                case_id, inv,
                "title, investigator, reviewer, priority, tags, description"
            )
        self._refresh_table()
        if self._current_case_id == case_id:
            self._build_case_detail(case_id)
        if hasattr(mw, "set_status"):
            mw.set_status("Case details saved.")

    def _on_status_selected(self, case_id: int, status: str):
        """
        Combo-box handler for the Status control. CLOSED requires a
        closure reason, collected here via a dialog; if the user cancels,
        the combo is reset to the case's current status without saving.
        """
        if status is None:
            return
        case = self.db.get_case(case_id)
        current_status = normalize_case_status(case["status"]) if case else None
        if status == current_status:
            return  # combo repopulated to the same value — no-op

        closure_reason = None
        if status == "CLOSED":
            existing = (case["closure_reason"] or "") if case else ""
            text, ok = QInputDialog.getMultiLineText(
                self, "Close Case",
                "Closure reason (required):", existing
            )
            if not ok:
                self._build_case_detail(case_id)  # revert combo selection
                return
            if not text.strip():
                QMessageBox.warning(self, "Closure Reason Required",
                                    "Closing a case requires a closure reason.")
                self._build_case_detail(case_id)
                return
            closure_reason = text.strip()

        self._update_status(case_id, status, closure_reason=closure_reason,
                            previous_status=current_status)

    def _update_status(self, case_id: int, status: str,
                       closure_reason: str = None,
                       previous_status: str = None):
        try:
            self.db.update_case_status(case_id, status, closure_reason=closure_reason)
            mw = self.window()
            if hasattr(mw, "audit"):
                case = self.db.get_case(case_id)
                inv  = case["investigator"] if case else ""
                mw.audit.log_case_status_changed(
                    case_id, inv, status,
                    previous_status=previous_status,
                    closure_reason=closure_reason,
                )
            self._refresh_table()
            if self._current_case_id == case_id:
                self._build_case_detail(case_id)
        except Exception as e:
            QMessageBox.warning(self, "Error", str(e))
            if self._current_case_id == case_id:
                self._build_case_detail(case_id)

    def _goto_evidence_in_custody(self, case_id: int):
        """Navigate from a case's Related Evidence list to the Chain of
        Custody panel, pre-selected to this case."""
        mw = self.window()
        if hasattr(mw, "_nav_to") and hasattr(mw, "panels"):
            mw._nav_to("custody")
            custody_panel = mw.panels.get("custody")
            if custody_panel and hasattr(custody_panel, "select_case"):
                custody_panel.select_case(case_id)

    def _verify_all(self, case_id: int):
        """
        Verify all evidence SHA-256 hashes on a background thread.
        PERF FIX: previously re-hashed every evidence file synchronously on
        the UI thread (os.urandom-equivalent I/O for every item), freezing
        the entire application for the full duration with no progress
        feedback. Now reuses the existing VerificationWorker (already used
        by the Integrity panel) which runs verify_single() per item off the
        UI thread and emits progress signals.
        verify_single() already persists to verification_results and matches
        the Phase 1 fix that ensures results are not silently discarded.
        """
        evidence = list(self.db.get_evidence_for_case(case_id))
        if not evidence:
            return
        if self._verify_worker and self._verify_worker.isRunning():
            return   # already running

        if hasattr(self, "_verify_btn"):
            self._verify_btn.setEnabled(False)
            self._verify_btn.setText("Verifying…")

        self._verify_worker = VerificationWorker(self._engine, mode="case", case_id=case_id)
        self._verify_worker.finished.connect(
            lambda results: self._on_verify_all_done(case_id, results)
        )
        self._verify_worker.error.connect(self._on_verify_all_error)
        self._verify_worker.start()

    def _on_verify_all_done(self, case_id: int, results: list[dict]):
        """Build the same summary dialog and audit trail entries the old
        synchronous implementation produced, now driven by VerificationWorker
        results computed off the UI thread."""
        ok_count = bad_count = missing = 0
        lines: list[str] = []

        case = self.db.get_case(case_id)
        inv  = case["investigator"] if case else ""
        mw   = self.window()
        has_audit = hasattr(mw, "audit")

        for r in results:
            result   = r.get("result", "ERROR")
            filename = r.get("filename") or str(r.get("evidence_id", ""))
            if result == "PASS":
                ok_count += 1
                lines.append(f"OK       {filename}")
            elif result in ("MISSING", "ERROR"):
                missing += 1
                lines.append(f"MISSING  {filename}: {r.get('notes', '')}")
            else:
                bad_count += 1
                lines.append(f"MISMATCH {filename}")

            # Audit log — matches prior synchronous behavior
            if has_audit:
                try:
                    mw.audit.log_verification(
                        case_id, r.get("evidence_id"), inv, result,
                        filename, r.get("stored_hash", "")
                    )
                except Exception:
                    pass

        if hasattr(self, "_verify_btn"):
            self._verify_btn.setEnabled(True)
            self._verify_btn.setText("✔  Verify All SHA-256 Hashes")

        summary = (
            f"Verification complete.\n\n"
            f"✔  Verified:  {ok_count}\n"
            f"✘  Mismatch:  {bad_count}\n"
            f"—  Missing:   {missing}\n\n"
            + "\n".join(lines[:40])
            + ("\n…" if len(lines) > 40 else "")
        )
        QMessageBox.information(self, "SHA-256 Verification", summary)

        # Refresh the evidence table in the detail view to show updated status
        if self._current_case_id == case_id:
            self._build_case_detail(case_id)

    def _on_verify_all_error(self, msg: str):
        if hasattr(self, "_verify_btn"):
            self._verify_btn.setEnabled(True)
            self._verify_btn.setText("✔  Verify All SHA-256 Hashes")
        QMessageBox.warning(self, "Verification Error", msg)
