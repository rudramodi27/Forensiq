"""
Phase 2 — Evidence Acquisition panel.

FIXES:
  - BUG#1: Stop button re-connected every acquisition (signal stacking) — now uses abort()
  - BUG#2: _category_for() returned 'files' for all pulled media — now checks dir structure
  - BUG#3: Device registration failed silently then set device_id=None for all evidence
  - BUG#4: Output dir not created before worker start — moved os.makedirs earlier
  - BUG#5: File table size column showed 0 for files not yet written to disk
  - UI: Log font corrected to single family name; table column stretch fixed

Phase 3 — Device Acquisition Accuracy:
  - Each acquisition run now opens an acquisition_sessions row (start
    time, target list, device snapshot) instead of only registering/
    refreshing the device row. The device row itself (add_device) is
    still a stable get-or-update-or-create keyed on (case_id, serial) —
    unchanged — so re-running acquisition never creates a duplicate
    device; it creates a new session under the same device.
  - Evidence pulled during a run is now linked to that run's session_id.
"""

import os
import json
from datetime import datetime

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QCheckBox, QProgressBar, QFrame, QFileDialog, QLineEdit,
    QTextEdit, QGroupBox, QTableWidget, QTableWidgetItem,
    QHeaderView, QComboBox, QSplitter, QSizePolicy,
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QColor

from forensiq.core.adb_manager import ADBManager
from forensiq.core.case_manager import CaseManager


TARGETS = [
    ("apps",      "Installed Applications",  "Third-party APK list with installer info"),
    ("processes", "Running Processes",        "Active process table (ps -A)"),
    ("battery",   "Battery Information",      "Level, health, temperature, voltage"),
    ("network",   "Network Information",      "IP addresses, Wi-Fi state"),
    ("files",     "User Files",               "Photos, Videos, Documents from /sdcard"),
]


class AcquisitionPanel(QWidget):
    def __init__(self, adb: ADBManager, db: CaseManager, parent=None):
        super().__init__(parent)
        self.adb               = adb
        self.db                = db
        self._worker           = None
        self._active_case_id: int | None = None
        self._active_device_id: int | None = None
        self._active_session_id: int | None = None
        self._stop_requested   = False
        self._build()

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)

        # ── Left panel — configuration ─────────────────────────────────
        left = QWidget()
        ll   = QVBoxLayout(left)
        ll.setContentsMargins(0, 0, 0, 0)
        ll.setSpacing(14)

        # Context: case + device
        ctx = QFrame()
        ctx.setObjectName("card")
        ctx_l = QVBoxLayout(ctx)
        ctx_l.setContentsMargins(14, 12, 14, 12)
        ctx_l.setSpacing(8)

        ctx_title = QLabel("Context")
        ctx_title.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        ctx_l.addWidget(ctx_title)

        r1 = QHBoxLayout()
        r1.addWidget(QLabel("Case:"))
        self.case_combo = QComboBox()
        self.case_combo.setPlaceholderText("Select case…")
        self.case_combo.currentIndexChanged.connect(self._on_case_changed)
        r1.addWidget(self.case_combo, 1)
        ctx_l.addLayout(r1)

        r2 = QHBoxLayout()
        r2.addWidget(QLabel("Device Serial:"))
        self.serial_input = QLineEdit()
        self.serial_input.setPlaceholderText("e.g. emulator-5554  (auto-filled from Phase 1)")
        r2.addWidget(self.serial_input, 1)
        ctx_l.addLayout(r2)

        ll.addWidget(ctx)

        # Targets
        tg = QGroupBox("Acquisition Targets")
        tg_l = QVBoxLayout(tg)
        tg_l.setSpacing(4)
        self.checkboxes: dict[str, QCheckBox] = {}
        for key, label, tip in TARGETS:
            cb = QCheckBox(label)
            cb.setChecked(True)
            cb.setToolTip(tip)
            self.checkboxes[key] = cb
            sub = QLabel(tip)
            sub.setObjectName("metaLabel")
            sub.setContentsMargins(22, 0, 0, 4)
            tg_l.addWidget(cb)
            tg_l.addWidget(sub)
        ll.addWidget(tg)

        # Output directory
        out = QFrame()
        out.setObjectName("card")
        out_l = QVBoxLayout(out)
        out_l.setContentsMargins(14, 12, 14, 12)
        out_l.setSpacing(8)
        out_l.addWidget(self._titled_label("Output Directory"))

        dir_row = QHBoxLayout()
        self.dir_input = QLineEdit()
        self.dir_input.setText(
            os.path.join(os.path.expanduser("~"), "ForensIQ", "evidence")
        )
        browse = QPushButton("Browse…")
        browse.setFixedWidth(80)
        browse.clicked.connect(self._browse_dir)
        dir_row.addWidget(self.dir_input, 1)
        dir_row.addWidget(browse)
        out_l.addLayout(dir_row)
        ll.addWidget(out)

        # Action buttons
        btn_row = QHBoxLayout()
        self.btn_start = QPushButton("▶  Start Acquisition")
        self.btn_start.setObjectName("primaryBtn")
        self.btn_start.clicked.connect(self._start_acquisition)

        self.btn_stop = QPushButton("■  Stop")
        self.btn_stop.setObjectName("dangerBtn")
        self.btn_stop.setEnabled(False)
        # FIX: connect once at build time; abort() is idempotent
        self.btn_stop.clicked.connect(self._stop_acquisition)

        btn_row.addWidget(self.btn_start)
        btn_row.addWidget(self.btn_stop)
        ll.addLayout(btn_row)

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        ll.addWidget(self.progress_bar)

        self.progress_lbl = QLabel("Ready.")
        self.progress_lbl.setObjectName("metaLabel")
        ll.addWidget(self.progress_lbl)

        ll.addStretch()
        splitter.addWidget(left)

        # ── Right panel — log + file table ────────────────────────────
        right = QWidget()
        rl    = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(10)

        log_lbl = QLabel("Acquisition Log")
        log_lbl.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        rl.addWidget(log_lbl)

        self.log = QTextEdit()
        self.log.setReadOnly(True)
        # FIX: single font name, not comma list (Qt doesn't parse CSS font stacks)
        self.log.setFont(QFont("Courier New", 9))
        self.log.setMaximumHeight(180)
        rl.addWidget(self.log)

        files_lbl = QLabel("Acquired Files & SHA-256 Hashes")
        files_lbl.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        rl.addWidget(files_lbl)

        self.file_table = QTableWidget(0, 4)
        self.file_table.setMinimumHeight(160)
        self.file_table.setHorizontalHeaderLabels(["Category", "Filename", "SHA-256", "Size"])
        self.file_table.setAlternatingRowColors(True)
        self.file_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.file_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        # FIX: stretch SHA-256 column (2), not filename (1), so hashes are visible
        self.file_table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.Stretch
        )
        self.file_table.setColumnWidth(0, 100)
        self.file_table.setColumnWidth(1, 160)
        self.file_table.setColumnWidth(3, 80)
        rl.addWidget(self.file_table, 1)

        splitter.addWidget(right)
        splitter.setSizes([340, 640])
        layout.addWidget(splitter)

    def _titled_label(self, text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        return lbl

    # ── Slots ──────────────────────────────────────────────────────────

    def on_shown(self):
        self.case_combo.blockSignals(True)
        self.case_combo.clear()
        for case in self.db.get_all_cases():
            self.case_combo.addItem(
                f"{case['case_number']} — {case['title']}",
                userData=case["id"]
            )
        self.case_combo.blockSignals(False)
        if self.case_combo.count():
            self._on_case_changed(0)

    def _on_case_changed(self, idx: int):
        cid = self.case_combo.itemData(idx)
        if cid:
            self._active_case_id = cid
            case = self.db.get_case(cid)
            if case and case["evidence_dir"]:
                self.dir_input.setText(case["evidence_dir"])

    def _browse_dir(self):
        path = QFileDialog.getExistingDirectory(
            self, "Select Output Directory", self.dir_input.text()
        )
        if path:
            self.dir_input.setText(path)

    def _log(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log.append(f"[{ts}]  {msg}")

    def _add_file_row(self, category: str, filepath: str, sha256: str):
        row  = self.file_table.rowCount()
        self.file_table.insertRow(row)
        fname = os.path.basename(filepath)
        # FIX: read size here — file is confirmed on disk at this point
        try:
            size = os.path.getsize(filepath)
        except OSError:
            size = 0

        self.file_table.setItem(row, 0, QTableWidgetItem(category))
        self.file_table.setItem(row, 1, QTableWidgetItem(fname))

        hash_item = QTableWidgetItem(sha256[:32] + "…")
        hash_item.setForeground(QColor("#3FB950"))
        hash_item.setFont(QFont("Courier New", 8))
        self.file_table.setItem(row, 2, hash_item)

        self.file_table.setItem(row, 3, QTableWidgetItem(f"{size:,} B"))
        self.file_table.scrollToBottom()

    # ── Acquisition flow ───────────────────────────────────────────────

    def _start_acquisition(self):
        serial = self.serial_input.text().strip()
        if not serial:
            self._log("ERROR: Enter a device serial number.")
            return
        if not self._active_case_id:
            self._log("ERROR: Select a case first.")
            return

        targets = [k for k, cb in self.checkboxes.items() if cb.isChecked()]
        if not targets:
            self._log("ERROR: Select at least one target.")
            return

        output_dir = self.dir_input.text().strip()
        if not output_dir:
            self._log("ERROR: Set an output directory.")
            return

        # FIX: create dir BEFORE starting worker
        ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
        run_dir = os.path.join(output_dir, f"acquisition_{ts}")
        try:
            os.makedirs(run_dir, exist_ok=True)
        except OSError as e:
            self._log(f"ERROR: Cannot create output directory: {e}")
            return

        # FIX: register device first; log failure but continue
        # Phase 3: add_device() is a stable-identity get-or-create keyed on
        # (case_id, serial) — this NEVER creates a new device row for a
        # device already registered to this case, even across many
        # acquisition runs. The per-run record is the Acquisition Session
        # started below, not a new device.
        self._active_device_id  = None
        self._active_session_id = None
        self._stop_requested    = False
        dev_info = None
        try:
            dev_info = self.adb.get_device_info(serial)
            self._active_device_id = self.db.add_device(self._active_case_id, dev_info)
            self._log(f"Device registered: {dev_info.manufacturer} {dev_info.model} ({serial})")
        except Exception as e:
            self._log(f"Warning: Device registration failed — {e}")

        if self._active_device_id is not None and dev_info is not None:
            try:
                self._active_session_id = self.db.start_acquisition_session(
                    self._active_case_id,
                    self._active_device_id,
                    device_snapshot=dict(dev_info.__dict__),
                    targets=targets,
                    output_dir=run_dir,
                    adb_state="device",
                    usb_debugging=dev_info.usb_debugging,
                )
                self._log(f"Acquisition session #{self._active_session_id} started.")
            except Exception as e:
                self._log(f"Warning: Could not start acquisition session — {e}")

        self._log(f"Output directory: {run_dir}")
        self._log(f"Targets: {', '.join(targets)}")
        self.file_table.setRowCount(0)
        self.progress_bar.setValue(0)
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)

        self._worker = self.adb.acquire_async(
            serial, targets, run_dir,
            on_progress=self._on_progress,
            on_file=self._on_file_acquired,
            on_done=self._on_done,
            on_error=self._on_error,
        )

    def _stop_acquisition(self):
        if self._worker and self._worker.isRunning():
            self._worker.abort()
            self._stop_requested = True
            self._log("Stop requested — waiting for current operation to finish…")
            self.btn_stop.setEnabled(False)

    def _on_progress(self, pct: int, msg: str):
        if pct >= 0:
            self.progress_bar.setValue(pct)
        self.progress_lbl.setText(msg)
        self._log(msg)

    def _on_file_acquired(self, filepath: str, sha256: str):
        # Determine category from path
        category = self._category_for(filepath)
        self._log(f"✔  {os.path.basename(filepath)}  [{sha256[:16]}…]")
        self._add_file_row(category, filepath, sha256)

        if self._active_case_id:
            try:
                fname = os.path.basename(filepath)
                size  = os.path.getsize(filepath) if os.path.exists(filepath) else 0
                _new_eid = self.db.add_evidence(
                    case_id=self._active_case_id,
                    device_id=self._active_device_id,
                    category=category,
                    filename=fname,
                    filepath=filepath,
                    sha256=sha256,
                    file_size=size,
                    session_id=self._active_session_id,
                )
                _mw = self.window()
                if hasattr(_mw, "audit"):
                    _case = self.db.get_case(self._active_case_id)
                    _inv  = _case["investigator"] if _case else ""
                    _mw.audit.log_evidence_added(
                        self._active_case_id, _new_eid, _inv, fname, category,
                        filepath=filepath,
                    )
            except Exception as e:
                self._log(f"Warning: DB insert failed for {os.path.basename(filepath)}: {e}")

    def _category_for(self, filepath: str) -> str:
        """FIX: derive category from filepath, not just filename."""
        name  = os.path.basename(filepath)
        lower = filepath.lower().replace("\\", "/")
        if "installed_apps"   in name: return "apps"
        if "running_processes" in name: return "processes"
        if "battery_info"     in name: return "battery"
        if "network_info"     in name: return "network"
        if "/photos/"  in lower or "/dcim/" in lower or "/pictures/" in lower:
            return "photos"
        if "/videos/"  in lower or "/movies/" in lower:
            return "videos"
        if "/documents/" in lower or "/download/" in lower:
            return "documents"
        return "files"

    def _on_done(self, results: dict):
        self.progress_bar.setValue(100)
        self._log("=" * 50)
        self._log("Acquisition complete.")
        for key, val in results.items():
            if isinstance(val, dict):
                cnt = val.get("count", "")
                self._log(f"  {key}: {cnt} items" if cnt else f"  {key}: recorded")
            elif isinstance(val, list):
                self._log(f"  {key}: {len(val)} files")

        if self._active_session_id is not None:
            try:
                status = "aborted" if self._stop_requested else "completed"
                self.db.end_acquisition_session(self._active_session_id, status=status)
                self._log(f"Acquisition session #{self._active_session_id} marked {status}.")
            except Exception as e:
                self._log(f"Warning: Could not close acquisition session — {e}")

        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)

    def _on_error(self, msg: str):
        self._log(f"ERROR: {msg}")
        # Don't disable start here; error is per-target, acquisition may continue

    def set_serial(self, serial: str):
        self.serial_input.setText(serial)
