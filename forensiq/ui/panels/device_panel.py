"""
Phase 1 — Device Identification panel.
Detects connected Android devices via ADB and displays full device info.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QFrame, QHeaderView,
    QGroupBox, QGridLayout, QSizePolicy,
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QColor

from forensiq.core.adb_manager import ADBManager, DeviceInfo


def _badge(text: str, ok: bool) -> QLabel:
    lbl = QLabel(text)
    color = "#3FB950" if ok else "#F85149"
    lbl.setStyleSheet(
        f"color: {color}; background: {color}22; border-radius: 10px;"
        "padding: 2px 10px; font-size: 11px; font-weight: 600;"
    )
    return lbl


class DeviceInfoCard(QFrame):
    def __init__(self):
        super().__init__()
        self.setObjectName("card")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(10)

        title = QLabel("Device Details")
        title.setFont(QFont("Segoe UI", 13, QFont.Weight.Bold))
        layout.addWidget(title)

        self.grid = QGridLayout()
        self.grid.setSpacing(8)
        layout.addLayout(self.grid)

        self._rows: dict[str, QLabel] = {}
        fields = [
            ("Serial Number", "serial"),
            ("Manufacturer",  "manufacturer"),
            ("Model",         "model"),
            ("Android Version", "android_version"),
            ("SDK Version",   "sdk_version"),
            ("Build Number",  "build_number"),
            ("CPU ABI",       "cpu_abi"),
            ("USB Debugging", "usb_debugging"),
        ]
        for i, (label, key) in enumerate(fields):
            k_lbl = QLabel(label)
            k_lbl.setObjectName("metaLabel")
            k_lbl.setFixedWidth(140)
            v_lbl = QLabel("—")
            v_lbl.setWordWrap(True)
            self.grid.addWidget(k_lbl, i, 0)
            self.grid.addWidget(v_lbl, i, 1)
            self._rows[key] = v_lbl

        self.setVisible(False)

    def populate(self, info: DeviceInfo):
        self._rows["serial"].setText(info.serial)
        self._rows["manufacturer"].setText(info.manufacturer)
        self._rows["model"].setText(info.model)
        self._rows["android_version"].setText(f"Android {info.android_version}")
        self._rows["sdk_version"].setText(f"API {info.sdk_version}")
        self._rows["build_number"].setText(info.build_number)
        self._rows["cpu_abi"].setText(info.cpu_abi)

        usb_lbl = self._rows["usb_debugging"]
        if info.usb_debugging:
            usb_lbl.setText("✔  Enabled")
            usb_lbl.setStyleSheet("color: #3FB950; font-weight: 600;")
        else:
            usb_lbl.setText("✘  Disabled — enable in Developer Options")
            usb_lbl.setStyleSheet("color: #F85149;")

        self.setVisible(True)


class DevicePanel(QWidget):
    def __init__(self, adb: ADBManager, parent=None):
        super().__init__(parent)
        self.adb = adb
        self._devices: list[DeviceInfo] = []
        self._worker = None
        self._build()

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        # ── Toolbar ────────────────────────────────────────────────────
        toolbar = QHBoxLayout()
        self.btn_scan = QPushButton("⬡  Scan for Devices")
        self.btn_scan.setObjectName("primaryBtn")
        self.btn_scan.setFixedWidth(180)
        self.btn_scan.clicked.connect(self._scan)

        self.scan_status = QLabel("Click 'Scan' to detect connected Android devices.")
        self.scan_status.setObjectName("metaLabel")

        toolbar.addWidget(self.btn_scan)
        toolbar.addSpacing(12)
        toolbar.addWidget(self.scan_status)
        toolbar.addStretch()
        layout.addLayout(toolbar)

        # ── Device table ───────────────────────────────────────────────
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Serial", "Manufacturer / Model", "Android", "USB Debug"])
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.setFixedHeight(200)
        self.table.currentCellChanged.connect(self._on_row_selected)
        layout.addWidget(self.table)

        # ── USB Debugging helper ────────────────────────────────────────
        help_frame = QFrame()
        help_frame.setObjectName("card")
        help_layout = QVBoxLayout(help_frame)
        help_layout.setContentsMargins(14, 10, 14, 10)
        help_layout.setSpacing(4)
        help_lbl = QLabel("USB Debugging not enabled?")
        help_lbl.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        steps_lbl = QLabel(
            "Settings → About Phone → tap 'Build Number' 7 times → "
            "Developer Options → Enable USB Debugging → Authorize this computer."
        )
        steps_lbl.setObjectName("metaLabel")
        steps_lbl.setWordWrap(True)
        help_layout.addWidget(help_lbl)
        help_layout.addWidget(steps_lbl)
        layout.addWidget(help_frame)

        # ── Device info card ───────────────────────────────────────────
        self.info_card = DeviceInfoCard()
        layout.addWidget(self.info_card)
        layout.addStretch()

    def _scan(self):
        self.btn_scan.setEnabled(False)
        self.scan_status.setText("Scanning…")
        self.table.setRowCount(0)
        self.info_card.setVisible(False)
        self._devices = []

        self._worker = self.adb.detect_devices_async(
            on_done=self._on_devices_found,
            on_error=self._on_error,
        )

    def _on_devices_found(self, devices: list[DeviceInfo]):
        self.btn_scan.setEnabled(True)
        self._devices = devices

        if not devices:
            self.scan_status.setText("No devices found. Check USB connection and try again.")
            return

        self.scan_status.setText(f"{len(devices)} device(s) detected.")
        self.table.setRowCount(len(devices))

        for row, dev in enumerate(devices):
            self.table.setItem(row, 0, QTableWidgetItem(dev.serial))
            self.table.setItem(row, 1, QTableWidgetItem(f"{dev.manufacturer} {dev.model}"))
            self.table.setItem(row, 2, QTableWidgetItem(f"Android {dev.android_version}"))

            usb_item = QTableWidgetItem("✔  Enabled" if dev.usb_debugging else "✘  Disabled")
            usb_item.setForeground(
                QColor("#3FB950") if dev.usb_debugging else QColor("#F85149")
            )
            self.table.setItem(row, 3, usb_item)

        self.table.selectRow(0)

    def _on_row_selected(self, row: int, *_):
        if 0 <= row < len(self._devices):
            self.info_card.populate(self._devices[row])

    def _on_error(self, msg: str):
        self.btn_scan.setEnabled(True)
        self.scan_status.setText(f"Error: {msg}")

    def on_shown(self):
        pass

    def selected_device(self) -> DeviceInfo | None:
        """Returns the currently selected DeviceInfo, or None."""
        row = self.table.currentRow()
        if 0 <= row < len(self._devices):
            return self._devices[row]
        return None
