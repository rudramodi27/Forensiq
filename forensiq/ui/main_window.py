"""
MainWindow — top-level application window.
Sidebar navigation + stacked content panels (one per phase).
"""

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QVBoxLayout,
    QPushButton, QLabel, QStackedWidget, QStatusBar,
    QFrame, QSizePolicy, QSpacerItem,
)
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QFont, QIcon

from forensiq.ui.styles import STYLESHEET
from forensiq.core.audit_service import AuditService
from forensiq.core.adb_manager import ADBManager
from forensiq.core.case_manager import CaseManager


NAV_ITEMS = [
    ("dashboard",   "⌂  Dashboard",     "Overview and quick-action panel"),
    ("device",      "⎙  Device",        "Phase 1 — Device identification"),
    ("acquisition", "↓  Acquisition",   "Phase 2 — Evidence acquisition"),
    ("cases",       "◉  Cases",         "Phase 3 — Evidence management"),
    ("analysis",    "⊕  Analysis",      "Phase 4 — Artifact analysis"),
    ("report",      "▤  Reports",       "Phase 5 — Report generation"),
    ("signature",   "🔏  Signatures",    "Phase 5 — Cryptographic signing & verification"),
    ("integrity",   "⊞  Integrity",     "SHA-256 integrity verification"),
    ("audit",       "≡  Audit Trail",   "Immutable system audit log"),
    ("custody",     "⛓  Custody",       "Chain of custody management"),
]


class SidebarButton(QPushButton):
    def __init__(self, label: str, tooltip: str):
        super().__init__(label)
        self.setToolTip(tooltip)
        self.setProperty("active", False)
        self.setMinimumHeight(40)
        self.setCheckable(False)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

    def set_active(self, active: bool):
        self.setProperty("active", active)
        # Force style refresh
        self.style().unpolish(self)
        self.style().polish(self)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ForensIQ — Digital Forensic Tool")
        self.resize(1280, 820)
        self.setMinimumSize(960, 640)

        # Shared services
        self.adb   = ADBManager()
        self.db    = CaseManager()
        self.audit = AuditService(self.db)

        self.setStyleSheet(STYLESHEET)
        self._build_ui()
        self._nav_to("dashboard")

    def _build_ui(self):
        root = QWidget()
        root.setObjectName("contentPanel")
        self.setCentralWidget(root)
        layout = QHBoxLayout(root)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # ── Sidebar ──────────────────────────────────────────────────
        sidebar = QWidget()
        sidebar.setObjectName("sidebar")
        sidebar.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Expanding)
        sb_layout = QVBoxLayout(sidebar)
        sb_layout.setContentsMargins(8, 0, 8, 8)
        sb_layout.setSpacing(2)

        # Brand header
        brand = QWidget()
        brand.setObjectName("card")
        brand.setFixedHeight(60)
        brand_layout = QVBoxLayout(brand)
        brand_layout.setContentsMargins(12, 8, 12, 8)
        brand_layout.setSpacing(2)
        name_lbl = QLabel("ForensIQ")
        name_lbl.setFont(QFont("Segoe UI", 15, QFont.Weight.Bold))
        name_lbl.setObjectName("tealAccent")
        sub_lbl = QLabel("Digital Forensic Suite")
        sub_lbl.setObjectName("metaLabel")
        brand_layout.addWidget(name_lbl)
        brand_layout.addWidget(sub_lbl)
        sb_layout.addSpacing(8)
        sb_layout.addWidget(brand)
        sb_layout.addSpacing(12)

        # Section divider label
        def section_label(text):
            lbl = QLabel(text)
            lbl.setObjectName("metaLabel")
            lbl.setContentsMargins(8, 4, 0, 2)
            font = lbl.font()
            font.setPointSize(9)
            lbl.setFont(font)
            return lbl

        sb_layout.addWidget(section_label("INVESTIGATION"))

        # Nav buttons
        self._nav_buttons: dict[str, SidebarButton] = {}
        for key, label, tip in NAV_ITEMS:
            btn = SidebarButton(label, tip)
            btn.clicked.connect(lambda checked, k=key: self._nav_to(k))
            self._nav_buttons[key] = btn
            sb_layout.addWidget(btn)
            if key == "acquisition":  # visual separator
                sb_layout.addSpacing(8)
                sb_layout.addWidget(section_label("MANAGEMENT"))
            if key == "cases":
                sb_layout.addSpacing(8)
                sb_layout.addWidget(section_label("INTELLIGENCE"))
            if key == "signature":
                sb_layout.addSpacing(8)
                sb_layout.addWidget(section_label("INTEGRITY"))
            if key == "integrity":
                sb_layout.addSpacing(8)
                sb_layout.addWidget(section_label("ACCOUNTABILITY"))

        sb_layout.addStretch()

        # Status widget at bottom
        status_widget = QWidget()
        sv_layout = QVBoxLayout(status_widget)
        sv_layout.setContentsMargins(8, 8, 8, 4)
        sv_layout.setSpacing(2)
        self.status_dot_lbl = QLabel("● ADB Ready")
        self.status_dot_lbl.setObjectName("successLabel")
        self.status_dot_lbl.setFont(QFont("Segoe UI", 11))
        self.investigator_lbl = QLabel("Investigator: —")
        self.investigator_lbl.setObjectName("metaLabel")
        sv_layout.addWidget(self.status_dot_lbl)
        sv_layout.addWidget(self.investigator_lbl)
        sb_layout.addWidget(status_widget)

        layout.addWidget(sidebar)

        # ── Main content ─────────────────────────────────────────────
        main_area = QWidget()
        main_area.setObjectName("contentPanel")
        main_layout = QVBoxLayout(main_area)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Top header bar
        self.header = QWidget()
        self.header.setObjectName("header")
        self.header.setFixedHeight(60)
        header_layout = QHBoxLayout(self.header)
        header_layout.setContentsMargins(20, 0, 20, 0)
        self.header_title = QLabel("Dashboard")
        self.header_title.setObjectName("sectionTitle")
        self.header_subtitle = QLabel("Overview & quick stats")
        self.header_subtitle.setObjectName("metaLabel")
        hv = QVBoxLayout()
        hv.setSpacing(1)
        hv.addWidget(self.header_title)
        hv.addWidget(self.header_subtitle)
        header_layout.addLayout(hv)
        header_layout.addStretch()

        # Active case label in header
        self.active_case_lbl = QLabel("No active case")
        self.active_case_lbl.setObjectName("metaLabel")
        header_layout.addWidget(self.active_case_lbl)

        main_layout.addWidget(self.header)

        # Stacked panels
        self.stack = QStackedWidget()
        self.stack.setObjectName("contentPanel")
        main_layout.addWidget(self.stack)
        self._load_panels()

        layout.addWidget(main_area)

        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("ForensIQ ready.")

    def _load_panels(self):
        # Lazy import panels to keep startup fast
        from forensiq.ui.panels.dashboard import DashboardPanel
        from forensiq.ui.panels.device_panel import DevicePanel
        from forensiq.ui.panels.acquisition_panel import AcquisitionPanel
        from forensiq.ui.panels.cases_panel import CasesPanel
        from forensiq.ui.panels.analysis_panel import AnalysisPanel
        from forensiq.ui.panels.report_panel import ReportPanel
        from forensiq.ui.panels.signature_panel import SignaturePanel
        from forensiq.ui.panels.integrity_panel import IntegrityPanel
        from forensiq.ui.panels.audit_panel import AuditPanel
        from forensiq.ui.panels.custody_panel import CustodyPanel

        self.panels = {
            "dashboard":   DashboardPanel(self.db, self.adb, self),
            "device":      DevicePanel(self.adb, self),
            "acquisition": AcquisitionPanel(self.adb, self.db, self),
            "cases":       CasesPanel(self.db, self),
            "analysis":    AnalysisPanel(self.db, self),
            "report":      ReportPanel(self.db, self),
            "signature":   SignaturePanel(self.db, self),
            "integrity":   IntegrityPanel(self.db, self),
            "audit":       AuditPanel(self.db, self.audit, self),
            "custody":     CustodyPanel(self.db, self.audit, self),
        }
        for panel in self.panels.values():
            self.stack.addWidget(panel)

    def _nav_to(self, key: str):
        for k, btn in self._nav_buttons.items():
            btn.set_active(k == key)

        panel = self.panels[key]
        self.stack.setCurrentWidget(panel)

        # Update header
        for nav_key, label, tip in NAV_ITEMS:
            if nav_key == key:
                self.header_title.setText(label.split("  ", 1)[-1])
                self.header_subtitle.setText(tip)
                break

        # Refresh panel if it has a refresh hook
        if hasattr(panel, "on_shown"):
            panel.on_shown()

    def set_status(self, msg: str):
        self.status_bar.showMessage(msg)

    def set_active_case(self, case_number: str, investigator: str = ""):
        self.active_case_lbl.setText(f"Case: {case_number}")
        if investigator:
            self.investigator_lbl.setText(f"Investigator: {investigator}")
