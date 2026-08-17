"""
Analysis Panel — Upgrade Pack C (Advanced Analysis Engine).

NEW TABS / FEATURES:
  - Timeline View:    unified forensic timeline with category filter + search
  - Metadata View:    extended file metadata (MIME, SHA-256, original path)
  - Correlation View: artifact correlation across modules
  - Duplicates Tab:   SHA-256 + size duplicate detection
  - Search Tab:       global keyword + filter search (date, case, investigator,
                      file type, verification status, evidence type)
  - Applications:     system / user / disabled / recently-installed breakdown
  - Analysis Report:  generates analysis_report.json + analysis_report.html

PRESERVED FIXES from Phase 4:
  - BUG#1: AnalysisWorker signature (evidence_dir, tasks) — now also accepts db/case_id
  - BUG#2: results["apps"] flat (no nested 'apps.apps')
  - BUG#3: Analysis re-run clears old results first
  - BUG#4: Timeline batch-inserts after dedup
  - BUG#5: App table minimum height set
  - BUG#6: Search tab shows clear message when evidence_dir missing
"""

import os
import json
import webbrowser

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QComboBox, QTabWidget, QTableWidget, QTableWidgetItem,
    QFrame, QHeaderView, QProgressBar, QLineEdit,
    QCheckBox, QTextEdit, QDateEdit, QSplitter,
    QGroupBox, QScrollArea, QSizePolicy, QMessageBox,
    QFileDialog,
)
from PyQt6.QtCore import Qt, QDate
from PyQt6.QtGui import QFont, QColor

from forensiq.core.case_manager import CaseManager
from forensiq.core.analyzer import (
    AnalysisWorker, keyword_search_files, keyword_search_global,
    extract_file_metadata, analyze_apps, build_unified_timeline,
    persist_unified_timeline,
    detect_duplicates, correlate_artifacts, generate_analysis_report,
    analyze_network_info, analyze_battery_system, analyze_hash_integrity,
    detect_suspicious_artifacts, search_iocs, highest_severity,
)


STATUS_COLORS = {
    "clean":      "#3FB950",
    "suspicious": "#F85149",
    "review":     "#E3B341",
    "unknown":    "#8B949E",
}

TIMELINE_CATEGORY_COLORS = {
    "case":               "#D2A8FF",
    "file_system":        "#1D9E75",
    "evidence":           "#3FB950",
    "device_acquisition": "#58A6FF",
    "analysis":           "#F778BA",
    "verification":       "#E3B341",
    "audit":              "#A5D6FF",
    "custody":            "#F0883E",
}

APP_TYPE_COLORS = {
    "system":    "#8B949E",
    "user":      "#3FB950",
    "disabled":  "#F85149",
    "sideloaded":"#E3B341",
}

# Phase 6 — shared severity palette for the unified Findings tab and report.
SEVERITY_COLORS = {
    "critical": "#F85149",
    "high":     "#F0883E",
    "medium":   "#E3B341",
    "low":      "#A5D6FF",
    "info":     "#8B949E",
}


class AnalysisPanel(QWidget):
    def __init__(self, db: CaseManager, parent=None):
        super().__init__(parent)
        self.db                  = db
        self._worker             = None
        self._current_case_id: int | None = None
        self._current_evidence_dir: str   = ""
        self._build()

    # ── Build UI ───────────────────────────────────────────────────────────────

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(14)

        # ── Top bar ──
        top = QHBoxLayout()
        top.addWidget(QLabel("Case:"))
        self.case_combo = QComboBox()
        self.case_combo.setMinimumWidth(280)
        self.case_combo.setPlaceholderText("Select case…")
        self.case_combo.currentIndexChanged.connect(self._on_case_changed)
        top.addWidget(self.case_combo)

        self.btn_run = QPushButton("▶  Run Analysis")
        self.btn_run.setObjectName("primaryBtn")
        self.btn_run.setFixedWidth(150)
        self.btn_run.clicked.connect(self._run_analysis)
        top.addWidget(self.btn_run)

        self.btn_report = QPushButton("📄  Generate Report")
        self.btn_report.setObjectName("primaryBtn")
        self.btn_report.setFixedWidth(160)
        self.btn_report.clicked.connect(self._generate_report)
        top.addWidget(self.btn_report)

        self.progress = QProgressBar()
        self.progress.setValue(0)
        self.progress.setFixedWidth(200)
        top.addWidget(self.progress)

        self.status_lbl = QLabel("Select a case and run analysis.")
        self.status_lbl.setObjectName("metaLabel")
        self.status_lbl.setWordWrap(True)
        top.addWidget(self.status_lbl)
        top.addStretch()
        layout.addLayout(top)

        # ── Task checkboxes ──
        cb_row = QHBoxLayout()
        cb_row.setSpacing(18)
        self.cb_apps        = QCheckBox("Applications");        self.cb_apps.setChecked(True)
        self.cb_files       = QCheckBox("File Metadata");       self.cb_files.setChecked(True)
        self.cb_timeline    = QCheckBox("Unified Timeline");    self.cb_timeline.setChecked(True)
        self.cb_duplicates  = QCheckBox("Duplicate Detection"); self.cb_duplicates.setChecked(True)
        self.cb_correlate   = QCheckBox("Artifact Correlation");self.cb_correlate.setChecked(True)
        self.cb_network     = QCheckBox("Network Info");        self.cb_network.setChecked(True)
        self.cb_battery     = QCheckBox("Battery/System");      self.cb_battery.setChecked(True)
        self.cb_integrity   = QCheckBox("Hash/Integrity");      self.cb_integrity.setChecked(True)
        self.cb_suspicious  = QCheckBox("Suspicious Artifacts");self.cb_suspicious.setChecked(True)
        self.cb_ioc         = QCheckBox("IOC Search");          self.cb_ioc.setChecked(False)
        for cb in (self.cb_apps, self.cb_files, self.cb_timeline,
                   self.cb_duplicates, self.cb_correlate, self.cb_network,
                   self.cb_battery, self.cb_integrity, self.cb_suspicious,
                   self.cb_ioc):
            cb_row.addWidget(cb)
        cb_row.addStretch()
        layout.addLayout(cb_row)

        # ── IOC input row (only used when "IOC Search" is checked) ──
        ioc_row = QHBoxLayout()
        ioc_row.addWidget(QLabel("IOCs:"))
        self.ioc_input = QLineEdit()
        self.ioc_input.setPlaceholderText(
            "Comma-separated indicators — IP, domain, SHA-256, package name, filename…"
        )
        ioc_row.addWidget(self.ioc_input, 1)
        layout.addLayout(ioc_row)

        # ── Tabs ──
        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_findings_tab(),     "🛡️ Findings")
        self.tabs.addTab(self._build_timeline_tab(),     "🕐 Timeline")
        self.tabs.addTab(self._build_apps_tab(),         "📱 Applications")
        self.tabs.addTab(self._build_files_tab(),        "📁 File Metadata")
        self.tabs.addTab(self._build_correlation_tab(),  "🔗 Correlations")
        self.tabs.addTab(self._build_duplicates_tab(),   "🔁 Duplicates")
        self.tabs.addTab(self._build_search_tab(),       "🔍 Search & Filter")
        layout.addWidget(self.tabs, 1)

    # ── Tab: Findings (Phase 6 — Network, Battery/System, Hash/Integrity, ──────
    #    Suspicious Artifacts, IOC Search — all share the same result shape) ───

    def _build_findings_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(10, 10, 10, 10)
        l.setSpacing(10)

        self.findings_summary_lbl = QLabel(
            "Run analysis to see Network, Battery/System, Hash/Integrity, "
            "Suspicious Artifact, and IOC findings."
        )
        self.findings_summary_lbl.setObjectName("metaLabel")
        l.addWidget(self.findings_summary_lbl)

        fb = QHBoxLayout()
        fb.addWidget(QLabel("Type:"))
        self.finding_type_combo = QComboBox()
        self.finding_type_combo.addItem("All")
        self.finding_type_combo.setFixedWidth(160)
        self.finding_type_combo.currentIndexChanged.connect(self._filter_findings)
        fb.addWidget(self.finding_type_combo)
        fb.addWidget(QLabel("Severity:"))
        self.finding_severity_combo = QComboBox()
        self.finding_severity_combo.addItems(
            ["All", "critical", "high", "medium", "low", "info"]
        )
        self.finding_severity_combo.setFixedWidth(110)
        self.finding_severity_combo.currentIndexChanged.connect(self._filter_findings)
        fb.addWidget(self.finding_severity_combo)
        fb.addStretch()
        l.addLayout(fb)

        self.findings_table = QTableWidget(0, 5)
        self.findings_table.setMinimumHeight(220)
        self.findings_table.setHorizontalHeaderLabels(
            ["Analysis Type", "Severity", "Finding", "Timestamp", "Evidence Reference"]
        )
        self.findings_table.setAlternatingRowColors(True)
        self.findings_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.findings_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        hh = self.findings_table.horizontalHeader()
        hh.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.findings_table.setColumnWidth(0, 150)
        self.findings_table.setColumnWidth(1, 80)
        self.findings_table.setColumnWidth(3, 150)
        self.findings_table.setColumnWidth(4, 220)
        l.addWidget(self.findings_table, 1)

        self._all_findings: list[dict] = []
        return w

    # ── Tab: Timeline ──────────────────────────────────────────────────────────

    def _build_timeline_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(10, 10, 10, 10)
        l.setSpacing(8)

        # Filter bar — row 1: keyword, category, date range
        fb1 = QHBoxLayout()
        fb1.addWidget(QLabel("Filter:"))

        self.tl_filter_input = QLineEdit()
        self.tl_filter_input.setPlaceholderText("Keyword filter…")
        self.tl_filter_input.setFixedWidth(160)
        self.tl_filter_input.textChanged.connect(self._filter_timeline)
        fb1.addWidget(self.tl_filter_input)

        fb1.addWidget(QLabel("Category:"))
        self.tl_cat_combo = QComboBox()
        self.tl_cat_combo.addItems(
            ["All", "case", "file_system", "evidence", "device_acquisition",
             "analysis", "verification", "audit", "custody"]
        )
        self.tl_cat_combo.setFixedWidth(150)
        self.tl_cat_combo.currentIndexChanged.connect(self._filter_timeline)
        fb1.addWidget(self.tl_cat_combo)

        fb1.addWidget(QLabel("From:"))
        self.tl_date_from = QDateEdit()
        self.tl_date_from.setCalendarPopup(True)
        self.tl_date_from.setDisplayFormat("yyyy-MM-dd")
        self.tl_date_from.setDate(QDate(2000, 1, 1))
        self.tl_date_from.setFixedWidth(110)
        self.tl_date_from.dateChanged.connect(self._filter_timeline)
        fb1.addWidget(self.tl_date_from)

        fb1.addWidget(QLabel("To:"))
        self.tl_date_to = QDateEdit()
        self.tl_date_to.setCalendarPopup(True)
        self.tl_date_to.setDisplayFormat("yyyy-MM-dd")
        self.tl_date_to.setDate(QDate(2100, 12, 31))
        self.tl_date_to.setFixedWidth(110)
        self.tl_date_to.dateChanged.connect(self._filter_timeline)
        fb1.addWidget(self.tl_date_to)

        self.tl_date_enabled = QCheckBox("Apply date range")
        self.tl_date_enabled.setChecked(False)
        self.tl_date_enabled.stateChanged.connect(self._filter_timeline)
        fb1.addWidget(self.tl_date_enabled)
        fb1.addStretch()
        l.addLayout(fb1)

        # Filter bar — row 2: event type, evidence, device, investigator/actor
        fb2 = QHBoxLayout()
        fb2.addWidget(QLabel("Event Type:"))
        self.tl_type_combo = QComboBox()
        self.tl_type_combo.addItem("All")
        self.tl_type_combo.setFixedWidth(180)
        self.tl_type_combo.currentIndexChanged.connect(self._filter_timeline)
        fb2.addWidget(self.tl_type_combo)

        fb2.addWidget(QLabel("Evidence:"))
        self.tl_evidence_combo = QComboBox()
        self.tl_evidence_combo.addItem("All")
        self.tl_evidence_combo.setFixedWidth(180)
        self.tl_evidence_combo.currentIndexChanged.connect(self._filter_timeline)
        fb2.addWidget(self.tl_evidence_combo)

        fb2.addWidget(QLabel("Device:"))
        self.tl_device_combo = QComboBox()
        self.tl_device_combo.addItem("All")
        self.tl_device_combo.setFixedWidth(160)
        self.tl_device_combo.currentIndexChanged.connect(self._filter_timeline)
        fb2.addWidget(self.tl_device_combo)

        fb2.addWidget(QLabel("Investigator/Actor:"))
        self.tl_actor_combo = QComboBox()
        self.tl_actor_combo.addItem("All")
        self.tl_actor_combo.setFixedWidth(160)
        self.tl_actor_combo.currentIndexChanged.connect(self._filter_timeline)
        fb2.addWidget(self.tl_actor_combo)

        self.tl_sort_btn = QPushButton("⇅ Sort Asc")
        self.tl_sort_btn.setFixedWidth(90)
        self.tl_sort_btn.setCheckable(True)
        self.tl_sort_btn.clicked.connect(self._sort_timeline)
        fb2.addWidget(self.tl_sort_btn)

        self.tl_count_lbl = QLabel("0 events")
        self.tl_count_lbl.setObjectName("metaLabel")
        fb2.addWidget(self.tl_count_lbl)
        fb2.addStretch()
        l.addLayout(fb2)

        # Timeline table (8 cols: timestamp, category, event_type,
        # description, evidence, device/session, actor, source)
        self.timeline_table = QTableWidget(0, 8)
        self.timeline_table.setMinimumHeight(180)
        self.timeline_table.setHorizontalHeaderLabels(
            ["Timestamp", "Category", "Event Type", "Description",
             "Evidence", "Device/Session", "Investigator/Actor", "Source"]
        )
        self.timeline_table.setAlternatingRowColors(True)
        self.timeline_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.timeline_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        hh = self.timeline_table.horizontalHeader()
        hh.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        hh.setSectionResizeMode(7, QHeaderView.ResizeMode.ResizeToContents)
        self.timeline_table.setColumnWidth(0, 150)
        self.timeline_table.setColumnWidth(1, 110)
        self.timeline_table.setColumnWidth(2, 150)
        self.timeline_table.setColumnWidth(4, 120)
        self.timeline_table.setColumnWidth(5, 120)
        self.timeline_table.setColumnWidth(6, 120)
        l.addWidget(self.timeline_table, 1)

        # Store all events for filtering
        self._timeline_all_events: list[dict] = []
        self._timeline_sort_asc = True
        return w

    # ── Tab: Applications ──────────────────────────────────────────────────────

    def _build_apps_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(10, 10, 10, 10)
        l.setSpacing(10)

        # Summary cards row
        summary_row = QHBoxLayout()
        self.app_summary_labels: dict[str, QLabel] = {}
        for status, color in STATUS_COLORS.items():
            box = QFrame(); box.setObjectName("card")
            bl  = QVBoxLayout(box); bl.setContentsMargins(12, 8, 12, 8)
            num = QLabel("—")
            num.setFont(QFont("Segoe UI", 22, QFont.Weight.Bold))
            num.setStyleSheet(f"color:{color};")
            lbl = QLabel(status.capitalize()); lbl.setObjectName("metaLabel")
            bl.addWidget(num); bl.addWidget(lbl)
            self.app_summary_labels[status] = num
            summary_row.addWidget(box)

        # Inventory cards
        self.app_inv_labels: dict[str, QLabel] = {}
        for inv_key, color in [("system","#8B949E"),("user","#3FB950"),
                                ("disabled","#F85149"),("recently_installed","#E3B341")]:
            box = QFrame(); box.setObjectName("card")
            bl  = QVBoxLayout(box); bl.setContentsMargins(12, 8, 12, 8)
            num = QLabel("—")
            num.setFont(QFont("Segoe UI", 22, QFont.Weight.Bold))
            num.setStyleSheet(f"color:{color};")
            lbl = QLabel(inv_key.replace("_"," ").title()); lbl.setObjectName("metaLabel")
            bl.addWidget(num); bl.addWidget(lbl)
            self.app_inv_labels[inv_key] = num
            summary_row.addWidget(box)
        l.addLayout(summary_row)

        # App type filter
        af = QHBoxLayout()
        af.addWidget(QLabel("Filter by type:"))
        self.app_type_combo = QComboBox()
        self.app_type_combo.addItems(["All", "system", "user", "disabled", "sideloaded"])
        self.app_type_combo.setFixedWidth(130)
        self.app_type_combo.currentIndexChanged.connect(self._filter_apps)
        af.addWidget(self.app_type_combo)
        self.app_search = QLineEdit()
        self.app_search.setPlaceholderText("Search package…")
        self.app_search.setFixedWidth(200)
        self.app_search.textChanged.connect(self._filter_apps)
        af.addWidget(self.app_search)
        af.addStretch()
        l.addLayout(af)

        self.apps_table = QTableWidget(0, 5)
        self.apps_table.setHorizontalHeaderLabels(
            ["Package", "Installer", "Status", "Type", "Recent"]
        )
        self.apps_table.setAlternatingRowColors(True)
        self.apps_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.apps_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.apps_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch
        )
        self.apps_table.setColumnWidth(1, 180)
        self.apps_table.setColumnWidth(2, 90)
        self.apps_table.setColumnWidth(3, 90)
        self.apps_table.setColumnWidth(4, 60)
        self.apps_table.setMinimumHeight(200)
        l.addWidget(self.apps_table, 1)

        self._all_apps: list[dict] = []
        return w

    # ── Tab: File Metadata ─────────────────────────────────────────────────────

    def _build_files_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(10, 10, 10, 10)
        l.setSpacing(8)

        # Filter bar
        fb = QHBoxLayout()
        self.meta_filter = QLineEdit()
        self.meta_filter.setPlaceholderText("Filter by filename or extension…")
        self.meta_filter.setFixedWidth(260)
        self.meta_filter.textChanged.connect(self._filter_metadata)
        fb.addWidget(self.meta_filter)
        self.meta_ext_filter = QComboBox()
        self.meta_ext_filter.addItem("All types")
        self.meta_ext_filter.setFixedWidth(120)
        self.meta_ext_filter.currentIndexChanged.connect(self._filter_metadata)
        fb.addWidget(QLabel("Ext:"))
        fb.addWidget(self.meta_ext_filter)
        self.meta_count_lbl = QLabel("0 files")
        self.meta_count_lbl.setObjectName("metaLabel")
        fb.addWidget(self.meta_count_lbl)
        fb.addStretch()
        l.addLayout(fb)

        self.files_table = QTableWidget(0, 8)
        self.files_table.setMinimumHeight(180)
        self.files_table.setHorizontalHeaderLabels(
            ["Filename", "Ext", "MIME Type", "Size", "Created", "Modified", "SHA-256", "Original Path"]
        )
        self.files_table.setAlternatingRowColors(True)
        self.files_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        hh = self.files_table.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(7, QHeaderView.ResizeMode.Stretch)
        self.files_table.setColumnWidth(1, 50)
        self.files_table.setColumnWidth(3, 80)
        self.files_table.setColumnWidth(4, 140)
        self.files_table.setColumnWidth(5, 140)
        l.addWidget(self.files_table, 1)

        self._all_metadata: list[dict] = []
        return w

    # ── Tab: Correlations ──────────────────────────────────────────────────────

    def _build_correlation_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(10, 10, 10, 10)
        l.setSpacing(10)

        self.corr_summary = QLabel("Run analysis to see artifact correlations.")
        self.corr_summary.setObjectName("metaLabel")
        l.addWidget(self.corr_summary)

        # Splitter: left = correlation categories, right = detail
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Category list
        self.corr_cat_table = QTableWidget(0, 2)
        self.corr_cat_table.setMinimumHeight(120)
        self.corr_cat_table.setHorizontalHeaderLabels(["Correlation", "Count"])
        self.corr_cat_table.setAlternatingRowColors(True)
        self.corr_cat_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.corr_cat_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch
        )
        self.corr_cat_table.setColumnWidth(1, 60)
        self.corr_cat_table.setMaximumWidth(350)
        self.corr_cat_table.currentCellChanged.connect(self._on_corr_cat_selected)
        splitter.addWidget(self.corr_cat_table)

        # Detail panel
        detail_w = QWidget()
        dl = QVBoxLayout(detail_w)
        dl.setContentsMargins(0, 0, 0, 0)
        self.corr_detail_table = QTableWidget(0, 3)
        self.corr_detail_table.setMinimumHeight(120)
        self.corr_detail_table.setHorizontalHeaderLabels(["Evidence ID", "Filename", "Detail"])
        self.corr_detail_table.setAlternatingRowColors(True)
        self.corr_detail_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.corr_detail_table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.Stretch
        )
        self.corr_detail_table.setColumnWidth(0, 80)
        self.corr_detail_table.setColumnWidth(1, 180)
        dl.addWidget(self.corr_detail_table)
        splitter.addWidget(detail_w)

        splitter.setSizes([320, 500])
        l.addWidget(splitter, 1)

        self._corr_data: dict = {}
        return w

    # ── Tab: Duplicates ────────────────────────────────────────────────────────

    def _build_duplicates_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(10, 10, 10, 10)
        l.setSpacing(10)

        self.dup_summary_lbl = QLabel("Run analysis to detect duplicates.")
        self.dup_summary_lbl.setObjectName("metaLabel")
        l.addWidget(self.dup_summary_lbl)

        self.dup_table = QTableWidget(0, 4)
        self.dup_table.setMinimumHeight(160)
        self.dup_table.setHorizontalHeaderLabels(["SHA-256", "Copies", "Size", "Files"])
        self.dup_table.setAlternatingRowColors(True)
        self.dup_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.dup_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        hh = self.dup_table.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.dup_table.setColumnWidth(1, 60)
        self.dup_table.setColumnWidth(2, 80)
        l.addWidget(self.dup_table, 1)
        return w

    # ── Tab: Search & Filter ───────────────────────────────────────────────────

    def _build_search_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(10, 10, 10, 10)
        l.setSpacing(10)

        # Search row
        sr = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText(
            "Keyword search (evidence, audit, custody, apps, cases)…"
        )
        self.search_input.returnPressed.connect(self._run_search)
        sb = QPushButton("Search")
        sb.setObjectName("primaryBtn")
        sb.setFixedWidth(90)
        sb.clicked.connect(self._run_search)
        sr.addWidget(self.search_input, 1)
        sr.addWidget(sb)
        l.addLayout(sr)

        # Filter row 1: date range + investigator
        filt1 = QHBoxLayout()
        filt1.setSpacing(8)
        filt1.addWidget(QLabel("From:"))
        self.filter_date_from = QLineEdit()
        self.filter_date_from.setPlaceholderText("YYYY-MM-DD")
        self.filter_date_from.setFixedWidth(100)
        filt1.addWidget(self.filter_date_from)

        filt1.addWidget(QLabel("To:"))
        self.filter_date_to = QLineEdit()
        self.filter_date_to.setPlaceholderText("YYYY-MM-DD")
        self.filter_date_to.setFixedWidth(100)
        filt1.addWidget(self.filter_date_to)

        filt1.addWidget(QLabel("Investigator:"))
        self.filter_investigator = QLineEdit()
        self.filter_investigator.setFixedWidth(120)
        filt1.addWidget(self.filter_investigator)
        filt1.addStretch()
        l.addLayout(filt1)

        # Filter row 2: type filters + clear button
        filt2 = QHBoxLayout()
        filt2.setSpacing(8)
        filt2.addWidget(QLabel("Evidence:"))
        self.filter_ev_type = QComboBox()
        self.filter_ev_type.addItems(["All", "acquisition", "apps",
                                       "contacts", "sms", "calls", "media"])
        self.filter_ev_type.setFixedWidth(110)
        filt2.addWidget(self.filter_ev_type)

        filt2.addWidget(QLabel("File type:"))
        self.filter_file_type = QLineEdit()
        self.filter_file_type.setPlaceholderText("apk, txt, json…")
        self.filter_file_type.setFixedWidth(90)
        filt2.addWidget(self.filter_file_type)

        filt2.addWidget(QLabel("Hash:"))
        self.filter_verification_status = QComboBox()
        self.filter_verification_status.addItems(["All", "pass", "fail", "unverified"])
        self.filter_verification_status.setFixedWidth(95)
        filt2.addWidget(self.filter_verification_status)

        btn_clear = QPushButton("✕ Clear")
        btn_clear.setFixedWidth(80)
        btn_clear.clicked.connect(self._clear_search_filters)
        filt2.addWidget(btn_clear)
        filt2.addStretch()
        l.addLayout(filt2)

        self.search_table = QTableWidget(0, 5)
        self.search_table.setMinimumHeight(180)
        self.search_table.setHorizontalHeaderLabels(
            ["Source", "Type", "Match", "Detail", "Timestamp"]
        )
        self.search_table.setAlternatingRowColors(True)
        self.search_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        hh = self.search_table.horizontalHeader()
        hh.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.search_table.setColumnWidth(0, 70)
        self.search_table.setColumnWidth(1, 100)
        self.search_table.setColumnWidth(3, 180)
        self.search_table.setColumnWidth(4, 150)
        l.addWidget(self.search_table, 1)

        self.search_count_lbl = QLabel("")
        self.search_count_lbl.setObjectName("metaLabel")
        l.addWidget(self.search_count_lbl)
        return w

    # ── Refresh ────────────────────────────────────────────────────────────────

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
            self._current_evidence_dir = (case["evidence_dir"] or "").strip() if case else ""
            self._load_existing_timeline()
            self._load_existing_findings()

    _FINDING_ANALYSIS_TYPES = {
        "network", "battery", "hash_integrity", "suspicious_artifacts", "ioc_search",
    }

    def _load_existing_findings(self):
        """
        Reload previously-saved Phase 6 findings for the selected case from
        analysis_results (reuses the existing table — no separate storage),
        so switching cases shows prior results without re-running analysis.
        """
        if not self._current_case_id:
            return
        findings: list[dict] = []
        for row in self.db.get_analysis_results(self._current_case_id):
            if row["analysis_type"] not in self._FINDING_ANALYSIS_TYPES:
                continue
            try:
                data = json.loads(row["result_data"] or "{}")
            except (ValueError, TypeError):
                continue
            findings.extend(data.get("findings", []))
        self._all_findings = findings
        types = sorted({f.get("analysis_type", "") for f in findings})
        self.finding_type_combo.blockSignals(True)
        self.finding_type_combo.clear()
        self.finding_type_combo.addItem("All")
        for t in types:
            self.finding_type_combo.addItem(t)
        self.finding_type_combo.blockSignals(False)
        self._render_findings(findings)

    def _load_existing_timeline(self):
        if not self._current_case_id:
            return
        events = [self._normalize_timeline_row(dict(e))
                  for e in self.db.get_timeline(self._current_case_id)]
        self._timeline_all_events = events
        self._populate_timeline_filters(events)
        self._render_timeline(events)

    @staticmethod
    def _normalize_timeline_row(row: dict) -> dict:
        """
        DB rows from CaseManager.get_timeline() use `source_file` and
        expose the join columns `evidence_filename`/`device_serial`; the
        in-memory events produced by analyzer.build_unified_timeline() use
        `source` directly. Normalise both shapes to the same keys the
        Timeline tab renders/filters on.
        """
        row.setdefault("source", row.get("source_file", "") or "")
        row.setdefault("evidence_filename", "")
        row.setdefault("device_serial", "")
        return row

    def _populate_timeline_filters(self, events: list[dict]):
        """Refresh the Event Type / Evidence / Device / Actor filter dropdowns
        from the currently loaded set of timeline events."""
        def _refill(combo: QComboBox, values: list[str]):
            current = combo.currentText()
            combo.blockSignals(True)
            combo.clear()
            combo.addItem("All")
            for v in values:
                combo.addItem(v)
            idx = combo.findText(current)
            combo.setCurrentIndex(idx if idx >= 0 else 0)
            combo.blockSignals(False)

        event_types = sorted({str(e.get("event_type", "")) for e in events if e.get("event_type")})
        _refill(self.tl_type_combo, event_types)

        evidence_names = sorted({
            str(e.get("evidence_filename") or f"evidence #{e['evidence_id']}")
            for e in events if e.get("evidence_id")
        })
        _refill(self.tl_evidence_combo, evidence_names)

        device_names = sorted({
            str(e.get("device_serial") or f"device #{e['device_id']}")
            for e in events if e.get("device_id")
        })
        _refill(self.tl_device_combo, device_names)

        actors = sorted({str(e.get("actor", "")) for e in events if e.get("actor")})
        _refill(self.tl_actor_combo, actors)

    # ── Analysis runner ────────────────────────────────────────────────────────

    def _run_analysis(self):
        if not self._current_case_id:
            self.status_lbl.setText("Select a case first.")
            return
        ev_dir = self._current_evidence_dir
        if not ev_dir or not os.path.exists(ev_dir):
            self.status_lbl.setText(
                f"Evidence directory not found: {ev_dir or 'not set'}"
            )
            return

        tasks = []
        if self.cb_apps.isChecked():       tasks.append("apps")
        if self.cb_files.isChecked():      tasks.append("file_metadata")
        if self.cb_timeline.isChecked():   tasks.append("timeline")
        if self.cb_duplicates.isChecked(): tasks.append("duplicates")
        if self.cb_correlate.isChecked():  tasks.append("correlations")
        if self.cb_network.isChecked():    tasks.append("network")
        if self.cb_battery.isChecked():    tasks.append("battery")
        if self.cb_integrity.isChecked():  tasks.append("hash_integrity")
        if self.cb_suspicious.isChecked(): tasks.append("suspicious_artifacts")
        iocs = []
        if self.cb_ioc.isChecked():
            tasks.append("ioc_search")
            iocs = [t.strip() for t in self.ioc_input.text().split(",") if t.strip()]
        if not tasks:
            self.status_lbl.setText("Select at least one task.")
            return

        self.btn_run.setEnabled(False)
        self.btn_report.setEnabled(False)
        self.progress.setValue(0)
        self.status_lbl.setText("Running…")

        self._worker = AnalysisWorker(
            ev_dir, tasks, db=self.db, case_id=self._current_case_id, iocs=iocs
        )
        self._worker.progress.connect(self._on_progress)
        self._worker.finished.connect(self._on_analysis_done)
        self._worker.error.connect(lambda msg: self.status_lbl.setText(f"Error: {msg}"))
        self._worker.start()

    def _generate_report(self):
        if not self._current_case_id:
            self.status_lbl.setText("Select a case first.")
            return
        ev_dir = self._current_evidence_dir
        if not ev_dir:
            ev_dir = str(__import__("pathlib").Path.home() / ".forensiq" / "reports")

        out_dir = QFileDialog.getExistingDirectory(
            self, "Select Output Directory", ev_dir
        )
        if not out_dir:
            return

        self.status_lbl.setText("Generating analysis report…")
        try:
            paths = generate_analysis_report(
                self._current_case_id, self.db, ev_dir, out_dir
            )
            self.status_lbl.setText(
                f"Report generated: {os.path.basename(paths['html'])}"
            )
            if os.path.exists(paths["html"]):
                webbrowser.open(f"file://{paths['html']}")
        except Exception as e:
            self.status_lbl.setText(f"Report error: {e}")

    def _on_progress(self, pct: int, msg: str):
        self.progress.setValue(max(0, pct))
        self.status_lbl.setText(msg)

    def _on_analysis_done(self, results: dict):
        self.progress.setValue(100)
        self.btn_run.setEnabled(True)
        self.btn_report.setEnabled(True)
        self.status_lbl.setText("Analysis complete.")

        # ── Apps ──────────────────────────────────────────────────────────────
        if "apps" in results:
            data = results["apps"]
            if "error" not in data:
                for status, lbl in self.app_summary_labels.items():
                    lbl.setText(str(data.get("summary", {}).get(status, 0)))
                inv = data.get("inventory", {})
                for key, lbl in self.app_inv_labels.items():
                    lbl.setText(str(inv.get(key, 0)))
                self._all_apps = data.get("apps", [])
                self._render_apps(self._all_apps)
                self._save_analysis_result(
                    "app_classification",
                    f"Classified {data.get('total', 0)} apps — "
                    f"suspicious: {data.get('summary', {}).get('suspicious', 0)}, "
                    f"sideloaded: {data.get('inventory', {}).get('sideloaded', 0)}, "
                    f"recently_installed: {data.get('inventory', {}).get('recently_installed', 0)}",
                    data,
                )

        # ── File metadata ──────────────────────────────────────────────────────
        if "file_metadata" in results:
            meta_list = list(results["file_metadata"].values())
            self._all_metadata = meta_list
            # Populate extension filter
            exts = sorted({m.get("extension", "") for m in meta_list
                           if m.get("extension")})
            self.meta_ext_filter.clear()
            self.meta_ext_filter.addItem("All types")
            for ext in exts:
                self.meta_ext_filter.addItem(ext)
            self._render_metadata(meta_list)

        # ── Unified Timeline ───────────────────────────────────────────────────
        if "timeline" in results:
            events = results["timeline"]

            # Persist into the DB — persist_unified_timeline() delegates to
            # CaseManager.add_timeline_event(), which itself skips inserting
            # any event that already exists (same case/type/description/
            # timestamp/evidence/device/session), so re-running analysis
            # over unchanged source data never grows the table.
            persist_unified_timeline(self.db, self._current_case_id, events)

            # Reload from the DB rather than rendering the in-memory list
            # directly, so displayed rows always reflect real persisted
            # ids/links and stay consistent with what filters/reports see.
            self._load_existing_timeline()

        # ── Duplicates ─────────────────────────────────────────────────────────
        if "duplicates" in results:
            dup_data = results["duplicates"]
            self._render_duplicates(dup_data)
            self._save_analysis_result(
                "duplicate_detection",
                f"{dup_data.get('duplicate_groups', 0)} duplicate group(s), "
                f"{dup_data.get('duplicate_count', 0)} redundant file(s) of {dup_data.get('total_files', 0)} scanned",
                dup_data,
            )

        # ── Correlations ───────────────────────────────────────────────────────
        if "correlations" in results:
            self._corr_data = results["correlations"]
            self._render_correlations(self._corr_data)

        # ── Phase 6: Network / Battery-System / Hash-Integrity /
        #    Suspicious Artifacts / IOC Search — all share the standard
        #    finding shape (analysis_type, evidence_ref, timestamp, status,
        #    finding, severity), saved as one analysis_results row per
        #    module with its findings list in result_data. ─────────────────
        new_findings: list[dict] = []
        for key in ("network", "battery", "hash_integrity",
                    "suspicious_artifacts", "ioc_search"):
            if key not in results:
                continue
            data = results[key]
            if "error" in data:
                continue
            findings = data.get("findings", [])
            new_findings.extend(findings)
            top_sev = highest_severity(findings)
            self._save_analysis_result(
                key,
                f"{len(findings)} finding(s) — highest severity: {top_sev}",
                data,
            )

        if new_findings:
            # Merge with any findings already loaded for this case/session
            # rather than discarding results from tasks that weren't
            # re-run this time.
            existing_types = {f.get("analysis_type") for f in new_findings}
            carried = [f for f in self._all_findings
                       if f.get("analysis_type") not in existing_types]
            self._all_findings = carried + new_findings
            types = sorted({f.get("analysis_type", "") for f in self._all_findings})
            self.finding_type_combo.blockSignals(True)
            self.finding_type_combo.clear()
            self.finding_type_combo.addItem("All")
            for t in types:
                self.finding_type_combo.addItem(t)
            self.finding_type_combo.blockSignals(False)
            self._render_findings(self._all_findings)

        self.tabs.setCurrentIndex(0)

    # ── Render helpers ─────────────────────────────────────────────────────────

    def _render_findings(self, findings: list[dict]):
        """
        Render the unified Phase 6 findings table. Every finding shares the
        same shape produced by analyzer.make_finding(): analysis_type,
        severity, finding, timestamp, evidence_ref — this is the single
        place that displays that consistent record for Network,
        Battery/System, Hash/Integrity, Suspicious Artifacts, and IOC Search.
        """
        self.findings_table.setRowCount(0)
        type_filter = self.finding_type_combo.currentText()
        sev_filter  = self.finding_severity_combo.currentText()

        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            counts[f.get("severity", "info")] = counts.get(f.get("severity", "info"), 0) + 1

        for f in findings:
            atype = f.get("analysis_type", "")
            sev   = f.get("severity", "info")
            if type_filter != "All" and atype != type_filter:
                continue
            if sev_filter != "All" and sev != sev_filter:
                continue
            row = self.findings_table.rowCount()
            self.findings_table.insertRow(row)
            self.findings_table.setItem(row, 0, QTableWidgetItem(atype))
            si = QTableWidgetItem(sev.upper())
            si.setForeground(QColor(SEVERITY_COLORS.get(sev, "#8B949E")))
            self.findings_table.setItem(row, 1, si)
            self.findings_table.setItem(row, 2, QTableWidgetItem(str(f.get("finding", ""))))
            ts_i = QTableWidgetItem(str(f.get("timestamp", "")))
            ts_i.setFont(QFont("Courier New", 9))
            self.findings_table.setItem(row, 3, ts_i)
            ref_i = QTableWidgetItem(str(f.get("evidence_ref", "")))
            ref_i.setFont(QFont("Courier New", 9))
            self.findings_table.setItem(row, 4, ref_i)

        self.findings_summary_lbl.setText(
            f"{len(findings)} finding(s) — critical: {counts['critical']}, "
            f"high: {counts['high']}, medium: {counts['medium']}, "
            f"low: {counts['low']}, info: {counts['info']}"
        )

    def _filter_findings(self):
        self._render_findings(self._all_findings)

    def _render_timeline(self, events: list[dict]):
        self.timeline_table.setRowCount(0)
        cat_filter    = self.tl_cat_combo.currentText()
        type_filter   = self.tl_type_combo.currentText()
        evidence_filter = self.tl_evidence_combo.currentText()
        device_filter   = self.tl_device_combo.currentText()
        actor_filter    = self.tl_actor_combo.currentText()
        kw            = self.tl_filter_input.text().strip().lower()
        use_dates     = self.tl_date_enabled.isChecked()
        date_from     = self.tl_date_from.date().toString("yyyy-MM-dd") if use_dates else None
        date_to       = self.tl_date_to.date().toString("yyyy-MM-dd") if use_dates else None

        for ev in events:
            cat = ev.get("category", "")
            if cat_filter != "All" and cat != cat_filter:
                continue
            if type_filter != "All" and str(ev.get("event_type", "")) != type_filter:
                continue
            if evidence_filter != "All":
                ev_name = str(ev.get("evidence_filename") or
                              (f"evidence #{ev['evidence_id']}" if ev.get("evidence_id") else ""))
                if ev_name != evidence_filter:
                    continue
            if device_filter != "All":
                dev_name = str(ev.get("device_serial") or
                               (f"device #{ev['device_id']}" if ev.get("device_id") else ""))
                if dev_name != device_filter:
                    continue
            if actor_filter != "All" and str(ev.get("actor", "")) != actor_filter:
                continue
            if kw and kw not in str(ev.get("description", "")).lower() \
                    and kw not in str(ev.get("event_type", "")).lower():
                continue
            if use_dates:
                ts_date = str(ev.get("timestamp", ""))[:10]
                if ts_date and (ts_date < date_from or ts_date > date_to):
                    continue

            row = self.timeline_table.rowCount()
            self.timeline_table.insertRow(row)

            ts_i = QTableWidgetItem(str(ev.get("timestamp", "")))
            ts_i.setFont(QFont("Courier New", 9))
            ts_i.setForeground(QColor("#8B949E"))
            self.timeline_table.setItem(row, 0, ts_i)

            cat_color = TIMELINE_CATEGORY_COLORS.get(cat, "#ccc")
            cat_i = QTableWidgetItem(cat)
            cat_i.setForeground(QColor(cat_color))
            self.timeline_table.setItem(row, 1, cat_i)

            et_i = QTableWidgetItem(str(ev.get("event_type", "")))
            et_i.setForeground(QColor("#1D9E75"))
            self.timeline_table.setItem(row, 2, et_i)

            self.timeline_table.setItem(row, 3, QTableWidgetItem(str(ev.get("description", ""))))

            ev_disp = ev.get("evidence_filename") or (
                f"evidence #{ev['evidence_id']}" if ev.get("evidence_id") else "")
            self.timeline_table.setItem(row, 4, QTableWidgetItem(str(ev_disp)))

            dev_parts = []
            dev_disp = ev.get("device_serial") or (
                f"device #{ev['device_id']}" if ev.get("device_id") else "")
            if dev_disp:
                dev_parts.append(str(dev_disp))
            if ev.get("session_id"):
                dev_parts.append(f"session #{ev['session_id']}")
            self.timeline_table.setItem(row, 5, QTableWidgetItem(" / ".join(dev_parts)))

            self.timeline_table.setItem(row, 6, QTableWidgetItem(str(ev.get("actor", ""))))
            self.timeline_table.setItem(row, 7, QTableWidgetItem(str(ev.get("source", ""))))

        self.tl_count_lbl.setText(f"{self.timeline_table.rowCount()} events")

    def _render_apps(self, apps: list[dict]):
        self.apps_table.setRowCount(0)
        type_filter = self.app_type_combo.currentText()
        kw          = self.app_search.text().strip().lower()
        for app in apps:
            atype = app.get("app_type", "user")
            pkg   = (app.get("package") or "").lower()
            if type_filter != "All" and atype != type_filter:
                continue
            if kw and kw not in pkg:
                continue
            row = self.apps_table.rowCount()
            self.apps_table.insertRow(row)
            self.apps_table.setItem(row, 0, QTableWidgetItem(app.get("package", "")))
            self.apps_table.setItem(row, 1, QTableWidgetItem(app.get("installer", "")))
            status = app.get("status", "unknown")
            si = QTableWidgetItem(status.upper())
            si.setForeground(QColor(STATUS_COLORS.get(status, "#8B949E")))
            self.apps_table.setItem(row, 2, si)
            ti = QTableWidgetItem(atype)
            ti.setForeground(QColor(APP_TYPE_COLORS.get(atype, "#ccc")))
            self.apps_table.setItem(row, 3, ti)
            ri = QTableWidgetItem("✓" if app.get("recently_installed") else "")
            ri.setForeground(QColor("#E3B341"))
            self.apps_table.setItem(row, 4, ri)

    def _render_metadata(self, meta_list: list[dict]):
        self.files_table.setRowCount(0)
        kw  = self.meta_filter.text().strip().lower()
        ext_filter = self.meta_ext_filter.currentText()
        count = 0
        for m in meta_list:
            if "error" in m:
                continue
            fn  = (m.get("filename") or "").lower()
            ext = m.get("extension", "")
            if kw and kw not in fn and kw not in ext:
                continue
            if ext_filter != "All types" and ext != ext_filter:
                continue
            row = self.files_table.rowCount()
            self.files_table.insertRow(row)
            self.files_table.setItem(row, 0, QTableWidgetItem(m.get("filename", "")))
            self.files_table.setItem(row, 1, QTableWidgetItem(ext))
            self.files_table.setItem(row, 2, QTableWidgetItem(m.get("mime_type", "")))
            self.files_table.setItem(row, 3, QTableWidgetItem(m.get("size_human", "")))
            self.files_table.setItem(row, 4, QTableWidgetItem(m.get("created", "")))
            self.files_table.setItem(row, 5, QTableWidgetItem(m.get("modified", "")))
            sha_i = QTableWidgetItem((m.get("sha256") or "")[:32])
            sha_i.setFont(QFont("Courier New", 9))
            sha_i.setForeground(QColor("#1D9E75"))
            self.files_table.setItem(row, 6, sha_i)
            self.files_table.setItem(row, 7, QTableWidgetItem(m.get("original_path", "")))
            count += 1
        self.meta_count_lbl.setText(f"{count} files")

    def _render_correlations(self, corr: dict):
        self.corr_cat_table.setRowCount(0)
        total_links = 0
        for key, items in corr.items():
            count = len(items) if isinstance(items, list) else 0
            total_links += count
            row = self.corr_cat_table.rowCount()
            self.corr_cat_table.insertRow(row)
            label = key.replace("_", " ").title()
            li = QTableWidgetItem(label)
            self.corr_cat_table.setItem(row, 0, li)
            ci = QTableWidgetItem(str(count))
            if count > 0 and ("risk" in key or "unverified" in key):
                ci.setForeground(QColor("#F85149"))
            elif count > 0:
                ci.setForeground(QColor("#3FB950"))
            self.corr_cat_table.setItem(row, 1, ci)
        self.corr_summary.setText(
            f"Artifact correlations: {len(corr)} category types, {total_links} total links."
        )

    def _render_duplicates(self, dup_data: dict):
        groups = dup_data.get("duplicates", [])
        self.dup_table.setRowCount(0)
        for d in groups:
            row = self.dup_table.rowCount()
            self.dup_table.insertRow(row)
            sha_i = QTableWidgetItem(d.get("sha256", "")[:48])
            sha_i.setFont(QFont("Courier New", 9))
            sha_i.setForeground(QColor("#E3B341"))
            self.dup_table.setItem(row, 0, sha_i)
            ci = QTableWidgetItem(str(d.get("count", 0)))
            ci.setForeground(QColor("#F85149"))
            self.dup_table.setItem(row, 1, ci)
            from forensiq.core.analyzer import _human_size
            self.dup_table.setItem(row, 2, QTableWidgetItem(_human_size(d.get("size", 0))))
            files_str = ", ".join(f.get("filename", "") for f in d.get("files", [])[:4])
            if len(d.get("files", [])) > 4:
                files_str += f" (+{len(d['files'])-4} more)"
            self.dup_table.setItem(row, 3, QTableWidgetItem(files_str))

        total  = dup_data.get("total_files", 0)
        dcount = dup_data.get("duplicate_count", 0)
        dgroups= dup_data.get("duplicate_groups", 0)
        self.dup_summary_lbl.setText(
            f"Scanned {total} files — found {dgroups} duplicate group(s) "
            f"({dcount} redundant file(s))."
        )

    # ── Filter / sort slots ────────────────────────────────────────────────────

    def _filter_timeline(self):
        self._render_timeline(self._timeline_all_events)

    def _sort_timeline(self):
        self._timeline_sort_asc = not self._timeline_sort_asc
        self._timeline_all_events.sort(
            key=lambda x: str(x.get("timestamp") or ""),
            reverse=not self._timeline_sort_asc
        )
        self.tl_sort_btn.setText("⇅ Sort Asc" if self._timeline_sort_asc else "⇅ Sort Desc")
        self._render_timeline(self._timeline_all_events)

    def _filter_apps(self):
        self._render_apps(self._all_apps)

    def _filter_metadata(self):
        self._render_metadata(self._all_metadata)

    def _on_corr_cat_selected(self, row, *_):
        if row < 0 or not self._corr_data:
            return
        keys = list(self._corr_data.keys())
        if row >= len(keys):
            return
        key   = keys[row]
        items = self._corr_data.get(key, [])
        self.corr_detail_table.setRowCount(0)
        for item in items if isinstance(items, list) else []:
            r = self.corr_detail_table.rowCount()
            self.corr_detail_table.insertRow(r)
            self.corr_detail_table.setItem(r, 0, QTableWidgetItem(str(item.get("evidence_id", ""))))
            self.corr_detail_table.setItem(r, 1, QTableWidgetItem(str(item.get("filename", ""))))
            # Build detail string from remaining keys
            detail = " | ".join(
                f"{k}: {v}" for k, v in item.items()
                if k not in ("evidence_id", "filename")
            )
            self.corr_detail_table.setItem(r, 2, QTableWidgetItem(detail))

    # ── Global search ──────────────────────────────────────────────────────────

    def _run_search(self):
        keyword = self.search_input.text().strip()
        if not keyword:
            return
        if not self._current_case_id:
            self.status_lbl.setText("Select a case first.")
            return

        filters = {}
        df = self.filter_date_from.text().strip()
        dt = self.filter_date_to.text().strip()
        if df: filters["date_from"] = df
        if dt: filters["date_to"]   = dt
        inv = self.filter_investigator.text().strip()
        if inv: filters["investigator"] = inv
        et = self.filter_ev_type.currentText()
        if et != "All": filters["evidence_type"] = et
        ft = self.filter_file_type.text().strip()
        if ft: filters["file_type"] = ft
        vs = self.filter_verification_status.currentText()
        if vs != "All": filters["verification_status"] = vs

        self.search_table.setRowCount(0)

        # Global DB search
        results = keyword_search_global(
            keyword, self.db, self._current_case_id, filters
        )
        for r in results:
            self._add_search_row(
                r.get("source", ""), r.get("type", ""),
                r.get("match", ""), r.get("detail", ""), r.get("ts", "")
            )

        # File content search
        if self._current_evidence_dir and os.path.exists(self._current_evidence_dir):
            for r in keyword_search_files(self._current_evidence_dir, keyword):
                self._add_search_row(
                    "file", r.get("file", ""),
                    r.get("match", ""), f"line {r.get('line','')}", ""
                )
        elif self._current_evidence_dir:
            self.status_lbl.setText(
                "Search: evidence directory not found. DB results shown."
            )

        count = self.search_table.rowCount()
        self.search_count_lbl.setText(f"{count} result(s) for '{keyword}'")
        self.tabs.setCurrentIndex(5)

    def _add_search_row(self, source: str, stype: str, match: str,
                         detail: str, ts: str):
        row = self.search_table.rowCount()
        self.search_table.insertRow(row)
        si = QTableWidgetItem(source)
        si.setForeground(QColor("#1D9E75"))
        self.search_table.setItem(row, 0, si)
        self.search_table.setItem(row, 1, QTableWidgetItem(stype))
        self.search_table.setItem(row, 2, QTableWidgetItem(str(match)[:150]))
        self.search_table.setItem(row, 3, QTableWidgetItem(str(detail)[:150]))
        ts_i = QTableWidgetItem(str(ts))
        ts_i.setFont(QFont("Courier New", 9))
        ts_i.setForeground(QColor("#8B949E"))
        self.search_table.setItem(row, 4, ts_i)

    def _clear_search_filters(self):
        self.filter_date_from.clear()
        self.filter_date_to.clear()
        self.filter_investigator.clear()
        self.filter_ev_type.setCurrentIndex(0)
        self.filter_file_type.clear()
        self.filter_verification_status.setCurrentIndex(0)

    def _save_analysis_result(self, atype: str, summary: str, data: dict):
        """
        FIX (report duplication): previously this always INSERTed a new
        analysis_results row, even if the exact same result (same type +
        summary) had just been saved. Since generated reports list every
        analysis_results row for the case, re-running analysis without any
        change in outcome (e.g. running "duplicates" twice with no new
        evidence added) produced two identical "duplicate_detection"
        entries in the report — implementation duplication, not two
        genuinely different findings.

        This mirrors the dedup already used for timeline events: skip the
        insert if the most recent row for this (case, analysis_type)
        already has the identical summary. A genuinely new/changed result
        (different summary — e.g. duplicate count changed after adding
        evidence) is still saved as a new history entry, so real analysis
        history is preserved, not deleted or overwritten.
        """
        if not self._current_case_id:
            return
        existing = self.db.get_analysis_results(self._current_case_id)
        same_type = [r for r in existing if r["analysis_type"] == atype]
        if same_type:
            latest = max(same_type, key=lambda r: (r["created_at"], r["id"]))
            if latest["result_summary"] == summary:
                return  # identical result already recorded — skip duplicate
        self.db.add_analysis_result(
            self._current_case_id, None, atype, summary, data
        )
        # Phase 2: record the ANALYZED lifecycle/audit event for a
        # genuinely new/changed analysis result (the dedup check above
        # already filtered out no-op re-runs, so this only fires for
        # real analysis activity).
        mw = self.window()
        if hasattr(mw, "audit"):
            case = self.db.get_case(self._current_case_id)
            inv  = case["investigator"] if case else ""
            mw.audit.log_analysis_performed(
                self._current_case_id, inv, atype, summary
            )
