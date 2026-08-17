"""
Dashboard panel.

FIXES:
  - BUG#1: Recent-cases widget cleanup used takeAt(0) but never called deleteLater()
           causing widget accumulation on each on_shown() refresh
  - BUG#2: Metric cards showed stale values when switching tabs (now always refreshes)
  - BUG#3: addStretch() inserted inside recent_cases_layout caused misalignment on refresh
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QFrame, QGridLayout, QScrollArea,
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from forensiq.core.time_utils import parse_stored


class StatCard(QFrame):
    def __init__(self, title: str, value: str, subtitle: str = "", color="#1D9E75"):
        super().__init__()
        self.setObjectName("card")
        l = QVBoxLayout(self)
        l.setContentsMargins(16, 14, 16, 14)
        l.setSpacing(4)

        lbl = QLabel(title); lbl.setObjectName("metaLabel")
        l.addWidget(lbl)

        self.value_lbl = QLabel(value)
        self.value_lbl.setFont(QFont("Segoe UI", 28, QFont.Weight.Bold))
        self.value_lbl.setStyleSheet(f"color:{color};")
        l.addWidget(self.value_lbl)

        if subtitle:
            sl = QLabel(subtitle); sl.setObjectName("metaLabel")
            l.addWidget(sl)

    def set_value(self, v: str):
        self.value_lbl.setText(v)


class DashboardPanel(QWidget):
    def __init__(self, db, adb, parent=None):
        super().__init__(parent)
        self.db  = db
        self.adb = adb
        self._build()

    def _build(self):
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)

        content = QWidget()
        scroll.setWidget(content)
        l = QVBoxLayout(content)
        l.setContentsMargins(24, 24, 24, 24)
        l.setSpacing(20)

        # Metric cards
        grid = QGridLayout(); grid.setSpacing(12)
        self.card_cases    = StatCard("Total Cases",    "0", "in database")
        self.card_devices  = StatCard("Devices",        "0", "examined",   "#3FB950")
        self.card_evidence = StatCard("Evidence Items", "0", "acquired",   "#E3B341")
        self.card_analysis = StatCard("Analysis Runs",  "0", "completed")
        for i, c in enumerate([self.card_cases, self.card_devices,
                                self.card_evidence, self.card_analysis]):
            grid.addWidget(c, 0, i)
        l.addLayout(grid)

        # Quick actions
        af = QFrame(); af.setObjectName("card")
        afl = QVBoxLayout(af); afl.setContentsMargins(16, 14, 16, 14)
        afl.addWidget(self._bold_label("Quick Actions"))
        btn_row = QHBoxLayout(); btn_row.setSpacing(10)
        self.btn_new_case = QPushButton("+ New Case")
        self.btn_new_case.setObjectName("primaryBtn")
        self.btn_new_case.clicked.connect(
            lambda: self.window()._nav_to("cases") if hasattr(self.window(), "_nav_to") else None
        )
        self.btn_detect = QPushButton("⬡  Detect Device")
        self.btn_detect.setObjectName("primaryBtn")
        self.btn_detect.clicked.connect(
            lambda: self.window()._nav_to("device") if hasattr(self.window(), "_nav_to") else None
        )
        btn_row.addWidget(self.btn_new_case)
        btn_row.addWidget(self.btn_detect)
        btn_row.addStretch()
        afl.addSpacing(6)
        afl.addLayout(btn_row)
        l.addWidget(af)

        # Recent cases
        rc = QFrame(); rc.setObjectName("card")
        rcl = QVBoxLayout(rc); rcl.setContentsMargins(16, 14, 16, 14); rcl.setSpacing(8)
        rcl.addWidget(self._bold_label("Recent Cases"))
        # FIX: store reference to inner container, not layout, for clean teardown
        self._cases_container = QWidget()
        self._cases_inner     = QVBoxLayout(self._cases_container)
        self._cases_inner.setContentsMargins(0, 0, 0, 0)
        self._cases_inner.setSpacing(4)
        rcl.addWidget(self._cases_container)
        l.addWidget(rc)

        # Workflow guide
        gf = QFrame(); gf.setObjectName("card")
        gl = QVBoxLayout(gf); gl.setContentsMargins(16, 14, 16, 14); gl.setSpacing(6)
        gl.addWidget(self._bold_label("Investigation Workflow"))
        for num, desc, loc in [
            ("1", "Create or open a Case",                 "Cases panel"),
            ("2", "Connect device & verify USB Debugging", "Device panel"),
            ("3", "Select targets & run Acquisition",      "Acquisition panel"),
            ("4", "Run analysis on acquired evidence",     "Analysis panel"),
            ("5", "Verify evidence integrity (SHA-256)",   "Integrity panel"),
            ("6", "Generate PDF / HTML Reports",           "Reports panel"),
            ("7", "Review immutable Audit Trail",          "Audit panel"),
            ("8", "Manage Chain of Custody",               "Custody panel"),
        ]:
            row = QHBoxLayout()
            nb  = QLabel(num)
            nb.setFixedSize(24, 24)
            nb.setAlignment(Qt.AlignmentFlag.AlignCenter)
            nb.setStyleSheet(
                "background:#1D9E75;color:white;border-radius:12px;"
                "font-size:11px;font-weight:bold;"
            )
            dl = QLabel(desc)
            ll = QLabel(loc); ll.setObjectName("metaLabel")
            ll.setAlignment(Qt.AlignmentFlag.AlignRight)
            row.addWidget(nb); row.addWidget(dl); row.addStretch(); row.addWidget(ll)
            gl.addLayout(row)
        l.addWidget(gf)
        l.addStretch()

    def _bold_label(self, text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setFont(QFont("Segoe UI", 13, QFont.Weight.Bold))
        return lbl

    def on_shown(self):
        try:
            cases = self.db.get_all_cases()
            self.card_cases.set_value(str(len(cases)))

            # FIX: properly destroy old case row widgets before rebuilding
            while self._cases_inner.count():
                item = self._cases_inner.takeAt(0)
                w = item.widget()
                if w:
                    w.setParent(None)
                    w.deleteLater()

            for case in cases[:5]:
                row_w = QWidget()
                row   = QHBoxLayout(row_w)
                row.setContentsMargins(0, 0, 0, 0)
                num_l = QLabel(case["case_number"]); num_l.setObjectName("tealAccent")
                tit_l = QLabel(case["title"])
                # Phase 10: compact card keeps date-only by design, but
                # must still label the timezone (was bare, unlabelled).
                _dt = parse_stored(case["created_at"])
                ts_l  = QLabel((_dt.strftime("%Y-%m-%d") + " UTC") if _dt else "—")
                ts_l.setObjectName("metaLabel")
                st_color = "#3FB950" if str(case["status"]).upper() == "ACTIVE" else "#8B949E"
                st_l  = QLabel(case["status"].upper())
                st_l.setStyleSheet(
                    f"color:{st_color};font-size:11px;"
                    f"background:{st_color}20;padding:2px 8px;border-radius:10px;"
                )
                row.addWidget(num_l); row.addWidget(tit_l)
                row.addStretch()
                row.addWidget(ts_l);  row.addWidget(st_l)
                self._cases_inner.addWidget(row_w)

            if not cases:
                no_lbl = QLabel("No cases yet — create one in the Cases panel.")
                no_lbl.setObjectName("metaLabel")
                self._cases_inner.addWidget(no_lbl)

            # PERF FIX: was looping per-case calling get_evidence_count() +
            # get_devices_for_case() + get_analysis_results() — up to 15 extra
            # queries per dashboard visit, AND the totals only summed the first
            # 5 cases shown while being displayed as if system-wide. Now a
            # single get_system_stats() call returns accurate, complete totals
            # across ALL cases in 3 queries total regardless of case count.
            stats = self.db.get_system_stats()
            self.card_devices.set_value(str(stats["devices"]))
            self.card_evidence.set_value(str(stats["evidence"]))
            self.card_analysis.set_value(str(stats["analysis"]))

        except Exception:
            # Never crash the dashboard on unexpected DB errors; metrics
            # remain at their last-known values until the next successful
            # refresh (e.g. next tab switch).
            pass
