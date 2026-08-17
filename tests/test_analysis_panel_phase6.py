"""
UI tests — Phase 6 Analysis Panel expansion (findings tab, new task
checkboxes, IOC input, and reload of Phase 6 findings from the existing
analysis_results table).

Requires a Qt platform plugin; uses 'offscreen' the same way the Phase 1-5
regression suite does, and skips gracefully if Qt cannot initialize in this
environment (mirrors tests/test_regression.py's pattern).
"""

import os
import json

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


def _make_app():
    try:
        from PyQt6.QtWidgets import QApplication
        return QApplication.instance() or QApplication([])
    except Exception:
        pytest.skip("Qt display not available in this environment")


class TestAnalysisPanelPhase6UI:
    def test_panel_builds_with_new_widgets(self, db):
        _qt_app = _make_app()  # noqa: F841 — keep QApplication alive for the widget's lifetime
        from forensiq.ui.panels.analysis_panel import AnalysisPanel
        panel = AnalysisPanel(db)
        # New Phase 6 task checkboxes
        for attr in ("cb_network", "cb_battery", "cb_integrity",
                     "cb_suspicious", "cb_ioc"):
            assert hasattr(panel, attr), f"missing checkbox: {attr}"
        # New IOC input
        assert hasattr(panel, "ioc_input")
        # New Findings tab widgets
        assert hasattr(panel, "findings_table")
        assert hasattr(panel, "finding_type_combo")
        assert hasattr(panel, "finding_severity_combo")

    def test_findings_tab_is_first_tab(self, db):
        _qt_app = _make_app()  # noqa: F841 — keep QApplication alive for the widget's lifetime
        from forensiq.ui.panels.analysis_panel import AnalysisPanel
        panel = AnalysisPanel(db)
        assert panel.tabs.tabText(0).strip().endswith("Findings")

    def test_findings_table_has_five_columns(self, db):
        _qt_app = _make_app()  # noqa: F841 — keep QApplication alive for the widget's lifetime
        from forensiq.ui.panels.analysis_panel import AnalysisPanel
        panel = AnalysisPanel(db)
        assert panel.findings_table.columnCount() == 5
        headers = [panel.findings_table.horizontalHeaderItem(i).text()
                   for i in range(5)]
        assert headers == ["Analysis Type", "Severity", "Finding",
                            "Timestamp", "Evidence Reference"]

    def test_render_findings_populates_table(self, db):
        _qt_app = _make_app()  # noqa: F841 — keep QApplication alive for the widget's lifetime
        from forensiq.ui.panels.analysis_panel import AnalysisPanel
        from forensiq.core.analyzer import make_finding
        panel = AnalysisPanel(db)
        findings = [
            make_finding("network_info", "/tmp/network_info.txt",
                         "VPN interface detected", severity="medium", case_id=1),
            make_finding("suspicious_artifact", "app:com.magisk",
                         "suspicious app", severity="high", case_id=1),
        ]
        panel._render_findings(findings)
        assert panel.findings_table.rowCount() == 2
        assert "2 finding(s)" in panel.findings_summary_lbl.text()

    def test_severity_filter_narrows_results(self, db):
        _qt_app = _make_app()  # noqa: F841 — keep QApplication alive for the widget's lifetime
        from forensiq.ui.panels.analysis_panel import AnalysisPanel
        from forensiq.core.analyzer import make_finding
        panel = AnalysisPanel(db)
        findings = [
            make_finding("network_info", "/tmp/a.txt", "a", severity="high", case_id=1),
            make_finding("battery_system", "/tmp/b.json", "b", severity="low", case_id=1),
        ]
        panel._all_findings = findings
        panel.finding_severity_combo.setCurrentText("high")
        panel._render_findings(findings)
        assert panel.findings_table.rowCount() == 1
        assert panel.findings_table.item(0, 1).text() == "HIGH"

    def test_type_filter_narrows_results(self, db):
        _qt_app = _make_app()  # noqa: F841 — keep QApplication alive for the widget's lifetime
        from forensiq.ui.panels.analysis_panel import AnalysisPanel
        from forensiq.core.analyzer import make_finding
        panel = AnalysisPanel(db)
        findings = [
            make_finding("network_info", "/tmp/a.txt", "a", severity="high", case_id=1),
            make_finding("battery_system", "/tmp/b.json", "b", severity="low", case_id=1),
        ]
        panel.finding_type_combo.addItem("network_info")
        panel.finding_type_combo.setCurrentText("network_info")
        panel._render_findings(findings)
        assert panel.findings_table.rowCount() == 1
        assert panel.findings_table.item(0, 0).text() == "network_info"


class TestAnalysisPanelPhase6Persistence:
    """
    Verifies Phase 6 results are saved to (and reloaded from) the EXISTING
    analysis_results table — no new table/schema introduced — and that each
    saved row is traceable (findings carry evidence_ref).
    """

    def test_save_analysis_result_persists_findings(self, populated):
        _qt_app = _make_app()  # noqa: F841 — keep QApplication alive for the widget's lifetime
        from forensiq.ui.panels.analysis_panel import AnalysisPanel
        from forensiq.core.analyzer import analyze_network_info
        panel = AnalysisPanel(populated.db)
        panel._current_case_id = populated.cid
        data = analyze_network_info(populated.ev_dir, case_id=populated.cid)
        panel._save_analysis_result(
            "network_info", f"{len(data['findings'])} finding(s)", data
        )
        rows = populated.db.get_analysis_results(populated.cid)
        saved = [r for r in rows if r["analysis_type"] == "network_info"]
        assert saved
        stored = json.loads(saved[-1]["result_data"])
        assert stored["findings"], "findings must be persisted in result_data"
        assert stored["findings"][0]["evidence_ref"]

    def test_load_existing_findings_reloads_from_db(self, populated):
        _qt_app = _make_app()  # noqa: F841 — keep QApplication alive for the widget's lifetime
        from forensiq.ui.panels.analysis_panel import AnalysisPanel
        from forensiq.core.analyzer import analyze_battery_system

        data = analyze_battery_system(
            populated.ev_dir, db=populated.db, case_id=populated.cid
        )
        populated.db.add_analysis_result(
            populated.cid, None, "battery",
            f"{len(data['findings'])} finding(s)", data,
        )

        panel = AnalysisPanel(populated.db)
        panel._current_case_id = populated.cid
        panel._load_existing_findings()
        assert panel.findings_table.rowCount() == len(data["findings"])

    def test_on_case_changed_reloads_findings(self, populated):
        _qt_app = _make_app()  # noqa: F841 — keep QApplication alive for the widget's lifetime
        from forensiq.ui.panels.analysis_panel import AnalysisPanel
        from forensiq.core.analyzer import detect_suspicious_artifacts

        data = detect_suspicious_artifacts(
            populated.ev_dir, db=populated.db, case_id=populated.cid
        )
        populated.db.add_analysis_result(
            populated.cid, None, "suspicious_artifacts",
            f"{len(data['findings'])} finding(s)", data,
        )

        panel = AnalysisPanel(populated.db)
        panel.on_shown()  # populates case_combo from DB
        # Selecting the populated case must trigger _load_existing_findings()
        idx = panel.case_combo.findData(populated.cid)
        assert idx >= 0
        panel.case_combo.setCurrentIndex(idx)
        assert panel.findings_table.rowCount() == len(data["findings"])
