"""
Unit & Integration tests — Phase 6: Analysis Engine Expansion.

Covers the five new analyzer modules and their standard finding shape:
  - make_finding() / highest_severity()   — shared record schema
  - analyze_network_info()                — network_info.txt parsing
  - analyze_battery_system()               — battery_info.json + device record
  - analyze_hash_integrity()               — wraps existing integrity engine
  - detect_suspicious_artifacts()          — filesystem + app sweep
  - search_iocs()                          — IOC search across evidence/apps/network

Every analysis function is checked for:
  Input → Processing → Finding → Timestamp → Evidence Reference
i.e. every finding dict must carry analysis_type, evidence_ref, timestamp,
status, finding, and severity — and must be traceable to real source data,
never fabricated.
"""

import json
import os

import pytest

from forensiq.core.analyzer import (
    SEVERITY_ORDER,
    STATUS_COMPLETED,
    STATUS_NO_DATA,
    make_finding,
    highest_severity,
    analyze_network_info,
    analyze_battery_system,
    analyze_hash_integrity,
    detect_suspicious_artifacts,
    search_iocs,
    AnalysisWorker,
)


REQUIRED_FINDING_KEYS = (
    "case_id", "analysis_type", "evidence_ref", "timestamp",
    "status", "finding", "severity",
)


def _assert_valid_findings(findings):
    """Shared assertion: every finding follows the standard Phase 6 shape."""
    assert isinstance(findings, list)
    for f in findings:
        for key in REQUIRED_FINDING_KEYS:
            assert key in f, f"finding missing required key '{key}': {f}"
        assert f["severity"] in SEVERITY_ORDER
        assert f["evidence_ref"], "every finding must reference source evidence"


# ── make_finding / highest_severity ─────────────────────────────────────────────

class TestMakeFinding:
    def test_default_shape(self):
        f = make_finding("network_info", "/tmp/x.txt", "test finding")
        for key in REQUIRED_FINDING_KEYS:
            assert key in f

    def test_status_defaults_completed(self):
        f = make_finding("network_info", "/tmp/x.txt", "test finding")
        assert f["status"] == STATUS_COMPLETED

    def test_severity_defaults_info(self):
        f = make_finding("network_info", "/tmp/x.txt", "test finding")
        assert f["severity"] == "info"

    def test_extra_kwargs_passthrough(self):
        f = make_finding("network_info", "/tmp/x.txt", "test", ip="1.2.3.4")
        assert f["ip"] == "1.2.3.4"

    def test_case_id_attached(self):
        f = make_finding("network_info", "/tmp/x.txt", "test", case_id=42)
        assert f["case_id"] == 42


class TestHighestSeverity:
    def test_empty_list_is_info(self):
        assert highest_severity([]) == "info"

    def test_picks_max_severity(self):
        findings = [
            make_finding("t", "x", "a", severity="low"),
            make_finding("t", "x", "b", severity="critical"),
            make_finding("t", "x", "c", severity="medium"),
        ]
        assert highest_severity(findings) == "critical"


# ── analyze_network_info ─────────────────────────────────────────────────────────

class TestAnalyzeNetworkInfo:
    def test_returns_valid_findings(self, ev_dir):
        result = analyze_network_info(ev_dir, case_id=1)
        assert result["status"] == STATUS_COMPLETED
        _assert_valid_findings(result["findings"])

    def test_evidence_ref_is_network_info_path(self, ev_dir):
        result = analyze_network_info(ev_dir, case_id=1)
        assert result["evidence_ref"] == os.path.join(ev_dir, "network_info.txt")

    def test_sha256_computed(self, ev_dir):
        result = analyze_network_info(ev_dir, case_id=1)
        assert len(result["sha256"]) == 64

    def test_ip_addresses_parsed(self, ev_dir):
        result = analyze_network_info(ev_dir, case_id=1)
        assert "192.168.1.42" in result["ip_addresses"]

    def test_loopback_excluded_from_non_loopback_check(self, ev_dir):
        result = analyze_network_info(ev_dir, case_id=1)
        assert "127.0.0.1" in result["ip_addresses"]  # still captured...
        # ...but does not trigger the "no active IP" finding since 192.168.1.42 exists
        msgs = [f["finding"] for f in result["findings"]]
        assert not any("No active non-loopback IP" in m for m in msgs)

    def test_vpn_tunnel_interface_flagged(self, ev_dir):
        result = analyze_network_info(ev_dir, case_id=1)
        assert "tun0" in result["interfaces"]
        vpn_findings = [f for f in result["findings"] if "tun0" in f["finding"]]
        assert vpn_findings
        assert vpn_findings[0]["severity"] == "medium"

    def test_wifi_ssid_parsed(self, ev_dir):
        result = analyze_network_info(ev_dir, case_id=1)
        assert result["wifi"].get("ssid") == "TestNetwork"

    def test_ssid_finding_present(self, ev_dir):
        result = analyze_network_info(ev_dir, case_id=1)
        ssid_findings = [f for f in result["findings"] if f.get("ssid") == "TestNetwork"]
        assert ssid_findings

    def test_missing_file_returns_no_data_status(self, tmp_path):
        result = analyze_network_info(str(tmp_path), case_id=1)
        assert result["status"] == STATUS_NO_DATA
        _assert_valid_findings(result["findings"])

    def test_missing_evidence_dir(self):
        result = analyze_network_info("", case_id=1)
        assert result["status"] == STATUS_NO_DATA

    def test_case_id_propagated_to_findings(self, ev_dir):
        result = analyze_network_info(ev_dir, case_id=99)
        assert all(f["case_id"] == 99 for f in result["findings"])


# ── analyze_battery_system ────────────────────────────────────────────────────────

class TestAnalyzeBatterySystem:
    def test_returns_valid_findings(self, ev_dir):
        result = analyze_battery_system(ev_dir, case_id=1)
        _assert_valid_findings(result["findings"])

    def test_evidence_ref_is_battery_info_path(self, ev_dir):
        result = analyze_battery_system(ev_dir, case_id=1)
        assert result["evidence_ref"] == os.path.join(ev_dir, "battery_info.json")

    def test_battery_parsed(self, ev_dir):
        result = analyze_battery_system(ev_dir, case_id=1)
        assert result["battery"]["level"] == 41
        assert result["battery"]["health"] == "Good"

    def test_good_health_no_health_finding(self, ev_dir):
        result = analyze_battery_system(ev_dir, case_id=1)
        health_findings = [f for f in result["findings"] if "health reported" in f["finding"]]
        assert not health_findings  # health == "Good" — no anomaly

    def test_overheat_flagged_high(self, tmp_path):
        evd = tmp_path / "ev"
        evd.mkdir()
        (evd / "battery_info.json").write_text(json.dumps({
            "level": 60, "status": "Discharging", "health": "Overheat",
            "temperature": 48.0, "voltage": 3800, "plugged": "Unplugged",
            "technology": "Li-ion",
        }))
        result = analyze_battery_system(str(evd), case_id=1)
        severities = {f["severity"] for f in result["findings"]}
        assert "high" in severities  # elevated temperature
        assert "medium" in severities  # health != Good

    def test_low_battery_flagged_info(self, tmp_path):
        evd = tmp_path / "ev"
        evd.mkdir()
        (evd / "battery_info.json").write_text(json.dumps({
            "level": 2, "status": "Discharging", "health": "Good",
            "temperature": 25.0, "voltage": 3400, "plugged": "Unplugged",
            "technology": "Li-ion",
        }))
        result = analyze_battery_system(str(evd), case_id=1)
        low_batt = [f for f in result["findings"] if "critically low" in f["finding"]]
        assert low_batt
        assert low_batt[0]["severity"] == "info"

    def test_missing_file_flags_no_data(self, tmp_path):
        result = analyze_battery_system(str(tmp_path), case_id=1)
        no_data = [f for f in result["findings"] if f["status"] == STATUS_NO_DATA]
        assert no_data

    def test_device_record_reused_not_requeried(self, ev_dir, populated):
        """Reuses the DB's devices row (usb_debugging=True from _FakeDevice fixture)."""
        result = analyze_battery_system(
            populated.ev_dir, db=populated.db, case_id=populated.cid
        )
        assert result["device"].get("serial") == "DEV001"
        usb_findings = [f for f in result["findings"] if "USB debugging" in f["finding"]]
        assert usb_findings  # _FakeDevice.usb_debugging = True

    def test_explicit_device_dict_used_over_db(self, ev_dir):
        device = {"serial": "XYZ", "usb_debugging": False, "sdk_version": "33"}
        result = analyze_battery_system(ev_dir, case_id=1, device=device)
        assert result["device"]["serial"] == "XYZ"

    def test_outdated_sdk_flagged(self, ev_dir):
        device = {"serial": "OLD1", "usb_debugging": False, "sdk_version": "19"}
        result = analyze_battery_system(ev_dir, case_id=1, device=device)
        sdk_findings = [f for f in result["findings"] if "outdated Android SDK" in f["finding"]]
        assert sdk_findings
        assert sdk_findings[0]["severity"] == "medium"


# ── analyze_hash_integrity ────────────────────────────────────────────────────────

class TestAnalyzeHashIntegrity:
    def test_reuses_existing_integrity_summary(self, populated):
        result = analyze_hash_integrity(populated.db, populated.cid)
        assert result["summary"] == populated.db.get_case_integrity_summary(populated.cid)

    def test_returns_valid_findings(self, populated):
        result = analyze_hash_integrity(populated.db, populated.cid)
        _assert_valid_findings(result["findings"])

    def test_pass_verified_item_is_info(self, populated):
        result = analyze_hash_integrity(populated.db, populated.cid)
        pass_findings = [f for f in result["findings"]
                          if f.get("evidence_id") == populated.eid_pass]
        assert pass_findings
        assert pass_findings[0]["severity"] == "info"
        assert "verified" in pass_findings[0]["finding"].lower()

    def test_fail_verified_item_is_critical(self, populated):
        result = analyze_hash_integrity(populated.db, populated.cid)
        fail_findings = [f for f in result["findings"]
                          if f.get("evidence_id") == populated.eid_fail]
        assert fail_findings
        assert fail_findings[0]["severity"] == "critical"

    def test_unverified_item_is_medium(self, populated):
        result = analyze_hash_integrity(populated.db, populated.cid)
        unverified = [f for f in result["findings"]
                       if f.get("evidence_id") == populated.eid_null]
        assert unverified
        assert unverified[0]["severity"] == "medium"
        assert "never" in unverified[0]["finding"].lower()

    def test_no_hash_recomputed(self, populated):
        """
        FIX-DUP: analyze_hash_integrity() must not recompute any hash — it
        only reads the verification rows CaseManager already has. Verified
        here by checking that its findings exactly mirror
        get_last_verification_per_evidence()'s stored/current hash values
        (i.e. it is a pure read, not an independent recomputation).
        """
        result = analyze_hash_integrity(populated.db, populated.cid)
        last_by_ev = populated.db.get_last_verification_per_evidence(populated.cid)
        for f in result["findings"]:
            eid = f.get("evidence_id")
            if eid in last_by_ev:
                vr = last_by_ev[eid]
                if "current_sha256" in f:
                    assert f["current_sha256"] == vr["current_hash"]
                if "stored_sha256" in f:
                    assert f["stored_sha256"] in (vr["stored_hash"], "")

    def test_empty_case_returns_info_finding(self, db):
        cid = db.create_case("TC-EMPTY", "Empty", "Inv", "")
        result = analyze_hash_integrity(db, cid)
        assert result["findings"][0]["severity"] == "info"


# ── detect_suspicious_artifacts ───────────────────────────────────────────────────

class TestDetectSuspiciousArtifacts:
    def test_returns_valid_findings(self, ev_dir):
        result = detect_suspicious_artifacts(ev_dir, case_id=1)
        _assert_valid_findings(result["findings"])

    def test_high_risk_extension_flagged(self, ev_dir):
        """malware.apk in ev_dir fixture."""
        result = detect_suspicious_artifacts(ev_dir, case_id=1)
        apk_findings = [f for f in result["findings"] if "malware.apk" in f["evidence_ref"]]
        assert apk_findings
        assert apk_findings[0]["severity"] == "low"

    def test_suspicious_app_flagged_high(self, ev_dir):
        """com.magisk / com.termux present in ev_dir's installed_apps.json fixture."""
        result = detect_suspicious_artifacts(ev_dir, case_id=1)
        app_findings = [f for f in result["findings"] if f.get("package")]
        assert app_findings
        assert all(f["severity"] in ("high", "medium") for f in app_findings)

    def test_suspicious_count_tallied(self, ev_dir):
        result = detect_suspicious_artifacts(ev_dir, case_id=1)
        high_crit = [f for f in result["findings"] if f["severity"] in ("high", "critical")]
        assert result["suspicious_count"] == len(high_crit)

    def test_filename_marker_flagged_high(self, tmp_path):
        evd = tmp_path / "ev"
        evd.mkdir()
        (evd / "magisk_backup.zip").write_bytes(b"data")
        result = detect_suspicious_artifacts(str(evd), case_id=1)
        marker_findings = [f for f in result["findings"] if f.get("marker") == "magisk"]
        assert marker_findings
        assert marker_findings[0]["severity"] == "high"

    def test_clean_evidence_no_suspicious_findings(self, tmp_path):
        evd = tmp_path / "ev"
        evd.mkdir()
        (evd / "photo.jpg").write_bytes(b"\xff\xd8\xff")
        result = detect_suspicious_artifacts(str(evd), case_id=1)
        assert result["suspicious_count"] == 0
        assert result["findings"][0]["severity"] == "info"

    def test_does_not_duplicate_app_classification_logic(self, ev_dir):
        """FIX-DUP: reuses analyze_apps()/classify_app() rather than re-implementing."""
        import forensiq.core.analyzer as az
        result_direct = az.analyze_apps(os.path.join(ev_dir, "installed_apps.json"))
        result = detect_suspicious_artifacts(ev_dir, case_id=1)
        expected_suspicious = sum(
            1 for a in result_direct["apps"] if a["status"] == "suspicious"
        )
        actual = sum(1 for f in result["findings"]
                      if f.get("package") and f["severity"] == "high")
        assert actual == expected_suspicious


# ── search_iocs ────────────────────────────────────────────────────────────────────

class TestSearchIOCs:
    def test_empty_ioc_list_returns_no_data(self, populated):
        result = search_iocs(populated.ev_dir, populated.db, populated.cid, [])
        assert result["status"] == STATUS_NO_DATA

    def test_returns_valid_findings(self, populated):
        result = search_iocs(populated.ev_dir, populated.db, populated.cid, ["nomatch999"])
        _assert_valid_findings(result["findings"])

    def test_no_match_is_info(self, populated):
        result = search_iocs(populated.ev_dir, populated.db, populated.cid, ["totally-unrelated-ioc"])
        assert result["findings"][0]["severity"] == "info"
        assert "no match" in result["findings"][0]["finding"].lower()

    def test_sha256_hash_match_is_critical(self, populated):
        """h_pass is the real recorded SHA-256 of report.txt in the populated fixture."""
        result = search_iocs(populated.ev_dir, populated.db, populated.cid, [populated.h_pass])
        crit = [f for f in result["findings"] if f["severity"] == "critical"]
        assert crit
        assert crit[0]["evidence_id"] == populated.eid_pass

    def test_ip_address_match_from_network_info(self, populated):
        result = search_iocs(populated.ev_dir, populated.db, populated.cid, ["192.168.1.42"])
        crit = [f for f in result["findings"] if f["severity"] == "critical"
                and f["ioc"] == "192.168.1.42"]
        assert crit

    def test_ssid_match_from_network_info(self, populated):
        result = search_iocs(populated.ev_dir, populated.db, populated.cid, ["TestNetwork"])
        matches = [f for f in result["findings"] if f.get("ioc") == "TestNetwork"
                   and f["severity"] != "info"]
        assert matches

    def test_filename_keyword_match_reuses_global_search(self, populated):
        """'report.txt' should surface via keyword_search_global (evidence source)."""
        result = search_iocs(populated.ev_dir, populated.db, populated.cid, ["report.txt"])
        hits = [f for f in result["findings"] if f.get("ioc") == "report.txt"
                and f["severity"] != "info"]
        assert hits

    def test_iocs_searched_recorded(self, populated):
        iocs = ["a", "b", "c"]
        result = search_iocs(populated.ev_dir, populated.db, populated.cid, iocs)
        assert result["iocs_searched"] == iocs

    def test_whitespace_only_iocs_filtered(self, populated):
        result = search_iocs(populated.ev_dir, populated.db, populated.cid, ["  ", "", "real-ioc"])
        assert result["iocs_searched"] == ["real-ioc"]


# ── AnalysisWorker Phase 6 task routing (headless-safe subset) ─────────────────────

class TestAnalysisWorkerPhase6Tasks:
    """
    AnalysisWorker is a QThread and requires PyQt6 to instantiate; these tests
    only verify the task-name plumbing added in Phase 6 without actually
    starting a Qt event loop (mirrors how Phase 4/5 tests treat AnalysisWorker).
    """

    @staticmethod
    def _require_pyqt6():
        try:
            import PyQt6  # noqa: F401
        except ImportError:
            pytest.skip("PyQt6 not available in this environment")

    def test_iocs_stored_on_worker(self, ev_dir, populated):
        self._require_pyqt6()
        worker = AnalysisWorker(
            ev_dir, ["ioc_search"], db=populated.db, case_id=populated.cid,
            iocs=["1.2.3.4"],
        )
        assert worker.iocs == ["1.2.3.4"]

    def test_iocs_defaults_to_empty_list(self, ev_dir, populated):
        self._require_pyqt6()
        worker = AnalysisWorker(ev_dir, ["network"], db=populated.db, case_id=populated.cid)
        assert worker.iocs == []

    def test_new_task_names_accepted(self, ev_dir, populated):
        self._require_pyqt6()
        worker = AnalysisWorker(
            ev_dir,
            ["network", "battery", "hash_integrity", "suspicious_artifacts", "ioc_search"],
            db=populated.db, case_id=populated.cid, iocs=["x"],
        )
        assert worker.tasks == [
            "network", "battery", "hash_integrity", "suspicious_artifacts", "ioc_search"
        ]


# ── generate_analysis_report Phase 6 integration ────────────────────────────────────

class TestGenerateAnalysisReportPhase6:
    def test_report_includes_phase6_sections(self, populated, tmp_path):
        from forensiq.core.analyzer import generate_analysis_report
        out = generate_analysis_report(
            populated.cid, populated.db, populated.ev_dir, str(tmp_path)
        )
        rpt = json.loads(open(out["json"]).read())
        for key in ("network", "battery_system", "hash_integrity",
                    "suspicious_artifacts", "findings"):
            assert key in rpt, f"missing Phase 6 report key: {key}"

    def test_report_findings_are_sorted_by_severity_desc(self, populated, tmp_path):
        from forensiq.core.analyzer import generate_analysis_report, SEVERITY_ORDER
        out = generate_analysis_report(
            populated.cid, populated.db, populated.ev_dir, str(tmp_path)
        )
        rpt = json.loads(open(out["json"]).read())
        sevs = [SEVERITY_ORDER.get(f.get("severity", "info"), 0) for f in rpt["findings"]]
        assert sevs == sorted(sevs, reverse=True)

    def test_report_html_contains_findings_section(self, populated, tmp_path):
        from forensiq.core.analyzer import generate_analysis_report
        out = generate_analysis_report(
            populated.cid, populated.db, populated.ev_dir, str(tmp_path)
        )
        html = open(out["html"]).read()
        assert "Analysis Findings" in html
        assert "Evidence Reference" in html
