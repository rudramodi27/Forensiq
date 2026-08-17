"""
Unit & Integration tests — forensiq.core.analyzer

Covers: classify_app (exact + substring matching), extract_file_metadata,
analyze_apps, build_file_timeline, build_unified_timeline (Phase 7: all 8
categories — case, file_system, evidence, device_acquisition, analysis,
verification, audit, custody), persist_unified_timeline (duplicate
prevention), detect_duplicates, correlate_artifacts (audit_evidence_links
populated), keyword_search_files (cap), keyword_search_global (all 5
filters), generate_analysis_report (JSON schema + HTML + timeline
categories).
"""

import json
import os

import pytest

from forensiq.core.analyzer import (
    SUSPICIOUS_SUBSTRINGS,
    AnalysisWorker,
    classify_app,
    correlate_artifacts,
    detect_duplicates,
    extract_file_metadata,
    analyze_apps,
    build_file_timeline,
    build_unified_timeline,
    persist_unified_timeline,
    generate_analysis_report,
    keyword_search_files,
    keyword_search_global,
    _human_size,
)


# ── classify_app ──────────────────────────────────────────────────────────────

class TestClassifyApp:
    def test_exact_suspicious_match(self):
        assert classify_app("com.termux", "unknown") == "suspicious"

    def test_exact_magisk_match(self):
        assert classify_app("com.topjohnwu.magisk", "unknown") == "suspicious"

    def test_substring_magisk_variant(self):
        """Phase 3 fix: variant package names caught by substring."""
        assert classify_app("com.magisk", "unknown") == "suspicious"

    def test_substring_supersu_variant(self):
        assert classify_app("com.example.supersu.helper", "unknown") == "suspicious"

    def test_all_suspicious_substrings_defined(self):
        """Every entry in SUSPICIOUS_SUBSTRINGS must actually trigger suspicious."""
        for sub in SUSPICIOUS_SUBSTRINGS:
            result = classify_app(f"com.test.{sub}", "unknown")
            assert result == "suspicious", \
                f"substring '{sub}' should trigger suspicious, got '{result}'"

    def test_benign_google_prefix(self):
        assert classify_app("com.google.android.gms", "system") == "clean"

    def test_benign_android_prefix(self):
        assert classify_app("com.android.phone", "system") == "clean"

    def test_unknown_with_clean_installer(self):
        result = classify_app("com.example.app", "com.android.vending")
        assert result in ("unknown", "clean")  # unknown installer triggers review

    def test_sideloaded_empty_installer(self):
        result = classify_app("com.sideloaded.tool", "")
        assert result == "review"

    def test_empty_package(self):
        """Empty package name must not crash."""
        result = classify_app("", "")
        assert result in ("suspicious", "review", "unknown", "clean")


# ── extract_file_metadata ─────────────────────────────────────────────────────

class TestExtractFileMetadata:
    def test_all_required_fields_present(self, ev_dir):
        path = os.path.join(ev_dir, "report.txt")
        m = extract_file_metadata(path)
        for field in ("filename", "extension", "mime_type", "size_bytes",
                      "size_human", "created", "modified", "sha256", "original_path"):
            assert field in m, f"missing field: {field}"

    def test_correct_filename(self, ev_dir):
        m = extract_file_metadata(os.path.join(ev_dir, "report.txt"))
        assert m["filename"] == "report.txt"
        assert m["extension"] == ".txt"

    def test_sha256_is_64_hex_chars(self, ev_dir):
        m = extract_file_metadata(os.path.join(ev_dir, "report.txt"))
        assert len(m["sha256"]) == 64
        assert all(c in "0123456789abcdef" for c in m["sha256"])

    def test_size_bytes_correct(self, ev_dir):
        content = b"Suspect device forensic evidence keyword data"
        m = extract_file_metadata(os.path.join(ev_dir, "report.txt"))
        assert m["size_bytes"] == len(content)

    def test_original_path_is_absolute(self, ev_dir):
        path = os.path.join(ev_dir, "report.txt")
        m = extract_file_metadata(path)
        assert os.path.isabs(m["original_path"])

    def test_mime_type_not_empty(self, ev_dir):
        m = extract_file_metadata(os.path.join(ev_dir, "report.txt"))
        assert m["mime_type"] and "/" in m["mime_type"]

    def test_missing_file_returns_error_key(self):
        m = extract_file_metadata("/no/such/file/ghost.bin")
        assert "error" in m

    def test_apk_has_expected_extension(self, ev_dir):
        m = extract_file_metadata(os.path.join(ev_dir, "malware.apk"))
        assert m["extension"] == ".apk"


# ── analyze_apps ──────────────────────────────────────────────────────────────

class TestAnalyzeApps:
    def test_total_count(self, ev_dir):
        apps = analyze_apps(os.path.join(ev_dir, "installed_apps.json"))
        assert apps["total"] == 6

    def test_suspicious_count(self, ev_dir):
        apps = analyze_apps(os.path.join(ev_dir, "installed_apps.json"))
        assert apps["summary"]["suspicious"] >= 2  # termux + magisk variant

    def test_system_apps_identified(self, ev_dir):
        apps = analyze_apps(os.path.join(ev_dir, "installed_apps.json"))
        assert apps["inventory"]["system"] >= 2  # com.android.*

    def test_disabled_apps_identified(self, ev_dir):
        apps = analyze_apps(os.path.join(ev_dir, "installed_apps.json"))
        assert apps["inventory"]["disabled"] >= 1

    def test_all_apps_have_required_keys(self, ev_dir):
        apps = analyze_apps(os.path.join(ev_dir, "installed_apps.json"))
        for app in apps["apps"]:
            assert "app_type" in app
            assert "status" in app
            assert "recently_installed" in app
            assert "package" in app

    def test_flat_structure_no_nested_apps(self, ev_dir):
        """Result must be flat dict — no apps['apps']['apps'] nesting."""
        apps = analyze_apps(os.path.join(ev_dir, "installed_apps.json"))
        assert isinstance(apps["apps"], list)
        assert "apps" not in apps.get("apps", {})

    def test_missing_file_returns_error(self):
        result = analyze_apps("/no/such/installed_apps.json")
        assert result["total"] == 0
        assert "error" in result


# ── build_file_timeline ───────────────────────────────────────────────────────

class TestBuildFileTimeline:
    def test_returns_list(self, ev_dir):
        tl = build_file_timeline(ev_dir)
        assert isinstance(tl, list)

    def test_sorted_by_timestamp(self, ev_dir):
        tl = build_file_timeline(ev_dir)
        timestamps = [ev["timestamp"] for ev in tl]
        assert timestamps == sorted(timestamps)

    def test_at_least_one_event_per_file(self, ev_dir):
        import os
        file_count = sum(1 for f in os.listdir(ev_dir)
                         if os.path.isfile(os.path.join(ev_dir, f)))
        tl = build_file_timeline(ev_dir)
        assert len(tl) >= file_count

    def test_no_duplicate_events(self, ev_dir):
        tl = build_file_timeline(ev_dir)
        keys = [(e["source"], e["timestamp"], e["event_type"]) for e in tl]
        assert len(keys) == len(set(keys))

    def test_event_has_required_fields(self, ev_dir):
        tl = build_file_timeline(ev_dir)
        assert tl  # non-empty
        for ev in tl:
            for field in ("timestamp", "event_type", "description", "source"):
                assert field in ev

    def test_file_created_events_present(self, ev_dir):
        tl = build_file_timeline(ev_dir)
        event_types = {ev["event_type"] for ev in tl}
        assert "file_created" in event_types


# ── build_unified_timeline ────────────────────────────────────────────────────

class TestBuildUnifiedTimeline:
    # Phase 7 — Unified Forensic Timeline: expanded from 5 to 8 categories.
    # "acquisition" (evidence-acquired events) was split into "evidence"
    # (evidence items acquired) and "device_acquisition" (device
    # registration + acquisition session start/end), and "case" (case
    # created/updated) and "analysis" (analysis_results runs) were added.
    REQUIRED_CATS = {"case", "file_system", "evidence", "device_acquisition",
                      "analysis", "audit", "custody", "verification"}

    def test_all_required_categories_present(self, populated):
        utf = build_unified_timeline(
            populated.ev_dir, populated.db, populated.cid
        )
        cats = {ev["category"] for ev in utf}
        missing = self.REQUIRED_CATS - cats
        assert not missing, f"Missing timeline categories: {missing}"

    def test_all_events_have_required_fields(self, populated):
        utf = build_unified_timeline(
            populated.ev_dir, populated.db, populated.cid
        )
        for ev in utf:
            for field in ("timestamp", "event_type", "description", "category",
                          "case_id", "evidence_id", "device_id", "session_id",
                          "actor", "source"):
                assert field in ev, f"Missing {field} in event: {ev}"

    def test_sorted_by_timestamp(self, populated):
        utf = build_unified_timeline(
            populated.ev_dir, populated.db, populated.cid
        )
        ts = [ev["timestamp"] for ev in utf]
        assert ts == sorted(ts)

    def test_case_id_set_on_every_event(self, populated):
        utf = build_unified_timeline(
            populated.ev_dir, populated.db, populated.cid
        )
        assert utf
        assert all(ev["case_id"] == populated.cid for ev in utf)

    def test_evidence_events_link_evidence_id(self, populated):
        """Evidence category events must carry the real evidence_id so
        the timeline can be filtered/joined by evidence item."""
        utf = build_unified_timeline(
            populated.ev_dir, populated.db, populated.cid
        )
        ev_events = [ev for ev in utf if ev["category"] == "evidence"]
        assert ev_events
        assert all(ev["evidence_id"] for ev in ev_events)

    def test_device_acquisition_events_link_device_id(self, populated):
        utf = build_unified_timeline(
            populated.ev_dir, populated.db, populated.cid
        )
        dev_events = [ev for ev in utf if ev["category"] == "device_acquisition"]
        assert dev_events
        assert all(ev["device_id"] for ev in dev_events)

    def test_no_events_fabricated_beyond_source_data(self, populated):
        """Every timestamp in the unified timeline must trace back to a
        real stored timestamp — nothing invented. Spot-check the case
        category against the case's own created_at."""
        utf = build_unified_timeline(
            populated.ev_dir, populated.db, populated.cid
        )
        case_events = [ev for ev in utf if ev["category"] == "case"]
        case_row = populated.db.get_case(populated.cid)
        assert case_events
        assert case_events[0]["timestamp"] == case_row["created_at"]


# ── persist_unified_timeline ────────────────────────────────────────────────

class TestPersistUnifiedTimeline:
    def test_persists_new_events(self, populated):
        utf = build_unified_timeline(populated.ev_dir, populated.db, populated.cid)
        inserted = persist_unified_timeline(populated.db, populated.cid, utf)
        assert inserted > 0
        rows = populated.db.get_timeline(populated.cid)
        assert len(rows) >= inserted

    def test_rerun_does_not_duplicate(self, populated):
        """Running the same analysis/persist cycle twice over unchanged
        source data must not grow the timeline_events table."""
        utf = build_unified_timeline(populated.ev_dir, populated.db, populated.cid)
        persist_unified_timeline(populated.db, populated.cid, utf)
        count_after_first = len(populated.db.get_timeline(populated.cid))

        utf2 = build_unified_timeline(populated.ev_dir, populated.db, populated.cid)
        inserted_second = persist_unified_timeline(populated.db, populated.cid, utf2)
        count_after_second = len(populated.db.get_timeline(populated.cid))

        assert inserted_second == 0
        assert count_after_second == count_after_first

    def test_persisted_rows_carry_category_and_actor(self, populated):
        utf = build_unified_timeline(populated.ev_dir, populated.db, populated.cid)
        persist_unified_timeline(populated.db, populated.cid, utf)
        rows = populated.db.get_timeline(populated.cid)
        cats = {r["category"] for r in rows}
        assert "case" in cats
        assert "evidence" in cats
        assert any(r["actor"] for r in rows)

    def test_persisted_rows_expose_evidence_and_device_joins(self, populated):
        utf = build_unified_timeline(populated.ev_dir, populated.db, populated.cid)
        persist_unified_timeline(populated.db, populated.cid, utf)
        rows = populated.db.get_timeline(populated.cid, category="evidence")
        assert rows
        assert any(r["evidence_filename"] for r in rows)


# ── detect_duplicates ─────────────────────────────────────────────────────────

class TestDetectDuplicates:
    def test_finds_exact_duplicate(self, ev_dir, populated):
        dups = detect_duplicates(ev_dir, populated.db, populated.cid)
        assert dups["duplicate_groups"] >= 1

    def test_duplicate_count_is_redundant_files(self, ev_dir, populated):
        dups = detect_duplicates(ev_dir, populated.db, populated.cid)
        assert dups["duplicate_count"] >= 1

    def test_total_files_count(self, ev_dir, populated):
        import os
        file_count = sum(1 for f in os.listdir(ev_dir)
                         if os.path.isfile(os.path.join(ev_dir, f)))
        dups = detect_duplicates(ev_dir, populated.db, populated.cid)
        assert dups["total_files"] >= file_count

    def test_group_structure(self, ev_dir, populated):
        dups = detect_duplicates(ev_dir, populated.db, populated.cid)
        for grp in dups["duplicates"]:
            assert "sha256" in grp and len(grp["sha256"]) == 64
            assert "count" in grp and grp["count"] >= 2
            assert "files" in grp and isinstance(grp["files"], list)
            assert "size" in grp

    def test_no_duplicates_in_unique_dir(self, tmp_path, db):
        cid = db.create_case("X", "X", "I", "")
        for i in range(3):
            (tmp_path / f"unique_{i}.txt").write_bytes(f"unique content {i}".encode())
        dups = detect_duplicates(str(tmp_path), db, cid)
        assert dups["duplicate_groups"] == 0


# ── correlate_artifacts ───────────────────────────────────────────────────────

class TestCorrelateArtifacts:
    def test_required_keys_present(self, populated):
        corr = correlate_artifacts(populated.ev_dir, populated.db, populated.cid)
        for key in ("high_risk_files", "file_app_matches", "verified_evidence",
                    "unverified_evidence", "custody_chain", "audit_evidence_links"):
            assert key in corr, f"Missing correlation key: {key}"

    def test_high_risk_detects_apk(self, populated):
        """malware.apk is in evidence → must appear in high_risk_files."""
        corr = correlate_artifacts(populated.ev_dir, populated.db, populated.cid)
        hrisk = [x["filename"] for x in corr["high_risk_files"]]
        assert "malware.apk" in hrisk

    def test_verified_evidence_correct(self, populated):
        corr = correlate_artifacts(populated.ev_dir, populated.db, populated.cid)
        v_ids = [x["evidence_id"] for x in corr["verified_evidence"]]
        assert populated.eid_pass in v_ids

    def test_unverified_evidence_excludes_verified(self, populated):
        corr = correlate_artifacts(populated.ev_dir, populated.db, populated.cid)
        uv_ids = [x["evidence_id"] for x in corr["unverified_evidence"]]
        assert populated.eid_pass not in uv_ids

    def test_audit_evidence_links_populated(self, populated):
        """Phase 2 fix: audit_evidence_links was always empty before the fix."""
        corr = correlate_artifacts(populated.ev_dir, populated.db, populated.cid)
        links = corr["audit_evidence_links"]
        assert len(links) >= 1, "audit_evidence_links should be populated"
        ev_ids_linked = {x["evidence_id"] for x in links}
        assert populated.eid_pass in ev_ids_linked

    def test_audit_link_has_action_and_count(self, populated):
        corr = correlate_artifacts(populated.ev_dir, populated.db, populated.cid)
        for link in corr["audit_evidence_links"]:
            assert "audit_count" in link and link["audit_count"] >= 1
            assert "actions" in link and len(link["actions"]) > 0
            assert "filename" in link


# ── keyword_search_files ──────────────────────────────────────────────────────

class TestKeywordSearchFiles:
    def test_finds_keyword(self, ev_dir):
        results = keyword_search_files(ev_dir, "suspect")
        assert len(results) >= 1

    def test_result_contains_keyword(self, ev_dir):
        results = keyword_search_files(ev_dir, "suspect")
        for r in results:
            assert "suspect" in r["match"].lower()

    def test_result_has_required_keys(self, ev_dir):
        results = keyword_search_files(ev_dir, "evidence")
        assert results
        for r in results:
            for k in ("file", "path", "line", "match"):
                assert k in r

    def test_500_result_cap(self, tmp_path):
        """Safety cap: never return more than 500 results."""
        f = tmp_path / "big.txt"
        f.write_bytes(b"needle\n" * 600)
        results = keyword_search_files(str(tmp_path), "needle")
        assert len(results) == 500

    def test_no_results_for_absent_keyword(self, ev_dir):
        results = keyword_search_files(ev_dir, "ZZZZNOTPRESENT_XYZ_9999")
        assert results == []

    def test_case_insensitive(self, ev_dir):
        lower = keyword_search_files(ev_dir, "suspect")
        upper = keyword_search_files(ev_dir, "SUSPECT")
        assert len(lower) == len(upper)


# ── keyword_search_global ─────────────────────────────────────────────────────

class TestKeywordSearchGlobal:
    def test_basic_search_returns_results(self, populated):
        res = keyword_search_global("jones", populated.db, populated.cid)
        assert len(res) >= 1

    def test_finds_evidence_source(self, populated):
        res = keyword_search_global("report.txt", populated.db, populated.cid)
        assert any(r["source"] == "evidence" for r in res)

    def test_verification_status_pass_filter(self, populated):
        """Only eid_pass has PASS — filter must exclude eid_fail evidence."""
        res = keyword_search_global(
            "acquisition", populated.db, populated.cid,
            {"verification_status": "pass"}
        )
        ev_res = [r for r in res if r["source"] == "evidence"]
        assert all(r["id"] == populated.eid_pass for r in ev_res)

    def test_verification_status_fail_filter(self, populated):
        res = keyword_search_global(
            "malware", populated.db, populated.cid,
            {"verification_status": "fail"}
        )
        ev_res = [r for r in res if r["source"] == "evidence"]
        assert all(r["id"] == populated.eid_fail for r in ev_res)

    def test_file_type_filter_apk(self, populated):
        """Phase 2 fix: file_type filter was documented but never implemented."""
        res = keyword_search_global(
            "acquisition", populated.db, populated.cid,
            {"file_type": "apk"}
        )
        ev_res = [r for r in res if r["source"] == "evidence"]
        assert all(r["id"] == populated.eid_fail for r in ev_res)

    def test_file_type_filter_with_dot_prefix(self, populated):
        """file_type='.txt' and 'txt' must both work."""
        res_dot = keyword_search_global(
            "acquisition", populated.db, populated.cid, {"file_type": ".txt"}
        )
        res_plain = keyword_search_global(
            "acquisition", populated.db, populated.cid, {"file_type": "txt"}
        )
        assert len(res_dot) == len(res_plain)

    def test_date_from_filter(self, populated):
        res = keyword_search_global(
            "jones", populated.db, populated.cid,
            {"date_from": "2020-01-01"}
        )
        assert len(res) >= 0  # must not crash

    def test_investigator_filter(self, populated):
        res = keyword_search_global(
            "jones", populated.db, populated.cid,
            {"investigator": "Jones"}
        )
        assert len(res) >= 1

    def test_combined_filters(self, populated):
        """Multiple filters applied simultaneously."""
        res = keyword_search_global(
            "acquisition", populated.db, populated.cid,
            {"file_type": "apk", "verification_status": "fail"}
        )
        ev_res = [r for r in res if r["source"] == "evidence"]
        assert all(r["id"] == populated.eid_fail for r in ev_res)

    def test_evidence_type_filter(self, populated):
        res = keyword_search_global(
            "report", populated.db, populated.cid,
            {"evidence_type": "acquisition"}
        )
        for r in res:
            if r["source"] == "evidence":
                assert r["type"] == "acquisition"


# ── generate_analysis_report ──────────────────────────────────────────────────

class TestGenerateAnalysisReport:
    REQUIRED_TOP_KEYS = (
        "report_type", "generated_at", "case", "summary",
        "timeline", "file_metadata", "applications", "duplicates", "correlations",
    )
    REQUIRED_TL_CATS = {"case", "file_system", "evidence", "device_acquisition",
                         "analysis", "audit", "custody", "verification"}

    def test_creates_json_and_html(self, populated, tmp_path):
        out = generate_analysis_report(
            populated.cid, populated.db, populated.ev_dir, str(tmp_path)
        )
        assert os.path.exists(out["json"])
        assert os.path.exists(out["html"])

    def test_json_has_required_keys(self, populated, tmp_path):
        out = generate_analysis_report(
            populated.cid, populated.db, populated.ev_dir, str(tmp_path)
        )
        rpt = json.loads(open(out["json"]).read())
        for key in self.REQUIRED_TOP_KEYS:
            assert key in rpt, f"missing JSON key: {key}"

    def test_report_type_string(self, populated, tmp_path):
        out = generate_analysis_report(
            populated.cid, populated.db, populated.ev_dir, str(tmp_path)
        )
        rpt = json.loads(open(out["json"]).read())
        assert rpt["report_type"] == "ForensIQ Advanced Analysis Report"

    def test_correct_case_in_report(self, populated, tmp_path):
        out = generate_analysis_report(
            populated.cid, populated.db, populated.ev_dir, str(tmp_path)
        )
        rpt = json.loads(open(out["json"]).read())
        assert rpt["case"]["case_number"] == "TC-001"

    def test_timeline_has_all_categories(self, populated, tmp_path):
        out = generate_analysis_report(
            populated.cid, populated.db, populated.ev_dir, str(tmp_path)
        )
        rpt = json.loads(open(out["json"]).read())
        cats = {ev.get("category") for ev in rpt["timeline"]}
        missing = self.REQUIRED_TL_CATS - cats
        assert not missing, f"Report timeline missing categories: {missing}"

    def test_audit_evidence_links_in_report(self, populated, tmp_path):
        """Phase 2: audit_evidence_links must appear in report correlations."""
        out = generate_analysis_report(
            populated.cid, populated.db, populated.ev_dir, str(tmp_path)
        )
        rpt = json.loads(open(out["json"]).read())
        assert "audit_evidence_links" in rpt["correlations"]
        assert len(rpt["correlations"]["audit_evidence_links"]) >= 1

    def test_html_contains_case_number(self, populated, tmp_path):
        out = generate_analysis_report(
            populated.cid, populated.db, populated.ev_dir, str(tmp_path)
        )
        html = open(out["html"]).read()
        assert "TC-001" in html
        assert "ForensIQ" in html
        assert "<table" in html

    def test_duplicate_detection_in_report(self, populated, tmp_path):
        out = generate_analysis_report(
            populated.cid, populated.db, populated.ev_dir, str(tmp_path)
        )
        rpt = json.loads(open(out["json"]).read())
        assert rpt["duplicates"]["duplicate_groups"] >= 1


# ── _human_size ───────────────────────────────────────────────────────────────

class TestHumanSize:
    def test_zero(self):       assert _human_size(0)       == "0.0 B"
    def test_bytes(self):      assert _human_size(1023)    == "1023.0 B"
    def test_kilobytes(self):  assert _human_size(1024)    == "1.0 KB"
    def test_megabytes(self):  assert _human_size(1024**2) == "1.0 MB"
    def test_gigabytes(self):  assert _human_size(1024**3) == "1.0 GB"
