"""
Reporter — PDF and HTML report generation.

FIXES:
  - BUG#1: {e['file_size']:,} crashed on NULL file_size — now uses (e['file_size'] or 0)
  - BUG#2: ReportLab Table colWidths used % strings (unsupported) — now uses cm units
  - BUG#3: evidence/analysis result sets iterated twice — now materialized to lists first
  - BUG#4: HTML injection risk in case fields — values are now escaped
  - BUG#5: PDF table cells held raw strings — long unbroken values (SHA-256 hashes,
           deep Android filepaths, long filenames) do not wrap on whitespace and
           overflow the column by up to 700%, corrupting the page layout. Table
           cells likely to contain long unbroken text now use Paragraph with
           wordWrap='CJK', which breaks on any character boundary and correctly
           respects the column width.
  - Added: SHA-256 verification section in both HTML and PDF reports

Phase 9 — Report Generator 2.0:
  The main forensic report (generate_html_report / generate_pdf_report) is
  restructured into a single, consistently-ordered "Full Forensic
  Investigation Report" with 14 numbered sections (Case Information ...
  Final Conclusion — see _SECTION_TITLES below). This is a presentation
  and organisation upgrade only: every figure shown is read from the same
  CaseManager / manifest_service / SignatureService calls prior phases
  already used (or, for the two genuinely new sections — Investigator/
  Reviewer Information and Digital Signature Information — from the
  existing `cases.reviewer` column added in Phase 8 and the existing
  `signatures` table added in Phase 5). No forensic data is invented,
  recomputed differently, or changed to make the report "look" better.
  HTML and PDF share the same section-data helpers (_section_*) so the
  two renderers never independently duplicate how a section's content is
  derived from the database — only how it is laid out on the page.
"""

import json
import os
import html as html_lib
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from forensiq.core.case_manager import CaseManager
from forensiq.core.manifest_service import build_manifest
from forensiq.core.signature_service import SignatureService, ARTIFACT_REPORT
from forensiq.core.time_utils import (
    now_utc_str,
    format_dual_html,
    format_dual_pdf,
    format_dual_plain,
    DEFAULT_SECONDARY_TZ,
)


def _esc(value) -> str:
    """HTML-escape a value for safe insertion into report markup."""
    return html_lib.escape(str(value or ""))


# ── Phase 9 — Full Forensic Investigation Report: shared section metadata ──
# Single source of truth for section numbering/titles so the HTML and PDF
# renderers (and their headers/footers/TOC) never drift out of sync.
_SECTION_TITLES = [
    "Case Information",
    "Investigator / Reviewer Information",
    "Device Information",
    "Acquisition Summary",
    "Evidence Inventory / Manifest",
    "Evidence Integrity",
    "Chain of Custody",
    "Analysis Methodology",
    "Analysis Findings",
    "Unified Forensic Timeline",
    "Investigator Notes",
    "Integrity Verification",
    "Digital Signature Information",
    "Final Conclusion",
]
_SEC = {title: i + 1 for i, title in enumerate(_SECTION_TITLES)}


def _sh(title: str) -> str:
    """'N. Section Title' heading text for a Phase 9 report section."""
    return f"{_SEC[title]}. {title}"


# Short, factual descriptions of each analysis engine method — used only
# to describe methodology for analysis types that actually appear in this
# case's analysis_results (never listed for a method that was not run).
_ANALYSIS_METHOD_DESCRIPTIONS = {
    "network":               "Parsed acquired network configuration/interface data "
                              "(IP addressing, Wi-Fi state) for indicators of network activity.",
    "battery":                "Parsed acquired battery/system telemetry for the device's "
                              "power and hardware state at acquisition time.",
    "hash_integrity":         "Recomputed SHA-256 over acquired evidence files and compared "
                              "against the recorded acquisition-time hash.",
    "suspicious_artifacts":   "Scanned acquired file listings/paths against known "
                              "suspicious-artifact and high-risk-extension patterns.",
    "ioc_search":              "Searched acquired evidence content for user-supplied "
                              "indicators of compromise (IOCs).",
    "duplicate_detection":    "Compared SHA-256 hashes across acquired evidence items to "
                              "identify exact duplicates.",
    "app_classification":     "Classified installed-application listings by installer "
                              "origin and known suspicious/sideloaded package signatures.",
}


def _analysis_methodology_entries(an_list) -> list[dict]:
    """
    Build the Analysis Methodology section's content: one entry per
    distinct analysis_type actually present in this case's
    analysis_results, each with a real count of how many results of
    that type were recorded. An unknown/legacy analysis_type still gets
    an entry (with a generic description) rather than being silently
    dropped — methodology must account for everything that was run.
    """
    counts: dict = {}
    for a in an_list:
        t = a["analysis_type"] or "unknown"
        counts[t] = counts.get(t, 0) + 1
    entries = []
    for t in sorted(counts):
        entries.append({
            "type": t,
            "count": counts[t],
            "description": _ANALYSIS_METHOD_DESCRIPTIONS.get(
                t, "Recorded analysis result — see Analysis Findings for detail."
            ),
        })
    return entries


def _acquisition_summary(dev_list, db: CaseManager) -> dict:
    """
    Case-wide acquisition rollup: total devices, total acquisition
    sessions across those devices, session status breakdown, and the
    earliest/latest session start time on record. Built entirely from
    CaseManager.get_sessions_for_device() (Phase 3) — no new data source.
    """
    sessions = []
    for d in dev_list:
        sessions.extend(list(db.get_sessions_for_device(d["id"])))
    status_counts: dict = {}
    for s in sessions:
        st = s["status"] or "unknown"
        status_counts[st] = status_counts.get(st, 0) + 1
    starts = sorted(s["start_time"] for s in sessions if s["start_time"])
    return {
        "device_count":    len(dev_list),
        "session_count":   len(sessions),
        "status_counts":   status_counts,
        "earliest_start":  starts[0] if starts else "",
        "latest_start":    starts[-1] if starts else "",
    }


def _report_signature_info(case_id: Optional[int], db: CaseManager) -> Optional[dict]:
    """
    Most recent REPORT-artifact signature recorded for this case, if any.
    A report is signed as a separate step after it is generated/exported
    (see SignaturePanel — "Sign Report" operates on whatever file the
    Reports panel already produced), so a report being generated right
    now naturally has no signature of itself yet; this surfaces the
    latest signature already on record for a previous export of this
    case's report, re-verified live via SignatureService if that signed
    file still exists on disk. Returns None gracefully if this case has
    never had a report signed — never fabricates a signature.
    """
    if case_id is None:
        return None
    try:
        rows = [r for r in db.get_signatures_for_case(case_id)
                if r["artifact_type"] == ARTIFACT_REPORT]
    except Exception:
        return None
    if not rows:
        return None
    rec = dict(rows[0])
    result = dict(rec)
    result["live_status"] = None
    result["live_notes"] = ""
    try:
        verifier = SignatureService(db)
        live = verifier.verify_artifact(rec["artifact_path"], case_id=case_id)
        result["live_status"] = live["status"]
        result["live_notes"] = live["notes"]
    except Exception:
        pass
    return result


def _final_conclusion_text(case, dev_list, ev_list, an_list, tl_list,
                            integrity_summary: dict, sig_info: Optional[dict]) -> str:
    """
    Build a short, entirely factual closing summary from figures already
    computed elsewhere in the report (device/evidence/analysis/timeline
    counts, the case-level integrity rollup, and signature status if
    any). This is a restatement of report contents, not an investigative
    determination — no severity judgement, culpability, or finding beyond
    what the case record already states is written here.
    """
    parts = []
    parts.append(
        f"This report documents the examination of case {case['case_number']} "
        f"({case['title']}), covering {len(dev_list)} device(s) and "
        f"{len(ev_list)} evidence item(s) acquired across "
        f"{sum(integrity_summary.get(k, 0) for k in ('MATCH','MISMATCH','MISSING','CORRUPTED','NOT_VERIFIED')) or len(ev_list)} "
        f"tracked item(s), with {len(an_list)} analysis result(s) and "
        f"{len(tl_list)} timeline event(s) recorded."
    )
    overall = integrity_summary.get("overall_status", "NOT_VERIFIED")
    if overall == "VERIFIED":
        parts.append("All evidence items with a recorded verification passed integrity checking.")
    elif overall == "COMPROMISED":
        parts.append(
            "One or more evidence items failed integrity verification "
            "(hash mismatch or corruption) — see Evidence Integrity and "
            "Integrity Verification above for the affected item(s)."
        )
    elif overall == "INCOMPLETE":
        parts.append(
            "One or more evidence items are missing from their recorded "
            "storage location and could not be re-verified."
        )
    else:
        parts.append("Evidence integrity has not yet been fully verified for this case.")
    if sig_info:
        status = sig_info.get("live_status") or "recorded, not re-verified"
        signed_at_raw = sig_info.get("signed_at")
        signed_at_display = format_dual_plain(signed_at_raw, sep=" / ") if signed_at_raw else "an unrecorded date"
        parts.append(
            f"The most recent signed report artifact for this case was signed by "
            f"{sig_info.get('signer') or 'an unrecorded signer'} on "
            f"{signed_at_display} "
            f"(status: {status})."
        )
    else:
        parts.append("No prior report artifact for this case has been digitally signed.")
    status_str = str(case["status"] or "").upper()
    if status_str == "CLOSED" and str(case["closure_reason"] or "").strip():
        parts.append(f"Case closure reason on record: {case['closure_reason']}.")
    parts.append(
        "This document reflects the state of the case record at the time of "
        "generation and does not itself constitute a final legal determination."
    )
    return " ".join(parts)


_SEVERITY_COLORS = {
    "critical": "#F85149", "high": "#F0883E", "medium": "#E3B341",
    "low": "#A5D6FF", "info": "#8B949E",
}


def _analysis_severity_and_ref(row) -> tuple[str, str]:
    """
    Derive (severity, evidence_ref) for an analysis_results row without
    duplicating analyzer logic. Phase 6 analysis types (network,
    battery, hash_integrity, suspicious_artifacts, ioc_search) store a
    standard findings[] list (analyzer.make_finding()) in result_data —
    this reads the highest severity present and a representative evidence
    reference. Older/other analysis types have no severity data, so they
    fall back to 'info' with no reference, same as before this field existed.
    """
    try:
        data = json.loads(row["result_data"] or "{}")
    except (ValueError, TypeError):
        return "info", ""
    findings = data.get("findings") if isinstance(data, dict) else None
    if not findings:
        return "info", ""
    order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    top = max(findings, key=lambda f: order.get(f.get("severity", "info"), 0))
    ref = top.get("evidence_ref", "")
    if len(findings) > 1:
        ref = f"{ref} (+{len(findings)-1} more)" if ref else f"{len(findings)} references"
    return top.get("severity", "info"), ref


# ── HTML Report ────────────────────────────────────────────────────────────────

def generate_html_report(case_id: int, db: CaseManager, output_path: str) -> str:
    case     = db.get_case(case_id)
    devices  = db.get_devices_for_case(case_id)
    evidence = db.get_evidence_for_case(case_id)   # list
    analysis = db.get_analysis_results(case_id)    # list
    timeline = db.get_timeline(case_id)             # list

    if not case:
        raise ValueError(f"Case {case_id} not found in database")

    # Materialise once — prevents double-iteration bugs
    ev_list  = list(evidence)
    an_list  = list(analysis)
    tl_list  = list(timeline)
    dev_list = list(devices)

    # Phase 3 — one physical device is shown ONCE, with its acquisition
    # sessions nested underneath it (Device → Session 1, Session 2, …)
    # rather than the device repeating once per acquisition run.
    def _session_status_badge(status: str) -> str:
        cls = {"completed": "ok", "in_progress": "warn",
               "aborted": "warn", "error": "err"}.get(status, "warn")
        return f'<span class="{cls}">{_esc(status)}</span>'

    dev_blocks = []
    for d in dev_list:
        sessions = list(db.get_sessions_for_device(d["id"]))
        if sessions:
            sess_rows = "\n".join(
                f"""<tr>
                      <td>Session {s['id']}</td>
                      <td class="mono">{format_dual_html(s['start_time'])}</td>
                      <td class="mono">{format_dual_html(s['end_time']) if s['end_time'] else '—'}</td>
                      <td>{_session_status_badge(s['status'])}</td>
                      <td>{_esc(', '.join(json.loads(s['targets'] or '[]')))}</td>
                      <td>{len(db.get_evidence_for_session(s['id']))}</td>
                    </tr>"""
                for s in sessions
            )
        else:
            sess_rows = ('<tr><td colspan="6" style="color:#8b949e">'
                         'No acquisition sessions recorded for this device.</td></tr>')
        dev_blocks.append(f"""<div class="device-block">
<table><thead><tr><th>Serial</th><th>Device</th><th>Android / SDK</th><th>USB Debug</th><th>First Connected</th><th>Last Connected</th></tr></thead>
<tbody><tr>
  <td class="mono">{_esc(d['serial'])}</td>
  <td>{_esc(d['manufacturer'])} {_esc(d['model'])}</td>
  <td>Android {_esc(d['android_version'])} (SDK {_esc(d['sdk_version'])})</td>
  <td>{'<span class="ok">✔ Yes</span>' if d['usb_debugging'] else '<span class="err">✘ No</span>'}</td>
  <td>{format_dual_html(d['first_connected'] or d['acquired_at'])}</td>
  <td>{format_dual_html(d['last_connected'] or d['acquired_at'])}</td>
</tr></tbody></table>
<div class="session-tree">
  <div class="session-tree-label">└─ Acquisition Sessions ({len(sessions)})</div>
  <table><thead><tr><th>Session</th><th>Start</th><th>End</th><th>Status</th><th>Targets</th><th>Evidence</th></tr></thead>
  <tbody>{sess_rows}</tbody></table>
</div>
</div>""")

    dev_rows = "\n".join(dev_blocks)

    acq_summary = _acquisition_summary(dev_list, db)
    acq_status_rows = "\n".join(
        f"<tr><td>{_esc(status)}</td><td>{count}</td></tr>"
        for status, count in sorted(acq_summary["status_counts"].items())
    ) or "<tr><td colspan='2' style='color:#8b949e'>No acquisition sessions recorded.</td></tr>"

    # ── Section 5 — Evidence Inventory / Manifest ───────────────────────
    # Reuses manifest_service.build_manifest() (Phase 4) as the single
    # evidence table — Case -> Device -> Session -> Evidence resolved in
    # one place, rather than a second, separately-computed inventory
    # table duplicating the same evidence rows.
    manifest = build_manifest(case_id, db)
    m_items  = manifest["items"]

    MANIFEST_STATUS_COLORS = {
        "MATCH": "#3fb950", "MISMATCH": "#f85149", "MISSING": "#e3b341",
        "CORRUPTED": "#f85149", "NOT_VERIFIED": "#8b949e", "ERROR": "#8b949e",
    }
    man_rows = "\n".join(
        f"""<tr>
          <td>{_esc(it['evidence_id'])}</td>
          <td>{_esc(it['filename'] or '—')}</td>
          <td>{_esc(it['category'] or '—')}</td>
          <td class="mono">{_esc((it['recorded_sha256'] or '')[:40])}{'…' if it['recorded_sha256'] else '—'}</td>
          <td>{(it['file_size'] or 0):,} B</td>
          <td>{_esc(f"{it['device_model']} ({it['device_serial']})" if it['device_serial'] else '— (legacy)')}</td>
          <td>{_esc(f"#{it['session_id']}") if it['session_id'] else '— (legacy)'}</td>
          <td>{_esc(it['collector'] or '—')}{' <small style="color:#8b949e">(case-level)</small>' if it['collector_source'] == 'case_investigator' else ''}</td>
          <td><span style="color:{MANIFEST_STATUS_COLORS.get(it['integrity_status'],'#8b949e')};font-weight:600">{_esc(it['integrity_status'])}</span></td>
        </tr>"""
        for it in m_items
    )
    legacy_note = ""
    if manifest["legacy_items"]:
        legacy_note = (
            f'<p style="color:#e3b341;font-size:11.5px;margin-top:0.6rem">⚠ '
            f'{manifest["legacy_items"]} item(s) have no device/acquisition-session '
            f'on record (added before Phase 3 tracking, or imported manually) — '
            f'shown as “— (legacy)”, never invented.</p>'
        )

    def _an_row(a) -> str:
        sev, ref = _analysis_severity_and_ref(a)
        color = _SEVERITY_COLORS.get(sev, "#8B949E")
        return (
            f"<tr><td>{_esc(a['analysis_type'])}</td>"
            f"<td><span style='color:{color};font-weight:600'>{_esc(sev.upper())}</span></td>"
            f"<td>{_esc(a['result_summary'] or '—')}</td>"
            f"<td class='mono'>{format_dual_html(a['created_at'])}</td>"
            f"<td class='mono'><small>{_esc(ref)}</small></td></tr>"
        )

    an_rows = "\n".join(_an_row(a) for a in an_list)
    methodology_entries = _analysis_methodology_entries(an_list)
    methodology_rows = "\n".join(
        f"<tr><td>{_esc(e['type'])}</td><td>{e['count']}</td><td>{_esc(e['description'])}</td></tr>"
        for e in methodology_entries
    ) or "<tr><td colspan='3' style='color:#8b949e'>No analysis has been run on this case yet.</td></tr>"

    # SHA-256 verification table (Section 6 — Evidence Integrity).
    # Distinguishes the immutable Recorded SHA-256 (acquisition-time) from
    # the most recent re-verification (if any): the Verified SHA-256
    # actually recalculated at verification time, the resulting Integrity
    # Status, and when that check last ran. Evidence with no verification
    # run yet is shown as NOT VERIFIED rather than silently implying it's fine.
    last_vr_by_ev = db.get_last_verification_per_evidence(case_id)

    def _status_badge(status: str) -> str:
        cls = {"MATCH": "ok", "PASS": "ok",
               "MISMATCH": "err", "FAIL": "err", "CORRUPTED": "err",
               "MISSING": "warn", "ERROR": "warn"}.get(status, "warn")
        return f'<span class="{cls}">{_esc(status)}</span>'

    hash_rows = "\n".join(
        (lambda last: f"""<tr>
              <td>{_esc(e['filename'] or '—')}</td>
              <td class="mono ok">{_esc(e['sha256'] or 'NOT HASHED')}</td>
              <td class="mono">{_esc(last['current_hash']) if last else '—'}</td>
              <td>{_status_badge(last['result']) if last else _status_badge('NOT VERIFIED')}</td>
              <td class="mono">{format_dual_html(last['verification_time']) if last else '—'}</td>
            </tr>""")(last_vr_by_ev.get(e["id"]))
        for e in ev_list
    )

    ts_generated = now_utc_str()

    # ── Section 7 — Chain of Custody (+ Transfer History, Audit Summary) ──
    # Deliberately NOT a re-listing of the Timeline section: the Timeline
    # interleaves every event type as flat description strings; this
    # instead shows the structured custody lifecycle per evidence item,
    # a dedicated transfer table, and an aggregated audit summary —
    # information not already presented that way elsewhere.
    _action_colors2 = {
        "ACQUIRED": "#1d9e75", "STORED": "#58a6ff", "VERIFIED": "#3fb950",
        "TRANSFERRED": "#f0883e", "ANALYZED": "#bc8cff", "REPORTED": "#d2a8ff",
        "REVIEWED": "#a5d6ff", "EXPORTED": "#e3b341", "ARCHIVED": "#8b949e",
        "NOTED": "#8b949e",
    }
    _integrity_colors2 = {
        "MATCH": "#3fb950", "MISMATCH": "#f85149", "MISSING": "#e3b341",
        "CORRUPTED": "#f85149", "NOT_VERIFIED": "#8b949e", "ERROR": "#8b949e",
    }

    custody_rows = "\n".join(
        f"""<tr>
              <td>{_esc(e['filename'] or '—')}</td>
              <td style="color:{_action_colors2.get(db.get_evidence_lifecycle_status(e['id']),'#8b949e')};font-weight:600">
                {_esc(db.get_evidence_lifecycle_status(e['id']))}</td>
              <td>{len(db.get_custody_chain(e['id']))}</td>
              <td>{len(db.get_transfer_history(evidence_id=e['id']))}</td>
            </tr>"""
        for e in ev_list
    )

    transfer_events = db.get_transfer_history(case_id=case_id)
    transfer_rows = "\n".join(
        f"""<tr>
              <td class="mono">{format_dual_html(t['timestamp'])}</td>
              <td>{_esc(t['filename'] or '—')}</td>
              <td>{_esc(t['investigator'])}</td>
              <td>{_esc(t['from_location'] or '?')} → {_esc(t['to_location'] or '?')}</td>
              <td style="color:{_integrity_colors2.get(t['integrity_status'],'#8b949e')}">{_esc(t['integrity_status'] or '—')}</td>
              <td>{_esc(t['notes'])}</td>
            </tr>"""
        for t in transfer_events
    )

    audit_summary_counts: dict = {}
    try:
        target_ids = {str(case_id)} | {str(e["id"]) for e in ev_list}
        for rec in db.get_audit_trail(limit=5000):
            if str(rec["target_id"]) in target_ids:
                audit_summary_counts[rec["action"]] = audit_summary_counts.get(rec["action"], 0) + 1
    except Exception:
        pass
    audit_summary_rows = "\n".join(
        f"<tr><td>{_esc(action)}</td><td>{count}</td></tr>"
        for action, count in sorted(audit_summary_counts.items())
    ) or "<tr><td colspan='2' style='color:#8b949e'>No audit records for this case.</td></tr>"

    def _tl_device_session(t) -> str:
        parts = []
        serial = t["device_serial"] if "device_serial" in t.keys() else None
        if serial:
            parts.append(serial)
        sess_id = t["session_id"] if "session_id" in t.keys() else None
        if sess_id:
            parts.append(f"session #{sess_id}")
        return " / ".join(parts)

    tl_rows = "\n".join(
        f"<tr><td class='mono'>{format_dual_html(t['timestamp'])}</td>"
        f"<td>{_esc(t['category'] if 'category' in t.keys() else '')}</td>"
        f"<td>{_esc(t['event_type'])}</td>"
        f"<td>{_esc(t['description'])}</td>"
        f"<td>{_esc(t['evidence_filename'] if 'evidence_filename' in t.keys() else '')}</td>"
        f"<td class='mono'>{_esc(_tl_device_session(t))}</td>"
        f"<td>{_esc(t['actor'] if 'actor' in t.keys() else '')}</td></tr>"
        for t in tl_list[:100]
    )

    # ── Section 12 — Integrity Verification (case-level rollup) ─────────
    integrity_summary = db.get_case_integrity_summary(case_id)
    _OVERALL_COLORS = {
        "VERIFIED": "#3fb950", "COMPROMISED": "#f85149",
        "INCOMPLETE": "#e3b341", "NOT_VERIFIED": "#8b949e",
    }
    overall_status = integrity_summary.get("overall_status", "NOT_VERIFIED")
    integrity_rollup_rows = "\n".join(
        f"<tr><td>{_esc(k)}</td><td>{integrity_summary.get(k, 0)}</td></tr>"
        for k in ("MATCH", "MISMATCH", "MISSING", "CORRUPTED", "NOT_VERIFIED")
    )

    # ── Section 13 — Digital Signature Information ───────────────────────
    sig_info = _report_signature_info(case_id, db)
    if sig_info:
        sig_status = sig_info.get("live_status") or "RECORDED"
        _SIG_COLORS = {"VALID": "#3fb950", "INVALID": "#f85149", "MODIFIED": "#f85149",
                       "MISSING": "#e3b341", "KEY_UNAVAILABLE": "#e3b341", "RECORDED": "#8b949e"}
        sig_block = f"""<table><tbody>
<tr><td>Signer</td><td>{_esc(sig_info.get('signer') or '—')}</td></tr>
<tr><td>Algorithm</td><td class="mono">{_esc(sig_info.get('algorithm') or '—')}</td></tr>
<tr><td>Signed At</td><td class="mono">{format_dual_html(sig_info.get('signed_at'))}</td></tr>
<tr><td>Artifact SHA-256</td><td class="mono">{_esc(sig_info.get('artifact_sha256') or '—')}</td></tr>
<tr><td>Artifact File</td><td class="mono">{_esc(sig_info.get('artifact_filename') or sig_info.get('artifact_path') or '—')}</td></tr>
<tr><td>Signature Status</td><td><span style="color:{_SIG_COLORS.get(sig_status,'#8b949e')};font-weight:600">{_esc(sig_status)}</span></td></tr>
<tr><td>Notes</td><td>{_esc(sig_info.get('live_notes') or 'Recorded signature metadata shown; artifact was not re-verified.')}</td></tr>
</tbody></table>"""
    else:
        sig_block = ('<p style="color:#8b949e">No report artifact for this case has been '
                     'digitally signed yet. Reports are signed as a separate step from the '
                     'Digital Signature panel after export.</p>')

    # ── Section 14 — Final Conclusion ────────────────────────────────────
    conclusion_text = _final_conclusion_text(
        case, dev_list, ev_list, an_list, tl_list, integrity_summary, sig_info
    )

    reviewer = str(case["reviewer"] or "").strip() if "reviewer" in case.keys() else ""
    tags_raw = case["tags"] if "tags" in case.keys() else "[]"
    try:
        tags = json.loads(tags_raw or "[]")
    except (TypeError, ValueError):
        tags = []
    priority = str(case["priority"] or "MEDIUM") if "priority" in case.keys() else "MEDIUM"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ForensIQ Full Forensic Investigation Report — {_esc(case['case_number'])}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',Arial,sans-serif;background:#0d1117;color:#e6edf3;padding:2rem;font-size:13px;line-height:1.6}}
h1{{font-size:24px;color:#1d9e75;margin-bottom:6px}}
h2{{font-size:14px;color:#1d9e75;margin:2rem 0 0.6rem;padding-left:10px;border-left:3px solid #1d9e75;text-transform:uppercase;letter-spacing:.05em}}
h3{{font-size:12px;color:#c9d1d9;margin:1.2rem 0 0.5rem;padding-left:10px;border-left:2px solid #30363d;text-transform:uppercase;letter-spacing:.04em}}
.meta{{font-size:12px;color:#8b949e;margin-bottom:1.5rem}}
.badge{{display:inline-block;padding:2px 10px;border-radius:10px;font-size:11px;background:#1d9e7520;color:#1d9e75;border:1px solid #1d9e7540}}
table{{width:100%;border-collapse:collapse;margin-bottom:1rem;font-size:12px}}
th{{background:#21262d;color:#8b949e;font-weight:600;text-align:left;padding:7px 10px;border-bottom:1px solid #30363d;font-size:11px;text-transform:uppercase;letter-spacing:.04em}}
td{{padding:6px 10px;border-bottom:1px solid #21262d;vertical-align:top}}
tr:hover td{{background:#161b22}}
.section{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1rem;margin-bottom:1.5rem;overflow-x:auto}}
.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:1.5rem}}
.card{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1rem;text-align:center}}
.card .num{{font-size:28px;font-weight:600;color:#1d9e75}}
.card .lbl{{font-size:11px;color:#8b949e;margin-top:3px}}
.mono{{font-family:'Courier New',monospace;font-size:11px;word-break:break-all}}
.ok{{color:#3fb950}}.err{{color:#f85149}}.warn{{color:#e3b341}}
.footer{{margin-top:2.5rem;font-size:11px;color:#30363d;text-align:center;border-top:1px solid #21262d;padding-top:1rem}}
.device-block{{margin-bottom:1.2rem;padding-bottom:1rem;border-bottom:1px solid #21262d}}
.device-block:last-child{{border-bottom:none;margin-bottom:0;padding-bottom:0}}
.session-tree{{margin:0.5rem 0 0 1.4rem}}
.session-tree-label{{font-size:11px;color:#8b949e;text-transform:uppercase;letter-spacing:.04em;margin-bottom:4px}}
.toc{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1rem 1.4rem;margin-bottom:1.5rem;columns:2;font-size:12px}}
.toc a{{color:#a5d6ff;text-decoration:none}}
.conclusion{{background:#161b22;border:1px solid #1d9e7540;border-left:4px solid #1d9e75;border-radius:8px;padding:1rem 1.2rem;font-size:13px;line-height:1.7}}
@media print{{body{{background:#fff;color:#000}}th{{background:#eee;color:#333}}td{{border-bottom:1px solid #ddd}}}}
</style>
</head>
<body>
<h1>🔍 ForensIQ — Full Forensic Investigation Report</h1>
<div class="meta">
  Report generated {format_dual_plain(ts_generated, sep=' / ')} &nbsp;·&nbsp; ForensIQ v1.4 &nbsp;·&nbsp;
  Case {_esc(case['case_number'])}
</div>

<div class="grid">
  <div class="card"><div class="num">{len(dev_list)}</div><div class="lbl">Devices</div></div>
  <div class="card"><div class="num">{len(ev_list)}</div><div class="lbl">Evidence Items</div></div>
  <div class="card"><div class="num">{len(an_list)}</div><div class="lbl">Analysis Results</div></div>
  <div class="card"><div class="num">{len(tl_list)}</div><div class="lbl">Timeline Events</div></div>
</div>

<div class="toc">
{"".join(f'<div><a href="#s{_SEC[t]}">{_sh(t)}</a></div>' for t in _SECTION_TITLES)}
</div>

<h2 id="s{_SEC['Case Information']}">{_sh('Case Information')}</h2>
<div class="section">
<table><tbody>
<tr><td style="width:220px">Case Number</td><td><b>{_esc(case['case_number'])}</b></td></tr>
<tr><td>Title</td><td>{_esc(case['title'])}</td></tr>
<tr><td>Description</td><td>{_esc(case['description'] or '—')}</td></tr>
<tr><td>Status</td><td><span class="badge">{_esc(case['status']).upper()}</span></td></tr>
<tr><td>Priority</td><td>{_esc(priority).upper()}</td></tr>
<tr><td>Tags</td><td>{_esc(', '.join(tags)) if tags else '—'}</td></tr>
<tr><td>Case Created</td><td class="mono">{format_dual_html(case['created_at'])}</td></tr>
<tr><td>Case Last Updated</td><td class="mono">{format_dual_html(case['updated_at']) if 'updated_at' in case.keys() and case['updated_at'] else '—'}</td></tr>
<tr><td>Evidence Directory</td><td class="mono">{_esc(case['evidence_dir'] or '—')}</td></tr>
<tr><td>Report Generated</td><td class="mono">{format_dual_html(ts_generated)}</td></tr>
</tbody></table>
</div>

<h2 id="s{_SEC['Investigator / Reviewer Information']}">{_sh('Investigator / Reviewer Information')}</h2>
<div class="section">
<table><tbody>
<tr><td style="width:220px">Lead Investigator</td><td><b>{_esc(case['investigator'])}</b></td></tr>
<tr><td>Reviewer</td><td>{_esc(reviewer) if reviewer else '<span style="color:#8b949e">Not assigned</span>'}</td></tr>
</tbody></table>
</div>

<h2 id="s{_SEC['Device Information']}">{_sh('Device Information')}</h2>
<div class="section">
{dev_rows or '<p style="color:#8b949e">No devices recorded.</p>'}
</div>

<h2 id="s{_SEC['Acquisition Summary']}">{_sh('Acquisition Summary')}</h2>
<div class="section">
<div class="grid" style="grid-template-columns:repeat(4,1fr);margin-bottom:0.8rem">
  <div class="card"><div class="num">{acq_summary['device_count']}</div><div class="lbl">Devices</div></div>
  <div class="card"><div class="num">{acq_summary['session_count']}</div><div class="lbl">Acquisition Sessions</div></div>
  <div class="card" style="font-size:11px"><div class="num" style="font-size:13px">{format_dual_html(acq_summary['earliest_start'])}</div><div class="lbl">Earliest Session</div></div>
  <div class="card" style="font-size:11px"><div class="num" style="font-size:13px">{format_dual_html(acq_summary['latest_start'])}</div><div class="lbl">Latest Session</div></div>
</div>
<table><thead><tr><th>Session Status</th><th>Count</th></tr></thead>
<tbody>{acq_status_rows}</tbody></table>
</div>

<h2 id="s{_SEC['Evidence Inventory / Manifest']}">{_sh('Evidence Inventory / Manifest')}</h2>
<div class="section">
<table><thead><tr><th>ID</th><th>Filename</th><th>Category</th><th>SHA-256 (Recorded)</th><th>Size</th><th>Source Device</th><th>Session</th><th>Collector</th><th>Integrity</th></tr></thead>
<tbody>{man_rows or '<tr><td colspan="9" style="color:#8b949e">No evidence recorded.</td></tr>'}</tbody>
</table>
{legacy_note}
</div>

<h2 id="s{_SEC['Evidence Integrity']}">{_sh('Evidence Integrity')}</h2>
<div class="section">
<h3>SHA-256 Hash Verification</h3>
<table><thead><tr><th>Filename</th><th>Recorded SHA-256</th><th>Verified SHA-256</th><th>Integrity Status</th><th>Last Verification Time</th></tr></thead>
<tbody>{hash_rows or '<tr><td colspan="5" style="color:#8b949e">No evidence recorded.</td></tr>'}</tbody>
</table>
<p style="color:#8b949e;font-size:11px">Recorded SHA-256 hashes are set at acquisition and never changed; Verified SHA-256 reflects the most recent re-verification, if any.</p>
</div>

<h2 id="s{_SEC['Chain of Custody']}">{_sh('Chain of Custody')}</h2>
<div class="section">
<table><thead><tr><th>Filename</th><th>Lifecycle Status</th><th>Custody Events</th><th>Transfers</th></tr></thead>
<tbody>{custody_rows or '<tr><td colspan="4" style="color:#8b949e">No evidence recorded.</td></tr>'}</tbody>
</table>
<h3>Evidence Transfer History</h3>
<table><thead><tr><th>Timestamp</th><th>Evidence</th><th>Investigator</th><th>From → To</th><th>Integrity at Transfer</th><th>Reason</th></tr></thead>
<tbody>{transfer_rows or '<tr><td colspan="6" style="color:#8b949e">No transfers recorded for this case.</td></tr>'}</tbody>
</table>
<h3>Audit Summary</h3>
<table><thead><tr><th>Action</th><th>Count</th></tr></thead>
<tbody>{audit_summary_rows}</tbody>
</table>
</div>

<h2 id="s{_SEC['Analysis Methodology']}">{_sh('Analysis Methodology')}</h2>
<div class="section">
<p style="color:#8b949e;font-size:11.5px;margin-bottom:0.6rem">Methods actually run against this case's evidence, derived from recorded analysis results — no method is listed unless it was performed.</p>
<table><thead><tr><th>Method</th><th>Results Recorded</th><th>Description</th></tr></thead>
<tbody>{methodology_rows}</tbody>
</table>
</div>

<h2 id="s{_SEC['Analysis Findings']}">{_sh('Analysis Findings')}</h2>
<div class="section">
<table><thead><tr><th>Analysis Type</th><th>Severity</th><th>Finding</th><th>Timestamp</th><th>Evidence Reference</th></tr></thead>
<tbody>{an_rows or '<tr><td colspan="5" style="color:#8b949e">No analysis results recorded.</td></tr>'}</tbody>
</table></div>

<h2 id="s{_SEC['Unified Forensic Timeline']}">{_sh('Unified Forensic Timeline')}{f" (showing {min(100,len(tl_list))} of {len(tl_list)} events)" if len(tl_list) > 100 else ""}</h2>
<div class="section">
<table><thead><tr><th>Timestamp</th><th>Category</th><th>Event Type</th><th>Description</th><th>Evidence</th><th>Device/Session</th><th>Actor</th></tr></thead>
<tbody>{tl_rows or '<tr><td colspan="7" style="color:#8b949e">No timeline events recorded.</td></tr>'}</tbody>
</table></div>

<h2 id="s{_SEC['Investigator Notes']}">{_sh('Investigator Notes')}</h2>
<div class="section">
{('<p style="white-space:pre-wrap">' + _esc(case["notes"]) + '</p>') if str(case["notes"] or "").strip() else '<p style="color:#8b949e">No investigator notes recorded for this case.</p>'}
</div>

<h2 id="s{_SEC['Integrity Verification']}">{_sh('Integrity Verification')}</h2>
<div class="section">
<div class="grid" style="grid-template-columns:repeat(5,1fr);margin-bottom:0.8rem">
  <div class="card"><div class="num" style="color:{_OVERALL_COLORS.get(overall_status,'#8b949e')}">{_esc(overall_status)}</div><div class="lbl">Overall Case Status</div></div>
  <div class="card"><div class="num">{integrity_summary.get('MATCH',0)}</div><div class="lbl">Match</div></div>
  <div class="card"><div class="num" style="color:#f85149">{integrity_summary.get('MISMATCH',0)}</div><div class="lbl">Mismatch</div></div>
  <div class="card"><div class="num" style="color:#e3b341">{integrity_summary.get('MISSING',0) + integrity_summary.get('CORRUPTED',0)}</div><div class="lbl">Missing/Corrupted</div></div>
  <div class="card"><div class="num" style="color:#8b949e">{integrity_summary.get('NOT_VERIFIED',0)}</div><div class="lbl">Not Verified</div></div>
</div>
<table><thead><tr><th>Status</th><th>Evidence Item Count</th></tr></thead>
<tbody>{integrity_rollup_rows}</tbody></table>
<p style="color:#8b949e;font-size:11px">Case-level rollup of each evidence item's most recent verification status — distinct from the per-item table in Evidence Integrity above.</p>
</div>

<h2 id="s{_SEC['Digital Signature Information']}">{_sh('Digital Signature Information')}</h2>
<div class="section">
{sig_block}
</div>

<h2 id="s{_SEC['Final Conclusion']}">{_sh('Final Conclusion')}</h2>
<div class="section conclusion">
{_esc(conclusion_text)}
</div>

<div class="footer">
  Generated by ForensIQ v1.4 &nbsp;·&nbsp; {format_dual_plain(ts_generated, sep=' / ')} &nbsp;·&nbsp;
  Case: {_esc(case['case_number'])} &nbsp;·&nbsp;
  All timestamps are stored in UTC; a secondary {DEFAULT_SECONDARY_TZ} time is shown alongside each for reference.
</div>
</body></html>"""

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)
    return output_path

# ── PDF Report ─────────────────────────────────────────────────────────────────

def generate_pdf_report(case_id: int, db: CaseManager, output_path: str) -> str:
    try:
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Table, TableStyle,
            Spacer, HRFlowable, KeepTogether,
        )
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.units import cm
        from reportlab.pdfgen import canvas as pdfcanvas
    except ImportError:
        raise RuntimeError(
            "ReportLab is not installed.\n"
            "Run: pip install reportlab"
        )

    case     = db.get_case(case_id)
    devices  = db.get_devices_for_case(case_id)
    evidence = db.get_evidence_for_case(case_id)
    analysis = db.get_analysis_results(case_id)
    timeline = db.get_timeline(case_id)

    if not case:
        raise ValueError(f"Case {case_id} not found")

    # Materialise all result sets before building the document
    dev_list = list(devices)
    ev_list  = list(evidence)
    an_list  = list(analysis)
    tl_list  = list(timeline)

    PAGE_W = A4[0] - 4 * cm   # usable width with 2cm margins each side

    # ── Page headers/footers + page numbers ──────────────────────────────
    # SimpleDocTemplate only exposes per-page draw callbacks, not a running
    # "N of M" page count, so a small buffering canvas (standard ReportLab
    # recipe) records every page, then draws the header/footer — including
    # the total page count — once the full page count is known at save().
    header_text = f"ForensIQ — Full Forensic Investigation Report  ·  Case {case['case_number']}"
    footer_text = f"{case['case_number']}  ·  Generated {format_dual_plain(now_utc_str(), sep=' / ')}"

    class _NumberedCanvas(pdfcanvas.Canvas):
        def __init__(self, *args, **kwargs):
            pdfcanvas.Canvas.__init__(self, *args, **kwargs)
            self._saved_page_states = []

        def showPage(self):
            self._saved_page_states.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            total_pages = len(self._saved_page_states)
            for state in self._saved_page_states:
                self.__dict__.update(state)
                self._draw_header_footer(total_pages)
                pdfcanvas.Canvas.showPage(self)
            pdfcanvas.Canvas.save(self)

        def _draw_header_footer(self, total_pages):
            w, h = A4
            self.setStrokeColor(colors.HexColor("#d0d7de"))
            self.setFillColor(colors.HexColor("#8b949e"))
            self.setFont("Helvetica", 7.5)
            self.drawString(2 * cm, h - 1.3 * cm, header_text)
            self.line(2 * cm, h - 1.42 * cm, w - 2 * cm, h - 1.42 * cm)
            self.line(2 * cm, 1.55 * cm, w - 2 * cm, 1.55 * cm)
            self.drawString(2 * cm, 1.2 * cm, footer_text)
            self.drawRightString(
                w - 2 * cm, 1.2 * cm,
                f"Page {self._pageNumber} of {total_pages}"
            )

    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        rightMargin=2*cm, leftMargin=2*cm,
        topMargin=2*cm,   bottomMargin=2*cm,
        title=f"ForensIQ Full Forensic Investigation Report — {case['case_number']}",
        author=str(case["investigator"] or "ForensIQ"),
        subject=f"Case {case['case_number']} — {case['title']}",
    )

    styles = getSampleStyleSheet()
    TEAL  = colors.HexColor("#1d9e75")
    DARK  = colors.HexColor("#1a1a2e")
    MID   = colors.HexColor("#555f6e")
    WHITE = colors.white
    LGRAY = colors.HexColor("#f6f8fa")
    DGRAY = colors.HexColor("#e8eaed")

    title_s = ParagraphStyle("ftitle",  parent=styles["Title"],
                              fontSize=20, textColor=TEAL, spaceAfter=4)
    h2_s    = ParagraphStyle("fh2",     parent=styles["Heading2"],
                              fontSize=12, textColor=TEAL, spaceBefore=14, spaceAfter=6)
    h3_s    = ParagraphStyle("fh3",     parent=styles["Heading3"],
                              fontSize=10, textColor=DARK, spaceBefore=8, spaceAfter=4)
    normal  = ParagraphStyle("fnorm",   parent=styles["Normal"],
                              fontSize=9,  leading=13)
    meta_s  = ParagraphStyle("fmeta",   parent=styles["Normal"],
                              fontSize=8,  textColor=MID, leading=11)
    mono_s  = ParagraphStyle("fmono",   parent=styles["Normal"],
                              fontSize=7,  fontName="Courier", leading=10)
    # FIX BUG#5: cell style for values that may be long & unbroken (filenames,
    # filepaths, SHA-256 hashes). wordWrap='CJK' allows breaking on any character
    # boundary, not just whitespace, so cells respect their column width instead
    # of overflowing across the page.
    wrap_s  = ParagraphStyle("fwrap",   parent=styles["Normal"],
                              fontSize=7,  leading=9, wordWrap="CJK")
    wrap_mono_s = ParagraphStyle("fwrapmono", parent=styles["Normal"],
                              fontSize=7,  leading=9, fontName="Courier", wordWrap="CJK")

    def _pdf_esc(value) -> str:
        """Escape a value for safe insertion into a ReportLab Paragraph (XML-like markup)."""
        return html_lib.escape(str(value if value is not None else ""))

    def wrap_cell(value, mono: bool = False) -> Paragraph:
        """Wrap a table cell value in a Paragraph so long unbroken strings wrap
        instead of overflowing the column (FIX BUG#5)."""
        return Paragraph(_pdf_esc(value), wrap_mono_s if mono else wrap_s)

    def ts_cell(value) -> Paragraph:
        """
        Phase 10: dual UTC/IST timestamp cell for PDF tables. Every
        forensic timestamp (case, evidence, device/session, analysis,
        custody, audit, verification, signature) renders as two lines:
            2026-08-15 04:44:29 UTC
            2026-08-15 10:14:29 IST
        format_dual_pdf() already returns ReportLab-safe markup
        ('<br/>' + an inline <font> tag) built only from formatted
        datetime components, so — unlike wrap_cell/_pdf_esc — this must
        NOT re-escape it (that would show literal '&lt;br/&gt;').
        """
        return Paragraph(format_dual_pdf(value), wrap_s)

    _pdf_severity_colors = {
        "critical": colors.HexColor("#c93c37"), "high": colors.HexColor("#c9702e"),
        "medium": colors.HexColor("#a98416"), "low": colors.HexColor("#3d6fa8"),
        "info": colors.HexColor("#6e7681"),
    }

    def severity_cell(sev: str) -> Paragraph:
        """Severity cell colored to match the analysis engine's severity vocabulary."""
        color = _pdf_severity_colors.get(sev, _pdf_severity_colors["info"])
        style = ParagraphStyle("fseverity", parent=wrap_s, textColor=color,
                                fontName="Helvetica-Bold")
        return Paragraph(_pdf_esc((sev or "info").upper()), style)

    def tbl_style(header_color=TEAL) -> TableStyle:
        return TableStyle([
            ("BACKGROUND",   (0, 0), (-1, 0), header_color),
            ("TEXTCOLOR",    (0, 0), (-1, 0), WHITE),
            ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",     (0, 0), (-1, 0), 8),
            ("FONTSIZE",     (0, 1), (-1, -1), 7),
            ("ROWBACKGROUNDS",(0, 1),(-1, -1), [LGRAY, WHITE]),
            ("GRID",         (0, 0), (-1, -1), 0.4, colors.HexColor("#d0d7de")),
            ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",   (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
            ("LEFTPADDING",  (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("WORDWRAP",     (0, 0), (-1, -1), True),
        ])

    def section_heading(title: str) -> Paragraph:
        return Paragraph(_pdf_esc(_sh(title)), h2_s)

    _hdr_style = ParagraphStyle("fhdr", fontSize=7.5, textColor=WHITE,
                                 fontName="Helvetica-Bold", leading=9)

    def hdr_row(labels) -> list:
        """Wrap a header row's labels in Paragraphs so column headers wrap
        instead of visually overlapping the next column when narrow."""
        return [Paragraph(_pdf_esc(lbl), _hdr_style) for lbl in labels]

    ts_generated = now_utc_str()
    story = []

    # Title
    story.append(Paragraph("ForensIQ — Full Forensic Investigation Report", title_s))
    story.append(Paragraph(
        f"<b>Case:</b> {_pdf_esc(case['case_number'])}  &nbsp;|&nbsp;  "
        f"<b>Title:</b> {_pdf_esc(case['title'])}  &nbsp;|&nbsp;  "
        f"<b>Status:</b> {_pdf_esc(case['status']).upper()}",
        meta_s
    ))
    story.append(Paragraph(
        f"Report Generated: {format_dual_pdf(ts_generated)}  &nbsp;|&nbsp;  ForensIQ v1.4",
        meta_s
    ))
    story.append(Spacer(1, 0.3*cm))
    story.append(HRFlowable(width="100%", thickness=1.5, color=TEAL, spaceAfter=6))

    # ── Section 1 — Case Information ─────────────────────────────────────
    story.append(section_heading("Case Information"))
    reviewer = str(case["reviewer"] or "").strip() if "reviewer" in case.keys() else ""
    priority = str(case["priority"] or "MEDIUM") if "priority" in case.keys() else "MEDIUM"
    tags_raw = case["tags"] if "tags" in case.keys() else "[]"
    try:
        tags = json.loads(tags_raw or "[]")
    except (TypeError, ValueError):
        tags = []
    case_data = [
        ["Field", "Value"],
        ["Case Number",   case["case_number"]],
        ["Title",         case["title"]],
        ["Description",   (case["description"] or "—")[:200]],
        ["Status",        case["status"].upper()],
        ["Priority",      priority.upper()],
        ["Tags",          ", ".join(tags) if tags else "—"],
        ["Evidence Directory", (case["evidence_dir"] or "—")],
    ]
    case_data = [case_data[0]] + [[r[0], wrap_cell(r[1])] for r in case_data[1:]]
    case_data.append(["Case Created", ts_cell(case["created_at"])])
    case_data.append(["Case Last Updated",
                       ts_cell(case["updated_at"]) if "updated_at" in case.keys() and case["updated_at"] else "—"])
    story.append(Table(
        case_data,
        colWidths=[PAGE_W * 0.30, PAGE_W * 0.70],
        style=tbl_style(),
    ))
    story.append(Spacer(1, 0.3*cm))

    # ── Section 2 — Investigator / Reviewer Information ─────────────────
    story.append(section_heading("Investigator / Reviewer Information"))
    inv_data = [
        ["Role", "Name"],
        ["Lead Investigator", case["investigator"]],
        ["Reviewer", reviewer or "Not assigned"],
    ]
    story.append(Table(
        inv_data,
        colWidths=[PAGE_W * 0.30, PAGE_W * 0.70],
        style=tbl_style(),
    ))
    story.append(Spacer(1, 0.4*cm))

    # ── Section 3 — Device Information (Phase 3: device rendered ONCE, ──
    # with its acquisition sessions nested directly beneath it)
    story.append(section_heading("Device Information"))
    sess_label_s = ParagraphStyle("fsesslbl", parent=styles["Normal"],
                                   fontSize=8, textColor=MID,
                                   spaceBefore=4, spaceAfter=3, leftIndent=8)
    if dev_list:
        for d in dev_list:
            dev_data = [["Serial", "Manufacturer", "Model", "Android",
                         "USB Debug", "First Connected", "Last Connected"]]
            dev_data[0] = [Paragraph(f"<b>{h}</b>", ParagraphStyle(
                "fdevhdr", fontSize=7.5, textColor=WHITE, fontName="Helvetica-Bold"
            )) for h in dev_data[0]]
            dev_data.append([
                (d["serial"] or "")[:18],
                d["manufacturer"] or "—",
                d["model"] or "—",
                f"Android {d['android_version']} (SDK {d['sdk_version']})",
                "Yes" if d["usb_debugging"] else "No",
                ts_cell(d["first_connected"] or d["acquired_at"]),
                ts_cell(d["last_connected"] or d["acquired_at"]),
            ])
            dev_block = [
                Table(
                    dev_data,
                    colWidths=[
                        PAGE_W * 0.13, PAGE_W * 0.13, PAGE_W * 0.10,
                        PAGE_W * 0.20, PAGE_W * 0.11, PAGE_W * 0.165, PAGE_W * 0.165,
                    ],
                    style=tbl_style(),
                ),
            ]

            sessions = list(db.get_sessions_for_device(d["id"]))
            dev_block.append(Paragraph(
                f"└─ Acquisition Sessions ({len(sessions)})", sess_label_s
            ))
            if sessions:
                sess_data = [["Session", "Start", "End", "Status", "Targets", "Evidence"]]
                for s in sessions:
                    try:
                        targets_str = ", ".join(json.loads(s["targets"] or "[]"))
                    except (TypeError, ValueError):
                        targets_str = ""
                    sess_data.append([
                        f"#{s['id']}",
                        ts_cell(s["start_time"]),
                        ts_cell(s["end_time"]) if s["end_time"] else "—",
                        s["status"] or "—",
                        wrap_cell(targets_str),
                        str(len(db.get_evidence_for_session(s["id"]))),
                    ])
                dev_block.append(Table(
                    sess_data,
                    colWidths=[
                        PAGE_W * 0.09, PAGE_W * 0.17, PAGE_W * 0.17,
                        PAGE_W * 0.13, PAGE_W * 0.32, PAGE_W * 0.12,
                    ],
                    style=tbl_style(header_color=MID),
                ))
            else:
                dev_block.append(Paragraph(
                    "No acquisition sessions recorded for this device.", meta_s
                ))
            dev_block.append(Spacer(1, 0.3*cm))
            story.append(KeepTogether(dev_block))
    else:
        story.append(Paragraph("No devices recorded.", meta_s))
    story.append(Spacer(1, 0.2*cm))

    # ── Section 4 — Acquisition Summary ──────────────────────────────────
    story.append(section_heading("Acquisition Summary"))
    acq_summary = _acquisition_summary(dev_list, db)
    acq_data = [
        ["Metric", "Value"],
        ["Devices", str(acq_summary["device_count"])],
        ["Acquisition Sessions", str(acq_summary["session_count"])],
        ["Earliest Session", ts_cell(acq_summary["earliest_start"])],
        ["Latest Session", ts_cell(acq_summary["latest_start"])],
    ]
    story.append(Table(
        acq_data, colWidths=[PAGE_W * 0.38, PAGE_W * 0.62], style=tbl_style(),
    ))
    if acq_summary["status_counts"]:
        st_data = [["Session Status", "Count"]] + [
            [k, str(v)] for k, v in sorted(acq_summary["status_counts"].items())
        ]
        story.append(Spacer(1, 0.15*cm))
        story.append(Table(
            st_data, colWidths=[PAGE_W * 0.38, PAGE_W * 0.62], style=tbl_style(header_color=MID),
        ))
    story.append(Spacer(1, 0.4*cm))

    # ── Section 5 — Evidence Inventory / Manifest ────────────────────────
    # Reuses manifest_service.build_manifest() (Phase 4) as the single
    # evidence table, resolving Case -> Device -> Session -> Evidence in
    # one place instead of duplicating the same rows in a second,
    # separately-computed evidence inventory table.
    story.append(section_heading("Evidence Inventory / Manifest"))
    manifest = build_manifest(case_id, db)
    m_items = manifest["items"]
    if m_items:
        man_data = [hdr_row([
            "Evidence ID", "Filename", "Category", "SHA-256 (Recorded)",
            "Source Device", "Session", "Collector", "Storage Location",
            "Integrity",
        ])]
        for it in m_items:
            device_str = (
                f"{it['device_model']} ({it['device_serial']})"
                if it["device_serial"] else "— (legacy)"
            )
            session_str = f"#{it['session_id']}" if it["session_id"] else "— (legacy)"
            man_data.append([
                str(it["evidence_id"]),
                wrap_cell(it["filename"] or "—"),
                it["category"] or "—",
                wrap_cell((it["recorded_sha256"] or "")[:48] +
                          ("…" if it["recorded_sha256"] else "—"), mono=True),
                wrap_cell(device_str),
                session_str,
                wrap_cell(it["collector"] or "—"),
                wrap_cell(it["storage_location"] or "—"),
                it["integrity_status"],
            ])
        story.append(Table(
            man_data,
            colWidths=[
                PAGE_W * 0.08, PAGE_W * 0.12, PAGE_W * 0.07, PAGE_W * 0.17,
                PAGE_W * 0.13, PAGE_W * 0.07, PAGE_W * 0.10, PAGE_W * 0.16,
                PAGE_W * 0.10,
            ],
            style=tbl_style(),
        ))
        if manifest["legacy_items"]:
            story.append(Paragraph(
                f"{manifest['legacy_items']} of {manifest['total_items']} item(s) "
                f"are legacy evidence with no device/session on record — shown "
                f"as \u201c\u2014 (legacy)\u201d rather than invented.",
                meta_s
            ))
    else:
        story.append(Paragraph("No evidence recorded for this case.", meta_s))
    story.append(Spacer(1, 0.4*cm))

    # ── Section 6 — Evidence Integrity (per-item SHA-256 verification) ──
    # FIX (Phase 1): previously only ever showed the RECORDED hash with a
    # "Recorded" status — never whether it had actually been re-verified.
    # Now distinguishes Recorded (immutable, acquisition-time) SHA-256 from
    # the most recent Verified SHA-256 and Integrity Status, with when that
    # check last ran. A recorded hash is never labeled "Verified" unless a
    # later recalculation actually matched it.
    story.append(section_heading("Evidence Integrity"))
    story.append(Paragraph("SHA-256 Hash Verification", h3_s))
    if ev_list:
        last_vr_by_ev = db.get_last_verification_per_evidence(case_id)
        hash_data = [hdr_row(["Filename", "Recorded SHA-256", "Verified SHA-256",
                      "Status", "Last Verified"])]
        for e in ev_list:
            h    = e["sha256"] or ""
            last = last_vr_by_ev.get(e["id"])
            if last:
                verified_h = (last["current_hash"] or "")[:48] + \
                             ("…" if last["current_hash"] else "—")
                status     = last["result"]
                last_time  = ts_cell(last["verification_time"])
            else:
                verified_h = "—"
                status     = "NOT VERIFIED"
                last_time  = "—"
            # FIX BUG#5: filename and full hash wrapped — 48-char hashes are the
            # worst-case overflow scenario (787pt wide vs ~280pt column).
            hash_data.append([
                wrap_cell(e["filename"] or "—"),
                wrap_cell(h[:48] + ("…" if h else ""), mono=True),
                wrap_cell(verified_h, mono=True),
                status,
                last_time,
            ])
        story.append(Table(
            hash_data,
            colWidths=[PAGE_W * 0.16, PAGE_W * 0.30, PAGE_W * 0.30,
                       PAGE_W * 0.12, PAGE_W * 0.12],
            style=tbl_style(),
        ))
    else:
        story.append(Paragraph("No evidence to verify.", meta_s))
    story.append(Spacer(1, 0.4*cm))

    # ── Section 7 — Chain of Custody (+ Transfer History, Audit Summary) ──
    # Deliberately structured differently from the Timeline below (which
    # already interleaves every event type as flat description strings):
    # this groups by evidence item and shows the lifecycle stage reached
    # plus transfer count, not a re-listing of individual timeline rows.
    story.append(section_heading("Chain of Custody"))
    if ev_list:
        cc_data = [["Filename", "Lifecycle Status", "Custody Events", "Transfers"]]
        for e in ev_list:
            cc_data.append([
                wrap_cell(e["filename"] or "—"),
                db.get_evidence_lifecycle_status(e["id"]),
                str(len(db.get_custody_chain(e["id"]))),
                str(len(db.get_transfer_history(evidence_id=e["id"]))),
            ])
        story.append(Table(
            cc_data,
            colWidths=[PAGE_W * 0.40, PAGE_W * 0.30, PAGE_W * 0.15, PAGE_W * 0.15],
            style=tbl_style(),
        ))
    else:
        story.append(Paragraph("No evidence recorded.", meta_s))
    story.append(Spacer(1, 0.3*cm))

    # Evidence Transfer History — only TRANSFERRED custody events, with
    # the evidence's real integrity state captured at transfer time.
    story.append(Paragraph("Evidence Transfer History", h3_s))
    transfer_events = db.get_transfer_history(case_id=case_id)
    if transfer_events:
        tr_data = [["Timestamp", "Evidence", "Investigator", "From → To", "Integrity"]]
        for t in transfer_events:
            tr_data.append([
                ts_cell(t["timestamp"]),
                wrap_cell(t["filename"] or "—"),
                t["investigator"] or "—",
                wrap_cell(f"{t['from_location'] or '?'} → {t['to_location'] or '?'}"),
                t["integrity_status"] or "—",
            ])
        story.append(Table(
            tr_data,
            colWidths=[PAGE_W * 0.16, PAGE_W * 0.22, PAGE_W * 0.16,
                       PAGE_W * 0.30, PAGE_W * 0.16],
            style=tbl_style(),
        ))
    else:
        story.append(Paragraph("No transfers recorded for this case.", meta_s))
    story.append(Spacer(1, 0.3*cm))

    # Audit Summary — aggregated action counts for this case's audit
    # events (case + its evidence items), not the full raw audit dump
    # (that's the separate Audit Trail report/export).
    story.append(Paragraph("Audit Summary", h3_s))
    audit_counts: dict = {}
    try:
        target_ids = {str(case_id)} | {str(e["id"]) for e in ev_list}
        for rec in db.get_audit_trail(limit=5000):
            if str(rec["target_id"]) in target_ids:
                audit_counts[rec["action"]] = audit_counts.get(rec["action"], 0) + 1
    except Exception:
        pass
    if audit_counts:
        au_data = [["Action", "Count"]]
        for action, count in sorted(audit_counts.items()):
            au_data.append([action, str(count)])
        story.append(Table(
            au_data,
            colWidths=[PAGE_W * 0.70, PAGE_W * 0.30],
            style=tbl_style(),
        ))
    else:
        story.append(Paragraph("No audit records for this case.", meta_s))
    story.append(Spacer(1, 0.4*cm))

    # ── Section 8 — Analysis Methodology ─────────────────────────────────
    story.append(section_heading("Analysis Methodology"))
    methodology_entries = _analysis_methodology_entries(an_list)
    if methodology_entries:
        meth_data = [["Method", "Results Recorded", "Description"]]
        for me in methodology_entries:
            meth_data.append([
                me["type"], str(me["count"]), wrap_cell(me["description"]),
            ])
        story.append(Table(
            meth_data,
            colWidths=[PAGE_W * 0.20, PAGE_W * 0.15, PAGE_W * 0.65],
            style=tbl_style(),
        ))
    else:
        story.append(Paragraph("No analysis has been run on this case yet.", meta_s))
    story.append(Spacer(1, 0.4*cm))

    # ── Section 9 — Analysis Findings ────────────────────────────────────
    story.append(section_heading("Analysis Findings"))
    if an_list:
        an_data = [hdr_row(["Analysis Type", "Severity", "Finding", "Timestamp", "Evidence Reference"])]
        for a in an_list:
            sev, ref = _analysis_severity_and_ref(a)
            an_data.append([
                a["analysis_type"] or "—",
                severity_cell(sev),
                wrap_cell((a["result_summary"] or "—")[:200]),
                ts_cell(a["created_at"]),
                wrap_cell(ref[:120], mono=True),
            ])
        story.append(Table(
            an_data,
            colWidths=[PAGE_W * 0.16, PAGE_W * 0.10, PAGE_W * 0.34,
                       PAGE_W * 0.16, PAGE_W * 0.24],
            style=tbl_style(),
        ))
    else:
        story.append(Paragraph("No analysis results recorded.", meta_s))
    story.append(Spacer(1, 0.4*cm))

    # ── Section 10 — Unified Forensic Timeline (capped at 100 events) ───
    story.append(Paragraph(
        _pdf_esc(
            _sh("Unified Forensic Timeline") +
            (f" (showing 100 of {len(tl_list)})" if len(tl_list) > 100 else "")
        ),
        h2_s
    ))
    if tl_list:
        def _pdf_device_session(t) -> str:
            parts = []
            serial = t["device_serial"] if "device_serial" in t.keys() else None
            if serial:
                parts.append(serial)
            sess_id = t["session_id"] if "session_id" in t.keys() else None
            if sess_id:
                parts.append(f"sess#{sess_id}")
            return " / ".join(parts)

        tl_data = [hdr_row(["Timestamp", "Category", "Event Type", "Description",
                    "Evidence", "Device/Session", "Actor"])]
        for t in tl_list[:100]:
            tl_data.append([
                ts_cell(t["timestamp"]),
                t["category"] if "category" in t.keys() else "—",
                t["event_type"] or "—",
                wrap_cell((t["description"] or "")[:200]),
                wrap_cell((t["evidence_filename"] if "evidence_filename" in t.keys()
                           and t["evidence_filename"] else "—")),
                wrap_cell(_pdf_device_session(t) or "—"),
                (t["actor"] if "actor" in t.keys() and t["actor"] else "—"),
            ])
        story.append(Table(
            tl_data,
            colWidths=[PAGE_W * 0.13, PAGE_W * 0.11, PAGE_W * 0.14,
                       PAGE_W * 0.28, PAGE_W * 0.13, PAGE_W * 0.11, PAGE_W * 0.10],
            style=tbl_style(),
        ))
    else:
        story.append(Paragraph("No timeline events recorded.", meta_s))
    story.append(Spacer(1, 0.4*cm))

    # ── Section 11 — Investigator Notes ──────────────────────────────────
    story.append(section_heading("Investigator Notes"))
    notes = (str(case["notes"] or "") if case["notes"] is not None else "").strip()
    if notes:
        story.append(Paragraph(notes.replace("\n", "<br/>"), normal))
    else:
        story.append(Paragraph("No investigator notes recorded for this case.", meta_s))
    story.append(Spacer(1, 0.4*cm))

    # ── Section 12 — Integrity Verification (case-level rollup) ─────────
    story.append(section_heading("Integrity Verification"))
    integrity_summary = db.get_case_integrity_summary(case_id)
    overall_status = integrity_summary.get("overall_status", "NOT_VERIFIED")
    iv_data = [
        ["Overall Case Status", overall_status],
        ["Match",               str(integrity_summary.get("MATCH", 0))],
        ["Mismatch",            str(integrity_summary.get("MISMATCH", 0))],
        ["Missing",             str(integrity_summary.get("MISSING", 0))],
        ["Corrupted",           str(integrity_summary.get("CORRUPTED", 0))],
        ["Not Verified",        str(integrity_summary.get("NOT_VERIFIED", 0))],
    ]
    story.append(Table(
        [["Metric", "Value"]] + iv_data,
        colWidths=[PAGE_W * 0.38, PAGE_W * 0.62], style=tbl_style(),
    ))
    story.append(Paragraph(
        "Case-level rollup of each evidence item's most recent verification "
        "status — distinct from the per-item table in Evidence Integrity above.",
        meta_s
    ))
    story.append(Spacer(1, 0.4*cm))

    # ── Section 13 — Digital Signature Information ───────────────────────
    story.append(section_heading("Digital Signature Information"))
    sig_info = _report_signature_info(case_id, db)
    if sig_info:
        sig_status = sig_info.get("live_status") or "RECORDED"
        sig_data = [
            ["Field", "Value"],
            ["Signer", sig_info.get("signer") or "—"],
            ["Algorithm", sig_info.get("algorithm") or "—"],
            ["Signed At", ts_cell(sig_info.get("signed_at"))],
            ["Artifact SHA-256", wrap_cell(sig_info.get("artifact_sha256") or "—", mono=True)],
            ["Artifact File", wrap_cell(sig_info.get("artifact_filename")
                                         or sig_info.get("artifact_path") or "—")],
            ["Signature Status", sig_status],
            ["Notes", wrap_cell(sig_info.get("live_notes") or
                                 "Recorded signature metadata shown; artifact was not re-verified.")],
        ]
        story.append(Table(
            sig_data, colWidths=[PAGE_W * 0.28, PAGE_W * 0.72], style=tbl_style(),
        ))
    else:
        story.append(Paragraph(
            "No report artifact for this case has been digitally signed yet. "
            "Reports are signed as a separate step from the Digital Signature "
            "panel after export.",
            meta_s
        ))
    story.append(Spacer(1, 0.4*cm))

    # ── Section 14 — Final Conclusion ────────────────────────────────────
    story.append(section_heading("Final Conclusion"))
    conclusion_text = _final_conclusion_text(
        case, dev_list, ev_list, an_list, tl_list, integrity_summary, sig_info
    )
    story.append(Paragraph(_pdf_esc(conclusion_text), normal))

    doc.build(story, canvasmaker=_NumberedCanvas)
    return output_path

# ── Specialised Report Types ───────────────────────────────────────────────────
# These are exported by generate_report() and by the updated ReportPanel.

def generate_case_summary_report(case_id: int, db: CaseManager,
                                  output_path: str) -> str:
    """
    Case Summary Report: concise one-page overview of the case,
    evidence counts, device list, and investigator notes.
    Exported as self-contained HTML.
    """
    case     = db.get_case(case_id)
    if not case:
        raise ValueError(f"Case {case_id} not found")
    devices  = list(db.get_devices_for_case(case_id))
    ev_count = db.get_evidence_count(case_id)
    an_count = len(db.get_analysis_results(case_id))
    tl_count = len(db.get_timeline(case_id))
    vr_summ  = db.get_verification_summary(case_id)
    custody  = db.get_custody_events(case_id=case_id)
    cu_count = len(list(custody))
    ts_gen   = now_utc_str()
    st_color = "#3FB950" if str(case["status"]).upper() == "ACTIVE" else "#8B949E"

    dev_rows = "\n".join(
        f"<tr><td class='mono'>{_esc(d['serial'])}</td>"
        f"<td>{_esc(d['manufacturer'])} {_esc(d['model'])}</td>"
        f"<td>Android {_esc(d['android_version'])} SDK {_esc(d['sdk_version'])}</td>"
        f"<td>{'✔' if d['usb_debugging'] else '✘'}</td>"
        f"<td>{format_dual_html(d['acquired_at'])}</td>"
        f"<td>{db.get_session_count_for_device(d['id'])}</td></tr>"
        for d in devices
    ) or "<tr><td colspan='6' style='color:#8b949e'>No devices.</td></tr>"

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>ForensIQ Case Summary — {_esc(case['case_number'])}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',Arial,sans-serif;background:#0d1117;color:#e6edf3;padding:2rem;font-size:13px;line-height:1.6}}
h1{{color:#1d9e75;font-size:24px;margin-bottom:4px}}
h2{{color:#1d9e75;font-size:12px;margin:1.6rem 0 0.5rem;padding-left:8px;border-left:3px solid #1d9e75;text-transform:uppercase;letter-spacing:.05em}}
.meta{{color:#8b949e;font-size:12px;margin-bottom:1.5rem}}
.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:1.5rem}}
.card{{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:1rem;text-align:center}}
.card .num{{font-size:28px;font-weight:700;color:#1d9e75}}
.card .lbl{{font-size:11px;color:#8b949e;margin-top:3px}}
.section{{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:1rem;margin-bottom:1rem}}
table{{width:100%;border-collapse:collapse;font-size:12px}}
th{{background:#21262d;color:#8b949e;padding:6px 8px;text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.04em;border-bottom:1px solid #30363d}}
td{{padding:5px 8px;border-bottom:1px solid #21262d;vertical-align:middle}}
tr:hover td{{background:#1c2128}}
.mono{{font-family:'Courier New',monospace;font-size:11px}}
.badge{{display:inline-block;padding:2px 10px;border-radius:10px;font-size:11px;border:1px solid {st_color}40;color:{st_color};background:{st_color}15}}
.footer{{margin-top:2rem;font-size:11px;color:#484f58;border-top:1px solid #21262d;padding-top:1rem;text-align:center}}
@media print{{body{{background:#fff;color:#000}}th{{background:#eee;color:#333}}}}
</style></head><body>
<h1>📋 ForensIQ — Case Summary</h1>
<div class="meta">
  <strong>Case:</strong> {_esc(case['case_number'])} &nbsp;·&nbsp;
  <strong>{_esc(case['title'])}</strong> &nbsp;·&nbsp;
  <span class="badge">{_esc(case['status']).upper()}</span><br>
  <strong>Investigator:</strong> {_esc(case['investigator'])} &nbsp;·&nbsp;
  <strong>Created:</strong> {format_dual_plain(case['created_at'], sep=' / ')} &nbsp;·&nbsp;
  <strong>Generated:</strong> {format_dual_plain(ts_gen, sep=' / ')}
</div>
<div class="grid">
  <div class="card"><div class="num">{len(devices)}</div><div class="lbl">Devices</div></div>
  <div class="card"><div class="num">{ev_count}</div><div class="lbl">Evidence</div></div>
  <div class="card"><div class="num">{an_count}</div><div class="lbl">Analysis</div></div>
  <div class="card"><div class="num">{tl_count}</div><div class="lbl">Timeline Events</div></div>
  <div class="card"><div class="num" style="color:#3fb950">{vr_summ.get('PASS',0)}</div><div class="lbl">Hash PASS</div></div>
  <div class="card"><div class="num" style="color:#f85149">{vr_summ.get('FAIL',0)}</div><div class="lbl">Hash FAIL</div></div>
  <div class="card"><div class="num" style="color:#e3b341">{vr_summ.get('MISSING',0)}</div><div class="lbl">Hash MISSING</div></div>
  <div class="card"><div class="num">{cu_count}</div><div class="lbl">Custody Events</div></div>
</div>
<h2>Description</h2>
<div class="section"><p style="white-space:pre-wrap">{_esc(case['description'] or '—')}</p></div>
<h2>Devices Examined</h2>
<div class="section">
<table><thead><tr><th>Serial</th><th>Device</th><th>Android</th><th>USB Debug</th><th>Acquired</th><th>Sessions</th></tr></thead>
<tbody>{dev_rows}</tbody></table></div>
{f'<h2>Investigator Notes</h2><div class="section"><p style="white-space:pre-wrap">{_esc(case["notes"])}</p></div>' if (case["notes"] or "").strip() else ""}
<div class="footer">ForensIQ Case Summary &nbsp;·&nbsp; {format_dual_plain(ts_gen, sep=' / ')} &nbsp;·&nbsp; {_esc(case['case_number'])}</div>
</body></html>"""

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)
    return output_path


def generate_integrity_report_html(case_id: int, db: CaseManager,
                                    output_path: str) -> str:
    """
    Integrity / Hash Verification Report: shows every evidence item's stored
    hash, last verification result, and current hash match status.
    """
    case = db.get_case(case_id)
    if not case:
        raise ValueError(f"Case {case_id} not found")
    ev_list = list(db.get_evidence_for_case(case_id))
    vr_summ = db.get_verification_summary(case_id)
    ts_gen  = now_utc_str()

    # Join last verification per evidence item
    last_vr: dict[int, dict] = {}
    for ev in ev_list:
        row = db.get_last_verification(ev["id"])
        if row:
            last_vr[ev["id"]] = dict(row)

    def _result_color(r: str) -> str:
        return {"PASS":"#3fb950","FAIL":"#f85149","MISSING":"#e3b341","ERROR":"#8b949e"}.get(r,"#ccc")

    ev_rows = "\n".join(
        f"""<tr>
          <td>{_esc(ev['filename'] or '—')}</td>
          <td>{_esc(ev['category'])}</td>
          <td class='mono' style='font-size:10px'>{_esc((ev['sha256'] or '')[:48])}{'…' if ev['sha256'] else '—'}</td>
          <td><span style='color:{_result_color(last_vr.get(ev["id"],{}).get("result","—"))};font-weight:600'>{_esc(last_vr.get(ev["id"],{}).get("result","NOT VERIFIED"))}</span></td>
          <td class='mono' style='font-size:10px'>{_esc((last_vr.get(ev["id"],{}).get("current_hash",""))[:32])}{"…" if last_vr.get(ev["id"],{}).get("current_hash") else "—"}</td>
          <td class='mono'>{format_dual_html(last_vr.get(ev["id"],{}).get("verification_time")) if last_vr.get(ev["id"],{}).get("verification_time") else "—"}</td>
          <td>{_esc(last_vr.get(ev["id"],{}).get("notes","—"))}</td>
        </tr>"""
        for ev in ev_list
    ) or "<tr><td colspan='7' style='color:#8b949e'>No evidence items.</td></tr>"

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>ForensIQ Integrity Report — {_esc(case['case_number'])}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',Arial,sans-serif;background:#0d1117;color:#e6edf3;padding:2rem;font-size:13px;line-height:1.6}}
h1{{color:#1d9e75;font-size:24px;margin-bottom:4px}}
h2{{color:#1d9e75;font-size:12px;margin:1.6rem 0 0.5rem;padding-left:8px;border-left:3px solid #1d9e75;text-transform:uppercase;letter-spacing:.05em}}
.meta{{color:#8b949e;font-size:12px;margin-bottom:1.5rem}}
.grid{{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-bottom:1.5rem}}
.card{{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:1rem;text-align:center}}
.card .num{{font-size:28px;font-weight:700}}
.card .lbl{{font-size:11px;color:#8b949e;margin-top:3px}}
.section{{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:1rem;overflow-x:auto;margin-bottom:1rem}}
table{{width:100%;border-collapse:collapse;font-size:12px}}
th{{background:#21262d;color:#8b949e;padding:6px 8px;text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.04em;border-bottom:1px solid #30363d}}
td{{padding:5px 8px;border-bottom:1px solid #21262d;vertical-align:middle}}
tr:hover td{{background:#1c2128}}
.mono{{font-family:'Courier New',monospace}}
.footer{{margin-top:2rem;font-size:11px;color:#484f58;border-top:1px solid #21262d;padding-top:1rem;text-align:center}}
@media print{{body{{background:#fff;color:#000}}th{{background:#eee;color:#333}}}}
</style></head><body>
<h1>🔐 ForensIQ — Evidence Integrity Report</h1>
<div class="meta">
  <strong>Case:</strong> {_esc(case['case_number'])} — {_esc(case['title'])} &nbsp;·&nbsp;
  <strong>Investigator:</strong> {_esc(case['investigator'])} &nbsp;·&nbsp;
  <strong>Generated:</strong> {format_dual_plain(ts_gen, sep=' / ')}
</div>
<div class="grid">
  <div class="card"><div class="num" style="color:#e6edf3">{vr_summ.get('total',0)}</div><div class="lbl">Total Checked</div></div>
  <div class="card"><div class="num" style="color:#3fb950">{vr_summ.get('PASS',0)}</div><div class="lbl">PASS</div></div>
  <div class="card"><div class="num" style="color:#f85149">{vr_summ.get('FAIL',0)}</div><div class="lbl">FAIL</div></div>
  <div class="card"><div class="num" style="color:#e3b341">{vr_summ.get('MISSING',0)}</div><div class="lbl">MISSING</div></div>
  <div class="card"><div class="num" style="color:#8b949e">{vr_summ.get('ERROR',0)}</div><div class="lbl">ERROR</div></div>
</div>
<h2>Evidence Hash Status ({len(ev_list)} items)</h2>
<div class="section">
<table><thead><tr>
  <th>Filename</th><th>Category</th><th>Stored SHA-256</th>
  <th>Last Result</th><th>Current SHA-256</th><th>Verified At</th><th>Notes</th>
</tr></thead>
<tbody>{ev_rows}</tbody></table></div>
<div class="footer">ForensIQ Integrity Report &nbsp;·&nbsp; {format_dual_plain(ts_gen, sep=' / ')} &nbsp;·&nbsp; {_esc(case['case_number'])}</div>
</body></html>"""

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)
    return output_path


def generate_audit_report_html(case_id: int, db: CaseManager,
                                output_path: str,
                                include_all_audit: bool = False) -> str:
    """
    Audit Trail Report: all audit events related to this case.
    include_all_audit=True includes global audit records (cross-case events).
    """
    case = db.get_case(case_id)
    if not case:
        raise ValueError(f"Case {case_id} not found")
    ts_gen = now_utc_str()

    # Fetch audit records referencing this case
    all_trail = list(db.get_audit_trail())
    case_str  = str(case_id)
    # Filter to events targeting this case OR referencing it
    trail = [
        r for r in all_trail
        if str(r["target_id"]) == case_str
        or r["target_type"] in ("case", "evidence", "report")
    ] if not include_all_audit else all_trail

    _result_color = {"OK": "#3fb950", "FAILED": "#f85149", "WARNING": "#e3b341"}
    _action_color_cls = {
        "CASE_CREATED": "#1d9e75", "CASE_MODIFIED": "#a5d6ff",
        "EVIDENCE_ADDED": "#3fb950", "EVIDENCE_REMOVED": "#f85149",
        "VERIFICATION_PASSED": "#3fb950", "VERIFICATION_FAILED": "#f85149",
        "REPORT_GENERATED": "#e3b341", "CUSTODY_ACQUIRED": "#1d9e75",
    }

    rows = "\n".join(
        f"""<tr>
          <td class='mono'>{format_dual_html(r['timestamp'])}</td>
          <td>{_esc(r['user'])}</td>
          <td style='color:{_action_color_cls.get(r["action"],"#a5d6ff")};font-weight:500'>{_esc(r['action'])}</td>
          <td>{_esc(r['target_type'])}</td>
          <td class='mono'>{_esc(r['target_id'])}</td>
          <td style='color:{_result_color.get(r["result"],"#8b949e")};font-weight:600'>{_esc(r['result'])}</td>
          <td>{_esc(r['notes'])}</td>
        </tr>"""
        for r in trail
    ) or "<tr><td colspan='7' style='color:#8b949e'>No audit records for this case.</td></tr>"

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>ForensIQ Audit Report — {_esc(case['case_number'])}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',Arial,sans-serif;background:#0d1117;color:#e6edf3;padding:2rem;font-size:13px;line-height:1.6}}
h1{{color:#1d9e75;font-size:24px;margin-bottom:4px}}
h2{{color:#1d9e75;font-size:12px;margin:1.6rem 0 0.5rem;padding-left:8px;border-left:3px solid #1d9e75;text-transform:uppercase;letter-spacing:.05em}}
.meta{{color:#8b949e;font-size:12px;margin-bottom:1.5rem}}
.notice{{background:#1d9e7510;border:1px solid #1d9e7530;border-radius:6px;padding:8px 12px;font-size:12px;color:#1d9e75;margin-bottom:1rem}}
.section{{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:1rem;overflow-x:auto;margin-bottom:1rem}}
table{{width:100%;border-collapse:collapse;font-size:12px}}
th{{background:#21262d;color:#8b949e;padding:6px 8px;text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.04em;border-bottom:1px solid #30363d}}
td{{padding:5px 8px;border-bottom:1px solid #21262d;vertical-align:middle}}
tr:hover td{{background:#1c2128}}
.mono{{font-family:'Courier New',monospace;font-size:11px}}
.footer{{margin-top:2rem;font-size:11px;color:#484f58;border-top:1px solid #21262d;padding-top:1rem;text-align:center}}
@media print{{body{{background:#fff;color:#000}}th{{background:#eee;color:#333}}}}
</style></head><body>
<h1>🗒️ ForensIQ — Audit Trail Report</h1>
<div class="meta">
  <strong>Case:</strong> {_esc(case['case_number'])} — {_esc(case['title'])} &nbsp;·&nbsp;
  <strong>Investigator:</strong> {_esc(case['investigator'])} &nbsp;·&nbsp;
  <strong>Generated:</strong> {format_dual_plain(ts_gen, sep=' / ')}
</div>
<div class="notice">⚠️ Audit records are immutable — no modification or deletion is possible once written.</div>
<h2>Audit Events ({len(trail)} records)</h2>
<div class="section">
<table><thead><tr>
  <th>Timestamp</th><th>User</th><th>Action</th>
  <th>Target</th><th>Target ID</th><th>Result</th><th>Notes</th>
</tr></thead>
<tbody>{rows}</tbody></table></div>
<div class="footer">ForensIQ Audit Trail Report &nbsp;·&nbsp; {format_dual_plain(ts_gen, sep=' / ')} &nbsp;·&nbsp; Records are immutable.</div>
</body></html>"""

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)
    return output_path


def generate_custody_report_html(case_id: int, db: CaseManager,
                                  output_path: str) -> str:
    """
    Chain of Custody Report: chronological custody chain for every evidence
    item in the case, grouped by evidence item.
    """
    case = db.get_case(case_id)
    if not case:
        raise ValueError(f"Case {case_id} not found")
    ev_list = list(db.get_evidence_for_case(case_id))
    ts_gen  = now_utc_str()

    _action_colors = {
        "ACQUIRED":    "#1d9e75", "STORED":     "#58a6ff",
        "VERIFIED":    "#3fb950", "TRANSFERRED": "#f0883e",
        "ANALYZED":    "#bc8cff", "REPORTED":   "#d2a8ff",
        "REVIEWED":    "#a5d6ff", "EXPORTED":   "#e3b341",
        "ARCHIVED":    "#8b949e", "NOTED":      "#8b949e",
    }
    _integrity_colors = {
        "MATCH": "#3fb950", "MISMATCH": "#f85149", "MISSING": "#e3b341",
        "CORRUPTED": "#f85149", "NOT_VERIFIED": "#8b949e", "ERROR": "#8b949e",
    }

    def _loc_cell(ce) -> str:
        """Phase 2: show explicit From → To for a transfer event."""
        keys = ce.keys()
        fl = ce["from_location"] if "from_location" in keys else ""
        tl = ce["to_location"] if "to_location" in keys else ""
        if fl or tl:
            return f"{_esc(fl or '?')} → {_esc(tl or '?')}"
        return _esc(ce["location"] or "—")

    def _integrity_cell(ce) -> str:
        keys = ce.keys()
        st = ce["integrity_status"] if "integrity_status" in keys else ""
        if not st:
            return "—"
        color = _integrity_colors.get(st, "#8b949e")
        return f"<span style='color:{color};font-weight:600'>{_esc(st)}</span>"

    sections = []
    total_events = 0
    total_transfers = 0
    for ev in ev_list:
        chain = list(db.get_custody_chain(ev["id"]))
        total_events += len(chain)
        total_transfers += sum(1 for ce in chain if ce["action"] == "TRANSFERRED")
        chain_rows = "\n".join(
            f"""<tr>
              <td class='mono'>{format_dual_html(ce['timestamp'])}</td>
              <td>{_esc(ce['investigator'])}</td>
              <td style='color:{_action_colors.get(ce["action"],"#ccc")};font-weight:600'>{_esc(ce['action'])}</td>
              <td>{_loc_cell(ce)}</td>
              <td>{_integrity_cell(ce)}</td>
              <td>{_esc(ce['notes'])}</td>
            </tr>"""
            for ce in chain
        ) or "<tr><td colspan='6' style='color:#8b949e'>No custody events.</td></tr>"
        has_gap = len(chain) == 0

        sections.append(f"""
<div class="ev-section">
  <div class="ev-header">
    <span class="ev-name">{_esc(ev['filename'] or '—')}</span>
    <span class="ev-cat">{_esc(ev['category'])}</span>
    {'<span class="warning">⚠ No custody chain</span>' if has_gap else f'<span class="ok">{len(chain)} event(s)</span>'}
    <span class="mono ev-hash">{_esc((ev['sha256'] or '')[:32])}{"…" if ev['sha256'] else "—"}</span>
  </div>
  <div class="section">
  <table><thead><tr><th>Timestamp</th><th>Investigator</th><th>Action</th><th>Location</th><th>Integrity</th><th>Notes</th></tr></thead>
  <tbody>{chain_rows}</tbody></table>
  </div>
</div>""")


    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>ForensIQ Chain of Custody — {_esc(case['case_number'])}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',Arial,sans-serif;background:#0d1117;color:#e6edf3;padding:2rem;font-size:13px;line-height:1.6}}
h1{{color:#1d9e75;font-size:24px;margin-bottom:4px}}
.meta{{color:#8b949e;font-size:12px;margin-bottom:1.5rem}}
.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:1.5rem}}
.card{{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:1rem;text-align:center}}
.card .num{{font-size:28px;font-weight:700;color:#1d9e75}}
.card .lbl{{font-size:11px;color:#8b949e;margin-top:3px}}
.ev-section{{margin-bottom:1.5rem}}
.ev-header{{background:#161b22;border:1px solid #21262d;border-radius:8px 8px 0 0;padding:10px 14px;display:flex;gap:12px;align-items:center;flex-wrap:wrap}}
.ev-name{{font-weight:600;font-size:13px}}
.ev-cat{{font-size:11px;color:#8b949e;padding:2px 8px;border:1px solid #30363d;border-radius:10px}}
.ev-hash{{font-family:'Courier New',monospace;font-size:10px;color:#8b949e;margin-left:auto}}
.ok{{color:#3fb950;font-size:11px}}
.warning{{color:#e3b341;font-size:11px}}
.section{{background:#161b22;border:1px solid #21262d;border-top:none;border-radius:0 0 8px 8px;padding:0 1rem 1rem;overflow-x:auto}}
table{{width:100%;border-collapse:collapse;font-size:12px}}
th{{background:#21262d;color:#8b949e;padding:6px 8px;text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.04em;border-bottom:1px solid #30363d}}
td{{padding:5px 8px;border-bottom:1px solid #21262d;vertical-align:middle}}
tr:hover td{{background:#1c2128}}
.mono{{font-family:'Courier New',monospace;font-size:11px}}
.footer{{margin-top:2rem;font-size:11px;color:#484f58;border-top:1px solid #21262d;padding-top:1rem;text-align:center}}
@media print{{body{{background:#fff;color:#000}}th{{background:#eee;color:#333}}.ev-header{{background:#eee}}}}
</style></head><body>
<h1>🔗 ForensIQ — Chain of Custody Report</h1>
<div class="meta">
  <strong>Case:</strong> {_esc(case['case_number'])} — {_esc(case['title'])} &nbsp;·&nbsp;
  <strong>Investigator:</strong> {_esc(case['investigator'])} &nbsp;·&nbsp;
  <strong>Generated:</strong> {format_dual_plain(ts_gen, sep=' / ')}
</div>
<div class="grid">
  <div class="card"><div class="num">{len(ev_list)}</div><div class="lbl">Evidence Items</div></div>
  <div class="card"><div class="num">{total_events}</div><div class="lbl">Custody Events</div></div>
  <div class="card"><div class="num">{total_transfers}</div><div class="lbl">Transfers</div></div>
  <div class="card"><div class="num">{sum(1 for ev in ev_list if list(db.get_custody_chain(ev["id"])))}</div><div class="lbl">Items with Full Chain</div></div>
</div>
{"".join(sections) or "<p style='color:#8b949e'>No evidence items in this case.</p>"}
<div class="footer">ForensIQ Chain of Custody Report &nbsp;·&nbsp; {format_dual_plain(ts_gen, sep=' / ')} &nbsp;·&nbsp; {_esc(case['case_number'])}</div>
</body></html>"""

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)
    return output_path


def generate_executive_report(case_id: int, db: CaseManager,
                               output_path: str) -> str:
    """
    Executive Report: high-level summary for non-technical stakeholders.
    One page. No raw hashes. Status indicators only.
    """
    case     = db.get_case(case_id)
    if not case:
        raise ValueError(f"Case {case_id} not found")
    ev_count = db.get_evidence_count(case_id)
    an_count = len(db.get_analysis_results(case_id))
    vr_summ  = db.get_verification_summary(case_id)
    devices  = list(db.get_devices_for_case(case_id))
    ts_gen   = now_utc_str()
    st_color = "#3fb950" if str(case["status"]).upper() == "ACTIVE" else "#8b949e"

    integrity_ok  = vr_summ.get("PASS", 0)
    integrity_bad = vr_summ.get("FAIL", 0) + vr_summ.get("MISSING", 0) + vr_summ.get("ERROR", 0)
    integrity_status = "✅ All Verified" if integrity_bad == 0 and integrity_ok > 0 \
                       else ("⚠️ Issues Found" if integrity_bad > 0 else "🔲 Not Yet Verified")
    integrity_color  = "#3fb950" if integrity_bad == 0 and integrity_ok > 0 \
                       else ("#f85149" if integrity_bad > 0 else "#8b949e")

    analysis_results = list(db.get_analysis_results(case_id))
    suspicious_apps = 0
    for ar in analysis_results:
        import json as _json
        try:
            data = _json.loads(ar["result_data"] or "{}")
            suspicious_apps += data.get("summary", {}).get("suspicious", 0)
        except Exception:
            pass

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>ForensIQ Executive Report — {_esc(case['case_number'])}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',Arial,sans-serif;background:#0d1117;color:#e6edf3;padding:2rem;font-size:14px;line-height:1.7}}
.logo{{color:#1d9e75;font-size:22px;font-weight:700;margin-bottom:4px}}
.sub{{color:#8b949e;font-size:12px;margin-bottom:1.5rem}}
h2{{color:#1d9e75;font-size:14px;margin:2rem 0 0.8rem;padding-left:10px;border-left:3px solid #1d9e75;text-transform:uppercase;letter-spacing:.05em}}
.header-block{{background:#161b22;border:1px solid #21262d;border-radius:10px;padding:1.5rem;margin-bottom:1.5rem}}
.header-block .case-num{{font-size:20px;font-weight:700;color:#1d9e75}}
.header-block .case-title{{font-size:16px;color:#e6edf3;margin:4px 0}}
.header-block .meta{{color:#8b949e;font-size:12px}}
.badge{{display:inline-block;padding:3px 12px;border-radius:10px;font-size:12px;font-weight:600;border:1px solid {st_color}40;color:{st_color};background:{st_color}15}}
.grid4{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:1.5rem}}
.grid2{{display:grid;grid-template-columns:repeat(2,1fr);gap:12px;margin-bottom:1.5rem}}
.card{{background:#161b22;border:1px solid #21262d;border-radius:10px;padding:1.2rem;text-align:center}}
.card .icon{{font-size:24px;margin-bottom:6px}}
.card .num{{font-size:30px;font-weight:700;color:#1d9e75}}
.card .lbl{{font-size:12px;color:#8b949e;margin-top:4px}}
.status-card{{background:#161b22;border:1px solid #21262d;border-radius:10px;padding:1.2rem;display:flex;align-items:center;gap:12px}}
.status-icon{{font-size:28px}}
.status-text .title{{font-weight:600;font-size:14px}}
.status-text .desc{{color:#8b949e;font-size:12px;margin-top:2px}}
.section-box{{background:#161b22;border:1px solid #21262d;border-radius:10px;padding:1.2rem;margin-bottom:1rem}}
.row{{display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid #21262d}}
.row:last-child{{border-bottom:none}}
.footer{{margin-top:2rem;font-size:11px;color:#484f58;border-top:1px solid #21262d;padding-top:1rem;text-align:center}}
@media print{{body{{background:#fff;color:#000}}.card,.section-box,.header-block,.status-card{{background:#f6f8fa;border:1px solid #d0d7de}}}}
</style></head><body>
<div class="logo">ForensIQ</div>
<div class="sub">Executive Investigation Report &nbsp;·&nbsp; {format_dual_plain(ts_gen, sep=' / ')}</div>

<div class="header-block">
  <div class="case-num">{_esc(case['case_number'])}</div>
  <div class="case-title">{_esc(case['title'])}</div>
  <div class="meta">
    <strong>Investigator:</strong> {_esc(case['investigator'])} &nbsp;·&nbsp;
    <strong>Status:</strong> <span class="badge">{_esc(case['status']).upper()}</span> &nbsp;·&nbsp;
    <strong>Opened:</strong> {format_dual_plain(case['created_at'], sep=' / ')}
  </div>
</div>

<h2>Investigation Summary</h2>
<div class="grid4">
  <div class="card"><div class="icon">📱</div><div class="num">{len(devices)}</div><div class="lbl">Devices Examined</div></div>
  <div class="card"><div class="icon">📁</div><div class="num">{ev_count}</div><div class="lbl">Evidence Items</div></div>
  <div class="card"><div class="icon">🔬</div><div class="num">{an_count}</div><div class="lbl">Analysis Runs</div></div>
  <div class="card"><div class="icon">⚠️</div><div class="num" style="color:#f85149">{suspicious_apps}</div><div class="lbl">Suspicious Apps</div></div>
</div>

<h2>Key Findings</h2>
<div class="grid2">
  <div class="status-card">
    <div class="status-icon">{'✅' if integrity_bad == 0 and integrity_ok > 0 else '⚠️' if integrity_bad > 0 else '🔲'}</div>
    <div class="status-text">
      <div class="title" style="color:{integrity_color}">{integrity_status}</div>
      <div class="desc">{integrity_ok} evidence items hash-verified · {integrity_bad} issue(s)</div>
    </div>
  </div>
  <div class="status-card">
    <div class="status-icon">{'✅' if suspicious_apps == 0 else '🚨'}</div>
    <div class="status-text">
      <div class="title" style="color:{'#3fb950' if suspicious_apps == 0 else '#f85149'}">
        {'No Suspicious Apps' if suspicious_apps == 0 else f'{suspicious_apps} Suspicious App(s) Found'}
      </div>
      <div class="desc">Based on application analysis results</div>
    </div>
  </div>
</div>

<h2>Case Details</h2>
<div class="section-box">
  <div class="row"><span style="color:#8b949e">Description</span><span>{_esc((case['description'] or '—')[:120])}</span></div>
  <div class="row"><span style="color:#8b949e">Devices</span><span>{", ".join(_esc(d["manufacturer"]+" "+d["model"]) for d in devices) or "—"}</span></div>
  <div class="row"><span style="color:#8b949e">Hash Verification</span><span>{integrity_ok} PASS · {integrity_bad} ISSUE(S)</span></div>
  <div class="row"><span style="color:#8b949e">Investigator</span><span>{_esc(case['investigator'])}</span></div>
  <div class="row"><span style="color:#8b949e">Report Generated</span><span>{format_dual_plain(ts_gen, sep=' / ')}</span></div>
</div>

<div class="footer">ForensIQ Executive Report &nbsp;·&nbsp; {format_dual_plain(ts_gen, sep=' / ')} &nbsp;·&nbsp; CONFIDENTIAL</div>
</body></html>"""

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)
    return output_path


def generate_evidence_summary_report(case_id: int, db: CaseManager,
                                      output_path: str) -> str:
    """
    Evidence Summary Report: a dedicated per-item inventory of every evidence
    item in the case, grouped by category, with filename, SHA-256, size,
    and acquisition timestamp. Distinct from Case Summary, which shows only
    an aggregate evidence count.
    """
    case = db.get_case(case_id)
    if not case:
        raise ValueError(f"Case {case_id} not found")
    ev_list = list(db.get_evidence_for_case(case_id))
    ts_gen  = now_utc_str()

    def _human_size(n: int) -> str:
        n = n or 0
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if n < 1024:
                return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
            n /= 1024
        return f"{n:.1f} PB"

    # Group by category
    by_category: dict = {}
    total_size = 0
    for ev in ev_list:
        cat = ev["category"] or "uncategorized"
        by_category.setdefault(cat, []).append(ev)
        total_size += ev["file_size"] or 0

    cat_colors = {
        "acquisition": "#3fb950", "apps": "#a5d6ff", "contacts": "#e3b341",
        "sms": "#f0883e", "calls": "#f0883e", "media": "#1d9e75",
    }

    sections = []
    for cat in sorted(by_category.keys()):
        items = by_category[cat]
        cat_size = sum(e["file_size"] or 0 for e in items)
        color = cat_colors.get(cat, "#8b949e")
        rows = "\n".join(
            f"""<tr>
              <td>{_esc(e['filename'] or '—')}</td>
              <td class='mono'>{_esc((e['sha256'] or '')[:32])}{'…' if e['sha256'] else '—'}</td>
              <td>{_human_size(e['file_size'])}</td>
              <td class='mono'>{format_dual_html(e['acquired_at'])}</td>
            </tr>"""
            for e in items
        )
        sections.append(f"""
<div class="cat-section">
  <div class="cat-header">
    <span class="cat-badge" style="color:{color};background:{color}18;border:1px solid {color}33">{_esc(cat.upper())}</span>
    <span class="cat-count">{len(items)} item(s)</span>
    <span class="cat-size">{_human_size(cat_size)}</span>
  </div>
  <div class="section">
  <table><thead><tr><th>Filename</th><th>SHA-256</th><th>Size</th><th>Acquired</th></tr></thead>
  <tbody>{rows}</tbody></table>
  </div>
</div>""")

    hashed_count   = sum(1 for e in ev_list if e["sha256"])
    unhashed_count = len(ev_list) - hashed_count

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>ForensIQ Evidence Summary — {_esc(case['case_number'])}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',Arial,sans-serif;background:#0d1117;color:#e6edf3;padding:2rem;font-size:13px;line-height:1.6}}
h1{{color:#1d9e75;font-size:24px;margin-bottom:4px}}
.meta{{color:#8b949e;font-size:12px;margin-bottom:1.5rem}}
.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:1.5rem}}
.card{{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:1rem;text-align:center}}
.card .num{{font-size:28px;font-weight:700;color:#1d9e75}}
.card .lbl{{font-size:11px;color:#8b949e;margin-top:3px}}
.cat-section{{margin-bottom:1.2rem}}
.cat-header{{background:#161b22;border:1px solid #21262d;border-radius:8px 8px 0 0;padding:8px 14px;display:flex;gap:12px;align-items:center}}
.cat-badge{{font-size:11px;font-weight:700;padding:2px 10px;border-radius:10px;letter-spacing:.04em}}
.cat-count{{font-size:12px;color:#8b949e}}
.cat-size{{font-size:12px;color:#8b949e;margin-left:auto}}
.section{{background:#161b22;border:1px solid #21262d;border-top:none;border-radius:0 0 8px 8px;padding:0 1rem 0.5rem;overflow-x:auto}}
table{{width:100%;border-collapse:collapse;font-size:12px}}
th{{background:#21262d;color:#8b949e;padding:6px 8px;text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.04em;border-bottom:1px solid #30363d}}
td{{padding:5px 8px;border-bottom:1px solid #21262d;vertical-align:middle}}
tr:hover td{{background:#1c2128}}
.mono{{font-family:'Courier New',monospace;font-size:11px}}
.footer{{margin-top:2rem;font-size:11px;color:#484f58;border-top:1px solid #21262d;padding-top:1rem;text-align:center}}
@media print{{body{{background:#fff;color:#000}}th{{background:#eee;color:#333}}.cat-header{{background:#eee}}}}
</style></head><body>
<h1>📦 ForensIQ — Evidence Summary</h1>
<div class="meta">
  <strong>Case:</strong> {_esc(case['case_number'])} — {_esc(case['title'])} &nbsp;·&nbsp;
  <strong>Investigator:</strong> {_esc(case['investigator'])} &nbsp;·&nbsp;
  <strong>Generated:</strong> {format_dual_plain(ts_gen, sep=' / ')}
</div>
<div class="grid">
  <div class="card"><div class="num">{len(ev_list)}</div><div class="lbl">Total Items</div></div>
  <div class="card"><div class="num">{len(by_category)}</div><div class="lbl">Categories</div></div>
  <div class="card"><div class="num" style="color:#3fb950">{hashed_count}</div><div class="lbl">Hashed</div></div>
  <div class="card"><div class="num" style="color:{'#f85149' if unhashed_count else '#3fb950'}">{unhashed_count}</div><div class="lbl">Not Hashed</div></div>
</div>
{"".join(sections) or "<p style='color:#8b949e'>No evidence items in this case.</p>"}
<div class="footer">ForensIQ Evidence Summary &nbsp;·&nbsp; {format_dual_plain(ts_gen, sep=' / ')} &nbsp;·&nbsp; Total size: {_human_size(total_size)}</div>
</body></html>"""

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)
    return output_path


def generate_case_evidence_manifest_report(case_id: int, db: CaseManager,
                                            output_path: str) -> str:
    """
    Phase 4 — Case Evidence Manifest Report (standalone HTML).

    One row per evidence item, resolving Case -> Device -> Acquisition
    Session -> Evidence, with the collector/investigator and integrity
    status (recorded vs. last-verified SHA-256). Built entirely from
    manifest_service.build_manifest(), which itself only reads existing
    Phase 1-3 tables — nothing here duplicates or rewrites evidence data.
    Legacy evidence with no resolvable device/session is shown as such,
    never fabricated.
    """
    case = db.get_case(case_id)
    if not case:
        raise ValueError(f"Case {case_id} not found")

    manifest = build_manifest(case_id, db)
    items    = manifest["items"]
    ts_gen   = manifest["generated_at"]

    def _human_size(n) -> str:
        n = n or 0
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if n < 1024:
                return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
            n /= 1024
        return f"{n:.1f} PB"

    STATUS_COLORS = {
        "MATCH": "#3fb950", "MISMATCH": "#f85149", "MISSING": "#e3b341",
        "CORRUPTED": "#f85149", "NOT_VERIFIED": "#8b949e", "ERROR": "#8b949e",
    }
    DEFAULT_COLOR = "#8b949e"

    rows = "\n".join(
        f"""<tr>
          <td>{_esc(it['evidence_id'])}</td>
          <td>{_esc(it['filename'] or '—')}</td>
          <td>{_esc(it['category'] or '—')}</td>
          <td>{_human_size(it['file_size'])}</td>
          <td class='mono'>{_esc((it['recorded_sha256'] or '')[:32])}{'…' if it['recorded_sha256'] else '—'}</td>
          <td class='mono'>{format_dual_html(it['acquired_at'])}</td>
          <td>{_esc(f"{it['device_model']} ({it['device_serial']})" if it['device_serial'] else '— (legacy)')}</td>
          <td>{_esc(f"#{it['session_id']}") if it['session_id'] else '— (legacy)'}</td>
          <td>{_esc(it['collector'] or '—')}{' <span class="src">(case-level)</span>' if it['collector_source'] == 'case_investigator' else ''}</td>
          <td class='mono' style='font-size:10px'>{_esc(it['storage_location'] or '—')}</td>
          <td><span class="badge" style="color:{STATUS_COLORS.get(it['integrity_status'], DEFAULT_COLOR)};background:{STATUS_COLORS.get(it['integrity_status'], DEFAULT_COLOR)}18;border:1px solid {STATUS_COLORS.get(it['integrity_status'], DEFAULT_COLOR)}33">{_esc(it['integrity_status'])}</span></td>
        </tr>"""
        for it in items
    )

    integrity_summary = " &nbsp;·&nbsp; ".join(
        f"<span style='color:{STATUS_COLORS.get(k, DEFAULT_COLOR)}'>{_esc(k)}: {v}</span>"
        for k, v in sorted(manifest["integrity_counts"].items())
    ) or "—"

    legacy_note = ""
    if manifest["legacy_items"]:
        legacy_note = (
            "<p class='legacy-note'>&#9888; "
            f"{manifest['legacy_items']} item(s) have no device/acquisition-session "
            "on record (added before Phase 3 tracking, or imported manually) — "
            "shown as \u201c\u2014 (legacy)\u201d, never invented.</p>"
        )

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>ForensIQ Case Evidence Manifest — {_esc(case['case_number'])}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',Arial,sans-serif;background:#0d1117;color:#e6edf3;padding:2rem;font-size:13px;line-height:1.6}}
h1{{color:#1d9e75;font-size:24px;margin-bottom:4px}}
.meta{{color:#8b949e;font-size:12px;margin-bottom:1rem}}
.grid{{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-bottom:1.2rem}}
.card{{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:1rem;text-align:center}}
.card .num{{font-size:24px;font-weight:700;color:#1d9e75}}
.card .lbl{{font-size:11px;color:#8b949e;margin-top:3px}}
.integrity-line{{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:0.7rem 1rem;margin-bottom:1.2rem;font-size:12px}}
.section{{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:0 1rem 0.5rem;overflow-x:auto}}
table{{width:100%;border-collapse:collapse;font-size:11.5px}}
th{{background:#21262d;color:#8b949e;padding:6px 8px;text-align:left;font-size:10.5px;text-transform:uppercase;letter-spacing:.03em;border-bottom:1px solid #30363d;white-space:nowrap}}
td{{padding:5px 8px;border-bottom:1px solid #21262d;vertical-align:middle}}
tr:hover td{{background:#1c2128}}
.mono{{font-family:'Courier New',monospace;font-size:11px;word-break:break-all}}
.badge{{font-size:10px;font-weight:700;padding:2px 8px;border-radius:10px}}
.src{{color:#8b949e;font-size:10px}}
.footer{{margin-top:2rem;font-size:11px;color:#484f58;border-top:1px solid #21262d;padding-top:1rem;text-align:center}}
.legacy-note{{color:#e3b341;font-size:11.5px;margin:0.6rem 0}}
@media print{{body{{background:#fff;color:#000}}th{{background:#eee;color:#333}}}}
</style></head><body>
<h1>🧾 ForensIQ — Case Evidence Manifest</h1>
<div class="meta">
  <strong>Case:</strong> {_esc(case['case_number'])} — {_esc(case['title'])} &nbsp;·&nbsp;
  <strong>Investigator:</strong> {_esc(case['investigator'])} &nbsp;·&nbsp;
  <strong>Generated:</strong> {_esc(ts_gen)}
</div>
<div class="grid">
  <div class="card"><div class="num">{manifest['total_items']}</div><div class="lbl">Evidence Items</div></div>
  <div class="card"><div class="num">{manifest['devices_referenced']}</div><div class="lbl">Devices Referenced</div></div>
  <div class="card"><div class="num">{manifest['sessions_referenced']}</div><div class="lbl">Sessions Referenced</div></div>
  <div class="card"><div class="num" style="color:{'#e3b341' if manifest['legacy_items'] else '#3fb950'}">{manifest['legacy_items']}</div><div class="lbl">Legacy Items</div></div>
  <div class="card"><div class="num">{len(manifest['integrity_counts'])}</div><div class="lbl">Integrity States</div></div>
</div>
<div class="integrity-line"><strong>Integrity Status Breakdown:</strong> &nbsp;{integrity_summary}</div>
{legacy_note}
<div class="section">
<table>
<thead><tr>
  <th>Evidence ID</th><th>Filename</th><th>Category</th><th>Size</th>
  <th>SHA-256</th><th>Acquired</th><th>Source Device</th><th>Session</th>
  <th>Collector</th><th>Storage Location</th><th>Integrity</th>
</tr></thead>
<tbody>{rows or "<tr><td colspan='11' style='text-align:center;color:#8b949e;padding:1.2rem'>No evidence items in this case.</td></tr>"}</tbody>
</table>
</div>
<div class="footer">ForensIQ Case Evidence Manifest &nbsp;·&nbsp; {_esc(ts_gen)} &nbsp;·&nbsp; Case ID {manifest['case_id']}</div>
</body></html>"""

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)
    return output_path
