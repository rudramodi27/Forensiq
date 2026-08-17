"""
AuditService — Forensic Audit Trail & Chain of Custody Service.

Provides:
  log_*()            : one method per auditable system event
  add_custody_event(): forward to CaseManager with validation
  export_audit_json / export_audit_html
  export_custody_json / export_custody_html

Design principles:
  - All log methods are fire-and-forget (never raise to callers).
  - audit_trail rows are IMMUTABLE — no update/delete ever.
  - custody_events survive case/evidence deletion (ON DELETE SET NULL FK).
  - Panels call mw.audit.log_X() right after db.X(); no signatures changed.
"""

import json
import logging
import os
import html as html_lib
from datetime import datetime, timezone
from typing import Optional

from forensiq.core.case_manager import CaseManager
from forensiq.core.time_utils import now_utc_str

logger = logging.getLogger("forensiq.audit")


# ── Action constants (audit_trail) ─────────────────────────────────────────────

A_CASE_CREATED       = "CASE_CREATED"
A_CASE_MODIFIED      = "CASE_MODIFIED"
A_CASE_STATUS        = "CASE_STATUS_CHANGED"
A_CASE_DELETED       = "CASE_DELETED"
A_EVIDENCE_ADDED     = "EVIDENCE_ADDED"
A_EVIDENCE_REMOVED   = "EVIDENCE_REMOVED"
A_EVIDENCE_VERIFIED  = "EVIDENCE_VERIFIED"
A_EVIDENCE_STORED    = "EVIDENCE_STORED"
A_EVIDENCE_ANALYZED  = "EVIDENCE_ANALYZED"
A_EVIDENCE_REPORTED  = "EVIDENCE_REPORTED"
A_VERIFICATION_PASS      = "VERIFICATION_PASSED"
A_VERIFICATION_FAIL      = "VERIFICATION_FAILED"
A_VERIFICATION_MISS      = "VERIFICATION_MISSING"
A_VERIFICATION_CORRUPTED = "VERIFICATION_CORRUPTED"
A_REPORT_GENERATED   = "REPORT_GENERATED"
A_NOTES_CREATED      = "NOTES_CREATED"
A_NOTES_EDITED       = "NOTES_EDITED"
A_NOTES_DELETED      = "NOTES_DELETED"
A_CUSTODY_TRANSFER   = "CUSTODY_TRANSFERRED"
A_CUSTODY_EXPORT     = "EVIDENCE_EXPORTED"
A_ARTIFACT_SIGNED           = "ARTIFACT_SIGNED"
A_SIGNATURE_VERIFIED        = "SIGNATURE_VERIFIED"
A_SIGNATURE_VERIFY_FAILED   = "SIGNATURE_VERIFICATION_FAILED"

# Result constants
R_OK      = "OK"
R_FAILED  = "FAILED"
R_WARNING = "WARNING"

_RESULT_COLOR = {R_OK: "#3FB950", R_FAILED: "#F85149", R_WARNING: "#E3B341"}


def _esc(v) -> str:
    return html_lib.escape(str(v or ""))


# Phase 10: was a locally-formatted datetime.now(timezone.utc) one-liner;
# now delegates to the single centralized clock in time_utils.
def _ts() -> str:
    return now_utc_str()


class AuditService:
    """
    Thin wrapper that:
      1. Writes to audit_trail via CaseManager.add_audit_event()
      2. Writes to custody_events via CaseManager.add_custody_event()
      3. Provides structured log_*() helpers for every auditable event
      4. Provides export_*() methods for JSON and HTML reports

    Never raises — all DB errors are logged but swallowed so callers
    (UI panels) are never disrupted by audit failures.
    """

    def __init__(self, db: CaseManager):
        self.db = db

    # ── Internal helper ────────────────────────────────────────────────────────

    def _log(self, action: str, user: str = "", target_type: str = "",
             target_id=None, result: str = R_OK, notes: str = ""):
        try:
            self.db.add_audit_event(
                action=action, user=user or "",
                target_type=target_type, target_id=target_id,
                result=result, notes=notes,
            )
            level = logging.WARNING if result == R_FAILED else logging.INFO
            logger.log(level, "AUDIT  %s  user=%s  target=%s/%s  result=%s  %s",
                       action, user, target_type, target_id, result, notes)
        except Exception as e:
            logger.error("Audit write failed: %s", e)

    # ── Case events ────────────────────────────────────────────────────────────

    def log_case_created(self, case_id: int, investigator: str,
                         case_number: str):
        self._log(A_CASE_CREATED, user=investigator,
                  target_type="case", target_id=case_id,
                  notes=f"Case number: {case_number}")

    def log_case_modified(self, case_id: int, investigator: str,
                          fields_changed: str = ""):
        self._log(A_CASE_MODIFIED, user=investigator,
                  target_type="case", target_id=case_id,
                  notes=fields_changed or "")

    def log_case_status_changed(self, case_id: int, investigator: str,
                                new_status: str,
                                previous_status: Optional[str] = None,
                                closure_reason: Optional[str] = None):
        """
        Phase 8: previous_status/closure_reason are optional/keyword-only
        so every pre-Phase-8 caller (positional case_id/investigator/
        new_status only) behaves identically. When given, they're folded
        into the same audit_trail row's notes — this is still the single
        existing audit event for a status change; nothing new is added to
        the audit/timeline pipeline itself.
        """
        notes = f"New status: {new_status}"
        if previous_status:
            notes = f"Status changed: {previous_status} -> {new_status}"
        if closure_reason:
            notes += f"  Closure reason: {closure_reason}"
        self._log(A_CASE_STATUS, user=investigator,
                  target_type="case", target_id=case_id,
                  notes=notes)

    def log_case_deleted(self, case_id: int, investigator: str,
                         case_number: str):
        self._log(A_CASE_DELETED, user=investigator,
                  target_type="case", target_id=case_id,
                  result=R_WARNING,
                  notes=f"Deleted case: {case_number}")

    # ── Evidence events ────────────────────────────────────────────────────────

    def log_evidence_added(self, case_id: int, evidence_id: int,
                           investigator: str, filename: str,
                           category: str = "", filepath: str = ""):
        self._log(A_EVIDENCE_ADDED, user=investigator,
                  target_type="evidence", target_id=evidence_id,
                  notes=f"File: {filename}  Category: {category}  Case: {case_id}")
        # Auto-create ACQUIRED custody event
        try:
            self.db.add_custody_event(
                case_id=case_id, evidence_id=evidence_id,
                investigator=investigator, action="ACQUIRED",
                notes=f"Acquired: {filename}",
            )
        except Exception as e:
            logger.error("Custody event write failed: %s", e)

        # Phase 2: once the file genuinely exists on disk in the case's
        # managed evidence directory, the item has also reached the
        # STORED stage of the lifecycle. This is tied to a real,
        # checkable condition (the file is actually there) rather than
        # assumed — if filepath isn't given or the file isn't found,
        # no STORED event is fabricated.
        if filepath and os.path.exists(filepath):
            self._log(A_EVIDENCE_STORED, user=investigator,
                      target_type="evidence", target_id=evidence_id,
                      notes=f"Stored: {filepath}")
            try:
                self.db.add_custody_event(
                    case_id=case_id, evidence_id=evidence_id,
                    investigator=investigator, action="STORED",
                    location=os.path.dirname(filepath),
                    notes=f"Stored on disk: {filename}",
                )
            except Exception as e:
                logger.error("Custody event (stored) write failed: %s", e)

    def log_evidence_removed(self, case_id: int, evidence_id: int,
                             investigator: str, filename: str):
        self._log(A_EVIDENCE_REMOVED, user=investigator,
                  target_type="evidence", target_id=evidence_id,
                  result=R_WARNING,
                  notes=f"Removed: {filename}  Case: {case_id}")

    # ── Verification events ────────────────────────────────────────────────────

    def log_verification(self, case_id: int, evidence_id: int,
                         investigator: str, result: str,
                         filename: str = "", stored_hash: str = ""):
        """
        result is the integrity engine result. Accepts both the canonical
        Phase 1 vocabulary (MATCH | MISMATCH | MISSING | CORRUPTED | ERROR)
        and the legacy pre-Phase-1 vocabulary (PASS | FAIL | MISSING |
        ERROR) so callers on either version behave identically.
        NOT_VERIFIED is not an event and is never passed here.
        """
        action_map = {
            "MATCH":     A_VERIFICATION_PASS,
            "MISMATCH":  A_VERIFICATION_FAIL,
            "MISSING":   A_VERIFICATION_MISS,
            "CORRUPTED": A_VERIFICATION_CORRUPTED,
            "ERROR":     A_VERIFICATION_FAIL,
            # Legacy aliases
            "PASS":      A_VERIFICATION_PASS,
            "FAIL":      A_VERIFICATION_FAIL,
        }
        audit_result_map = {
            "MATCH":     R_OK,
            "MISMATCH":  R_FAILED,
            "MISSING":   R_WARNING,
            "CORRUPTED": R_FAILED,
            "ERROR":     R_FAILED,
            # Legacy aliases
            "PASS":      R_OK,
            "FAIL":      R_FAILED,
        }
        action     = action_map.get(result, A_EVIDENCE_VERIFIED)
        audit_res  = audit_result_map.get(result, R_WARNING)
        self._log(action, user=investigator,
                  target_type="evidence", target_id=evidence_id,
                  result=audit_res,
                  notes=f"File: {filename}  IntegrityResult: {result}")
        # Auto-create VERIFIED custody event
        try:
            self.db.add_custody_event(
                case_id=case_id, evidence_id=evidence_id,
                investigator=investigator, action="VERIFIED",
                notes=f"Integrity check: {result}  File: {filename}",
                integrity_status=result,
            )
        except Exception as e:
            logger.error("Custody event (verify) failed: %s", e)

    # ── Analysis events ────────────────────────────────────────────────────────

    def log_analysis_performed(self, case_id: int, investigator: str,
                               analysis_type: str, summary: str = "",
                               evidence_id: Optional[int] = None):
        """
        Phase 2 — records an ANALYZED lifecycle event. evidence_id is
        optional since most analysis tasks (duplicate detection, app
        classification, timeline building, etc.) run across the whole
        case rather than one specific evidence item — in that case the
        custody event is recorded at the case level (evidence_id=None),
        same pattern already used for REVIEWED/EXPORTED case-wide events.
        """
        self._log(A_EVIDENCE_ANALYZED, user=investigator,
                  target_type="evidence" if evidence_id else "case",
                  target_id=evidence_id or case_id,
                  notes=f"Type: {analysis_type}  {summary}  Case: {case_id}")
        try:
            self.db.add_custody_event(
                case_id=case_id, evidence_id=evidence_id,
                investigator=investigator, action="ANALYZED",
                notes=f"Analysis: {analysis_type} — {summary}",
            )
        except Exception as e:
            logger.error("Custody event (analyzed) failed: %s", e)

    # ── Report events ──────────────────────────────────────────────────────────

    def log_report_generated(self, case_id: int, investigator: str,
                             report_type: str, path: str = ""):
        self._log(A_REPORT_GENERATED, user=investigator,
                  target_type="report", target_id=case_id,
                  notes=f"Type: {report_type}  Path: {os.path.basename(path)}")
        # Auto-create EXPORTED + REPORTED custody events for all evidence
        # in the case. EXPORTED is kept for backward compatibility with
        # pre-Phase-2 data/consumers; REPORTED is the Phase 2 canonical
        # lifecycle stage. Each REPORTED event snapshots the evidence's
        # real last-known integrity state (never invented) so a reader of
        # the custody chain can see what the integrity status was at the
        # moment it went into a report.
        try:
            evs = self.db.get_evidence_for_case(case_id)
            for ev in evs:
                integrity_status = "NOT_VERIFIED"
                try:
                    from forensiq.core.integrity_engine import normalize_status
                    last = self.db.get_last_verification(ev["id"])
                    if last:
                        integrity_status = normalize_status(last["result"])
                except Exception:
                    pass
                self.db.add_custody_event(
                    case_id=case_id, evidence_id=ev["id"],
                    investigator=investigator, action="EXPORTED",
                    notes=f"Included in {report_type} report",
                )
                self.db.add_custody_event(
                    case_id=case_id, evidence_id=ev["id"],
                    investigator=investigator, action="REPORTED",
                    notes=f"Included in {report_type} report",
                    integrity_status=integrity_status,
                )
        except Exception as e:
            logger.error("Custody export events failed: %s", e)

    # ── Digital Signature events (Phase 5) ─────────────────────────────────────

    def log_artifact_signed(self, case_id: Optional[int], investigator: str,
                            artifact_type: str, artifact_path: str,
                            key_id: str = ""):
        """
        Records that an artifact (Manifest or Report) was signed. Only
        the artifact filename, type, and key_id (a public fingerprint)
        are recorded — never the private key or signature bytes.
        """
        self._log(A_ARTIFACT_SIGNED, user=investigator,
                  target_type="signature", target_id=case_id,
                  notes=(f"Type: {artifact_type}  "
                         f"File: {os.path.basename(artifact_path)}  "
                         f"Key: {key_id}"))

    def log_signature_verified(self, case_id: Optional[int], investigator: str,
                               artifact_type: str, artifact_path: str,
                               status: str):
        """
        Records a signature verification outcome. `status` is one of
        VALID / INVALID / MODIFIED / MISSING / KEY_UNAVAILABLE (see
        signature_service.py). VALID is logged as SIGNATURE_VERIFIED
        with an OK result; every other status is logged as
        SIGNATURE_VERIFICATION_FAILED so a failed/inconclusive
        verification is never recorded as a plain success.
        """
        detail = (f"Type: {artifact_type}  "
                  f"File: {os.path.basename(artifact_path)}  "
                  f"Status: {status}")
        if status == "VALID":
            self._log(A_SIGNATURE_VERIFIED, user=investigator,
                      target_type="signature", target_id=case_id,
                      result=R_OK, notes=detail)
        else:
            audit_result = R_WARNING if status == "MISSING" else R_FAILED
            self._log(A_SIGNATURE_VERIFY_FAILED, user=investigator,
                      target_type="signature", target_id=case_id,
                      result=audit_result, notes=detail)

    # ── Notes events ───────────────────────────────────────────────────────────

    def log_notes_created(self, case_id: int, investigator: str):
        self._log(A_NOTES_CREATED, user=investigator,
                  target_type="case", target_id=case_id)

    def log_notes_edited(self, case_id: int, investigator: str):
        self._log(A_NOTES_EDITED, user=investigator,
                  target_type="case", target_id=case_id)

    # ── Manual custody helpers (called from CustodyPanel) ─────────────────────

    def add_custody_event(self, case_id: int, evidence_id: Optional[int],
                          investigator: str, action: str,
                          location: str = "", notes: str = "",
                          from_location: str = "", to_location: str = "",
                          integrity_status: Optional[str] = None) -> int:
        """
        Thin validated wrapper — also writes an AUDIT log entry.

        Phase 2: when recording a TRANSFERRED event with a source and/or
        destination, this delegates to CaseManager.add_transfer_event()
        so the transfer's integrity snapshot is captured from the
        evidence's real last verification result when the caller doesn't
        supply one explicitly (never fabricated).
        """
        action_upper = (action or "").upper()
        if action_upper == "TRANSFERRED" and (from_location or to_location or location):
            eid = self.db.add_transfer_event(
                case_id=case_id, evidence_id=evidence_id,
                investigator=investigator,
                from_location=from_location,
                to_location=to_location or location,
                reason=notes,
                integrity_status=integrity_status,
            )
        else:
            eid = self.db.add_custody_event(
                case_id=case_id, evidence_id=evidence_id,
                investigator=investigator, action=action,
                location=location, notes=notes,
                from_location=from_location, to_location=to_location,
                integrity_status=integrity_status or "",
            )
        detail = f"Action: {action_upper}  Location: {location}  {notes}"
        if from_location or to_location:
            detail += f"  From: {from_location}  To: {to_location}"
        self._log(f"CUSTODY_{action_upper}", user=investigator,
                  target_type="evidence", target_id=evidence_id,
                  notes=detail)
        return eid

    def log_transfer(self, case_id: int, evidence_id: Optional[int],
                     investigator: str, from_location: str,
                     to_location: str, reason: str = "") -> int:
        """
        Phase 2 requirement 3 — Evidence Transfer. Convenience wrapper
        around add_custody_event() for the common "record a transfer"
        case. Never modifies the evidence file — only writes the custody
        record, with the evidence's real integrity state at transfer time
        captured automatically.
        """
        return self.add_custody_event(
            case_id=case_id, evidence_id=evidence_id,
            investigator=investigator, action="TRANSFERRED",
            from_location=from_location, to_location=to_location,
            notes=reason,
        )

    # ── Audit Trail exports ────────────────────────────────────────────────────

    def export_audit_json(self, records: list, output_path: str,
                          title: str = "ForensIQ Audit Trail") -> str:
        payload = {
            "report_type": title,
            "generated_at": _ts(),
            "total": len(records),
            "records": [dict(r) for r in records],
        }
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, default=str)
        logger.info("Audit JSON written: %s", output_path)
        return output_path

    def export_audit_html(self, records: list, output_path: str,
                          title: str = "ForensIQ Audit Trail") -> str:
        records = [dict(r) if not isinstance(r, dict) else r for r in records]
        ts = _ts()
        rows_html = "\n".join(
            f"""<tr>
              <td class="mono">{_esc(r['timestamp'])}</td>
              <td>{_esc(r['user'])}</td>
              <td><span class="action">{_esc(r['action'])}</span></td>
              <td>{_esc(r['target_type'])}</td>
              <td class="mono">{_esc(r['target_id'])}</td>
              <td><span class="result" style="color:{_RESULT_COLOR.get(str(r['result']),
                  '#8b949e')}">{_esc(r['result'])}</span></td>
              <td>{_esc(r['notes'])}</td>
            </tr>"""
            for r in records
        )
        html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>{_esc(title)}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',Arial,sans-serif;background:#0d1117;color:#e6edf3;
      padding:2rem;font-size:13px;line-height:1.5}}
h1{{color:#1d9e75;font-size:22px;margin-bottom:6px}}
.meta{{color:#8b949e;font-size:12px;margin-bottom:1.5rem}}
.section{{background:#161b22;border:1px solid #30363d;border-radius:8px;
          padding:1rem;overflow-x:auto;margin-bottom:1.5rem}}
table{{width:100%;border-collapse:collapse;font-size:12px}}
th{{background:#21262d;color:#8b949e;padding:7px 8px;text-align:left;
    font-size:11px;text-transform:uppercase;letter-spacing:.04em;
    border-bottom:1px solid #30363d}}
td{{padding:5px 8px;border-bottom:1px solid #21262d;vertical-align:middle}}
tr:hover td{{background:#1c2128}}
.mono{{font-family:'Courier New',monospace;font-size:11px}}
.action{{color:#a5d6ff;font-weight:500}}
.result{{font-weight:600}}
.footer{{margin-top:2rem;font-size:11px;color:#484f58;border-top:1px solid
         #21262d;padding-top:1rem;text-align:center}}
</style></head><body>
<h1>🗒️ {_esc(title)}</h1>
<div class="meta">Generated: {ts} &nbsp;·&nbsp; Total Records: {len(records)}</div>
<div class="section">
<table><thead><tr>
  <th>Timestamp</th><th>User</th><th>Action</th>
  <th>Target Type</th><th>Target ID</th><th>Result</th><th>Notes</th>
</tr></thead>
<tbody>{rows_html or '<tr><td colspan="7" style="color:#8b949e">No audit records.</td></tr>'}</tbody>
</table></div>
<div class="footer">ForensIQ Audit Trail &nbsp;·&nbsp; {ts} &nbsp;·&nbsp;
Records are immutable and cannot be modified.</div>
</body></html>"""
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(html)
        logger.info("Audit HTML written: %s", output_path)
        return output_path

    # ── Chain of Custody exports ───────────────────────────────────────────────

    def export_custody_json(self, events: list, output_path: str,
                            case_number: str = "") -> str:
        payload = {
            "report_type":  "ForensIQ Chain of Custody",
            "generated_at": _ts(),
            "case_number":  case_number,
            "total_events": len(events),
            "events":       [dict(e) for e in events],
        }
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, default=str)
        logger.info("Custody JSON written: %s", output_path)
        return output_path

    def export_custody_html(self, events: list, output_path: str,
                            case_number: str = "") -> str:
        events = [dict(e) if not isinstance(e, dict) else e for e in events]
        ts = _ts()

        _action_color = {
            "ACQUIRED":    "#1D9E75",
            "VERIFIED":    "#3FB950",
            "REVIEWED":    "#A5D6FF",
            "EXPORTED":    "#E3B341",
            "TRANSFERRED": "#F0883E",
            "ARCHIVED":    "#8B949E",
            "NOTED":       "#8B949E",
        }

        rows_html = "\n".join(
            f"""<tr>
              <td class="mono">{_esc(e['timestamp'])}</td>
              <td>{_esc(e['investigator'])}</td>
              <td><span class="badge" style="color:{_action_color.get(str(e['action']),'#ccc')};
                  background:{_action_color.get(str(e['action']),'#555')}18;
                  border:1px solid {_action_color.get(str(e['action']),'#555')}33;
                  padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600">
                  {_esc(e['action'])}</span></td>
              <td>{_esc(e.get('filename') or '—')}</td>
              <td>{_esc(e.get('category') or '—')}</td>
              <td>{_esc(e.get('location') or '—')}</td>
              <td>{_esc(e['notes'])}</td>
            </tr>"""
            for e in events
        )
        html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>ForensIQ — Chain of Custody {_esc(case_number)}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',Arial,sans-serif;background:#0d1117;color:#e6edf3;
      padding:2rem;font-size:13px;line-height:1.5}}
h1{{color:#1d9e75;font-size:22px;margin-bottom:6px}}
.meta{{color:#8b949e;font-size:12px;margin-bottom:1.5rem}}
.section{{background:#161b22;border:1px solid #30363d;border-radius:8px;
          padding:1rem;overflow-x:auto;margin-bottom:1.5rem}}
table{{width:100%;border-collapse:collapse;font-size:12px}}
th{{background:#21262d;color:#8b949e;padding:7px 8px;text-align:left;
    font-size:11px;text-transform:uppercase;letter-spacing:.04em;
    border-bottom:1px solid #30363d}}
td{{padding:6px 8px;border-bottom:1px solid #21262d;vertical-align:middle}}
tr:hover td{{background:#1c2128}}
.mono{{font-family:'Courier New',monospace;font-size:11px}}
.footer{{margin-top:2rem;font-size:11px;color:#484f58;border-top:1px solid
         #21262d;padding-top:1rem;text-align:center}}
</style></head><body>
<h1>🔗 ForensIQ — Chain of Custody</h1>
<div class="meta">Case: <strong>{_esc(case_number) or '—'}</strong>
&nbsp;·&nbsp; Generated: {ts}
&nbsp;·&nbsp; Total Events: {len(events)}</div>
<div class="section">
<table><thead><tr>
  <th>Timestamp</th><th>Investigator</th><th>Action</th>
  <th>Filename</th><th>Category</th><th>Location</th><th>Notes</th>
</tr></thead>
<tbody>{rows_html or '<tr><td colspan="7" style="color:#8b949e">No custody events.</td></tr>'}</tbody>
</table></div>
<div class="footer">ForensIQ Chain of Custody &nbsp;·&nbsp; {ts}</div>
</body></html>"""
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(html)
        logger.info("Custody HTML written: %s", output_path)
        return output_path
