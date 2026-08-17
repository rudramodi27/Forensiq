"""
Manifest Service — Case Evidence Manifest (Phase 4).

Builds a Case Evidence Manifest for a case by reading the existing
Phase 1-3 data through CaseManager / IntegrityEngine. This module owns NO
tables of its own and writes nothing new to the database — a manifest is a
read-only, generated view over `cases`, `devices`, `acquisition_sessions`,
`evidence`, `verification_results`, and `custody_events`. Re-running
`build_manifest()` always reflects current data; nothing here is cached or
duplicated into a new evidence record.

Hierarchy resolved per item: Case -> Device -> Acquisition Session -> Evidence
(see ARCHITECTURE.md / DATABASE_SCHEMA.md, Phase 3). `evidence.device_id`
and `evidence.session_id` are both nullable — legacy evidence (added before
Phase 3, or imported manually without a tracked acquisition run) simply has
no device/session to resolve. This module never invents a device or session
for such items; it reports them as unresolved.

Integrity status per item is the evidence's most recent verification result
(via CaseManager.get_last_verification_per_evidence() — the same source of
truth used by get_case_integrity_summary()), normalized through
integrity_engine.normalize_status() so legacy PASS/FAIL rows read the same
as canonical MATCH/MISMATCH. An item is never reported as MATCH/"VERIFIED"
unless a verification_results row actually recorded that outcome; an item
with no verification history is NOT_VERIFIED.

Exports:
  - export_manifest_json() : manifest.json
  - export_manifest_csv()  : manifest.csv (flat, one row per evidence item)
"""

import csv
import json
from datetime import datetime, timezone

from forensiq.core.case_manager import CaseManager
from forensiq.core.integrity_engine import normalize_status, NOT_VERIFIED
from forensiq.core.time_utils import now_utc_str


# Phase 10: delegates to the single centralized clock in time_utils
# instead of formatting datetime.now(timezone.utc) locally.
def _manifest_generated_at() -> str:
    return now_utc_str()


def _collector_for_evidence(db: CaseManager, case, evidence_id: int):
    """
    Resolve the collector/investigator who acquired this specific evidence
    item, from the real ACQUIRED custody event written by
    AuditService.log_evidence_added() (see audit_service.py). This is the
    most accurate per-item record available — the case's `investigator`
    field is the case's lead investigator, not necessarily the person who
    physically collected any given item.

    Returns (collector, source) where source is:
      "custody_event"    — a real ACQUIRED custody event named the collector
      "case_investigator" — no custody event found; fell back to the case's
                             investigator of record (real stored data, but
                             not evidence-item-specific — flagged so the
                             manifest never implies more precision than it
                             has)
      "unknown"           — neither was available
    """
    try:
        chain = db.get_custody_chain(evidence_id)  # oldest-first
    except Exception:
        chain = []
    for event in chain:
        if event["action"] == "ACQUIRED" and (event["investigator"] or "").strip():
            return event["investigator"], "custody_event"

    case_investigator = (case["investigator"] or "").strip() if case else ""
    if case_investigator:
        return case_investigator, "case_investigator"
    return "", "unknown"


def _build_manifest_item(db: CaseManager, case,
                          evidence_row, devices_by_id: dict,
                          sessions_by_id: dict, last_vr_by_ev: dict) -> dict:
    eid = evidence_row["id"]

    device = None
    if evidence_row["device_id"] is not None:
        device = devices_by_id.get(evidence_row["device_id"])

    session = None
    session_id = evidence_row["session_id"]
    if session_id is not None:
        session = sessions_by_id.get(session_id)

    last_vr = last_vr_by_ev.get(eid)
    if last_vr:
        integrity_status  = normalize_status(last_vr["result"])
        verified_sha256   = last_vr["current_hash"] or ""
        last_verified_at  = last_vr["verification_time"] or ""
    else:
        integrity_status  = NOT_VERIFIED
        verified_sha256   = ""
        last_verified_at  = ""

    collector, collector_source = _collector_for_evidence(db, case, eid)

    return {
        # Case
        "case_id":                  case["id"],
        "case_number":              case["case_number"],
        # Evidence
        "evidence_id":              eid,
        "filename":                 evidence_row["filename"] or "",
        "category":                 evidence_row["category"] or "",
        "file_size":                evidence_row["file_size"] or 0,
        "acquired_at":              evidence_row["acquired_at"] or "",
        "storage_location":         evidence_row["filepath"] or "",
        # Device (Case -> Device -> Session -> Evidence; may be unresolved
        # for legacy evidence — never fabricated)
        "device_id":                device["id"] if device else None,
        "device_serial":            device["serial"] if device else "",
        "device_model":             device["model"] if device else "",
        "device_manufacturer":      device["manufacturer"] if device else "",
        # Acquisition session (Phase 3; may be unresolved for legacy evidence)
        "session_id":               session["id"] if session else None,
        "session_status":           session["status"] if session else "",
        "session_start_time":       session["start_time"] if session else "",
        # Collector
        "collector":                collector,
        "collector_source":         collector_source,
        # Integrity — recorded (immutable, acquisition-time) vs verified
        # (most recent re-hash), never conflated
        "recorded_sha256":          evidence_row["sha256"] or "",
        "verified_sha256":          verified_sha256,
        "integrity_status":         integrity_status,
        "last_verified_at":         last_verified_at,
        "is_legacy":                device is None or session is None,
    }


def build_manifest(case_id: int, db: CaseManager) -> dict:
    """
    Build the complete Case Evidence Manifest for a case. Read-only —
    references existing evidence/device/session/verification rows rather
    than copying them into a new record.
    """
    case = db.get_case(case_id)
    if not case:
        raise ValueError(f"Case {case_id} not found")

    evidence  = list(db.get_evidence_for_case(case_id))
    devices   = {d["id"]: d for d in db.get_devices_for_case(case_id)}
    sessions  = {s["id"]: s for s in db.get_sessions_for_case(case_id)}
    last_vr_by_ev = db.get_last_verification_per_evidence(case_id)

    items = [
        _build_manifest_item(db, case, ev, devices, sessions, last_vr_by_ev)
        for ev in evidence
    ]

    integrity_counts: dict = {}
    for it in items:
        integrity_counts[it["integrity_status"]] = integrity_counts.get(it["integrity_status"], 0) + 1

    legacy_count = sum(1 for it in items if it["is_legacy"])
    devices_referenced = len({it["device_id"] for it in items if it["device_id"] is not None})
    sessions_referenced = len({it["session_id"] for it in items if it["session_id"] is not None})

    return {
        "manifest_type":   "Case Evidence Manifest",
        "generated_at":    _manifest_generated_at(),
        "case_id":         case["id"],
        "case_number":     case["case_number"],
        "case_title":      case["title"],
        "case_investigator": case["investigator"],
        "case_status":     case["status"],
        "total_items":     len(items),
        "devices_referenced":  devices_referenced,
        "sessions_referenced": sessions_referenced,
        "legacy_items":    legacy_count,
        "integrity_counts": integrity_counts,
        "items":           items,
    }


# ── Export ─────────────────────────────────────────────────────────────────

# (internal key, CSV column header) — order defines column order.
CSV_COLUMNS = [
    ("case_number",       "Case Number"),
    ("evidence_id",       "Evidence ID"),
    ("filename",          "Filename"),
    ("category",          "Category"),
    ("file_size",         "File Size (bytes)"),
    ("recorded_sha256",   "SHA-256 (Recorded)"),
    ("acquired_at",       "Acquisition Time"),
    ("device_serial",     "Source Device (Serial)"),
    ("device_model",      "Source Device (Model)"),
    ("session_id",        "Acquisition Session ID"),
    ("collector",         "Collector/Investigator"),
    ("storage_location",  "Storage Location"),
    ("integrity_status",  "Integrity Status"),
    ("verified_sha256",   "SHA-256 (Last Verified)"),
    ("last_verified_at",  "Last Verified At"),
]


def export_manifest_json(manifest: dict, output_path: str) -> str:
    """Write the manifest as JSON. Returns output_path."""
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, default=str)
    return output_path


def export_manifest_csv(manifest: dict, output_path: str) -> str:
    """Write the manifest as a flat CSV (one row per evidence item)."""
    with open(output_path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow([label for _, label in CSV_COLUMNS])
        for item in manifest["items"]:
            row = []
            for key, _ in CSV_COLUMNS:
                val = item.get(key)
                row.append("" if val is None else val)
            writer.writerow(row)
    return output_path
