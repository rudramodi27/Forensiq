"""
Analyzer — Advanced Analysis Engine (Upgrade Pack C + Phase 6 Expansion).

NEW in Pack C:
  - extract_file_metadata(): adds mime_type, sha256, original_path fields
  - analyze_apps():          adds system/user/disabled/recently_installed classification
  - build_unified_timeline(): merges file events + DB audit/custody/verification events
  - detect_duplicates():      SHA-256 + file-size duplicate detection across evidence
  - keyword_search_global():  searches evidence, audit, custody, apps, reports, notes
  - correlate_artifacts():    links files ↔ apps ↔ processes ↔ audit ↔ custody
  - generate_analysis_report(): writes analysis_report.json + analysis_report.html

NEW in Phase 6 (Analysis Engine Expansion):
  - make_finding():             builds the standard finding record shared by every
                                 analysis module: Input → Processing → Finding →
                                 Timestamp → Evidence Reference, with
                                 case_id/analysis_type/status/severity attached.
  - analyze_network_info():     parses the acquired network_info.txt (IP addresses,
                                 Wi-Fi state) and flags VPN/tunnel interfaces, missing
                                 network data, disabled Wi-Fi, etc.
  - analyze_battery_system():   parses the acquired battery_info.json plus the
                                 device's system record (Android/SDK/USB debugging)
                                 and flags thermal/health anomalies and hardening gaps.
  - analyze_hash_integrity():   wraps the EXISTING integrity engine / verification
                                 history (case_manager.get_case_integrity_summary /
                                 get_last_verification_per_evidence) into per-item
                                 findings — no hashing logic is duplicated here.
  - detect_suspicious_artifacts(): filesystem + app-level suspicious-artifact sweep;
                                 reuses classify_app()/SUSPICIOUS_* tables rather than
                                 re-implementing app classification.
  - search_iocs():              searches a supplied IOC list (hash/IP/domain/
                                 package/filename) across evidence, apps, and network
                                 data by reusing keyword_search_global()/analyze_apps()/
                                 analyze_network_info() rather than duplicating search.

PRESERVED FIXES from Phase 4:
  - BUG#1: AnalysisWorker passed `case` Row object — uses evidence_dir only
  - BUG#2: build_file_timeline deduplicated ctime≈mtime events
  - BUG#3: keyword_search_files closes file handles with context manager
  - BUG#4: analyze_apps returns flat dict (no nested 'apps' key)
"""

import json
import os
import re
import html as html_lib
import hashlib
import mimetypes
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from forensiq.core.time_utils import now_utc_str, now_utc, parse_stored, format_epoch_utc

try:
    from PyQt6.QtCore import QThread, pyqtSignal
    _QT_AVAILABLE = True
except ImportError:
    # analyzer.py's pure functions (duplicate detection, timeline building,
    # keyword search, etc.) have no Qt dependency and should be importable
    # and unit-testable headless. Only AnalysisWorker (a QThread) actually
    # needs PyQt6, and only if it's instantiated.
    _QT_AVAILABLE = False
    QThread = object

try:
    import magic as libmagic
    _MAGIC = libmagic.Magic(mime=True)
    _HAS_MAGIC = True
except Exception:
    _HAS_MAGIC = False


# ── Known suspicious packages ──────────────────────────────────────────────────

SUSPICIOUS_PACKAGES = frozenset([
    "com.termux", "com.fox2code", "eu.chainfire", "com.koushikdutta.superuser",
    "com.noshufou.android.su", "com.thirdparty.superuser", "com.yellowes.su",
    "com.topjohnwu.magisk", "com.kingroot.kinguser", "com.kingo.root",
    "com.smedialink.oneclickroot", "com.zhiqupk.root.global",
    "com.alephzain.framaroot", "com.koushikdutta.rommanager",
    "com.keramidas.TitaniumBackup", "com.stericson.busyboxfree",
    "de.robv.android.xposed", "com.saurik.substrate",
    "com.busybox", "com.zhiqupk.root",
])

# Suspicious keyword substrings — catch package variants not in the exact list above
# (e.g. "com.magisk" variants, "su" apps, root tools with different publishers)
SUSPICIOUS_SUBSTRINGS = (
    "magisk", "supersu", "superuser", "kingroot", "kingoroot",
    "framaroot", "xposed", "substrate", "busybox",
)

SUSPICIOUS_INSTALLERS = frozenset(["unknown", "null", ""])

# Filename/path substrings that commonly indicate root tools, tampering
# utilities, or offensive-security payloads dropped onto a device.
# Shared by detect_suspicious_artifacts() and search_iocs().
SUSPICIOUS_FILENAME_MARKERS = (
    "magisk", "supersu", "superuser", "busybox", "xposed", "substrate",
    "frida", "root_", "su_binary", "payload", "exploit", "keylog",
    "spyware", "stalkerware", "stealer", "backdoor", "rat_",
)

# Extensions that warrant a closer look wherever they appear in evidence —
# shared by correlate_artifacts() (existing) and detect_suspicious_artifacts()
# (Phase 6) so the definition lives in exactly one place.
HIGH_RISK_EXTENSIONS = frozenset({
    ".apk", ".exe", ".sh", ".bat", ".py", ".js", ".so", ".dex",
})

# network_info.txt interface-name prefixes that indicate a VPN/tunnel —
# not inherently malicious, but forensically notable (may mask true traffic).
VPN_TUNNEL_INTERFACE_PREFIXES = ("tun", "ppp", "wg", "utun", "ipsec")

BENIGN_PREFIXES = (
    "com.google.", "com.android.", "com.samsung.", "com.oneplus.",
    "org.mozilla.", "com.microsoft.", "com.whatsapp", "com.instagram.",
    "com.facebook.", "com.twitter.", "com.snapchat.",
)

# System package prefixes (Android)
SYSTEM_PREFIXES = (
    "com.android.", "android.", "com.google.android.",
    "com.samsung.", "com.oneplus.", "com.qualcomm.", "com.mediatek.",
)

# Recently-installed threshold: within 30 days of acquisition
RECENT_INSTALL_DAYS = 30


# ── Phase 6: standard analysis-result vocabulary ────────────────────────────────

SEVERITY_INFO     = "info"
SEVERITY_LOW      = "low"
SEVERITY_MEDIUM   = "medium"
SEVERITY_HIGH     = "high"
SEVERITY_CRITICAL = "critical"

SEVERITY_ORDER = {SEVERITY_INFO: 0, SEVERITY_LOW: 1, SEVERITY_MEDIUM: 2,
                   SEVERITY_HIGH: 3, SEVERITY_CRITICAL: 4}

STATUS_COMPLETED   = "completed"
STATUS_NO_DATA     = "no_data"
STATUS_ERROR       = "error"


# Phase 10: delegates to the single centralized clock in time_utils
# instead of formatting datetime.now(timezone.utc) locally.
def _now_iso() -> str:
    return now_utc_str()


def make_finding(analysis_type: str, evidence_ref, finding: str,
                  severity: str = SEVERITY_INFO, status: str = STATUS_COMPLETED,
                  case_id: Optional[int] = None, timestamp: Optional[str] = None,
                  **extra) -> dict:
    """
    Build the standard finding record every Phase 6 analysis module returns:
        Input (evidence_ref) → Processing (analysis_type) → Finding (finding)
        → Timestamp → Evidence Reference
    plus case_id/status/severity, so every analysis type — old and new —
    produces an identically-shaped record for the UI, the report generator,
    and analysis_results (analysis_id is assigned when the record is
    persisted via CaseManager.add_analysis_result(), which returns the row id).
    Extra analysis-specific fields (e.g. sha256, ip, package) are passed
    through via **extra so nothing is lost, without breaking the common shape.
    """
    rec = {
        "case_id":       case_id,
        "analysis_type": analysis_type,
        "evidence_ref":  evidence_ref,
        "timestamp":     timestamp or _now_iso(),
        "status":        status,
        "finding":       finding,
        "severity":      severity,
    }
    rec.update(extra)
    return rec


def highest_severity(findings: list[dict]) -> str:
    """Return the highest severity present in a list of finding dicts (or 'info' if empty)."""
    if not findings:
        return SEVERITY_INFO
    return max((f.get("severity", SEVERITY_INFO) for f in findings),
               key=lambda s: SEVERITY_ORDER.get(s, 0))


# ── Internal utilities ─────────────────────────────────────────────────────────

def _human_size(size: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size //= 1024
    return f"{size:.1f} PB"


# Phase 10: delegates to the single centralized clock in time_utils
# instead of formatting datetime.now(timezone.utc) locally.
def _now_str() -> str:
    return now_utc_str()


def _esc(v) -> str:
    return html_lib.escape(str(v or ""))


def _sha256_file(filepath: str) -> str:
    """Compute SHA-256 in streaming chunks."""
    h = hashlib.sha256()
    try:
        with open(filepath, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


def _mime_type(filepath: str) -> str:
    """Return MIME type using libmagic if available, else mimetypes fallback."""
    if _HAS_MAGIC:
        try:
            return _MAGIC.from_file(filepath) or "application/octet-stream"
        except Exception:
            pass
    mt, _ = mimetypes.guess_type(filepath)
    return mt or "application/octet-stream"


# ── App classification ─────────────────────────────────────────────────────────

def classify_app(package: str, installer: str) -> str:
    """
    Classify an app package as: suspicious | clean | review | unknown.
    Checks exact match, then suspicious substrings (catches vendor variants),
    then benign prefixes, then installer source.
    """
    pkg  = (package or "").lower().strip()
    inst = (installer or "").lower().strip()
    if pkg in SUSPICIOUS_PACKAGES:
        return "suspicious"
    # Substring match catches variants: "com.magisk", "dev.magisk.manager", etc.
    for sub in SUSPICIOUS_SUBSTRINGS:
        if sub in pkg:
            return "suspicious"
    for prefix in BENIGN_PREFIXES:
        if pkg.startswith(prefix):
            return "clean"
    if inst in SUSPICIOUS_INSTALLERS:
        return "review"
    return "unknown"


def _app_type(app: dict) -> str:
    """Classify app as system / user / disabled / sideloaded."""
    pkg       = (app.get("package") or "").lower()
    flags     = str(app.get("flags") or "").lower()
    enabled   = app.get("enabled", True)
    installer = (app.get("installer") or "").lower()

    if not enabled or "disabled" in flags:
        return "disabled"
    for prefix in SYSTEM_PREFIXES:
        if pkg.startswith(prefix):
            return "system"
    if installer in ("", "null", "unknown") or "sideload" in installer:
        return "sideloaded"
    return "user"


def _is_recently_installed(app: dict, reference_ts: Optional[str] = None) -> bool:
    """
    Return True if install_time is within RECENT_INSTALL_DAYS of reference_ts.

    Phase 10 fix: previously parsed install_time with a bare
    datetime.fromisoformat() (silently NAIVE unless the source string
    itself carried an offset) and reference_ts with a fragile manual
    string-replace ("... UTC" -> "...+00:00"). A naive install_dt
    compared against the aware ref_dt raised TypeError, which the
    broad except silently swallowed as "not recently installed" —
    wrong, not just unlabelled. Both sides now go through
    time_utils.parse_stored(), which always returns an aware UTC
    datetime (treating a bare/offset-less value as UTC, never local)
    or None, instead of a second bespoke parser here.
    """
    raw = app.get("install_time") or app.get("first_install_time") or ""
    if not raw:
        return False
    install_dt = parse_stored(raw)
    if install_dt is None:
        return False
    ref_dt = parse_stored(reference_ts) if reference_ts else None
    if ref_dt is None:
        ref_dt = now_utc()
    delta = abs((ref_dt - install_dt).days)
    return delta <= RECENT_INSTALL_DAYS


# ── Core analysis functions ────────────────────────────────────────────────────

def extract_file_metadata(filepath: str) -> dict:
    """
    Enhanced metadata extraction — adds mime_type, sha256, original_path.
    Backward-compatible: all Phase 4 fields preserved.

    Phase 10 fix: created/modified/accessed were previously
    datetime.fromtimestamp(epoch) with no tz argument — a naive
    datetime in the host machine's LOCAL timezone with no label at
    all, silently wrong wherever ForensIQ doesn't run on a UTC host.
    Now uses format_epoch_utc(), matching every other timestamp this
    system stores (UTC, explicitly labelled).
    """
    try:
        stat = os.stat(filepath)
        p    = Path(filepath)
        sha  = _sha256_file(filepath)
        mime = _mime_type(filepath)
        return {
            "filename":      p.name,
            "extension":     p.suffix.lower(),
            "mime_type":     mime,
            "size_bytes":    stat.st_size,
            "size_human":    _human_size(stat.st_size),
            "created":       format_epoch_utc(stat.st_ctime),
            "modified":      format_epoch_utc(stat.st_mtime),
            "accessed":      format_epoch_utc(stat.st_atime),
            "sha256":        sha,
            "original_path": str(filepath),
        }
    except OSError as e:
        return {"error": str(e), "filename": os.path.basename(filepath)}


def analyze_apps(apps_json_path: str) -> dict:
    """
    Enhanced app analysis. Returns flat dict: {total, summary, apps, inventory}.
    Adds: app_type (system/user/disabled/sideloaded), recently_installed flag.
    FIX: flat layout preserved — no nested 'apps.apps'.
    """
    if not os.path.exists(apps_json_path):
        return {"error": "installed_apps.json not found", "total": 0,
                "summary": {}, "apps": [], "inventory": {}}
    try:
        with open(apps_json_path, encoding="utf-8") as f:
            raw_apps = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        return {"error": str(e), "total": 0, "summary": {}, "apps": [], "inventory": {}}

    summary    = {"clean": 0, "suspicious": 0, "review": 0, "unknown": 0}
    inventory  = {"system": 0, "user": 0, "disabled": 0, "sideloaded": 0, "recently_installed": 0}
    classified = []

    for app in raw_apps:
        pkg      = app.get("package", "")
        inst     = app.get("installer", "")
        status   = classify_app(pkg, inst)
        app_type = _app_type(app)
        recent   = _is_recently_installed(app)

        summary[status] += 1
        inventory[app_type] = inventory.get(app_type, 0) + 1
        if recent:
            inventory["recently_installed"] += 1

        classified.append({
            **app,
            "status":             status,
            "app_type":           app_type,
            "recently_installed": recent,
        })

    return {
        "total":     len(classified),
        "summary":   summary,
        "inventory": inventory,
        "apps":      classified,
    }


def build_file_timeline(evidence_dir: str) -> list[dict]:
    """
    File-system timeline from evidence directory.
    FIX: Deduplicate events where ctime == mtime (common on pulled Android files).

    Phase 10 fix: mtime/ctime were previously formatted with
    datetime.fromtimestamp(epoch) and no tz argument — a naive
    datetime in the host machine's LOCAL timezone, with no timezone
    label, then merged directly into build_unified_timeline() right
    alongside proper 'YYYY-MM-DD HH:MM:SS UTC' rows from the database.
    That silently broke both the displayed value (wrong absolute time
    off any non-UTC host) and the timeline's chronological sort order.
    Now uses format_epoch_utc(), which is explicitly UTC and sorts
    correctly (lexically) against every other timeline event.
    """
    events = []
    seen   = set()

    for root, _, files in os.walk(evidence_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            try:
                stat  = os.stat(fpath)
                mtime = format_epoch_utc(stat.st_mtime)
                ctime = format_epoch_utc(stat.st_ctime)

                key_c = (fpath, ctime, "file_created")
                if key_c not in seen:
                    seen.add(key_c)
                    events.append({
                        "timestamp":   ctime,
                        "event_type":  "file_created",
                        "description": f"File created: {fname}",
                        "source":      fpath,
                    })

                if mtime != ctime:
                    key_m = (fpath, mtime, "file_modified")
                    if key_m not in seen:
                        seen.add(key_m)
                        events.append({
                            "timestamp":   mtime,
                            "event_type":  "file_modified",
                            "description": f"File modified: {fname}",
                            "source":      fpath,
                        })
            except OSError:
                pass

    events.sort(key=lambda x: x["timestamp"])
    return events


_TIMELINE_EVENT_DEFAULTS = {
    "case_id": None, "evidence_id": None, "device_id": None,
    "session_id": None, "actor": "", "source": "",
}


def _tl_event(case_id: int, **fields) -> dict:
    """
    Build one unified-timeline event with every field the Phase 7 schema
    expects (timestamp | event_type | category | description | case_id |
    evidence_id | device_id | session_id | actor | source), filling in
    sensible empty defaults for whichever of those don't apply to this
    particular event so every event in the timeline has the same shape.
    """
    ev = dict(_TIMELINE_EVENT_DEFAULTS)
    ev["case_id"] = case_id
    ev.update(fields)
    return ev


def build_unified_timeline(evidence_dir: str, db, case_id: int) -> list[dict]:
    """
    Unified forensic timeline merging every category of recorded case
    activity:
      - case         — case creation / edits (from the cases table itself)
      - evidence     — evidence items acquired (from the evidence table)
      - device_acquisition — devices registered + acquisition sessions
                             started/finished (devices + acquisition_sessions)
      - analysis     — analysis runs recorded (analysis_results table)
      - verification — integrity checks (verification_results table)
      - audit        — investigator/system audit trail (audit_trail table)
      - custody      — chain-of-custody actions (custody_events table)
      - file_system  — created/modified events from the evidence directory

    Every event is normalised (see `_tl_event`) to:
        timestamp, event_type, category, description,
        case_id, evidence_id, device_id, session_id, actor, source
    Nothing here is fabricated — every event is read straight from an
    existing row (or an on-disk file's own mtime/ctime); this function only
    merges and re-sorts, never invents a timestamp or history.
    """
    events = []
    case_row = None
    try:
        case_row = db.get_case(case_id)
    except Exception:
        pass
    case_investigator = case_row["investigator"] if case_row else ""

    # 1. Case events — from the case row itself
    if case_row:
        events.append(_tl_event(
            case_id,
            timestamp=case_row["created_at"],
            event_type="case_created",
            category="case",
            description=f"Case created: {case_row['case_number']} — {case_row['title']}",
            actor=case_investigator,
        ))
        if case_row["updated_at"] and case_row["updated_at"] != case_row["created_at"]:
            events.append(_tl_event(
                case_id,
                timestamp=case_row["updated_at"],
                event_type="case_updated",
                category="case",
                description=f"Case updated: {case_row['case_number']} — status {case_row['status']}",
                actor=case_investigator,
            ))

    # 2. File system events
    if evidence_dir and os.path.exists(evidence_dir):
        for ev in build_file_timeline(evidence_dir):
            events.append(_tl_event(
                case_id,
                timestamp=ev["timestamp"],
                event_type=ev["event_type"],
                category="file_system",
                description=ev["description"],
                source=ev["source"],
            ))

    # 3. Evidence acquisition events
    try:
        for ev in db.get_evidence_for_case(case_id):
            events.append(_tl_event(
                case_id,
                timestamp=ev["acquired_at"],
                event_type="evidence_acquired",
                category="evidence",
                description=f"Evidence acquired: {ev['filename'] or ev['category']}",
                source=ev["filepath"] or "",
                evidence_id=ev["id"],
                device_id=ev["device_id"],
                session_id=ev["session_id"] if "session_id" in ev.keys() else None,
                actor=case_investigator,
            ))
    except Exception:
        pass

    # 4. Device / acquisition-session events
    try:
        for dv in db.get_devices_for_case(case_id):
            events.append(_tl_event(
                case_id,
                timestamp=dv["first_connected"] or dv["acquired_at"],
                event_type="device_registered",
                category="device_acquisition",
                description=f"Device registered: {dv['model']} ({dv['serial']})",
                source=dv["serial"] or "",
                device_id=dv["id"],
                actor=case_investigator,
            ))
    except Exception:
        pass

    try:
        for ss in db.get_sessions_for_case(case_id):
            events.append(_tl_event(
                case_id,
                timestamp=ss["start_time"],
                event_type="acquisition_session_started",
                category="device_acquisition",
                description=f"Acquisition session started (targets: {ss['targets']})",
                device_id=ss["device_id"],
                session_id=ss["id"],
                actor=case_investigator,
            ))
            if ss["end_time"]:
                events.append(_tl_event(
                    case_id,
                    timestamp=ss["end_time"],
                    event_type=f"acquisition_session_{ss['status']}",
                    category="device_acquisition",
                    description=f"Acquisition session {ss['status']}",
                    device_id=ss["device_id"],
                    session_id=ss["id"],
                    actor=case_investigator,
                ))
    except Exception:
        pass

    # 5. Analysis events
    try:
        for ar in db.get_analysis_results(case_id):
            events.append(_tl_event(
                case_id,
                timestamp=ar["created_at"],
                event_type=f"analysis_{ar['analysis_type']}",
                category="analysis",
                description=ar["result_summary"] or f"Analysis run: {ar['analysis_type']}",
                evidence_id=ar["evidence_id"],
                actor=case_investigator,
            ))
    except Exception:
        pass

    # 6. Verification events
    # FIX-BUG-VR: sqlite3.Row has no .get() — index with [] and use or-fallback
    try:
        for vr in db.get_verification_history(case_id=case_id):
            fname = vr["filename"] if vr["filename"] else "evidence"
            events.append(_tl_event(
                case_id,
                timestamp=vr["verification_time"],
                event_type=f"verification_{vr['result'].lower()}",
                category="verification",
                description=f"Integrity check {vr['result']}: {fname}",
                evidence_id=vr["evidence_id"],
            ))
    except Exception:
        pass

    # 7. Audit trail
    try:
        for _at in db.get_audit_trail():
            at = dict(_at)
            events.append(_tl_event(
                case_id,
                timestamp=at["timestamp"],
                event_type=at["action"].lower(),
                category="audit",
                description=f"Audit: {at['action']} by {at['user'] or 'system'} — {at['notes'] or ''}",
                actor=at["user"] or "",
                evidence_id=(int(at["target_id"]) if at["target_type"] == "evidence"
                             and str(at["target_id"]).isdigit() else None),
            ))
    except Exception:
        pass

    # 8. Custody events
    # FIX-BUG-CE-TL: sqlite3.Row has no .get() — convert to dict first
    try:
        for _ce in db.get_custody_events(case_id=case_id):
            ce = dict(_ce)
            fname = ce.get("filename") or "evidence"
            events.append(_tl_event(
                case_id,
                timestamp=ce["timestamp"],
                event_type=f"custody_{ce['action'].lower()}",
                category="custody",
                description=f"Custody {ce['action']}: {fname} — {ce['investigator']}",
                evidence_id=ce.get("evidence_id"),
                actor=ce.get("investigator") or "",
            ))
    except Exception:
        pass

    events.sort(key=lambda x: str(x.get("timestamp") or ""))
    return events


def persist_unified_timeline(db, case_id: int, events: list[dict]) -> int:
    """
    Persist a freshly-built unified timeline (from build_unified_timeline)
    into the timeline_events table.

    Duplicate prevention lives in CaseManager.add_timeline_event() itself
    (matched on case_id/event_type/description/timestamp/evidence_id/
    device_id/session_id), so calling this again after re-running the same
    analysis over unchanged source data is a safe no-op — it will not grow
    the table. Returns the number of NEW rows actually inserted.
    """
    if db is None:
        return 0
    before = {row["id"] for row in db.get_timeline(case_id)}
    for ev in events:
        db.add_timeline_event(
            case_id,
            ev.get("event_type", ""),
            ev.get("description", ""),
            ev.get("timestamp", ""),
            evidence_id=ev.get("evidence_id"),
            source_file=ev.get("source", ""),
            metadata={},
            category=ev.get("category", ""),
            actor=ev.get("actor", ""),
            device_id=ev.get("device_id"),
            session_id=ev.get("session_id"),
        )
    after = {row["id"] for row in db.get_timeline(case_id)}
    return len(after - before)


def detect_duplicates(evidence_dir: str, db=None, case_id: int = None) -> dict:
    """
    Detect duplicate evidence using SHA-256 and file size.
    Returns: {duplicates: [{hash, size, files:[...]}, ...], total_files, duplicate_count}
    """
    hash_map: dict[str, list[dict]] = {}
    total = 0

    # Scan evidence directory
    if evidence_dir and os.path.exists(evidence_dir):
        for root, _, files in os.walk(evidence_dir):
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    size = os.path.getsize(fpath)
                    sha  = _sha256_file(fpath)
                    if sha:
                        key = f"{sha}:{size}"
                        if key not in hash_map:
                            hash_map[key] = []
                        hash_map[key].append({
                            "filename": fname,
                            "path":     fpath,
                            "size":     size,
                            "sha256":   sha,
                            "source":   "filesystem",
                        })
                        total += 1
                except OSError:
                    pass

    # Also compare against DB evidence records
    if db and case_id:
        try:
            for ev in db.get_evidence_for_case(case_id):
                sha  = ev["sha256"] or ""
                size = ev["file_size"] or 0
                if sha:
                    key = f"{sha}:{size}"
                    if key not in hash_map:
                        hash_map[key] = []
                    # Avoid adding same file twice if already found in filesystem scan
                    existing_paths = {e["path"] for e in hash_map[key]}
                    if ev["filepath"] not in existing_paths:
                        hash_map[key].append({
                            "filename": ev["filename"],
                            "path":     ev["filepath"] or "",
                            "size":     size,
                            "sha256":   sha,
                            "source":   "database",
                        })
        except Exception:
            pass

    duplicates = [
        {"sha256": key.split(":")[0], "size": int(key.split(":")[1]),
         "count": len(files), "files": files}
        for key, files in hash_map.items()
        if len(files) > 1
    ]
    duplicates.sort(key=lambda x: x["count"], reverse=True)

    return {
        "total_files":     total,
        "duplicate_groups": len(duplicates),
        "duplicate_count": sum(d["count"] - 1 for d in duplicates),
        "duplicates":      duplicates,
    }


def correlate_artifacts(evidence_dir: str, db, case_id: int) -> dict:
    """
    Correlate evidence across modules:
      files ↔ installed apps ↔ audit events ↔ custody events ↔ verification results
    Returns structured correlation map for display.
    """
    correlations = {
        "file_app_matches":       [],  # files whose names match installed packages
        "high_risk_files":        [],  # files with suspicious extensions
        "verified_evidence":      [],  # evidence with verification results
        "unverified_evidence":    [],  # evidence never verified
        "custody_chain":          [],  # evidence items with full custody chains
        "audit_evidence_links":   [],  # audit events referencing evidence IDs
    }

    # Load evidence
    evidence = []
    try:
        evidence = [dict(e) for e in db.get_evidence_for_case(case_id)]
    except Exception:
        pass

    # Load apps (if installed_apps.json exists)
    app_packages: set[str] = set()
    if evidence_dir and os.path.exists(evidence_dir):
        apps_path = os.path.join(evidence_dir, "installed_apps.json")
        if os.path.exists(apps_path):
            try:
                with open(apps_path, encoding="utf-8") as f:
                    for app in json.load(f):
                        p = (app.get("package") or "").lower()
                        if p:
                            app_packages.add(p)
            except Exception:
                pass

    # Load verification summary
    verified_ids: set[int] = set()
    try:
        for vr in db.get_verification_history(case_id=case_id):
            if vr["evidence_id"]:
                verified_ids.add(vr["evidence_id"])
    except Exception:
        pass

    # Load custody events
    ev_with_custody: set[int] = set()
    try:
        for ce in db.get_custody_events(case_id=case_id):
            if ce["evidence_id"]:
                ev_with_custody.add(ce["evidence_id"])
    except Exception:
        pass

    # Load audit events referencing evidence (for audit_evidence_links)
    audit_by_evidence: dict = {}
    try:
        for at in db.get_audit_trail(target_type="evidence"):
            tid = at["target_id"]
            if tid is None:
                continue
            try:
                tid_int = int(tid)
            except (TypeError, ValueError):
                continue
            audit_by_evidence.setdefault(tid_int, []).append(dict(at))
    except Exception:
        pass

    for ev in evidence:
        fname = (ev.get("filename") or "").lower()
        ext   = Path(fname).suffix.lower() if fname else ""
        ev_id = ev.get("id")

        # File ↔ App correlation
        for pkg in app_packages:
            if pkg in fname or (fname and fname.replace(".apk", "") in pkg):
                correlations["file_app_matches"].append({
                    "evidence_id":   ev_id,
                    "filename":      ev.get("filename", ""),
                    "matched_package": pkg,
                    "category":      ev.get("category", ""),
                })
                break

        # High-risk files
        if ext in HIGH_RISK_EXTENSIONS:
            correlations["high_risk_files"].append({
                "evidence_id": ev_id,
                "filename":    ev.get("filename", ""),
                "extension":   ext,
                "sha256":      (ev.get("sha256") or "")[:32],
            })

        # Verification status
        if ev_id in verified_ids:
            correlations["verified_evidence"].append({
                "evidence_id": ev_id,
                "filename":    ev.get("filename", ""),
                "category":    ev.get("category", ""),
            })
        else:
            correlations["unverified_evidence"].append({
                "evidence_id": ev_id,
                "filename":    ev.get("filename", ""),
                "category":    ev.get("category", ""),
            })

        # Custody chain completeness
        if ev_id in ev_with_custody:
            correlations["custody_chain"].append({
                "evidence_id": ev_id,
                "filename":    ev.get("filename", ""),
                "has_custody": True,
            })

        # Audit events that reference this evidence item
        ev_audit_events = audit_by_evidence.get(ev_id, [])
        if ev_audit_events:
            correlations["audit_evidence_links"].append({
                "evidence_id":  ev_id,
                "filename":     ev.get("filename", ""),
                "audit_count":  len(ev_audit_events),
                "actions":      ", ".join(sorted({a["action"] for a in ev_audit_events})),
            })

    return correlations


def keyword_search_files(evidence_dir: str, keyword: str) -> list[dict]:
    """FIX: Explicit file handle closure, skip binary files gracefully."""
    results  = []
    kw_lower = keyword.lower()
    text_exts = {".txt", ".json", ".csv", ".log", ".xml", ".html", ".md", ".dat"}

    for root, _, files in os.walk(evidence_dir):
        for fname in files:
            if Path(fname).suffix.lower() not in text_exts:
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, encoding="utf-8", errors="replace") as fh:
                    for lineno, line in enumerate(fh, 1):
                        if kw_lower in line.lower():
                            results.append({
                                "file":  fname,
                                "path":  fpath,
                                "line":  lineno,
                                "match": line.strip()[:200],
                            })
                            if len(results) >= 500:
                                return results
            except OSError:
                pass
    return results


def keyword_search_global(keyword: str, db, case_id: int = None,
                           filters: dict = None) -> list[dict]:
    """
    Global search across all data sources.
    filters: {date_from, date_to, investigator, file_type, verification_status, evidence_type}
    """
    results  = []
    kw_lower = keyword.lower()
    filters  = filters or {}

    def _match(text: str) -> bool:
        return kw_lower in str(text or "").lower()

    def _date_ok(ts: str) -> bool:
        d_from = filters.get("date_from")
        d_to   = filters.get("date_to")
        if not (d_from or d_to):
            return True
        try:
            t = str(ts or "")[:10]
            if d_from and t < d_from:
                return False
            if d_to and t > d_to:
                return False
        except Exception:
            pass
        return True

    # Evidence / Files
    # Precompute verification status map for this case (for verification_status filter)
    # Accepts both the canonical Phase 1 vocabulary (MATCH/MISMATCH/...) and
    # the legacy pre-Phase-1 vocabulary (PASS/FAIL) so old and new
    # verification rows are both classified correctly.
    _verified_pass_ids: set = set()
    _verified_fail_ids: set = set()
    try:
        if case_id:
            for vr in db.get_verification_history(case_id=case_id):
                eid = vr["evidence_id"]
                if vr["result"] in ("PASS", "MATCH"):
                    _verified_pass_ids.add(eid)
                elif vr["result"] in ("FAIL", "MISMATCH", "MISSING", "CORRUPTED", "ERROR"):
                    _verified_fail_ids.add(eid)
    except Exception:
        pass

    try:
        evs = db.get_evidence_for_case(case_id) if case_id else []
        for ev in evs:
            if not _date_ok(ev["acquired_at"]):
                continue
            et_filter = filters.get("evidence_type")
            if et_filter and ev["category"] != et_filter:
                continue
            # file_type filter: matches extension derived from filename, e.g. ".apk" or "apk"
            ft_filter = (filters.get("file_type") or "").lower().lstrip(".")
            if ft_filter:
                ev_ext = Path(ev["filename"] or "").suffix.lower().lstrip(".")
                if ev_ext != ft_filter:
                    continue
            # verification_status filter: "pass" | "fail" | "unverified"
            vs_filter = filters.get("verification_status", "").lower()
            if vs_filter == "pass" and ev["id"] not in _verified_pass_ids:
                continue
            if vs_filter == "fail" and ev["id"] not in _verified_fail_ids:
                continue
            if vs_filter == "unverified" and (
                ev["id"] in _verified_pass_ids or ev["id"] in _verified_fail_ids
            ):
                continue
            if _match(ev["filename"]) or _match(ev["filepath"]) or _match(ev["category"]):
                results.append({
                    "source": "evidence", "type": ev["category"],
                    "match":  ev["filename"] or ev["filepath"],
                    "detail": f"SHA256: {(ev['sha256'] or '')[:32]}",
                    "ts":     ev["acquired_at"],
                    "id":     ev["id"],
                })
    except Exception:
        pass

    # Analysis results
    try:
        ars = db.get_analysis_results(case_id) if case_id else []
        for ar in ars:
            if not _date_ok(ar["created_at"]):
                continue
            if _match(ar["result_summary"]) or _match(ar["analysis_type"]):
                results.append({
                    "source": "analysis", "type": ar["analysis_type"],
                    "match":  ar["result_summary"] or "",
                    "detail": ar["analysis_type"],
                    "ts":     ar["created_at"],
                    "id":     ar["id"],
                })
    except Exception:
        pass

    # Audit trail
    try:
        for at in db.get_audit_trail():
            if not _date_ok(at["timestamp"]):
                continue
            inv_filter = filters.get("investigator")
            if inv_filter and inv_filter.lower() not in str(at["user"] or "").lower():
                continue
            if _match(at["action"]) or _match(at["notes"]) or _match(at["user"]):
                results.append({
                    "source": "audit", "type": at["action"],
                    "match":  at["notes"] or at["action"],
                    "detail": f"User: {at['user']} | Result: {at['result']}",
                    "ts":     at["timestamp"],
                    "id":     at["id"],
                })
    except Exception:
        pass

    # Custody events
    # FIX-BUG-CE-KS: sqlite3.Row has no .get() — use bracket access, "location" column exists
    try:
        ces = db.get_custody_events(case_id=case_id)
        for ce in ces:
            if not _date_ok(ce["timestamp"]):
                continue
            inv_filter = filters.get("investigator")
            if inv_filter and inv_filter.lower() not in str(ce["investigator"] or "").lower():
                continue
            if _match(ce["action"]) or _match(ce["notes"]) or _match(ce["investigator"]):
                results.append({
                    "source": "custody", "type": ce["action"],
                    "match":  ce["notes"] or ce["action"],
                    "detail": f"Investigator: {ce['investigator']} | Location: {ce['location']}",
                    "ts":     ce["timestamp"],
                    "id":     ce["id"],
                })
    except Exception:
        pass

    # Cases (notes, title, case_number, investigator)
    try:
        cases_to_search = ([db.get_case(case_id)] if case_id else db.get_all_cases())
        for c in cases_to_search:
            if c is None:
                continue
            if not _date_ok(c["created_at"]):
                continue
            inv_filter = filters.get("investigator")
            if inv_filter and inv_filter.lower() not in str(c["investigator"] or "").lower():
                continue
            if (_match(c["case_number"]) or _match(c["title"]) or
                    _match(c["investigator"]) or _match(c["notes"])):
                results.append({
                    "source": "case", "type": "case",
                    "match":  c["case_number"] + " — " + c["title"],
                    "detail": f"Investigator: {c['investigator']}",
                    "ts":     c["created_at"],
                    "id":     c["id"],
                })
    except Exception:
        pass

    # Sort by timestamp desc
    results.sort(key=lambda x: str(x.get("ts") or ""), reverse=True)
    return results


# ── Phase 6: Network Information Analysis ───────────────────────────────────────

def analyze_network_info(evidence_dir: str, case_id: Optional[int] = None) -> dict:
    """
    Parse the acquired network_info.txt (written by ADBManager.get_network_info(),
    target='network') and produce standard findings. Does not re-acquire or
    re-derive network data — reads exactly what acquisition already captured.
    Returns {status, evidence_ref, sha256, ip_addresses, interfaces, wifi,
             findings: [make_finding(...), ...]}.
    """
    findings: list[dict] = []
    path = os.path.join(evidence_dir or "", "network_info.txt")

    if not evidence_dir or not os.path.exists(path):
        findings.append(make_finding(
            "network_info", path, "network_info.txt not found — "
            "network target was not acquired for this case",
            severity=SEVERITY_LOW, status=STATUS_NO_DATA, case_id=case_id,
        ))
        return {"status": STATUS_NO_DATA, "evidence_ref": path, "sha256": "",
                "ip_addresses": [], "interfaces": [], "wifi": {}, "findings": findings}

    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError as e:
        findings.append(make_finding(
            "network_info", path, f"Could not read network_info.txt: {e}",
            severity=SEVERITY_LOW, status=STATUS_ERROR, case_id=case_id,
        ))
        return {"status": STATUS_ERROR, "evidence_ref": path, "sha256": "",
                "ip_addresses": [], "interfaces": [], "wifi": {}, "findings": findings}

    sha = _sha256_file(path)

    # Interfaces + IPv4 addresses from the "ip addr" section.
    interfaces: list[str] = []
    ip_addresses: list[str] = []
    iface_re = re.compile(r"^\d+:\s+([\w.@-]+):", re.MULTILINE)
    ip_re    = re.compile(r"inet\s+(\d{1,3}(?:\.\d{1,3}){3})/\d+")
    for m in iface_re.finditer(text):
        iface = m.group(1)
        if iface not in interfaces:
            interfaces.append(iface)
    for m in ip_re.finditer(text):
        ip = m.group(1)
        if ip not in ip_addresses:
            ip_addresses.append(ip)

    # Wi-Fi block.
    wifi: dict = {}
    for line in text.splitlines():
        low = line.strip().lower()
        if low.startswith("ssid"):
            wifi["ssid"] = line.split(":", 1)[-1].strip() if ":" in line else line.strip()
        elif low.startswith("bssid"):
            wifi["bssid"] = line.split(":", 1)[-1].strip() if ":" in line else line.strip()
        elif "wi-fi is" in low:
            wifi["wifi_state"] = line.strip()

    # ── Findings ──
    non_loopback_ips = [ip for ip in ip_addresses if not ip.startswith("127.")]
    if not non_loopback_ips:
        findings.append(make_finding(
            "network_info", path,
            "No active non-loopback IP address recorded at acquisition time",
            severity=SEVERITY_INFO, case_id=case_id, ip_addresses=ip_addresses,
        ))

    vpn_ifaces = [i for i in interfaces
                  if i.lower().startswith(VPN_TUNNEL_INTERFACE_PREFIXES)]
    if vpn_ifaces:
        findings.append(make_finding(
            "network_info", path,
            f"Possible VPN/tunnel interface(s) present: {', '.join(vpn_ifaces)} — "
            f"may mask the device's true network traffic",
            severity=SEVERITY_MEDIUM, case_id=case_id, interfaces=vpn_ifaces,
        ))

    wifi_state = wifi.get("wifi_state", "")
    if wifi_state and "enabled" not in wifi_state.lower():
        findings.append(make_finding(
            "network_info", path, f"Wi-Fi state at acquisition: {wifi_state}",
            severity=SEVERITY_INFO, case_id=case_id,
        ))

    if wifi.get("ssid"):
        findings.append(make_finding(
            "network_info", path,
            f"Device was associated with Wi-Fi network: {wifi.get('ssid')}",
            severity=SEVERITY_INFO, case_id=case_id, ssid=wifi.get("ssid"),
            bssid=wifi.get("bssid", ""),
        ))

    if not findings:
        findings.append(make_finding(
            "network_info", path, "Network information parsed — no anomalies flagged",
            severity=SEVERITY_INFO, case_id=case_id,
        ))

    return {
        "status":       STATUS_COMPLETED,
        "evidence_ref": path,
        "sha256":       sha,
        "ip_addresses": ip_addresses,
        "interfaces":   interfaces,
        "wifi":         wifi,
        "findings":     findings,
    }


# ── Phase 6: Battery / System Analysis ──────────────────────────────────────────

def analyze_battery_system(evidence_dir: str, db=None, case_id: Optional[int] = None,
                            device: Optional[dict] = None) -> dict:
    """
    Parse the acquired battery_info.json (ADBManager.get_battery_info(), target=
    'battery') and combine it with the device's system record already stored
    in the DB (devices table — Android/SDK/USB-debugging) for a Battery/System
    finding set. Reuses the existing device row rather than re-querying ADB.
    Returns {status, evidence_ref, battery, device, findings: [...]}.
    """
    findings: list[dict] = []
    path = os.path.join(evidence_dir or "", "battery_info.json")

    battery: dict = {}
    if not evidence_dir or not os.path.exists(path):
        findings.append(make_finding(
            "battery_system", path, "battery_info.json not found — "
            "battery target was not acquired for this case",
            severity=SEVERITY_LOW, status=STATUS_NO_DATA, case_id=case_id,
        ))
    else:
        try:
            with open(path, encoding="utf-8") as f:
                battery = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            findings.append(make_finding(
                "battery_system", path, f"Could not read battery_info.json: {e}",
                severity=SEVERITY_LOW, status=STATUS_ERROR, case_id=case_id,
            ))

    if battery:
        health = str(battery.get("health", "Unknown"))
        if health not in ("Good", "Unknown"):
            findings.append(make_finding(
                "battery_system", path, f"Battery health reported as '{health}'",
                severity=SEVERITY_MEDIUM, case_id=case_id, health=health,
            ))
        temp = battery.get("temperature", 0.0) or 0.0
        try:
            if float(temp) >= 45.0:
                findings.append(make_finding(
                    "battery_system", path,
                    f"Elevated battery temperature at acquisition: {temp}°C",
                    severity=SEVERITY_HIGH, case_id=case_id, temperature=temp,
                ))
        except (TypeError, ValueError):
            pass
        level = battery.get("level", None)
        if isinstance(level, (int, float)) and level <= 5:
            findings.append(make_finding(
                "battery_system", path,
                f"Battery level was critically low ({level}%) at acquisition time",
                severity=SEVERITY_INFO, case_id=case_id, level=level,
            ))

    # System / device record — reuse the existing devices row, never re-derive it.
    dev = dict(device) if device else None
    if dev is None and db is not None and case_id is not None:
        try:
            devices = db.get_devices_for_case(case_id)
            dev = dict(devices[0]) if devices else None
        except Exception:
            dev = None

    if dev:
        if dev.get("usb_debugging"):
            findings.append(make_finding(
                "battery_system", f"device:{dev.get('serial','')}",
                "USB debugging was enabled on the device at acquisition time "
                "(expected for ADB-based acquisition, but widens the attack "
                "surface if left enabled after the investigation)",
                severity=SEVERITY_LOW, case_id=case_id,
            ))
        sdk = dev.get("sdk_version", "Unknown")
        try:
            if sdk not in (None, "Unknown") and int(sdk) < 26:
                findings.append(make_finding(
                    "battery_system", f"device:{dev.get('serial','')}",
                    f"Device is running an outdated Android SDK ({sdk}) — "
                    f"known unpatched vulnerabilities are more likely",
                    severity=SEVERITY_MEDIUM, case_id=case_id, sdk_version=sdk,
                ))
        except (TypeError, ValueError):
            pass
    elif not battery:
        # Neither battery file nor device row available — already reported above.
        pass

    if not findings:
        findings.append(make_finding(
            "battery_system", path, "Battery/system information parsed — "
            "no anomalies flagged", severity=SEVERITY_INFO, case_id=case_id,
        ))

    return {
        "status":       STATUS_COMPLETED if (battery or dev) else STATUS_NO_DATA,
        "evidence_ref": path,
        "battery":      battery,
        "device":       dev or {},
        "findings":     findings,
    }


# ── Phase 6: Hash / Integrity Analysis ──────────────────────────────────────────

def analyze_hash_integrity(db, case_id: int) -> dict:
    """
    Wrap the EXISTING integrity engine / verification history into the
    standard finding shape. No hash is recomputed and no verification logic
    is duplicated here — this reads CaseManager.get_case_integrity_summary()
    and get_last_verification_per_evidence(), which are the same calls the
    Integrity panel already uses.
    Returns {status, summary: {...}, findings: [...]}.
    """
    summary = db.get_case_integrity_summary(case_id)
    last_by_ev = db.get_last_verification_per_evidence(case_id)
    findings: list[dict] = []

    for ev in db.get_evidence_for_case(case_id):
        ev = dict(ev)
        vr = last_by_ev.get(ev["id"])
        ref = ev.get("filepath") or ev.get("filename") or f"evidence:{ev['id']}"
        if vr is None:
            findings.append(make_finding(
                "hash_integrity", ref,
                f"{ev.get('filename') or 'Evidence #' + str(ev['id'])} has never "
                f"been integrity-verified since acquisition",
                severity=SEVERITY_MEDIUM, case_id=case_id, evidence_id=ev["id"],
                stored_sha256=ev.get("sha256", ""),
            ))
            continue
        result = vr["result"]
        if result in ("MATCH", "PASS"):
            findings.append(make_finding(
                "hash_integrity", ref,
                f"{ev.get('filename') or 'Evidence #' + str(ev['id'])} SHA-256 "
                f"verified — matches the hash recorded at acquisition",
                severity=SEVERITY_INFO, case_id=case_id, evidence_id=ev["id"],
                stored_sha256=vr["stored_hash"], current_sha256=vr["current_hash"],
            ))
        elif result == "MISSING":
            findings.append(make_finding(
                "hash_integrity", ref,
                f"{ev.get('filename') or 'Evidence #' + str(ev['id'])} is MISSING "
                f"from disk at last verification",
                severity=SEVERITY_HIGH, case_id=case_id, evidence_id=ev["id"],
            ))
        else:  # MISMATCH / FAIL / CORRUPTED / ERROR
            findings.append(make_finding(
                "hash_integrity", ref,
                f"{ev.get('filename') or 'Evidence #' + str(ev['id'])} SHA-256 "
                f"{result} — recorded hash does not match the current file",
                severity=SEVERITY_CRITICAL, case_id=case_id, evidence_id=ev["id"],
                stored_sha256=vr["stored_hash"], current_sha256=vr["current_hash"],
            ))

    if not findings:
        findings.append(make_finding(
            "hash_integrity", f"case:{case_id}",
            "No evidence items to verify for this case",
            severity=SEVERITY_INFO, case_id=case_id,
        ))

    return {"status": STATUS_COMPLETED, "summary": summary, "findings": findings}


# ── Phase 6: Suspicious Artifact Detection ──────────────────────────────────────

def detect_suspicious_artifacts(evidence_dir: str, db=None,
                                 case_id: Optional[int] = None) -> dict:
    """
    Sweep evidence for suspicious artifacts at both the filesystem and
    application level. Reuses classify_app()/SUSPICIOUS_* tables for apps
    (does not re-implement app classification) and HIGH_RISK_EXTENSIONS /
    SUSPICIOUS_FILENAME_MARKERS for filenames.
    Returns {status, findings: [...]}.
    """
    findings: list[dict] = []

    # 1. Filesystem sweep.
    if evidence_dir and os.path.exists(evidence_dir):
        for root, _, files in os.walk(evidence_dir):
            for fname in files:
                fpath = os.path.join(root, fname)
                low   = fname.lower()
                ext   = Path(low).suffix

                marker_hit = next((m for m in SUSPICIOUS_FILENAME_MARKERS if m in low), None)
                if marker_hit:
                    findings.append(make_finding(
                        "suspicious_artifact", fpath,
                        f"Filename matches known suspicious-tooling marker "
                        f"'{marker_hit}': {fname}",
                        severity=SEVERITY_HIGH, case_id=case_id, marker=marker_hit,
                    ))
                elif ext in HIGH_RISK_EXTENSIONS:
                    findings.append(make_finding(
                        "suspicious_artifact", fpath,
                        f"High-risk file extension '{ext}' found: {fname}",
                        severity=SEVERITY_LOW, case_id=case_id, extension=ext,
                    ))

    # 2. Application-level sweep — reuse analyze_apps()/classify_app(), no duplication.
    if evidence_dir:
        apps_path = os.path.join(evidence_dir, "installed_apps.json")
        if os.path.exists(apps_path):
            apps_data = analyze_apps(apps_path)
            for app in apps_data.get("apps", []):
                if app.get("status") == "suspicious":
                    findings.append(make_finding(
                        "suspicious_artifact", f"app:{app.get('package','')}",
                        f"Installed application classified as suspicious: "
                        f"{app.get('package','')} (installer: {app.get('installer','unknown')})",
                        severity=SEVERITY_HIGH, case_id=case_id,
                        package=app.get("package", ""),
                    ))
                elif app.get("status") == "review":
                    findings.append(make_finding(
                        "suspicious_artifact", f"app:{app.get('package','')}",
                        f"Installed application flagged for review — unknown "
                        f"installer source: {app.get('package','')}",
                        severity=SEVERITY_MEDIUM, case_id=case_id,
                        package=app.get("package", ""),
                    ))

    if not findings:
        findings.append(make_finding(
            "suspicious_artifact", evidence_dir or f"case:{case_id}",
            "No suspicious artifacts detected in evidence or application inventory",
            severity=SEVERITY_INFO, case_id=case_id,
        ))

    return {"status": STATUS_COMPLETED, "findings": findings,
            "suspicious_count": sum(1 for f in findings
                                     if f["severity"] in (SEVERITY_HIGH, SEVERITY_CRITICAL))}


# ── Phase 6: IOC Search ──────────────────────────────────────────────────────────

def search_iocs(evidence_dir: str, db, case_id: int, iocs: list[str]) -> dict:
    """
    Search a supplied list of Indicators of Compromise (hash / IP / domain /
    package name / filename fragment) across the case. Reuses
    keyword_search_global() (DB-wide search), analyze_apps() (package match),
    and analyze_network_info() (IP/domain match) instead of re-implementing
    search logic for each source.
    Returns {status, iocs_searched, findings: [...]}.
    """
    findings: list[dict] = []
    iocs = [i.strip() for i in (iocs or []) if i and i.strip()]

    if not iocs:
        return {"status": STATUS_NO_DATA, "iocs_searched": [],
                "findings": [make_finding(
                    "ioc_search", f"case:{case_id}", "No IOCs supplied to search for",
                    severity=SEVERITY_INFO, case_id=case_id, status=STATUS_NO_DATA,
                )]}

    # Network data, parsed once and reused for every IOC (IP/SSID match).
    net = analyze_network_info(evidence_dir, case_id=case_id) if evidence_dir else None

    for ioc in iocs:
        ioc_low = ioc.lower()
        matched = False

        # 1. DB-wide keyword search — reuses keyword_search_global() verbatim.
        try:
            db_hits = keyword_search_global(ioc, db, case_id=case_id) if db else []
        except Exception:
            db_hits = []
        for hit in db_hits:
            matched = True
            findings.append(make_finding(
                "ioc_search", f"{hit.get('source')}:{hit.get('id')}",
                f"IOC '{ioc}' matched {hit.get('source')} record: {hit.get('match')}",
                severity=SEVERITY_HIGH, case_id=case_id, ioc=ioc,
                source=hit.get("source"), matched_type=hit.get("type"),
            ))

        # 2. Evidence SHA-256 match — reuses stored hashes, never recomputed here.
        if case_id:
            try:
                for ev in db.get_evidence_for_case(case_id):
                    if ev["sha256"] and ioc_low == ev["sha256"].lower():
                        matched = True
                        findings.append(make_finding(
                            "ioc_search", ev["filepath"] or ev["filename"],
                            f"IOC '{ioc}' matches SHA-256 of evidence item "
                            f"{ev['filename']}",
                            severity=SEVERITY_CRITICAL, case_id=case_id, ioc=ioc,
                            evidence_id=ev["id"],
                        ))
            except Exception:
                pass

        # 3. Network IP/SSID match — reuses analyze_network_info() output.
        if net:
            if ioc in net.get("ip_addresses", []):
                matched = True
                findings.append(make_finding(
                    "ioc_search", net["evidence_ref"],
                    f"IOC '{ioc}' matches an IP address recorded in network_info.txt",
                    severity=SEVERITY_CRITICAL, case_id=case_id, ioc=ioc,
                ))
            if ioc_low == str(net.get("wifi", {}).get("ssid", "")).lower() and ioc_low:
                matched = True
                findings.append(make_finding(
                    "ioc_search", net["evidence_ref"],
                    f"IOC '{ioc}' matches the Wi-Fi SSID recorded in network_info.txt",
                    severity=SEVERITY_MEDIUM, case_id=case_id, ioc=ioc,
                ))

        if not matched:
            findings.append(make_finding(
                "ioc_search", f"case:{case_id}", f"IOC '{ioc}' — no match found",
                severity=SEVERITY_INFO, case_id=case_id, ioc=ioc,
            ))

    return {"status": STATUS_COMPLETED, "iocs_searched": iocs, "findings": findings}


# ── Analysis Report Generator ──────────────────────────────────────────────────

def generate_analysis_report(case_id: int, db, evidence_dir: str,
                              output_dir: str) -> dict:
    """
    Generate analysis_report.json and analysis_report.html.
    Returns {"json": path, "html": path}.
    """
    os.makedirs(output_dir, exist_ok=True)

    # Gather all data
    case       = dict(db.get_case(case_id)) if db.get_case(case_id) else {}
    evidence   = [dict(e) for e in db.get_evidence_for_case(case_id)]
    timeline   = build_unified_timeline(evidence_dir, db, case_id)
    duplicates = detect_duplicates(evidence_dir, db, case_id)
    correlations = correlate_artifacts(evidence_dir, db, case_id)

    # File metadata
    file_metadata = {}
    if evidence_dir and os.path.exists(evidence_dir):
        files_dir = os.path.join(evidence_dir, "files")
        scan_dir  = files_dir if os.path.exists(files_dir) else evidence_dir
        for root, _, files in os.walk(scan_dir):
            for fn in files:
                fp = os.path.join(root, fn)
                file_metadata[fp] = extract_file_metadata(fp)

    # App analysis
    apps_data = {}
    if evidence_dir:
        apps_path = os.path.join(evidence_dir, "installed_apps.json")
        apps_data = analyze_apps(apps_path)

    # Phase 6: Network / Battery-System / Hash-Integrity / Suspicious Artifacts / IOC
    network_data     = analyze_network_info(evidence_dir, case_id=case_id)
    battery_data     = analyze_battery_system(evidence_dir, db=db, case_id=case_id)
    integrity_data   = analyze_hash_integrity(db, case_id)
    suspicious_data  = detect_suspicious_artifacts(evidence_dir, db=db, case_id=case_id)

    all_findings = (
        network_data.get("findings", []) + battery_data.get("findings", []) +
        integrity_data.get("findings", []) + suspicious_data.get("findings", [])
    )

    # Build report payload
    ts_now = _now_str()
    payload = {
        "report_type":    "ForensIQ Advanced Analysis Report",
        "generated_at":   ts_now,
        "case":           case,
        "summary": {
            "evidence_items":      len(evidence),
            "timeline_events":     len(timeline),
            "duplicate_groups":    duplicates["duplicate_groups"],
            "duplicate_count":     duplicates["duplicate_count"],
            "file_metadata_count": len(file_metadata),
            "total_apps":          apps_data.get("total", 0),
            "suspicious_apps":     apps_data.get("summary", {}).get("suspicious", 0),
            "suspicious_artifacts": suspicious_data.get("suspicious_count", 0),
            "high_critical_findings": sum(
                1 for f in all_findings
                if f.get("severity") in (SEVERITY_HIGH, SEVERITY_CRITICAL)
            ),
        },
        "timeline":       timeline[:500],   # cap at 500 for JSON size
        "file_metadata":  list(file_metadata.values())[:200],
        "applications":   apps_data,
        "duplicates":     duplicates,
        "correlations":   correlations,
        "network":        network_data,
        "battery_system": battery_data,
        "hash_integrity": integrity_data,
        "suspicious_artifacts": suspicious_data,
        "findings":       sorted(
            all_findings,
            key=lambda f: SEVERITY_ORDER.get(f.get("severity", "info"), 0),
            reverse=True,
        )[:500],
    }

    # Write JSON
    json_path = os.path.join(output_dir, "analysis_report.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, default=str)

    # Write HTML
    html_path = os.path.join(output_dir, "analysis_report.html")
    _write_analysis_html(payload, html_path)

    return {"json": json_path, "html": html_path}


def _write_analysis_html(payload: dict, output_path: str):
    """Write analysis_report.html from payload dict."""
    case     = payload.get("case", {})
    summary  = payload.get("summary", {})
    timeline = payload.get("timeline", [])
    dups     = payload.get("duplicates", {})
    corr     = payload.get("correlations", {})
    apps     = payload.get("applications", {})
    findings = payload.get("findings", [])
    ts_gen   = payload.get("generated_at", "")

    # Timeline table rows (capped)
    tl_category_colors = {
        "case":               "#D2A8FF",
        "file_system":        "#1D9E75",
        "evidence":           "#3FB950",
        "device_acquisition": "#58A6FF",
        "analysis":           "#F778BA",
        "verification":       "#E3B341",
        "audit":              "#A5D6FF",
        "custody":            "#F0883E",
    }

    def _device_session_cell(ev: dict) -> str:
        parts = []
        if ev.get("device_id"):
            parts.append(f"dev#{ev['device_id']}")
        if ev.get("session_id"):
            parts.append(f"sess#{ev['session_id']}")
        return " / ".join(parts)

    tl_rows = "\n".join(
        f"""<tr>
          <td class='mono'>{_esc(ev.get('timestamp',''))}</td>
          <td><span class='badge' style='color:{tl_category_colors.get(ev.get("category",""),"#ccc")};
              background:{tl_category_colors.get(ev.get("category",""),"#555")}18;
              border:1px solid {tl_category_colors.get(ev.get("category",""),"#555")}33;
              padding:2px 8px;border-radius:10px;font-size:10px;font-weight:600'>
              {_esc(ev.get('category',''))}</span></td>
          <td>{_esc(ev.get('event_type',''))}</td>
          <td>{_esc(ev.get('description',''))}</td>
          <td class='mono'>{_esc(ev.get('evidence_id') or '')}</td>
          <td class='mono'>{_esc(_device_session_cell(ev))}</td>
          <td>{_esc(ev.get('actor',''))}</td>
        </tr>"""
        for ev in timeline[:200]
    )

    # Duplicates rows
    dup_rows = "\n".join(
        f"""<tr>
          <td class='mono'>{_esc(d['sha256'][:48])}</td>
          <td>{d['count']}</td>
          <td>{_human_size(d['size'])}</td>
          <td><small>{_esc(', '.join(f['filename'] for f in d['files'][:3]))}</small></td>
        </tr>"""
        for d in dups.get("duplicates", [])[:50]
    )

    # App inventory rows
    app_inv = apps.get("inventory", {})
    app_rows = "\n".join(
        f"""<tr>
          <td class='mono'>{_esc(a.get('package',''))}</td>
          <td><span style='color:#{"F85149" if a.get("status")=="suspicious" else
              "3FB950" if a.get("status")=="clean" else
              "E3B341" if a.get("status")=="review" else "8B949E"}'>{_esc(a.get('status',''))}</span></td>
          <td>{_esc(a.get('app_type',''))}</td>
          <td>{'✓' if a.get('recently_installed') else ''}</td>
          <td>{_esc(a.get('installer',''))}</td>
        </tr>"""
        for a in apps.get("apps", [])[:100]
    )

    # Phase 6: standardized findings rows (network, battery/system,
    # hash/integrity, suspicious artifacts — all share the same shape)
    severity_colors = {
        "critical": "#F85149", "high": "#F0883E", "medium": "#E3B341",
        "low": "#A5D6FF", "info": "#8B949E",
    }
    finding_rows = "\n".join(
        f"""<tr>
          <td>{_esc(f.get('analysis_type',''))}</td>
          <td><span class='badge' style='color:{severity_colors.get(f.get("severity","info"),"#8B949E")};
              background:{severity_colors.get(f.get("severity","info"),"#8B949E")}18;
              border:1px solid {severity_colors.get(f.get("severity","info"),"#8B949E")}33;
              padding:2px 8px;border-radius:10px;font-size:10px;font-weight:600;
              text-transform:uppercase'>{_esc(f.get('severity',''))}</span></td>
          <td>{_esc(f.get('finding',''))}</td>
          <td class='mono'>{_esc(f.get('timestamp',''))}</td>
          <td class='mono'><small>{_esc(f.get('evidence_ref',''))}</small></td>
        </tr>"""
        for f in findings
    )

    # Correlation summary
    corr_rows = ""
    for key, items in corr.items():
        label = key.replace("_", " ").title()
        count = len(items) if isinstance(items, list) else 0
        color = "#F85149" if "risk" in key or "unverified" in key else "#3FB950"
        corr_rows += f"""<tr>
          <td>{_esc(label)}</td>
          <td style='color:{color};font-weight:600'>{count}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>ForensIQ Analysis Report — {_esc(case.get('case_number',''))}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',Arial,sans-serif;background:#0d1117;color:#e6edf3;
     padding:2rem;font-size:13px;line-height:1.6}}
h1{{color:#1d9e75;font-size:24px;margin-bottom:4px}}
h2{{color:#1d9e75;font-size:13px;margin:2rem 0 0.6rem;padding-left:10px;
    border-left:3px solid #1d9e75;text-transform:uppercase;letter-spacing:.05em}}
.meta{{color:#8b949e;font-size:12px;margin-bottom:1.5rem}}
.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:1.5rem}}
.card{{background:#161b22;border:1px solid #30363d;border-radius:8px;
       padding:1rem;text-align:center}}
.card .num{{font-size:26px;font-weight:600;color:#1d9e75}}
.card .lbl{{font-size:11px;color:#8b949e;margin-top:3px}}
.section{{background:#161b22;border:1px solid #30363d;border-radius:8px;
          padding:1rem;overflow-x:auto;margin-bottom:1.5rem}}
table{{width:100%;border-collapse:collapse;font-size:12px}}
th{{background:#21262d;color:#8b949e;padding:7px 8px;text-align:left;
    font-size:11px;text-transform:uppercase;letter-spacing:.04em;
    border-bottom:1px solid #30363d}}
td{{padding:5px 8px;border-bottom:1px solid #21262d;vertical-align:middle}}
tr:hover td{{background:#1c2128}}
.mono{{font-family:'Courier New',monospace;font-size:11px;word-break:break-all}}
.badge{{display:inline-block}}
.footer{{margin-top:2rem;font-size:11px;color:#484f58;border-top:1px solid
         #21262d;padding-top:1rem;text-align:center}}
</style></head><body>
<h1>🔬 ForensIQ — Advanced Analysis Report</h1>
<div class="meta">
  <strong>Case:</strong> {_esc(case.get('case_number','—'))} &nbsp;·&nbsp;
  <strong>Title:</strong> {_esc(case.get('title','—'))} &nbsp;·&nbsp;
  <strong>Investigator:</strong> {_esc(case.get('investigator','—'))} &nbsp;·&nbsp;
  <strong>Generated:</strong> {_esc(ts_gen)}
</div>

<div class="grid">
  <div class="card"><div class="num">{summary.get('evidence_items',0)}</div><div class="lbl">Evidence Items</div></div>
  <div class="card"><div class="num">{summary.get('timeline_events',0)}</div><div class="lbl">Timeline Events</div></div>
  <div class="card"><div class="num">{summary.get('duplicate_count',0)}</div><div class="lbl">Duplicate Files</div></div>
  <div class="card"><div class="num">{summary.get('suspicious_apps',0)}</div><div class="lbl">Suspicious Apps</div></div>
  <div class="card"><div class="num">{summary.get('suspicious_artifacts',0)}</div><div class="lbl">Suspicious Artifacts</div></div>
  <div class="card"><div class="num">{summary.get('high_critical_findings',0)}</div><div class="lbl">High/Critical Findings</div></div>
</div>

<h2>Analysis Findings — Network, Battery/System, Hash/Integrity, Suspicious Artifacts</h2>
<div class="section">
<table><thead><tr><th>Analysis Type</th><th>Severity</th><th>Finding</th><th>Timestamp</th><th>Evidence Reference</th></tr></thead>
<tbody>{finding_rows or '<tr><td colspan="5" style="color:#8b949e">No findings recorded.</td></tr>'}</tbody>
</table></div>

<h2>Unified Timeline{f" (showing 200 of {len(timeline)})" if len(timeline) > 200 else ""}</h2>
<div class="section">
<table><thead><tr><th>Timestamp</th><th>Category</th><th>Event Type</th><th>Description</th><th>Evidence</th><th>Device/Session</th><th>Actor</th></tr></thead>
<tbody>{tl_rows or '<tr><td colspan="7" style="color:#8b949e">No timeline events.</td></tr>'}</tbody>
</table></div>

<h2>Artifact Correlations</h2>
<div class="section">
<table><thead><tr><th>Correlation Type</th><th>Count</th></tr></thead>
<tbody>{corr_rows or '<tr><td colspan="2" style="color:#8b949e">No correlations.</td></tr>'}</tbody>
</table></div>

<h2>Duplicate Evidence — {dups.get('duplicate_groups',0)} group(s) / {dups.get('duplicate_count',0)} duplicate(s)</h2>
<div class="section">
<table><thead><tr><th>SHA-256</th><th>Copies</th><th>Size</th><th>Files</th></tr></thead>
<tbody>{dup_rows or '<tr><td colspan="4" style="color:#8b949e">No duplicates detected.</td></tr>'}</tbody>
</table></div>

<h2>Application Inventory — {apps.get('total',0)} apps
  (System: {app_inv.get('system',0)}, User: {app_inv.get('user',0)},
   Disabled: {app_inv.get('disabled',0)}, Recent: {app_inv.get('recently_installed',0)})</h2>
<div class="section">
<table><thead><tr><th>Package</th><th>Status</th><th>Type</th><th>Recent</th><th>Installer</th></tr></thead>
<tbody>{app_rows or '<tr><td colspan="5" style="color:#8b949e">No applications data.</td></tr>'}</tbody>
</table></div>

<div class="footer">ForensIQ Advanced Analysis Report &nbsp;·&nbsp; {_esc(ts_gen)} &nbsp;·&nbsp;
Generated by ForensIQ Upgrade Pack C</div>
</body></html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)


# ── Background Worker ──────────────────────────────────────────────────────────

class AnalysisWorker(QThread):
    if _QT_AVAILABLE:
        progress = pyqtSignal(int, str)
        finished = pyqtSignal(dict)
        error    = pyqtSignal(str)

    def __init__(self, evidence_dir: str, tasks: list[str],
                 db=None, case_id: int = None, iocs: list[str] = None):
        if not _QT_AVAILABLE:
            raise ImportError(
                "PyQt6 is required to run AnalysisWorker in a background "
                "thread. The analyzer functions themselves do not require "
                "PyQt6 and can be called directly for headless use."
            )
        super().__init__()
        self.evidence_dir = evidence_dir
        self.tasks        = tasks
        self.db           = db
        self.case_id      = case_id
        self.iocs         = iocs or []

    def run(self):
        results = {}
        total   = len(self.tasks)

        for i, task in enumerate(self.tasks):
            self.progress.emit(int(i / total * 100), f"Running: {task} …")
            try:
                if task == "apps":
                    path = os.path.join(self.evidence_dir, "installed_apps.json")
                    results["apps"] = analyze_apps(path)

                elif task == "file_metadata":
                    meta = {}
                    files_dir = os.path.join(self.evidence_dir, "files")
                    scan_dir  = files_dir if os.path.exists(files_dir) else self.evidence_dir
                    for root, _, files in os.walk(scan_dir):
                        for fn in files:
                            fp = os.path.join(root, fn)
                            meta[fp] = extract_file_metadata(fp)
                    results["file_metadata"] = meta

                elif task == "timeline":
                    if self.db and self.case_id:
                        results["timeline"] = build_unified_timeline(
                            self.evidence_dir, self.db, self.case_id
                        )
                    else:
                        results["timeline"] = build_file_timeline(self.evidence_dir)

                elif task == "duplicates":
                    results["duplicates"] = detect_duplicates(
                        self.evidence_dir, self.db, self.case_id
                    )

                elif task == "correlations":
                    if self.db and self.case_id:
                        results["correlations"] = correlate_artifacts(
                            self.evidence_dir, self.db, self.case_id
                        )

                elif task == "analysis_report":
                    if self.db and self.case_id:
                        out_dir = self.evidence_dir
                        results["analysis_report"] = generate_analysis_report(
                            self.case_id, self.db, self.evidence_dir, out_dir
                        )

                # ── Phase 6 tasks ──
                elif task == "network":
                    results["network"] = analyze_network_info(
                        self.evidence_dir, case_id=self.case_id
                    )

                elif task == "battery":
                    results["battery"] = analyze_battery_system(
                        self.evidence_dir, db=self.db, case_id=self.case_id
                    )

                elif task == "hash_integrity":
                    if self.db and self.case_id:
                        results["hash_integrity"] = analyze_hash_integrity(
                            self.db, self.case_id
                        )

                elif task == "suspicious_artifacts":
                    results["suspicious_artifacts"] = detect_suspicious_artifacts(
                        self.evidence_dir, db=self.db, case_id=self.case_id
                    )

                elif task == "ioc_search":
                    results["ioc_search"] = search_iocs(
                        self.evidence_dir, self.db, self.case_id, self.iocs
                    )

            except Exception as e:
                results[task] = {"error": str(e)}
                self.error.emit(f"{task}: {e}")

        self.progress.emit(100, "Analysis complete.")
        self.finished.emit(results)
