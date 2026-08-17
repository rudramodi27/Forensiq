"""
Case Manager — SQLite-backed storage for cases, devices, evidence, analysis results.

FIXES:
  - Added DB indexes on all foreign-key columns (performance)
  - Added schema migration: safely adds columns missing from older DBs
  - update_case() method added for full case editing
  - get_evidence_count() now uses COUNT(*) efficiently
  - keyword_search() handles None match values gracefully

Phase 8 — Advanced Case Management: extends the existing case record and
`update_case_status()` (previously a flat active/closed/archived set) with
a full case-management workflow:
  - Status workflow: DRAFT -> ACTIVE -> UNDER_INVESTIGATION -> REVIEW ->
    CLOSED -> ARCHIVED, with an explicit valid-transition graph (including
    reopen paths) enforced in update_case_status(). Every status change is
    still recorded through the existing audit_trail/timeline system (see
    AuditService.log_case_status_changed + analyzer.build_unified_timeline)
    — nothing new is added to that pipeline, it is reused as-is.
  - New case metadata columns (priority, reviewer, tags, closure_reason),
    added the same additive-migration way every prior phase added columns
    (see _MIGRATIONS): safe no-op on DBs that already have them, and
    existing rows get sane defaults, never fabricated values.
  - CLOSED requires a non-empty closure_reason; ARCHIVED cases are
    read-only (update_case/update_case_notes refuse edits) until reopened
    back to ACTIVE via update_case_status().
"""

import sqlite3
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from forensiq.core.time_utils import now_utc_str as _now_utc_str


DB_PATH = Path.home() / ".forensiq" / "forensiq.db"

# Base schema — CREATE TABLE IF NOT EXISTS is idempotent
SCHEMA = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS cases (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    case_number    TEXT UNIQUE NOT NULL,
    title          TEXT NOT NULL,
    investigator   TEXT NOT NULL,
    description    TEXT DEFAULT '',
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'DRAFT',
    notes          TEXT DEFAULT '',
    evidence_dir   TEXT DEFAULT '',
    priority       TEXT NOT NULL DEFAULT 'MEDIUM',
    reviewer       TEXT DEFAULT '',
    tags           TEXT NOT NULL DEFAULT '[]',
    closure_reason TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS devices (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id         INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    serial          TEXT NOT NULL,
    model           TEXT DEFAULT 'Unknown',
    manufacturer    TEXT DEFAULT 'Unknown',
    android_version TEXT DEFAULT 'Unknown',
    sdk_version     TEXT DEFAULT 'Unknown',
    build_number    TEXT DEFAULT 'Unknown',
    cpu_abi         TEXT DEFAULT 'Unknown',
    usb_debugging   INTEGER NOT NULL DEFAULT 0,
    acquired_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id     INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    device_id   INTEGER REFERENCES devices(id) ON DELETE SET NULL,
    category    TEXT NOT NULL,
    filename    TEXT DEFAULT '',
    filepath    TEXT DEFAULT '',
    sha256      TEXT DEFAULT '',
    file_size   INTEGER NOT NULL DEFAULT 0,
    acquired_at TEXT NOT NULL,
    metadata    TEXT NOT NULL DEFAULT '{}'
);

-- Phase 3 — Device Acquisition Accuracy: one physical device (one `devices`
-- row, keyed on case_id+serial — see add_device()) can be connected /
-- acquired from multiple times. Each connection/acquisition run is one
-- `acquisition_sessions` row, never a new device identity.
CREATE TABLE IF NOT EXISTS acquisition_sessions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id         INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    device_id       INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    start_time      TEXT NOT NULL,
    end_time        TEXT,
    status          TEXT NOT NULL DEFAULT 'in_progress',
    adb_state       TEXT DEFAULT 'Unknown',
    usb_debugging   INTEGER NOT NULL DEFAULT 0,
    device_snapshot TEXT NOT NULL DEFAULT '{}',
    targets         TEXT NOT NULL DEFAULT '[]',
    output_dir      TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS analysis_results (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id        INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    evidence_id    INTEGER REFERENCES evidence(id) ON DELETE SET NULL,
    analysis_type  TEXT NOT NULL,
    result_summary TEXT DEFAULT '',
    result_data    TEXT NOT NULL DEFAULT '{}',
    created_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS timeline_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id     INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    evidence_id INTEGER REFERENCES evidence(id) ON DELETE SET NULL,
    event_type  TEXT NOT NULL,
    description TEXT NOT NULL,
    timestamp   TEXT NOT NULL,
    source_file TEXT DEFAULT '',
    metadata    TEXT NOT NULL DEFAULT '{}'
);

-- Performance indexes on foreign keys and common filter columns
CREATE INDEX IF NOT EXISTS idx_devices_case   ON devices(case_id);
CREATE INDEX IF NOT EXISTS idx_evidence_case  ON evidence(case_id);
CREATE INDEX IF NOT EXISTS idx_evidence_cat   ON evidence(case_id, category);
CREATE INDEX IF NOT EXISTS idx_analysis_case  ON analysis_results(case_id);
CREATE INDEX IF NOT EXISTS idx_timeline_case  ON timeline_events(case_id);
CREATE INDEX IF NOT EXISTS idx_timeline_ts    ON timeline_events(case_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_sessions_case    ON acquisition_sessions(case_id);
CREATE INDEX IF NOT EXISTS idx_sessions_device  ON acquisition_sessions(device_id);
CREATE INDEX IF NOT EXISTS idx_sessions_start   ON acquisition_sessions(device_id, start_time);
CREATE TABLE IF NOT EXISTS verification_results (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id             INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    evidence_id         INTEGER REFERENCES evidence(id) ON DELETE SET NULL,
    verification_time   TEXT NOT NULL,
    result              TEXT NOT NULL,   -- PASS | FAIL | MISSING | ERROR
    stored_hash         TEXT NOT NULL DEFAULT '',
    current_hash        TEXT NOT NULL DEFAULT '',
    notes               TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_verification_case ON verification_results(case_id);
CREATE INDEX IF NOT EXISTS idx_verification_ev   ON verification_results(evidence_id);
CREATE INDEX IF NOT EXISTS idx_verification_time ON verification_results(case_id, verification_time);

CREATE TABLE IF NOT EXISTS audit_trail (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT NOT NULL,
    user        TEXT NOT NULL DEFAULT '',
    action      TEXT NOT NULL,
    target_type TEXT NOT NULL DEFAULT '',
    target_id   TEXT NOT NULL DEFAULT '',
    result      TEXT NOT NULL DEFAULT 'OK',
    notes       TEXT NOT NULL DEFAULT ''
    -- No FK on case_id: audit records are IMMUTABLE and survive case deletion
);

CREATE TABLE IF NOT EXISTS custody_events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id      INTEGER REFERENCES cases(id) ON DELETE SET NULL,
    evidence_id  INTEGER REFERENCES evidence(id) ON DELETE SET NULL,
    timestamp    TEXT NOT NULL,
    investigator TEXT NOT NULL DEFAULT '',
    action       TEXT NOT NULL,
    location     TEXT NOT NULL DEFAULT '',
    notes        TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp  ON audit_trail(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_action     ON audit_trail(action);
CREATE INDEX IF NOT EXISTS idx_audit_user       ON audit_trail(user);
CREATE INDEX IF NOT EXISTS idx_custody_case     ON custody_events(case_id);
CREATE INDEX IF NOT EXISTS idx_custody_evidence ON custody_events(evidence_id);
CREATE INDEX IF NOT EXISTS idx_custody_ts       ON custody_events(timestamp);

-- Phase 5 — Digital Signature: one immutable row per sign operation on a
-- generated artifact (Case Evidence Manifest or forensic Report). Never
-- stores a private key — only the public-facing signature metadata
-- (signer, algorithm, timestamp, artifact hash, signature bytes, and the
-- key_id fingerprint needed to look up the public key for verification).
-- Append-only, same pattern as verification_results/audit_trail: no
-- update/delete method is exposed for this table.
CREATE TABLE IF NOT EXISTS signatures (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id         INTEGER REFERENCES cases(id) ON DELETE SET NULL,
    artifact_type   TEXT NOT NULL,            -- MANIFEST | REPORT
    artifact_path   TEXT NOT NULL,
    artifact_sha256 TEXT NOT NULL,
    signature_path  TEXT NOT NULL DEFAULT '', -- detached .sig.json sidecar file
    signature       TEXT NOT NULL,            -- base64-encoded signature bytes
    algorithm       TEXT NOT NULL,            -- e.g. Ed25519
    signer          TEXT NOT NULL DEFAULT '',
    key_id          TEXT NOT NULL DEFAULT '', -- public-key fingerprint, never the key itself
    signed_at       TEXT NOT NULL,
    notes           TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_signatures_case     ON signatures(case_id);
CREATE INDEX IF NOT EXISTS idx_signatures_artifact ON signatures(artifact_path);
CREATE INDEX IF NOT EXISTS idx_signatures_signed_at ON signatures(signed_at);
"""

# Migrations: (column, table, definition) — applied on startup if missing
_MIGRATIONS = [
    # Add any new columns here for existing DB compatibility
    ("evidence_dir", "cases",   "TEXT DEFAULT ''"),
    ("file_size",    "evidence", "INTEGER NOT NULL DEFAULT 0"),
    ("cpu_abi",      "devices",  "TEXT DEFAULT 'Unknown'"),
    ("build_number", "devices",  "TEXT DEFAULT 'Unknown'"),
    # Phase 2 — Chain of Custody & Audit Trail: transfer source/destination
    # and an integrity snapshot at the time of the custody event, so a
    # TRANSFERRED (or any) event can show what the evidence's integrity
    # state was at that moment without re-deriving it after the fact.
    ("from_location",    "custody_events", "TEXT DEFAULT ''"),
    ("to_location",      "custody_events", "TEXT DEFAULT ''"),
    ("integrity_status", "custody_events", "TEXT DEFAULT ''"),
    # Phase 3 — Device Acquisition Accuracy: device identity is stable
    # (one row per case+serial, see add_device()); these two columns track
    # the connection lifespan of that identity across every acquisition
    # run without ever creating a new device row.
    ("first_connected", "devices",  "TEXT DEFAULT ''"),
    ("last_connected",  "devices",  "TEXT DEFAULT ''"),
    # Links an evidence row to the specific acquisition_sessions run that
    # produced it. Nullable + ON DELETE SET NULL so deleting a session
    # never deletes evidence or breaks the SHA-256/custody history.
    ("session_id", "evidence", "INTEGER REFERENCES acquisition_sessions(id) ON DELETE SET NULL"),
    # Phase 7 — Unified Forensic Timeline: every timeline event now carries
    # its category (case/evidence/device_acquisition/analysis/verification/
    # audit/custody/file_system), the investigator/actor responsible where
    # known, and — where the event originated from a specific physical
    # device or acquisition run — links to that device/session. All four
    # are nullable/empty-default so existing rows and existing callers of
    # add_timeline_event()/get_timeline() are unaffected.
    ("category",   "timeline_events", "TEXT DEFAULT ''"),
    ("actor",      "timeline_events", "TEXT DEFAULT ''"),
    ("device_id",  "timeline_events", "INTEGER REFERENCES devices(id) ON DELETE SET NULL"),
    ("session_id", "timeline_events", "INTEGER REFERENCES acquisition_sessions(id) ON DELETE SET NULL"),
    # Phase 8 — Advanced Case Management: new case metadata columns.
    # Nullable/empty-default so existing rows and existing callers of
    # create_case()/update_case() are unaffected; nothing is fabricated
    # for pre-existing cases beyond these safe empty defaults.
    ("priority",       "cases", "TEXT NOT NULL DEFAULT 'MEDIUM'"),
    ("reviewer",       "cases", "TEXT DEFAULT ''"),
    ("tags",           "cases", "TEXT NOT NULL DEFAULT '[]'"),
    ("closure_reason", "cases", "TEXT DEFAULT ''"),
]

# ── Phase 8 — Case status workflow ──────────────────────────────────────────
#
# DRAFT -> ACTIVE -> UNDER_INVESTIGATION -> REVIEW -> CLOSED -> ARCHIVED
#
# CASE_STATUSES is the full canonical vocabulary (uppercase). Legacy
# pre-Phase-8 databases stored lowercase 'active' | 'closed' | 'archived';
# _run_migrations() normalises those in place (UPPER()) since it is a
# case-only formatting change, not fabricated history — the same real
# status is kept, just spelled the canonical way.
CASE_STATUSES = (
    "DRAFT", "ACTIVE", "UNDER_INVESTIGATION", "REVIEW", "CLOSED", "ARCHIVED",
)

# Valid forward transitions plus explicit reopen paths. CLOSED/ARCHIVED can
# both return a case to ACTIVE ("reopen") per the Phase 8 requirement that
# archived cases are read-only "unless the existing architecture requires
# reopening" — reopening is therefore modeled as an explicit, auditable
# status transition rather than a silent unlock.
CASE_STATUS_TRANSITIONS = {
    "DRAFT":                {"ACTIVE"},
    "ACTIVE":                {"UNDER_INVESTIGATION", "REVIEW", "CLOSED"},
    "UNDER_INVESTIGATION":  {"REVIEW", "ACTIVE", "CLOSED"},
    "REVIEW":                {"UNDER_INVESTIGATION", "ACTIVE", "CLOSED"},
    "CLOSED":                {"ARCHIVED", "ACTIVE"},
    "ARCHIVED":              {"ACTIVE"},
}

CASE_STATUS_LABELS = {
    "DRAFT": "Draft",
    "ACTIVE": "Active",
    "UNDER_INVESTIGATION": "Under Investigation",
    "REVIEW": "Review",
    "CLOSED": "Closed",
    "ARCHIVED": "Archived",
}

STATUS_COLORS = {
    "DRAFT":               "#8B949E",
    "ACTIVE":              "#3FB950",
    "UNDER_INVESTIGATION": "#E3B341",
    "REVIEW":              "#A5D6FF",
    "CLOSED":              "#F0883E",
    "ARCHIVED":            "#6E7681",
}

CASE_PRIORITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

PRIORITY_COLORS = {
    "LOW":      "#8B949E",
    "MEDIUM":   "#58A6FF",
    "HIGH":     "#E3B341",
    "CRITICAL": "#F85149",
}


def normalize_case_status(status: str) -> str:
    """Uppercase + strip; legacy lowercase values map onto the same word."""
    return str(status or "").strip().upper()


# Phase 10: now_utc() is kept here (re-exported) so every existing caller
# across the codebase (`from forensiq.core.case_manager import now_utc`)
# keeps working unchanged — it now delegates to the single centralized
# implementation in time_utils instead of formatting the clock itself.
def now_utc() -> str:
    return _now_utc_str()


class CaseManager:
    def __init__(self, db_path: str = None):
        self.db_path = Path(db_path) if db_path else DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        return conn

    def _init_db(self):
        with self._connect() as conn:
            conn.executescript(SCHEMA)
        self._run_migrations()

    def _run_migrations(self):
        """Safely add missing columns to existing databases."""
        with self._connect() as conn:
            for col, table, defn in _MIGRATIONS:
                try:
                    # Check if column exists
                    cur = conn.execute(f"PRAGMA table_info({table})")
                    cols = {row["name"] for row in cur.fetchall()}
                    if col not in cols:
                        conn.execute(
                            f"ALTER TABLE {table} ADD COLUMN {col} {defn}"
                        )
                except sqlite3.OperationalError:
                    pass  # Column already exists or table doesn't exist yet

            # Phase 3 data backfill: existing `devices` rows created before
            # first_connected/last_connected existed already have a known
            # connection timestamp — acquired_at — recorded at insert time.
            # Carrying that forward into the two new columns is NOT
            # inventing history (the value already existed); it just makes
            # it queryable under its new name. Only rows where the new
            # columns are still empty are touched, so this is a safe no-op
            # on a database that has already been migrated, and it never
            # fabricates acquisition_sessions rows for old acquisitions.
            try:
                conn.execute(
                    "UPDATE devices SET first_connected = acquired_at "
                    "WHERE first_connected IS NULL OR first_connected = ''"
                )
                conn.execute(
                    "UPDATE devices SET last_connected = acquired_at "
                    "WHERE last_connected IS NULL OR last_connected = ''"
                )
            except sqlite3.OperationalError:
                pass  # devices table/columns not present yet (fresh DB mid-init)

            # Phase 8 data normalisation: pre-Phase-8 databases stored
            # status as lowercase ('active' | 'closed' | 'archived'). This
            # is a spelling/casing normalisation of the SAME real value —
            # not a status change and not fabricated history — so every
            # case keeps its true status, just in the canonical uppercase
            # form the new workflow (DRAFT/ACTIVE/UNDER_INVESTIGATION/
            # REVIEW/CLOSED/ARCHIVED) uses. Only rows with a recognised
            # legacy lowercase value are touched; anything else (including
            # already-migrated uppercase rows) is left untouched, so this
            # is a safe no-op on a database that has already been migrated.
            try:
                conn.execute(
                    "UPDATE cases SET status = UPPER(status) "
                    "WHERE status IN ('active', 'closed', 'archived')"
                )
            except sqlite3.OperationalError:
                pass  # cases table not present yet (fresh DB mid-init)

    # ── Cases ──────────────────────────────────────────────────────────────────

    def create_case(self, case_number: str, title: str, investigator: str,
                    description: str = "", notes: str = "",
                    evidence_dir: str = "", priority: str = "MEDIUM",
                    reviewer: str = "", tags: Optional[list] = None) -> int:
        """
        New cases start in DRAFT — the first stage of the Phase 8 status
        workflow (DRAFT -> ACTIVE -> UNDER_INVESTIGATION -> REVIEW ->
        CLOSED -> ARCHIVED). Move a case to ACTIVE via update_case_status()
        once work begins.

        priority defaults to MEDIUM (one of CASE_PRIORITIES); tags is an
        optional list of short strings, stored as JSON.
        """
        priority = normalize_case_status(priority) or "MEDIUM"
        if priority not in CASE_PRIORITIES:
            raise ValueError(f"priority must be one of {CASE_PRIORITIES}, got {priority!r}")
        ts = now_utc()
        with self._connect() as conn:
            cur = conn.execute(
                """INSERT INTO cases
                   (case_number, title, investigator, description,
                    created_at, updated_at, status, notes, evidence_dir,
                    priority, reviewer, tags)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (case_number, title, investigator, description or "",
                 ts, ts, "DRAFT", notes or "", evidence_dir or "",
                 priority, reviewer or "", json.dumps(list(tags or [])))
            )
            return cur.lastrowid

    def get_all_cases(self) -> list[sqlite3.Row]:
        with self._connect() as conn:
            return conn.execute(
                "SELECT * FROM cases ORDER BY created_at DESC"
            ).fetchall()

    def get_case(self, case_id: int) -> Optional[sqlite3.Row]:
        with self._connect() as conn:
            return conn.execute(
                "SELECT * FROM cases WHERE id = ?", (case_id,)
            ).fetchone()

    def _assert_case_editable(self, conn: sqlite3.Connection, case_id: int):
        """
        Phase 8: ARCHIVED cases are read-only. Raises ValueError if the
        case is archived or doesn't exist; callers that legitimately need
        to change status (including reopening an archived case back to
        ACTIVE) go through update_case_status(), which is exempt from this
        check by design.
        """
        row = conn.execute(
            "SELECT status FROM cases WHERE id = ?", (case_id,)
        ).fetchone()
        if row is None:
            raise ValueError(f"Case {case_id} not found")
        if normalize_case_status(row["status"]) == "ARCHIVED":
            raise ValueError(
                "Case is ARCHIVED and read-only. Reopen it (update_case_status "
                "to ACTIVE) before editing."
            )

    def update_case(self, case_id: int, title: str = None,
                    investigator: str = None, description: str = None,
                    evidence_dir: str = None, priority: str = None,
                    reviewer: str = None, tags: Optional[list] = None) -> bool:
        """
        Update editable case fields. Only non-None arguments are changed.
        Raises ValueError if the case is ARCHIVED (read-only) — see
        _assert_case_editable().
        """
        if priority is not None:
            priority = normalize_case_status(priority)
            if priority not in CASE_PRIORITIES:
                raise ValueError(f"priority must be one of {CASE_PRIORITIES}, got {priority!r}")

        sets, vals = [], []
        if title        is not None: sets.append("title = ?");        vals.append(title)
        if investigator is not None: sets.append("investigator = ?"); vals.append(investigator)
        if description  is not None: sets.append("description = ?");  vals.append(description)
        if evidence_dir is not None: sets.append("evidence_dir = ?"); vals.append(evidence_dir)
        if priority     is not None: sets.append("priority = ?");     vals.append(priority)
        if reviewer     is not None: sets.append("reviewer = ?");     vals.append(reviewer)
        if tags         is not None: sets.append("tags = ?");         vals.append(json.dumps(list(tags)))
        if not sets:
            return False
        sets.append("updated_at = ?")
        vals.append(now_utc())
        vals.append(case_id)
        with self._connect() as conn:
            self._assert_case_editable(conn, case_id)
            conn.execute(
                f"UPDATE cases SET {', '.join(sets)} WHERE id = ?", vals
            )
        return True

    def update_case_notes(self, case_id: int, notes: str):
        with self._connect() as conn:
            self._assert_case_editable(conn, case_id)
            conn.execute(
                "UPDATE cases SET notes = ?, updated_at = ? WHERE id = ?",
                (notes, now_utc(), case_id)
            )

    def get_case_tags(self, case_id: int) -> list[str]:
        case = self.get_case(case_id)
        if not case:
            return []
        try:
            return list(json.loads(case["tags"] or "[]"))
        except (TypeError, ValueError):
            return []

    def get_valid_next_statuses(self, current_status: str) -> list[str]:
        """Statuses `current_status` may legally transition to next."""
        return sorted(CASE_STATUS_TRANSITIONS.get(normalize_case_status(current_status), set()))

    def update_case_status(self, case_id: int, status: str,
                           closure_reason: Optional[str] = None) -> bool:
        """
        Transition a case's status, enforcing the Phase 8 workflow graph
        (CASE_STATUS_TRANSITIONS) and the CLOSED-requires-a-reason rule.

        - `status` must be a legal next status for the case's CURRENT
          status (self-transitions and skipped/backward-incompatible
          transitions raise ValueError; see CASE_STATUS_TRANSITIONS).
        - Moving to CLOSED requires a non-empty `closure_reason` (or an
          existing closure_reason already on the case, e.g. re-closing
          after a brief reopen); it is persisted on the case row.
        - Moving OUT of CLOSED/ARCHIVED (reopening) clears closure_reason,
          since the case is no longer in a closed state — the original
          reason remains discoverable in the audit trail/timeline, which
          are never altered by this method.
        - This method does NOT itself write to audit_trail/timeline —
          exactly like the pre-Phase-8 update_case_status(), callers are
          expected to follow it with AuditService.log_case_status_changed()
          (see cases_panel.py), so status changes keep flowing through the
          existing, unmodified audit/timeline pipeline.
        """
        status = normalize_case_status(status)
        if status not in CASE_STATUSES:
            raise ValueError(f"Status must be one of {CASE_STATUSES}, got {status!r}")

        with self._connect() as conn:
            row = conn.execute(
                "SELECT status, closure_reason FROM cases WHERE id = ?", (case_id,)
            ).fetchone()
            if row is None:
                raise ValueError(f"Case {case_id} not found")
            current = normalize_case_status(row["status"])

            allowed = CASE_STATUS_TRANSITIONS.get(current, set())
            if status not in allowed:
                raise ValueError(
                    f"Invalid status transition: {current} -> {status}. "
                    f"Valid next statuses from {current}: {sorted(allowed) or 'none'}"
                )

            new_reason = row["closure_reason"] or ""
            if status == "CLOSED":
                reason = (closure_reason if closure_reason is not None
                          else row["closure_reason"])
                if not (reason or "").strip():
                    raise ValueError(
                        "Closing a case requires a non-empty closure_reason."
                    )
                new_reason = reason.strip()
            elif current in ("CLOSED", "ARCHIVED") and status not in ("CLOSED", "ARCHIVED"):
                # Reopening — the reason no longer describes the case's
                # current (active) state; audit/timeline history keeps it.
                new_reason = ""

            conn.execute(
                "UPDATE cases SET status = ?, closure_reason = ?, updated_at = ? WHERE id = ?",
                (status, new_reason, now_utc(), case_id)
            )
        return True

    def delete_case(self, case_id: int):
        with self._connect() as conn:
            conn.execute("DELETE FROM cases WHERE id = ?", (case_id,))

    def case_number_exists(self, case_number: str) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM cases WHERE case_number = ?", (case_number,)
            ).fetchone()
            return row is not None

    # ── Devices ────────────────────────────────────────────────────────────────

    def add_device(self, case_id: int, device_info) -> int:
        """
        Register a device identity for a case. A physical device is
        stored ONCE per case (see Phase 3 architecture: Case → Device →
        Acquisition Sessions → Evidence) — every connection/acquisition
        against that same physical device is a separate
        `acquisition_sessions` row (see start_acquisition_session()), not
        a new device row.

        FIX (report duplication): previously this always INSERTed a new
        row, so re-running acquisition against the same physical device
        (same serial) within the same case — e.g. pulling different
        evidence categories in separate acquisition runs, or re-acquiring
        to refresh data — created a new `devices` row each time. Reports
        then showed the identical device (same serial/model) multiple
        times, which is implementation duplication, not a genuinely
        distinct device.

        This is a get-or-update-or-create keyed on (case_id, serial) —
        the serial number is the one piece of device information that is
        both stable across reconnections and unique per physical device,
        so it is used as the device's identity key. Do NOT swap this for
        anything that changes between connections (e.g. a timestamp or a
        freshly generated id): a device with the same serial already
        registered to this case has its mutable fields (OS/SDK/build, USB
        debugging state, last_connected) refreshed and its existing id is
        returned, instead of inserting a duplicate row. A different
        serial — a genuinely different physical device — still gets its
        own row, so multi-device cases are unaffected.

        `first_connected` is set once, at initial registration, and never
        overwritten. `last_connected` is refreshed on every call (i.e. on
        every acquisition run against this device).
        """
        ts = now_utc()
        with self._connect() as conn:
            existing = conn.execute(
                "SELECT id FROM devices WHERE case_id = ? AND serial = ?",
                (case_id, device_info.serial)
            ).fetchone()
            if existing:
                conn.execute(
                    """UPDATE devices SET
                           model=?, manufacturer=?, android_version=?,
                           sdk_version=?, build_number=?, cpu_abi=?,
                           usb_debugging=?, last_connected=?
                       WHERE id=?""",
                    (device_info.model,
                     device_info.manufacturer,
                     device_info.android_version,
                     device_info.sdk_version,
                     device_info.build_number,
                     device_info.cpu_abi,
                     int(device_info.usb_debugging),
                     ts,
                     existing["id"])
                )
                return existing["id"]

            cur = conn.execute(
                """INSERT INTO devices
                   (case_id, serial, model, manufacturer, android_version,
                    sdk_version, build_number, cpu_abi, usb_debugging,
                    acquired_at, first_connected, last_connected)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (case_id,
                 device_info.serial,
                 device_info.model,
                 device_info.manufacturer,
                 device_info.android_version,
                 device_info.sdk_version,
                 device_info.build_number,
                 device_info.cpu_abi,
                 int(device_info.usb_debugging),
                 ts, ts, ts)
            )
            return cur.lastrowid

    def get_devices_for_case(self, case_id: int) -> list[sqlite3.Row]:
        with self._connect() as conn:
            return conn.execute(
                "SELECT * FROM devices WHERE case_id = ? ORDER BY acquired_at",
                (case_id,)
            ).fetchall()

    def get_device(self, device_id: int) -> Optional[sqlite3.Row]:
        with self._connect() as conn:
            return conn.execute(
                "SELECT * FROM devices WHERE id = ?", (device_id,)
            ).fetchone()

    # ── Acquisition Sessions ──────────────────────────────────────────────────
    # Case → Device → Acquisition Sessions → Evidence.
    # A physical device is one `devices` row (see add_device()); every
    # distinct connection/acquisition run against it is one
    # `acquisition_sessions` row here. Nothing in this section ever
    # creates a new device identity.

    _SESSION_STATUSES = {"in_progress", "completed", "aborted", "error"}

    def start_acquisition_session(self, case_id: int, device_id: int,
                                   device_snapshot: dict = None,
                                   targets: list = None,
                                   output_dir: str = "",
                                   adb_state: str = "Unknown",
                                   usb_debugging: bool = False) -> int:
        """
        Begin a new Acquisition Session — one row per connection/run
        against an existing device identity.

        `device_snapshot` captures the device's metadata (model, OS/SDK,
        USB debugging state, etc.) AS OF THIS SESSION'S START and is
        stored verbatim (JSON) so it remains a historical record even if
        the device's `devices` row is later refreshed by a subsequent
        session (e.g. after an OS update between acquisitions).
        """
        if device_snapshot is None:
            device_snapshot = {}
        ts = now_utc()
        with self._connect() as conn:
            cur = conn.execute(
                """INSERT INTO acquisition_sessions
                   (case_id, device_id, start_time, status, adb_state,
                    usb_debugging, device_snapshot, targets, output_dir)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (case_id, device_id, ts, "in_progress",
                 adb_state or "Unknown", int(bool(usb_debugging)),
                 json.dumps(device_snapshot), json.dumps(targets or []),
                 output_dir or "")
            )
            session_id = cur.lastrowid
            # A new session means a fresh connection to this device — keep
            # the device identity's last_connected in step with it.
            conn.execute(
                "UPDATE devices SET last_connected = ? WHERE id = ?",
                (ts, device_id)
            )
            return session_id

    def end_acquisition_session(self, session_id: int,
                                 status: str = "completed") -> bool:
        """Close out a session with a terminal status and an end_time."""
        if status not in self._SESSION_STATUSES or status == "in_progress":
            raise ValueError(
                f"status must be one of {self._SESSION_STATUSES - {'in_progress'}}, "
                f"got {status!r}"
            )
        with self._connect() as conn:
            conn.execute(
                """UPDATE acquisition_sessions
                   SET end_time = ?, status = ? WHERE id = ?""",
                (now_utc(), status, session_id)
            )
        return True

    def get_session(self, session_id: int) -> Optional[sqlite3.Row]:
        with self._connect() as conn:
            return conn.execute(
                "SELECT * FROM acquisition_sessions WHERE id = ?",
                (session_id,)
            ).fetchone()

    def get_sessions_for_device(self, device_id: int) -> list[sqlite3.Row]:
        """All acquisition sessions for one physical device, oldest first."""
        with self._connect() as conn:
            return conn.execute(
                """SELECT * FROM acquisition_sessions
                   WHERE device_id = ? ORDER BY start_time, id""",
                (device_id,)
            ).fetchall()

    def get_sessions_for_case(self, case_id: int) -> list[sqlite3.Row]:
        with self._connect() as conn:
            return conn.execute(
                """SELECT * FROM acquisition_sessions
                   WHERE case_id = ? ORDER BY start_time, id""",
                (case_id,)
            ).fetchall()

    def get_session_count_for_device(self, device_id: int) -> int:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM acquisition_sessions WHERE device_id = ?",
                (device_id,)
            ).fetchone()
            return row[0] if row else 0

    # ── Evidence ───────────────────────────────────────────────────────────────

    def add_evidence(self, case_id: int, device_id: Optional[int],
                     category: str, filename: str, filepath: str,
                     sha256: str, file_size: int = 0,
                     metadata: dict = None,
                     session_id: Optional[int] = None) -> int:
        """
        `session_id` (Phase 3, optional/keyword-only in practice) links
        this evidence item to the specific `acquisition_sessions` run that
        produced it, where the calling code has one available (live ADB
        acquisitions). It is intentionally optional and defaults to None
        so existing callers — and evidence added outside a tracked
        acquisition session (manual imports, pre-Phase-3 records) — are
        unaffected. Does not change SHA-256/integrity behavior in any way.
        """
        with self._connect() as conn:
            cur = conn.execute(
                """INSERT INTO evidence
                   (case_id, device_id, category, filename, filepath,
                    sha256, file_size, acquired_at, metadata, session_id)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (case_id, device_id, category,
                 filename or "", filepath or "",
                 sha256 or "", int(file_size or 0),
                 now_utc(), json.dumps(metadata or {}), session_id)
            )
            return cur.lastrowid

    def get_evidence_for_session(self, session_id: int) -> list[sqlite3.Row]:
        with self._connect() as conn:
            return conn.execute(
                "SELECT * FROM evidence WHERE session_id = ? ORDER BY acquired_at",
                (session_id,)
            ).fetchall()

    def get_evidence_for_case(self, case_id: int,
                               category: str = None) -> list[sqlite3.Row]:
        with self._connect() as conn:
            if category:
                return conn.execute(
                    """SELECT * FROM evidence
                       WHERE case_id = ? AND category = ?
                       ORDER BY acquired_at""",
                    (case_id, category)
                ).fetchall()
            return conn.execute(
                "SELECT * FROM evidence WHERE case_id = ? ORDER BY acquired_at",
                (case_id,)
            ).fetchall()

    def get_evidence_count(self, case_id: int) -> int:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM evidence WHERE case_id = ?", (case_id,)
            ).fetchone()
            return row[0] if row else 0

    def get_system_stats(self) -> dict:
        """
        System-wide aggregate counts across ALL cases in 3 queries total
        (not 3 queries per case). Used by the dashboard to avoid the N+1
        query pattern of summing get_evidence_count/get_devices_for_case/
        get_analysis_results in a per-case loop.
        Returns {cases, devices, evidence, analysis}.
        """
        with self._connect() as conn:
            cases    = conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
            devices  = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
            evidence = conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]
            analysis = conn.execute("SELECT COUNT(*) FROM analysis_results").fetchone()[0]
            sessions = conn.execute("SELECT COUNT(*) FROM acquisition_sessions").fetchone()[0]
        return {
            "cases":    cases,
            "devices":  devices,
            "evidence": evidence,
            "analysis": analysis,
            "sessions": sessions,
        }

    def verify_evidence(self, evidence_id: int) -> dict:
        """
        Re-hash a file and compare to the ORIGINAL (immutable) acquisition
        SHA-256. This method never writes to evidence.sha256 — the recorded
        hash is never overwritten, only compared against.

        Uses hasher.sha256_file_verify() (streaming, chunked — safe for
        large evidence files) which raises typed errors so this method can
        return an explicit "status" distinguishing:
          MISSING   — file no longer exists on disk
          CORRUPTED — file exists but could not be fully/reliably read
          ERROR     — any other unexpected failure
        alongside the existing "match"/"ok"/"stored"/"current" keys, which
        are kept for backward compatibility with callers written against
        the pre-Phase-1 shape of this method.
        """
        from forensiq.core.hasher import sha256_file_verify, HashCorruptedError

        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM evidence WHERE id = ?", (evidence_id,)
            ).fetchone()
        if not row:
            return {"ok": False, "status": "ERROR",
                     "error": "Evidence record not found"}

        stored_hash = row["sha256"] or ""
        filepath    = row["filepath"] or ""

        if not filepath:
            return {"ok": False, "status": "MISSING",
                     "error": "No file path recorded for this evidence item",
                     "stored": stored_hash}

        try:
            current_hash = sha256_file_verify(filepath)
        except FileNotFoundError:
            return {"ok": False, "status": "MISSING",
                     "error": f"File not found on disk: {filepath}",
                     "stored": stored_hash}
        except HashCorruptedError as e:
            return {"ok": False, "status": "CORRUPTED",
                     "error": str(e), "stored": stored_hash}
        except OSError as e:
            return {"ok": False, "status": "ERROR",
                     "error": f"Unexpected I/O error: {e}",
                     "stored": stored_hash}

        match = current_hash.lower() == stored_hash.lower()
        return {
            "ok":      match,
            "status":  "MATCH" if match else "MISMATCH",
            "stored":  stored_hash,
            "current": current_hash,
            "match":   match,
            "file":    filepath,
        }

    # ── Analysis Results ───────────────────────────────────────────────────────

    def add_analysis_result(self, case_id: int,
                             evidence_id: Optional[int],
                             analysis_type: str, summary: str,
                             data: dict = None) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                """INSERT INTO analysis_results
                   (case_id, evidence_id, analysis_type, result_summary,
                    result_data, created_at)
                   VALUES (?,?,?,?,?,?)""",
                (case_id, evidence_id, analysis_type,
                 summary or "",
                 json.dumps(data or {}), now_utc())
            )
            return cur.lastrowid

    def get_analysis_results(self, case_id: int) -> list[sqlite3.Row]:
        with self._connect() as conn:
            return conn.execute(
                """SELECT * FROM analysis_results
                   WHERE case_id = ? ORDER BY created_at""",
                (case_id,)
            ).fetchall()

    # ── Timeline ───────────────────────────────────────────────────────────────

    def add_timeline_event(self, case_id: int, event_type: str,
                            description: str, timestamp: str,
                            evidence_id: Optional[int] = None,
                            source_file: str = None,
                            metadata: dict = None,
                            category: str = "",
                            actor: str = "",
                            device_id: Optional[int] = None,
                            session_id: Optional[int] = None) -> int:
        """
        Insert one unified-timeline event.

        Phase 7 duplicate prevention: an event is identified by
        (case_id, event_type, description, timestamp, evidence_id,
        device_id, session_id). If a row with that exact identity already
        exists, this is a no-op and the existing row's id is returned
        instead of inserting a duplicate — so re-running the same
        analysis/timeline build against unchanged source data never grows
        the table. Genuinely new events (a re-verification with a new
        timestamp, a new custody action, etc.) always get their own row.
        """
        with self._connect() as conn:
            existing = conn.execute(
                """SELECT id FROM timeline_events
                   WHERE case_id = ? AND event_type = ? AND description = ?
                     AND timestamp = ?
                     AND IFNULL(evidence_id, -1) = IFNULL(?, -1)
                     AND IFNULL(device_id, -1)   = IFNULL(?, -1)
                     AND IFNULL(session_id, -1)  = IFNULL(?, -1)
                   LIMIT 1""",
                (case_id, event_type, description, timestamp,
                 evidence_id, device_id, session_id)
            ).fetchone()
            if existing:
                return existing["id"]

            cur = conn.execute(
                """INSERT INTO timeline_events
                   (case_id, evidence_id, event_type, description,
                    timestamp, source_file, metadata, category, actor,
                    device_id, session_id)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (case_id, evidence_id, event_type, description,
                 timestamp, source_file or "", json.dumps(metadata or {}),
                 category or "", actor or "", device_id, session_id)
            )
            return cur.lastrowid

    def get_timeline(self, case_id: int,
                      event_type: str = None,
                      category: str = None,
                      evidence_id: Optional[int] = None,
                      device_id: Optional[int] = None,
                      actor: str = None,
                      date_from: str = None,
                      date_to: str = None) -> list[sqlite3.Row]:
        """
        Return this case's unified timeline, chronologically ordered.

        All filter arguments are optional and additive (AND'ed together);
        called with just `case_id` this returns the full case timeline
        exactly as before Phase 7. Each row is joined against `evidence`
        and `devices` (LEFT JOIN, so events with no evidence/device link
        still come back) to expose `evidence_filename`, `device_serial`,
        and `device_model` alongside the raw *_id columns, for display
        without a separate lookup per row.
        """
        clauses  = ["te.case_id = ?"]
        params: list = [case_id]

        if event_type:
            clauses.append("te.event_type = ?"); params.append(event_type)
        if category:
            clauses.append("te.category = ?");   params.append(category)
        if evidence_id is not None:
            clauses.append("te.evidence_id = ?"); params.append(evidence_id)
        if device_id is not None:
            clauses.append("te.device_id = ?");   params.append(device_id)
        if actor:
            clauses.append("te.actor = ?");       params.append(actor)
        if date_from:
            clauses.append("te.timestamp >= ?");  params.append(date_from)
        if date_to:
            clauses.append("te.timestamp <= ?");  params.append(date_to)

        where = "WHERE " + " AND ".join(clauses)
        with self._connect() as conn:
            return conn.execute(
                f"""SELECT te.*, e.filename AS evidence_filename,
                           d.serial AS device_serial, d.model AS device_model
                    FROM timeline_events te
                    LEFT JOIN evidence e ON e.id = te.evidence_id
                    LEFT JOIN devices  d ON d.id = te.device_id
                    {where}
                    ORDER BY te.timestamp ASC, te.id ASC""",
                params
            ).fetchall()

    def get_timeline_event_types(self, case_id: int) -> list[str]:
        """Distinct event_type values for this case's timeline — filter dropdown."""
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT DISTINCT event_type FROM timeline_events
                   WHERE case_id = ? ORDER BY event_type""",
                (case_id,)
            ).fetchall()
        return [r["event_type"] for r in rows]

    def get_timeline_actors(self, case_id: int) -> list[str]:
        """Distinct investigator/actor values for this case's timeline — filter dropdown."""
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT DISTINCT actor FROM timeline_events
                   WHERE case_id = ? AND actor != '' ORDER BY actor""",
                (case_id,)
            ).fetchall()
        return [r["actor"] for r in rows]

    # ── Search ─────────────────────────────────────────────────────────────────

    def keyword_search(self, case_id: int, keyword: str) -> list[dict]:
        """
        FIX: Wrap all results in coalesce to prevent None match values
             from crashing callers that expect strings.
        """
        kw = f"%{keyword}%"
        results: list[dict] = []
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT 'evidence' AS source,
                          COALESCE(filename, '') AS match,
                          COALESCE(filepath, '') AS filepath,
                          acquired_at AS ts
                   FROM evidence
                   WHERE case_id = ? AND (filename LIKE ? OR filepath LIKE ?)""",
                (case_id, kw, kw)
            ).fetchall()
            results.extend(dict(r) for r in rows)

            rows = conn.execute(
                """SELECT 'analysis' AS source,
                          COALESCE(result_summary, '') AS match,
                          '' AS filepath,
                          created_at AS ts
                   FROM analysis_results
                   WHERE case_id = ? AND result_summary LIKE ?""",
                (case_id, kw)
            ).fetchall()
            results.extend(dict(r) for r in rows)

            rows = conn.execute(
                """SELECT 'timeline' AS source,
                          COALESCE(description, '') AS match,
                          COALESCE(source_file, '') AS filepath,
                          timestamp AS ts
                   FROM timeline_events
                   WHERE case_id = ? AND (description LIKE ? OR source_file LIKE ?)""",
                (case_id, kw, kw)
            ).fetchall()
            results.extend(dict(r) for r in rows)

        return results

    # ── Verification Results ───────────────────────────────────────────────────

    def add_verification_result(self, case_id: int,
                                 evidence_id: Optional[int],
                                 result: str,
                                 stored_hash: str = "",
                                 current_hash: str = "",
                                 notes: str = "") -> int:
        """
        Persist one verification event. Append-only — there is no update
        or delete method for verification_results, by design.

        result must be one of the canonical Phase 1 statuses
        (MATCH | MISMATCH | MISSING | CORRUPTED | ERROR) or one of the
        legacy pre-Phase-1 statuses (PASS | FAIL | MISSING | ERROR), kept
        accepted here for backward compatibility with any existing callers
        or data. NOT_VERIFIED is never persisted — it represents the
        *absence* of a verification row, not an event.
        """
        allowed = {
            # Canonical (Phase 1)
            "MATCH", "MISMATCH", "MISSING", "CORRUPTED", "ERROR",
            # Legacy (pre-Phase-1) — accepted for backward compatibility
            "PASS", "FAIL",
        }
        if result not in allowed:
            raise ValueError(f"result must be one of {allowed}, got {result!r}")
        with self._connect() as conn:
            cur = conn.execute(
                """INSERT INTO verification_results
                   (case_id, evidence_id, verification_time, result,
                    stored_hash, current_hash, notes)
                   VALUES (?,?,?,?,?,?,?)""",
                (case_id, evidence_id, now_utc(), result,
                 stored_hash or "", current_hash or "", notes or "")
            )
            return cur.lastrowid

    def get_verification_history(self, case_id: int = None,
                                  evidence_id: int = None) -> list[sqlite3.Row]:
        """Return verification events, ordered newest-first."""
        with self._connect() as conn:
            if evidence_id is not None:
                return conn.execute(
                    """SELECT vr.*, e.filename, e.category
                       FROM verification_results vr
                       LEFT JOIN evidence e ON e.id = vr.evidence_id
                       WHERE vr.evidence_id = ?
                       ORDER BY vr.verification_time DESC, vr.id DESC""",
                    (evidence_id,)
                ).fetchall()
            if case_id is not None:
                return conn.execute(
                    """SELECT vr.*, e.filename, e.category
                       FROM verification_results vr
                       LEFT JOIN evidence e ON e.id = vr.evidence_id
                       WHERE vr.case_id = ?
                       ORDER BY vr.verification_time DESC, vr.id DESC""",
                    (case_id,)
                ).fetchall()
            return conn.execute(
                """SELECT vr.*, e.filename, e.category
                   FROM verification_results vr
                   LEFT JOIN evidence e ON e.id = vr.evidence_id
                   ORDER BY vr.verification_time DESC, vr.id DESC"""
            ).fetchall()

    def get_last_verification(self, evidence_id: int) -> Optional[sqlite3.Row]:
        """Return the most recent verification event for one evidence item."""
        with self._connect() as conn:
            return conn.execute(
                """SELECT * FROM verification_results
                   WHERE evidence_id = ?
                   ORDER BY verification_time DESC, id DESC LIMIT 1""",
                (evidence_id,)
            ).fetchone()

    def get_last_verification_per_evidence(self, case_id: int) -> dict:
        """
        Return {evidence_id: sqlite3.Row} mapping each evidence item in this
        case to its most recent verification result, in ONE query instead of
        calling get_last_verification() once per evidence item (N+1 pattern).
        Used by the Integrity panel to load the evidence table efficiently.
        """
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT vr.* FROM verification_results vr
                   INNER JOIN (
                       SELECT evidence_id, MAX(verification_time) AS max_time
                       FROM verification_results
                       WHERE case_id = ?
                       GROUP BY evidence_id
                   ) latest
                   ON vr.evidence_id = latest.evidence_id
                   AND vr.verification_time = latest.max_time""",
                (case_id,)
            ).fetchall()
        # On verification_time ties, keep the row with the highest id (most recent insert)
        result: dict = {}
        for r in rows:
            eid = r["evidence_id"]
            if eid not in result or r["id"] > result[eid]["id"]:
                result[eid] = r
        return result

    def get_verification_summary(self, case_id: int) -> dict:
        """Return {PASS: n, FAIL: n, MISSING: n, ERROR: n, total: n} for a case."""
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT result, COUNT(*) as cnt
                   FROM verification_results
                   WHERE case_id = ?
                   GROUP BY result""",
                (case_id,)
            ).fetchall()
        counts = {"PASS": 0, "FAIL": 0, "MISSING": 0, "ERROR": 0}
        for row in rows:
            counts[row["result"]] = row["cnt"]
        counts["total"] = sum(counts.values())
        return counts

    def get_case_integrity_summary(self, case_id: int) -> dict:
        """
        Case Integrity Summary (Phase 1).

        Unlike get_verification_summary() (which counts every historical
        verification *attempt* row, for the legacy Integrity Panel cards),
        this looks at each evidence item's MOST RECENT verification status
        — the item's current, present-day integrity state — and buckets
        the case into:
            total, MATCH, MISMATCH, MISSING, CORRUPTED, NOT_VERIFIED
        plus an overall_status:
            VERIFIED     — every evidence item has been verified and all MATCH
            COMPROMISED  — at least one item is MISMATCH or CORRUPTED
            INCOMPLETE   — no MISMATCH/CORRUPTED, but at least one MISSING
            NOT_VERIFIED — no evidence has been verified yet at all
        COMPROMISED takes priority over INCOMPLETE, which takes priority
        over NOT_VERIFIED, since a confirmed tamper/corruption finding is
        more severe than evidence simply not having been checked yet.
        Legacy PASS/FAIL rows (written before this upgrade) are treated as
        MATCH/MISMATCH respectively.
        """
        from forensiq.core.integrity_engine import normalize_status, MATCH, MISMATCH, CORRUPTED

        evidence = self.get_evidence_for_case(case_id)
        last_by_ev = self.get_last_verification_per_evidence(case_id)

        counts = {"MATCH": 0, "MISMATCH": 0, "MISSING": 0,
                  "CORRUPTED": 0, "NOT_VERIFIED": 0}
        total = 0
        for ev in evidence:
            total += 1
            last = last_by_ev.get(ev["id"])
            status = normalize_status(last["result"]) if last else "NOT_VERIFIED"
            if status not in counts:
                counts[status] = 0
            counts[status] += 1

        if counts["MISMATCH"] > 0 or counts["CORRUPTED"] > 0:
            overall = "COMPROMISED"
        elif counts["MISSING"] > 0:
            overall = "INCOMPLETE"
        elif counts["NOT_VERIFIED"] > 0 and counts["MATCH"] == 0:
            overall = "NOT_VERIFIED"
        elif counts["NOT_VERIFIED"] > 0:
            # Some verified (all MATCH so far), some not yet checked.
            overall = "NOT_VERIFIED"
        else:
            overall = "VERIFIED" if total > 0 else "NOT_VERIFIED"

        counts["total"] = total
        counts["overall_status"] = overall
        return counts

    # ── Audit Trail (IMMUTABLE — no update/delete methods provided) ────────────

    def add_audit_event(self, action: str,
                        user: str = "",
                        target_type: str = "",
                        target_id: str = "",
                        result: str = "OK",
                        notes: str = "") -> int:
        """
        Append one immutable audit record.
        No UPDATE or DELETE methods exist for audit_trail by design.
        """
        with self._connect() as conn:
            cur = conn.execute(
                """INSERT INTO audit_trail
                   (timestamp, user, action, target_type, target_id, result, notes)
                   VALUES (?,?,?,?,?,?,?)""",
                (now_utc(), user or "", action, target_type or "",
                 str(target_id) if target_id is not None else "",
                 result or "OK", notes or "")
            )
            return cur.lastrowid

    def get_audit_trail(self, user: str = None, action: str = None,
                        target_type: str = None,
                        limit: int = 5000) -> list[sqlite3.Row]:
        """Return audit events newest-first with optional filters.
        Default limit raised to 5000 — audit trail must not silently truncate.
        """
        clauses, params = [], []
        if user:
            clauses.append("user LIKE ?"); params.append(f"%{user}%")
        if action:
            clauses.append("action = ?"); params.append(action)
        if target_type:
            clauses.append("target_type = ?"); params.append(target_type)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)
        with self._connect() as conn:
            return conn.execute(
                f"SELECT * FROM audit_trail {where} ORDER BY id DESC LIMIT ?",
                params
            ).fetchall()

    def get_audit_actions(self) -> list[str]:
        """Return distinct action values for filter dropdowns."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT DISTINCT action FROM audit_trail ORDER BY action"
            ).fetchall()
        return [r["action"] for r in rows]

    def get_audit_users(self) -> list[str]:
        """Return distinct user values for filter dropdowns."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT DISTINCT user FROM audit_trail WHERE user != '' ORDER BY user"
            ).fetchall()
        return [r["user"] for r in rows]

    # ── Chain of Custody ───────────────────────────────────────────────────────

    # Phase 2 canonical evidence lifecycle: ACQUIRED → STORED → VERIFIED →
    # TRANSFERRED → ANALYZED → REPORTED. REVIEWED/EXPORTED/ARCHIVED/NOTED
    # are auxiliary custody actions kept from Phase 1/pre-Phase-2 for
    # backward compatibility — they don't advance the primary lifecycle
    # but are still recorded and shown in the chain.
    LIFECYCLE_ORDER = (
        "ACQUIRED", "STORED", "VERIFIED", "TRANSFERRED", "ANALYZED", "REPORTED",
    )

    _CUSTODY_ACTIONS = frozenset(
        {"ACQUIRED", "STORED", "VERIFIED", "TRANSFERRED", "ANALYZED", "REPORTED",
         "REVIEWED", "EXPORTED", "ARCHIVED", "NOTED"}
    )

    def add_custody_event(self, case_id: int,
                          evidence_id: Optional[int],
                          investigator: str,
                          action: str,
                          location: str = "",
                          notes: str = "",
                          from_location: str = "",
                          to_location: str = "",
                          integrity_status: str = "") -> int:
        """
        Record one custody event. Append-only — there is no update or
        delete method for custody_events, by design; nothing here ever
        rewrites a prior row.

        action must be one of ACQUIRED | STORED | VERIFIED | TRANSFERRED |
                              ANALYZED | REPORTED | REVIEWED | EXPORTED |
                              ARCHIVED | NOTED

        from_location/to_location (Phase 2): explicit transfer source and
        destination — kept separate from the general-purpose `location`
        field, which is preserved for backward compatibility with
        pre-Phase-2 callers/data (e.g. an ACQUIRED event's storage site).
        For a TRANSFERRED event, `location` is auto-filled from
        `to_location` if not given, so older code that only reads
        `location` still sees something sensible.

        integrity_status (Phase 2): a snapshot of the evidence's integrity
        state (MATCH/MISMATCH/MISSING/CORRUPTED/NOT_VERIFIED) at the time
        of this event, e.g. captured at transfer time. Never computed
        after the fact — callers should pass the actual verification
        result current at insert time (see add_transfer_event()), so this
        column never fabricates a check that didn't happen.
        """
        action_upper = action.upper()
        if action_upper not in self._CUSTODY_ACTIONS:
            raise ValueError(
                f"action must be one of {sorted(self._CUSTODY_ACTIONS)}, "
                f"got {action!r}"
            )
        if action_upper == "TRANSFERRED" and not location:
            location = to_location or ""
        with self._connect() as conn:
            cur = conn.execute(
                """INSERT INTO custody_events
                   (case_id, evidence_id, timestamp, investigator,
                    action, location, notes,
                    from_location, to_location, integrity_status)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (case_id, evidence_id, now_utc(),
                 investigator or "", action_upper,
                 location or "", notes or "",
                 from_location or "", to_location or "",
                 integrity_status or "")
            )
            return cur.lastrowid

    def add_transfer_event(self, case_id: int,
                           evidence_id: Optional[int],
                           investigator: str,
                           from_location: str,
                           to_location: str,
                           reason: str = "",
                           integrity_status: Optional[str] = None) -> int:
        """
        Record a controlled evidence transfer (Phase 2 requirement 3).

        Never touches the evidence file itself — this only writes a
        custody_events row. If integrity_status is not explicitly given,
        it is captured from the evidence's REAL most recent verification
        result (never fabricated/invented) via get_last_verification(),
        falling back to NOT_VERIFIED if the item has never been checked.
        """
        if integrity_status is None:
            integrity_status = "NOT_VERIFIED"
            if evidence_id is not None:
                try:
                    from forensiq.core.integrity_engine import normalize_status
                    last = self.get_last_verification(evidence_id)
                    if last:
                        integrity_status = normalize_status(last["result"])
                except Exception:
                    pass
        return self.add_custody_event(
            case_id=case_id, evidence_id=evidence_id,
            investigator=investigator, action="TRANSFERRED",
            location=to_location, notes=reason,
            from_location=from_location, to_location=to_location,
            integrity_status=integrity_status,
        )

    def get_custody_events(self, case_id: int = None,
                            evidence_id: int = None) -> list[sqlite3.Row]:
        """Return custody events, oldest-first (chronological chain)."""
        with self._connect() as conn:
            if evidence_id is not None:
                return conn.execute(
                    """SELECT ce.*,
                              e.filename, e.category, e.sha256,
                              c.case_number, c.title AS case_title
                       FROM custody_events ce
                       LEFT JOIN evidence e  ON e.id  = ce.evidence_id
                       LEFT JOIN cases c     ON c.id  = ce.case_id
                       WHERE ce.evidence_id = ?
                       ORDER BY ce.id ASC""",
                    (evidence_id,)
                ).fetchall()
            if case_id is not None:
                return conn.execute(
                    """SELECT ce.*,
                              e.filename, e.category,
                              c.case_number
                       FROM custody_events ce
                       LEFT JOIN evidence e  ON e.id  = ce.evidence_id
                       LEFT JOIN cases c     ON c.id  = ce.case_id
                       WHERE ce.case_id = ?
                       ORDER BY ce.id ASC""",
                    (case_id,)
                ).fetchall()
            return conn.execute(
                """SELECT ce.*,
                          e.filename, e.category,
                          c.case_number
                   FROM custody_events ce
                   LEFT JOIN evidence e  ON e.id  = ce.evidence_id
                   LEFT JOIN cases c     ON c.id  = ce.case_id
                   ORDER BY ce.id ASC"""
            ).fetchall()

    def get_custody_chain(self, evidence_id: int) -> list[sqlite3.Row]:
        """
        Return the complete lifecycle chain for one evidence item.
        Alias for get_custody_events(evidence_id=evidence_id).
        """
        return self.get_custody_events(evidence_id=evidence_id)

    def get_transfer_history(self, evidence_id: int = None,
                             case_id: int = None) -> list[sqlite3.Row]:
        """
        Phase 2 requirement 3 — Evidence Transfer tracking. Returns only
        TRANSFERRED custody events (oldest-first), preserving every
        transfer across multiple hand-offs — nothing is collapsed or
        overwritten.
        """
        events = self.get_custody_events(case_id=case_id, evidence_id=evidence_id)
        return [e for e in events if e["action"] == "TRANSFERRED"]

    def get_evidence_lifecycle_status(self, evidence_id: int) -> str:
        """
        Phase 2 requirement 4 — current lifecycle stage for one evidence
        item: the most recent custody event whose action is part of the
        canonical ACQUIRED→STORED→VERIFIED→TRANSFERRED→ANALYZED→REPORTED
        progression (auxiliary actions like REVIEWED/NOTED don't change
        the reported stage). Returns "UNKNOWN" if no lifecycle event has
        been recorded yet.
        """
        chain = self.get_custody_chain(evidence_id)
        for event in reversed(chain):  # most recent first
            if event["action"] in self.LIFECYCLE_ORDER:
                return event["action"]
        return "UNKNOWN"

    def get_custody_summary(self, case_id: int) -> dict:
        """Return {action: count} for all custody events in a case."""
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT action, COUNT(*) as cnt FROM custody_events
                   WHERE case_id = ? GROUP BY action""",
                (case_id,)
            ).fetchall()
        return {r["action"]: r["cnt"] for r in rows}

    # ── Global Search (Pack C) ─────────────────────────────────────────────────

    def global_search(self, keyword: str, case_id: int = None,
                      date_from: str = None, date_to: str = None,
                      investigator: str = None,
                      evidence_type: str = None) -> list[dict]:
        """
        Cross-module keyword search across evidence, analysis, timeline,
        audit trail, custody events, and cases.
        Returns list of {source, type, match, detail, ts, id} dicts.
        """
        kw      = f"%{keyword}%"
        results: list[dict] = []

        def _date_clause(col: str) -> tuple[str, list]:
            clauses, params = [], []
            if date_from:
                clauses.append(f"{col} >= ?"); params.append(date_from)
            if date_to:
                clauses.append(f"{col} <= ?"); params.append(date_to + " 99:99:99")
            return (" AND ".join(clauses), params)

        with self._connect() as conn:
            # Evidence
            ev_where = "case_id = ? AND (filename LIKE ? OR filepath LIKE ? OR category LIKE ?)"
            ev_params = [case_id, kw, kw, kw] if case_id else [kw, kw, kw]
            ev_case_clause = "WHERE " + (ev_where if case_id else
                             "(filename LIKE ? OR filepath LIKE ? OR category LIKE ?)")
            if evidence_type:
                ev_case_clause += " AND category = ?"
                ev_params.append(evidence_type)
            dc, dp = _date_clause("acquired_at")
            if dc:
                ev_case_clause += " AND " + dc
                ev_params.extend(dp)
            rows = conn.execute(
                f"SELECT 'evidence' AS source, category AS type, "
                f"COALESCE(filename,'') AS match, "
                f"COALESCE(filepath,'') AS detail, acquired_at AS ts, id "
                f"FROM evidence {ev_case_clause}",
                ev_params
            ).fetchall()
            results.extend(dict(r) for r in rows)

            # Analysis results
            an_where = ("WHERE case_id = ? AND (result_summary LIKE ? OR analysis_type LIKE ?)"
                        if case_id else
                        "WHERE (result_summary LIKE ? OR analysis_type LIKE ?)")
            an_params = ([case_id, kw, kw] if case_id else [kw, kw])
            dc, dp = _date_clause("created_at")
            if dc:
                an_where += " AND " + dc; an_params.extend(dp)
            rows = conn.execute(
                f"SELECT 'analysis' AS source, analysis_type AS type, "
                f"COALESCE(result_summary,'') AS match, analysis_type AS detail, "
                f"created_at AS ts, id FROM analysis_results {an_where}",
                an_params
            ).fetchall()
            results.extend(dict(r) for r in rows)

            # Timeline events
            tl_where = ("WHERE case_id = ? AND (description LIKE ? OR event_type LIKE ?)"
                        if case_id else
                        "WHERE (description LIKE ? OR event_type LIKE ?)")
            tl_params = ([case_id, kw, kw] if case_id else [kw, kw])
            dc, dp = _date_clause("timestamp")
            if dc:
                tl_where += " AND " + dc; tl_params.extend(dp)
            rows = conn.execute(
                f"SELECT 'timeline' AS source, event_type AS type, "
                f"COALESCE(description,'') AS match, "
                f"COALESCE(source_file,'') AS detail, timestamp AS ts, id "
                f"FROM timeline_events {tl_where}",
                tl_params
            ).fetchall()
            results.extend(dict(r) for r in rows)

            # Audit trail
            at_where = "WHERE (action LIKE ? OR notes LIKE ? OR user LIKE ?)"
            at_params = [kw, kw, kw]
            if investigator:
                at_where += " AND user LIKE ?"; at_params.append(f"%{investigator}%")
            dc, dp = _date_clause("timestamp")
            if dc:
                at_where += " AND " + dc; at_params.extend(dp)
            rows = conn.execute(
                f"SELECT 'audit' AS source, action AS type, "
                f"COALESCE(notes,'') AS match, user AS detail, "
                f"timestamp AS ts, id FROM audit_trail {at_where}",
                at_params
            ).fetchall()
            results.extend(dict(r) for r in rows)

            # Custody events
            ce_where = ("WHERE case_id = ? AND (action LIKE ? OR notes LIKE ? OR investigator LIKE ?)"
                        if case_id else
                        "WHERE (action LIKE ? OR notes LIKE ? OR investigator LIKE ?)")
            ce_params = ([case_id, kw, kw, kw] if case_id else [kw, kw, kw])
            if investigator:
                ce_where += " AND investigator LIKE ?"; ce_params.append(f"%{investigator}%")
            dc, dp = _date_clause("timestamp")
            if dc:
                ce_where += " AND " + dc; ce_params.extend(dp)
            rows = conn.execute(
                f"SELECT 'custody' AS source, action AS type, "
                f"COALESCE(notes,'') AS match, investigator AS detail, "
                f"timestamp AS ts, id FROM custody_events {ce_where}",
                ce_params
            ).fetchall()
            results.extend(dict(r) for r in rows)

            # Cases
            case_where = ("WHERE id = ? AND (case_number LIKE ? OR title LIKE ? OR "
                          "investigator LIKE ? OR notes LIKE ?)"
                          if case_id else
                          "WHERE (case_number LIKE ? OR title LIKE ? OR "
                          "investigator LIKE ? OR notes LIKE ?)")
            case_params = ([case_id, kw, kw, kw, kw] if case_id else [kw, kw, kw, kw])
            if investigator:
                case_where += " AND investigator LIKE ?"; case_params.append(f"%{investigator}%")
            rows = conn.execute(
                f"SELECT 'case' AS source, status AS type, "
                f"case_number || ' — ' || title AS match, investigator AS detail, "
                f"created_at AS ts, id FROM cases {case_where}",
                case_params
            ).fetchall()
            results.extend(dict(r) for r in rows)

        # Sort newest first
        results.sort(key=lambda x: str(x.get("ts") or ""), reverse=True)
        return results

    # ── Digital Signatures (Phase 5, IMMUTABLE — no update/delete methods) ─────

    def add_signature(self, artifact_type: str, artifact_path: str,
                      artifact_sha256: str, signature: str, algorithm: str,
                      case_id: Optional[int] = None, signature_path: str = "",
                      signer: str = "", key_id: str = "",
                      signed_at: Optional[str] = None, notes: str = "") -> int:
        """
        Persist one signing event. Append-only, like verification_results
        and audit_trail — there is no update or delete method for this
        table, by design, so a signature record can never be quietly
        altered after the fact. Never accepts or stores a private key;
        only public signature metadata (see DATABASE_SCHEMA.md).
        """
        if artifact_type not in ("MANIFEST", "REPORT"):
            raise ValueError(
                f"artifact_type must be 'MANIFEST' or 'REPORT', got {artifact_type!r}"
            )
        if not artifact_sha256:
            raise ValueError("artifact_sha256 is required")
        if not signature:
            raise ValueError("signature is required")
        ts = signed_at or now_utc()
        with self._connect() as conn:
            cur = conn.execute(
                """INSERT INTO signatures
                   (case_id, artifact_type, artifact_path, artifact_sha256,
                    signature_path, signature, algorithm, signer, key_id,
                    signed_at, notes)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (case_id, artifact_type, artifact_path, artifact_sha256,
                 signature_path or "", signature, algorithm, signer or "",
                 key_id or "", ts, notes or "")
            )
            return cur.lastrowid

    def get_signature(self, signature_id: int) -> Optional[sqlite3.Row]:
        with self._connect() as conn:
            return conn.execute(
                "SELECT * FROM signatures WHERE id = ?", (signature_id,)
            ).fetchone()

    def get_signatures_for_case(self, case_id: int) -> list[sqlite3.Row]:
        """Return every signature event for a case, newest first."""
        with self._connect() as conn:
            return conn.execute(
                """SELECT * FROM signatures WHERE case_id = ?
                   ORDER BY signed_at DESC, id DESC""",
                (case_id,)
            ).fetchall()

    def get_signatures_for_artifact(self, artifact_path: str,
                                    case_id: Optional[int] = None) -> list[sqlite3.Row]:
        """Return every signature recorded for one artifact path, newest first."""
        with self._connect() as conn:
            if case_id is not None:
                return conn.execute(
                    """SELECT * FROM signatures
                       WHERE artifact_path = ? AND case_id = ?
                       ORDER BY signed_at DESC, id DESC""",
                    (artifact_path, case_id)
                ).fetchall()
            return conn.execute(
                """SELECT * FROM signatures WHERE artifact_path = ?
                   ORDER BY signed_at DESC, id DESC""",
                (artifact_path,)
            ).fetchall()

    def get_last_signature_for_artifact(self, artifact_path: str,
                                        case_id: Optional[int] = None) -> Optional[sqlite3.Row]:
        """Return the most recent signature recorded for one artifact path."""
        rows = self.get_signatures_for_artifact(artifact_path, case_id=case_id)
        return rows[0] if rows else None

