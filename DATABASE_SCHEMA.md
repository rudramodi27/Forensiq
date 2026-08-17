# ForensIQ — Database Schema

- **Engine:** SQLite 3
- **Location:** `~/.forensiq/forensiq.db`
- **Mode:** `PRAGMA journal_mode=WAL`, `PRAGMA foreign_keys=ON` (set on every
  connection)
- **Migrations:** applied automatically and idempotently on every startup —
  see [§4 Migrations](#4-migrations). Opening an older database is safe; no
  manual upgrade step is required.

All timestamps are stored as `TEXT` in `YYYY-MM-DD HH:MM:SS UTC` format
(`case_manager.now_utc()`), not SQLite's `DATETIME` type, so they sort and
compare correctly as plain strings.

## 1. Entity-Relationship Summary

```
cases ──┬──< devices ──< acquisition_sessions
        ├──< evidence >── devices (nullable), acquisition_sessions (nullable)
        ├──< analysis_results >── evidence (nullable)
        ├──< timeline_events >── evidence (nullable)
        ├──< verification_results >── evidence (nullable)
        ├──< custody_events >── evidence (nullable)
        └──< signatures (nullable)

custody_events          — case_id, evidence_id both nullable (see §2.8)
audit_trail             — standalone, no foreign keys (see §3.6)
signatures              — case_id nullable (see §2.9)
```

`<` denotes "one-to-many". All child rows referencing a `case_id` cascade
delete with their parent case (`ON DELETE CASCADE`), **except**
`custody_events`, which is set to `NULL` instead (`ON DELETE SET NULL`) so
chain-of-custody history survives case deletion.

**Phase 3 — Device Acquisition Accuracy:** a physical device is stored
**once** per case (`devices`, keyed on `case_id` + `serial` — see
`add_device()` in §2.2). Every connection/acquisition run against that same
physical device is a separate `acquisition_sessions` row (§2.2b), never a new
device row. Evidence produced during a tracked acquisition run is linked to
that session via `evidence.session_id` (§2.3).

## 2. Tables

### 2.1 `cases`
| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER PK AUTOINCREMENT | |
| `case_number` | TEXT UNIQUE NOT NULL | |
| `title` | TEXT NOT NULL | |
| `investigator` | TEXT NOT NULL | |
| `description` | TEXT DEFAULT '' | |
| `created_at` | TEXT NOT NULL | UTC timestamp |
| `updated_at` | TEXT NOT NULL | UTC timestamp |
| `status` | TEXT NOT NULL DEFAULT 'DRAFT' | Phase 8 workflow: `DRAFT → ACTIVE → UNDER_INVESTIGATION → REVIEW → CLOSED → ARCHIVED` (see §5) |
| `notes` | TEXT DEFAULT '' | |
| `evidence_dir` | TEXT DEFAULT '' | *(migrated column, see §4)* |
| `priority` | TEXT NOT NULL DEFAULT 'MEDIUM' | *(Phase 8, migrated column, see §4)* — one of `LOW`/`MEDIUM`/`HIGH`/`CRITICAL` |
| `reviewer` | TEXT DEFAULT '' | *(Phase 8, migrated column, see §4)* |
| `tags` | TEXT NOT NULL DEFAULT '[]' | *(Phase 8, migrated column, see §4)* — JSON array of strings |
| `closure_reason` | TEXT DEFAULT '' | *(Phase 8, migrated column, see §4)* — required non-empty when `status = 'CLOSED'`, cleared on reopen |

### 2.2 `devices`
| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER PK AUTOINCREMENT | |
| `case_id` | INTEGER NOT NULL → `cases(id)` | `ON DELETE CASCADE` |
| `serial` | TEXT NOT NULL | |
| `model` | TEXT DEFAULT 'Unknown' | |
| `manufacturer` | TEXT DEFAULT 'Unknown' | |
| `android_version` | TEXT DEFAULT 'Unknown' | |
| `sdk_version` | TEXT DEFAULT 'Unknown' | |
| `build_number` | TEXT DEFAULT 'Unknown' | *(migrated column, see §4)* |
| `cpu_abi` | TEXT DEFAULT 'Unknown' | *(migrated column, see §4)* |
| `usb_debugging` | INTEGER NOT NULL DEFAULT 0 | boolean 0/1 |
| `acquired_at` | TEXT NOT NULL | UTC timestamp of first registration |
| `first_connected` | TEXT DEFAULT '' | *(Phase 3, migrated column)* — set once, never overwritten |
| `last_connected` | TEXT DEFAULT '' | *(Phase 3, migrated column)* — refreshed on every `add_device()` call and every new session |

Index: `idx_devices_case (case_id)`

Identity is keyed on `(case_id, serial)` — see `add_device()` in
`case_manager.py`. Re-registering the same serial within a case updates the
existing row's mutable fields (OS/SDK/build, USB debugging, `last_connected`)
instead of inserting a duplicate row. A different serial is a genuinely
different physical device and gets its own row.

### 2.2b `acquisition_sessions` *(Phase 3)*
| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER PK AUTOINCREMENT | |
| `case_id` | INTEGER NOT NULL → `cases(id)` | `ON DELETE CASCADE` |
| `device_id` | INTEGER NOT NULL → `devices(id)` | `ON DELETE CASCADE` |
| `start_time` | TEXT NOT NULL | UTC timestamp |
| `end_time` | TEXT | UTC timestamp, NULL while in progress |
| `status` | TEXT NOT NULL DEFAULT `'in_progress'` | `in_progress` \| `completed` \| `aborted` \| `error` |
| `adb_state` | TEXT DEFAULT `'Unknown'` | ADB connection state at session start |
| `usb_debugging` | INTEGER NOT NULL DEFAULT 0 | boolean 0/1, at session start |
| `device_snapshot` | TEXT NOT NULL DEFAULT `'{}'` | JSON blob — full device metadata captured at session start, preserved historically even if the device's own row is later refreshed |
| `targets` | TEXT NOT NULL DEFAULT `'[]'` | JSON list of acquisition targets requested for this run |
| `output_dir` | TEXT DEFAULT '' | local output directory for this run |

Indexes: `idx_sessions_case (case_id)`, `idx_sessions_device (device_id)`,
`idx_sessions_start (device_id, start_time)`

One physical device (`devices` row) has **many** `acquisition_sessions` rows
— one per connection/acquisition run. Deleting a device cascades to its
sessions; sessions are never fabricated for pre-Phase-3 acquisitions (see §4
Migrations).

### 2.3 `evidence`
| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER PK AUTOINCREMENT | |
| `case_id` | INTEGER NOT NULL → `cases(id)` | `ON DELETE CASCADE` |
| `device_id` | INTEGER → `devices(id)` | `ON DELETE SET NULL` |
| `category` | TEXT NOT NULL | e.g. `Photos`, `Videos`, `Documents` |
| `filename` | TEXT DEFAULT '' | |
| `filepath` | TEXT DEFAULT '' | local path under case evidence dir |
| `sha256` | TEXT DEFAULT '' | hash at acquisition time |
| `file_size` | INTEGER NOT NULL DEFAULT 0 | *(migrated column, see §4)* |
| `acquired_at` | TEXT NOT NULL | UTC timestamp |
| `metadata` | TEXT NOT NULL DEFAULT '{}' | JSON blob |
| `session_id` | INTEGER → `acquisition_sessions(id)` | *(Phase 3, migrated column)* `ON DELETE SET NULL` — the acquisition run that produced this item, when known |

Indexes: `idx_evidence_case (case_id)`, `idx_evidence_cat (case_id, category)`

### 2.4 `analysis_results`
| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER PK AUTOINCREMENT | |
| `case_id` | INTEGER NOT NULL → `cases(id)` | `ON DELETE CASCADE` |
| `evidence_id` | INTEGER → `evidence(id)` | `ON DELETE SET NULL` |
| `analysis_type` | TEXT NOT NULL | e.g. `timeline`, `apps`, `duplicates`, `correlation` |
| `result_summary` | TEXT DEFAULT '' | human-readable summary |
| `result_data` | TEXT NOT NULL DEFAULT '{}' | JSON blob |
| `created_at` | TEXT NOT NULL | UTC timestamp |

Index: `idx_analysis_case (case_id)`

### 2.5 `timeline_events`
| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER PK AUTOINCREMENT | |
| `case_id` | INTEGER NOT NULL → `cases(id)` | `ON DELETE CASCADE` |
| `evidence_id` | INTEGER → `evidence(id)` | `ON DELETE SET NULL` |
| `event_type` | TEXT NOT NULL | e.g. `file_created`, `acquisition`, `verification`, `audit`, `custody` |
| `description` | TEXT NOT NULL | |
| `timestamp` | TEXT NOT NULL | UTC timestamp — used for chronological sort |
| `source_file` | TEXT DEFAULT '' | |
| `metadata` | TEXT NOT NULL DEFAULT '{}' | JSON blob |

Indexes: `idx_timeline_case (case_id)`, `idx_timeline_ts (case_id, timestamp)`

### 2.6 `verification_results`
| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER PK AUTOINCREMENT | |
| `case_id` | INTEGER NOT NULL → `cases(id)` | `ON DELETE CASCADE` |
| `evidence_id` | INTEGER → `evidence(id)` | `ON DELETE SET NULL` |
| `verification_time` | TEXT NOT NULL | UTC timestamp |
| `result` | TEXT NOT NULL | `PASS` \| `FAIL` \| `MISSING` \| `ERROR` |
| `stored_hash` | TEXT NOT NULL DEFAULT '' | hash recorded at acquisition |
| `current_hash` | TEXT NOT NULL DEFAULT '' | hash recomputed at verification time |
| `notes` | TEXT NOT NULL DEFAULT '' | |

Indexes: `idx_verification_case (case_id)`, `idx_verification_ev (evidence_id)`,
`idx_verification_time (case_id, verification_time)`

### 2.7 `audit_trail`
| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER PK AUTOINCREMENT | |
| `timestamp` | TEXT NOT NULL | UTC timestamp |
| `user` | TEXT NOT NULL DEFAULT '' | investigator/username |
| `action` | TEXT NOT NULL | e.g. `CASE_CREATED`, `EVIDENCE_ADDED`, `VERIFICATION_RUN`, `REPORT_GENERATED` |
| `target_type` | TEXT NOT NULL DEFAULT '' | e.g. `case`, `evidence` |
| `target_id` | TEXT NOT NULL DEFAULT '' | |
| `result` | TEXT NOT NULL DEFAULT 'OK' | |
| `notes` | TEXT NOT NULL DEFAULT '' | |

Indexes: `idx_audit_timestamp (timestamp)`, `idx_audit_action (action)`,
`idx_audit_user (user)`

**Deliberately has no foreign key on `case_id`/`target_id`.** This table is
the system's immutable audit log: `CaseManager` and `AuditService` expose only
`add_audit_event` / `get_audit_trail` / `get_audit_actions` /
`get_audit_users` — there is no update or delete method, by design, so audit
history is preserved even after a referenced case or evidence item is
deleted.

### 2.8 `custody_events`
| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER PK AUTOINCREMENT | |
| `case_id` | INTEGER → `cases(id)` | `ON DELETE SET NULL` |
| `evidence_id` | INTEGER → `evidence(id)` | `ON DELETE SET NULL` |
| `timestamp` | TEXT NOT NULL | UTC timestamp |
| `investigator` | TEXT NOT NULL DEFAULT '' | |
| `action` | TEXT NOT NULL | e.g. `COLLECTED`, `TRANSFERRED`, `STORED`, `RELEASED` |
| `location` | TEXT NOT NULL DEFAULT '' | |
| `notes` | TEXT NOT NULL DEFAULT '' | |

Indexes: `idx_custody_case (case_id)`, `idx_custody_evidence (evidence_id)`,
`idx_custody_ts (timestamp)`

### 2.9 `signatures` *(Phase 5)*
| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER PK AUTOINCREMENT | |
| `case_id` | INTEGER → `cases(id)` | `ON DELETE SET NULL` |
| `artifact_type` | TEXT NOT NULL | `MANIFEST` or `REPORT` |
| `artifact_path` | TEXT NOT NULL | absolute path of the signed file |
| `artifact_sha256` | TEXT NOT NULL | hash of the artifact **at signing time** |
| `signature_path` | TEXT NOT NULL DEFAULT '' | detached `<artifact>.sig.json` sidecar |
| `signature` | TEXT NOT NULL | base64-encoded signature bytes |
| `algorithm` | TEXT NOT NULL | e.g. `Ed25519` |
| `signer` | TEXT NOT NULL DEFAULT '' | signer identity (investigator) |
| `key_id` | TEXT NOT NULL DEFAULT '' | public-key fingerprint — **never the key itself** |
| `signed_at` | TEXT NOT NULL | UTC timestamp |
| `notes` | TEXT NOT NULL DEFAULT '' | |

Indexes: `idx_signatures_case (case_id)`,
`idx_signatures_artifact (artifact_path)`,
`idx_signatures_signed_at (signed_at)`

**No private key material is ever stored here** — `forensiq.core.key_manager`
keeps private keys in their own directory on disk (`~/.forensiq/keys/` by
default), outside `forensiq.db` entirely. Only the public `key_id`
fingerprint needed to look up the *public* key for verification is
persisted. Like `verification_results`/`audit_trail`, this table is
append-only: `CaseManager` exposes `add_signature` /
`get_signatures_for_case` / `get_signatures_for_artifact` /
`get_last_signature_for_artifact` / `get_signature`, and no update/delete
method, so a signature record can never be quietly altered after the fact.
See `forensiq/core/signature_service.py` and `forensiq/core/key_manager.py`
for the sign/verify logic and key custody model (module docstrings there
document the security rationale in detail).

## 3. Referential Integrity Notes

1. **Cascade deletes** — deleting a case removes its `devices`, `evidence`,
   `analysis_results`, `timeline_events`, and `verification_results` rows
   automatically via `ON DELETE CASCADE`.
2. **Set-null deletes** — deleting a `device` or `evidence` row does not
   remove dependent `evidence` / `analysis_results` / `timeline_events` /
   `verification_results` / `custody_events` rows; the foreign key is set to
   `NULL` instead so historical records remain queryable.
3. **`custody_events.case_id`** uses `ON DELETE SET NULL`, not `CASCADE`,
   which is intentional and matches the immutability guarantee described in
   the project's security notes: chain-of-custody survives case deletion.
4. **`audit_trail`** has no foreign keys at all — see §2.7.
5. **`signatures.case_id`** uses `ON DELETE SET NULL`, matching
   `custody_events` and `verification_results` — a signature record
   survives deletion of the case it was created under, since it is
   evidence of what was signed and when, not case metadata.

## 4. Migrations

`case_manager._MIGRATIONS` is an additive, ordered list of
`(column, table, definition)` tuples applied by `_run_migrations()` on every
`CaseManager` startup, after the base `SCHEMA` (`CREATE TABLE IF NOT EXISTS`)
has run:

| Column added | Table | Definition |
|---|---|---|
| `evidence_dir` | `cases` | `TEXT DEFAULT ''` |
| `file_size` | `evidence` | `INTEGER NOT NULL DEFAULT 0` |
| `cpu_abi` | `devices` | `TEXT DEFAULT 'Unknown'` |
| `build_number` | `devices` | `TEXT DEFAULT 'Unknown'` |
| `from_location` | `custody_events` | `TEXT DEFAULT ''` |
| `to_location` | `custody_events` | `TEXT DEFAULT ''` |
| `integrity_status` | `custody_events` | `TEXT DEFAULT ''` |
| `first_connected` | `devices` | `TEXT DEFAULT ''` |
| `last_connected` | `devices` | `TEXT DEFAULT ''` |
| `session_id` | `evidence` | `INTEGER REFERENCES acquisition_sessions(id) ON DELETE SET NULL` |
| `category` | `timeline_events` | `TEXT DEFAULT ''` |
| `actor` | `timeline_events` | `TEXT DEFAULT ''` |
| `device_id` | `timeline_events` | `INTEGER REFERENCES devices(id) ON DELETE SET NULL` |
| `session_id` | `timeline_events` | `INTEGER REFERENCES acquisition_sessions(id) ON DELETE SET NULL` |
| `priority` | `cases` | `TEXT NOT NULL DEFAULT 'MEDIUM'` |
| `reviewer` | `cases` | `TEXT DEFAULT ''` |
| `tags` | `cases` | `TEXT NOT NULL DEFAULT '[]'` |
| `closure_reason` | `cases` | `TEXT DEFAULT ''` |

Each migration checks `PRAGMA table_info(<table>)` first and only issues
`ALTER TABLE ... ADD COLUMN` if the column is missing, so re-running against
an already-migrated database is a safe no-op. Existing rows receive the
column's `DEFAULT` value.

**Phase 3 backfill:** immediately after the column migrations above run,
`_run_migrations()` also backfills `devices.first_connected` and
`devices.last_connected` from the existing `devices.acquired_at` value for
any row where the new columns are still empty. This reuses a timestamp that
was already recorded — it does not fabricate new history — and is a no-op
once a database has been migrated once. No historical `acquisition_sessions`
rows are ever created for pre-Phase-3 acquisitions; devices migrated from an
older database simply show zero sessions until the next real acquisition
run.

**Phase 8 status normalisation:** immediately after the column migrations,
`_run_migrations()` also runs `UPDATE cases SET status = UPPER(status)
WHERE status IN ('active','closed','archived')` — pre-Phase-8 databases
stored status in lowercase; this is a case/spelling normalisation of the
same real value, not a status change, so no case's actual status is
altered. Rows already in the canonical uppercase form are left untouched,
making this a safe no-op on an already-migrated database.

**Adding a future migration:** append a new `(column, table, definition)`
tuple to `_MIGRATIONS` — do not modify the base `SCHEMA` string for columns
that must survive on existing installations, since `CREATE TABLE IF NOT
EXISTS` will not retroactively add columns to a database that already has the
table.

## 5. Case Status Workflow (Phase 8)

`cases.status` follows an explicit workflow, enforced by
`CaseManager.update_case_status()` via the `CASE_STATUS_TRANSITIONS` graph:

```
DRAFT → ACTIVE → UNDER_INVESTIGATION → REVIEW → CLOSED → ARCHIVED
                     ↑___________________|          |
                     └──────────── ACTIVE ←──────────┘ (reopen)
```

- `DRAFT → ACTIVE` — case work begins.
- `ACTIVE ↔ UNDER_INVESTIGATION ↔ REVIEW` — case may move forward or back
  between these three active-work stages, and any of them may close
  directly (`→ CLOSED`).
- `CLOSED → ARCHIVED` — normal end-of-life path.
- `CLOSED → ACTIVE` and `ARCHIVED → ACTIVE` — explicit, audited "reopen"
  transitions.
- Any transition not listed above (including staying on the same status)
  is rejected with `ValueError`.
- Moving to `CLOSED` requires a non-empty `closure_reason`; reopening a
  `CLOSED`/`ARCHIVED` case clears it (the original reason remains visible
  in `audit_trail`/`timeline_events`, which this method never modifies).
- A case whose current status is `ARCHIVED` is read-only:
  `CaseManager.update_case()` / `update_case_notes()` raise `ValueError`
  until the case is reopened via `update_case_status(..., 'ACTIVE')`.
- Every status change is expected to be followed by
  `AuditService.log_case_status_changed()` (as `cases_panel.py` does),
  keeping status history in the existing, unmodified audit/timeline
  pipeline — `update_case_status()` itself does not write to
  `audit_trail`/`timeline_events`.

## 6. Backup Recommendation


Because the database is a single WAL-mode SQLite file, a consistent backup
should copy `forensiq.db`, `forensiq.db-wal`, and `forensiq.db-shm` together
(or run `PRAGMA wal_checkpoint(FULL);` before copying just `forensiq.db`).
