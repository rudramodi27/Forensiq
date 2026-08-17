# ForensIQ — Architecture

## 1. Overview

ForensIQ is a single-user desktop application for acquiring, analyzing, and
reporting on evidence pulled from Android devices via ADB. It is built as a
three-layer PyQt6 application on top of a local SQLite database:

```
┌─────────────────────────────────────────────────────────┐
│                      UI Layer (PyQt6)                    │
│   forensiq/ui/main_window.py + forensiq/ui/panels/*.py   │
└───────────────────────────┬───────────────────────────────┘
                            │ calls
┌───────────────────────────▼───────────────────────────────┐
│                     Core / Service Layer                 │
│  adb_manager · analyzer · integrity_engine · audit_service│
│  reporter · hasher                                        │
└───────────────────────────┬───────────────────────────────┘
                            │ reads/writes
┌───────────────────────────▼───────────────────────────────┐
│                 Persistence — case_manager.py             │
│              SQLite (~/.forensiq/forensiq.db)             │
└─────────────────────────────────────────────────────────┘
```

The UI never touches the database directly — every panel goes through
`CaseManager` (persistence) or one of the core services. This keeps business
logic testable independent of Qt (see `tests/`, which import core modules
without instantiating any widgets).

## 2. Process & Threading Model

PyQt's event loop is single-threaded; long-running work (ADB pulls, hashing,
verification, analysis) is offloaded to `QThread` subclasses so the UI stays
responsive:

| Worker | Defined in | Used by |
|---|---|---|
| `DeviceDetectWorker` | `core/adb_manager.py` | Device panel — device scan |
| `AcquisitionWorker` | `core/adb_manager.py` | Acquisition panel — file pull |
| `VerificationWorker` | `core/integrity_engine.py` | Integrity panel — hash re-check |
| `AnalysisWorker` | `core/analyzer.py` | Analysis panel — timeline/metadata/apps/duplicates/correlation |
| `ReportWorker` | `ui/panels/report_panel.py` | Report panel — PDF/HTML generation |

Each worker communicates back to its panel exclusively through Qt signals
(`progress`, `finished`, `error`, and workload-specific signals such as
`file_acquired`). No worker touches a Qt widget directly, and no widget is
shared across threads — only primitive data crosses the signal boundary.

`CaseManager` opens a fresh SQLite connection per call (`check_same_thread=False`,
WAL mode) rather than holding one connection open across threads, which avoids
cross-thread cursor issues when a worker thread and the UI thread both query
the database around the same time.

## 3. Core Modules

### `core/case_manager.py` — Persistence
Owns the schema (`SCHEMA`), the startup migration routine (`_run_migrations`),
and all CRUD access across the tables described in `DATABASE_SCHEMA.md`.
Every other core module depends on `CaseManager`; it has no dependency on any
other core module.

**Phase 3 — Device Acquisition Accuracy:** device identity (`add_device`) is
a stable get-or-update-or-create keyed on `(case_id, serial)` — a physical
device is stored once per case no matter how many times it's connected.
Each connection/acquisition run is instead recorded as a separate
`acquisition_sessions` row (`start_acquisition_session` /
`end_acquisition_session`), capturing a point-in-time `device_snapshot` and
the requested targets. Evidence produced during a tracked run links to that
session via `evidence.session_id`. Hierarchy: **Case → Device → Acquisition
Sessions → Evidence.**

### `core/adb_manager.py` — Device Communication
Thin wrapper around the `adb` binary via `subprocess`. Responsibilities:
device discovery (`list_devices`), device profiling (`get_device_info`,
`get_installed_apps`, `get_running_processes`, `get_battery_info`,
`get_network_info`), and evidence acquisition (`pull_user_files`), which pulls
`Photos`, `Videos`, and `Documents` categories from standard `/sdcard`
locations into the case's evidence directory and SHA-256 hashes each new file
as it lands. No root access is used or required.

### `core/hasher.py` — Hashing Primitives
Streaming SHA-256 (`sha256_file`, `hash_directory`) in 64 KB chunks so large
evidence files don't need to be loaded into memory, plus `sha256_string` /
`sha256_bytes` / `verify_file` helpers used across acquisition, integrity, and
analysis.

### `core/integrity_engine.py` — Integrity Verification
Re-hashes evidence on disk and compares it against the hash stored at
acquisition time (`verify_single`, `verify_case`, `verify_all`), classifying
each item as `PASS`, `FAIL`, `MISSING`, or `ERROR`. Every verification is
persisted to `verification_results` and mirrored into the audit trail via
`AuditService`. Includes JSON/HTML export (`export_json`, `export_html`).

### `core/analyzer.py` — Analysis Engine
Stateless functions operating on an evidence directory (+ optionally the DB
for correlation):
- `build_file_timeline` / `build_unified_timeline` — filesystem timestamps
  merged with acquisition, verification, audit, and custody events into one
  chronological view.
- `extract_file_metadata` — MIME type (via `python-magic` if installed, else
  stdlib `mimetypes`), size, SHA-256, timestamps.
- `analyze_apps` / `classify_app` — classifies installed apps as
  system / user / disabled / sideloaded and flags recent installs.
- `detect_duplicates` — SHA-256 + size matching across the evidence
  directory and DB.
- `correlate_artifacts` — links files ↔ apps ↔ audit ↔ custody ↔
  verification records for a case.
- `keyword_search_files` / `keyword_search_global` — filename/content and
  cross-table keyword search with date/investigator/type/status filters.
- `generate_analysis_report` — bundles the above into a JSON + HTML report.

### `core/audit_service.py` — Audit & Custody
`AuditService` wraps `CaseManager.add_audit_event` /
`CaseManager.add_custody_event` with typed helper methods
(`log_case_created`, `log_evidence_added`, `log_verification`, ...) so
call sites can't misspell an action string. Audit rows are **append-only**:
`case_manager.py` and `audit_service.py` intentionally expose no update or
delete method for `audit_trail`. Custody events reference `case_id` /
`evidence_id` with `ON DELETE SET NULL`, so a chain-of-custody record
survives case or evidence deletion.

### `core/reporter.py` — Reporting
Nine report generators (eight HTML, via hand-built templates, plus one PDF
via ReportLab's `Table`/`Paragraph` flowables). All user-supplied text (case
notes, investigator names, filenames, custody notes, etc.) is HTML-escaped
through a shared `_esc` helper before being interpolated into a report, which
is the project's primary XSS/HTML-injection mitigation for generated reports.

### `core/key_manager.py` / `core/signature_service.py` — Digital Signature *(Phase 5)*
`KeyManager` generates and loads one Ed25519 keypair per signer identity
(via the `cryptography` library — no custom cryptography), stored under
`~/.forensiq/keys/` with owner-only file permissions and optional
passphrase encryption. Private keys never enter `forensiq.db`, never leave
`key_manager.py`, and are never logged.

`SignatureService` signs a generated Manifest or Report file
(`sign_manifest` / `sign_report`) by hashing it with the same
`hasher.sha256_file_verify` helper `IntegrityEngine` uses, writing a
detached `<artifact>.sig.json` sidecar (the original artifact is opened
read-only and never rewritten), and persisting the same metadata to the
new `signatures` table via `CaseManager.add_signature`.
`verify_artifact` re-hashes the artifact and returns exactly one of
`VALID` / `INVALID` / `MODIFIED` / `MISSING` / `KEY_UNAVAILABLE` — see
`DATABASE_SCHEMA.md §2.9` for the table layout and
`signature_service.py`'s module docstring for how each state is derived.
Both `log_artifact_signed` and `log_signature_verified` on
`AuditService` mirror sign/verify outcomes into the existing audit trail,
matching the append-only pattern already used for `verification_results`.

## 4. UI Layer

`main_window.py` hosts a `QStackedWidget` driven by a sidebar built from the
static `NAV_ITEMS` list (Dashboard, Device, Acquisition, Cases, Analysis,
Reports, Signatures, Integrity, Audit Trail, Custody). Each entry in
`NAV_ITEMS` maps to exactly one panel class in `ui/panels/`;
`MainWindow._nav_to` swaps the visible widget and updates the header
title/subtitle from the same list, so adding a new panel means adding one
`NAV_ITEMS` tuple plus one `stack.addWidget(...)` call — no other
navigation wiring is needed.

Styling is centralized in `ui/styles.py`, a single dark QSS theme applied at
the application level; panels do not set per-widget stylesheets outside of
status/result color coding (e.g. PASS/FAIL badges, VALID/INVALID/MODIFIED
signature status badges).

## 5. Data Flow — Typical Case Lifecycle

1. **Cases panel** → `CaseManager.create_case` → row in `cases`,
   `AuditService.log_case_created`.
2. **Device panel** → `ADBManager.get_device_info` (+ async detect) →
   `CaseManager.add_device` → row in `devices`.
3. **Acquisition panel** → `ADBManager.acquire_async` → files written to disk
   under the case's evidence directory, each hashed →
   `CaseManager.add_evidence` per file → rows in `evidence`,
   `AuditService.log_evidence_added`.
4. **Analysis panel** → `analyzer.*` functions read the evidence directory
   (+ DB) → `CaseManager.add_analysis_result` / `add_timeline_event`.
5. **Integrity panel** → `IntegrityEngine.verify_case` re-hashes each
   evidence file → `CaseManager.add_verification_result`,
   `AuditService.log_verification`.
6. **Custody panel** → `AuditService.add_custody_event` → row in
   `custody_events` (independent of audit_trail, but both are shown together
   in the unified timeline).
7. **Report panel** → `reporter.generate_*` reads across all of the above
   tables and renders a self-contained HTML or PDF file →
   `AuditService.log_report_generated`.
8. **Signature panel** → `manifest_service.build_manifest` /
   `export_manifest_json` (Sign Manifest) or a previously generated report
   file (Sign Report) → `SignatureService.sign_artifact` hashes the file,
   signs it via `KeyManager`, writes a detached `.sig.json` sidecar →
   `CaseManager.add_signature`, `AuditService.log_artifact_signed`. Verify
   Signature re-hashes the chosen file → `SignatureService.verify_artifact`
   → `AuditService.log_signature_verified`.

## 6. Design Principles Preserved

- **Immutability of the audit trail** — no code path updates or deletes
  `audit_trail` rows.
- **No root / exploit usage** — acquisition is limited to user-accessible
  `/sdcard` paths reachable via standard ADB with USB debugging enabled.
- **Idempotent schema** — `CREATE TABLE IF NOT EXISTS` + an additive
  migration list means the app can be pointed at an existing database from an
  older version without data loss (see `DATABASE_SCHEMA.md`).
- **Escaping at the boundary** — all report generators escape user data
  before writing HTML.
