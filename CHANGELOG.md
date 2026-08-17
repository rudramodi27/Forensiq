# Changelog

All notable changes to ForensIQ are documented in this file. Entries are
grouped by the development phase in which they landed, per the project's
phased execution plan (Stabilization → Analysis → Reporting → Performance →
UI Polish → Testing → Documentation → Release).

**Current release: v1.4.0** (2026-08-14)

This file reflects what is verifiably present in the codebase's own fix
history (comment headers in each module) plus the current test/documentation
state; it does not speculate about unreleased or planned work beyond that.

## [1.4.0] — 2026-08-14 — Phase 8: Advanced Case Management

Extends the existing Case Manager (`case_manager.py`), Cases UI
(`cases_panel.py`), and Audit/Timeline system — no module was rewritten
from scratch, and the case-activity view reuses the Phase 7 unified
timeline builder (`analyzer.build_unified_timeline`) rather than
duplicating it.

### Added
- Case status workflow: `DRAFT → ACTIVE → UNDER_INVESTIGATION → REVIEW →
  CLOSED → ARCHIVED`, replacing the old flat `active`/`closed`/`archived`
  set. `CaseManager.update_case_status()` now validates every transition
  against an explicit graph (`CASE_STATUS_TRANSITIONS`) that also allows
  reopening (`CLOSED → ACTIVE`, `ARCHIVED → ACTIVE`); invalid transitions
  raise `ValueError`. See `DATABASE_SCHEMA.md` §5 for the full graph.
- Closing a case now requires a non-empty `closure_reason`, collected by
  the Cases UI via a dialog and persisted on the case row; reopening a
  closed/archived case clears it (the original reason stays visible in
  `audit_trail`/`timeline_events`, which this feature never modifies).
- Archived cases are read-only: `update_case()`/`update_case_notes()`
  raise `ValueError` while `status = 'ARCHIVED'`, until the case is
  reopened.
- New case metadata columns, added via the existing additive-migration
  mechanism (safe no-op on already-migrated DBs, sane empty defaults on
  existing rows — nothing fabricated): `priority` (`LOW`/`MEDIUM`/`HIGH`/
  `CRITICAL`, default `MEDIUM`), `reviewer`, `tags` (JSON string array),
  `closure_reason`. Existing `description`/`investigator`/`notes` fields
  are reused, not duplicated.
- `CaseManager.get_valid_next_statuses()`, `get_case_tags()` — helpers for
  the UI's status combo and tag display.
- `AuditService.log_case_status_changed()` gains optional
  `previous_status`/`closure_reason` keyword arguments, folded into the
  same `CASE_STATUS_CHANGED` audit row; existing positional-only callers
  are unaffected.
- Cases UI (`cases_panel.py`): New Case dialog gains Priority/Reviewer/Tags
  fields; case list gains a Priority column; case detail view gains an
  editable "Case Details" section (title/investigator/reviewer/priority/
  tags/description), a status control that only offers the case's valid
  next statuses, a closure-reason prompt on close, and a "Case Activity"
  panel driven by `build_unified_timeline()` showing status changes,
  evidence actions, device/acquisition activity, analysis activity,
  custody events, and investigator/audit actions in one place.
- Related Evidence table gains case→evidence navigation: double-clicking
  an evidence row jumps to the Chain of Custody panel pre-selected to
  that case (`CustodyPanel.select_case()`), rather than duplicating
  evidence-detail display that custody already provides.

### Changed
- New cases now start in `DRAFT` status instead of `active`. This is an
  intentional part of the new workflow (DRAFT is its first stage); tests
  that previously asserted a fresh case's status was `"active"` were
  updated to assert `"DRAFT"`.
- `cases.status` values are now canonically uppercase
  (`ACTIVE`/`CLOSED`/`ARCHIVED`/…). A migration normalises pre-Phase-8
  lowercase values in place (`UPPER(status)`) — the same real status,
  re-spelled, not changed — and is a no-op on already-migrated databases.
  Code that compared `case["status"] == "active"` (dashboard, report
  panel, PDF/HTML reports) was updated to compare case-insensitively.

## [1.3.0] — 2026-08-14 — Phase 7: Unified Forensic Timeline Upgrade

Extends the existing Phase 1–6 timeline (`analyzer.build_unified_timeline`,
`CaseManager.add_timeline_event`/`get_timeline`, the Timeline tab in
`analysis_panel.py`, and the Timeline section of the HTML/PDF reports) —
nothing was rewritten from scratch or duplicated.

### Added
- `timeline_events` table gains four columns via the existing additive
  migration mechanism (`category`, `actor`, `device_id`, `session_id`) —
  safe no-op on databases that already have them, applied automatically on
  startup like every other Phase 1–6 migration.
- `build_unified_timeline()` now merges **8** categories instead of 5:
  `case` (case created/updated), `file_system`, `evidence` (evidence items
  acquired — previously labelled `acquisition`), `device_acquisition`
  (device registration + acquisition session start/end),
  `analysis` (recorded `analysis_results` runs), `verification`, `audit`,
  `custody`. Every event now carries the full field set requested for
  Phase 7: `timestamp | event_type | category | description | case_id |
  evidence_id | device_id | session_id | actor | source`. Nothing is
  fabricated — every event is read from an existing row or a file's own
  mtime/ctime.
- `CaseManager.add_timeline_event()` now checks for an existing row with
  the same (case_id, event_type, description, timestamp, evidence_id,
  device_id, session_id) before inserting — the same identity it already
  matched loosely in the UI's ad-hoc dedup set, now enforced at the DB
  layer so *every* caller gets duplicate prevention, not just the
  Analysis panel.
- `CaseManager.get_timeline()` gains optional filters —
  `event_type`, `category`, `evidence_id`, `device_id`, `actor`,
  `date_from`, `date_to` — all additive/AND'ed, and now LEFT JOINs
  `evidence`/`devices` to expose `evidence_filename`/`device_serial`/
  `device_model` without a per-row lookup. Existing `get_timeline(case_id)`
  callers are unaffected.
- `CaseManager.get_timeline_event_types()` / `get_timeline_actors()` —
  distinct-value helpers for filter dropdowns, matching the existing
  `get_audit_actions()`/`get_audit_users()` pattern.
- `analyzer.persist_unified_timeline(db, case_id, events)` — extracted the
  UI's inline dedup-insert loop into a reusable, independently-tested
  function; duplicate prevention itself now lives in
  `add_timeline_event()`, so this just delegates.
- Timeline tab (`analysis_panel.py`): new filter row for Event Type,
  Evidence, Device, and Investigator/Actor (dropdowns populated from the
  loaded timeline), plus a Date Range filter (from/to + an "Apply date
  range" toggle so it doesn't affect users who don't set one). Existing
  keyword/category filters and the Sort toggle are unchanged. Table grew
  from 5 to 8 columns (added Evidence / Device-Session / Investigator-
  Actor). Analysis-run timeline results are now persisted via
  `persist_unified_timeline()` and reloaded from the DB (so displayed rows
  always carry real ids/joins) instead of rendering the in-memory list
  directly.
- Forensic PDF and HTML reports (`reporter.py`) — Timeline section grew
  from 3 columns (Timestamp/Event Type/Description) to 7
  (+ Category, Evidence, Device/Session, Actor) in both formats.
- Analysis report HTML (`analyzer._write_analysis_html`) — same 7-column
  Timeline table, updated category color palette for the 3 new categories.

### Changed
- The evidence-acquisition timeline category is now `evidence` rather than
  `acquisition` (device connection/session activity moved to its own new
  `device_acquisition` category, matching the Phase 7 spec's "Device/
  acquisition events" vs "Evidence events" split). Tests that previously
  asserted `"acquisition" in categories` were updated to assert the new
  8-category set; this is the one intentional taxonomy change in this
  phase and is called out explicitly since older external tooling reading
  `category` directly would need the same update.

### Preserved
- Chronological ordering, existing search/keyword/category filtering and
  sort toggle, existing audit/custody history and immutability guarantees,
  event-to-evidence/device/session linking, and every Phase 1–6 report
  section (Evidence Inventory, SHA-256 Verification, Analysis Findings,
  Chain of Custody, Transfer History, Audit Summary) untouched apart from
  the Timeline section itself.

### Tests
- `tests/test_analyzer.py` — `TestBuildUnifiedTimeline` rewritten for the
  8-category set plus new coverage for full-field-shape, case_id
  stamping, evidence/device linking, and non-fabrication (case-created
  timestamp traced back to the case row). New `TestPersistUnifiedTimeline`
  class covers first-run insert, no-op re-run (duplicate prevention),
  category/actor persistence, and the evidence/device join.
- `tests/test_case_manager.py` — new `TestTimelineEvents` class (14 tests):
  add/get, duplicate-call no-op + returns existing id, differing-timestamp
  is a genuine new row, filters (event_type/category/evidence_id/
  device_id/actor/date range), evidence/device join columns, backward
  compatibility with `get_timeline(case_id)` alone, and the two new
  distinct-value helpers. `TestSchema` gained a migration-columns check.
- Full suite: 532 passed / 0 failed after this phase (up from 507 passed
  pre-Phase-7 baseline on the same environment). One pre-existing error
  (`test_signature.py::test_log_signature_verified_failure_statuses_
  logged_as_failed` — a parametrized test the sandbox's no-pytest shim
  can't run; unrelated to this phase, present before these changes) and
  13 pre-existing skips (PyQt6/Qt display unavailable in this sandbox)
  are unchanged from baseline.


### Added
- `forensiq/core/analyzer.py` — standard finding schema shared by every
  analysis module: `make_finding()` / `highest_severity()` produce records
  with `case_id`, `analysis_type`, `evidence_ref`, `timestamp`, `status`,
  `finding`, `severity` (Input → Processing → Finding → Timestamp →
  Evidence Reference), persisted through the existing `analysis_results`
  table (`analysis_id` = row id) — no new table, no schema change.
- `analyze_network_info()` — parses the already-acquired `network_info.txt`
  (IP addresses, interfaces, Wi-Fi SSID/BSSID) and flags VPN/tunnel
  interfaces, missing network data, and other network anomalies.
- `analyze_battery_system()` — parses the already-acquired
  `battery_info.json` and reuses the device's existing DB row (Android/SDK/
  USB-debugging) to flag thermal/health anomalies and hardening gaps,
  without re-querying ADB.
- `analyze_hash_integrity()` — thin wrapper around the existing
  `CaseManager.get_case_integrity_summary()` /
  `get_last_verification_per_evidence()`; recomputes nothing.
- `detect_suspicious_artifacts()` — filesystem + application-level
  suspicious-artifact sweep; reuses `classify_app()` / `analyze_apps()` for
  the app side rather than re-implementing app classification.
- `search_iocs()` — searches a supplied IOC list (hash / IP / domain /
  package / filename) by reusing `keyword_search_global()`, evidence
  SHA-256 lookups, and `analyze_network_info()` output.
- `forensiq/ui/panels/analysis_panel.py` — new "Findings" tab showing every
  Phase 6 finding (Analysis Type / Severity / Finding / Timestamp / Evidence
  Reference) with type/severity filters; new task checkboxes (Network,
  Battery/System, Hash/Integrity, Suspicious Artifacts, IOC Search) and an
  IOC input field; findings persist to and reload from the existing
  `analysis_results` table when switching cases.
- `forensiq/core/reporter.py` — HTML and PDF "Analysis Findings" sections
  now show Analysis Type, color-coded Severity, Finding, Timestamp, and
  Evidence Reference (previously Type/Summary/Date only), derived from the
  same finding records via `_analysis_severity_and_ref()`.
- `generate_analysis_report()` — JSON/HTML analysis report now includes
  `network`, `battery_system`, `hash_integrity`, `suspicious_artifacts`, and
  a combined `findings` list sorted by severity.
- Tests: `tests/test_analysis_phase6.py` (57 tests covering all five new
  analysis modules, the standard finding schema, `AnalysisWorker` task
  routing, and `generate_analysis_report()` integration) and
  `tests/test_analysis_panel_phase6.py` (9 tests covering the new Findings
  tab, filters, and analysis_results persistence/reload).

### Notes
- No existing analysis, evidence, integrity, timeline, manifest, audit, or
  report functionality was rewritten or duplicated — Phase 6 modules call
  into the Phase 1–5 implementations (`classify_app`, `analyze_apps`,
  `keyword_search_global`, `get_case_integrity_summary`,
  `get_last_verification_per_evidence`, `_sha256_file`, `add_analysis_result`,
  `log_analysis_performed`) rather than re-implementing them.
- No unrelated ML, blockchain, or SIEM features were added.

## [1.1.0] — 2026-08-13 — Phase 5: Digital Signature

### Added
- `forensiq/core/key_manager.py` — `KeyManager` generates/loads one
  Ed25519 keypair per signer identity (via the `cryptography` library —
  no custom cryptography), stored under `~/.forensiq/keys/` with
  owner-only (`0600`) file permissions and optional passphrase
  encryption (`FORENSIQ_SIGNING_KEY_PASSPHRASE`). Private keys are never
  written to `forensiq.db`, never logged, and never returned from any
  public method — only a `key_id` public-key fingerprint is exposed.
- `forensiq/core/signature_service.py` — `SignatureService.sign_manifest`
  / `sign_report` sign a generated artifact with a detached
  `<artifact>.sig.json` sidecar (the original artifact is never
  rewritten) and record signer, algorithm, timestamp, artifact type,
  artifact SHA-256, signature, and key_id. `verify_artifact` returns one
  of `VALID` / `INVALID` / `MODIFIED` / `MISSING` / `KEY_UNAVAILABLE`.
- `signatures` table (`case_manager.py` `SCHEMA`) — append-only, same
  pattern as `verification_results`/`audit_trail`; no update/delete
  method is exposed. New `CaseManager` methods: `add_signature`,
  `get_signature`, `get_signatures_for_case`,
  `get_signatures_for_artifact`, `get_last_signature_for_artifact`. See
  `DATABASE_SCHEMA.md` §2.9.
- `AuditService.log_artifact_signed` / `log_signature_verified` — new
  `ARTIFACT_SIGNED`, `SIGNATURE_VERIFIED`, `SIGNATURE_VERIFICATION_FAILED`
  audit actions, reusing the existing `_log`/`add_audit_event` plumbing.
  Any non-`VALID` verification status is logged as
  `SIGNATURE_VERIFICATION_FAILED` (with `WARNING` for `MISSING`, `FAILED`
  otherwise) so a failed or inconclusive verification can never be
  mistaken for a plain success in the audit trail.
- `forensiq/ui/panels/signature_panel.py` — new **Signatures** nav item
  with Sign Manifest / Sign Report… / Verify Signature… actions, a
  result panel (signer, algorithm, timestamp, artifact/current SHA-256,
  key ID, status), and a per-case signature history table.
- `cryptography>=42.0.0` added to `requirements.txt` and
  `pyproject.toml` dependencies.
- `tests/test_signature.py` — 51 new tests covering key generation/reuse/
  isolation, signing (sidecar written, original artifact byte-for-byte
  unchanged, all required metadata fields present, DB persistence),
  every verification state (`VALID`, `MODIFIED` via tampered artifact,
  `INVALID` via wrong key and via tampered signature/metadata, `MISSING`
  with and without a DB fallback, `KEY_UNAVAILABLE` via a removed public
  key), the new `case_manager` signature CRUD, audit integration for all
  three new actions, and a no-PyQt6-required import check mirroring the
  existing regression guarantee for `integrity_engine`.

### Changed
- `forensiq/ui/main_window.py` — added `"signature"` to `NAV_ITEMS`
  between Reports and Integrity, and wired `SignaturePanel` into the
  panel `QStackedWidget` alongside the existing Phase 1–4 panels. No
  existing panel, route, or nav entry was modified or removed.
- `forensiq/core/case_manager.py` — added the `signatures` table via
  `CREATE TABLE IF NOT EXISTS` in the base `SCHEMA` string (safe,
  idempotent for existing databases — no `_MIGRATIONS` entry was needed
  since this adds a whole new table rather than a column to an existing
  one).
- `pyproject.toml` — version bumped `1.0.0` → `1.1.0`.

### Security
- Private signing keys are stored outside `forensiq.db`, are never
  embedded in generated reports, signature metadata, or audit log
  entries, and use the `cryptography` library's Ed25519 implementation
  (RFC 8032) rather than a custom/home-grown signature scheme, per the
  project's existing "no custom cryptography" posture.

### Validation
- Full test suite: **459/459 passing** (408 pre-existing + 51 new),
  run with `QT_QPA_PLATFORM=offscreen python3 -m pytest -q`.
- No Phase 1–4 test was modified to make the suite pass.

## [1.0.0] — 2026-07-10 — Phase 8: Release

### Added
- `pyproject.toml` — packaging metadata (name, version, dependencies,
  optional `magic`/`dev` extras), enabling `pip install -e .` and a
  `forensiq` console entry point as an alternative to `python main.py`
  (which continues to work unchanged).
- `.gitignore` — excludes virtual envs, bytecode caches, build/dist output,
  and — importantly — the local `.forensiq/` runtime database and any
  generated case reports, so evidence data is never accidentally committed.
- `scripts/build_release.sh` / `scripts/build_release.bat` — optional
  PyInstaller-based build scripts producing a standalone single-file
  executable (`dist/ForensIQ` / `dist/ForensIQ.exe`) for distribution
  without requiring an end-user Python install. `adb` must still be
  installed separately on the target machine.
- `RELEASE_NOTES.md` — v1.0.0 release summary for end users.

### Changed
- Removed stray `__pycache__`/`.pyc` artifacts from the working tree (not
  previously ignored by any VCS config, since none existed).

### Validation
- Full test suite: **243/243 passing**.
- `pyproject.toml` parsed successfully with Python's `tomllib`.
- No application source (`forensiq/`, `main.py`) modified in this phase —
  release prep is additive (packaging/config/build files only), per the
  "never introduce breaking changes" rule.

This is the first tagged release. All Phase 1–7 fixes and additions listed
below are included in this release.

## Phase 7 — Documentation

### Added
- `ARCHITECTURE.md` — layered architecture, threading model, and core module
  responsibilities.
- `DATABASE_SCHEMA.md` — full schema for all 8 tables, relationships, and
  migration mechanics.
- `USER_GUIDE.md` — end-to-end walkthrough of the case lifecycle, panel by
  panel, plus a troubleshooting table.
- `INSTALLATION.md` — setup steps for Python/PyQt6, ADB, and device
  preparation, split from the quick-start README.
- `CHANGELOG.md` (this file).

### Changed
- `README.md` — trimmed to a project overview with links out to the new
  documentation set, so setup/architecture/schema details live in one place
  each instead of being duplicated.

No source code was modified in this phase, per the phase's scope
(documentation only).

## Phase 6 — Testing

### Added
- `tests/test_analyzer.py`, `test_audit.py`, `test_case_manager.py`,
  `test_hasher.py`, `test_integrity.py`, `test_reporter.py` — unit coverage
  for each core module.
- `tests/test_regression.py` — regression coverage for previously fixed
  defects (see Phase 1–5 entries below), to prevent reintroduction.
- `tests/conftest.py` — shared fixtures (temp DB, temp evidence dir, seeded
  case data).
- `pytest.ini` — test discovery and warning-filter configuration.

### Validation
- Full suite: **243 tests passing** across analyzer (74), case manager (54),
  reporter (33), audit (23), regression (25), hasher (20), and integrity
  (14).

## Phase 5 — UI Polish

### Fixed
- Acquisition panel: log font specified as a single family name instead of a
  CSS-style font stack (Qt stylesheets don't parse comma-separated font
  lists); SHA-256 column set to stretch instead of the filename column, so
  full hashes remain visible.
- Dashboard: recent-cases list widgets are now properly torn down with
  `deleteLater()` on refresh (previously accumulated hidden widgets each time
  the dashboard was shown); metric cards refresh on every tab switch instead
  of showing stale values; a misplaced `addStretch()` causing layout drift on
  refresh was removed.
- Cases panel: evidence table given a minimum height so it no longer
  collapses to zero height in smaller windows.

## Phase 4 — Performance

### Fixed
- `AnalysisWorker` no longer passes a full `case` row into the worker
  thread — only the evidence directory path crosses the thread boundary,
  avoiding unnecessary data copying and sqlite Row access from a
  non-owning thread.
- `build_file_timeline` deduplicates events where a file's `ctime` and
  `mtime` are equal (common for files pulled via ADB, since the pull
  operation sets both), which previously inflated timeline event counts.
- Timeline events are batch-inserted after deduplication rather than
  row-by-row.
- `keyword_search_files` now uses a context manager to close file handles
  explicitly instead of relying on garbage collection, reducing open file
  handle pressure during large-evidence keyword scans.

## Phase 3 — Reporting Completion

### Fixed
- PDF generation: `Table` `colWidths` switched from unsupported percentage
  strings to explicit `cm` units, fixing report layout on ReportLab.
- PDF generation: evidence/analysis result sets were being iterated twice
  during table construction; both are now materialized to lists first.
- Long unbroken values (SHA-256 hashes, filenames) are wrapped in
  `Paragraph` cells instead of raw strings, so they wrap within their column
  instead of overflowing it.
- `file_size` formatting (`{value:,}`) no longer crashes on `NULL` — falls
  back to `0` via `(value or 0)`.
- All case/evidence fields are HTML-escaped before being written into
  generated HTML reports, closing an HTML-injection path via
  attacker-controlled case notes, filenames, or investigator names.
- Report panel: progress bar range corrected from an indeterminate `(0, 0)`
  to a determinate `(0, 100)`; "Open Last HTML" no longer silently fails
  when the most recently generated report was a PDF; report preview no
  longer runs an f-string directly against a raw `sqlite3.Row`.

### Added
- `generate_case_summary_report`, `generate_evidence_summary_report`,
  `generate_integrity_report_html`, `generate_audit_report_html`,
  `generate_custody_report_html`, `generate_executive_report` — rounding
  out the reporting suite to 7 distinct report types (plus the original
  full HTML/PDF report) covering every major data domain in the schema.

## Phase 2 — Analysis Completion

### Fixed
- `analyze_apps` returns a flat result dict — a prior nested
  `{"apps": {"apps": [...]}}` shape was flattened to match how callers
  consume it.
- `keyword_search_files` and correlation/timeline helpers no longer assume
  `sqlite3.Row` supports `.get()` (it doesn't) — all access converted to
  bracket indexing with explicit fallbacks.

### Added
- `build_unified_timeline`, `detect_duplicates`, `correlate_artifacts`,
  `keyword_search_global`, `generate_analysis_report` — completing the
  Analysis Engine's feature set (timeline, correlation, duplicates, global
  search, filters, and a dedicated analysis report).

## Phase 1 — Stabilization

### Fixed
- ADB battery/network parsing no longer crashes on empty or non-numeric
  values — all int/float conversions routed through `_safe_int` /
  `_safe_float`.
- `get_installed_apps` package/installer parsing switched from a
  double-space split (fragile) to a general whitespace split, fixing
  contaminated package names.
- `pull_user_files` snapshots existing local files *before* each remote
  pull and only processes newly created files afterward, fixing a
  double-counting bug where re-running acquisition against the same output
  directory inflated the evidence count.
- `AcquisitionWorker` now emits a `file_acquired` signal per pulled file
  (previously only a final batch result), so the UI reflects acquisition
  progress in real time.
- Acquisition panel: the Stop button's signal was being reconnected on every
  acquisition run, causing signal stacking; replaced with an idempotent
  `abort()` call. `_category_for()` previously misreported all pulled media
  as a generic `files` category — now inspects the actual directory
  structure. Silent device-registration failures no longer leave
  `device_id=None` on every subsequent evidence row for that acquisition.
  Output directory creation moved earlier so it exists before the worker
  starts. File table size column no longer shows `0` for files not yet
  fully written to disk.
- Cases panel: case-number uniqueness is validated before the database
  insert (previously relied on the DB's `UNIQUE` constraint throwing an
  unhandled exception); recent-cases widget cleanup no longer leaks
  `QLayoutItem`s; notes-save no longer crashes when the panel is used
  outside of `MainWindow` (added a guard around `window().set_status`).
- `keyword_search` (case manager) wraps result columns in `COALESCE` to
  prevent `None` values from breaking match highlighting.

## v1.0.0 Baseline

Initial feature set prior to the phased stabilization/completion work above:
case management, device identification, ADB-based evidence acquisition,
SQLite persistence with WAL mode and foreign-key enforcement, SHA-256
hashing, the original full HTML/PDF report, and the PyQt6 desktop UI shell
(Dashboard, Device, Acquisition, Cases, Analysis, Reports panels).
