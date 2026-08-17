# Changelog

All notable changes to ForensIQ are documented in this file. Entries are
grouped by the development phase in which they landed, per the project's
phased execution plan (Stabilization → Analysis → Reporting → Performance →
UI Polish → Testing → Documentation → Release).

**Current release: v1.4.0** (2026-08-14)

This file reflects what is verifiably present in the codebase's own fix
history (comment headers in each module) plus the current test/documentation
state; it does not speculate about unreleased or planned work beyond that.

---

## [1.4.0] — 2026-08-14 — Phase 8: Advanced Case Management

Extends the existing Case Manager (`case_manager.py`), Cases UI
(`cases_panel.py`), and Audit/Timeline system — no module was rewritten
from scratch, and the case-activity view reuses the Phase 7 unified
timeline builder (`analyzer.build_unified_timeline`) rather than
duplicating it.

### Added

* Case status workflow: `DRAFT → ACTIVE → UNDER_INVESTIGATION → REVIEW →
  CLOSED → ARCHIVED`, replacing the old flat `active`/`closed`/`archived`
  set. `CaseManager.update_case_status()` now validates every transition
  against an explicit graph (`CASE_STATUS_TRANSITIONS`) that also allows
  reopening (`CLOSED → ACTIVE`, `ARCHIVED → ACTIVE`). Invalid transitions
  raise `ValueError`. See `DATABASE_SCHEMA.md` §5 for the full graph.
* Closing a case now requires a non-empty `closure_reason`, collected by
  the Cases UI via a dialog and persisted on the case row. Reopening a
  closed/archived case clears it; the original reason remains visible in
  `audit_trail`/`timeline_events`.
* Archived cases are read-only: `update_case()`/`update_case_notes()`
  raise `ValueError` while `status = 'ARCHIVED'`, until the case is
  reopened.
* New case metadata columns, added via the existing additive-migration
  mechanism: `priority` (`LOW`/`MEDIUM`/`HIGH`/`CRITICAL`, default
  `MEDIUM`), `reviewer`, `tags` (JSON string array), and `closure_reason`.
  Existing `description`/`investigator`/`notes` fields are reused.
* `CaseManager.get_valid_next_statuses()` and `get_case_tags()` helpers for
  the UI's status controls and tag display.
* `AuditService.log_case_status_changed()` gains optional
  `previous_status`/`closure_reason` information while preserving existing
  callers.
* Cases UI (`cases_panel.py): New Case dialog gains Priority/Reviewer/Tags
  fields; case list gains a Priority column; case detail view gains an
  editable Case Details section; status controls only offer valid next
  statuses; closing requires a closure reason; and Case Activity is shown
  using `build_unified_timeline()`.
* Case Activity displays status changes, evidence actions,
  device/acquisition activity, analysis activity, custody events, and
  investigator/audit actions in one place.
* Related Evidence table gains case-to-evidence navigation to the Chain of
  Custody panel.

### Changed

* New cases now start in `DRAFT` status instead of `active`.
* `cases.status` values are now canonically uppercase
  (`ACTIVE`/`CLOSED`/`ARCHIVED`/…). Existing lowercase values are normalized
  during migration.
* Code that compared case status using lowercase values was updated to
  compare case-insensitively where required.

---

## [1.3.0] — 2026-08-14 — Phase 7: Unified Forensic Timeline Upgrade

Extends the existing Phase 1–6 timeline implementation without rewriting
or duplicating the existing analysis and reporting architecture.

### Added

* `timeline_events` gains `category`, `actor`, `device_id`, and
  `session_id` through the existing additive migration mechanism.
* `build_unified_timeline()` now merges eight event categories:
  `case`, `file_system`, `evidence`, `device_acquisition`, `analysis`,
  `verification`, `audit`, and `custody`.
* Timeline events contain:
  `timestamp | event_type | category | description | case_id |
  evidence_id | device_id | session_id | actor | source`.
* `CaseManager.add_timeline_event()` now prevents duplicate timeline
  records at the database layer.
* `CaseManager.get_timeline()` supports filters for event type, category,
  evidence, device, actor, and date range.
* Added timeline event-type and actor helper methods.
* Added reusable `persist_unified_timeline()` functionality.
* Timeline UI gained Event Type, Evidence, Device, Investigator/Actor, and
  Date Range filters.
* Timeline tables were expanded to show additional evidence, device/session,
  and actor information.
* Forensic PDF and HTML reports now include expanded timeline information.
* Analysis report HTML includes the expanded timeline structure.

### Changed

* The evidence-acquisition timeline category is now `evidence` rather than
  `acquisition`.
* Device connection and acquisition-session activity is represented by the
  dedicated `device_acquisition` category.

### Preserved

* Chronological ordering.
* Existing search, keyword, category filtering, and sorting.
* Existing audit and custody history.
* Event-to-evidence/device/session linking.
* Existing forensic report sections.

### Tests

* Updated unified timeline tests for the eight-category model and expanded
  event fields.
* Added persistence and duplicate-prevention coverage.
* Added timeline filtering and evidence/device join coverage.
* Full Phase 7 test validation was performed against the existing suite.

---

## [1.2.0] — 2026-08-14 — Phase 6: Advanced Forensic Analysis

### Added

* `forensiq/core/analyzer.py` — standard finding schema shared by analysis
  modules using `make_finding()` and `highest_severity()`.
* `analyze_network_info()` — analyses acquired network information and
  identifies relevant network anomalies.
* `analyze_battery_system()` — analyses acquired battery/system information
  and identifies relevant system or device anomalies.
* `analyze_hash_integrity()` — integrates existing case integrity and
  verification information into analysis findings without recomputing
  hashes.
* `detect_suspicious_artifacts()` — performs filesystem and
  application-level suspicious-artifact analysis.
* `search_iocs()` — searches supplied IOC values including hashes, IP
  addresses, domains, package names, and filenames using existing search and
  analysis functionality.
* Analysis UI gained a **Findings** tab showing analysis type, severity,
  finding, timestamp, and evidence reference.
* Analysis UI gained task controls for Network, Battery/System,
  Hash/Integrity, Suspicious Artifacts, and IOC Search.
* Findings persist to and reload from the existing `analysis_results` table.
* HTML and PDF reports now include expanded Analysis Findings sections.
* Analysis JSON/HTML reports include network, battery/system,
  hash/integrity, suspicious-artifact, IOC, and combined finding data.
* Added dedicated analysis-phase test coverage.

### Notes

* Existing analysis, evidence, integrity, timeline, manifest, audit, and
  reporting functionality was reused rather than duplicated.
* No unrelated ML, blockchain, or SIEM functionality was added.

---

## [1.1.0] — 2026-08-13 — Phase 5: Digital Signature

### Added

* `forensiq/core/key_manager.py` — `KeyManager` generates and loads one
  Ed25519 keypair per signer identity using the `cryptography` library.
* Signing keys are stored under `~/.forensiq/keys/` with owner-only
  permissions and optional passphrase encryption.
* Private keys are never written to `forensiq.db`, logged, or exposed through
  public application methods.
* `forensiq/core/signature_service.py` — signs manifests and reports using
  detached `.sig.json` sidecar files.
* Original signed artifacts are never rewritten.
* Signature metadata includes signer, algorithm, timestamp, artifact type,
  artifact SHA-256, signature, and key ID.
* Signature verification supports:
  `VALID`, `INVALID`, `MODIFIED`, `MISSING`, and `KEY_UNAVAILABLE`.
* Added the append-only `signatures` database table.
* Added signature CRUD methods to `CaseManager`.
* Added `ARTIFACT_SIGNED`, `SIGNATURE_VERIFIED`, and
  `SIGNATURE_VERIFICATION_FAILED` audit actions.
* Added the **Signatures** UI panel with Sign Manifest, Sign Report, and
  Verify Signature operations.
* Added signature history per case.
* Added `cryptography>=42.0.0` to project dependencies.
* Added dedicated signature test coverage.

### Changed

* `forensiq/ui/main_window.py` added the Signatures navigation item.
* `forensiq/core/case_manager.py` added the signatures table.
* `pyproject.toml` version was bumped from `1.0.0` to `1.1.0`.

### Security

* Private signing keys are stored outside `forensiq.db`.
* Private keys are not embedded in generated reports, signature metadata,
  or audit records.
* Ed25519 is provided through the `cryptography` library rather than custom
  cryptographic code.

### Validation

* Full test suite validation was completed for the Phase 5 implementation.

---

## [1.0.0] — 2026-07-10 — Initial Release

### Added

* `pyproject.toml` — packaging metadata, dependencies, optional extras,
  editable installation support, and a `forensiq` console entry point.
* `.gitignore` — excludes virtual environments, Python bytecode,
  build/dist output, local `.forensiq/` runtime data, and generated reports.
* `scripts/build_release.sh` and `scripts/build_release.bat` — optional
  PyInstaller-based standalone build scripts.
* `RELEASE_NOTES.md` — initial v1.0.0 release documentation.

### Changed

* Removed stray `__pycache__` and `.pyc` artifacts from the working tree.

### Validation

* Full initial test suite: **243/243 passing**.
* `pyproject.toml` parsed successfully.
* No application source was modified during the release-preparation work.

This was the first release of ForensIQ. It included the completed
stabilization, analysis, reporting, performance, UI, testing, and
documentation work available at the time.

---

## Phase 7 — Documentation

### Added

* `ARCHITECTURE.md` — layered architecture, threading model, and core
  module responsibilities.
* `DATABASE_SCHEMA.md` — database schema, relationships, and migration
  mechanics.
* `USER_GUIDE.md` — end-to-end investigation workflow and troubleshooting.
* `INSTALLATION.md` — Python/PyQt6, ADB, and Android device setup.
* `CHANGELOG.md` — project change history.

### Changed

* `README.md` — project overview and links to the documentation set.

No source code was modified during this documentation phase.

---

## Phase 6 — Testing

### Added

* Unit coverage for analyzer, audit, case manager, hasher, integrity, and
  reporter modules.
* Regression coverage for previously fixed defects.
* Shared test fixtures.
* `pytest.ini` for test discovery and warning configuration.

### Validation

* Baseline suite contained **243 passing tests** across the core modules.

---

## Phase 5 — UI Polish

### Fixed

* Acquisition panel log font configuration.
* SHA-256 column sizing.
* Dashboard widget cleanup and metric refresh behavior.
* Dashboard layout refresh behavior.
* Cases panel evidence-table sizing.

---

## Phase 4 — Performance

### Fixed

* Reduced unnecessary data transfer into analysis worker threads.
* Improved file timeline deduplication.
* Improved timeline event insertion efficiency.
* Improved file-handle management during keyword searches.

---

## Phase 3 — Reporting Completion

### Fixed

* Corrected PDF table column sizing.
* Fixed duplicate iteration over report data.
* Improved wrapping of long hashes and filenames.
* Fixed handling of null file sizes.
* Added HTML escaping for case and evidence data.
* Improved report-panel progress and preview behavior.

### Added

* Case Summary report.
* Evidence Summary report.
* Integrity report.
* Audit report.
* Custody report.
* Executive report.
* Expanded reporting coverage across the major forensic data domains.

---

## Phase 2 — Analysis Completion

### Fixed

* Corrected application-analysis result structure.
* Fixed SQLite row access assumptions in analysis helpers.

### Added

* Unified forensic timeline.
* Duplicate detection.
* Artifact correlation.
* Global keyword search.
* Analysis report generation.
* Analysis filtering capabilities.

---

## Phase 1 — Stabilization

### Fixed

* Improved ADB battery and network parsing for empty or non-numeric values.
* Improved installed-application package parsing.
* Fixed duplicate evidence counting during repeated acquisition.
* Added per-file acquisition progress reporting.
* Fixed acquisition-panel signal stacking.
* Corrected evidence categorization.
* Improved device registration handling during acquisition.
* Improved acquisition output-directory preparation.
* Improved evidence file-size reporting during acquisition.
* Improved case-number uniqueness validation.
* Improved recent-case widget cleanup.
* Improved notes-save behavior outside the main window.
* Improved keyword-search handling of null values.

---

## v1.0.0 Baseline

Initial feature set prior to the phased stabilization and completion work:

* Case management
* Android device identification
* ADB-based evidence acquisition
* SQLite persistence with WAL mode and foreign-key enforcement
* SHA-256 hashing
* Full HTML/PDF reporting
* PyQt6 desktop UI
* Dashboard
* Device panel
* Acquisition panel
* Cases panel
* Analysis panel
* Reports panel
