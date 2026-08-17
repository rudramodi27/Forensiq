# ForensIQ v1.4.0 — Release Notes

**Release date:** 2026-08-14

ForensIQ is a PyQt6 desktop application for Android digital forensic
investigation, providing device identification, evidence acquisition over
ADB, artifact analysis, evidence integrity verification, chain-of-custody
tracking, audit logging, case management, and multi-format forensic
reporting backed by a local SQLite case database.

This release consolidates the major forensic investigation capabilities
developed across Phases 1–8, including advanced case management,
investigation workflow, unified forensic analysis, evidence integrity,
auditability, and reporting.

## Highlights

* **Advanced Case Management** with case priority, reviewer assignment,
  tags, investigation status, closure reason, and case activity tracking.
* **Case lifecycle workflow** supporting DRAFT, ACTIVE,
  UNDER_INVESTIGATION, REVIEW, CLOSED, and ARCHIVED states.
* **Unified forensic timeline** for correlating evidence and investigation
  events chronologically.
* **Forensic analysis engine** supporting file metadata extraction,
  installed application analysis, artifact correlation, duplicate
  detection, and keyword-based investigation.
* **SHA-256 evidence integrity verification** with verification history
  and mismatch detection.
* **Digital evidence signatures** using Ed25519-based signing and
  verification.
* **Immutable audit trail and chain-of-custody tracking** for recording
  important investigation and evidence-handling events.
* **Multi-format forensic reporting** including HTML and PDF reports,
  along with specialized case, evidence, integrity, audit, custody,
  executive, and analysis reports.
* **ADB-based evidence acquisition** with acquisition logging and
  forensic evidence hashing.
* **Automated test coverage** across the core forensic modules and
  regression-tested functionality.

## What's Included

* Full application source (`forensiq/`) and entry point (`main.py`)
* `requirements.txt` for standard Python installation
* `pyproject.toml` for packaging and editable installation
* Optional standalone executable build scripts
  (`scripts/build_release.sh`, `scripts/build_release.bat`)
* Test suite (`tests/`)
* Database schema and migration support
* Complete project documentation:

  * `README.md`
  * `INSTALLATION.md`
  * `USER_GUIDE.md`
  * `ARCHITECTURE.md`
  * `DATABASE_SCHEMA.md`
  * `CHANGELOG.md`
  * `RELEASE_NOTES.md`

## Case Management

Version 1.4 introduces the advanced investigation case-management
workflow.

Cases can maintain:

* Priority
* Assigned investigator
* Reviewer
* Tags
* Investigation status
* Closure reason
* Case activity history
* Investigation notes

The supported lifecycle is:

```text
DRAFT
  ↓
ACTIVE
  ↓
UNDER_INVESTIGATION
  ↓
REVIEW
  ↓
CLOSED
  ↓
ARCHIVED
```

Archived cases are treated as read-only to preserve the investigation
record.

## Evidence Integrity & Auditability

ForensIQ provides forensic evidence-integrity controls based on SHA-256
hash verification.

The integrity subsystem supports:

* Evidence hash generation
* Hash re-verification
* Match/mismatch detection
* Verification timestamps
* Integrity status tracking
* Audit entries for important integrity operations

The chain-of-custody and audit systems maintain a traceable history of
evidence handling and investigation activity.

## Analysis & Reporting

The analysis subsystem provides forensic investigation capabilities
including:

* Installed application analysis
* File metadata extraction
* Timeline generation
* Keyword search
* Artifact correlation
* Duplicate detection
* Evidence analysis findings

Reports can be generated in multiple formats for investigation,
verification, review, and presentation purposes.

## Digital Signatures

ForensIQ includes digital-signature support for forensic records using
Ed25519-based signing and verification.

This provides an additional authenticity mechanism alongside SHA-256
integrity verification and audit logging.

## Known Limitations

* Evidence acquisition is limited to user-accessible Android storage
  through authorized ADB connections. It does not perform a full
  physical/root-level device image.
* MIME type detection uses `python-magic` when available and falls back
  to Python's standard-library `mimetypes`.
* Standalone executable builds may require additional platform-specific
  validation; running the application through the Python environment
  remains the primary development and validation workflow.

## Upcoming

### Android Deleted Data Recovery

Planned future functionality for recovering and analysing deleted
Android data.

This capability is **not part of v1.4.0** and should not be considered
available in the current release.

## Full Change History

See [`CHANGELOG.md`](CHANGELOG.md) for the complete phase-by-phase
development history, fixes, and feature additions.
