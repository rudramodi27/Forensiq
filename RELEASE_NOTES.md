# ForensIQ v1.0.0 — Release Notes

**Release date:** 2026-07-10

ForensIQ is a PyQt6 desktop application for Android device forensic
investigation: device identification, evidence acquisition over ADB,
artifact analysis, integrity verification, chain-of-custody tracking,
immutable audit logging, and multi-format reporting — backed by a local
SQLite case database.

This is the first tagged release, bringing together the full set of
stabilization, feature-completion, performance, UI, testing, and
documentation work completed across Phases 1–7.

## Highlights

- **9 navigable modules**: Dashboard, Device, Acquisition, Cases, Analysis,
  Reports, Integrity, Audit Trail, Custody.
- **9 report types**, including a full HTML and PDF forensic report, plus
  case, evidence, integrity, audit, custody, executive, and analysis-specific
  reports.
- **Analysis engine**: unified timeline, file metadata extraction, app
  classification (system/user/disabled/sideloaded), duplicate detection,
  artifact correlation, and global keyword search with filters.
- **Immutable audit trail** and **chain-of-custody tracking** that survives
  case/evidence deletion, for evidentiary integrity.
- **SHA-256 integrity verification** with full pass/fail history per item.
- No root access required — acquisition is limited to user-accessible
  device storage over standard ADB.
- **243 automated tests** covering every core module plus dedicated
  regression coverage for previously fixed defects.

## What's Included

- Full application source (`forensiq/`) and entry point (`main.py`)
- `requirements.txt` for a plain `pip install` workflow, and `pyproject.toml`
  for `pip install -e .` / packaging workflows
- Optional standalone-executable build scripts
  (`scripts/build_release.sh`, `scripts/build_release.bat`)
- Full documentation set: `README.md`, `INSTALLATION.md`, `USER_GUIDE.md`,
  `ARCHITECTURE.md`, `DATABASE_SCHEMA.md`, `CHANGELOG.md`
- Full test suite (`tests/`)

## Upgrading from a Pre-Release Build

No action required. The database schema is versioned via an additive,
idempotent migration list — ForensIQ detects and safely upgrades an existing
`~/.forensiq/forensiq.db` on first launch. No data is lost or altered.

## Known Limitations

- Evidence acquisition covers user-accessible storage (`DCIM`, `Pictures`,
  `Movies`, `Videos`, `Documents`, `Download`) over ADB; it does not perform
  a full physical/root-level device image.
- MIME type detection uses `python-magic` if installed, otherwise falls back
  to Python's standard-library `mimetypes`, which is somewhat less precise
  for files without a reliable extension.
- The standalone executable build (via PyInstaller) has not been exercised
  on every target OS as part of this release; `python main.py` with
  `requirements.txt` installed remains the primary, fully validated way to
  run ForensIQ.

## Full Change History

See [`CHANGELOG.md`](CHANGELOG.md) for the complete, phase-by-phase list of
fixes and features included in this release.
