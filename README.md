# ForensIQ — Digital Forensic Suite v1.0

A Python/PyQt6 desktop application for professional Android device forensic investigation.

## Documentation

| Doc | Covers |
|---|---|
| [`INSTALLATION.md`](INSTALLATION.md) | Full setup: Python env, ADB, device prep, troubleshooting |
| [`USER_GUIDE.md`](USER_GUIDE.md) | Panel-by-panel walkthrough of a case, from creation to report |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Layered design, threading model, core module responsibilities |
| [`DATABASE_SCHEMA.md`](DATABASE_SCHEMA.md) | All 8 tables, relationships, and migration mechanics |
| [`CHANGELOG.md`](CHANGELOG.md) | Fix and feature history by development phase |
| [`RELEASE_NOTES.md`](RELEASE_NOTES.md) | v1.0.0 release summary |

This README covers the quick start; the docs above go deeper on each area.

---

## Requirements

- Python 3.11+
- Android Platform Tools (ADB) installed and on PATH
- USB Debugging enabled on target device

## Setup

```bash
# 1. Create virtual environment
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run
python main.py
```

Optional — build a standalone executable instead of running from source:
`scripts/build_release.sh` (macOS/Linux) or `scripts\build_release.bat`
(Windows). ADB must still be installed separately either way.

## ADB Installation

Download Android Platform Tools:  
https://developer.android.com/tools/releases/platform-tools

Add `adb` to your system PATH. Verify with:
```bash
adb version
```

---

## Workflow

| Step | Panel | Action |
|------|-------|--------|
| 1 | Cases | Create or open an investigation case |
| 2 | Device | Connect device, click Scan, verify USB Debugging |
| 3 | Acquisition | Select case & evidence targets, click Start Acquisition |
| 4 | Analysis | Run app classification, timeline, metadata, keyword search |
| 5 | Integrity | Verify SHA-256 hashes; view per-item pass/fail history |
| 6 | Reports | Generate PDF/HTML — full, summary, integrity, audit, custody, executive |
| 7 | Audit Trail | Review immutable system audit log; export JSON/HTML |
| 8 | Custody | Record and export chain of custody events per evidence item |

---

## Project Structure

```
forensiq_tool/
├── main.py                         # Entry point — HiDPI aware
├── requirements.txt
└── forensiq/
    ├── core/
    │   ├── adb_manager.py          # ADB operations + background workers
    │   ├── case_manager.py         # SQLite CRUD — all 8 tables
    │   ├── hasher.py               # SHA-256 streaming hash utilities
    │   ├── analyzer.py             # Timeline, metadata, apps, duplicates,
    │   │                           #   correlation, global search, analysis reports
    │   ├── integrity_engine.py     # Hash re-verification + VerificationWorker thread
    │   ├── audit_service.py        # Immutable audit trail + custody event helpers
    │   └── reporter.py             # PDF (ReportLab) + HTML — 9 report types
    └── ui/
        ├── styles.py               # Dark QSS theme (HiDPI-aware)
        ├── main_window.py          # Main window + sidebar navigation
        └── panels/
            ├── dashboard.py        # Overview, quick stats, recent cases
            ├── device_panel.py     # Phase 1 — Device Identification
            ├── acquisition_panel.py # Phase 2 — Evidence Acquisition
            ├── cases_panel.py      # Phase 3 — Evidence Management
            ├── analysis_panel.py   # Phase 4 — Advanced Analysis Engine
            ├── report_panel.py     # Phase 5 — Report Generation (9 types)
            ├── integrity_panel.py  # SHA-256 integrity verification
            ├── audit_panel.py      # Immutable audit trail viewer
            └── custody_panel.py    # Chain of custody management
```

---

## Database

SQLite at `~/.forensiq/forensiq.db` (WAL mode, FK enforcement on). 8 tables
covering cases, devices, evidence, analysis results, timeline events,
verification history, an **immutable** audit trail, and chain-of-custody
events. Schema migrations run automatically on startup — existing databases
are upgraded safely.

Full table definitions and relationships: [`DATABASE_SCHEMA.md`](DATABASE_SCHEMA.md).

---

## Reports & Analysis

9 report types (Full Forensic HTML, Full Forensic PDF, Case Summary,
Evidence Summary, Integrity, Audit Trail, Chain of Custody, Executive,
Analysis) and an
analysis engine covering unified timeline, file metadata, application
classification, duplicate detection, artifact correlation, global search,
and filtering.

Full details: [`USER_GUIDE.md`](USER_GUIDE.md) (how to use them) and
[`ARCHITECTURE.md`](ARCHITECTURE.md) (how they're implemented).

---

## Security Notes

- Audit trail rows are **immutable** — no UPDATE or DELETE methods exist
- Custody events survive case/evidence deletion (ON DELETE SET NULL FK)
- All case/evidence fields are HTML-escaped before report output
- SHA-256 hashes are computed in 64 KB streaming chunks (safe for large files)
- Root access is **not required** — only user-accessible storage is pulled via ADB

---

## Notes

- User file pull (`/sdcard/DCIM`, `/sdcard/Documents`, etc.) requires device unlocked
- `python-magic` is used for accurate MIME type detection if installed; falls back to `mimetypes`
- All evidence files are SHA-256 hashed at acquisition time and stored in the DB

## 🔄 Current Version & Upcoming Upgrade

### 📌 Current ForensIQ

ForensIQ currently provides a structured **digital forensics workflow** for:

- 📱 Evidence and Case Acquisition
- 🔐 Evidence Integrity & SHA-256 Hash Verification
- 🔍 Forensic Artifact Analysis
- 🧾 Audit Logging & Chain of Custody
- 📊 HTML/PDF Forensic Report Generation

In short, the current version focuses on **acquiring, analyzing, validating, and documenting digital evidence**.

---

### 🚧 Upcoming Major Upgrade — Android Deleted Data Recovery

The next major upgrade of ForensIQ is currently under development.

The upcoming version will introduce **Android Deleted Data Recovery**, focusing on identifying and recovering **recoverable remnants of deleted data** through:

- Filesystem Analysis
- Unallocated-Space Analysis
- File Carving
- Recovery Validation
- Cryptographic Hash Verification
- Forensic Analysis of Recovered Artifacts
- Evidence Documentation & Reporting

This upgrade will extend ForensIQ toward a more complete forensic workflow:

**Acquisition → Recovery → Validation → Analysis → Reporting**

> 🚀 **Status:** Current version available • **Android Deleted Data Recovery — Coming Soon**

---

## 🛣️ Roadmap

### ✅ Completed

- [x] 📱 Evidence & Case Acquisition
- [x] 🔐 Hash Verification
- [x] 🔍 Forensic Analysis
- [x] 🧾 Audit & Chain of Custody
- [x] 📊 Report Generation

### 🚧 In Development

- [ ] 🗑️ Android Deleted Data Recovery
- [ ] 💾 Filesystem & Unallocated-Space Analysis
- [ ] 🧩 File Carving Engine
- [ ] 🔎 Advanced Recovery Validation

> **Note:** The recovery features listed above are part of the upcoming major upgrade and are currently under development.
---

## ⚠️ Disclaimer

ForensIQ is developed **for educational and authorized digital forensics research purposes only**.

This project is intended to be used only on devices, systems, and data for which you have explicit authorization.

The author is not responsible for misuse, unauthorized access, data loss, or any damage resulting from the use of this software.

---

## 📄 License

This project is currently **not licensed for redistribution or commercial use**.

All rights are reserved by the author unless otherwise stated.
