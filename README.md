# ForensIQ — Android Digital Forensics Suite

> **Current Release: v1.4.0**

A Python/PyQt6 desktop application for professional Android device forensic investigation.

---

## Documentation

| Doc | Covers |
|---|---|
| [`INSTALLATION.md`](INSTALLATION.md) | Full setup: Python environment, ADB, device preparation, and troubleshooting |
| [`USER_GUIDE.md`](USER_GUIDE.md) | Panel-by-panel walkthrough of a case, from creation to report |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Layered design, threading model, and core module responsibilities |
| [`DATABASE_SCHEMA.md`](DATABASE_SCHEMA.md) | Database tables, relationships, and migration mechanics |
| [`CHANGELOG.md`](CHANGELOG.md) | Fixes and feature history by development phase |
| [`RELEASE_NOTES.md`](RELEASE_NOTES.md) | Release notes and version summary |

This README provides a quick overview and setup guide. The documentation above provides deeper technical and usage details.

---

## Requirements

- Python 3.11+
- Android Platform Tools (ADB) installed and available on PATH
- USB Debugging enabled on the target device

---

## Setup

```bash
# 1. Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate

# macOS/Linux:
source venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run ForensIQ
python main.py
```

### Optional: Build a Standalone Executable

Instead of running from source, you can build a standalone executable using the provided build scripts:

- Windows: `scripts\build_release.bat`
- macOS/Linux: `scripts/build_release.sh`

> **Note:** ADB must still be installed separately and available on the system PATH.

---

## ADB Installation

Download Android Platform Tools:

https://developer.android.com/tools/releases/platform-tools

Add `adb` to your system PATH and verify the installation:

```bash
adb version
```

---

## Core Workflow

| Step | Panel | Action |
|------|-------|--------|
| 1 | Cases | Create or open an investigation case |
| 2 | Device | Connect device, scan, and verify USB Debugging |
| 3 | Acquisition | Select case and evidence targets, then start acquisition |
| 4 | Analysis | Run application classification, timeline, metadata, and keyword analysis |
| 5 | Integrity | Verify SHA-256 hashes and review verification history |
| 6 | Reports | Generate forensic reports in PDF/HTML formats |
| 7 | Audit Trail | Review and export the system audit log |
| 8 | Custody | Record and export chain-of-custody events for evidence |

---

## Project Structure

```text
Forensiq/
├── forensiq/
│   ├── core/
│   │   ├── adb_manager.py
│   │   ├── analyzer.py
│   │   ├── audit_service.py
│   │   ├── case_manager.py
│   │   ├── hasher.py
│   │   ├── integrity_engine.py
│   │   ├── key_manager.py
│   │   ├── manifest_service.py
│   │   ├── reporter.py
│   │   ├── signature_service.py
│   │   └── time_utils.py
│   │
│   └── ui/
│       ├── main_window.py
│       └── panels/
│           ├── acquisition_panel.py
│           ├── analysis_panel.py
│           ├── audit_panel.py
│           ├── cases_panel.py
│           ├── custody_panel.py
│           ├── dashboard.py
│           ├── device_panel.py
│           ├── integrity_panel.py
│           ├── report_panel.py
│           └── signature_panel.py
│
├── scripts/
│   ├── build_release.bat
│   └── build_release.sh
│
├── tests/
│   ├── test_analyzer.py
│   ├── test_audit.py
│   ├── test_case_manager.py
│   ├── test_hasher.py
│   ├── test_integrity.py
│   ├── test_manifest.py
│   ├── test_regression.py
│   ├── test_reporter.py
│   ├── test_signature.py
│   └── test_time_utils.py
│
├── main.py
├── pyproject.toml
├── requirements.txt
├── pytest.ini
└── README.md
```

---

## Database

ForensIQ uses SQLite at:

`~/.forensiq/forensiq.db`

The database uses WAL mode with foreign-key enforcement enabled.

It stores information covering:

- Cases
- Devices
- Evidence
- Analysis results
- Timeline events
- Verification history
- Audit trail
- Chain-of-custody events

Database schema migrations run automatically on startup to safely upgrade existing databases.

Full table definitions and relationships are documented in [`DATABASE_SCHEMA.md`](DATABASE_SCHEMA.md).

---

## Reports & Analysis

ForensIQ provides multiple forensic reporting and analysis capabilities.

### Reports

- Full Forensic HTML
- Full Forensic PDF
- Case Summary
- Evidence Summary
- Integrity Report
- Audit Trail Report
- Chain of Custody Report
- Executive Report
- Analysis Report

### Analysis

The analysis engine includes:

- Unified forensic timeline
- File metadata analysis
- Application classification
- Duplicate detection
- Artifact correlation
- Global search
- Filtering

For detailed usage, see [`USER_GUIDE.md`](USER_GUIDE.md).

For implementation details, see [`ARCHITECTURE.md`](ARCHITECTURE.md).

---

## Security & Integrity

- Audit trail records are designed to be immutable — no UPDATE or DELETE methods are provided
- Chain-of-custody events survive case/evidence deletion through `ON DELETE SET NULL`
- Case and evidence fields are HTML-escaped before report generation
- SHA-256 hashes are calculated using 64 KB streaming chunks for large files
- Root access is not required; only user-accessible storage is acquired through ADB

---

## Notes

- Device must be unlocked when pulling user files such as `/sdcard/DCIM` or `/sdcard/Documents`
- `python-magic` is used for MIME type detection when available; otherwise the application falls back to Python's `mimetypes`
- Evidence files are SHA-256 hashed during acquisition and the hashes are stored in the database

---

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

Copyright © 2026 Rudra Modi.

All rights reserved.

No license is currently granted for copying, modification, distribution, or commercial use of this software unless explicitly authorized by the author.
