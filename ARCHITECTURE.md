# ForensIQ — Architecture

## 1. Overview

ForensIQ is a single-user desktop application for acquiring, analyzing,
managing, verifying, and reporting on digital evidence obtained from
authorized Android devices through ADB.

It is implemented as a three-layer PyQt6 desktop application backed by a
local SQLite database:

```text id="r8m0a2"
┌─────────────────────────────────────────────────────────────┐
│                         UI Layer                            │
│                         PyQt6                               │
│  Dashboard · Device · Acquisition · Cases · Analysis        │
│  Reports · Signatures · Integrity · Audit · Custody         │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                    Core / Service Layer                     │
│                                                             │
│  ADB Manager · Case Manager · Analyzer · Integrity Engine   │
│  Audit Service · Hasher · Reporter · Key Manager            │
│  Signature Service · Manifest Service                       │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                     Persistence Layer                       │
│                                                             │
│               SQLite / Case Database                        │
│                 ~/.forensiq/forensiq.db                     │
└─────────────────────────────────────────────────────────────┘
```

The UI does not directly manipulate database tables. Persistence and
business operations are handled through `CaseManager` and the appropriate
core services. This keeps the core logic testable independently of Qt.

The architecture is intentionally local-first: investigation data,
evidence metadata, analysis results, verification records, audit records,
custody events, and signatures are maintained within the local
investigation environment.

---

## 2. Architectural Layers

### 2.1 UI Layer

The UI layer is implemented using PyQt6.

Responsibilities include:

* Navigation
* Case management
* Device identification
* Evidence acquisition
* Evidence browsing
* Analysis execution
* Integrity verification
* Digital-signature operations
* Audit review
* Chain-of-custody management
* Report generation
* Investigation status and result presentation

Panels communicate with core services rather than implementing forensic
business logic themselves.

### 2.2 Core / Service Layer

The core layer contains the application's forensic and business logic.

Major services include:

* `case_manager.py`
* `adb_manager.py`
* `hasher.py`
* `integrity_engine.py`
* `analyzer.py`
* `audit_service.py`
* `reporter.py`
* `key_manager.py`
* `signature_service.py`
* `manifest_service.py`

The core layer is designed to remain largely independent of Qt so that
important functionality can be tested without starting the graphical
interface.

### 2.3 Persistence Layer

ForensIQ uses SQLite for local case persistence.

The primary database is:

```text id="x6q3bn"
~/.forensiq/forensiq.db
```

`CaseManager` owns the database schema, migrations, and CRUD operations.

The application uses an additive and idempotent migration strategy so that
existing databases can be upgraded without destructive schema replacement.

---

## 3. Process and Threading Model

PyQt's event loop is single-threaded. Operations that may take significant
time are therefore executed asynchronously using Qt worker threads.

Current workers include:

| Worker               | Defined in                  | Purpose                       |
| -------------------- | --------------------------- | ----------------------------- |
| `DeviceDetectWorker` | `core/adb_manager.py`       | Asynchronous device discovery |
| `AcquisitionWorker`  | `core/adb_manager.py`       | Evidence acquisition          |
| `VerificationWorker` | `core/integrity_engine.py`  | SHA-256 verification          |
| `AnalysisWorker`     | `core/analyzer.py`          | Forensic analysis             |
| `ReportWorker`       | `ui/panels/report_panel.py` | Report generation             |

Workers communicate with their respective UI panels through Qt signals.

Typical signals include:

* `progress`
* `finished`
* `error`
* workload-specific result signals

Workers do not directly manipulate Qt widgets.

Only appropriate primitive or result data crosses the signal boundary.

### Database Thread Safety

`CaseManager` creates a fresh SQLite connection per operation and uses
WAL mode with `check_same_thread=False`.

This avoids sharing a long-lived SQLite connection between the UI thread
and worker threads.

---

## 4. Core Modules

### 4.1 `core/case_manager.py` — Case and Persistence Management

`CaseManager` owns:

* Database schema
* Database migrations
* Case CRUD
* Device records
* Evidence records
* Acquisition sessions
* Analysis results
* Timeline events
* Verification results
* Audit records
* Custody events
* Signature records

The primary investigation hierarchy is:

```text id="l7x0pd"
Case
  └── Device
       └── Acquisition Session
            └── Evidence
```

A device is identified using the case and device serial information so that
the same physical device is not unnecessarily duplicated within a case.

Each acquisition run is represented by a separate acquisition session.

Acquisition sessions preserve point-in-time acquisition context and connect
the resulting evidence to the corresponding acquisition operation.

---

## 5. Advanced Case Management

Version 1.4 introduces advanced investigation case management.

Cases support:

* Case number
* Case title
* Investigator
* Reviewer
* Priority
* Tags
* Description
* Investigation notes
* Evidence directory
* Investigation status
* Closure reason
* Case activity

### Case Lifecycle

The supported investigation workflow is:

```text id="1f5s0w"
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

The case lifecycle provides a controlled progression from initial case
creation through investigation, review, closure, and archival.

Important case operations and status transitions are recorded in the audit
trail.

### Archived Cases

Archived cases are treated as read-only to preserve the investigation
record.

Case activity, evidence history, audit information, and custody information
remain associated with the investigation record.

---

## 6. `core/adb_manager.py` — Android Device Communication

`ADBManager` provides the interface between ForensIQ and the Android Debug
Bridge executable.

Responsibilities include:

* Device discovery
* Device identification
* Device profiling
* Installed application information
* Running process information
* Battery information
* Network information
* Evidence acquisition

Device acquisition operates through authorized ADB access.

ForensIQ does not require root access and does not perform unrestricted
physical device extraction.

User-accessible storage is acquired from standard Android storage locations,
including:

* `DCIM`
* `Pictures`
* `Movies`
* `Videos`
* `Documents`
* `Download`

Each acquired file is hashed as it is written to the local evidence
directory.

---

## 7. `core/hasher.py` — Hashing

The hashing subsystem provides SHA-256 operations used throughout the
forensic workflow.

Supported operations include:

* File hashing
* Directory hashing
* String hashing
* Byte hashing
* File verification

File hashing is performed in streaming chunks so large evidence files do
not need to be completely loaded into memory.

SHA-256 is used during:

```text id="t7s5d8"
Evidence Acquisition
        ↓
Stored Evidence Hash
        ↓
Integrity Verification
        ↓
Analysis / Reporting
```

---

## 8. `core/integrity_engine.py` — Evidence Integrity

The integrity engine re-hashes evidence stored on disk and compares the
result against the acquisition-time SHA-256 hash.

Supported operations include:

* `verify_single`
* `verify_case`
* `verify_all`

Verification results are classified as:

```text id="8qz7k1"
PASS
FAIL
MISSING
ERROR
```

Every verification operation is persisted in `verification_results`.

Verification activity is also recorded in the audit trail.

Integrity results can be exported to JSON and HTML.

---

## 9. `core/analyzer.py` — Forensic Analysis Engine

The analysis engine provides stateless forensic analysis functions operating
on acquired evidence and, where required, the case database.

### Timeline Analysis

`build_file_timeline` and `build_unified_timeline` combine filesystem
timestamps with investigation events such as:

* Evidence acquisition
* Verification
* Audit activity
* Custody events

This produces a unified chronological investigation timeline.

### File Metadata

`extract_file_metadata` provides information including:

* MIME type
* File size
* SHA-256
* Relevant timestamps

MIME detection uses `python-magic` when available and falls back to Python's
standard `mimetypes` module.

### Application Analysis

Installed applications can be classified as:

* System
* User
* Disabled
* Sideloaded

The analysis can also identify recently installed applications where the
available device information supports the determination.

### Duplicate Detection

Duplicate detection identifies evidence sharing matching SHA-256 and size
information.

### Artifact Correlation

Correlation links relevant forensic records, including:

```text id="q1b2ny"
Evidence
  ↕
Applications
  ↕
Audit Events
  ↕
Custody Events
  ↕
Verification Records
```

### Global Search

Keyword search can operate across evidence and investigation records with
available filtering capabilities such as:

* Date range
* Investigator
* File type
* Evidence type
* Verification status

Analysis results are persisted in the database for later review and
reporting.

---

## 10. `core/audit_service.py` — Audit and Chain of Custody

`AuditService` provides typed helper methods around audit and custody
operations.

Examples include:

* Case creation logging
* Evidence addition logging
* Verification logging
* Report generation logging
* Signature logging
* Signature verification logging
* Custody events

### Audit Trail

The audit trail is append-only.

There is intentionally no normal application path for editing or deleting
audit entries.

This supports forensic traceability by preserving historical investigation
activity.

### Chain of Custody

Custody events record evidence-handling operations such as:

* Collection
* Transfer
* Storage
* Release

Custody records can contain investigator, location, timestamp, and notes.

Custody history is preserved as part of the investigation record.

---

## 11. Reporting Architecture

`core/reporter.py` provides forensic report generation.

Reports use structured investigation data from the case database and
evidence records.

Supported report categories include:

* Full Forensic
* Case Summary
* Evidence Summary
* Integrity
* Audit Trail
* Chain of Custody
* Executive
* Analysis

The full forensic report can be generated in HTML and PDF formats.

User-controlled data is escaped before being inserted into generated HTML
reports to reduce the risk of HTML/script injection through case or evidence
metadata.

Report generation is executed asynchronously so large reports do not block
the graphical interface.

---

## 12. Digital Signature Architecture

### `core/key_manager.py`

`KeyManager` manages Ed25519 signing keys.

Private keys are stored separately from the SQLite investigation database
under:

```text id="p6n5tj"
~/.forensiq/keys/
```

Private keys are not stored in `forensiq.db` and are not included in normal
application logging.

### `core/signature_service.py`

`SignatureService` provides signing and verification operations for supported
forensic artifacts.

The signing workflow is:

```text id="k9q0mv"
Forensic Artifact
       ↓
SHA-256 Hash
       ↓
Ed25519 Signature
       ↓
Detached .sig.json
       ↓
Signature Metadata in Database
```

The original artifact is not rewritten during the signing operation.

Signature verification re-hashes the selected artifact and validates its
signature.

Verification states include:

```text id="0b2xqv"
VALID
INVALID
MODIFIED
MISSING
KEY_UNAVAILABLE
```

Signature operations are also mirrored into the audit trail.

---

## 13. UI Architecture

`main_window.py` hosts the main application window and the navigation
system.

The primary application panels are:

```text id="4i4z9k"
Dashboard
Device
Acquisition
Cases
Analysis
Reports
Signatures
Integrity
Audit Trail
Custody
```

Navigation is driven by the application's navigation configuration and
stacked-widget architecture.

Each navigation entry maps to a corresponding panel.

The architecture allows new panels to be introduced without redesigning the
entire application navigation system.

### Styling

UI styling is centralized through the application stylesheet.

Status information such as:

* PASS / FAIL
* VALID / INVALID
* MODIFIED
* Other forensic result states

is presented through dedicated status/result indicators.

---

## 14. Data Flow — Complete Investigation Lifecycle

The typical investigation flow is:

```text id="3b2v5r"
1. Create Case
       ↓
2. Identify Android Device
       ↓
3. Start Acquisition Session
       ↓
4. Acquire Evidence
       ↓
5. Generate SHA-256 Hashes
       ↓
6. Analyse Evidence
       ↓
7. Build Unified Timeline
       ↓
8. Verify Evidence Integrity
       ↓
9. Record Audit / Custody Activity
       ↓
10. Generate Reports
       ↓
11. Sign Supported Artifacts
       ↓
12. Verify Signatures
       ↓
13. Review / Close Case
       ↓
14. Archive Case
```

### Detailed Data Flow

1. **Cases panel** creates the investigation case through `CaseManager`.
2. **Device panel** communicates with ADB and stores the identified device.
3. **Acquisition panel** starts an acquisition session and acquires
   user-accessible evidence.
4. Each acquired file is hashed and stored as an evidence record.
5. **Analysis panel** processes evidence and persists analysis results and
   timeline events.
6. **Integrity panel** re-hashes evidence and stores verification results.
7. **Audit Service** records important investigation operations.
8. **Custody panel** records evidence-handling events.
9. **Reports panel** collects investigation data and generates reports.
10. **Signature panel** signs supported artifacts and stores signature
    metadata.
11. Signature verification re-hashes the artifact and validates its
    signature.
12. Case management controls the investigation through review, closure,
    and archival.

---

## 15. Database and Persistence Model

The SQLite database is the central persistence layer for investigation
metadata.

Major logical data areas include:

```text id="q7m8pz"
Cases
 ├── Devices
 │    └── Acquisition Sessions
 │         └── Evidence
 │
 ├── Analysis Results
 ├── Timeline Events
 ├── Verification Results
 ├── Audit Trail
 ├── Custody Events
 ├── Signatures
 └── Case Activity / Investigation Metadata
```

The database schema and migration details are documented separately in
`DATABASE_SCHEMA.md`.

---

## 16. Security and Forensic Integrity Principles

ForensIQ follows several design principles intended to preserve forensic
traceability.

### Audit Immutability

Audit records are append-only. The application does not provide normal
operations for modifying or deleting historical audit entries.

### Evidence Integrity

Acquired evidence receives a SHA-256 hash that can later be independently
recomputed and compared.

### Chain of Custody

Evidence-handling events are recorded separately from the audit trail so
custody history remains explicitly identifiable.

### Digital Authenticity

Supported forensic artifacts can be signed using Ed25519 digital signatures.

### No Root / Exploit Usage

Acquisition is limited to data exposed through authorized ADB access.

ForensIQ does not attempt to bypass Android security controls or obtain
unauthorized access to protected device data.

### Database Migration Safety

Schema changes are implemented through additive migrations rather than
destructive database replacement.

### Output Escaping

User-controlled data is escaped before being inserted into generated HTML
reports.

---

## 17. Testing Architecture

The project maintains automated tests for core functionality.

The architecture intentionally keeps significant forensic logic independent
from Qt widgets so that modules can be tested without launching the full
graphical interface.

Testing areas include:

* Case management
* Database operations
* Device handling
* Evidence acquisition
* Hashing
* Integrity verification
* Analysis
* Audit logging
* Chain of custody
* Reporting
* Digital signatures
* Regression scenarios

The test suite is located under:

```text id="q0m6n3"
tests/
```

---

## 18. Repository Structure

The repository is organized around the application package, supporting
scripts, tests, and documentation:

```text id="z5n2k8"
Forensiq/
├── forensiq/
│   ├── core/
│   └── ui/
├── scripts/
├── tests/
├── main.py
├── requirements.txt
├── pyproject.toml
├── pytest.ini
├── README.md
├── INSTALLATION.md
├── USER_GUIDE.md
├── ARCHITECTURE.md
├── DATABASE_SCHEMA.md
├── CHANGELOG.md
└── RELEASE_NOTES.md
```

The exact set of internal modules may evolve as new forensic capabilities
are introduced.

---

## 19. Design Principles Preserved

The following principles are maintained throughout the architecture:

* **Evidence integrity** — acquired evidence is SHA-256 hashed and can be
  independently re-verified.
* **Audit immutability** — audit history is append-only.
* **Chain-of-custody traceability** — evidence-handling events are recorded
  independently.
* **Controlled case lifecycle** — investigations progress through defined
  case states.
* **No root / exploit usage** — acquisition relies on authorized ADB access.
* **Local-first persistence** — investigation metadata is stored locally.
* **Idempotent database migrations** — existing databases can be upgraded
  without destructive replacement.
* **Separation of concerns** — UI, forensic services, and persistence remain
  logically separated.
* **Thread-safe database access** — worker and UI operations use independent
  database connections.
* **Asynchronous long-running operations** — acquisition, analysis,
  verification, and reporting do not block the UI.
* **Boundary escaping** — generated HTML reports escape user-controlled data.
* **Cryptographic authenticity** — supported artifacts can be protected with
  Ed25519 signatures.
