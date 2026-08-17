# ForensIQ — User Guide

This guide walks through a typical Android forensic investigation from opening the application to generating a final report. For installation steps, see `INSTALLATION.md`. For database internals, see `DATABASE_SCHEMA.md`.

## 1. Application Layout

ForensIQ opens on the **Dashboard**, with a sidebar on the left for navigation:

| Sidebar item  | Purpose                                                                  |
| ------------- | ------------------------------------------------------------------------ |
| ⌂ Dashboard   | Overview, quick statistics, and recent cases                             |
| ⎙ Device      | Connect and identify an Android device                                   |
| ↓ Acquisition | Acquire user-accessible evidence from the device                         |
| ◉ Cases       | Create, open, and manage investigation cases                             |
| ⊕ Analysis    | Run timeline, metadata, app, duplicate, correlation, and search analysis |
| ▤ Reports     | Generate forensic reports                                                |
| ⊞ Integrity   | Verify SHA-256 hashes of acquired evidence                               |
| ≡ Audit Trail | Review the append-only system audit log                                  |
| ⛓ Custody     | Record and review chain-of-custody events                                |

The header bar shows the active case number and investigator once a case is opened, making it clear which case subsequent investigation actions apply to.

---

## 2. Starting and Managing a Case

1. Open the **Cases** panel and click **New Case**.
2. Enter a unique **case number**, case title, and investigator.
3. Add an optional description or investigation notes.
4. Optionally assign a **priority**, **reviewer**, and **tags** to help organize the investigation.
5. Optionally set an evidence directory. If left blank, ForensIQ creates one automatically.
6. Save the case. It becomes available across the other investigation panels.

### Case Status Workflow

ForensIQ supports a controlled investigation lifecycle:

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

Cases should progress through the supported investigation stages rather than being changed arbitrarily.

### Case Management Features

From the Cases panel, investigators can:

* Edit the case title, investigator, description, and evidence directory.
* Set and update case priority.
* Assign or change the reviewer.
* Add or update investigation tags.
* Add investigation notes.
* Change the case status through the supported workflow.
* Record a closure reason when closing a case.
* Review case activity associated with important case operations.

Important case changes and status transitions are recorded in the audit trail.

### Closing and Archiving a Case

Before closing a case, provide the required closure information and verify that the investigation is ready for final review.

Once a case is archived, it is treated as **read-only** to help preserve the investigation record.

Case activity, audit records, evidence history, and chain-of-custody records remain part of the forensic record and should be preserved throughout the investigation lifecycle.

---

## 3. Connecting and Identifying a Device

1. Enable **USB debugging** on the Android device through **Settings → Developer Options** and connect it via USB.
2. Open the **Device** panel and click **Scan**. ForensIQ lists devices visible to ADB.
3. Select a device to view its forensic identification profile, including model, manufacturer, Android/SDK version, build number, CPU ABI, USB debugging status, battery, and network information.
4. The device record is associated with the active case once identified.

If no devices appear, verify that `adb devices` shows the device from a terminal first. This helps determine whether the issue is related to ADB configuration or the device connection. See `INSTALLATION.md` for ADB setup.

---

## 4. Acquiring Evidence

1. Open the **Acquisition** panel with the case and device selected.
2. Click **Start Acquisition**. ForensIQ acquires user-accessible files from the device's `/sdcard` storage into the following categories:

   * **Photos** — `DCIM`, `Pictures`
   * **Videos** — `Movies`, `Videos`
   * **Documents** — `Documents`, `Download`
3. Each acquired file is SHA-256 hashed as it is copied locally and recorded as an evidence item with its hash, size, and acquisition timestamp.
4. Acquisition progress is streamed live. The acquisition operation runs on a background thread so the user interface remains responsive.

No root access is used or required. Acquisition is limited to storage the Android device exposes to the authorized debugging host.

---

## 5. Managing Evidence

The **Cases** panel's evidence view lets investigators browse acquired items by category, inspect individual file metadata, and manage evidence associated with the case.

For each evidence item, investigators can review information such as:

* File name and path
* Evidence category
* File size
* SHA-256 hash
* Acquisition timestamp
* Verification status
* Associated case information

Evidence removal operations are audit-logged. Individual evidence items can also be selected for deeper analysis or integrity verification.

---

## 6. Running Analysis

Open the **Analysis** panel with a case selected and choose which analyses to run.

### Timeline

Provides a unified, chronologically sorted view combining filesystem timestamps with acquisition, verification, audit, and custody events.

### Metadata

Extracts and displays file metadata including:

* MIME type
* File size
* SHA-256 hash
* Relevant filesystem timestamps

### App Analysis

Analyses installed applications and classifies them as:

* System
* User
* Disabled
* Sideloaded

The analysis can also identify recently installed applications where the available device information permits this.

### Duplicate Detection

Identifies files sharing the same SHA-256 hash and size, helping investigators identify duplicate evidence items.

### Correlation

Correlates files, applications, audit events, custody events, and verification records to provide a broader view of an evidence item's investigation history.

### Global Search

Provides keyword-based search across evidence, analysis results, timeline events, audit records, and custody events.

Search can use filters including:

* Date range
* Investigator
* File type
* Evidence type
* Verification status

Analysis results are stored in the database, including `analysis_results` and `timeline_events`, so results persist between sessions and can be reused when generating reports.

---

## 7. Verifying Evidence Integrity

Open the **Integrity** panel to verify evidence against its stored acquisition-time SHA-256 hash.

1. Choose whether to verify a single evidence item or the whole case.
2. ForensIQ recomputes the SHA-256 hash for each file.
3. The calculated hash is compared with the stored acquisition hash.
4. Results are classified as:

   * `PASS` — calculated hash matches the stored hash.
   * `FAIL` — calculated hash does not match.
   * `MISSING` — the evidence file is no longer present.
   * `ERROR` — the file could not be read or verified.
5. Each verification run is stored in `verification_results`.
6. Verification activity is also recorded in the audit trail.

This provides a historical verification record rather than only displaying the latest integrity status.

Verification results can be exported directly to JSON or HTML from the Integrity panel.

---

## 8. Reviewing the Audit Trail

The **Audit Trail** panel shows recorded system actions associated with the investigation.

Examples include:

* Case creation
* Case updates
* Status transitions
* Evidence acquisition
* Evidence addition or removal
* Verification operations
* Report generation
* Investigation note changes
* Other important forensic operations

The audit log is append-only. Audit entries cannot be edited or deleted through the application, helping preserve the integrity of the investigation record.

The audit trail can be filtered by available user and action information and exported to JSON or HTML.

---

## 9. Managing Chain of Custody

The **Custody** panel records evidence-handling events for individual evidence items or the investigation.

Custody events can include:

* Collected
* Transferred
* Stored
* Released
* Other supported custody operations

Each custody event can contain information such as investigator, location, timestamp, and notes.

Use **Transfer** to record an evidence handoff.

The complete custody history for an evidence item or case can be reviewed and exported to JSON or HTML.

Custody history is preserved as part of the forensic record even if the underlying case or evidence item is later removed.

---

## 10. Digital Signatures

ForensIQ supports digital signatures for applicable forensic records using **Ed25519-based signing and verification**.

Digital signatures provide an additional authenticity mechanism alongside:

* SHA-256 evidence integrity verification
* Audit logging
* Chain-of-custody tracking

Where signature functionality is available, investigators can use signing and verification operations to validate the authenticity of supported forensic records.

---

## 11. Generating Reports

Open the **Reports** panel, select the case, and choose a report type.

| Report               | Format      | Contents                                              |
| -------------------- | ----------- | ----------------------------------------------------- |
| Full Forensic (HTML) | HTML        | Complete case, device, evidence, and analysis details |
| Full Forensic (PDF)  | PDF         | Complete forensic report formatted for printing       |
| Case Summary         | HTML        | High-level case overview                              |
| Evidence Summary     | HTML        | Evidence inventory with hashes and metadata           |
| Integrity            | HTML        | Verification history and current integrity status     |
| Audit Trail          | HTML        | Filtered or complete audit log                        |
| Chain of Custody     | HTML        | Custody event history                                 |
| Executive            | HTML        | Condensed non-technical investigation summary         |
| Analysis             | JSON + HTML | Detailed analysis engine output                       |

Report generation runs on a background thread.

Once generation is complete, use **Open Last HTML** to immediately view the generated HTML report, or locate the generated report in the selected output path.

Every generated report is recorded in the audit trail.

---

## 12. Ending a Session

Cases, evidence, analysis results, verification history, audit records, custody events, and other investigation data persist in:

```text
~/.forensiq/forensiq.db
```

There is no separate manual save operation.

Investigators can close ForensIQ during an investigation and reopen the application later to continue working with the same case and its stored forensic records.

Forensic data should still be backed up according to the organization's evidence-handling and retention procedures.

---

## 13. Troubleshooting

| Symptom                      | Likely cause                                                        | What to check                                                |
| ---------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------ |
| No devices found on Scan     | ADB not installed/on PATH, or USB debugging disabled                | Run `adb version` and `adb devices`; check Developer Options |
| Device shows `unauthorized`  | USB debugging authorization has not been accepted                   | Unlock the device and accept the USB debugging prompt        |
| Device shows `offline`       | ADB connection is not functioning correctly                         | Reconnect USB, restart ADB, and verify `adb devices`         |
| Acquisition pulls 0 files    | Device locked, inaccessible storage, or no files in target folders  | Unlock the device and verify accessible storage              |
| Verification shows `MISSING` | Evidence file was moved or deleted locally                          | Check the case evidence directory                            |
| Verification shows `FAIL`    | Evidence contents changed after acquisition                         | Compare the current file with the stored acquisition hash    |
| Report generation fails      | Output path is not writable or required dependency is unavailable   | Choose another destination and verify dependencies           |
| `ModuleNotFoundError: PyQt6` | Dependencies are not installed or virtual environment is not active | Activate `venv` and run `pip install -r requirements.txt`    |

For deeper diagnostics, review the **Dashboard** quick statistics and the **Audit Trail**, which records relevant errors and failed operations where applicable.

---

## 14. Evidence Handling and Forensic Use

ForensIQ is designed as a forensic investigation and evidence-management tool.

Investigators should:

* Use only authorized Android devices.
* Maintain appropriate chain-of-custody records.
* Preserve original evidence where required.
* Verify evidence integrity using SHA-256.
* Document important investigation actions.
* Restrict access to forensic case data.
* Follow applicable organizational and legal procedures for digital evidence handling.

ForensIQ does not perform unrestricted physical extraction or bypass Android security controls. Acquisition is limited to data exposed through authorized ADB access.
