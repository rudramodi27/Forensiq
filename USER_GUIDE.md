# ForensIQ — User Guide

This guide walks through a typical investigation from opening the
application to generating a final report. For install steps, see
`INSTALLATION.md`. For database internals, see `DATABASE_SCHEMA.md`.

## 1. Application Layout

ForensIQ opens on the **Dashboard**, with a sidebar on the left for
navigation:

| Sidebar item | Purpose |
|---|---|
| ⌂ Dashboard | Overview, quick stats, recent cases |
| ⎙ Device | Connect and identify an Android device |
| ↓ Acquisition | Pull evidence from the device |
| ◉ Cases | Create, open, and manage investigation cases |
| ⊕ Analysis | Run timeline, metadata, app, duplicate, and correlation analysis |
| ▤ Reports | Generate PDF/HTML reports |
| ⊞ Integrity | Verify SHA-256 hashes of acquired evidence |
| ≡ Audit Trail | Review the immutable system audit log |
| ⛓ Custody | Record and export chain-of-custody events |

The header bar shows the active case number and investigator once a case is
opened, so it's always visible which case subsequent actions apply to.

## 2. Starting a Case

1. Open the **Cases** panel and click **New Case**.
2. Fill in the case number (must be unique), title, investigator, and an
   optional description/notes.
3. Optionally set an evidence directory — if left blank, ForensIQ creates one
   for you.
4. Save. The case now appears in the case list and becomes selectable across
   every other panel.

Editing a case later (title, investigator, description, evidence directory)
and changing its status are both available from the Cases panel; both are
recorded in the audit trail.

## 3. Connecting and Identifying a Device

1. Enable **USB debugging** on the Android device (Settings → Developer
   Options) and connect it via USB.
2. Open the **Device** panel and click **Scan**. ForensIQ lists all devices
   visible to `adb`.
3. Select a device to view its profile: model, manufacturer, Android/SDK
   version, build number, CPU ABI, USB debugging status, battery, and network
   info.
4. The device record is saved against the active case once identified.

If no devices appear, verify `adb devices` shows the device from a terminal
first — this isolates whether the issue is ADB setup or the device
connection itself (see `INSTALLATION.md` for ADB setup).

## 4. Acquiring Evidence

1. Open the **Acquisition** panel with the case and device selected.
2. Click **Start Acquisition**. ForensIQ pulls user-accessible files from
   the device's `/sdcard` storage into three categories:
   - **Photos** — `DCIM`, `Pictures`
   - **Videos** — `Movies`, `Videos`
   - **Documents** — `Documents`, `Download`
3. Each file is SHA-256 hashed as it lands locally and recorded as an
   `evidence` row with its hash, size, and acquisition timestamp.
4. Progress is streamed live; acquisition runs on a background thread so the
   UI stays responsive and can be safely left running.

No root access is used or required — acquisition is limited to storage the
device already exposes to a debugging host.

## 5. Managing Evidence

The **Cases** panel's evidence view lets you browse acquired items by
category, inspect individual file metadata, and remove items if needed
(removal is also audit-logged). This is also where you can jump into deeper
analysis or verification for a specific item.

## 6. Running Analysis

Open the **Analysis** panel with a case selected and choose which analyses to
run:

- **Timeline** — a unified, chronologically sorted view combining filesystem
  timestamps with acquisition, verification, audit, and custody events.
- **Metadata** — MIME type, size, SHA-256, and timestamps per file.
- **App Analysis** — classifies installed apps as system, user, disabled, or
  sideloaded, and flags recently installed apps.
- **Duplicate Detection** — finds files sharing both SHA-256 and size.
- **Correlation** — links files, apps, audit events, custody events, and
  verification records together for a holistic view of an item's history.
- **Global Search** — keyword search across evidence, analysis results,
  timeline, audit trail, and custody events, with filters for date range,
  investigator, file type, evidence type, and verification status.

Results are stored in the database (`analysis_results`, `timeline_events`) so
they persist between sessions and can be reused when generating an Analysis
Report.

## 7. Verifying Integrity

Open the **Integrity** panel to re-verify evidence against its
acquisition-time hash:

1. Choose to verify a single item or the whole case.
2. ForensIQ re-computes SHA-256 for each file and compares it to the stored
   hash, classifying the result as `PASS`, `FAIL`, `MISSING` (file no longer
   present), or `ERROR` (couldn't be read).
3. Every verification run is saved to `verification_results` and mirrored
   into the audit trail, so you can see a full pass/fail history per item,
   not just the latest result.
4. Results can be exported directly to JSON or HTML from this panel.

## 8. Reviewing the Audit Trail

The **Audit Trail** panel shows every logged system action — case creation,
evidence added/removed, verification runs, report generation, notes
edits, and more — filterable by user and action type. This log is
append-only: there is no way, in the UI or the underlying API, to edit or
delete an audit entry, which is intentional for evidentiary integrity.
Export to JSON or HTML is available directly from the panel.

## 9. Managing Chain of Custody

The **Custody** panel records custody events (collected, transferred, stored,
released, etc.) per evidence item, including investigator, location, and
notes. Use **Transfer** to log a custody handoff. The full custody chain for
a given evidence item, or for the whole case, can be viewed and exported to
JSON/HTML — custody history is preserved even if the underlying case or
evidence item is later deleted.

## 10. Generating Reports

Open the **Reports** panel, select the case, and choose a report type:

| Report | Format | Contents |
|---|---|---|
| Full Forensic (HTML) | HTML | Complete case, device, evidence, analysis detail |
| Full Forensic (PDF) | PDF | Same content as above, paginated for printing |
| Case Summary | HTML | High-level case overview |
| Evidence Summary | HTML | Evidence inventory with hashes and metadata |
| Integrity | HTML | Verification history and current pass/fail status |
| Audit Trail | HTML | Filtered/full audit log |
| Chain of Custody | HTML | Custody event history |
| Executive | HTML | Condensed, non-technical summary for stakeholders |
| Analysis | JSON + HTML | Full analysis engine output |

Report generation runs on a background thread; once finished, use
**Open Last HTML** to view the result immediately, or find the file in the
path you selected. Every report generated is logged to the audit trail.

## 11. Ending a Session

Cases, evidence, analysis results, verification history, audit trail, and
custody events all persist in `~/.forensiq/forensiq.db` between sessions —
there's no explicit "save" step. You can safely close ForensIQ mid-analysis
and reopen the same case later to continue.

## 12. Troubleshooting

| Symptom | Likely cause | What to check |
|---|---|---|
| No devices found on Scan | ADB not installed/on PATH, or USB debugging off | `adb version`, `adb devices`, device's Developer Options |
| Acquisition pulls 0 files | Device locked, or no files in the target folders | Unlock the device before acquiring |
| Verification shows MISSING | Evidence file moved/deleted from its local path | Check the case's evidence directory on disk |
| Report generation fails | Output path not writable | Choose a different destination folder |

For deeper diagnostics, see the **Dashboard**'s quick stats and the
**Audit Trail**, which will show `ERROR` results for failed operations where
applicable.
