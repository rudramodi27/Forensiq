# ForensIQ — Installation Guide

## 1. Requirements

- **Python 3.11+** (tested on 3.11–3.12)
- **Android Platform Tools (ADB)** installed and available on `PATH`
- A target Android device with **USB debugging** enabled
- OS: Windows, macOS, or Linux (PyQt6-supported platforms)

## 2. Install Python Dependencies

```bash
# 1. Clone or unpack the project, then from forensiq_tool/:
python -m venv venv

# 2. Activate the virtual environment
source venv/bin/activate        # macOS/Linux
venv\Scripts\activate           # Windows (cmd/PowerShell)

# 3. Install dependencies
pip install -r requirements.txt
```

`requirements.txt` installs:

| Package | Purpose |
|---|---|
| `PyQt6>=6.6.0` | GUI framework |
| `reportlab>=4.0.0` | PDF report generation |
| `Pillow>=10.0.0` | Image support used by ReportLab |

`python-magic` is listed as an optional, commented-out dependency for more
accurate MIME type detection during analysis. If it isn't installed,
ForensIQ automatically falls back to Python's standard-library `mimetypes`
module — no functionality is lost, detection is just slightly less precise
for files without a reliable extension. To enable it:

```bash
pip install python-magic          # macOS/Linux
pip install python-magic-bin       # Windows (bundles libmagic)
```

## 3. Install Android Platform Tools (ADB)

1. Download Platform Tools for your OS:
   https://developer.android.com/tools/releases/platform-tools
2. Unzip it somewhere permanent (e.g. `C:\platform-tools`,
   `~/platform-tools`).
3. Add that folder to your system `PATH`:
   - **Windows:** System Properties → Environment Variables → edit `Path` →
     add the `platform-tools` folder → restart your terminal.
   - **macOS/Linux:** add `export PATH="$PATH:/path/to/platform-tools"` to
     your shell profile (`~/.zshrc`, `~/.bashrc`, etc.) and reload it.
4. Verify:
   ```bash
   adb version
   ```
   This should print an Android Debug Bridge version string. If it doesn't,
   ADB is not correctly on `PATH` — re-check step 3 before launching
   ForensIQ.

## 4. Prepare the Target Device

1. On the Android device: **Settings → About phone** → tap **Build number**
   seven times to unlock Developer Options.
2. **Settings → Developer options** → enable **USB debugging**.
3. Connect the device via USB.
4. When prompted on the device, **Allow USB debugging** for this computer
   (optionally check "Always allow from this computer").
5. Confirm the device is visible:
   ```bash
   adb devices
   ```
   The serial should appear with state `device` (not `unauthorized` or
   `offline`).

## 5. Run ForensIQ

```bash
python main.py
```

`main.py` sets HiDPI scaling flags before creating the `QApplication`, so no
extra environment variables are required on most systems for crisp
rendering on 4K/Retina displays.

## 6. First-Run Behavior

- On first launch, ForensIQ creates `~/.forensiq/` and initializes
  `forensiq.db` with the full schema (see `DATABASE_SCHEMA.md`).
- On every launch (including subsequent ones), ForensIQ runs its migration
  check automatically — this is safe to run against a fresh database or an
  existing one from a prior version.
- No manual database setup or seeding is required.

## 7. Running the Test Suite (Optional, for Verification)

```bash
pip install pytest
python -m pytest
```

On headless Linux systems (CI, containers, servers without a display), set:

```bash
export QT_QPA_PLATFORM=offscreen
python -m pytest
```

`pytest.ini` is preconfigured to discover tests under `tests/`.

## 8. Troubleshooting

| Symptom | Fix |
|---|---|
| `ModuleNotFoundError: PyQt6` | Virtual environment not activated, or `pip install -r requirements.txt` not run |
| `adb: command not found` | Platform Tools not on `PATH` — see §3 |
| Device shows `unauthorized` in `adb devices` | Re-check the device screen for the USB debugging permission prompt; revoke and re-pair if needed |
| App window looks blurry on HiDPI display | Ensure you're on a recent PyQt6 (`>=6.6.0`); no extra config should be needed |
| PDF report generation fails on a minimal Linux install | Confirm `reportlab` and `Pillow` installed correctly (`pip show reportlab Pillow`) |
