#!/usr/bin/env bash
# ForensIQ — Release build script (macOS/Linux)
#
# Produces a standalone, single-file executable using PyInstaller.
# This is optional: ForensIQ also runs directly via `python main.py` with
# just requirements.txt installed — this script is only for producing a
# distributable binary that doesn't require an end-user Python install.
#
# Usage:
#   ./scripts/build_release.sh
#
# Output:
#   dist/ForensIQ         (the executable)

set -euo pipefail
cd "$(dirname "$0")/.."

echo "== ForensIQ release build =="

if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 not found on PATH." >&2
    exit 1
fi

echo "-- Installing runtime + build dependencies --"
python3 -m pip install --quiet -r requirements.txt
python3 -m pip install --quiet pyinstaller>=6.0

echo "-- Cleaning previous build artifacts --"
rm -rf build dist ForensIQ.spec

echo "-- Running PyInstaller --"
python3 -m PyInstaller \
    --name "ForensIQ" \
    --windowed \
    --onefile \
    --clean \
    --noconfirm \
    main.py

echo ""
echo "== Build complete =="
echo "Executable: dist/ForensIQ"
echo ""
echo "NOTE: Android Platform Tools (adb) must still be installed separately"
echo "      and on PATH for the packaged app to detect devices."
