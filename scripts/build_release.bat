@echo off
REM ForensIQ — Release build script (Windows)
REM
REM Produces a standalone executable using PyInstaller.
REM This is optional: ForensIQ also runs directly via "python main.py" with
REM just requirements.txt installed — this script is only for producing a
REM distributable .exe that doesn't require an end-user Python install.
REM
REM Usage:
REM   scripts\build_release.bat
REM
REM Output:
REM   dist\ForensIQ.exe

setlocal
cd /d "%~dp0\.."

echo == ForensIQ release build ==

where python >nul 2>nul
if errorlevel 1 (
    echo ERROR: python not found on PATH.
    exit /b 1
)

echo -- Installing runtime + build dependencies --
python -m pip install --quiet -r requirements.txt
python -m pip install --quiet "pyinstaller>=6.0"

echo -- Cleaning previous build artifacts --
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist ForensIQ.spec del /q ForensIQ.spec

echo -- Running PyInstaller --
python -m PyInstaller ^
    --name "ForensIQ" ^
    --windowed ^
    --onefile ^
    --clean ^
    --noconfirm ^
    main.py

echo.
echo == Build complete ==
echo Executable: dist\ForensIQ.exe
echo.
echo NOTE: Android Platform Tools (adb) must still be installed separately
echo       and on PATH for the packaged app to detect devices.

endlocal
