"""
ADB Manager — wraps ADB shell commands for device communication.
All blocking operations run on background QThreads to keep UI responsive.

FIXES:
  - BUG#1: battery int conversion crashes on empty/non-numeric strings
  - BUG#2: get_installed_apps single-space split contaminated package names
  - BUG#3: pull_user_files double-counted files (full dir rescan after each path)
  - BUG#4: AcquisitionWorker files result now emits file_acquired per pulled file
"""

import subprocess
import json
import os
from dataclasses import dataclass
from typing import Optional
from PyQt6.QtCore import QObject, pyqtSignal, QThread


# ── Data classes ───────────────────────────────────────────────────────────────

@dataclass
class DeviceInfo:
    serial: str
    model: str = "Unknown"
    manufacturer: str = "Unknown"
    android_version: str = "Unknown"
    sdk_version: str = "Unknown"
    build_number: str = "Unknown"
    usb_debugging: bool = False
    cpu_abi: str = "Unknown"


@dataclass
class BatteryInfo:
    level: int = 0
    status: str = "Unknown"
    health: str = "Unknown"
    temperature: float = 0.0
    voltage: int = 0
    plugged: str = "Unknown"
    technology: str = "Unknown"


# ── Helpers ────────────────────────────────────────────────────────────────────

def _safe_int(value, default: int = 0) -> int:
    """Convert to int safely; returns default on empty string or non-numeric."""
    try:
        v = str(value).strip()
        return int(v) if v else default
    except (ValueError, TypeError):
        return default


def _safe_float(value, default: float = 0.0) -> float:
    try:
        v = str(value).strip()
        return float(v) if v else default
    except (ValueError, TypeError):
        return default


# ── Background workers ─────────────────────────────────────────────────────────

class DeviceDetectWorker(QThread):
    finished = pyqtSignal(list)
    error    = pyqtSignal(str)

    def __init__(self, adb: "ADBManager"):
        super().__init__()
        self.adb = adb

    def run(self):
        try:
            serials = self.adb.list_devices()
            result  = [self.adb.get_device_info(s) for s in serials]
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))


class AcquisitionWorker(QThread):
    progress     = pyqtSignal(int, str)       # percent, message
    file_acquired = pyqtSignal(str, str)       # local_path, sha256
    finished     = pyqtSignal(dict)
    error        = pyqtSignal(str)

    def __init__(self, adb: "ADBManager", serial: str,
                 targets: list, output_dir: str):
        super().__init__()
        self.adb        = adb
        self.serial     = serial
        self.targets    = targets
        self.output_dir = output_dir
        self._abort     = False

    def abort(self):
        self._abort = True

    def run(self):
        from forensiq.core.hasher import sha256_file
        results = {}
        total   = len(self.targets)

        for i, target in enumerate(self.targets):
            if self._abort:
                break
            pct = int(i / total * 100)
            self.progress.emit(pct, f"Acquiring: {target} …")

            try:
                if target == "apps":
                    data = self.adb.get_installed_apps(self.serial)
                    path = os.path.join(self.output_dir, "installed_apps.json")
                    with open(path, "w", encoding="utf-8") as f:
                        json.dump(data, f, indent=2)
                    h = sha256_file(path)
                    results["apps"] = {"path": path, "count": len(data), "sha256": h}
                    self.file_acquired.emit(path, h)

                elif target == "processes":
                    data = self.adb.get_running_processes(self.serial)
                    path = os.path.join(self.output_dir, "running_processes.json")
                    with open(path, "w", encoding="utf-8") as f:
                        json.dump(data, f, indent=2)
                    h = sha256_file(path)
                    results["processes"] = {"path": path, "count": len(data), "sha256": h}
                    self.file_acquired.emit(path, h)

                elif target == "battery":
                    data = self.adb.get_battery_info(self.serial)
                    path = os.path.join(self.output_dir, "battery_info.json")
                    with open(path, "w", encoding="utf-8") as f:
                        json.dump(data.__dict__, f, indent=2)
                    h = sha256_file(path)
                    results["battery"] = {"path": path, "sha256": h}
                    self.file_acquired.emit(path, h)

                elif target == "network":
                    data = self.adb.get_network_info(self.serial)
                    path = os.path.join(self.output_dir, "network_info.txt")
                    with open(path, "w", encoding="utf-8") as f:
                        f.write(data)
                    h = sha256_file(path)
                    results["network"] = {"path": path, "sha256": h}
                    self.file_acquired.emit(path, h)

                elif target == "files":
                    self.progress.emit(pct, "Pulling user files (Photos / Videos / Documents)…")
                    pulled = self.adb.pull_user_files(
                        self.serial, self.output_dir,
                        progress_cb=lambda msg: self.progress.emit(-1, msg),
                        file_cb=lambda p, h: self.file_acquired.emit(p, h),
                    )
                    results["files"] = pulled

            except Exception as e:
                self.error.emit(f"Error acquiring '{target}': {e}")

        self.progress.emit(100, "Acquisition complete." if not self._abort else "Acquisition stopped.")
        self.finished.emit(results)


# ── ADB Manager ────────────────────────────────────────────────────────────────

class ADBManager(QObject):
    """Thin wrapper around ADB subprocess calls."""

    def _run(self, args: list, serial: str = None,
             timeout: int = 30) -> tuple[str, str]:
        cmd = ["adb"]
        if serial:
            cmd += ["-s", serial]
        cmd += args
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return r.stdout.strip(), r.stderr.strip()
        except FileNotFoundError:
            raise RuntimeError(
                "ADB not found.\n"
                "Install Android Platform Tools and add adb to your PATH.\n"
                "Download: https://developer.android.com/tools/releases/platform-tools"
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"ADB command timed out after {timeout}s: {' '.join(args)}")

    # ── Device listing ─────────────────────────────────────────────────────────

    def list_devices(self) -> list[str]:
        out, err = self._run(["devices"])
        serials = []
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 2 and parts[1] == "device":
                serials.append(parts[0])
        return serials

    def get_device_info(self, serial: str) -> DeviceInfo:
        def prop(key: str) -> str:
            out, _ = self._run(["shell", "getprop", key], serial)
            return out.strip() or "Unknown"

        usb_out, _ = self._run(
            ["shell", "settings", "get", "global", "adb_enabled"], serial
        )
        return DeviceInfo(
            serial=serial,
            model=prop("ro.product.model"),
            manufacturer=prop("ro.product.manufacturer"),
            android_version=prop("ro.build.version.release"),
            sdk_version=prop("ro.build.version.sdk"),
            build_number=prop("ro.build.display.id"),
            usb_debugging=usb_out.strip() == "1",
            cpu_abi=prop("ro.product.cpu.abi"),
        )

    # ── Phase 2 helpers ────────────────────────────────────────────────────────

    def get_installed_apps(self, serial: str) -> list[dict]:
        """
        Parse `pm list packages -3 -i -f` output.
        FIX: Use whitespace split instead of double-space to avoid package name
             contamination when only a single space separates package from installer.
        """
        out, _ = self._run(["shell", "pm", "list", "packages", "-3", "-i", "-f"], serial)
        apps = []
        for line in out.splitlines():
            line = line.strip()
            if not line.startswith("package:"):
                continue
            # Format: package:/path/to/apk=com.package.name installer=com.installer
            # Split on '=' to get everything after the path
            after_eq = line.split("=", 1)
            if len(after_eq) < 2:
                continue
            rest = after_eq[1]  # "com.package.name installer=com.installer"
            # FIX: split on any whitespace to correctly separate pkg from installer
            parts = rest.split()
            pkg       = parts[0] if parts else ""
            installer = "unknown"
            for part in parts[1:]:
                if part.startswith("installer="):
                    installer = part[len("installer="):].strip() or "unknown"
                    break
            if pkg:
                apps.append({"package": pkg, "installer": installer})
        return apps

    def get_running_processes(self, serial: str) -> list[dict]:
        out, _ = self._run(["shell", "ps", "-A"], serial)
        processes = []
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 5:
                processes.append({
                    "user": parts[0],
                    "pid":  parts[1],
                    "ppid": parts[2] if len(parts) > 2 else "",
                    "name": parts[-1],
                })
        return processes

    def get_battery_info(self, serial: str) -> BatteryInfo:
        """
        FIX: All int/float conversions now use _safe_int/_safe_float to handle
             empty strings and non-numeric values from `dumpsys battery`.
        """
        out, _ = self._run(["shell", "dumpsys", "battery"], serial)
        kv: dict[str, str] = {}
        for line in out.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                kv[k.strip().lower()] = v.strip()

        status_map = {"1": "Unknown", "2": "Charging", "3": "Discharging",
                      "4": "Not charging", "5": "Full"}
        health_map = {"1": "Unknown", "2": "Good", "3": "Overheat",
                      "4": "Dead", "5": "Over voltage", "7": "Cold"}
        plugged_map = {"0": "Unplugged", "1": "AC", "2": "USB", "4": "Wireless"}

        raw_level  = kv.get("level", "0")
        raw_temp   = kv.get("temperature", "0")
        raw_volt   = kv.get("voltage", "0")
        raw_status = kv.get("status", "1")
        raw_health = kv.get("health", "1")
        raw_plugged = kv.get("plugged", "0")

        return BatteryInfo(
            level       = _safe_int(raw_level),
            status      = status_map.get(raw_status, raw_status or "Unknown"),
            health      = health_map.get(raw_health, raw_health or "Unknown"),
            temperature = _safe_int(raw_temp) / 10.0,
            voltage     = _safe_int(raw_volt),
            plugged     = plugged_map.get(raw_plugged, "Unknown"),
            technology  = kv.get("technology", "Unknown"),
        )

    def get_network_info(self, serial: str) -> str:
        ip_out,   _ = self._run(["shell", "ip", "addr"],         serial)
        wifi_out, _ = self._run(["shell", "dumpsys", "wifi"],    serial, timeout=15)

        report  = "=== IP Addresses ===\n"
        report += ip_out + "\n\n"
        report += "=== WiFi State ===\n"
        for line in wifi_out.splitlines():
            if any(k in line.lower() for k in ["ssid", "bssid", "ip address",
                                                 "wi-fi is", "freq"]):
                report += line.rstrip() + "\n"
        return report

    def pull_user_files(self, serial: str, output_dir: str,
                        progress_cb=None, file_cb=None) -> list[dict]:
        """
        FIX: Track existing files before each pull to avoid double-counting.
        Only newly created files are hashed and reported.
        Callbacks:
          progress_cb(msg: str)
          file_cb(local_path: str, sha256: str)
        """
        from forensiq.core.hasher import sha256_file

        categories = {
            "Photos":    ["/sdcard/DCIM", "/sdcard/Pictures"],
            "Videos":    ["/sdcard/Movies", "/sdcard/Videos"],
            "Documents": ["/sdcard/Documents", "/sdcard/Download"],
        }

        pulled: list[dict] = []

        for cat, remote_paths in categories.items():
            cat_dir = os.path.join(output_dir, "files", cat)
            os.makedirs(cat_dir, exist_ok=True)

            for remote_path in remote_paths:
                if progress_cb:
                    progress_cb(f"Pulling {cat} ← {remote_path} …")

                # FIX: snapshot existing files BEFORE pull to detect new ones
                existing = set()
                for root, _, files in os.walk(cat_dir):
                    for fn in files:
                        existing.add(os.path.join(root, fn))

                self._run(["pull", remote_path, cat_dir], serial, timeout=300)

                # Only process files that didn't exist before this pull
                for root, _, files in os.walk(cat_dir):
                    for fname in files:
                        fpath = os.path.join(root, fname)
                        if fpath in existing:
                            continue
                        try:
                            size = os.path.getsize(fpath)
                            h    = sha256_file(fpath)
                            entry = {
                                "category":   cat,
                                "filename":   fname,
                                "local_path": fpath,
                                "size":       size,
                                "sha256":     h,
                            }
                            pulled.append(entry)
                            if file_cb:
                                file_cb(fpath, h)
                        except OSError:
                            pass

        return pulled

    # ── Async wrappers ─────────────────────────────────────────────────────────

    def detect_devices_async(self, on_done, on_error) -> DeviceDetectWorker:
        w = DeviceDetectWorker(self)
        w.finished.connect(on_done)
        w.error.connect(on_error)
        w.start()
        return w

    def acquire_async(self, serial, targets, output_dir,
                      on_progress, on_file, on_done, on_error) -> AcquisitionWorker:
        w = AcquisitionWorker(self, serial, targets, output_dir)
        w.progress.connect(on_progress)
        w.file_acquired.connect(on_file)
        w.finished.connect(on_done)
        w.error.connect(on_error)
        w.start()
        return w
