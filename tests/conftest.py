"""
Shared fixtures for the ForensIQ test suite.

All tests that need a real database, evidence directory, or a populated
case use the fixtures here rather than setting up their own temp directories,
so the fixture code is only written once and never duplicated.
"""

import json
import os
import tempfile

import pytest

from forensiq.core.case_manager import CaseManager
from forensiq.core.audit_service import AuditService
from forensiq.core.hasher import sha256_file


# ── Low-level fixtures ────────────────────────────────────────────────────────

@pytest.fixture
def tmp_dir(tmp_path):
    """A fresh temporary directory (pytest's built-in tmp_path, re-exported)."""
    return tmp_path


@pytest.fixture
def db(tmp_path):
    """An empty CaseManager backed by a temp SQLite database."""
    return CaseManager(db_path=str(tmp_path / "forensiq_test.db"))


@pytest.fixture
def audit(db):
    """An AuditService bound to the shared test database."""
    return AuditService(db)


# ── Evidence directory fixture ────────────────────────────────────────────────

@pytest.fixture
def ev_dir(tmp_path):
    """
    A temporary evidence directory containing realistic test files:
      - report.txt          — text file (will be duplicated)
      - report_dup.txt      — exact duplicate of report.txt
      - malware.apk         — high-risk extension
      - config.json         — JSON artefact
      - notes.md            — markdown with keywords
      - installed_apps.json — app-analysis input
      - network_info.txt    — Phase 6 network-analysis input (ADBManager.get_network_info() format)
      - battery_info.json   — Phase 6 battery/system-analysis input (BatteryInfo.__dict__ format)
    """
    evd = tmp_path / "evidence"
    evd.mkdir()

    content_a = b"Suspect device forensic evidence keyword data"

    files = {
        "report.txt":        content_a,
        "report_dup.txt":    content_a,           # exact SHA-256 duplicate
        "malware.apk":       b"fake apk payload",
        "config.json":       b'{"event":"login","user":"admin"}',
        "notes.md":          b"# Investigation Notes\nSuspect activity detected",
        "installed_apps.json": json.dumps([
            {"package": "com.android.phone",    "installer": "system",               "enabled": True},
            {"package": "com.android.settings", "installer": "system",               "enabled": True},
            {"package": "com.termux",           "installer": "unknown",              "enabled": True},
            {"package": "com.magisk",           "installer": "unknown",              "enabled": True},
            {"package": "com.example.user",     "installer": "com.android.vending",  "enabled": True},
            {"package": "com.disabled.app",     "installer": "",                     "enabled": False},
        ]).encode(),
        "network_info.txt": (
            "=== IP Addresses ===\n"
            "1: lo: <LOOPBACK,UP>\n"
            "    inet 127.0.0.1/8 scope host lo\n"
            "2: wlan0: <BROADCAST,MULTICAST,UP>\n"
            "    inet 192.168.1.42/24 brd 192.168.1.255 scope global wlan0\n"
            "3: tun0: <POINTOPOINT,UP>\n"
            "    inet 10.8.0.2/24 scope global tun0\n"
            "\n=== WiFi State ===\n"
            "Wi-Fi is enabled\n"
            "SSID: TestNetwork\n"
            "BSSID: aa:bb:cc:dd:ee:ff\n"
        ).encode(),
        "battery_info.json": json.dumps({
            "level": 41, "status": "Discharging", "health": "Good",
            "temperature": 29.5, "voltage": 3987, "plugged": "Unplugged",
            "technology": "Li-ion",
        }).encode(),
    }

    for fname, data in files.items():
        (evd / fname).write_bytes(data)

    return str(evd)


# ── Populated case fixture ────────────────────────────────────────────────────

class _FakeDevice:
    """Minimal device stub for db.add_device()."""
    serial          = "DEV001"
    model           = "Pixel 7"
    manufacturer    = "Google"
    android_version = "13"
    sdk_version     = "33"
    build_number    = "TQ3A"
    cpu_abi         = "arm64-v8a"
    usb_debugging   = True


@pytest.fixture
def populated(db, audit, ev_dir):
    """
    A fully populated test case with:
      - 1 case  (case_number='TC-001')
      - 1 device
      - 3 evidence items (eid_pass: PASS, eid_fail: FAIL, eid_null: no size)
      - 2 verification results (PASS for eid_pass, FAIL for eid_fail)
      - 2 audit events
      - 1 custody event
      - 1 timeline event
      - 1 analysis result

    Returns a namespace with: cid, did, eid_pass, eid_fail, eid_null,
                               h_pass, ev_dir, db, audit
    """
    import types

    cid = db.create_case("TC-001", "Test Case", "Det. Jones", "Integration test case")
    db.update_case(cid, evidence_dir=ev_dir)

    did = db.add_device(cid, _FakeDevice())

    # Evidence with real hash (for PASS verification)
    report_path = os.path.join(ev_dir, "report.txt")
    h_pass = sha256_file(report_path)
    eid_pass = db.add_evidence(
        cid, did, "acquisition", "report.txt", report_path, h_pass, 44, {}
    )

    # Evidence with wrong stored hash (for FAIL verification)
    apk_path = os.path.join(ev_dir, "malware.apk")
    eid_fail = db.add_evidence(
        cid, did, "acquisition", "malware.apk", apk_path, "WRONGHASH" * 4, 17, {}
    )

    # Evidence with NULL file_size (regression guard)
    eid_null = db.add_evidence(
        cid, None, "sms", "messages.db", "/tmp/messages.db", "", None, {}
    )

    # Verification results
    db.add_verification_result(cid, eid_pass, "PASS", h_pass, h_pass, "verified")
    db.add_verification_result(cid, eid_fail, "FAIL", "WRONGHASH" * 4, "actualXXX", "mismatch")

    # Audit events
    audit.log_case_created(cid, "Det. Jones", "TC-001")
    audit.log_evidence_added(cid, eid_pass, "Det. Jones", "report.txt", "acquisition")

    # Custody event
    db.add_custody_event(cid, eid_pass, "Det. Jones", "ACQUIRED", "Lab-A", "initial acquisition")

    # Timeline event
    db.add_timeline_event(
        cid, "file_created", "report.txt created on device",
        "2024-06-01 10:00:00", evidence_id=eid_pass
    )

    # Analysis result
    db.add_analysis_result(cid, eid_pass, "app_classification",
                           "Found 6 apps — 2 suspicious", {"total": 6})

    ns = types.SimpleNamespace(
        cid=cid, did=did,
        eid_pass=eid_pass, eid_fail=eid_fail, eid_null=eid_null,
        h_pass=h_pass, ev_dir=ev_dir,
        db=db, audit=audit,
    )
    return ns
