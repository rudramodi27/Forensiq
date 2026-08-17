"""
Unit + integration tests — Phase 3: Device Acquisition Accuracy.

Covers:
  - device identity stays a single row per (case_id, serial) even across
    many acquisition sessions
  - acquisition_sessions: creation, closing, status validation
  - same device -> multiple sessions; different devices -> separate rows
  - stable device identity (no new identity generated per connection)
  - first_connected / last_connected tracking
  - device snapshot capture + preservation across later sessions
  - session <-> evidence association
  - HTML / PDF report render each device once with sessions nested under it
  - safe migration of a pre-Phase-3 database (no invented sessions,
    no data loss)
  - all existing Phase 1 + Phase 2 behavior untouched
"""

import json
import os
import sqlite3

import pytest

from forensiq.core.case_manager import CaseManager, now_utc
from forensiq.core.reporter import generate_html_report, generate_pdf_report


class _FakeDevice:
    def __init__(self, serial="DEV001", model="Pixel 7", manufacturer="Google",
                 android_version="13", sdk_version="33", build_number="TQ3A",
                 cpu_abi="arm64-v8a", usb_debugging=True):
        self.serial = serial
        self.model = model
        self.manufacturer = manufacturer
        self.android_version = android_version
        self.sdk_version = sdk_version
        self.build_number = build_number
        self.cpu_abi = cpu_abi
        self.usb_debugging = usb_debugging


# ── Schema ───────────────────────────────────────────────────────────────────

class TestPhase3Schema:
    def test_acquisition_sessions_table_exists(self, db):
        with db._connect() as c:
            tables = {r[0] for r in c.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()}
        assert "acquisition_sessions" in tables

    def test_devices_has_first_last_connected_columns(self, db):
        with db._connect() as c:
            cols = {r["name"] for r in c.execute("PRAGMA table_info(devices)").fetchall()}
        assert "first_connected" in cols
        assert "last_connected" in cols

    def test_evidence_has_session_id_column(self, db):
        with db._connect() as c:
            cols = {r["name"] for r in c.execute("PRAGMA table_info(evidence)").fetchall()}
        assert "session_id" in cols

    def test_session_indexes_present(self, db):
        with db._connect() as c:
            idxs = {r[0] for r in c.execute(
                "SELECT name FROM sqlite_master WHERE type='index'"
            ).fetchall()}
        assert "idx_sessions_case" in idxs
        assert "idx_sessions_device" in idxs


# ── Device identity (stable across connections) ────────────────────────────

class TestDeviceIdentityStability:
    def test_same_device_one_device_record(self, db):
        """Re-registering the same physical device across many acquisition
        runs must never create a second devices row."""
        cid = db.create_case("P3-001", "T", "I", "")
        dev = _FakeDevice(serial="STABLE-001")

        id1 = db.add_device(cid, dev)
        id2 = db.add_device(cid, dev)
        id3 = db.add_device(cid, dev)

        assert id1 == id2 == id3
        devices = db.get_devices_for_case(cid)
        assert len(devices) == 1

    def test_different_devices_separate_records(self, db):
        cid = db.create_case("P3-002", "T", "I", "")
        idA = db.add_device(cid, _FakeDevice(serial="A-SERIAL"))
        idB = db.add_device(cid, _FakeDevice(serial="B-SERIAL"))
        assert idA != idB
        devices = db.get_devices_for_case(cid)
        assert len(devices) == 2
        assert {d["serial"] for d in devices} == {"A-SERIAL", "B-SERIAL"}

    def test_identity_not_regenerated_per_connection(self, db):
        """No new identity should be minted on repeat connections — the
        device id returned must be identical every time, not merely
        equivalent."""
        cid = db.create_case("P3-003", "T", "I", "")
        dev = _FakeDevice(serial="SAME-ID")
        ids = [db.add_device(cid, dev) for _ in range(5)]
        assert len(set(ids)) == 1


# ── first_connected / last_connected ────────────────────────────────────────

class TestConnectionTimestamps:
    def test_first_connected_set_on_first_registration(self, db):
        cid = db.create_case("P3-010", "T", "I", "")
        did = db.add_device(cid, _FakeDevice(serial="TS-001"))
        d = db.get_device(did)
        assert d["first_connected"]

    def test_first_connected_not_overwritten_on_reconnect(self, db):
        cid = db.create_case("P3-011", "T", "I", "")
        dev = _FakeDevice(serial="TS-002")
        did = db.add_device(cid, dev)
        first = db.get_device(did)["first_connected"]

        # Force a distinguishable timestamp for the second connection.
        with db._connect() as conn:
            conn.execute(
                "UPDATE devices SET first_connected = ?, last_connected = ? WHERE id = ?",
                ("2020-01-01 00:00:00 UTC", "2020-01-01 00:00:00 UTC", did),
            )
        db.add_device(cid, dev)  # second connection
        d = db.get_device(did)
        assert d["first_connected"] == "2020-01-01 00:00:00 UTC"
        assert d["last_connected"] != "2020-01-01 00:00:00 UTC"

    def test_last_connected_refreshes_on_each_registration(self, db):
        cid = db.create_case("P3-012", "T", "I", "")
        dev = _FakeDevice(serial="TS-003")
        did = db.add_device(cid, dev)
        with db._connect() as conn:
            conn.execute(
                "UPDATE devices SET last_connected = ? WHERE id = ?",
                ("2020-01-01 00:00:00 UTC", did),
            )
        db.add_device(cid, dev)
        d = db.get_device(did)
        assert d["last_connected"] != "2020-01-01 00:00:00 UTC"


# ── Acquisition sessions ─────────────────────────────────────────────────────

class TestAcquisitionSessions:
    def test_start_session_creates_row(self, db):
        cid = db.create_case("P3-020", "T", "I", "")
        did = db.add_device(cid, _FakeDevice(serial="SESS-001"))
        sid = db.start_acquisition_session(cid, did, targets=["files"])
        session = db.get_session(sid)
        assert session is not None
        assert session["status"] == "in_progress"
        assert session["device_id"] == did
        assert session["case_id"] == cid
        assert session["end_time"] is None

    def test_same_device_multiple_sessions(self, db):
        """Same device + multiple acquisitions = ONE device + MULTIPLE
        sessions — the core Phase 3 requirement."""
        cid = db.create_case("P3-021", "T", "I", "")
        dev = _FakeDevice(serial="SESS-002")
        did1 = db.add_device(cid, dev)
        s1 = db.start_acquisition_session(cid, did1, targets=["apps"])
        db.end_acquisition_session(s1, status="completed")

        did2 = db.add_device(cid, dev)  # second connection, same physical device
        s2 = db.start_acquisition_session(cid, did2, targets=["files"])
        db.end_acquisition_session(s2, status="completed")

        did3 = db.add_device(cid, dev)  # third connection
        s3 = db.start_acquisition_session(cid, did3, targets=["battery"])

        assert did1 == did2 == did3  # still one device
        devices = db.get_devices_for_case(cid)
        assert len(devices) == 1

        sessions = db.get_sessions_for_device(did1)
        assert len(sessions) == 3
        assert {s["id"] for s in sessions} == {s1, s2, s3}

    def test_different_devices_separate_session_sets(self, db):
        cid = db.create_case("P3-022", "T", "I", "")
        didA = db.add_device(cid, _FakeDevice(serial="MULTI-A"))
        didB = db.add_device(cid, _FakeDevice(serial="MULTI-B"))
        sA = db.start_acquisition_session(cid, didA, targets=["apps"])
        sB1 = db.start_acquisition_session(cid, didB, targets=["files"])
        sB2 = db.start_acquisition_session(cid, didB, targets=["network"])

        assert len(db.get_sessions_for_device(didA)) == 1
        assert len(db.get_sessions_for_device(didB)) == 2
        assert {s["id"] for s in db.get_sessions_for_device(didB)} == {sB1, sB2}

    def test_end_session_sets_end_time_and_status(self, db):
        cid = db.create_case("P3-023", "T", "I", "")
        did = db.add_device(cid, _FakeDevice(serial="END-001"))
        sid = db.start_acquisition_session(cid, did)
        db.end_acquisition_session(sid, status="completed")
        session = db.get_session(sid)
        assert session["status"] == "completed"
        assert session["end_time"]

    def test_end_session_rejects_invalid_status(self, db):
        cid = db.create_case("P3-024", "T", "I", "")
        did = db.add_device(cid, _FakeDevice(serial="END-002"))
        sid = db.start_acquisition_session(cid, did)
        with pytest.raises(ValueError):
            db.end_acquisition_session(sid, status="bogus")

    def test_end_session_rejects_in_progress_as_terminal_status(self, db):
        cid = db.create_case("P3-025", "T", "I", "")
        did = db.add_device(cid, _FakeDevice(serial="END-003"))
        sid = db.start_acquisition_session(cid, did)
        with pytest.raises(ValueError):
            db.end_acquisition_session(sid, status="in_progress")

    def test_aborted_status_supported(self, db):
        cid = db.create_case("P3-026", "T", "I", "")
        did = db.add_device(cid, _FakeDevice(serial="END-004"))
        sid = db.start_acquisition_session(cid, did)
        db.end_acquisition_session(sid, status="aborted")
        assert db.get_session(sid)["status"] == "aborted"

    def test_get_sessions_for_case(self, db):
        cid = db.create_case("P3-027", "T", "I", "")
        didA = db.add_device(cid, _FakeDevice(serial="CASE-A"))
        didB = db.add_device(cid, _FakeDevice(serial="CASE-B"))
        db.start_acquisition_session(cid, didA)
        db.start_acquisition_session(cid, didB)
        db.start_acquisition_session(cid, didB)
        assert len(db.get_sessions_for_case(cid)) == 3

    def test_session_starting_updates_last_connected(self, db):
        cid = db.create_case("P3-028", "T", "I", "")
        did = db.add_device(cid, _FakeDevice(serial="LC-001"))
        with db._connect() as conn:
            conn.execute(
                "UPDATE devices SET last_connected = ? WHERE id = ?",
                ("2020-01-01 00:00:00 UTC", did),
            )
        db.start_acquisition_session(cid, did)
        assert db.get_device(did)["last_connected"] != "2020-01-01 00:00:00 UTC"


# ── Device snapshot ──────────────────────────────────────────────────────────

class TestDeviceSnapshot:
    def test_snapshot_stored_as_json(self, db):
        cid = db.create_case("P3-030", "T", "I", "")
        did = db.add_device(cid, _FakeDevice(serial="SNAP-001"))
        snapshot = {
            "serial": "SNAP-001", "model": "Pixel 7", "manufacturer": "Google",
            "android_version": "13", "sdk_version": "33",
            "build_number": "TQ3A", "cpu_abi": "arm64-v8a",
            "usb_debugging": True,
        }
        sid = db.start_acquisition_session(cid, did, device_snapshot=snapshot)
        session = db.get_session(sid)
        stored = json.loads(session["device_snapshot"])
        assert stored == snapshot

    def test_snapshot_preserved_after_device_row_changes(self, db):
        """A session's snapshot is a point-in-time record: it must not
        change even if the device row is later refreshed by a subsequent
        acquisition (e.g. an OS update between two connections)."""
        cid = db.create_case("P3-031", "T", "I", "")
        dev_old = _FakeDevice(serial="SNAP-002", android_version="13", build_number="OLD")
        did = db.add_device(cid, dev_old)
        s1 = db.start_acquisition_session(
            cid, did, device_snapshot={"android_version": "13", "build_number": "OLD"}
        )

        # Simulate an OS update before the next connection.
        dev_new = _FakeDevice(serial="SNAP-002", android_version="14", build_number="NEW")
        db.add_device(cid, dev_new)  # refreshes devices row, same device id
        s2 = db.start_acquisition_session(
            cid, did, device_snapshot={"android_version": "14", "build_number": "NEW"}
        )

        snap1 = json.loads(db.get_session(s1)["device_snapshot"])
        snap2 = json.loads(db.get_session(s2)["device_snapshot"])
        assert snap1["build_number"] == "OLD"
        assert snap2["build_number"] == "NEW"
        # Current device row reflects the latest state, not session 1's.
        assert db.get_device(did)["build_number"] == "NEW"

    def test_missing_snapshot_defaults_to_empty_object(self, db):
        cid = db.create_case("P3-032", "T", "I", "")
        did = db.add_device(cid, _FakeDevice(serial="SNAP-003"))
        sid = db.start_acquisition_session(cid, did)
        assert json.loads(db.get_session(sid)["device_snapshot"]) == {}


# ── Session <-> evidence association ────────────────────────────────────────

class TestSessionEvidenceAssociation:
    def test_evidence_linked_to_session(self, db):
        cid = db.create_case("P3-040", "T", "I", "")
        did = db.add_device(cid, _FakeDevice(serial="EV-001"))
        sid = db.start_acquisition_session(cid, did, targets=["files"])
        eid = db.add_evidence(
            cid, did, "Photos", "img.jpg", "/tmp/img.jpg", "a" * 64, 100, {},
            session_id=sid,
        )
        ev = db.get_evidence_for_session(sid)
        assert len(ev) == 1
        assert ev[0]["id"] == eid

    def test_evidence_from_different_sessions_not_mixed(self, db):
        cid = db.create_case("P3-041", "T", "I", "")
        did = db.add_device(cid, _FakeDevice(serial="EV-002"))
        s1 = db.start_acquisition_session(cid, did)
        s2 = db.start_acquisition_session(cid, did)
        db.add_evidence(cid, did, "Photos", "a.jpg", "/tmp/a.jpg", "a" * 64, 1, {}, session_id=s1)
        db.add_evidence(cid, did, "Photos", "b.jpg", "/tmp/b.jpg", "b" * 64, 1, {}, session_id=s2)
        db.add_evidence(cid, did, "Photos", "c.jpg", "/tmp/c.jpg", "c" * 64, 1, {}, session_id=s2)

        assert len(db.get_evidence_for_session(s1)) == 1
        assert len(db.get_evidence_for_session(s2)) == 2

    def test_evidence_without_session_id_still_works(self, db):
        """Backward compatibility: session_id is optional and existing
        callers that don't pass it must not break."""
        cid = db.create_case("P3-042", "T", "I", "")
        eid = db.add_evidence(cid, None, "acquisition", "f.bin", "/tmp/f.bin", "a" * 64, 0, {})
        assert eid is not None
        # No crash, and this evidence simply has no session association.
        row = db.get_evidence_for_case(cid)[0]
        assert row["session_id"] is None

    def test_deleting_session_sets_evidence_session_id_null_not_deleting_evidence(self, db):
        cid = db.create_case("P3-043", "T", "I", "")
        did = db.add_device(cid, _FakeDevice(serial="EV-003"))
        sid = db.start_acquisition_session(cid, did)
        eid = db.add_evidence(
            cid, did, "Photos", "x.jpg", "/tmp/x.jpg", "a" * 64, 1, {}, session_id=sid
        )
        with db._connect() as conn:
            conn.execute("DELETE FROM acquisition_sessions WHERE id = ?", (sid,))
        ev = db.get_evidence_for_case(cid)
        assert len(ev) == 1
        assert ev[0]["id"] == eid
        assert ev[0]["session_id"] is None  # ON DELETE SET NULL, not cascaded


# ── Report rendering: device shown once, sessions nested underneath ────────

class TestReportDeviceSessionTree:
    def _case_with_sessions(self, db, ev_dir):
        cid = db.create_case("P3-050", "Session Report Test", "Det. Jones", "")
        did = db.add_device(cid, _FakeDevice(serial="RPT-001"))
        s1 = db.start_acquisition_session(cid, did, targets=["apps"])
        db.end_acquisition_session(s1, status="completed")
        s2 = db.start_acquisition_session(cid, did, targets=["files"])
        db.end_acquisition_session(s2, status="completed")
        s3 = db.start_acquisition_session(cid, did, targets=["battery"])
        return cid, did, [s1, s2, s3]

    def test_html_report_shows_device_once(self, db, tmp_path):
        cid, did, sessions = self._case_with_sessions(db, tmp_path)
        p = str(tmp_path / "r.html")
        generate_html_report(cid, db, p)
        html = open(p).read()
        assert html.count("RPT-001") == 1

    def test_html_report_lists_all_sessions(self, db, tmp_path):
        cid, did, sessions = self._case_with_sessions(db, tmp_path)
        p = str(tmp_path / "r.html")
        generate_html_report(cid, db, p)
        html = open(p).read()
        for sid in sessions:
            assert f"Session {sid}" in html

    def test_html_report_shows_session_header(self, db, tmp_path):
        cid, did, sessions = self._case_with_sessions(db, tmp_path)
        p = str(tmp_path / "r.html")
        generate_html_report(cid, db, p)
        html = open(p).read()
        assert "Acquisition Sessions" in html

    def test_html_report_no_sessions_graceful(self, db, tmp_path):
        """A device with no sessions (e.g. migrated from a pre-Phase-3
        database) must render gracefully, without fabricating any."""
        cid = db.create_case("P3-051", "T", "I", "")
        db.add_device(cid, _FakeDevice(serial="NOSESS-001"))
        p = str(tmp_path / "r.html")
        generate_html_report(cid, db, p)
        html = open(p).read()
        assert "No acquisition sessions recorded" in html

    def test_pdf_report_builds_with_sessions(self, db, tmp_path):
        cid, did, sessions = self._case_with_sessions(db, tmp_path)
        p = str(tmp_path / "r.pdf")
        generate_pdf_report(cid, db, p)
        assert os.path.exists(p)
        assert open(p, "rb").read(4) == b"%PDF"

    def test_pdf_report_no_sessions_graceful(self, db, tmp_path):
        cid = db.create_case("P3-052", "T", "I", "")
        db.add_device(cid, _FakeDevice(serial="NOSESS-002"))
        p = str(tmp_path / "r.pdf")
        generate_pdf_report(cid, db, p)
        assert os.path.exists(p)
        assert os.path.getsize(p) > 500

    def test_multi_device_report_each_device_once(self, db, tmp_path):
        """Regression guard for the exact bug in the Phase 3 brief:
        Device / Device / Device must become Device -> sessions, for
        every device in a multi-device case."""
        cid = db.create_case("P3-053", "Multi", "I", "")
        didA = db.add_device(cid, _FakeDevice(serial="MULTI-DEV-A"))
        didB = db.add_device(cid, _FakeDevice(serial="MULTI-DEV-B"))
        for _ in range(3):
            db.add_device(cid, _FakeDevice(serial="MULTI-DEV-A"))  # 3 more "runs"
            sid = db.start_acquisition_session(cid, didA)
            db.end_acquisition_session(sid)
        sid = db.start_acquisition_session(cid, didB)
        db.end_acquisition_session(sid)

        p = str(tmp_path / "r.html")
        generate_html_report(cid, db, p)
        html = open(p).read()
        assert html.count("MULTI-DEV-A") == 1
        assert html.count("MULTI-DEV-B") == 1
        assert "Acquisition Sessions (3)" in html
        assert "Acquisition Sessions (1)" in html


# ── Migration safety ─────────────────────────────────────────────────────────

class TestPhase3Migration:
    def test_migration_idempotent(self, db):
        db._run_migrations()
        db._run_migrations()

    def test_reopening_legacy_db_preserves_existing_data(self, tmp_path):
        """Simulate a pre-Phase-3 database (created before
        acquisition_sessions / first_connected / last_connected /
        session_id existed) and confirm CaseManager migrates it safely
        without deleting evidence, audit, custody, or integrity history,
        and without inventing sessions."""
        db_path = tmp_path / "legacy.db"

        # Build a pre-Phase-3-shaped DB by hand.
        conn = sqlite3.connect(str(db_path))
        conn.executescript("""
            CREATE TABLE cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_number TEXT UNIQUE NOT NULL, title TEXT NOT NULL,
                investigator TEXT NOT NULL, description TEXT DEFAULT '',
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active', notes TEXT DEFAULT '',
                evidence_dir TEXT DEFAULT ''
            );
            CREATE TABLE devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL, serial TEXT NOT NULL,
                model TEXT DEFAULT 'Unknown', manufacturer TEXT DEFAULT 'Unknown',
                android_version TEXT DEFAULT 'Unknown', sdk_version TEXT DEFAULT 'Unknown',
                build_number TEXT DEFAULT 'Unknown', cpu_abi TEXT DEFAULT 'Unknown',
                usb_debugging INTEGER NOT NULL DEFAULT 0, acquired_at TEXT NOT NULL
            );
            CREATE TABLE evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL, device_id INTEGER,
                category TEXT NOT NULL, filename TEXT DEFAULT '',
                filepath TEXT DEFAULT '', sha256 TEXT DEFAULT '',
                acquired_at TEXT NOT NULL, metadata TEXT NOT NULL DEFAULT '{}'
            );
            CREATE TABLE audit_trail (
                id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,
                user TEXT NOT NULL DEFAULT '', action TEXT NOT NULL,
                target_type TEXT NOT NULL DEFAULT '', target_id TEXT NOT NULL DEFAULT '',
                result TEXT NOT NULL DEFAULT 'OK', notes TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE custody_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER,
                evidence_id INTEGER, timestamp TEXT NOT NULL,
                investigator TEXT NOT NULL DEFAULT '', action TEXT NOT NULL,
                location TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE verification_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER NOT NULL,
                evidence_id INTEGER, verification_time TEXT NOT NULL,
                result TEXT NOT NULL, stored_hash TEXT NOT NULL DEFAULT '',
                current_hash TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT ''
            );
        """)
        conn.execute(
            "INSERT INTO cases (id, case_number, title, investigator, created_at, updated_at) "
            "VALUES (1, 'LEGACY-001', 'Legacy Case', 'Det. Old', '2019-01-01 00:00:00 UTC', "
            "'2019-01-01 00:00:00 UTC')"
        )
        conn.execute(
            "INSERT INTO devices (id, case_id, serial, model, acquired_at) "
            "VALUES (1, 1, 'LEGACY-SERIAL', 'Old Phone', '2019-01-01 00:00:00 UTC')"
        )
        conn.execute(
            "INSERT INTO evidence (id, case_id, device_id, category, filename, "
            "filepath, sha256, acquired_at) VALUES "
            "(1, 1, 1, 'Photos', 'old.jpg', '/legacy/old.jpg', 'deadbeef', "
            "'2019-01-01 00:00:00 UTC')"
        )
        conn.execute(
            "INSERT INTO audit_trail (id, timestamp, user, action, target_type, target_id) "
            "VALUES (1, '2019-01-01 00:00:00 UTC', 'Det. Old', 'CASE_CREATED', 'case', '1')"
        )
        conn.execute(
            "INSERT INTO custody_events (id, case_id, evidence_id, timestamp, "
            "investigator, action) VALUES "
            "(1, 1, 1, '2019-01-01 00:00:00 UTC', 'Det. Old', 'ACQUIRED')"
        )
        conn.execute(
            "INSERT INTO verification_results (id, case_id, evidence_id, "
            "verification_time, result, stored_hash, current_hash) VALUES "
            "(1, 1, 1, '2019-01-02 00:00:00 UTC', 'PASS', 'deadbeef', 'deadbeef')"
        )
        conn.commit()
        conn.close()

        # Now open it with the current (Phase 3) CaseManager — this must
        # run migrations safely, in place.
        db = CaseManager(db_path=str(db_path))

        # Old data must survive, untouched.
        case = db.get_case(1)
        assert case["case_number"] == "LEGACY-001"
        devices = db.get_devices_for_case(1)
        assert len(devices) == 1
        assert devices[0]["serial"] == "LEGACY-SERIAL"
        evidence = db.get_evidence_for_case(1)
        assert len(evidence) == 1
        assert evidence[0]["sha256"] == "deadbeef"
        audit = db.get_audit_trail()
        assert len(audit) == 1
        custody = db.get_custody_events(case_id=1)
        assert len(list(custody)) == 1
        verification = db.get_verification_history(case_id=1)
        assert len(verification) == 1

        # New Phase 3 columns exist and are backfilled from acquired_at
        # (not invented) rather than left blank.
        dev = devices[0]
        assert dev["first_connected"] == "2019-01-01 00:00:00 UTC"
        assert dev["last_connected"] == "2019-01-01 00:00:00 UTC"

        # No sessions were fabricated for this pre-Phase-3 device.
        assert db.get_sessions_for_device(dev["id"]) == []

        # evidence.session_id exists and is NULL for legacy evidence.
        assert evidence[0]["session_id"] is None

        # The DB now supports starting a brand-new session against the
        # legacy device without creating a duplicate device row.
        sid = db.start_acquisition_session(1, dev["id"], targets=["files"])
        assert db.get_session(sid) is not None
        assert len(db.get_devices_for_case(1)) == 1  # still one device

    def test_migrations_idempotent_after_legacy_upgrade(self, db):
        db._run_migrations()
        db._run_migrations()
        db._run_migrations()
        with db._connect() as c:
            cols = {r["name"] for r in c.execute("PRAGMA table_info(devices)").fetchall()}
        assert "first_connected" in cols


# ── Existing Phase 1 + Phase 2 behavior must be untouched ──────────────────

class TestPhase1And2Untouched:
    def test_device_dedup_still_works(self, db):
        cid = db.create_case("REG-001", "T", "I", "")
        dev = _FakeDevice(serial="REG-SERIAL")
        id1 = db.add_device(cid, dev)
        id2 = db.add_device(cid, dev)
        assert id1 == id2
        assert len(db.get_devices_for_case(cid)) == 1

    def test_add_evidence_positional_args_still_work(self, db):
        """Old positional call signature (no session_id) must be
        unaffected by the new keyword-only session_id parameter."""
        cid = db.create_case("REG-002", "T", "I", "")
        eid = db.add_evidence(cid, None, "acquisition", "f.txt", "/tmp/f.txt", "abc", 10, {})
        assert eid is not None

    def test_verification_integrity_unaffected(self, populated):
        """SHA-256/integrity behavior must be unchanged by Phase 3."""
        result = populated.db.verify_evidence(populated.eid_pass)
        assert result["ok"] is True
        assert result["status"] == "MATCH"

    def test_custody_chain_unaffected(self, populated):
        chain = populated.db.get_custody_chain(populated.eid_pass)
        assert len(chain) >= 1

    def test_audit_trail_still_immutable(self, db):
        assert not hasattr(db, "update_audit_event")
        assert not hasattr(db, "delete_audit_event")
