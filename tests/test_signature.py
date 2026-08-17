import os
"""
Tests — forensiq.core.key_manager / signature_service (Phase 5 — Digital
Signature), plus the signature-related additions to case_manager and
audit_service.

Covers:
  - Key generation/reuse/isolation per signer identity; private key file
    permissions; key lookup by key_id; KEY_UNAVAILABLE handling.
  - Signing a Manifest / Report: detached .sig.json written, original
    artifact never modified, all required metadata fields present,
    signature persisted to the `signatures` table.
  - Verification result vocabulary: VALID, MODIFIED, MISSING, INVALID
    (wrong key / tampered signature), KEY_UNAVAILABLE.
  - Audit trail integration: ARTIFACT_SIGNED / SIGNATURE_VERIFIED /
    SIGNATURE_VERIFICATION_FAILED events.
  - No private key material ever appears in signature metadata, DB rows,
    or audit notes.
"""

import base64
import json
import os

import pytest

from forensiq.core.hasher import sha256_file
from forensiq.core.key_manager import KeyManager, KeyUnavailableError
from forensiq.core.signature_service import (
    SignatureService,
    ARTIFACT_MANIFEST, ARTIFACT_REPORT, ALGORITHM,
    VALID, INVALID, MODIFIED, MISSING, KEY_UNAVAILABLE,
    SIG_SUFFIX,
)


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def key_manager(tmp_path):
    return KeyManager(keys_dir=str(tmp_path / "keys"))


@pytest.fixture
def sig_service(db, key_manager):
    return SignatureService(db, key_manager=key_manager)


@pytest.fixture
def manifest_file(tmp_path):
    """A stand-in generated artifact (plays the role of an exported
    manifest.json or a generated report)."""
    p = tmp_path / "ForensIQ_TC-001_EvidenceManifest.json"
    p.write_text(json.dumps({"case_number": "TC-001", "total_items": 3}))
    return str(p)


@pytest.fixture
def report_file(tmp_path):
    p = tmp_path / "ForensIQ_TC-001_Report.html"
    p.write_text("<html><body>Forensic Report</body></html>")
    return str(p)


# ── Constants ────────────────────────────────────────────────────────────────

class TestConstants:
    def test_algorithm_is_standard_established_algorithm(self):
        # Ed25519 (RFC 8032) via the `cryptography` library — not a
        # custom/home-grown scheme.
        assert ALGORITHM == "Ed25519"

    def test_artifact_types(self):
        assert ARTIFACT_MANIFEST == "MANIFEST"
        assert ARTIFACT_REPORT == "REPORT"

    def test_verification_status_vocabulary(self):
        assert {VALID, INVALID, MODIFIED, MISSING, KEY_UNAVAILABLE} == {
            "VALID", "INVALID", "MODIFIED", "MISSING", "KEY_UNAVAILABLE",
        }


# ── KeyManager ───────────────────────────────────────────────────────────────

class TestKeyManager:
    def test_creates_new_keypair_on_first_use(self, key_manager):
        key_id, private_key = key_manager.get_or_create_signing_key("Det. Jones")
        assert key_id
        assert len(key_id) == 16  # sha256(pub)[:16]
        assert private_key is not None

    def test_same_signer_reuses_same_key(self, key_manager):
        key_id_1, _ = key_manager.get_or_create_signing_key("Det. Jones")
        key_id_2, _ = key_manager.get_or_create_signing_key("Det. Jones")
        assert key_id_1 == key_id_2

    def test_different_signers_get_different_keys(self, key_manager):
        key_id_1, _ = key_manager.get_or_create_signing_key("Det. Jones")
        key_id_2, _ = key_manager.get_or_create_signing_key("Det. Smith")
        assert key_id_1 != key_id_2

    def test_signer_identity_is_case_insensitive_slug_stable(self, key_manager):
        """'Det. Jones' and 'det. jones' should resolve to the same
        signer identity/key so casing differences don't fragment a
        signer's signing history."""
        key_id_1, _ = key_manager.get_or_create_signing_key("Det. Jones")
        key_id_2, _ = key_manager.get_or_create_signing_key("det. jones")
        assert key_id_1 == key_id_2

    def test_private_key_file_is_not_world_readable(self, key_manager, tmp_path):
        key_manager.get_or_create_signing_key("Det. Jones")
        registry = key_manager._load_registry()
        entry = registry["det_jones"]
        priv_path = key_manager.keys_dir / entry["private_key_file"]
        assert priv_path.exists()
      mode = priv_path.stat().st_mode & 0o777
if os.name != "nt":
    assert mode == 0o600
    def test_registry_persists_across_instances(self, tmp_path):
        km1 = KeyManager(keys_dir=str(tmp_path / "keys"))
        key_id_1, _ = km1.get_or_create_signing_key("Det. Jones")

        km2 = KeyManager(keys_dir=str(tmp_path / "keys"))
        key_id_2, _ = km2.get_or_create_signing_key("Det. Jones")
        assert key_id_1 == key_id_2

    def test_load_public_key_unknown_id_returns_none(self, key_manager):
        assert key_manager.load_public_key("deadbeefdeadbeef") is None

    def test_load_public_key_empty_id_returns_none(self, key_manager):
        assert key_manager.load_public_key("") is None

    def test_missing_private_key_file_raises_key_unavailable(self, key_manager):
        key_id, _ = key_manager.get_or_create_signing_key("Det. Jones")
        registry = key_manager._load_registry()
        priv_path = key_manager.keys_dir / registry["det_jones"]["private_key_file"]
        os.remove(priv_path)
        with pytest.raises(KeyUnavailableError):
            key_manager.get_or_create_signing_key("Det. Jones")

    def test_load_public_key_missing_file_returns_none(self, key_manager):
        key_id, _ = key_manager.get_or_create_signing_key("Det. Jones")
        registry = key_manager._load_registry()
        pub_path = key_manager.keys_dir / registry["det_jones"]["public_key_file"]
        os.remove(pub_path)
        assert key_manager.load_public_key(key_id) is None

    def test_registry_never_contains_private_key_bytes(self, key_manager):
        key_manager.get_or_create_signing_key("Det. Jones")
        raw = key_manager.registry_path.read_text()
        assert "PRIVATE KEY" not in raw
        assert "BEGIN" not in raw


# ── Signing ──────────────────────────────────────────────────────────────────

class TestSignManifest:
    def test_sign_writes_detached_sidecar(self, sig_service, manifest_file):
        meta = sig_service.sign_manifest(manifest_file, "Det. Jones")
        sig_path = manifest_file + SIG_SUFFIX
        assert os.path.exists(sig_path)
        assert meta["signature_path"] == sig_path

    def test_sign_does_not_modify_original_artifact(self, sig_service, manifest_file):
        original_hash = sha256_file(manifest_file)
        original_bytes = open(manifest_file, "rb").read()
        sig_service.sign_manifest(manifest_file, "Det. Jones")
        assert sha256_file(manifest_file) == original_hash
        assert open(manifest_file, "rb").read() == original_bytes

    def test_sign_preserves_original_manifest_content(self, sig_service, manifest_file):
        """Requirement 1 — 'Preserve the original manifest.'"""
        before = json.load(open(manifest_file))
        sig_service.sign_manifest(manifest_file, "Det. Jones")
        after = json.load(open(manifest_file))
        assert before == after

    def test_signature_metadata_has_all_required_fields(self, sig_service, manifest_file):
        """Requirement 3 — signer, algorithm, timestamp, artifact type,
        artifact SHA-256, signature, key/certificate identifier."""
        meta = sig_service.sign_manifest(manifest_file, "Det. Jones")
        for field in ("signer", "algorithm", "signed_at", "artifact_type",
                      "artifact_sha256", "signature", "key_id"):
            assert field in meta and meta[field], f"missing/empty field: {field}"
        assert meta["signer"] == "Det. Jones"
        assert meta["algorithm"] == "Ed25519"
        assert meta["artifact_type"] == ARTIFACT_MANIFEST
        assert meta["artifact_sha256"] == sha256_file(manifest_file)

    def test_signature_persisted_to_db(self, sig_service, manifest_file, db):
        cid = db.create_case("TC-900", "Sig Test", "Det. Jones")
        meta = sig_service.sign_manifest(manifest_file, "Det. Jones", case_id=cid)
        rows = db.get_signatures_for_case(cid)
        assert len(rows) == 1
        assert rows[0]["artifact_type"] == "MANIFEST"
        assert rows[0]["signature"] == meta["signature"]
        assert rows[0]["key_id"] == meta["key_id"]

    def test_sign_missing_file_raises(self, sig_service, tmp_path):
        with pytest.raises(FileNotFoundError):
            sig_service.sign_manifest(str(tmp_path / "nope.json"), "Det. Jones")

    def test_sign_requires_signer(self, sig_service, manifest_file):
        with pytest.raises(ValueError):
            sig_service.sign_manifest(manifest_file, "")

    def test_sidecar_never_contains_private_key(self, sig_service, manifest_file):
        sig_service.sign_manifest(manifest_file, "Det. Jones")
        raw = open(manifest_file + SIG_SUFFIX).read()
        assert "PRIVATE KEY" not in raw


class TestSignReport:
    def test_sign_report_original_untouched(self, sig_service, report_file):
        original = open(report_file, "rb").read()
        meta = sig_service.sign_report(report_file, "Det. Jones")
        assert open(report_file, "rb").read() == original
        assert meta["artifact_type"] == ARTIFACT_REPORT

    def test_sign_invalid_artifact_type_rejected(self, sig_service, report_file):
        with pytest.raises(ValueError):
            sig_service.sign_artifact("EVIDENCE", report_file, "Det. Jones")


# ── Verification ─────────────────────────────────────────────────────────────

class TestVerification:
    def test_verify_valid(self, sig_service, manifest_file):
        sig_service.sign_manifest(manifest_file, "Det. Jones")
        res = sig_service.verify_manifest(manifest_file)
        assert res["status"] == VALID
        assert res["signer"] == "Det. Jones"
        assert res["algorithm"] == "Ed25519"
        assert res["artifact_sha256"] == res["current_sha256"]

    def test_verify_missing_no_signature_ever_made(self, sig_service, manifest_file):
        res = sig_service.verify_manifest(manifest_file)
        assert res["status"] == MISSING

    def test_verify_falls_back_to_db_when_sidecar_deleted_no_case_id(
        self, sig_service, manifest_file
    ):
        """Even without a case_id at sign time, the DB row (case_id=NULL)
        is still found by artifact path once the sidecar is gone."""
        sig_service.sign_manifest(manifest_file, "Det. Jones")
        os.remove(manifest_file + SIG_SUFFIX)
        res = sig_service.verify_manifest(manifest_file, case_id=None)
        assert res["status"] == VALID

    def test_verify_falls_back_to_db_when_sidecar_missing(
        self, sig_service, manifest_file, db
    ):
        cid = db.create_case("TC-901", "Sig Test", "Det. Jones")
        sig_service.sign_manifest(manifest_file, "Det. Jones", case_id=cid)
        os.remove(manifest_file + SIG_SUFFIX)
        res = sig_service.verify_manifest(manifest_file, case_id=cid)
        assert res["status"] == VALID

    def test_a_modified_artifact_fails_verification(self, sig_service, manifest_file):
        """Requirement 4 — 'A modified artifact must fail verification.'"""
        sig_service.sign_manifest(manifest_file, "Det. Jones")
        with open(manifest_file, "a") as fh:
            fh.write("tampered-appended-content")
        res = sig_service.verify_manifest(manifest_file)
        assert res["status"] == MODIFIED
        assert res["status"] != VALID

    def test_modified_content_still_reports_original_signed_hash(
        self, sig_service, manifest_file
    ):
        meta = sig_service.sign_manifest(manifest_file, "Det. Jones")
        with open(manifest_file, "a") as fh:
            fh.write("x")
        res = sig_service.verify_manifest(manifest_file)
        assert res["artifact_sha256"] == meta["artifact_sha256"]
        assert res["current_sha256"] != res["artifact_sha256"]

    def test_verify_wrong_key_is_invalid(self, sig_service, key_manager,
                                         manifest_file, report_file):
        """Simulates an attacker (or a mismatched export) pointing a
        signature record at the wrong signer's key."""
        sig_service.sign_manifest(manifest_file, "Det. Jones")
        # A second, unrelated signer key must exist in the same keystore.
        key_manager.get_or_create_signing_key("Det. Smith")
        wrong_key_id, _ = key_manager.get_or_create_signing_key("Det. Smith")

        sig_path = manifest_file + SIG_SUFFIX
        with open(sig_path) as fh:
            meta = json.load(fh)
        meta["key_id"] = wrong_key_id
        with open(sig_path, "w") as fh:
            json.dump(meta, fh)

        res = sig_service.verify_manifest(manifest_file)
        assert res["status"] == INVALID

    def test_verify_tampered_signature_bytes_is_invalid(self, sig_service, manifest_file):
        sig_service.sign_manifest(manifest_file, "Det. Jones")
        sig_path = manifest_file + SIG_SUFFIX
        with open(sig_path) as fh:
            meta = json.load(fh)
        # Corrupt the signature itself while keeping the hash/metadata
        # consistent with the (unmodified) artifact.
        corrupted = bytearray(base64.b64decode(meta["signature"]))
        corrupted[0] ^= 0xFF
        meta["signature"] = base64.b64encode(bytes(corrupted)).decode("ascii")
        with open(sig_path, "w") as fh:
            json.dump(meta, fh)

        res = sig_service.verify_manifest(manifest_file)
        assert res["status"] == INVALID

    def test_verify_tampered_metadata_field_is_invalid(self, sig_service, manifest_file):
        """Changing the recorded signer (without re-signing) must also
        be caught, even though the artifact bytes are untouched — the
        signer identity is part of the signed payload."""
        sig_service.sign_manifest(manifest_file, "Det. Jones")
        sig_path = manifest_file + SIG_SUFFIX
        with open(sig_path) as fh:
            meta = json.load(fh)
        meta["signer"] = "Det. Someone Else"
        with open(sig_path, "w") as fh:
            json.dump(meta, fh)

        res = sig_service.verify_manifest(manifest_file)
        assert res["status"] == INVALID

    def test_verify_key_unavailable(self, sig_service, key_manager, manifest_file):
        sig_service.sign_manifest(manifest_file, "Det. Jones")
        registry = key_manager._load_registry()
        pub_path = key_manager.keys_dir / registry["det_jones"]["public_key_file"]
        os.remove(pub_path)

        res = sig_service.verify_manifest(manifest_file)
        assert res["status"] == KEY_UNAVAILABLE

    def test_verify_artifact_file_deleted_after_signing_is_missing(
        self, sig_service, manifest_file
    ):
        sig_service.sign_manifest(manifest_file, "Det. Jones")
        os.remove(manifest_file)
        res = sig_service.verify_manifest(manifest_file)
        assert res["status"] == MISSING

    def test_verify_result_never_contains_private_key_material(
        self, sig_service, manifest_file
    ):
        sig_service.sign_manifest(manifest_file, "Det. Jones")
        res = sig_service.verify_manifest(manifest_file)
        blob = json.dumps(res)
        assert "PRIVATE KEY" not in blob


# ── case_manager signature CRUD ─────────────────────────────────────────────

class TestCaseManagerSignatures:
    def test_add_signature_rejects_bad_artifact_type(self, db):
        with pytest.raises(ValueError):
            db.add_signature(
                artifact_type="EVIDENCE", artifact_path="/tmp/x",
                artifact_sha256="a" * 64, signature="sig", algorithm="Ed25519",
            )

    def test_add_signature_requires_hash_and_signature(self, db):
        with pytest.raises(ValueError):
            db.add_signature(
                artifact_type="MANIFEST", artifact_path="/tmp/x",
                artifact_sha256="", signature="sig", algorithm="Ed25519",
            )
        with pytest.raises(ValueError):
            db.add_signature(
                artifact_type="MANIFEST", artifact_path="/tmp/x",
                artifact_sha256="a" * 64, signature="", algorithm="Ed25519",
            )

    def test_signatures_are_append_only(self, db):
        """No update/delete method is exposed for the signatures table,
        matching verification_results/audit_trail immutability."""
        assert not hasattr(db, "update_signature")
        assert not hasattr(db, "delete_signature")

    def test_get_signatures_for_case_newest_first(self, db, sig_service, tmp_path):
        cid = db.create_case("TC-902", "Sig Test", "Det. Jones")
        f1 = tmp_path / "a.json"; f1.write_text("{}")
        f2 = tmp_path / "b.json"; f2.write_text("{}")
        sig_service.sign_manifest(str(f1), "Det. Jones", case_id=cid)
        sig_service.sign_report(str(f2), "Det. Jones", case_id=cid)
        rows = db.get_signatures_for_case(cid)
        assert len(rows) == 2
        # Newest first: the report (signed second) should be first.
        assert rows[0]["artifact_type"] == "REPORT"

    def test_get_last_signature_for_artifact_picks_latest(self, db, sig_service, tmp_path):
        cid = db.create_case("TC-903", "Sig Test", "Det. Jones")
        f = tmp_path / "manifest.json"; f.write_text("{}")
        sig_service.sign_manifest(str(f), "Det. Jones", case_id=cid)
        first = db.get_last_signature_for_artifact(os.path.abspath(str(f)), case_id=cid)
        f.write_text('{"v":2}')
        sig_service.sign_manifest(str(f), "Det. Jones", case_id=cid)
        latest = db.get_last_signature_for_artifact(os.path.abspath(str(f)), case_id=cid)
        assert latest["id"] != first["id"]
        assert latest["id"] > first["id"]


# ── Audit integration ────────────────────────────────────────────────────────

class TestAuditIntegration:
    def test_log_artifact_signed_writes_audit_row(self, db, audit):
        cid = db.create_case("TC-904", "Sig Test", "Det. Jones")
        audit.log_artifact_signed(cid, "Det. Jones", "MANIFEST",
                                  "/tmp/manifest.json", "abc123")
        rows = db.get_audit_trail(action="ARTIFACT_SIGNED")
        assert len(rows) == 1
        assert rows[0]["user"] == "Det. Jones"
        assert "manifest.json" in rows[0]["notes"]
        assert "abc123" in rows[0]["notes"]

    def test_log_signature_verified_valid_is_ok_result(self, db, audit):
        cid = db.create_case("TC-905", "Sig Test", "Det. Jones")
        audit.log_signature_verified(cid, "Det. Jones", "MANIFEST",
                                     "/tmp/manifest.json", "VALID")
        rows = db.get_audit_trail(action="SIGNATURE_VERIFIED")
        assert len(rows) == 1
        assert rows[0]["result"] == "OK"

    @pytest.mark.parametrize("status", ["INVALID", "MODIFIED", "KEY_UNAVAILABLE"])
    def test_log_signature_verified_failure_statuses_logged_as_failed(
        self, db, audit, status
    ):
        cid = db.create_case(f"TC-906-{status}", "Sig Test", "Det. Jones")
        audit.log_signature_verified(cid, "Det. Jones", "REPORT",
                                     "/tmp/report.html", status)
        rows = db.get_audit_trail(action="SIGNATURE_VERIFICATION_FAILED")
        assert len(rows) == 1
        assert rows[0]["result"] == "FAILED"
        assert status in rows[0]["notes"]

    def test_log_signature_verified_missing_is_warning_not_ok(self, db, audit):
        cid = db.create_case("TC-907", "Sig Test", "Det. Jones")
        audit.log_signature_verified(cid, "Det. Jones", "MANIFEST",
                                     "/tmp/manifest.json", "MISSING")
        rows = db.get_audit_trail(action="SIGNATURE_VERIFICATION_FAILED")
        assert len(rows) == 1
        assert rows[0]["result"] == "WARNING"

    def test_full_sign_then_verify_audit_flow(self, db, audit, sig_service, manifest_file):
        cid = db.create_case("TC-908", "Sig Test", "Det. Jones")
        meta = sig_service.sign_manifest(manifest_file, "Det. Jones", case_id=cid)
        audit.log_artifact_signed(cid, "Det. Jones", "MANIFEST",
                                  manifest_file, meta["key_id"])

        res = sig_service.verify_manifest(manifest_file, case_id=cid)
        audit.log_signature_verified(cid, "Det. Jones", "MANIFEST",
                                     manifest_file, res["status"])

        actions = [r["action"] for r in db.get_audit_trail()]
        assert "ARTIFACT_SIGNED" in actions
        assert "SIGNATURE_VERIFIED" in actions

    def test_audit_notes_never_contain_private_key(self, db, audit, sig_service, manifest_file):
        cid = db.create_case("TC-909", "Sig Test", "Det. Jones")
        meta = sig_service.sign_manifest(manifest_file, "Det. Jones", case_id=cid)
        audit.log_artifact_signed(cid, "Det. Jones", "MANIFEST",
                                  manifest_file, meta["key_id"])
        rows = db.get_audit_trail(action="ARTIFACT_SIGNED")
        assert "PRIVATE KEY" not in rows[0]["notes"]


# ── Regression: existing systems still importable / unaffected ─────────────

class TestRegressionNoBreakage:
    def test_signature_service_importable_without_pyqt6(self):
        """signature_service / key_manager are pure Python + cryptography
        — must not require PyQt6 to import, same guarantee as
        integrity_engine (see test_regression.py)."""
        import subprocess, sys
        code = (
            "import builtins; real_import = builtins.__import__\n"
            "def blocked(name, *a, **k):\n"
            "    if name == 'PyQt6' or name.startswith('PyQt6.'):\n"
            "        raise ImportError('blocked for test')\n"
            "    return real_import(name, *a, **k)\n"
            "builtins.__import__ = blocked\n"
            "from forensiq.core.signature_service import SignatureService\n"
            "from forensiq.core.key_manager import KeyManager\n"
            "print('OK')\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True, text=True, cwd=".",
        )
        assert "OK" in result.stdout, (
            f"signature_service import failed without PyQt6: {result.stderr}"
        )

    def test_case_manager_still_creates_all_prior_tables(self, db):
        """New `signatures` table must not interfere with prior-phase
        tables/migrations."""
        with db._connect() as conn:
            tables = {
                r["name"] for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
        for t in ("cases", "devices", "evidence", "acquisition_sessions",
                  "analysis_results", "timeline_events", "verification_results",
                  "audit_trail", "custody_events", "signatures"):
            assert t in tables
