"""
SignatureService — Cryptographic Signing & Verification (Phase 5).

Signs generated forensic artifacts (Case Evidence Manifest, Report) with a
detached signature and verifies them later, returning one of the five
states required by Phase 5:

    VALID            — signature cryptographically checks out against an
                        unchanged artifact.
    INVALID          — a signature record exists but does not
                        cryptographically verify (wrong key, tampered
                        signature/metadata).
    MODIFIED         — the artifact's current SHA-256 no longer matches
                        the hash that was signed (the file changed after
                        signing).
    MISSING          — no signature record can be found for this
                        artifact at all.
    KEY_UNAVAILABLE  — a signature record exists, but the public key
                        needed to verify it cannot be located/loaded.

Reuses existing infrastructure rather than duplicating it:
  - forensiq.core.hasher.sha256_file_verify()  for hashing (same helper
    IntegrityEngine uses for evidence re-hashing).
  - forensiq.core.key_manager.KeyManager       for key custody (private
    keys never touch this module's return values or the database).
  - forensiq.core.case_manager.CaseManager.add_signature() /
    get_last_signature_for_artifact() for persistence — this module owns
    no table of its own, matching manifest_service.py's approach.

The original artifact file is never modified by signing or verification —
the signature is written to a separate ".sig.json" file next to it
(requirement 1/2: "detached... do not modify the original artifact").
"""

import base64
import json
import os
from datetime import datetime, timezone
from typing import Optional

from cryptography.exceptions import InvalidSignature

from forensiq.core.case_manager import CaseManager
from forensiq.core.hasher import sha256_file_verify, HashCorruptedError
from forensiq.core.key_manager import KeyManager, KeyUnavailableError
from forensiq.core.time_utils import now_utc_str

# ── Constants ────────────────────────────────────────────────────────────────

ALGORITHM = "Ed25519"

ARTIFACT_MANIFEST = "MANIFEST"
ARTIFACT_REPORT   = "REPORT"
VALID_ARTIFACT_TYPES = {ARTIFACT_MANIFEST, ARTIFACT_REPORT}

# Verification result vocabulary (requirement 4)
VALID           = "VALID"
INVALID         = "INVALID"
MODIFIED        = "MODIFIED"
MISSING         = "MISSING"
KEY_UNAVAILABLE = "KEY_UNAVAILABLE"

ALL_STATUSES = (VALID, INVALID, MODIFIED, MISSING, KEY_UNAVAILABLE)

SIG_SUFFIX = ".sig.json"


# Phase 10: delegates to the single centralized clock in time_utils
# instead of formatting datetime.now(timezone.utc) locally.
def _ts() -> str:
    return now_utc_str()


def _signing_payload(artifact_type: str, artifact_sha256: str, signer: str,
                      signed_at: str, key_id: str) -> bytes:
    """
    The exact bytes that get signed / verified. Every field that
    identifies *what* was signed and *by whom* is included so that
    tampering with any one of them (not just the artifact bytes) is
    detected as an INVALID signature. A fixed pipe-delimited join is used
    instead of json.dumps() so the payload never depends on a JSON
    library's key-ordering behaviour across versions/platforms.
    """
    parts = [artifact_type or "", artifact_sha256 or "", signer or "",
             signed_at or "", key_id or ""]
    return "|".join(parts).encode("utf-8")


class SignatureService:
    """
    Sign and verify Manifest/Report artifacts. Stateless aside from the
    CaseManager/KeyManager it wraps — safe to construct per-call, same as
    IntegrityEngine and AuditService.
    """

    def __init__(self, db: CaseManager, key_manager: Optional[KeyManager] = None):
        self.db = db
        self.keys = key_manager or KeyManager()

    # ── Signing ──────────────────────────────────────────────────────────────

    def sign_artifact(self, artifact_type: str, artifact_path: str,
                      signer: str, case_id: Optional[int] = None) -> dict:
        """
        Sign `artifact_path` (a generated manifest or report file) as
        `signer`. Writes a detached '<artifact_path>.sig.json' signature
        file and persists the same metadata to the `signatures` table.
        The original artifact file is opened read-only (for hashing) and
        is never rewritten. Returns the signature metadata dict.
        """
        if artifact_type not in VALID_ARTIFACT_TYPES:
            raise ValueError(
                f"artifact_type must be one of {sorted(VALID_ARTIFACT_TYPES)}, "
                f"got {artifact_type!r}"
            )
        if not signer or not signer.strip():
            raise ValueError("signer (signer identity) is required")
        if not os.path.exists(artifact_path):
            raise FileNotFoundError(f"Artifact not found: {artifact_path}")
        if not os.path.isfile(artifact_path):
            raise ValueError(f"Not a regular file: {artifact_path}")

        artifact_sha256 = sha256_file_verify(artifact_path)
        key_id, private_key = self.keys.get_or_create_signing_key(signer)
        signed_at = _ts()

        payload = _signing_payload(artifact_type, artifact_sha256, signer,
                                    signed_at, key_id)
        signature_bytes = private_key.sign(payload)
        signature_b64 = base64.b64encode(signature_bytes).decode("ascii")

        abs_path = os.path.abspath(artifact_path)
        meta = {
            "artifact_type":     artifact_type,
            "artifact_path":     abs_path,
            "artifact_filename": os.path.basename(artifact_path),
            "artifact_sha256":   artifact_sha256,
            "signer":            signer,
            "algorithm":         ALGORITHM,
            "signed_at":         signed_at,
            "key_id":            key_id,
            "signature":         signature_b64,
        }

        sig_path = artifact_path + SIG_SUFFIX
        with open(sig_path, "w", encoding="utf-8") as fh:
            json.dump(meta, fh, indent=2)
        meta["signature_path"] = sig_path

        sig_id = self.db.add_signature(
            case_id=case_id,
            artifact_type=artifact_type,
            artifact_path=abs_path,
            artifact_sha256=artifact_sha256,
            signature_path=sig_path,
            signature=signature_b64,
            algorithm=ALGORITHM,
            signer=signer,
            key_id=key_id,
            signed_at=signed_at,
        )
        meta["id"] = sig_id
        return meta

    def sign_manifest(self, artifact_path: str, signer: str,
                      case_id: Optional[int] = None) -> dict:
        """Convenience wrapper — sign a Case Evidence Manifest export."""
        return self.sign_artifact(ARTIFACT_MANIFEST, artifact_path, signer,
                                   case_id=case_id)

    def sign_report(self, artifact_path: str, signer: str,
                    case_id: Optional[int] = None) -> dict:
        """Convenience wrapper — sign a generated forensic report."""
        return self.sign_artifact(ARTIFACT_REPORT, artifact_path, signer,
                                   case_id=case_id)

    # ── Verification ─────────────────────────────────────────────────────────

    def _find_signature_record(self, artifact_path: str,
                               case_id: Optional[int] = None) -> Optional[dict]:
        """
        Locate signature metadata for an artifact. Prefers the detached
        sidecar file (travels with the artifact even outside this
        database — e.g. handed to opposing counsel), falling back to the
        most recent DB record for that path if no sidecar is present or
        readable.
        """
        abs_path = os.path.abspath(artifact_path)
        sig_path = abs_path + SIG_SUFFIX
        if os.path.exists(sig_path):
            try:
                with open(sig_path, "r", encoding="utf-8") as fh:
                    return json.load(fh)
            except (OSError, json.JSONDecodeError):
                pass  # fall through to DB lookup

        row = self.db.get_last_signature_for_artifact(abs_path, case_id=case_id)
        if row:
            return dict(row)
        return None

    def verify_artifact(self, artifact_path: str,
                        case_id: Optional[int] = None) -> dict:
        """
        Verify `artifact_path` against its recorded signature. Always
        returns a result dict with a `status` key set to exactly one of
        VALID / INVALID / MODIFIED / MISSING / KEY_UNAVAILABLE — never
        raises for an expected forensic outcome (missing file, tampered
        artifact, unavailable key); only truly unexpected I/O errors
        propagate.
        """
        result = {
            "artifact_path":    os.path.abspath(artifact_path),
            "status":           MISSING,
            "artifact_type":    "",
            "signer":           "",
            "algorithm":        "",
            "signed_at":        "",
            "artifact_sha256":  "",
            "current_sha256":   "",
            "key_id":           "",
            "notes":            "",
        }

        record = self._find_signature_record(artifact_path, case_id=case_id)
        if not record:
            result["notes"] = "No signature found for this artifact."
            return result

        result.update({
            "artifact_type":   record.get("artifact_type", ""),
            "signer":          record.get("signer", ""),
            "algorithm":       record.get("algorithm", ""),
            "signed_at":       record.get("signed_at", ""),
            "artifact_sha256": record.get("artifact_sha256", ""),
            "key_id":          record.get("key_id", ""),
        })

        if not os.path.exists(artifact_path):
            result["status"] = MISSING
            result["notes"] = "Artifact file no longer exists on disk."
            return result

        try:
            current_hash = sha256_file_verify(artifact_path)
        except FileNotFoundError:
            result["status"] = MISSING
            result["notes"] = "Artifact file no longer exists on disk."
            return result
        except HashCorruptedError as e:
            result["status"] = MODIFIED
            result["notes"] = f"Artifact could not be reliably re-read: {e}"
            return result

        result["current_sha256"] = current_hash

        # Hash check first: a modified artifact is reported as MODIFIED
        # (a specific, actionable finding) rather than the more generic
        # INVALID, even before we look at the key.
        if current_hash.lower() != (record.get("artifact_sha256") or "").lower():
            result["status"] = MODIFIED
            result["notes"] = "Artifact content has changed since it was signed."
            return result

        public_key = self.keys.load_public_key(record.get("key_id", ""))
        if public_key is None:
            result["status"] = KEY_UNAVAILABLE
            result["notes"] = (
                "The signing key/certificate for this signature is not "
                "available on this system — cannot cryptographically verify."
            )
            return result

        payload = _signing_payload(
            record.get("artifact_type", ""),
            record.get("artifact_sha256", ""),
            record.get("signer", ""),
            record.get("signed_at", ""),
            record.get("key_id", ""),
        )
        try:
            signature_bytes = base64.b64decode(record.get("signature", "") or "")
            public_key.verify(signature_bytes, payload)
            result["status"] = VALID
            result["notes"] = "Signature is valid — artifact is unmodified and authentic."
        except (InvalidSignature, ValueError, TypeError):
            result["status"] = INVALID
            result["notes"] = (
                "Signature does not verify against this artifact/key "
                "(tampered signature, tampered metadata, or wrong key)."
            )

        return result

    def verify_manifest(self, artifact_path: str,
                        case_id: Optional[int] = None) -> dict:
        return self.verify_artifact(artifact_path, case_id=case_id)

    def verify_report(self, artifact_path: str,
                      case_id: Optional[int] = None) -> dict:
        return self.verify_artifact(artifact_path, case_id=case_id)
