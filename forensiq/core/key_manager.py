"""
KeyManager — signing key custody for Phase 5 Digital Signature.

Design goals (see requirement 7 — Security):
  - Private keys are NEVER stored in source code or in the application
    database (forensiq.db). They live in their own directory on disk,
    outside every table SignatureService/CaseManager write to.
  - Private keys are NEVER logged or embedded in a report/signature
    record. Only a `key_id` — a public fingerprint derived from the
    *public* key — is persisted alongside a signature (see
    case_manager.add_signature / SCHEMA `signatures` table). Given a
    key_id there is no way to recover the private key.
  - Uses a standard, established cryptographic library (the `cryptography`
    package, which wraps OpenSSL) and a standard signature algorithm
    (Ed25519, RFC 8032). No custom/home-grown cryptography is implemented
    here.

Layout on disk (default: ~/.forensiq/keys/):
  registry.json                  — {signer_slug: {key_id, signer,
                                     private_key_file, public_key_file,
                                     algorithm, created_at}}
  <slug>__<key_id>.private.pem   — PKCS8 private key (optionally
                                    passphrase-encrypted — see below)
  <slug>__<key_id>.public.pem    — SubjectPublicKeyInfo public key

One Ed25519 keypair is created per distinct "signer" identity (the
investigator name passed to sign_artifact()) the first time that signer
signs anything, and reused afterward — mirroring how the rest of the app
treats a signer identity as free-text tied to the investigator field
elsewhere (cases.investigator, custody_events.investigator, ...).

Passphrase protection (optional): if the environment variable
FORENSIQ_SIGNING_KEY_PASSPHRASE is set when a key is generated, the
private key file is written encrypted (AES, via cryptography's
BestAvailableEncryption) and the same environment variable must be set to
load it again later. If unset, the private key file is written
unencrypted but with owner-only file permissions (0600), the same trust
model the rest of the app already uses for ~/.forensiq/forensiq.db.
"""

import json
import os
import re
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from forensiq.core.time_utils import now_utc_str

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

DEFAULT_KEYS_DIR = Path.home() / ".forensiq" / "keys"

ALGORITHM = "Ed25519"


class KeyUnavailableError(Exception):
    """
    Raised when a private key that should exist cannot be loaded — the
    registry entry or key file is missing, unreadable, or the configured
    passphrase does not decrypt it. Callers (SignatureService) surface
    this as a clear failure rather than silently signing with a new,
    unrelated key.
    """
    pass


# Phase 10: delegates to the single centralized clock in time_utils
# instead of formatting datetime.now(timezone.utc) locally.
def _now() -> str:
    return now_utc_str()


def _slug(signer: str) -> str:
    s = (signer or "").strip().lower()
    s = re.sub(r"[^a-z0-9]+", "_", s).strip("_")
    return s or "default"


def _passphrase_bytes() -> Optional[bytes]:
    p = os.environ.get("FORENSIQ_SIGNING_KEY_PASSPHRASE")
    return p.encode("utf-8") if p else None


class KeyManager:
    """
    Generates, stores, and loads Ed25519 signing keys used by
    SignatureService. Never returns or logs raw private key bytes to a
    caller outside this module — callers get back a `key_id` string and
    an in-memory key object to sign with immediately.
    """

    def __init__(self, keys_dir: Optional[str] = None):
        self.keys_dir = Path(keys_dir) if keys_dir else DEFAULT_KEYS_DIR
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.keys_dir, 0o700)
        except OSError:
            pass  # best-effort on platforms without POSIX permissions (e.g. Windows)
        self.registry_path = self.keys_dir / "registry.json"

    # ── Registry (public metadata only — no key material) ──────────────────────

    def _load_registry(self) -> dict:
        if not self.registry_path.exists():
            return {}
        try:
            with open(self.registry_path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, json.JSONDecodeError):
            return {}

    def _save_registry(self, registry: dict):
        with open(self.registry_path, "w", encoding="utf-8") as fh:
            json.dump(registry, fh, indent=2)
        try:
            os.chmod(self.registry_path, 0o600)
        except OSError:
            pass

    # ── Key generation / loading ────────────────────────────────────────────────

    def get_or_create_signing_key(self, signer: str):
        """
        Return (key_id, private_key) for `signer`. Creates a new Ed25519
        keypair the first time this signer identity is used; every later
        call for the same signer returns the same identity so all of a
        signer's signatures verify against one stable key_id.
        """
        slug = _slug(signer)
        registry = self._load_registry()
        entry = registry.get(slug)

        if entry:
            priv_path = self.keys_dir / entry["private_key_file"]
            if not priv_path.exists():
                raise KeyUnavailableError(
                    f"Private key file for signer {signer!r} is missing: {priv_path}"
                )
            private_key = self._load_private_key(priv_path)
            return entry["key_id"], private_key

        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        key_id = hashlib.sha256(pub_bytes).hexdigest()[:16]

        priv_file = f"{slug}__{key_id}.private.pem"
        pub_file = f"{slug}__{key_id}.public.pem"
        self._write_private_key(self.keys_dir / priv_file, private_key)
        self._write_public_key(self.keys_dir / pub_file, public_key)

        registry[slug] = {
            "key_id": key_id,
            "signer": signer,
            "algorithm": ALGORITHM,
            "private_key_file": priv_file,
            "public_key_file": pub_file,
            "created_at": _now(),
        }
        self._save_registry(registry)
        return key_id, private_key

    def load_public_key(self, key_id: str) -> Optional[Ed25519PublicKey]:
        """
        Locate and load the public key matching `key_id`. Returns None
        (never raises) if the key_id is unknown or its file is missing/
        unreadable — callers treat that as KEY_UNAVAILABLE, not a crash.
        """
        if not key_id:
            return None
        registry = self._load_registry()
        for entry in registry.values():
            if entry.get("key_id") == key_id:
                pub_path = self.keys_dir / entry.get("public_key_file", "")
                if not pub_path.exists():
                    return None
                try:
                    return self._load_public_key(pub_path)
                except (OSError, ValueError):
                    return None
        return None

    # ── PEM I/O ──────────────────────────────────────────────────────────────────

    def _write_private_key(self, path: Path, private_key: Ed25519PrivateKey):
        passphrase = _passphrase_bytes()
        encryption = (
            serialization.BestAvailableEncryption(passphrase)
            if passphrase else serialization.NoEncryption()
        )
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        )
        with open(path, "wb") as fh:
            fh.write(pem)
        try:
            os.chmod(path, 0o600)  # owner read/write only — never world-readable
        except OSError:
            pass

    def _write_public_key(self, path: Path, public_key: Ed25519PublicKey):
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        with open(path, "wb") as fh:
            fh.write(pem)

    def _load_private_key(self, path: Path) -> Ed25519PrivateKey:
        with open(path, "rb") as fh:
            data = fh.read()
        passphrase = _passphrase_bytes()
        try:
            return serialization.load_pem_private_key(data, password=passphrase)
        except (ValueError, TypeError) as e:
            raise KeyUnavailableError(
                f"Could not load private key {path} "
                f"(wrong/missing FORENSIQ_SIGNING_KEY_PASSPHRASE?): {e}"
            ) from e

    def _load_public_key(self, path: Path) -> Ed25519PublicKey:
        with open(path, "rb") as fh:
            data = fh.read()
        return serialization.load_pem_public_key(data)
