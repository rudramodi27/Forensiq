"""
Hasher — SHA-256 utilities for evidence integrity verification.

Phase 1 addition:
  - sha256_file_verify() : streaming SHA-256 that RAISES distinct, typed
    errors instead of returning an opaque sentinel string, so callers
    (IntegrityEngine) can tell "file missing" apart from "file present
    but unreadable/corrupted" apart from an unexpected error. Added
    alongside sha256_file() rather than changing it, since sha256_file()
    is relied on elsewhere (adb_manager, analyzer) for its existing
    "never raises, returns a sentinel" contract.
"""

import hashlib
import os
from pathlib import Path

# Default chunk size for streaming hashing. 1 MiB — evidence files (disk
# images, app data, backups) can be gigabytes; the whole point of streaming
# is to keep memory flat regardless of file size, so a larger chunk than the
# original 64 KiB reduces read-syscall overhead for large files without
# meaningfully increasing peak memory.
DEFAULT_CHUNK_SIZE = 1024 * 1024


class HashCorruptedError(OSError):
    """
    Raised by sha256_file_verify() when a file exists and can be opened,
    but a read error occurs partway through (disk error, permission
    change mid-read, truncated/corrupted media, etc). This is distinct
    from the file simply not existing (FileNotFoundError) — it means the
    file is present but its contents cannot be reliably read, so no
    trustworthy hash can be computed.
    """
    pass


def sha256_file(filepath: str) -> str:
    """Compute SHA-256 of a file in streaming chunks (safe for large files).

    Legacy, non-raising API: kept unchanged for existing callers
    (adb_manager, analyzer, hash_directory) that expect a string back
    and treat "ERROR_READING_FILE" as a non-matching sentinel value.
    New verification code should use sha256_file_verify() instead, which
    distinguishes *why* hashing failed.
    """
    h = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, IOError):
        return "ERROR_READING_FILE"


def sha256_file_verify(filepath: str, chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    """
    Compute SHA-256 of a file in streaming chunks, for integrity
    verification. Unlike sha256_file(), this raises typed exceptions so
    callers can distinguish failure modes instead of getting an opaque
    sentinel string:

      - FileNotFoundError    : path does not exist on disk (→ MISSING)
      - HashCorruptedError   : file exists but a read error occurred
                                partway through (→ CORRUPTED)
      - any other OSError    : unexpected I/O failure (→ ERROR)

    Never loads the whole file into memory — reads in fixed-size chunks
    regardless of file size, so multi-gigabyte evidence files are safe.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"Not a regular file: {filepath}")

    h = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(chunk_size), b""):
                h.update(chunk)
    except (OSError, IOError) as e:
        # File existed (we just checked) but couldn't be fully read —
        # treat as corruption, not a generic error.
        raise HashCorruptedError(
            f"Read error while hashing {filepath}: {e}"
        ) from e
    return h.hexdigest()


def sha256_string(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_file(filepath: str, expected_hash: str) -> bool:
    return sha256_file(filepath).lower() == expected_hash.lower()


def hash_directory(dirpath: str) -> dict[str, str]:
    """Return {relative_path: sha256} for all files in a directory."""
    results = {}
    base = Path(dirpath)
    for root, _, files in os.walk(dirpath):
        for fname in files:
            fpath = Path(root) / fname
            rel = str(fpath.relative_to(base))
            results[rel] = sha256_file(str(fpath))
    return results
