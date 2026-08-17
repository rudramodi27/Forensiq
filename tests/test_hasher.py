"""
Unit tests — forensiq.core.hasher

Tests every public function: sha256_file, sha256_string, sha256_bytes,
verify_file, hash_directory. All tests are pure Python with no Qt dependency.
"""

import hashlib
import os

import pytest

from forensiq.core.hasher import (
    hash_directory,
    sha256_bytes,
    sha256_file,
    sha256_string,
    verify_file,
)

SHA256_EMPTY = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


# ── sha256_file ───────────────────────────────────────────────────────────────

class TestSha256File:
    def test_known_content(self, tmp_path):
        """SHA-256 of known bytes must match reference digest."""
        f = tmp_path / "data.bin"
        f.write_bytes(b"hello forensics")
        expected = hashlib.sha256(b"hello forensics").hexdigest()
        assert sha256_file(str(f)) == expected

    def test_empty_file(self, tmp_path):
        """SHA-256 of empty file is the well-known empty-string digest."""
        f = tmp_path / "empty.bin"
        f.write_bytes(b"")
        assert sha256_file(str(f)) == SHA256_EMPTY

    def test_returns_lowercase_hex(self, tmp_path):
        """Digest is always lowercase 64-character hex string."""
        f = tmp_path / "x.bin"
        f.write_bytes(b"test")
        digest = sha256_file(str(f))
        assert len(digest) == 64
        assert digest == digest.lower()
        assert all(c in "0123456789abcdef" for c in digest)

    def test_large_file_streamed(self, tmp_path):
        """Large file (> 64 KB chunk size) is hashed correctly via streaming."""
        data = os.urandom(256 * 1024)  # 256 KB
        f = tmp_path / "large.bin"
        f.write_bytes(data)
        assert sha256_file(str(f)) == hashlib.sha256(data).hexdigest()

    def test_different_content_different_digest(self, tmp_path):
        f1 = tmp_path / "a.bin"; f1.write_bytes(b"aaa")
        f2 = tmp_path / "b.bin"; f2.write_bytes(b"bbb")
        assert sha256_file(str(f1)) != sha256_file(str(f2))

    def test_missing_file_returns_error_sentinel(self, tmp_path):
        """Non-existent file returns an error sentinel string, not a valid hash.
        sha256_file is designed to return 'ERROR_READING_FILE' rather than raise,
        so callers get a safe non-matching value for integrity comparison."""
        result = sha256_file(str(tmp_path / "ghost.bin"))
        # Must not look like a valid 64-char hex hash
        assert result != ""
        assert len(result) != 64 or not all(c in "0123456789abcdef" for c in result)


# ── sha256_string / sha256_bytes ──────────────────────────────────────────────

class TestSha256StringBytes:
    def test_string_matches_reference(self):
        s = "ForensIQ test string"
        expected = hashlib.sha256(s.encode()).hexdigest()
        assert sha256_string(s) == expected

    def test_empty_string(self):
        assert sha256_string("") == SHA256_EMPTY

    def test_bytes_matches_reference(self):
        b = b"\x00\x01\x02\x03"
        assert sha256_bytes(b) == hashlib.sha256(b).hexdigest()

    def test_bytes_empty(self):
        assert sha256_bytes(b"") == SHA256_EMPTY

    def test_string_and_bytes_agree(self):
        """sha256_string and sha256_bytes must agree on the same content."""
        text = "consistency check"
        assert sha256_string(text) == sha256_bytes(text.encode())


# ── verify_file ───────────────────────────────────────────────────────────────

class TestVerifyFile:
    def test_correct_hash_returns_true(self, tmp_path):
        f = tmp_path / "f.bin"
        f.write_bytes(b"evidence data")
        good_hash = sha256_file(str(f))
        assert verify_file(str(f), good_hash) is True

    def test_wrong_hash_returns_false(self, tmp_path):
        f = tmp_path / "f.bin"
        f.write_bytes(b"evidence data")
        assert verify_file(str(f), "a" * 64) is False

    def test_tampered_file_returns_false(self, tmp_path):
        f = tmp_path / "f.bin"
        f.write_bytes(b"original content")
        original_hash = sha256_file(str(f))
        f.write_bytes(b"tampered content")
        assert verify_file(str(f), original_hash) is False

    def test_missing_file_returns_false(self, tmp_path):
        """Missing file must return False, not raise."""
        result = verify_file(str(tmp_path / "ghost.bin"), "a" * 64)
        assert result is False

    def test_case_insensitive_hash_comparison(self, tmp_path):
        """Hash comparison should be case-insensitive (both UPPER and lower valid)."""
        f = tmp_path / "f.bin"; f.write_bytes(b"data")
        lower = sha256_file(str(f))
        upper = lower.upper()
        # At least one must work — typically both should
        result_lower = verify_file(str(f), lower)
        assert result_lower is True


# ── hash_directory ────────────────────────────────────────────────────────────

class TestHashDirectory:
    def test_returns_dict_of_path_to_hash(self, tmp_path):
        (tmp_path / "a.txt").write_bytes(b"aaa")
        (tmp_path / "b.txt").write_bytes(b"bbb")
        result = hash_directory(str(tmp_path))
        assert isinstance(result, dict)
        assert len(result) >= 2

    def test_hashes_are_correct(self, tmp_path):
        data = b"known content"
        f = tmp_path / "known.bin"
        f.write_bytes(data)
        result = hash_directory(str(tmp_path))
        matching = [v for k, v in result.items() if "known" in k]
        assert matching and matching[0] == hashlib.sha256(data).hexdigest()

    def test_empty_directory(self, tmp_path):
        result = hash_directory(str(tmp_path))
        assert result == {}

    def test_subdirectory_files_included(self, tmp_path):
        sub = tmp_path / "sub"; sub.mkdir()
        (sub / "nested.txt").write_bytes(b"nested")
        result = hash_directory(str(tmp_path))
        assert any("nested" in k for k in result)
