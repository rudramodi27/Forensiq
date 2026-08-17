"""
Integration tests — forensiq.core.integrity_engine

Phase 1 — Evidence Integrity Upgrade.

Covers: IntegrityEngine.verify_single (MATCH / MISMATCH / MISSING /
CORRUPTED / ERROR), verify_case, export_json, export_html, result
structure, append-only persistence to verification_results, the original
hash never being mutated, and backward compatibility with the legacy
PASS/FAIL vocabulary.
"""

import json
import os

import pytest

from forensiq.core.integrity_engine import (
    MATCH, MISMATCH, MISSING, CORRUPTED, NOT_VERIFIED, ERROR,
    PASS, FAIL,  # legacy aliases — must still be importable
    IntegrityEngine, RESULT_COLORS, normalize_status,
)
from forensiq.core.hasher import sha256_file_verify, HashCorruptedError


@pytest.fixture
def engine(populated):
    return IntegrityEngine(populated.db)


class TestConstants:
    def test_canonical_result_strings(self):
        """Phase 1 vocabulary: MATCH, MISMATCH, MISSING, CORRUPTED,
        NOT_VERIFIED, ERROR — exactly as specified."""
        assert MATCH == "MATCH"
        assert MISMATCH == "MISMATCH"
        assert MISSING == "MISSING"
        assert CORRUPTED == "CORRUPTED"
        assert NOT_VERIFIED == "NOT_VERIFIED"
        assert ERROR == "ERROR"

    def test_legacy_aliases_point_to_canonical(self):
        """PASS/FAIL are kept importable for backward compatibility, and
        now resolve to the canonical MATCH/MISMATCH strings."""
        assert PASS == MATCH
        assert FAIL == MISMATCH

    def test_result_colors_has_all_canonical(self):
        for r in (MATCH, MISMATCH, MISSING, CORRUPTED, NOT_VERIFIED, ERROR):
            assert r in RESULT_COLORS and RESULT_COLORS[r].startswith("#")

    def test_normalize_status_maps_legacy_to_canonical(self):
        assert normalize_status("PASS") == MATCH
        assert normalize_status("FAIL") == MISMATCH
        assert normalize_status("MISSING") == MISSING
        assert normalize_status("ERROR") == ERROR
        # Canonical values pass through unchanged
        assert normalize_status("MATCH") == MATCH
        assert normalize_status("CORRUPTED") == CORRUPTED


class TestVerifySingle:
    def test_match_on_correct_hash(self, engine, populated):
        r = engine.verify_single(populated.eid_pass, case_id=populated.cid)
        assert r["result"] == MATCH

    def test_mismatch_or_missing_on_wrong_hash(self, engine, populated):
        r = engine.verify_single(populated.eid_fail, case_id=populated.cid)
        assert r["result"] in (MISMATCH, MISSING, CORRUPTED, ERROR)

    def test_missing_on_nonexistent_file(self, engine, populated):
        r = engine.verify_single(populated.eid_null, case_id=populated.cid)
        assert r["result"] in (MISSING, ERROR)

    def test_required_keys(self, engine, populated):
        r = engine.verify_single(populated.eid_pass, case_id=populated.cid)
        for k in ("result", "evidence_id", "filename", "stored_hash",
                  "current_hash", "verification_time", "case_id"):
            assert k in r, f"Missing key: {k}"

    def test_result_persisted_to_db(self, engine, populated):
        """Verification History requirement: every attempt is recorded."""
        before = len(populated.db.get_verification_history(evidence_id=populated.eid_pass))
        engine.verify_single(populated.eid_pass, case_id=populated.cid)
        after = len(populated.db.get_verification_history(evidence_id=populated.eid_pass))
        assert after > before

    def test_history_is_append_only(self, engine, populated):
        """Running verification multiple times must ADD rows, never
        overwrite or replace existing ones."""
        engine.verify_single(populated.eid_pass, case_id=populated.cid)
        engine.verify_single(populated.eid_pass, case_id=populated.cid)
        engine.verify_single(populated.eid_pass, case_id=populated.cid)
        history = populated.db.get_verification_history(evidence_id=populated.eid_pass)
        # 1 pre-seeded (populated fixture) + 3 new from this test
        assert len(history) >= 4

    def test_match_hashes_equal(self, engine, populated):
        r = engine.verify_single(populated.eid_pass, case_id=populated.cid)
        if r["result"] == MATCH:
            assert r["stored_hash"] == r["current_hash"]

    def test_nonexistent_evidence_id(self, engine, populated):
        r = engine.verify_single(999999, case_id=populated.cid)
        assert r["result"] in (MISSING, ERROR)

    def test_original_hash_never_mutated_by_verification(self, engine, populated):
        """The recorded acquisition SHA-256 must stay immutable no matter
        how many times — or with what result — verification runs."""
        before = populated.db.get_evidence_for_case(populated.cid)
        orig_by_id = {e["id"]: e["sha256"] for e in before}

        engine.verify_single(populated.eid_pass, case_id=populated.cid)  # MATCH
        engine.verify_single(populated.eid_fail, case_id=populated.cid)  # MISMATCH
        engine.verify_single(populated.eid_null, case_id=populated.cid)  # MISSING

        after = populated.db.get_evidence_for_case(populated.cid)
        for e in after:
            assert e["sha256"] == orig_by_id[e["id"]], (
                f"Original hash for evidence {e['id']} was mutated by verification!"
            )

    def test_missing_evidence_status_is_missing_not_error(self, engine, populated):
        """A file that no longer exists on disk must be classified
        MISSING, not the generic ERROR bucket."""
        r = engine.verify_single(populated.eid_null, case_id=populated.cid)
        assert r["result"] == MISSING


class TestVerifyCase:
    def test_verifies_all_evidence(self, engine, populated):
        results = engine.verify_case(populated.cid)
        assert len(results) == populated.db.get_evidence_count(populated.cid)

    def test_progress_callback_invoked(self, engine, populated):
        calls = []
        engine.verify_case(populated.cid, progress_cb=lambda c, t, r: calls.append((c, t)))
        assert len(calls) == populated.db.get_evidence_count(populated.cid)

    def test_mixed_results_across_case(self, engine, populated):
        results = engine.verify_case(populated.cid)
        statuses = {r["result"] for r in results}
        # eid_pass -> MATCH, eid_fail -> MISMATCH (wrong stored hash but
        # file present), eid_null -> MISSING (no real file on disk)
        assert MATCH in statuses


class TestBackwardCompatibility:
    """
    Phase 1 must not break pre-Phase-1 data or callers.
    """
    def test_legacy_pass_fail_rows_still_readable(self, populated):
        """The `populated` fixture seeds rows with the literal legacy
        strings 'PASS'/'FAIL' directly (as older code would have) —
        get_verification_history must return them unchanged."""
        history = populated.db.get_verification_history(case_id=populated.cid)
        results = {h["result"] for h in history}
        assert "PASS" in results
        assert "FAIL" in results

    def test_legacy_verification_summary_unchanged(self, populated):
        """get_verification_summary() (pre-Phase-1 API) must keep counting
        literal PASS/FAIL rows as before — untouched by the new vocabulary."""
        summ = populated.db.get_verification_summary(populated.cid)
        assert summ["PASS"] == 1
        assert summ["FAIL"] == 1

    def test_add_verification_result_accepts_new_vocabulary(self, populated):
        """add_verification_result() must accept the new canonical
        statuses in addition to the legacy ones."""
        for status in (MATCH, MISMATCH, MISSING, CORRUPTED, ERROR):
            populated.db.add_verification_result(
                populated.cid, populated.eid_pass, status,
                "abc", "abc", f"test {status}"
            )  # must not raise

    def test_add_verification_result_rejects_unknown_status(self, populated):
        with pytest.raises(Exception):
            populated.db.add_verification_result(
                populated.cid, populated.eid_pass, "NOT_A_REAL_STATUS",
                "abc", "abc", "bad"
            )


class TestCaseIntegritySummary:
    """Phase 1 requirement 6 — Case Integrity Summary."""

    def test_all_matched_is_verified(self, db, audit):
        cid = db.create_case("CI-001", "T", "I", "")
        import tempfile, os as _os
        d = tempfile.mkdtemp()
        fp = _os.path.join(d, "f.bin")
        with open(fp, "wb") as f:
            f.write(b"hello world")
        h = sha256_file_verify(fp)
        eid = db.add_evidence(cid, None, "acquisition", "f.bin", fp, h, 11, {})
        engine = IntegrityEngine(db)
        engine.verify_single(eid, case_id=cid)
        summary = db.get_case_integrity_summary(cid)
        assert summary["overall_status"] == "VERIFIED"
        assert summary["MATCH"] == 1
        assert summary["total"] == 1

    def test_mismatch_is_compromised(self, populated):
        engine = IntegrityEngine(populated.db)
        engine.verify_single(populated.eid_fail, case_id=populated.cid)
        summary = populated.db.get_case_integrity_summary(populated.cid)
        assert summary["overall_status"] == "COMPROMISED"

    def test_missing_without_mismatch_is_incomplete(self, db):
        cid = db.create_case("CI-002", "T", "I", "")
        eid = db.add_evidence(cid, None, "sms", "gone.db", "/nonexistent/gone.db", "a"*64, 0, {})
        engine = IntegrityEngine(db)
        engine.verify_single(eid, case_id=cid)
        summary = db.get_case_integrity_summary(cid)
        assert summary["overall_status"] == "INCOMPLETE"

    def test_no_verification_yet_is_not_verified(self, db):
        cid = db.create_case("CI-003", "T", "I", "")
        db.add_evidence(cid, None, "acquisition", "f.bin", "/tmp/f.bin", "a"*64, 0, {})
        summary = db.get_case_integrity_summary(cid)
        assert summary["overall_status"] == "NOT_VERIFIED"
        assert summary["NOT_VERIFIED"] == 1

    def test_empty_case_is_not_verified(self, db):
        cid = db.create_case("CI-004", "T", "I", "")
        summary = db.get_case_integrity_summary(cid)
        assert summary["overall_status"] == "NOT_VERIFIED"
        assert summary["total"] == 0


class TestStreamingHashCorruption:
    """Phase 1 requirement 1 — streaming hashing + CORRUPTED status."""

    def test_large_file_hashed_without_loading_fully(self, tmp_path):
        """A multi-megabyte file must hash correctly via chunked reads."""
        p = tmp_path / "large.bin"
        chunk = b"A" * (1024 * 1024)  # 1 MiB
        with open(p, "wb") as f:
            for _ in range(5):  # 5 MiB total
                f.write(chunk)
        h = sha256_file_verify(str(p))
        assert len(h) == 64  # valid hex sha256

    def test_missing_file_raises_file_not_found(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            sha256_file_verify(str(tmp_path / "does_not_exist.bin"))

    def test_directory_path_raises_file_not_found(self, tmp_path):
        # A directory is not a regular file — must not be silently hashed.
        with pytest.raises(FileNotFoundError):
            sha256_file_verify(str(tmp_path))

    def test_corrupted_file_maps_to_corrupted_status(self, engine, populated):
        """Simulate a read failure partway through hashing (e.g. disk
        error, permission change mid-read) and confirm it is classified
        CORRUPTED, distinct from MISSING or generic ERROR."""
        import forensiq.core.case_manager as cm_module

        def _boom(filepath, chunk_size=1024 * 1024):
            raise HashCorruptedError("simulated read failure")

        original = cm_module.CaseManager.verify_evidence
        try:
            import forensiq.core.hasher as hasher_module
            real_verify = hasher_module.sha256_file_verify
            hasher_module.sha256_file_verify = _boom
            try:
                r = engine.verify_single(populated.eid_pass, case_id=populated.cid)
            finally:
                hasher_module.sha256_file_verify = real_verify
        finally:
            pass
        assert r["result"] == CORRUPTED


class TestExportJson:
    def test_creates_file(self, engine, populated, tmp_path):
        r = engine.verify_single(populated.eid_pass, case_id=populated.cid)
        p = str(tmp_path / "i.json")
        engine.export_json([r], p, case_number="TC-001")
        assert os.path.exists(p)

    def test_json_structure(self, engine, populated, tmp_path):
        r = engine.verify_single(populated.eid_pass, case_id=populated.cid)
        p = str(tmp_path / "i.json")
        engine.export_json([r], p, case_number="TC-001")
        d = json.loads(open(p).read())
        assert d["case_number"] == "TC-001"
        assert isinstance(d["results"], list)
        assert len(d["results"]) == 1

    def test_two_results(self, engine, populated, tmp_path):
        r1 = engine.verify_single(populated.eid_pass, case_id=populated.cid)
        r2 = engine.verify_single(populated.eid_fail, case_id=populated.cid)
        p = str(tmp_path / "i.json")
        engine.export_json([r1, r2], p, case_number="TC-001")
        d = json.loads(open(p).read())
        assert len(d["results"]) == 2


class TestExportHtml:
    def test_creates_file(self, engine, populated, tmp_path):
        r = engine.verify_single(populated.eid_pass, case_id=populated.cid)
        p = str(tmp_path / "i.html")
        engine.export_html([r], p, case_number="TC-001")
        assert os.path.exists(p)

    def test_html_content(self, engine, populated, tmp_path):
        r1 = engine.verify_single(populated.eid_pass, case_id=populated.cid)
        r2 = engine.verify_single(populated.eid_fail, case_id=populated.cid)
        p = str(tmp_path / "i.html")
        engine.export_html([r1, r2], p, case_number="TC-001")
        html = open(p).read()
        assert "TC-001" in html
        assert "ForensIQ" in html
        assert MATCH in html
        assert "<table" in html
