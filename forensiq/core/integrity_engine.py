"""
IntegrityEngine — Evidence Integrity Verification Service.

Provides:
  - verify_single()  : verify one evidence item, persist result
  - verify_case()    : verify all evidence in a case
  - verify_all()     : verify every evidence item across all cases
  - export_json()    : write verification_report.json
  - export_html()    : write verification_report.html

All verification events are persisted to verification_results table.
Reuses existing sha256_file_verify() from hasher.py — no duplicate hashing
code. CaseManager.verify_evidence() (also updated in Phase 1) still does
the actual hash check; this module owns interpreting the result into a
forensic status and persisting/reporting it.

Phase 1 — Evidence Integrity Upgrade:
  - Status vocabulary expanded to MATCH / MISMATCH / MISSING / CORRUPTED /
    NOT_VERIFIED / ERROR. PASS/FAIL are kept as backward-compatible aliases
    (PASS == MATCH, FAIL == MISMATCH) so any older code importing those
    names still behaves correctly — but note the *string value* changes
    (PASS now equals "MATCH", not "PASS"). Rows written to the DB before
    this upgrade may still contain the literal strings "PASS"/"FAIL"; read
    paths (UI, reports, summaries) treat those as legacy synonyms.
  - PyQt6 import is now optional/lazy: IntegrityEngine itself has no Qt
    dependency and can be unit-tested headless. Only VerificationWorker
    (a QThread) needs Qt, and only if it's actually instantiated.
"""

import json
import os
import logging
from datetime import datetime, timezone
from typing import Optional

from forensiq.core.hasher import sha256_file_verify, HashCorruptedError
from forensiq.core.case_manager import CaseManager
from forensiq.core.time_utils import now_utc_str

logger = logging.getLogger("forensiq.integrity")


# ── Result constants (canonical, Phase 1 vocabulary) ───────────────────────────

MATCH        = "MATCH"         # recalculated hash == original hash
MISMATCH     = "MISMATCH"      # recalculated hash != original hash
MISSING      = "MISSING"       # file no longer exists on disk
CORRUPTED    = "CORRUPTED"     # file exists but could not be fully/reliably read
NOT_VERIFIED = "NOT_VERIFIED"  # no verification has ever been run (default state)
ERROR        = "ERROR"         # unexpected error outside the above cases

# Backward-compatible aliases for pre-Phase-1 callers/tests that import
# PASS/FAIL by name. Values now point at the canonical strings.
PASS = MATCH
FAIL = MISMATCH

# Legacy status strings that may already exist in older verification_results
# rows, mapped to their canonical Phase 1 equivalent — used by read paths
# (summaries, UI, reports) so old data displays correctly without rewriting
# history.
LEGACY_STATUS_MAP = {
    "PASS": MATCH,
    "FAIL": MISMATCH,
    "MISSING": MISSING,
    "ERROR": ERROR,
}


def normalize_status(result: str) -> str:
    """Map a legacy or canonical status string to the canonical vocabulary."""
    return LEGACY_STATUS_MAP.get(result, result)


RESULT_COLORS = {
    MATCH:        "#3FB950",
    MISMATCH:     "#F85149",
    MISSING:      "#E3B341",
    CORRUPTED:    "#F85149",
    NOT_VERIFIED: "#8B949E",
    ERROR:        "#8B949E",
}


# ── Integrity Engine ───────────────────────────────────────────────────────────

class IntegrityEngine:
    """
    Forensic-grade integrity verification.
    Uses existing CaseManager.verify_evidence() for hash comparison,
    then persists every event to verification_results.
    """

    def __init__(self, db: CaseManager):
        self.db = db

    # ── Core verify methods ────────────────────────────────────────────────────

    def verify_single(self, evidence_id: int,
                      case_id: Optional[int] = None) -> dict:
        """
        Verify one evidence item.
        Returns result dict and persists to verification_results.
        """
        logger.info("Verification started — evidence_id=%s", evidence_id)

        # Fetch evidence record
        ev_list = None
        if case_id is None:
            # look up case_id from evidence table
            with self.db._connect() as conn:
                row = conn.execute(
                    "SELECT case_id FROM evidence WHERE id = ?", (evidence_id,)
                ).fetchone()
                if row:
                    case_id = row["case_id"]

        # Delegate hash check to existing verify_evidence()
        raw = self.db.verify_evidence(evidence_id)

        result = self._build_result(evidence_id, case_id, raw)

        # Persist
        if case_id is not None:
            try:
                self.db.add_verification_result(
                    case_id=case_id,
                    evidence_id=evidence_id,
                    result=result["result"],
                    stored_hash=result["stored_hash"],
                    current_hash=result["current_hash"],
                    notes=result.get("notes", ""),
                )
            except Exception as e:
                logger.error("Failed to persist verification result: %s", e)

        level = logging.WARNING if result["result"] in (MISMATCH, MISSING, CORRUPTED, ERROR) else logging.INFO
        logger.log(level, "Verification completed — evidence_id=%s result=%s",
                   evidence_id, result["result"])
        return result

    def verify_case(self, case_id: int,
                    progress_cb=None) -> list[dict]:
        """
        Verify all evidence in a case.
        progress_cb(current: int, total: int, result: dict)
        """
        logger.info("Case verification started — case_id=%s", case_id)
        evidence = self.db.get_evidence_for_case(case_id)
        ev_list  = list(evidence)
        results  = []
        total    = len(ev_list)

        for i, ev in enumerate(ev_list):
            r = self.verify_single(ev["id"], case_id=case_id)
            results.append(r)
            if progress_cb:
                progress_cb(i + 1, total, r)

        matched  = sum(1 for r in results if r["result"] == MATCH)
        mismatch = sum(1 for r in results if r["result"] == MISMATCH)
        missing  = sum(1 for r in results if r["result"] == MISSING)
        logger.info(
            "Case verification complete — case_id=%s total=%d match=%d mismatch=%d missing=%d",
            case_id, total, matched, mismatch, missing
        )
        return results

    def verify_all(self, progress_cb=None) -> dict:
        """
        Verify every evidence item across all cases.
        Returns {case_id: [result, ...]}
        """
        logger.info("Full verification started")
        cases = self.db.get_all_cases()
        all_results: dict[int, list[dict]] = {}

        for case in cases:
            cid = case["id"]

            def _cb(cur, tot, r, cid=cid):
                if progress_cb:
                    progress_cb(cid, cur, tot, r)

            all_results[cid] = self.verify_case(cid, progress_cb=_cb)

        logger.info("Full verification complete — %d cases", len(all_results))
        return all_results

    # ── Export ─────────────────────────────────────────────────────────────────

    def export_json(self, results: list[dict], output_path: str,
                    case_id: Optional[int] = None,
                    case_number: str = "") -> str:
        """Write verification_report.json."""
        payload = {
            "report_type":     "ForensIQ Integrity Verification",
            "generated_at":    now_utc_str(),
            "case_id":         case_id,
            "case_number":     case_number,
            "total":           len(results),
            "match":           sum(1 for r in results if r["result"] == MATCH),
            "mismatch":        sum(1 for r in results if r["result"] == MISMATCH),
            "missing":         sum(1 for r in results if r["result"] == MISSING),
            "corrupted":       sum(1 for r in results if r["result"] == CORRUPTED),
            "error":           sum(1 for r in results if r["result"] == ERROR),
            "results":         results,
        }
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, default=str)
        logger.info("JSON report written: %s", output_path)
        return output_path

    def export_html(self, results: list[dict], output_path: str,
                    case_id: Optional[int] = None,
                    case_number: str = "") -> str:
        """Write verification_report.html."""
        import html as html_lib

        def esc(v) -> str:
            return html_lib.escape(str(v or ""))

        total     = len(results)
        matched   = sum(1 for r in results if r["result"] == MATCH)
        mismatch  = sum(1 for r in results if r["result"] == MISMATCH)
        missing   = sum(1 for r in results if r["result"] == MISSING)
        corrupted = sum(1 for r in results if r["result"] == CORRUPTED)
        errors    = sum(1 for r in results if r["result"] == ERROR)
        ts        = now_utc_str()

        badge_color = RESULT_COLORS

        rows = "\n".join(
            f"""<tr>
              <td class="mono">{esc(r.get('evidence_id','—'))}</td>
              <td>{esc(r.get('filename','—'))}</td>
              <td>{esc(r.get('category','—'))}</td>
              <td><span class="badge" style="background:{badge_color.get(r['result'],'#555')}20;
                  color:{badge_color.get(r['result'],'#ccc')};border:1px solid {badge_color.get(r['result'],'#555')}40">
                  {esc(r['result'])}</span></td>
              <td class="mono small">{esc((r.get('stored_hash','') or '')[:32])}{'…' if r.get('stored_hash') else ''}</td>
              <td class="mono small">{esc((r.get('current_hash','') or '')[:32])}{'…' if r.get('current_hash') else ''}</td>
              <td class="mono">{esc(r.get('verification_time',''))}</td>
              <td>{esc(r.get('notes',''))}</td>
            </tr>"""
            for r in results
        )

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ForensIQ — Integrity Report {esc(case_number)}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',Arial,sans-serif;background:#0d1117;color:#e6edf3;padding:2rem;font-size:13px}}
h1{{color:#1d9e75;font-size:24px;margin-bottom:6px}}
h2{{color:#1d9e75;font-size:14px;margin:1.8rem 0 0.6rem;padding-left:10px;border-left:3px solid #1d9e75;text-transform:uppercase;letter-spacing:.05em}}
.meta{{color:#8b949e;font-size:12px;margin-bottom:1.5rem}}
.grid{{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-bottom:1.5rem}}
.card{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1rem;text-align:center}}
.card .num{{font-size:26px;font-weight:600}}.card .lbl{{font-size:11px;color:#8b949e;margin-top:3px}}
.section{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1rem;overflow-x:auto;margin-bottom:1.5rem}}
table{{width:100%;border-collapse:collapse;font-size:12px}}
th{{background:#21262d;color:#8b949e;padding:7px 8px;text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.04em;border-bottom:1px solid #30363d}}
td{{padding:6px 8px;border-bottom:1px solid #21262d;vertical-align:middle}}
tr:hover td{{background:#1c2128}}
.mono{{font-family:'Courier New',monospace}}.small{{font-size:10px}}
.badge{{padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600}}
.footer{{margin-top:2rem;font-size:11px;color:#30363d;border-top:1px solid #21262d;padding-top:1rem;text-align:center}}
</style>
</head>
<body>
<h1>🔐 ForensIQ — Evidence Integrity Report</h1>
<div class="meta">
  <strong>Case:</strong> {esc(case_number) or '—'} &nbsp;·&nbsp;
  <strong>Generated:</strong> {ts} &nbsp;·&nbsp;
  <strong>Total Evidence Items:</strong> {total}
</div>
<div class="grid">
  <div class="card"><div class="num" style="color:#e6edf3">{total}</div><div class="lbl">Total</div></div>
  <div class="card"><div class="num" style="color:#3fb950">{matched}</div><div class="lbl">MATCH</div></div>
  <div class="card"><div class="num" style="color:#f85149">{mismatch}</div><div class="lbl">MISMATCH</div></div>
  <div class="card"><div class="num" style="color:#e3b341">{missing}</div><div class="lbl">MISSING</div></div>
  <div class="card"><div class="num" style="color:#f85149">{corrupted}</div><div class="lbl">CORRUPTED</div></div>
  <div class="card"><div class="num" style="color:#8b949e">{errors}</div><div class="lbl">ERROR</div></div>
</div>
<h2>Verification Results</h2>
<div class="section">
<table>
<thead><tr>
  <th>Ev.ID</th><th>Filename</th><th>Category</th><th>Result</th>
  <th>Stored SHA-256</th><th>Current SHA-256</th><th>Verified At</th><th>Notes</th>
</tr></thead>
<tbody>{rows or '<tr><td colspan="8" style="color:#8b949e">No results.</td></tr>'}</tbody>
</table>
</div>
<div class="footer">
  ForensIQ Integrity Engine &nbsp;·&nbsp; {ts} &nbsp;·&nbsp;
  All SHA-256 hashes computed at verification time.
</div>
</body></html>"""

        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(html)
        logger.info("HTML report written: %s", output_path)
        return output_path

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _build_result(self, evidence_id: int,
                      case_id: Optional[int],
                      raw: dict) -> dict:
        """
        Convert CaseManager.verify_evidence() raw dict to normalised result dict.
        Maps: match=True → MATCH, match=False → MISMATCH,
              status="MISSING"/"CORRUPTED"/"ERROR" → same.
        """
        # Fetch filename/category for richer output
        filename = category = ""
        try:
            with self.db._connect() as conn:
                row = conn.execute(
                    "SELECT filename, category FROM evidence WHERE id = ?",
                    (evidence_id,)
                ).fetchone()
                if row:
                    filename = row["filename"] or ""
                    category = row["category"] or ""
        except Exception:
            pass

        stored  = raw.get("stored", "")
        current = raw.get("current", "")
        ts      = now_utc_str()

        # CaseManager.verify_evidence() (Phase 1) returns an explicit
        # "status" field distinguishing MISSING / CORRUPTED / ERROR instead
        # of a single opaque "error" string — use it when present, but stay
        # tolerant of the pre-Phase-1 shape (just "error"/"match") too.
        status = raw.get("status")

        if status == "MISSING" or (status is None and "error" in raw
                                    and "not found" in raw["error"].lower()):
            result = MISSING
            notes  = raw.get("error", "Evidence file not found on disk.")
        elif status == "CORRUPTED":
            result = CORRUPTED
            notes  = raw.get("error", "File exists but could not be fully read.")
        elif status == "ERROR" or (status is None and "error" in raw):
            result = ERROR
            notes  = raw.get("error", "Unexpected verification error.")
        elif raw.get("match"):
            result = MATCH
            notes  = "Recalculated hash matches the original acquisition hash."
        else:
            result = MISMATCH
            notes  = (
                f"HASH MISMATCH — original: {stored[:16]}… "
                f"recalculated: {current[:16]}…"
            )

        return {
            "evidence_id":       evidence_id,
            "case_id":           case_id,
            "filename":          filename,
            "category":          category,
            "result":            result,
            "stored_hash":       stored,
            "current_hash":      current,
            "verification_time": ts,
            "notes":             notes,
        }


# ── Background Worker ──────────────────────────────────────────────────────────
#
# PyQt6 is imported lazily, inside __init__, rather than at module load
# time. This keeps IntegrityEngine (the actual verification logic above)
# importable and unit-testable in headless/non-Qt environments — only code
# that actually constructs a VerificationWorker needs PyQt6 installed.

try:
    from PyQt6.QtCore import QThread, pyqtSignal
    _QT_AVAILABLE = True
except ImportError:
    _QT_AVAILABLE = False
    QThread = object  # fallback base so the class body below still parses


class VerificationWorker(QThread):
    """
    Runs verify_case() or verify_all() on a background thread.
    Emits per-item results so the UI table updates in real time.
    """
    if _QT_AVAILABLE:
        progress     = pyqtSignal(int, int, str)    # current, total, message
        item_done    = pyqtSignal(dict)              # one completed result
        finished     = pyqtSignal(list)             # all results
        error        = pyqtSignal(str)

    def __init__(self, engine: IntegrityEngine,
                 mode: str,                      # "single" | "case" | "all"
                 case_id: Optional[int] = None,
                 evidence_id: Optional[int] = None):
        if not _QT_AVAILABLE:
            raise ImportError(
                "PyQt6 is required to run VerificationWorker in a "
                "background thread. IntegrityEngine itself does not "
                "require PyQt6 — call engine.verify_case()/verify_all() "
                "directly for headless use."
            )
        super().__init__()
        self.engine      = engine
        self.mode        = mode
        self.case_id     = case_id
        self.evidence_id = evidence_id
        self._abort      = False

    def abort(self):
        self._abort = True

    def run(self):
        try:
            results: list[dict] = []

            if self.mode == "single" and self.evidence_id is not None:
                r = self.engine.verify_single(self.evidence_id, self.case_id)
                results = [r]
                self.item_done.emit(r)
                self.progress.emit(1, 1, f"{r['result']}: {r['filename']}")

            elif self.mode == "case" and self.case_id is not None:
                ev_list = list(self.engine.db.get_evidence_for_case(self.case_id))
                total   = len(ev_list)

                for i, ev in enumerate(ev_list):
                    if self._abort:
                        break
                    r = self.engine.verify_single(ev["id"], self.case_id)
                    results.append(r)
                    self.item_done.emit(r)
                    self.progress.emit(
                        i + 1, total,
                        f"[{i+1}/{total}] {r['result']}: {r['filename'] or ev['id']}"
                    )

            elif self.mode == "all":
                all_ev = []
                for case in self.engine.db.get_all_cases():
                    evs = list(self.engine.db.get_evidence_for_case(case["id"]))
                    for ev in evs:
                        all_ev.append((case["id"], ev))
                total = len(all_ev)

                for i, (cid, ev) in enumerate(all_ev):
                    if self._abort:
                        break
                    r = self.engine.verify_single(ev["id"], cid)
                    results.append(r)
                    self.item_done.emit(r)
                    self.progress.emit(
                        i + 1, total,
                        f"[{i+1}/{total}] {r['result']}: {r['filename'] or ev['id']}"
                    )

            self.finished.emit(results)

        except Exception as e:
            logger.exception("VerificationWorker error")
            self.error.emit(str(e))
