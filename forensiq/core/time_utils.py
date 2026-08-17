"""
Time Utilities — centralized UTC/timezone handling for ForensIQ.

Phase 10 — Time Handling & Timezone Fix:

  Every prior phase computed "now, formatted as UTC" independently:
    case_manager.now_utc(), audit_service._ts(), signature_service._ts(),
    key_manager._now(), manifest_service._manifest_generated_at(),
    analyzer._now_iso()/_now_str(), two inline calls in
    integrity_engine.py, and seven near-identical
    `ts_gen = datetime.now(timezone.utc).strftime(...)` lines in
    reporter.py — eight-plus copies of the same one-liner, scattered
    across modules with no single place to add a second timezone,
    change the storage format, or fix a bug consistently.

  This module is now the ONLY place that touches the system clock or
  performs timezone conversion. Every module that previously defined
  its own `_now()`/`_ts()` imports `now_utc_str()` from here instead
  (see each module's changelog for the specific line removed).

  Storage contract (UNCHANGED from Phase 1-9):
    - Every timestamp written to the database is UTC, in the canonical
      "YYYY-MM-DD HH:MM:SS UTC" string produced by now_utc_str().
    - This module never rewrites, reformats, or reinterprets an
      existing stored timestamp — it only adds a shared place to
      *display* an already-stored UTC timestamp in a second timezone.
    - A stored timestamp is NEVER assumed to be local time. Every
      parse path below treats a bare (no-suffix) timestamp as UTC,
      because every timestamp this system has ever written is UTC.
"""

import html as _html_lib
from datetime import datetime, timezone
from typing import Optional
from zoneinfo import ZoneInfo

# Canonical storage/display format for a UTC timestamp — unchanged from
# Phase 1-9 (case_manager.now_utc() et al. all produced this exact shape).
UTC_STORAGE_FMT = "%Y-%m-%d %H:%M:%S UTC"
_BARE_FMT = "%Y-%m-%d %H:%M:%S"

# Timezones this build understands for secondary/display purposes.
# Requirement #4: "If the existing architecture supports user timezone
# preferences, use them; otherwise default the secondary display to
# IST." ForensIQ has no per-user preference store (checked: no
# settings/preferences module exists anywhere in forensiq/), so IST is
# the fixed default secondary display. tz_name is still a parameter
# everywhere below, so wiring in a real user preference later is a
# one-line change at each call site, not a redesign.
SUPPORTED_TIMEZONES = {
    "UTC": timezone.utc,
    "IST": ZoneInfo("Asia/Kolkata"),  # UTC+05:30, no DST
}
DEFAULT_SECONDARY_TZ = "IST"


# ── Clock / storage ─────────────────────────────────────────────────────────

def now_utc() -> datetime:
    """Current time as an aware UTC datetime. The single source of 'now'."""
    return datetime.now(timezone.utc)


def now_utc_str() -> str:
    """
    Current time formatted for STORAGE: 'YYYY-MM-DD HH:MM:SS UTC'.

    This replaces every module-local _now()/_ts()/now_utc()/_now_iso()/
    _now_str()/_manifest_generated_at() one-liner from Phase 1-9 — this
    is the only place that should be called to stamp a new row or
    generated-report timestamp with 'now'.
    """
    return format_utc(now_utc())


# ── Parsing existing/stored timestamps ──────────────────────────────────────

def parse_stored(ts) -> Optional[datetime]:
    """
    Parse an existing stored/serialized timestamp into an aware UTC
    datetime, WITHOUT ever reinterpreting it as local time.

    Accepts, in order of what's tried:
      - an existing datetime: naive -> tagged as UTC (never assumed
        local); aware -> converted to UTC.
      - 'YYYY-MM-DD HH:MM:SS UTC'  (the Phase 1-9 canonical format)
      - ISO 8601, with or without a 'Z'/offset suffix — a bare
        (offset-less) ISO value is treated as UTC, never local.
      - bare 'YYYY-MM-DD HH:MM:SS' with no suffix at all — also
        treated as UTC.
      - None / '' / unparsable -> None (caller shows '—', never a
        guessed value).

    This is the single choke point that enforces "no naive datetime is
    ever silently treated as local time" for every caller in the app.
    """
    if ts is None or ts == "":
        return None
    if isinstance(ts, datetime):
        return ts.astimezone(timezone.utc) if ts.tzinfo else ts.replace(tzinfo=timezone.utc)

    s = str(ts).strip()
    if not s:
        return None

    if s.endswith(" UTC"):
        try:
            return datetime.strptime(s[:-4], _BARE_FMT).replace(tzinfo=timezone.utc)
        except ValueError:
            pass

    iso_candidate = s.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(iso_candidate)
        return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        pass

    try:
        return datetime.strptime(s, _BARE_FMT).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


# ── Formatting for display ──────────────────────────────────────────────────

def format_utc(dt: datetime) -> str:
    """Format an aware datetime as 'YYYY-MM-DD HH:MM:SS UTC'."""
    return dt.astimezone(timezone.utc).strftime(UTC_STORAGE_FMT)


def format_in_tz(dt: datetime, tz_name: str = DEFAULT_SECONDARY_TZ) -> str:
    """Format an aware datetime as 'YYYY-MM-DD HH:MM:SS <TZ>' in tz_name."""
    tz = SUPPORTED_TIMEZONES.get(tz_name, SUPPORTED_TIMEZONES[DEFAULT_SECONDARY_TZ])
    return dt.astimezone(tz).strftime(_BARE_FMT) + f" {tz_name}"


def display_lines(ts, secondary_tz: str = DEFAULT_SECONDARY_TZ) -> Optional[dict]:
    """
    Given a stored UTC timestamp (str or datetime), return the two
    display lines every screen/report should show, e.g.:
        {"utc": "2026-08-15 04:44:29 UTC",
         "secondary": "2026-08-15 10:14:29 IST",
         "secondary_tz": "IST"}
    Returns None for an empty/unparsable input — callers render '—'
    rather than a fabricated timestamp.
    """
    dt = parse_stored(ts)
    if dt is None:
        return None
    return {
        "utc": format_utc(dt),
        "secondary": format_in_tz(dt, secondary_tz),
        "secondary_tz": secondary_tz,
    }


def format_dual_plain(ts, secondary_tz: str = DEFAULT_SECONDARY_TZ, sep: str = "\n") -> str:
    """Two-line plain-text rendering, e.g. for audit/CLI/log-style output."""
    lines = display_lines(ts, secondary_tz)
    if lines is None:
        return "\u2014"  # em dash
    return f'{lines["utc"]}{sep}{lines["secondary"]}'


def format_dual_html(ts, secondary_tz: str = DEFAULT_SECONDARY_TZ,
                      css_class: str = "tz-secondary") -> str:
    """
    Two-line HTML rendering for report/UI tables:
        2026-08-15 04:44:29 UTC
        2026-08-15 10:14:29 IST   (secondary line, smaller/muted via css_class)
    Output is already HTML-escaped and safe to insert directly.
    """
    lines = display_lines(ts, secondary_tz)
    if lines is None:
        return "\u2014"
    return (f'{_html_lib.escape(lines["utc"])}'
            f'<br><span class="{_html_lib.escape(css_class)}">'
            f'{_html_lib.escape(lines["secondary"])}</span>')


def format_dual_pdf(ts, secondary_tz: str = DEFAULT_SECONDARY_TZ) -> str:
    """
    Two-line rendering for ReportLab Paragraph cells (uses '<br/>' and
    an inline <font> tag for the muted secondary line, both of which
    ReportLab's mini-HTML parser supports).
    """
    lines = display_lines(ts, secondary_tz)
    if lines is None:
        return "\u2014"
    return (f'{lines["utc"]}<br/>'
            f'<font size="7" color="#8b949e">{lines["secondary"]}</font>')


# ── File-system (epoch) timestamps ──────────────────────────────────────────

def format_epoch_utc(epoch: float) -> str:
    """
    Format a POSIX epoch (e.g. os.stat().st_mtime/st_ctime) as a UTC
    storage string.

    Phase 10 fix: file-system timestamps (extract_file_metadata's
    created/modified/accessed, and build_file_timeline's file_created/
    file_modified events) previously used datetime.fromtimestamp(epoch)
    with no tz argument. That silently produces a NAIVE datetime in
    the *host machine's local* timezone, formatted with no timezone
    label at all — then that value was merged directly into the
    unified forensic timeline right alongside proper
    'YYYY-MM-DD HH:MM:SS UTC' rows. Depending on the host's local
    timezone this corrupted both the display (looked unlabelled, was
    actually local rather than UTC) and the timeline's chronological
    sort (a naive lexical string sort across mismatched timezones).
    This always produces an explicit, correctly-labelled UTC string.
    """
    return format_utc(datetime.fromtimestamp(epoch, tz=timezone.utc))
