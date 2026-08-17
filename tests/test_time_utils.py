"""
Unit tests — forensiq.core.time_utils (Phase 10)

Covers: UTC "now" storage format, UTC -> IST conversion (+05:30),
midnight/date rollover in both directions, parsing of existing/legacy
stored timestamps (never reinterpreted as local), dual-line HTML/PDF/
plain formatting, and epoch (file-system) timestamp handling.
"""

from datetime import datetime, timezone

import pytest

from forensiq.core.time_utils import (
    DEFAULT_SECONDARY_TZ,
    SUPPORTED_TIMEZONES,
    display_lines,
    format_dual_html,
    format_dual_pdf,
    format_dual_plain,
    format_epoch_utc,
    format_in_tz,
    format_utc,
    now_utc,
    now_utc_str,
    parse_stored,
)


# ── now_utc / now_utc_str ────────────────────────────────────────────────────

class TestNowUtc:
    def test_now_utc_is_aware(self):
        dt = now_utc()
        assert dt.tzinfo is not None
        assert dt.utcoffset().total_seconds() == 0

    def test_now_utc_str_format(self):
        s = now_utc_str()
        assert s.endswith(" UTC")
        # 'YYYY-MM-DD HH:MM:SS UTC' -> 19 date/time chars + ' UTC'
        assert len(s) == 23
        datetime.strptime(s[:-4], "%Y-%m-%d %H:%M:%S")  # doesn't raise

    def test_now_utc_str_roundtrips_through_parse_stored(self):
        s = now_utc_str()
        dt = parse_stored(s)
        assert dt is not None
        assert format_utc(dt) == s


# ── UTC -> IST conversion ────────────────────────────────────────────────────

class TestUtcToIstConversion:
    def test_known_offset_plus_5_30(self):
        dt = datetime(2026, 8, 15, 4, 44, 29, tzinfo=timezone.utc)
        assert format_in_tz(dt, "IST") == "2026-08-15 10:14:29 IST"

    def test_ist_offset_is_exactly_5h30m(self):
        dt = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        ist = dt.astimezone(SUPPORTED_TIMEZONES["IST"])
        assert ist.utcoffset().total_seconds() == (5 * 3600 + 30 * 60)

    def test_ist_has_no_dst_shift_across_year(self):
        """IST is a fixed UTC+05:30 offset year-round — no DST."""
        summer = datetime(2026, 6, 21, 12, 0, 0, tzinfo=timezone.utc)
        winter = datetime(2026, 12, 21, 12, 0, 0, tzinfo=timezone.utc)
        off_summer = summer.astimezone(SUPPORTED_TIMEZONES["IST"]).utcoffset()
        off_winter = winter.astimezone(SUPPORTED_TIMEZONES["IST"]).utcoffset()
        assert off_summer.total_seconds() == off_winter.total_seconds() == 5.5 * 3600


# ── Midnight / date rollover ─────────────────────────────────────────────────

class TestMidnightRollover:
    def test_utc_late_evening_rolls_to_next_day_ist(self):
        # 19:00 UTC + 5:30 = 00:30 next day IST
        dt = datetime(2026, 8, 14, 19, 0, 0, tzinfo=timezone.utc)
        assert format_in_tz(dt, "IST") == "2026-08-15 00:30:00 IST"

    def test_utc_just_before_rollover_stays_same_day(self):
        dt = datetime(2026, 8, 14, 18, 29, 59, tzinfo=timezone.utc)
        assert format_in_tz(dt, "IST") == "2026-08-14 23:59:59 IST"

    def test_utc_midnight_is_mid_morning_ist(self):
        dt = datetime(2026, 8, 15, 0, 0, 0, tzinfo=timezone.utc)
        assert format_in_tz(dt, "IST") == "2026-08-15 05:30:00 IST"


# ── Parsing existing/stored timestamps ───────────────────────────────────────

class TestParseStored:
    def test_canonical_utc_suffixed_format(self):
        dt = parse_stored("2026-08-15 04:44:29 UTC")
        assert dt == datetime(2026, 8, 15, 4, 44, 29, tzinfo=timezone.utc)

    def test_iso_with_z_suffix(self):
        dt = parse_stored("2026-08-15T04:44:29Z")
        assert dt == datetime(2026, 8, 15, 4, 44, 29, tzinfo=timezone.utc)

    def test_iso_with_explicit_offset_converted_to_utc(self):
        dt = parse_stored("2026-08-15T10:14:29+05:30")
        assert dt == datetime(2026, 8, 15, 4, 44, 29, tzinfo=timezone.utc)

    def test_bare_no_suffix_timestamp_assumed_utc_not_local(self):
        """A bare legacy timestamp must be treated as UTC, never local."""
        dt = parse_stored("2026-08-15 04:44:29")
        assert dt == datetime(2026, 8, 15, 4, 44, 29, tzinfo=timezone.utc)

    def test_naive_datetime_object_assumed_utc_not_local(self):
        naive = datetime(2026, 8, 15, 4, 44, 29)
        dt = parse_stored(naive)
        assert dt == datetime(2026, 8, 15, 4, 44, 29, tzinfo=timezone.utc)

    def test_aware_non_utc_datetime_converted_to_utc(self):
        aware = datetime(2026, 8, 15, 10, 14, 29, tzinfo=SUPPORTED_TIMEZONES["IST"])
        dt = parse_stored(aware)
        assert dt == datetime(2026, 8, 15, 4, 44, 29, tzinfo=timezone.utc)

    def test_none_returns_none(self):
        assert parse_stored(None) is None

    def test_empty_string_returns_none(self):
        assert parse_stored("") is None

    def test_garbage_returns_none_not_raise(self):
        assert parse_stored("not a timestamp") is None


# ── Dual-line display formatting ─────────────────────────────────────────────

class TestDisplayLines:
    def test_default_secondary_is_ist(self):
        assert DEFAULT_SECONDARY_TZ == "IST"

    def test_returns_utc_and_secondary(self):
        lines = display_lines("2026-08-15 04:44:29 UTC")
        assert lines["utc"] == "2026-08-15 04:44:29 UTC"
        assert lines["secondary"] == "2026-08-15 10:14:29 IST"
        assert lines["secondary_tz"] == "IST"

    def test_none_for_empty_input(self):
        assert display_lines("") is None
        assert display_lines(None) is None


class TestFormatDualPlain:
    def test_two_lines_joined(self):
        out = format_dual_plain("2026-08-15 04:44:29 UTC")
        assert out == "2026-08-15 04:44:29 UTC\n2026-08-15 10:14:29 IST"

    def test_dash_for_missing(self):
        assert format_dual_plain(None) == "\u2014"


class TestFormatDualHtml:
    def test_contains_both_labelled_lines(self):
        out = format_dual_html("2026-08-15 04:44:29 UTC")
        assert "2026-08-15 04:44:29 UTC" in out
        assert "2026-08-15 10:14:29 IST" in out
        assert "<br>" in out
        assert "tz-secondary" in out

    def test_escapes_html(self):
        out = format_dual_html("2026-08-15 04:44:29 UTC", css_class='"><script>')
        assert "<script>" not in out

    def test_dash_for_missing(self):
        assert format_dual_html(None) == "\u2014"


class TestFormatDualPdf:
    def test_contains_reportlab_br_tag(self):
        out = format_dual_pdf("2026-08-15 04:44:29 UTC")
        assert "<br/>" in out
        assert "2026-08-15 04:44:29 UTC" in out
        assert "2026-08-15 10:14:29 IST" in out

    def test_dash_for_missing(self):
        assert format_dual_pdf(None) == "\u2014"


# ── Epoch (file-system) timestamps ───────────────────────────────────────────

class TestFormatEpochUtc:
    def test_known_epoch(self):
        # 2026-08-15 04:44:29 UTC
        epoch = datetime(2026, 8, 15, 4, 44, 29, tzinfo=timezone.utc).timestamp()
        assert format_epoch_utc(epoch) == "2026-08-15 04:44:29 UTC"

    def test_epoch_zero(self):
        assert format_epoch_utc(0) == "1970-01-01 00:00:00 UTC"

    def test_result_always_ends_with_utc_label(self):
        """Guards against the Phase 1-9 bug: fromtimestamp() with no tz
        silently used the host's local time and never labelled it."""
        assert format_epoch_utc(1_755_000_000).endswith(" UTC")
