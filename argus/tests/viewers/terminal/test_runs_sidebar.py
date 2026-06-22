"""Unit tests for runs-sidebar row formatting.

Pure string/id helpers — no Textual needed. They pin what each run row
shows (current marker, severity glyph, label, count) and the id the app
maps back to a scan path.
"""

from __future__ import annotations

from argus.core.findings_view import SEVERITY_GLYPH
from argus.core.models import Severity
from argus.viewers.terminal.runs_sidebar import (
    format_run_row,
    run_glyph,
    run_option_id,
)


class TestRunGlyph:
    def test_severity_maps_to_findings_glyph(self):
        assert run_glyph(Severity.CRITICAL) == SEVERITY_GLYPH[Severity.CRITICAL]

    def test_none_is_neutral_not_a_severity(self):
        glyph = run_glyph(None)
        assert "none" in glyph
        # Must not borrow any severity's glyph for a clean run.
        assert glyph not in SEVERITY_GLYPH.values()


class TestFormatRunRow:
    def _run(self, **kw):
        base = {
            "label": "2026-06-12",
            "count": 7,
            "worst_severity": Severity.HIGH,
            "path": "/runs/2026-06-12",
        }
        base.update(kw)
        return base

    def test_current_run_is_marked(self):
        row = format_run_row(self._run(), current=True)
        assert row.startswith("●")
        assert "2026-06-12" in row
        assert "7" in row

    def test_non_current_run_has_no_filled_marker(self):
        row = format_run_row(self._run(), current=False)
        assert not row.startswith("●")

    def test_worst_severity_glyph_present(self):
        row = format_run_row(self._run(worst_severity=Severity.CRITICAL), current=False)
        assert SEVERITY_GLYPH[Severity.CRITICAL] in row

    def test_clean_run_shows_neutral_glyph(self):
        row = format_run_row(self._run(worst_severity=None, count=0), current=False)
        assert "none" in row

    def test_missing_keys_degrade_safely(self):
        # A partial dict (no label/count/severity) must not raise.
        row = format_run_row({}, current=False)
        assert "(run)" in row
        assert "0" in row


class TestRunOptionId:
    def test_uses_path(self):
        assert run_option_id({"path": "/runs/x"}) == "/runs/x"

    def test_missing_path_is_empty_string(self):
        assert run_option_id({}) == ""
