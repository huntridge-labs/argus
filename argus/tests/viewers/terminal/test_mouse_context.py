"""Unit tests for the per-span hover / right-click helpers in app.py.

These run without spinning up a Textual ``App`` — the parser is a pure
function and the tooltip helpers are static methods that take a
``Finding`` and return a string, so the test surface is small and
deterministic.

Why this layer matters
----------------------
The mouse interaction in the TUI is data-driven: Textual emits a
``MouseDown`` carrying ``event.style.meta`` (the same payload the
``[@click=...]`` markup uses), and the app routes off that payload
instead of doing coordinate-arithmetic. Two pieces have to be right:

  1. ``_parse_click_action`` correctly recovers the action name + arg
     from the meta string (it's the discriminator for which context
     menu to push).
  2. The tooltip text helpers produce sensible strings for the things
     the cursor is on, so users get a useful preview before clicking.

Anything that touches Textual screens / event loops belongs in
``test_help.py`` or a Pilot-driven test, not here.
"""

from __future__ import annotations

import pytest

from argus.core.models import Finding, Severity
from argus.viewers.terminal.app import (
    BrowseApp,
    _parse_click_action,
)


class TestParseClickAction:
    """The regex underpins right-click routing — getting it wrong sends
    file-path clicks to the advisory handler and vice versa."""

    def test_file_path_with_line(self):
        action, arg = _parse_click_action(
            "app.action_open_location('/path/to/file.py:42')"
        )
        assert action == "action_open_location"
        assert arg == "/path/to/file.py:42"

    def test_cve_advisory(self):
        action, arg = _parse_click_action(
            "app.action_open_advisory('CVE-2024-12345')"
        )
        assert action == "action_open_advisory"
        assert arg == "CVE-2024-12345"

    def test_ghsa_advisory(self):
        action, arg = _parse_click_action(
            "app.action_open_advisory('GHSA-abcd-1234-efgh')"
        )
        assert action == "action_open_advisory"
        assert arg == "GHSA-abcd-1234-efgh"

    def test_double_quoted_arg(self):
        # Textual markup happens to emit single quotes today, but the
        # parser is permissive on quote style so a future change to
        # the markup generator doesn't silently break right-click.
        action, arg = _parse_click_action(
            'app.action_open_location("/path/to/file.py:42")'
        )
        assert action == "action_open_location"
        assert arg == "/path/to/file.py:42"

    def test_package_at_version(self):
        action, arg = _parse_click_action(
            "app.action_open_location('flask@3.0.0')"
        )
        assert action == "action_open_location"
        assert arg == "flask@3.0.0"

    @pytest.mark.parametrize("text", [
        "",                                  # empty
        "garbage",                           # not a function call
        "action_open_location('x')",         # missing ``app.`` prefix
        "app.action_open_location(/x)",      # missing quotes
        "app.action_open_location()",        # missing arg
    ])
    def test_malformed_returns_none(self, text):
        # Returning ``(None, None)`` is the contract — callers no-op
        # rather than crash on bad meta. This keeps the right-click
        # handler robust against future markup-shape changes.
        assert _parse_click_action(text) == (None, None)


class TestFindingTooltipText:
    """The DataTable hover tooltip is the primary preview affordance —
    if these don't carry the right signal, users have to commit a click
    just to triage."""

    def _finding(self, **kw) -> Finding:
        # All fields default to reasonable values so individual tests
        # can override only the bits they care about.
        defaults = dict(
            id="CVE-2024-99999",
            severity=Severity.HIGH,
            scanner="osv-scanner",
            title="Some vuln in flask",
            description=(
                "A really bad bug that lets anyone do anything they want "
                "to the server. Patch immediately."
            ),
            location="flask@3.0.0",
            metadata={"package": "flask", "installed_version": "3.0.0"},
        )
        defaults.update(kw)
        return Finding(**defaults)

    def test_includes_severity_id_package_and_description(self):
        f = self._finding()
        text = BrowseApp._finding_tooltip_text(f)
        assert "HIGH" in text
        assert "CVE-2024-99999" in text
        assert "flask@3.0.0" in text
        assert "A really bad bug" in text

    def test_truncates_long_descriptions(self):
        long = "x" * 500
        f = self._finding(description=long, title="short title")
        text = BrowseApp._finding_tooltip_text(f)
        # Bounded preview — the ellipsis marker is the contract that
        # tells the reader "there's more, click to see it".
        assert "…" in text
        # And it's actually shorter than the input.
        assert len(text) < 400

    def test_falls_back_to_title_when_no_description(self):
        f = self._finding(description="", title="title-only finding")
        text = BrowseApp._finding_tooltip_text(f)
        assert "title-only finding" in text

    def test_handles_missing_package_with_location_fallback(self):
        f = self._finding(
            metadata={},
            location="src/app.py:42",
        )
        text = BrowseApp._finding_tooltip_text(f)
        # Without ``package`` metadata, the location takes the package
        # slot — better than a bare em-dash for triage.
        assert "src/app.py:42" in text

    def test_handles_missing_description_and_title(self):
        f = self._finding(description="", title="")
        text = BrowseApp._finding_tooltip_text(f)
        # Empty preview shouldn't surface as a blank tooltip — explicit
        # placeholder text tells the user "the scanner gave us nothing".
        assert "no description" in text.lower()


class TestSpanTooltipText:
    """The detail-pane hover tooltip is action-aware so users see what
    *will* happen if they click — different action → different hint."""

    @pytest.fixture
    def app(self):
        # _span_tooltip_text doesn't touch any instance state beyond
        # being a bound method, so a bare instance is fine. We don't
        # call __init__ because that loads config from disk; bypass
        # via ``__new__`` for the test.
        return BrowseApp.__new__(BrowseApp)

    def test_advisory_action_tooltip_mentions_advisory(self, app):
        text = app._span_tooltip_text(
            "app.action_open_advisory('CVE-2024-99999')"
        )
        assert text is not None
        assert "CVE-2024-99999" in text or "advisory" in text.lower()

    def test_file_path_action_tooltip_mentions_editor_github(self, app):
        text = app._span_tooltip_text(
            "app.action_open_location('/src/foo.py:42')"
        )
        assert text is not None
        # User needs to know both routes exist — those are the actions
        # on the narrow right-click menu we're previewing.
        assert "editor" in text.lower() or "open" in text.lower()
        assert "github" in text.lower() or "remote" in text.lower() \
            or "right-click" in text.lower()

    def test_package_action_tooltip_mentions_package(self, app):
        text = app._span_tooltip_text(
            "app.action_open_location('flask@3.0.0')"
        )
        assert text is not None
        assert "package" in text.lower()

    def test_unknown_action_returns_none(self, app):
        # An unrecognized action shape should NOT produce a tooltip —
        # silently doing nothing is better than guessing wrong text.
        text = app._span_tooltip_text("app.action_made_up_thing('x')")
        assert text is None

    def test_empty_action_returns_none(self, app):
        assert app._span_tooltip_text("") is None
