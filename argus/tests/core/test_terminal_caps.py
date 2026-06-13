"""Unit tests for argus.core.terminal_caps (Phase 9 — graphics foundation)."""

from __future__ import annotations

import pytest

from argus.core.terminal_caps import (
    GRAPHICS_ITERM,
    GRAPHICS_KITTY,
    GRAPHICS_NONE,
    GRAPHICS_SIXEL,
    capability_summary,
    detect_graphics,
    supports_graphics,
    supports_hyperlinks,
    supports_truecolor,
)


class TestDetectGraphics:
    @pytest.mark.parametrize("env", [
        {"KITTY_WINDOW_ID": "1"},
        {"TERM": "xterm-kitty"},
        {"TERM_PROGRAM": "ghostty"},
        {"WEZTERM_PANE": "0"},
    ])
    def test_kitty_family(self, env):
        assert detect_graphics(env) == GRAPHICS_KITTY

    def test_iterm(self):
        assert detect_graphics({"TERM_PROGRAM": "iTerm.app"}) == GRAPHICS_ITERM
        assert detect_graphics({"ITERM_SESSION_ID": "w0"}) == GRAPHICS_ITERM

    def test_sixel(self):
        assert detect_graphics({"TERM": "foot"}) == GRAPHICS_SIXEL
        assert detect_graphics({"MLTERM": "3.9"}) == GRAPHICS_SIXEL

    def test_none_for_plain(self):
        assert detect_graphics({"TERM": "xterm-256color"}) == GRAPHICS_NONE
        assert detect_graphics({}) == GRAPHICS_NONE

    def test_supports_graphics(self):
        assert supports_graphics({"TERM": "xterm-kitty"}) is True
        assert supports_graphics({"TERM": "dumb"}) is False


class TestHyperlinks:
    def test_modern_terminal_yes(self):
        assert supports_hyperlinks({"TERM": "xterm-256color"}) is True

    def test_dumb_and_linux_console_no(self):
        assert supports_hyperlinks({"TERM": "dumb"}) is False
        assert supports_hyperlinks({"TERM": "linux"}) is False

    def test_explicit_optout(self):
        assert supports_hyperlinks({"TERM": "xterm", "NO_HYPERLINKS": "1"}) is False

    def test_no_term_no(self):
        assert supports_hyperlinks({}) is False


class TestTruecolor:
    def test_truecolor_env(self):
        assert supports_truecolor({"COLORTERM": "truecolor"}) is True
        assert supports_truecolor({"COLORTERM": "24bit"}) is True

    def test_absent_or_basic(self):
        assert supports_truecolor({}) is False
        assert supports_truecolor({"COLORTERM": "8bit"}) is False


class TestSummary:
    def test_summary_shape(self):
        s = capability_summary({"TERM": "xterm-kitty", "COLORTERM": "truecolor"})
        assert "graphics=kitty" in s and "hyperlinks=yes" in s and "truecolor=yes" in s

    def test_summary_plain(self):
        s = capability_summary({"TERM": "dumb"})
        assert "graphics=none" in s and "hyperlinks=no" in s
