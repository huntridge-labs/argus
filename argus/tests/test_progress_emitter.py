"""Tests for argus.cli._make_progress_emitter and the new flag-routing matrix.

Locks in the four-mode UX surface — default / --quiet / --no-spinner /
--debug — all composing through orthogonal flags.
"""

import argparse

import pytest

from argus.cli import (
    _TerminalSpinner,
    _make_progress_emitter,
    _quiet_enabled,
    _verbose_enabled,
)


def _ns(**flags) -> argparse.Namespace:
    """Build an argparse.Namespace with sensible defaults for testing."""
    base = {
        "verbose": False,
        "debug": False,
        "quiet": False,
        "no_spinner": False,
    }
    base.update(flags)
    return argparse.Namespace(**base)


# --------------------------------------------------------------------- #
# Flag predicates                                                       #
# --------------------------------------------------------------------- #


class TestVerboseEnabled:
    def test_no_flag_is_false(self):
        assert _verbose_enabled(_ns()) is False

    def test_verbose_flag(self):
        assert _verbose_enabled(_ns(verbose=True)) is True

    def test_debug_flag(self):
        assert _verbose_enabled(_ns(debug=True)) is True

    def test_either_flag_alone_is_enough(self):
        assert _verbose_enabled(_ns(verbose=True, debug=False)) is True
        assert _verbose_enabled(_ns(verbose=False, debug=True)) is True


class TestQuietEnabled:
    def test_no_flag_is_false(self):
        assert _quiet_enabled(_ns()) is False

    def test_quiet_flag(self):
        assert _quiet_enabled(_ns(quiet=True)) is True


# --------------------------------------------------------------------- #
# Progress emitter routing                                              #
# --------------------------------------------------------------------- #


class TestProgressEmitter:
    def test_quiet_returns_no_op(self, capsys):
        emit = _make_progress_emitter(_ns(quiet=True), spinner=None)
        emit(1, 4, "scanner-bandit", "build", 0)
        # No output anywhere — quiet mode is silence.
        out = capsys.readouterr()
        assert out.out == ""
        assert out.err == ""

    def test_verbose_returns_no_op(self, capsys):
        # --verbose / --debug routes through the logger; the progress
        # emitter is silent so we don't double-print phase lines.
        emit = _make_progress_emitter(_ns(verbose=True), spinner=None)
        emit(1, 4, "scanner-bandit", "build", 0)
        out = capsys.readouterr()
        assert out.out == ""
        assert out.err == ""

    def test_debug_alias_returns_no_op(self, capsys):
        emit = _make_progress_emitter(_ns(debug=True), spinner=None)
        emit(1, 4, "scanner-bandit", "build", 0)
        out = capsys.readouterr()
        assert out.out == ""
        assert out.err == ""

    def test_no_spinner_prints_persistent_lines(self, capsys):
        # --no-spinner + non-quiet + non-verbose → phase events go to
        # stderr as scrollback. This is the CI-friendly default.
        emit = _make_progress_emitter(_ns(no_spinner=True), spinner=None)
        emit(1, 4, "scanner-bandit", "build", 0)
        emit(1, 4, "scanner-bandit", "scan", 12000)
        emit(1, 4, "scanner-bandit", "done", 45000)
        err = capsys.readouterr().err
        assert "[1/4] scanner-bandit — build (0s)" in err
        assert "[1/4] scanner-bandit — scan (12s)" in err
        assert "[1/4] scanner-bandit — done (45s)" in err

    def test_disabled_spinner_falls_back_to_print(self, capsys):
        # When the spinner exists but its enabled flag is False (non-TTY,
        # for example), we still want phase lines to flow somewhere.
        spinner = _TerminalSpinner(message="x", enabled=False)
        emit = _make_progress_emitter(_ns(), spinner=spinner)
        emit(2, 3, "myapp", "scan", 8000)
        err = capsys.readouterr().err
        assert "[2/3] myapp — scan (8s)" in err

    def test_enabled_spinner_routes_to_update_message(self, capsys):
        # When the spinner IS drawing, phase events update its in-place
        # message rather than printing scrollback lines.
        spinner = _TerminalSpinner(message="initial", enabled=True)
        emit = _make_progress_emitter(_ns(), spinner=spinner)
        emit(2, 3, "myapp", "scan", 8000)
        # The spinner thread isn't running (we never entered the
        # context manager), but update_message still records the new
        # text on the instance for inspection.
        assert spinner._message == "[2/3] myapp — scan (8s)"
        # And nothing leaked to stderr.
        assert capsys.readouterr().err == ""

    def test_quiet_overrides_spinner_path(self, capsys):
        # --quiet wins over a drawing spinner — the spinner stays, but
        # its message doesn't update.
        spinner = _TerminalSpinner(message="initial", enabled=True)
        emit = _make_progress_emitter(_ns(quiet=True), spinner=spinner)
        emit(1, 1, "x", "scan", 0)
        assert spinner._message == "initial"
