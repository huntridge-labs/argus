"""Tests for bare ``argus`` (no subcommand) → Console / help dispatch.

The load-bearing backward-compat contract: a non-interactive invocation
(no TTY) must keep printing ``--help``, so CI / scripts / pipes that run a
bare ``argus`` are unaffected. Only an interactive terminal launches the
Console.
"""

from __future__ import annotations

import sys

from argus.cli import _run_bare_argus, EXIT_SUCCESS
from argus.viewers.terminal import ViewerUnavailable


class _FakeParser:
    def __init__(self):
        self.help_calls = 0

    def print_help(self):
        self.help_calls += 1


def _force_tty(monkeypatch, value: bool):
    monkeypatch.setattr(sys.stdout, "isatty", lambda: value)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: value)


def test_non_interactive_prints_help(monkeypatch):
    _force_tty(monkeypatch, False)
    parser = _FakeParser()
    # Even if a console were importable, no-TTY must never launch it.
    monkeypatch.setattr(
        "argus.viewers.terminal.launch_console",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not launch")),
        raising=False,
    )
    assert _run_bare_argus(parser) == EXIT_SUCCESS
    assert parser.help_calls == 1


def test_interactive_launches_console(monkeypatch):
    _force_tty(monkeypatch, True)
    parser = _FakeParser()
    launched = {"n": 0}

    def fake_launch(results_dir=None):
        launched["n"] += 1
        return 0

    monkeypatch.setattr("argus.viewers.terminal.launch_console", fake_launch, raising=False)
    assert _run_bare_argus(parser) == 0
    assert launched["n"] == 1
    assert parser.help_calls == 0   # console launched instead of help


def test_interactive_returns_console_exit_code(monkeypatch):
    _force_tty(monkeypatch, True)
    parser = _FakeParser()
    monkeypatch.setattr("argus.viewers.terminal.launch_console", lambda *a, **k: 3, raising=False)
    assert _run_bare_argus(parser) == 3


def test_missing_terminal_extra_falls_back_to_help(monkeypatch, capsys):
    _force_tty(monkeypatch, True)
    parser = _FakeParser()

    def raise_unavailable(*a, **k):
        raise ViewerUnavailable("needs the terminal extra")

    monkeypatch.setattr("argus.viewers.terminal.launch_console", raise_unavailable, raising=False)
    assert _run_bare_argus(parser) == EXIT_SUCCESS
    assert parser.help_calls == 1
    err = capsys.readouterr().err
    assert "terminal" in err.lower()  # install hint surfaced
