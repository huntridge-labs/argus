"""Tests for bare ``argus`` (no subcommand) → Console / help dispatch.

The load-bearing backward-compat contract: a non-interactive invocation
(no TTY) must keep printing ``--help``, so CI / scripts / pipes that run a
bare ``argus`` are unaffected. Only an interactive terminal launches the
Console.
"""

from __future__ import annotations

import sys

from argus.cli import _discover_console_provider, _run_bare_argus, EXIT_SUCCESS
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


class TestConsoleProviderSeam:
    """The open-core seam: an installed provider takes over bare ``argus``.

    Mirrors the reporters / browser-plugin entry-point pattern. OSS ships no
    provider; an external package (Argus Enterprise) supplies one.
    """

    def test_provider_takes_precedence_over_builtin(self, monkeypatch):
        _force_tty(monkeypatch, True)
        parser = _FakeParser()
        monkeypatch.setattr("argus.cli._discover_console_provider", lambda: (lambda: 7))
        # The built-in console must NOT run when a provider is present.
        monkeypatch.setattr(
            "argus.viewers.terminal.launch_console",
            lambda *a, **k: (_ for _ in ()).throw(AssertionError("built-in must not run")),
            raising=False,
        )
        assert _run_bare_argus(parser) == 7
        assert parser.help_calls == 0

    def test_no_provider_falls_back_to_builtin(self, monkeypatch):
        _force_tty(monkeypatch, True)
        parser = _FakeParser()
        monkeypatch.setattr("argus.cli._discover_console_provider", lambda: None)
        monkeypatch.setattr("argus.viewers.terminal.launch_console", lambda *a, **k: 0, raising=False)
        assert _run_bare_argus(parser) == 0

    def test_broken_provider_falls_back_to_builtin(self, monkeypatch):
        _force_tty(monkeypatch, True)
        parser = _FakeParser()

        def boom():
            raise RuntimeError("provider exploded")

        monkeypatch.setattr("argus.cli._discover_console_provider", lambda: boom)
        launched = {"n": 0}

        def fake_launch(results_dir=None):
            launched["n"] += 1
            return 0

        monkeypatch.setattr("argus.viewers.terminal.launch_console", fake_launch, raising=False)
        # A provider that raises must not break bare argus — fall through to built-in.
        assert _run_bare_argus(parser) == 0
        assert launched["n"] == 1

    def test_non_interactive_never_consults_provider(self, monkeypatch):
        _force_tty(monkeypatch, False)
        parser = _FakeParser()
        monkeypatch.setattr(
            "argus.cli._discover_console_provider",
            lambda: (_ for _ in ()).throw(AssertionError("must not discover without a TTY")),
        )
        assert _run_bare_argus(parser) == EXIT_SUCCESS
        assert parser.help_calls == 1

    def test_discover_returns_none_when_no_providers_registered(self):
        # OSS registers no provider, so real discovery must yield None.
        assert _discover_console_provider() is None

    def test_discover_loads_registered_provider(self, monkeypatch):
        class _FakeEP:
            name = "console"

            def load(self):
                return lambda: 0

        monkeypatch.setattr("importlib.metadata.entry_points", lambda group: [_FakeEP()])
        provider = _discover_console_provider()
        assert callable(provider)
        assert provider() == 0

    def test_discover_skips_provider_that_fails_to_load(self, monkeypatch):
        class _BadEP:
            name = "broken"

            def load(self):
                raise ImportError("missing dep")

        monkeypatch.setattr("importlib.metadata.entry_points", lambda group: [_BadEP()])
        # A provider whose load() raises is skipped, not propagated.
        assert _discover_console_provider() is None
