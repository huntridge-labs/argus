"""Tests for bare ``argus`` (no subcommand) → Console-provider / help dispatch.

The load-bearing backward-compat contract: a non-interactive invocation
(no TTY) must keep printing ``--help``, so CI / scripts / pipes that run a
bare ``argus`` are unaffected.

The core ships no built-in Console. In an interactive terminal, bare
``argus`` defers to an installed Console provider (the
``argus.console_providers`` entry-point seam) when one is present; otherwise
it prints a one-line pointer and falls back to ``--help``.
"""

from __future__ import annotations

import sys

from argus.cli import _discover_console_provider, _run_bare_argus, EXIT_SUCCESS


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
    # No TTY must never even consult a provider.
    monkeypatch.setattr(
        "argus.cli._discover_console_provider",
        lambda: (_ for _ in ()).throw(AssertionError("must not discover without a TTY")),
    )
    assert _run_bare_argus(parser) == EXIT_SUCCESS
    assert parser.help_calls == 1


def test_interactive_no_provider_prints_hint_and_help(monkeypatch, capsys):
    _force_tty(monkeypatch, True)
    parser = _FakeParser()
    monkeypatch.setattr("argus.cli._discover_console_provider", lambda: None)
    assert _run_bare_argus(parser) == EXIT_SUCCESS
    assert parser.help_calls == 1
    err = capsys.readouterr().err
    assert "huntridgelabs.com" in err  # add-on pointer surfaced


class TestConsoleProviderSeam:
    """The open-core seam: an installed provider takes over bare ``argus``.

    Mirrors the reporters / browser-plugin entry-point pattern. OSS ships no
    provider; an external package (e.g. an add-on) supplies one.
    """

    def test_provider_takes_over(self, monkeypatch):
        _force_tty(monkeypatch, True)
        parser = _FakeParser()
        monkeypatch.setattr("argus.cli._discover_console_provider", lambda: (lambda: 7))
        assert _run_bare_argus(parser) == 7
        assert parser.help_calls == 0   # provider ran instead of help

    def test_provider_exit_code_is_returned(self, monkeypatch):
        _force_tty(monkeypatch, True)
        parser = _FakeParser()
        monkeypatch.setattr("argus.cli._discover_console_provider", lambda: (lambda: 3))
        assert _run_bare_argus(parser) == 3

    def test_broken_provider_falls_back_to_help(self, monkeypatch):
        _force_tty(monkeypatch, True)
        parser = _FakeParser()

        def boom():
            raise RuntimeError("provider exploded")

        monkeypatch.setattr("argus.cli._discover_console_provider", lambda: boom)
        # A provider that raises must not break bare argus — fall through to help.
        assert _run_bare_argus(parser) == EXIT_SUCCESS
        assert parser.help_calls == 1

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
