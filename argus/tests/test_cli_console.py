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

import pytest

from argus.cli import (
    ENTERPRISE_COMMANDS,
    EXIT_ERROR,
    EXIT_SUCCESS,
    _discover_console_provider,
    _enterprise_command_upsell,
    _run_bare_argus,
    _subcommand_choices,
    build_parser,
    main,
)


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


class TestEnterpriseGhostCommands:
    """Known enterprise subcommands upsell (not argparse-error) when absent,
    and stay out of ``--help`` until the providing package registers them."""

    def test_console_is_a_known_enterprise_command(self):
        assert "console" in ENTERPRISE_COMMANDS

    def test_report_pdf_is_a_known_enterprise_command(self):
        assert "report-pdf" in ENTERPRISE_COMMANDS

    @pytest.mark.parametrize("name", sorted(ENTERPRISE_COMMANDS))
    def test_every_enterprise_command_upsells_when_uninstalled(self, name, monkeypatch, capsys):
        # Each known name must upsell (exit EXIT_ERROR) — never an argparse error —
        # and never be advertised in --help when no provider is installed.
        monkeypatch.setattr("argus.cli._discover_cli_command_registrars", lambda: [])
        assert name not in _subcommand_choices(build_parser())
        with pytest.raises(SystemExit) as exc:
            main([name])
        assert exc.value.code == EXIT_ERROR
        err = capsys.readouterr().err
        assert "huntridgelabs.com" in err and "invalid choice" not in err

    def test_not_registered_in_oss_help(self):
        # OSS ships no argus.cli_commands provider, so `console` is not a
        # subparser choice → never shown in --help.
        assert "console" not in _subcommand_choices(build_parser())

    def test_upsell_message_and_exit_code(self, capsys):
        rc = _enterprise_command_upsell("console")
        assert rc == EXIT_ERROR
        err = capsys.readouterr().err
        assert "Argus Enterprise" in err and "huntridgelabs.com" in err

    def test_typing_console_uninstalled_upsells_not_argparse_error(self, monkeypatch, capsys):
        # No registrar installed → bare `argus console` must upsell + exit
        # EXIT_ERROR, never reaching argparse's "invalid choice".
        monkeypatch.setattr("argus.cli._discover_cli_command_registrars", lambda: [])
        with pytest.raises(SystemExit) as exc:
            main(["console"])
        assert exc.value.code == EXIT_ERROR
        err = capsys.readouterr().err
        assert "huntridgelabs.com" in err
        assert "invalid choice" not in err

    def test_installed_registrar_makes_console_real(self, monkeypatch):
        # An installed package registers a real `console` subcommand via the
        # seam → it IS in choices and dispatches through args.func.
        ran = {"n": 0}

        def _register(subparsers, parent):
            p = subparsers.add_parser("console", parents=[parent], help="x")
            p.set_defaults(func=lambda args: (ran.__setitem__("n", ran["n"] + 1), 0)[1])

        monkeypatch.setattr("argus.cli._discover_cli_command_registrars", lambda: [_register])
        # Now in --help / choices...
        assert "console" in _subcommand_choices(build_parser())
        # ...and it runs (dispatched via the func default, not the upsell).
        with pytest.raises(SystemExit) as exc:
            main(["console"])
        assert exc.value.code == 0
        assert ran["n"] == 1

    def test_unknown_nonenterprise_command_still_argparse_errors(self, monkeypatch):
        monkeypatch.setattr("argus.cli._discover_cli_command_registrars", lambda: [])
        # A name we don't know is NOT intercepted — argparse rejects it (exit 2).
        with pytest.raises(SystemExit) as exc:
            main(["definitely-not-a-command"])
        assert exc.value.code == EXIT_ERROR
