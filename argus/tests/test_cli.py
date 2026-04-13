"""Tests for argus.cli — CLI argument parsing."""

import pytest

from argus import cli
from argus.cli import build_parser


class TestScanSubcommand:
    """Test parsing of the 'scan' subcommand."""

    def test_scan_default_args(self):
        parser = build_parser()
        args = parser.parse_args(["scan"])
        assert args.command == "scan"
        assert args.scanner is None
        assert args.path == "."
        assert args.config is None
        assert args.output_dir is None
        assert args.severity_threshold is None
        assert args.formats is None
        assert args.list is False
        assert args.verbose is False
        assert args.no_spinner is False

    def test_scan_with_scanner_name(self):
        parser = build_parser()
        args = parser.parse_args(["scan", "bandit"])
        assert args.scanner == "bandit"

    def test_scan_with_path(self):
        parser = build_parser()
        args = parser.parse_args(["scan", "--path", "src/"])
        assert args.path == "src/"

    def test_scan_with_short_path(self):
        parser = build_parser()
        args = parser.parse_args(["scan", "-p", "lib/"])
        assert args.path == "lib/"

    def test_scan_with_config(self):
        parser = build_parser()
        args = parser.parse_args(["scan", "--config", "custom.yml"])
        assert args.config == "custom.yml"

    def test_scan_with_output_dir(self):
        parser = build_parser()
        args = parser.parse_args(["scan", "--output-dir", "/tmp/results"])
        assert args.output_dir == "/tmp/results"

    def test_scan_with_severity_threshold(self):
        parser = build_parser()
        args = parser.parse_args(["scan", "--severity-threshold", "high"])
        assert args.severity_threshold == "high"

    def test_scan_severity_choices(self):
        parser = build_parser()
        for choice in ["critical", "high", "medium", "low", "none"]:
            args = parser.parse_args(["scan", "-s", choice])
            assert args.severity_threshold == choice

    def test_scan_invalid_severity_exits(self):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["scan", "-s", "invalid"])

    def test_scan_with_formats(self):
        parser = build_parser()
        args = parser.parse_args([
            "scan", "-f", "terminal", "-f", "markdown",
        ])
        assert args.formats == ["terminal", "markdown"]

    def test_scan_invalid_format_exits(self):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["scan", "-f", "invalid"])

    def test_scan_list_flag(self):
        parser = build_parser()
        args = parser.parse_args(["scan", "--list"])
        assert args.list is True

    def test_scan_verbose_flag(self):
        parser = build_parser()
        args = parser.parse_args(["scan", "--verbose"])
        assert args.verbose is True

    def test_scan_no_spinner_flag(self):
        parser = build_parser()
        args = parser.parse_args(["scan", "--no-spinner"])
        assert args.no_spinner is True


class TestReportSubcommand:
    """Test parsing of the 'report' subcommand."""

    def test_report_with_format(self):
        parser = build_parser()
        args = parser.parse_args(["report", "markdown"])
        assert args.command == "report"
        assert args.format == "markdown"

    def test_report_with_results_dir(self):
        parser = build_parser()
        args = parser.parse_args(["report", "sarif", "-r", "/tmp/results"])
        assert args.results_dir == "/tmp/results"

    def test_report_with_output_dir(self):
        parser = build_parser()
        args = parser.parse_args(["report", "json", "-o", "/tmp/output"])
        assert args.output_dir == "/tmp/output"

    def test_report_defaults(self):
        parser = build_parser()
        args = parser.parse_args(["report", "terminal"])
        assert args.results_dir == "./argus-results"
        assert args.output_dir is None
        assert args.verbose is False

    def test_report_invalid_format_exits(self):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["report", "invalid"])


class TestVersionFlag:
    """Test --version flag."""

    def test_version_flag_exits(self):
        parser = build_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["--version"])
        assert exc_info.value.code == 0


class TestNoCommand:
    """Test behavior when no command is provided."""

    def test_no_command_sets_none(self):
        parser = build_parser()
        args = parser.parse_args([])
        assert args.command is None


class TestHiddenEasterEgg:
    """Test hidden CLI easter egg behavior."""

    def test_hidden_logo_not_in_help(self):
        parser = build_parser()
        help_text = parser.format_help()
        assert "__logo" not in help_text

    def test_hidden_logo_trigger_runs(self, monkeypatch):
        called = {"value": False}

        def fake_show_logo():
            called["value"] = True
            return 0

        monkeypatch.setattr(cli, "_show_logo_easter_egg", fake_show_logo)

        with pytest.raises(SystemExit) as exc_info:
            cli.main(["__logo"])

        assert exc_info.value.code == 0
        assert called["value"] is True

    def test_inline_logo_trigger_with_scan_runs_then_dispatches(self, monkeypatch):
        state = {"logo": False, "scan": False}

        def fake_show_logo():
            state["logo"] = True
            return 0

        def fake_cmd_scan(_args):
            state["scan"] = True
            return 0

        monkeypatch.setattr(cli, "_show_logo_easter_egg", fake_show_logo)
        monkeypatch.setattr(cli, "cmd_scan", fake_cmd_scan)

        with pytest.raises(SystemExit) as exc_info:
            cli.main(["scan", "--list", "__logo"])

        assert exc_info.value.code == 0
        assert state["logo"] is True
        assert state["scan"] is True
