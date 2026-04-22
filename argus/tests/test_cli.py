"""Tests for argus.cli — argument parsing and command handler integration."""

import argparse
from unittest.mock import MagicMock

import pytest

from argus import cli
from argus.cli import (
    EXIT_ERROR,
    EXIT_FINDINGS,
    EXIT_SUCCESS,
    build_parser,
    cmd_report,
    cmd_scan,
    cmd_validate,
    _list_scanners,
)


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

    def test_scan_allow_local_versions_flag(self):
        parser = build_parser()
        args = parser.parse_args(["scan", "--allow-local-versions"])
        assert args.allow_local_versions is True

    def test_scan_allow_local_versions_default_false(self):
        parser = build_parser()
        args = parser.parse_args(["scan"])
        assert args.allow_local_versions is False


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


# ---------------------------------------------------------------------------
# Integration tests — exercise command handler functions directly
# ---------------------------------------------------------------------------


def _make_scan_args(**overrides) -> argparse.Namespace:
    """Build a Namespace with all attributes expected by cmd_scan."""
    defaults = {
        "scanner": None,
        "path": ".",
        "config": None,
        "output_dir": None,
        "severity_threshold": None,
        "formats": None,
        "list": False,
        "verbose": False,
        "no_spinner": True,
        "no_timestamp": True,
        "fail_fast": False,
        "timeout": None,
        "allow_local_versions": False,
        "discover": None,
        "images": None,
        "scanners": None,
        "target": None,
        "port": None,
        "env_vars": None,
        "scan_type": "baseline",
        "startup_timeout": 60,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


class TestCmdScan:
    """Integration tests for cmd_scan and _cmd_source_scan."""

    def test_scan_unknown_scanner_returns_error(self, monkeypatch, capsys):
        """Passing an unregistered scanner name should return EXIT_ERROR."""
        monkeypatch.setattr(
            "argus.scanners.SCANNER_REGISTRY",
            {"bandit": object, "gitleaks": object},
        )
        args = _make_scan_args(scanner="nonexistent")
        result = cmd_scan(args)

        assert result == EXIT_ERROR
        captured = capsys.readouterr()
        assert "unknown scanner 'nonexistent'" in captured.err

    def test_scan_source_runs_engine(self, monkeypatch, tmp_path):
        """A valid scan with no findings should call engine.run and return EXIT_SUCCESS."""
        from argus.core.config import ArgusConfig, ReportingConfig, ExecutionConfig
        from argus.core.models import ScanSummary

        config = ArgusConfig(
            reporting=ReportingConfig(
                output_dir=str(tmp_path),
                formats=["terminal"],
                severity_threshold=None,
            ),
            execution=ExecutionConfig(),
        )
        monkeypatch.setattr(
            "argus.core.config.ArgusConfig.load",
            lambda _path: config,
        )

        summary = ScanSummary(results=[], severity_threshold=None)
        mock_engine = MagicMock()
        mock_engine.run.return_value = summary
        mock_engine.config = config

        monkeypatch.setattr(
            "argus.core.engine.ArgusEngine.__init__",
            lambda self, _cfg: setattr(self, "config", config)
            or setattr(self, "_scanners", {}),
        )
        monkeypatch.setattr(
            "argus.core.engine.ArgusEngine.run",
            lambda self, **kwargs: summary,
        )
        monkeypatch.setattr(
            "argus.core.engine.ArgusEngine.register_scanner",
            lambda self, s: None,
        )
        monkeypatch.setattr("argus.scanners.get_available_scanners", lambda: [])
        monkeypatch.setattr(
            "argus.reporters.get_reporter",
            lambda fmt: MagicMock(),
        )
        # Stub audit module so it doesn't write files to random places
        monkeypatch.setattr(
            "argus.audit.get_logger",
            lambda *a, **kw: MagicMock(),
        )
        monkeypatch.setattr(
            "argus.audit.create_manifest",
            lambda **kw: MagicMock(execution_backend=None),
        )
        monkeypatch.setattr(
            "argus.audit.finalize_manifest",
            lambda *a, **kw: None,
        )

        args = _make_scan_args(output_dir=str(tmp_path))
        result = cmd_scan(args)

        assert result == EXIT_SUCCESS

    def test_scan_source_returns_findings_exit_code(self, monkeypatch, tmp_path):
        """When findings exceed the severity threshold, return EXIT_FINDINGS."""
        from argus.core.config import ArgusConfig, ReportingConfig, ExecutionConfig
        from argus.core.models import Finding, ScanResult, ScanSummary, Severity

        config = ArgusConfig(
            reporting=ReportingConfig(
                output_dir=str(tmp_path),
                formats=["terminal"],
                severity_threshold=Severity.HIGH,
            ),
            execution=ExecutionConfig(),
        )
        monkeypatch.setattr(
            "argus.core.config.ArgusConfig.load",
            lambda _path: config,
        )

        finding = Finding(
            id="TEST-001",
            title="Test finding",
            severity=Severity.HIGH,
            scanner="bandit",
        )
        result = ScanResult(scanner="bandit", findings=[finding])
        summary = ScanSummary(
            results=[result],
            severity_threshold=Severity.HIGH,
        )

        monkeypatch.setattr(
            "argus.core.engine.ArgusEngine.__init__",
            lambda self, _cfg: setattr(self, "config", config)
            or setattr(self, "_scanners", {}),
        )
        monkeypatch.setattr(
            "argus.core.engine.ArgusEngine.run",
            lambda self, **kw: summary,
        )
        monkeypatch.setattr(
            "argus.core.engine.ArgusEngine.register_scanner",
            lambda self, s: None,
        )
        monkeypatch.setattr("argus.scanners.get_available_scanners", lambda: [])
        monkeypatch.setattr(
            "argus.reporters.get_reporter",
            lambda fmt: MagicMock(),
        )
        monkeypatch.setattr(
            "argus.audit.get_logger",
            lambda *a, **kw: MagicMock(),
        )
        monkeypatch.setattr(
            "argus.audit.create_manifest",
            lambda **kw: MagicMock(execution_backend=None),
        )
        monkeypatch.setattr(
            "argus.audit.finalize_manifest",
            lambda *a, **kw: None,
        )

        args = _make_scan_args(output_dir=str(tmp_path))
        exit_code = cmd_scan(args)

        assert exit_code == EXIT_FINDINGS

    def test_scan_source_severity_none_returns_success(self, monkeypatch, tmp_path):
        """severity_threshold='none' should mean no threshold — always EXIT_SUCCESS."""
        from argus.core.config import ArgusConfig, ReportingConfig, ExecutionConfig
        from argus.core.models import Finding, ScanResult, ScanSummary, Severity

        config = ArgusConfig(
            reporting=ReportingConfig(
                output_dir=str(tmp_path),
                formats=["terminal"],
                severity_threshold=Severity.HIGH,  # will be overridden
            ),
            execution=ExecutionConfig(),
        )
        monkeypatch.setattr(
            "argus.core.config.ArgusConfig.load",
            lambda _path: config,
        )

        finding = Finding(
            id="TEST-001",
            title="Critical bug",
            severity=Severity.CRITICAL,
            scanner="bandit",
        )
        result = ScanResult(scanner="bandit", findings=[finding])
        # severity_threshold=None means passed is always True
        summary = ScanSummary(results=[result], severity_threshold=None)

        monkeypatch.setattr(
            "argus.core.engine.ArgusEngine.__init__",
            lambda self, _cfg: setattr(self, "config", config)
            or setattr(self, "_scanners", {}),
        )
        monkeypatch.setattr(
            "argus.core.engine.ArgusEngine.run",
            lambda self, **kw: summary,
        )
        monkeypatch.setattr(
            "argus.core.engine.ArgusEngine.register_scanner",
            lambda self, s: None,
        )
        monkeypatch.setattr("argus.scanners.get_available_scanners", lambda: [])
        monkeypatch.setattr(
            "argus.reporters.get_reporter",
            lambda fmt: MagicMock(),
        )
        monkeypatch.setattr(
            "argus.audit.get_logger",
            lambda *a, **kw: MagicMock(),
        )
        monkeypatch.setattr(
            "argus.audit.create_manifest",
            lambda **kw: MagicMock(execution_backend=None),
        )
        monkeypatch.setattr(
            "argus.audit.finalize_manifest",
            lambda *a, **kw: None,
        )

        # CLI passes severity_threshold="none" which _cmd_source_scan converts to None
        args = _make_scan_args(
            output_dir=str(tmp_path),
            severity_threshold="none",
        )
        exit_code = cmd_scan(args)

        assert exit_code == EXIT_SUCCESS

    def test_scan_list_mode(self, monkeypatch, tmp_path):
        """--list flag should call _list_scanners and return EXIT_SUCCESS."""
        from argus.core.config import ArgusConfig, ReportingConfig, ExecutionConfig

        config = ArgusConfig(
            reporting=ReportingConfig(output_dir=str(tmp_path)),
            execution=ExecutionConfig(),
        )
        monkeypatch.setattr(
            "argus.core.config.ArgusConfig.load",
            lambda _path: config,
        )
        monkeypatch.setattr(
            "argus.core.engine.ArgusEngine.__init__",
            lambda self, _cfg: setattr(self, "config", config)
            or setattr(self, "_scanners", {}),
        )
        monkeypatch.setattr(
            "argus.core.engine.ArgusEngine.register_scanner",
            lambda self, s: None,
        )
        monkeypatch.setattr("argus.scanners.get_available_scanners", lambda: [])
        monkeypatch.setattr(
            "argus.audit.get_logger",
            lambda *a, **kw: MagicMock(),
        )
        monkeypatch.setattr(
            "argus.audit.create_manifest",
            lambda **kw: MagicMock(execution_backend=None),
        )
        monkeypatch.setattr(
            "argus.audit.finalize_manifest",
            lambda *a, **kw: None,
        )

        args = _make_scan_args(list=True, output_dir=str(tmp_path))
        exit_code = cmd_scan(args)

        assert exit_code == EXIT_SUCCESS

    def test_scan_no_timestamp_flag(self, monkeypatch, tmp_path):
        """--no-timestamp should write output directly to output_dir (no subdir)."""
        from argus.core.config import ArgusConfig, ReportingConfig, ExecutionConfig
        from argus.core.models import ScanSummary

        out = tmp_path / "flat-output"
        config = ArgusConfig(
            reporting=ReportingConfig(
                output_dir=str(out),
                formats=["terminal"],
            ),
            execution=ExecutionConfig(),
        )
        monkeypatch.setattr(
            "argus.core.config.ArgusConfig.load",
            lambda _path: config,
        )

        summary = ScanSummary(results=[], severity_threshold=None)
        monkeypatch.setattr(
            "argus.core.engine.ArgusEngine.__init__",
            lambda self, _cfg: setattr(self, "config", config)
            or setattr(self, "_scanners", {}),
        )
        monkeypatch.setattr(
            "argus.core.engine.ArgusEngine.run",
            lambda self, **kw: summary,
        )
        monkeypatch.setattr(
            "argus.core.engine.ArgusEngine.register_scanner",
            lambda self, s: None,
        )
        monkeypatch.setattr("argus.scanners.get_available_scanners", lambda: [])
        monkeypatch.setattr(
            "argus.reporters.get_reporter",
            lambda fmt: MagicMock(),
        )
        monkeypatch.setattr(
            "argus.audit.get_logger",
            lambda *a, **kw: MagicMock(),
        )
        monkeypatch.setattr(
            "argus.audit.create_manifest",
            lambda **kw: MagicMock(execution_backend=None),
        )
        monkeypatch.setattr(
            "argus.audit.finalize_manifest",
            lambda *a, **kw: None,
        )

        args = _make_scan_args(
            output_dir=str(out),
            no_timestamp=True,
        )
        cmd_scan(args)

        # With no_timestamp, output_dir itself should exist — no timestamped subdir
        assert out.is_dir()
        # No child directories that look like timestamps (YYYY-MM-DDTHH-MM-SSZ)
        subdirs = [p for p in out.iterdir() if p.is_dir()]
        assert len(subdirs) == 0


class TestCmdValidate:
    """Integration tests for cmd_validate."""

    def test_validate_valid_config(self, tmp_path, capsys):
        """A minimal valid config should return EXIT_SUCCESS."""
        config_file = tmp_path / "argus.yml"
        config_file.write_text(
            "scanners:\n"
            "  bandit:\n"
            "    enabled: true\n"
        )
        args = argparse.Namespace(
            config=str(config_file),
            check_tools=False,
            strict=False,
        )
        result = cmd_validate(args)

        assert result == EXIT_SUCCESS
        captured = capsys.readouterr()
        assert "valid" in captured.out.lower() or "valid" in captured.out

    def test_validate_missing_config(self, tmp_path, capsys):
        """A nonexistent config path should return EXIT_ERROR."""
        args = argparse.Namespace(
            config=str(tmp_path / "does-not-exist.yml"),
            check_tools=False,
            strict=False,
        )
        result = cmd_validate(args)

        assert result == EXIT_ERROR
        captured = capsys.readouterr()
        assert "not found" in captured.err.lower()

    def test_validate_invalid_yaml(self, tmp_path, capsys):
        """Malformed YAML should return EXIT_ERROR."""
        config_file = tmp_path / "argus.yml"
        config_file.write_text(":\n  - :\n    [bad yaml")
        args = argparse.Namespace(
            config=str(config_file),
            check_tools=False,
            strict=False,
        )
        result = cmd_validate(args)

        assert result == EXIT_ERROR
        captured = capsys.readouterr()
        assert "invalid yaml" in captured.err.lower() or "yaml" in captured.err.lower()

    def test_validate_with_warnings(self, tmp_path, capsys):
        """Unknown keys produce warnings but validation still passes."""
        config_file = tmp_path / "argus.yml"
        config_file.write_text(
            "scanners:\n"
            "  bandit:\n"
            "    enabled: true\n"
            "unknown_key: true\n"
        )
        args = argparse.Namespace(
            config=str(config_file),
            check_tools=False,
            strict=False,
        )
        result = cmd_validate(args)

        assert result == EXIT_SUCCESS

    def test_validate_strict_fails_on_warnings(self, tmp_path, capsys):
        """With --strict, warnings should cause EXIT_ERROR."""
        config_file = tmp_path / "argus.yml"
        config_file.write_text(
            "scanners:\n"
            "  bandit:\n"
            "    enabled: true\n"
            "unknown_key: true\n"
        )
        args = argparse.Namespace(
            config=str(config_file),
            check_tools=False,
            strict=True,
        )
        result = cmd_validate(args)

        assert result == EXIT_ERROR
        captured = capsys.readouterr()
        assert "strict" in captured.out.lower() or "warning" in captured.out.lower()


class TestCmdReport:
    """Integration tests for cmd_report."""

    def test_report_missing_results_dir(self, tmp_path, capsys):
        """A nonexistent results directory should return EXIT_ERROR."""
        args = argparse.Namespace(
            format="terminal",
            results_dir=str(tmp_path / "nonexistent"),
            output_dir=None,
            verbose=False,
        )
        result = cmd_report(args)

        assert result == EXIT_ERROR
        captured = capsys.readouterr()
        assert "not found" in captured.err.lower()

    def test_report_missing_json_file(self, tmp_path, capsys):
        """Existing dir but no argus-results.json should return EXIT_ERROR."""
        results_dir = tmp_path / "results"
        results_dir.mkdir()
        args = argparse.Namespace(
            format="terminal",
            results_dir=str(results_dir),
            output_dir=None,
            verbose=False,
        )
        result = cmd_report(args)

        assert result == EXIT_ERROR
        captured = capsys.readouterr()
        assert "argus-results.json" in captured.err


class TestListScanners:
    """Integration tests for _list_scanners."""

    def test_list_no_scanners(self, capsys):
        """An engine with no scanners should print a 'no scanners' message."""
        engine = MagicMock()
        engine._scanners = {}

        result = _list_scanners(engine)

        assert result == EXIT_SUCCESS
        captured = capsys.readouterr()
        assert "no scanners registered" in captured.out.lower()

    def test_list_shows_availability(self, monkeypatch, capsys):
        """Registered scanners should show local/not-found availability."""
        local_scanner = MagicMock()
        local_scanner.is_available.return_value = True
        local_scanner.description = "Python SAST"
        local_scanner.container_image = ""

        missing_scanner = MagicMock()
        missing_scanner.is_available.return_value = False
        missing_scanner.description = "Secret detection"
        missing_scanner.container_image = ""

        engine = MagicMock()
        engine._scanners = {
            "bandit": local_scanner,
            "gitleaks": missing_scanner,
        }
        engine.config.execution.backend = "local"

        monkeypatch.setattr(
            "argus.containers.get_image",
            lambda name: "",
        )

        result = _list_scanners(engine)

        assert result == EXIT_SUCCESS
        captured = capsys.readouterr()
        assert "local" in captured.out
        assert "not found" in captured.out


class TestCacheSubcommand:
    """Test parsing and execution of the 'cache' subcommand."""

    def test_cache_command_parses(self):
        parser = build_parser()
        args = parser.parse_args(["cache", "info"])
        assert args.command == "cache"
        assert args.cache_action == "info"

    def test_cache_clean_parses(self):
        parser = build_parser()
        args = parser.parse_args(["cache", "clean"])
        assert args.command == "cache"
        assert args.cache_action == "clean"

    def test_cache_no_action_defaults_to_none(self):
        parser = build_parser()
        args = parser.parse_args(["cache"])
        assert args.command == "cache"
        assert args.cache_action is None

    def test_no_cache_flag_on_scan(self):
        parser = build_parser()
        args = parser.parse_args(["scan", "--no-cache"])
        assert args.no_cache is True

    def test_no_cache_flag_default(self):
        parser = build_parser()
        args = parser.parse_args(["scan"])
        assert args.no_cache is False

    def test_cache_info_runs(self, tmp_path, monkeypatch):
        from argus.cli import cmd_cache
        monkeypatch.setenv("ARGUS_CACHE_DIR", str(tmp_path))
        args = build_parser().parse_args(["cache", "info"])
        result = cmd_cache(args)
        assert result == EXIT_SUCCESS

    def test_cache_clean_runs(self, tmp_path, monkeypatch):
        from argus.cli import cmd_cache
        monkeypatch.setenv("ARGUS_CACHE_DIR", str(tmp_path))
        cache_dir = tmp_path / "trivy"
        cache_dir.mkdir()
        (cache_dir / "db.tar.gz").write_text("fake")
        args = build_parser().parse_args(["cache", "clean"])
        result = cmd_cache(args)
        assert result == EXIT_SUCCESS
        assert not tmp_path.exists()


class TestMissingScannerNudge:
    """End-of-scan nudge when requested scanners produced no results."""

    def _summary(self, scanner_names: list[str]):
        from argus.core.models import ScanResult, ScanSummary

        results = [ScanResult(scanner=name, findings=[]) for name in scanner_names]
        return ScanSummary(results=results, severity_threshold=None)

    def test_no_output_when_all_scanners_completed(self, capsys):
        from argus.cli import _print_missing_scanner_nudge

        _print_missing_scanner_nudge(
            requested=["bandit", "gitleaks"],
            summary=self._summary(["bandit", "gitleaks"]),
        )
        assert capsys.readouterr().err == ""

    def test_lists_missing_and_points_to_check_tools(self, capsys):
        from argus.cli import _print_missing_scanner_nudge

        _print_missing_scanner_nudge(
            requested=["bandit", "gitleaks", "opengrep"],
            summary=self._summary(["bandit"]),
        )
        err = capsys.readouterr().err
        assert "2 scanner(s) produced no results" in err
        assert "gitleaks" in err and "opengrep" in err
        assert "argus validate --check-tools" in err

    def test_silent_when_nothing_requested(self, capsys):
        from argus.cli import _print_missing_scanner_nudge

        _print_missing_scanner_nudge(requested=[], summary=self._summary([]))
        assert capsys.readouterr().err == ""
