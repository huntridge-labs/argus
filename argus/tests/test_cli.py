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


class TestCompletionHelp:
    """Test that 'argus completion --help' explains how to use it end-to-end."""

    def _completion_help(self) -> str:
        parser = build_parser()
        # Reach into the subparsers to render the completion subcommand's help.
        subparsers_action = next(
            action
            for action in parser._actions
            if isinstance(action, argparse._SubParsersAction)
        )
        return subparsers_action.choices["completion"].format_help()

    def test_help_mentions_what_gets_completed(self):
        help_text = self._completion_help()
        assert "subcommands" in help_text
        assert "scanner" in help_text

    def test_help_includes_source_step_for_zsh(self):
        # Regression: prior wording showed `>> ~/.zshrc` without the `source`
        # step, so users edited rc files but saw no completions until restart.
        help_text = self._completion_help()
        assert "source ~/.zshrc" in help_text
        assert "source ~/.bashrc" in help_text

    def test_help_includes_eval_for_current_session(self):
        help_text = self._completion_help()
        assert 'eval "$(argus completion zsh)"' in help_text


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

    def test_container_lifecycle_activates_from_config_only(self, tmp_path, monkeypatch):
        """Regression: ``argus scan container --config argus.yml`` should
        run end-to-end when the config has containers.images, with no
        --discover/--image required. Previously the CLI gate looked at
        flags only and exited with usage error before reading config."""
        from argus.cli import _container_config_has_targets, _load_container_config

        config_file = tmp_path / "argus.yml"
        config_file.write_text(
            "containers:\n"
            "  images:\n"
            "    - image: myapp:latest\n"
            "      dockerfile: Dockerfile\n"
        )
        args = _make_scan_args(scanner="container", config=str(config_file))

        loaded = _load_container_config(args)
        # Config-only invocation now resolves real targets without flags.
        assert _container_config_has_targets(loaded) is True
        assert loaded["images"] == [{"image": "myapp:latest", "dockerfile": "Dockerfile"}]

    def test_container_lifecycle_cli_image_overrides_config(self, tmp_path):
        """Explicit --image on the CLI replaces the config's images list,
        so a stale config entry doesn't sneak into a one-off scan."""
        from argus.cli import _load_container_config

        config_file = tmp_path / "argus.yml"
        config_file.write_text(
            "containers:\n  images:\n    - image: stale:1.0\n"
        )
        args = _make_scan_args(
            scanner="container", config=str(config_file), images=["fresh:2.0"],
        )

        loaded = _load_container_config(args)
        # CLI --image is the source of truth; stale config entry is gone.
        assert loaded["images"] == [{"image": "fresh:2.0", "name": "fresh"}]

    def test_container_lifecycle_cli_discover_overrides_search_paths(self, tmp_path):
        """``--discover .`` on the CLI replaces the config's search_paths."""
        from argus.cli import _load_container_config

        config_file = tmp_path / "argus.yml"
        config_file.write_text(
            "containers:\n"
            "  discover: true\n"
            "  search_paths:\n    - docker/\n"
        )
        args = _make_scan_args(
            scanner="container", config=str(config_file), discover=".",
        )

        loaded = _load_container_config(args)
        assert loaded["search_paths"] == ["."]
        assert loaded["discover"] is True

    def test_container_lifecycle_malformed_config_emits_actionable_error(self, tmp_path):
        """``containers:`` set to a string (not a mapping) gets a clear
        error, not a deep traceback."""
        from argus.cli import _load_container_config

        config_file = tmp_path / "argus.yml"
        config_file.write_text("containers: not-a-mapping\n")
        args = _make_scan_args(scanner="container", config=str(config_file))

        with pytest.raises(ValueError) as excinfo:
            _load_container_config(args)
        msg = str(excinfo.value)
        assert "containers" in msg
        assert "must be a mapping" in msg
        # Hint includes the expected shape so the user knows how to fix it.
        assert "images:" in msg

    def test_container_lifecycle_no_targets_returns_usage_error(self, tmp_path, monkeypatch, capsys):
        """A config with an empty ``containers:`` block AND no CLI flags
        hits the usage-error gate with a config-aware help message."""
        from argus.cli import cmd_scan
        monkeypatch.setattr(
            "argus.scanners.SCANNER_REGISTRY", {"container": object},
        )

        config_file = tmp_path / "argus.yml"
        config_file.write_text("containers: {}\n")
        args = _make_scan_args(scanner="container", config=str(config_file))

        rc = cmd_scan(args)
        err = capsys.readouterr().err

        assert rc == EXIT_ERROR
        # The new message names config as a valid source of targets,
        # so users running config-only flows see they need to populate
        # the ``containers.images`` block — not just add a CLI flag.
        assert "--config FILE" in err
        assert "containers.images" in err

    def test_container_lifecycle_yaml_parse_error_is_caught(self, tmp_path):
        """Invalid YAML produces a friendly error, not a yaml.YAMLError
        traceback bubbling up from deep in the loader."""
        from argus.cli import _load_container_config

        config_file = tmp_path / "argus.yml"
        config_file.write_text("containers: [{")  # incomplete
        args = _make_scan_args(scanner="container", config=str(config_file))

        with pytest.raises(ValueError) as excinfo:
            _load_container_config(args)
        assert "YAML parse error" in str(excinfo.value)

    def test_scan_source_always_emits_canonical_json(self, monkeypatch, tmp_path):
        """Regression for Option C: argus-results.json must be written
        regardless of the user's ``reporting.formats``. Captures the
        format names the cli.py loop asks ``get_reporter`` for, and
        asserts 'json' is in the list even though the user configured
        formats=[terminal] only."""
        from argus.core.config import ArgusConfig, ReportingConfig, ExecutionConfig
        from argus.core.models import ScanSummary

        config = ArgusConfig(
            reporting=ReportingConfig(
                output_dir=str(tmp_path),
                formats=["terminal"],   # deliberately omits json
                severity_threshold=None,
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
            lambda self, **kwargs: summary,
        )
        monkeypatch.setattr(
            "argus.core.engine.ArgusEngine.register_scanner",
            lambda self, s: None,
        )
        monkeypatch.setattr("argus.scanners.get_available_scanners", lambda: [])

        # Capture every format name the dispatch loop requests so we
        # can assert canonical JSON was demanded alongside the user's
        # configured formats.
        requested: list[str] = []

        def capture_reporter(fmt):
            requested.append(fmt)
            return MagicMock()

        monkeypatch.setattr("argus.reporters.get_reporter", capture_reporter)
        monkeypatch.setattr("argus.audit.get_logger", lambda *a, **kw: MagicMock())
        monkeypatch.setattr(
            "argus.audit.create_manifest",
            lambda **kw: MagicMock(execution_backend=None),
        )
        monkeypatch.setattr("argus.audit.finalize_manifest", lambda *a, **kw: None)

        args = _make_scan_args(output_dir=str(tmp_path))
        cmd_scan(args)

        # Canonical JSON is requested even though config didn't list it.
        # User's terminal report is still emitted.
        assert "json" in requested
        assert "terminal" in requested

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

    def test_no_default_excludes_flag(self):
        parser = build_parser()
        args = parser.parse_args(["scan", "--no-default-excludes"])
        assert args.no_default_excludes is True

    def test_no_default_excludes_default(self):
        parser = build_parser()
        args = parser.parse_args(["scan"])
        assert args.no_default_excludes is False

    def test_dry_run_flag(self):
        parser = build_parser()
        args = parser.parse_args(["scan", "--dry-run"])
        assert args.dry_run is True

    def test_sbom_flag_takes_path(self):
        parser = build_parser()
        args = parser.parse_args(["scan", "--sbom", "path/to/sbom.json"])
        assert args.sbom == "path/to/sbom.json"

    def test_sbom_flag_default_none(self):
        parser = build_parser()
        args = parser.parse_args(["scan"])
        assert args.sbom is None

    def test_fail_on_scanner_error_flag(self):
        """--fail-on-scanner-error is opt-in (default False) so existing
        ``argus scan`` users keep getting partial-scan PASS behavior;
        CI callers who want hard fails set the flag."""
        parser = build_parser()
        args = parser.parse_args(["scan"])
        assert args.fail_on_scanner_error is False

        args = parser.parse_args(["scan", "--fail-on-scanner-error"])
        assert args.fail_on_scanner_error is True

    def test_interface_flag_terminal(self):
        parser = build_parser()
        args = parser.parse_args(["scan", "--interface", "terminal"])
        assert args.view_interface == "terminal"

    def test_interface_flag_browser(self):
        parser = build_parser()
        args = parser.parse_args(["scan", "--interface=browser"])
        assert args.view_interface == "browser"

    def test_interface_flag_default_none(self):
        parser = build_parser()
        args = parser.parse_args(["scan"])
        assert args.view_interface is None


class TestViewSubcommand:
    """Parsing + dispatch for `argus view`."""

    def test_view_default_args(self):
        parser = build_parser()
        args = parser.parse_args(["view"])
        assert args.command == "view"
        assert args.interface_or_path is None
        assert args.interface_flag is None
        assert args.path_arg is None
        assert args.check is False

    def test_view_check_flag_parses(self):
        parser = build_parser()
        args = parser.parse_args(["view", "--check"])
        assert args.check is True

    def test_view_check_succeeds_when_results_present(self, tmp_path, capsys):
        """--check resolves the path, finds argus-results.json, prints OK,
        and exits 0 without launching the viewer."""
        from argus.cli import _check_view_artifact, EXIT_SUCCESS
        (tmp_path / "argus-results.json").write_text("{}")

        rc = _check_view_artifact(str(tmp_path))
        assert rc == EXIT_SUCCESS
        out = capsys.readouterr().out
        assert "OK:" in out
        assert "argus-results.json" in out

    def test_view_check_emits_diagnoser_when_results_missing(self, tmp_path, capsys, monkeypatch):
        """--check fails clean with the diagnoser's remediation message —
        no traceback, no launching viewer, EXIT_ERROR for CI gating."""
        from argus.cli import _check_view_artifact, EXIT_ERROR
        # No argus-results.json in tmp_path; no argus.yml either, so we
        # exercise the generic-hint branch.
        monkeypatch.chdir(tmp_path)

        rc = _check_view_artifact(str(tmp_path))
        assert rc == EXIT_ERROR
        err = capsys.readouterr().err
        # Original missing-file diagnostic is preserved...
        assert "argus-results.json not found" in err
        # ...and accompanied by both fix paths.
        assert "argus scan --format json" in err
        assert "reporting.formats" in err

    def test_view_positional_terminal(self):
        parser = build_parser()
        args = parser.parse_args(["view", "terminal"])
        assert args.interface_or_path == "terminal"
        assert args.path_arg is None

    def test_view_positional_browser_with_path(self):
        parser = build_parser()
        args = parser.parse_args(["view", "browser", "./run-01"])
        assert args.interface_or_path == "browser"
        assert args.path_arg == "./run-01"

    def test_view_path_only_positional(self):
        """Bare `argus view ./path` works — first positional is treated as path."""
        parser = build_parser()
        args = parser.parse_args(["view", "./argus-results/latest"])
        # Parser doesn't disambiguate; the resolver does.
        assert args.interface_or_path == "./argus-results/latest"
        assert args.path_arg is None

    def test_view_flag_form(self):
        parser = build_parser()
        args = parser.parse_args(["view", "--interface=terminal"])
        assert args.interface_flag == "terminal"

    def test_view_flag_with_path_positional(self):
        """`argus view -i terminal ./path` — the flag carries the interface,
        the lone positional is a path. (Regression for the bug where argparse
        choices= rejected the path as INTERFACE.)
        """
        parser = build_parser()
        args = parser.parse_args(["view", "-i", "terminal", "./run-01"])
        assert args.interface_flag == "terminal"
        assert args.interface_or_path == "./run-01"
        assert args.path_arg is None

    def test_view_resolve_defaults_to_terminal(self):
        from argus.cli import _resolve_view_args
        import argparse as _argparse
        ns = _argparse.Namespace(
            interface_or_path=None, path_arg=None, interface_flag=None,
        )
        assert _resolve_view_args(ns) == ("terminal", None)

    def test_view_resolve_prefers_flag_over_default(self):
        from argus.cli import _resolve_view_args
        import argparse as _argparse
        ns = _argparse.Namespace(
            interface_or_path=None, path_arg=None, interface_flag="browser",
        )
        assert _resolve_view_args(ns) == ("browser", None)

    def test_view_resolve_path_only_positional(self):
        """First positional is a path → interface defaults to terminal."""
        from argus.cli import _resolve_view_args
        import argparse as _argparse
        ns = _argparse.Namespace(
            interface_or_path="./argus-results/latest",
            path_arg=None,
            interface_flag=None,
        )
        assert _resolve_view_args(ns) == ("terminal", "./argus-results/latest")

    def test_view_resolve_flag_plus_path_positional(self):
        """`argus view -i browser ./path` → (browser, ./path)."""
        from argus.cli import _resolve_view_args
        import argparse as _argparse
        ns = _argparse.Namespace(
            interface_or_path="./run-01",
            path_arg=None,
            interface_flag="browser",
        )
        assert _resolve_view_args(ns) == ("browser", "./run-01")

    def test_view_resolve_interface_keyword_plus_path(self):
        """`argus view terminal ./path` → (terminal, ./path)."""
        from argus.cli import _resolve_view_args
        import argparse as _argparse
        ns = _argparse.Namespace(
            interface_or_path="terminal",
            path_arg="./run-01",
            interface_flag=None,
        )
        assert _resolve_view_args(ns) == ("terminal", "./run-01")

    def test_view_resolve_conflict_returns_none(self, capsys):
        from argus.cli import _resolve_view_args
        import argparse as _argparse
        ns = _argparse.Namespace(
            interface_or_path="terminal",
            path_arg=None,
            interface_flag="browser",
        )
        assert _resolve_view_args(ns) is None
        err = capsys.readouterr().err
        assert "conflicting" in err.lower()

    def test_view_resolve_two_interface_keywords_errors(self, capsys):
        from argus.cli import _resolve_view_args
        import argparse as _argparse
        ns = _argparse.Namespace(
            interface_or_path="terminal",
            path_arg="browser",
            interface_flag=None,
        )
        assert _resolve_view_args(ns) is None
        err = capsys.readouterr().err
        assert "interface keyword" in err.lower()

    def test_view_resolve_two_paths_errors(self, capsys):
        from argus.cli import _resolve_view_args
        import argparse as _argparse
        ns = _argparse.Namespace(
            interface_or_path="./a",
            path_arg="./b",
            interface_flag=None,
        )
        assert _resolve_view_args(ns) is None
        err = capsys.readouterr().err
        assert "two paths" in err.lower()

    def test_view_terminal_unavailable_returns_error(self, monkeypatch, capsys):
        """When the `terminal` extra isn't installed, exit clean with a hint."""
        from argus.cli import cmd_view
        import argparse as _argparse

        def fake_launch(_results):
            from argus.viewers import ViewerUnavailable
            raise ViewerUnavailable(
                "The terminal interface needs the 'terminal' extra. "
                "Install it with: pip install 'argus-security[terminal]'"
            )
        monkeypatch.setattr("argus.viewers.terminal.launch", fake_launch)

        rc = cmd_view(_argparse.Namespace(
            interface_or_path="terminal",
            path_arg=None,
            interface_flag=None,
            port=8080,
            no_open=True,
        ))
        assert rc == EXIT_ERROR
        err = capsys.readouterr().err
        assert "argus-security[terminal]" in err

    def test_view_browser_unavailable_returns_error(self, monkeypatch, capsys):
        """When the `browser` extra isn't installed, exit clean with a hint."""
        from argus.cli import cmd_view
        import argparse as _argparse

        def fake_launch(*, root, port, open_browser):
            from argus.viewers import ViewerUnavailable
            raise ViewerUnavailable(
                "The browser interface needs the 'browser' extra. "
                "Install it with: pip install 'argus-security[browser]'"
            )
        monkeypatch.setattr("argus.viewers.browser.launch", fake_launch)

        rc = cmd_view(_argparse.Namespace(
            interface_or_path="browser",
            path_arg=None,
            interface_flag=None,
            port=8080,
            no_open=True,
        ))
        assert rc == EXIT_ERROR
        err = capsys.readouterr().err
        assert "argus-security[browser]" in err


class TestLaunchViewAfterScan:
    """Covers the ``--interface`` dispatch extracted from ``cmd_scan``.

    Exercised directly rather than via a full scan run so we don't
    need to stand up scanner plumbing just to verify the viewer
    handoff. The handoff has two failure modes it must absorb without
    affecting the scan's exit code:

    - ``ViewerUnavailable`` (user didn't install the matching extra)
    - ``ImportError`` (something stranger wrong with the import chain)

    The first is the normal case — ships a message to stderr; the
    second is defensive and explicitly ``pragma: no cover``.
    """

    def test_terminal_happy_path_calls_launch(self, monkeypatch):
        from argus.cli import _launch_view_after_scan

        calls = []
        def fake_launch(results_dir):
            calls.append(results_dir)
            return 0
        monkeypatch.setattr("argus.viewers.terminal.launch", fake_launch)

        _launch_view_after_scan("terminal", "/tmp/scan-output")
        assert calls == ["/tmp/scan-output"]

    def test_browser_happy_path_calls_launch(self, monkeypatch):
        from argus.cli import _launch_view_after_scan

        calls = []
        def fake_launch(*, root, **_kw):
            calls.append(root)
            return 0
        monkeypatch.setattr("argus.viewers.browser.launch", fake_launch)

        _launch_view_after_scan("browser", "/tmp/scan-output")
        assert calls == ["/tmp/scan-output"]

    def test_terminal_unavailable_prints_to_stderr_without_raising(self, monkeypatch, capsys):
        from argus.cli import _launch_view_after_scan

        def fake_launch(_results_dir):
            from argus.viewers import ViewerUnavailable
            raise ViewerUnavailable(
                "The terminal interface needs the 'terminal' extra."
            )
        monkeypatch.setattr("argus.viewers.terminal.launch", fake_launch)

        # Returns cleanly — scan's exit code is unaffected by the
        # optional viewer handoff failure.
        _launch_view_after_scan("terminal", "/tmp/scan-output")
        err = capsys.readouterr().err
        assert "terminal" in err.lower()


class TestViewerUnavailableGuards:
    """Covers the ``argus.viewers.{terminal,browser}`` import-guard helpers.

    The cmd-level tests patch ``launch`` wholesale, so the real
    ``_require_textual`` and ``_require_web_stack`` branches never run
    under test. Exercise them here by simulating missing modules
    during import.
    """

    def test_require_textual_raises_when_missing(self, monkeypatch):
        import builtins
        from argus.viewers.terminal import _require_textual
        from argus.viewers import ViewerUnavailable

        real_import = builtins.__import__

        def fake_import(name, *a, **kw):
            if name == "textual":
                raise ImportError("No module named 'textual'")
            return real_import(name, *a, **kw)

        monkeypatch.setattr(builtins, "__import__", fake_import)

        with pytest.raises(ViewerUnavailable) as excinfo:
            _require_textual()
        assert "argus-security[terminal]" in str(excinfo.value)

    def test_terminal_launch_delegates_to_run_app_when_textual_available(self, monkeypatch):
        # Real argus.viewers.terminal.launch body: _require_textual() then
        # `from argus.viewers.terminal.app import run_app; return run_app(...)`.
        # Stub both so we don't need the live Textual runtime.
        import argus.viewers.terminal

        monkeypatch.setattr(argus.viewers.terminal, "_require_textual", lambda: None)
        import sys
        import types
        fake_module = types.ModuleType("argus.viewers.terminal.app")
        calls = []
        def fake_run_app(results_dir):
            calls.append(results_dir)
            return 0
        fake_module.run_app = fake_run_app
        monkeypatch.setitem(sys.modules, "argus.viewers.terminal.app", fake_module)

        rc = argus.viewers.terminal.launch("/some/dir")
        assert rc == 0
        assert calls == ["/some/dir"]


class TestSbomDirectoryMerge:
    """CLI helper that collapses per-SBOM ScanSummary objects into one."""

    def _make_info(self, tmp_path, name: str):
        from argus.core.sbom import SbomInfo
        p = tmp_path / name
        p.write_text("{}")
        return SbomInfo(path=p, format="cyclonedx-json")

    def _make_summary(self, scanner: str, findings):
        from argus.core.models import ScanResult, ScanSummary
        return ScanSummary(
            results=[ScanResult(scanner=scanner, findings=findings, metadata={"execution": "local"})],
            severity_threshold=None,
        )

    def _finding(self, fid: str):
        from argus.core.models import Finding, Severity
        return Finding(
            id=fid, severity=Severity.HIGH, title=fid,
            scanner="osv", metadata={},
        )

    def test_single_sbom_preserved(self, tmp_path):
        from argus.cli import _merge_sbom_summaries
        info = self._make_info(tmp_path, "sbom.json")
        summary = self._make_summary("osv", [self._finding("CVE-1")])

        merged = _merge_sbom_summaries([(info, summary)], severity_threshold=None)

        assert len(merged.results) == 1
        assert merged.results[0].scanner == "osv"
        assert len(merged.results[0].findings) == 1
        # Finding is annotated with its source SBOM
        assert merged.results[0].findings[0].metadata["sbom_source"] == str(info.path)

    def test_multiple_sboms_same_scanner_collapse(self, tmp_path):
        from argus.cli import _merge_sbom_summaries

        info_a = self._make_info(tmp_path, "a.json")
        info_b = self._make_info(tmp_path, "b.json")
        summary_a = self._make_summary("osv", [self._finding("CVE-1")])
        summary_b = self._make_summary("osv", [self._finding("CVE-2")])

        merged = _merge_sbom_summaries(
            [(info_a, summary_a), (info_b, summary_b)],
            severity_threshold=None,
        )

        assert len(merged.results) == 1
        assert merged.results[0].scanner == "osv"
        assert {f.id for f in merged.results[0].findings} == {"CVE-1", "CVE-2"}

        sources = [f.metadata["sbom_source"] for f in merged.results[0].findings]
        assert str(info_a.path) in sources
        assert str(info_b.path) in sources

    def test_records_all_sbom_sources_in_metadata(self, tmp_path):
        from argus.cli import _merge_sbom_summaries

        info_a = self._make_info(tmp_path, "a.json")
        info_b = self._make_info(tmp_path, "b.json")
        merged = _merge_sbom_summaries(
            [
                (info_a, self._make_summary("osv", [])),
                (info_b, self._make_summary("osv", [])),
            ],
            severity_threshold=None,
        )
        sources = merged.results[0].metadata["sbom_sources"]
        assert sources == [str(info_a.path), str(info_b.path)]

    def test_multiple_scanners_one_result_each(self, tmp_path):
        from argus.cli import _merge_sbom_summaries
        from argus.core.models import ScanResult, ScanSummary

        info = self._make_info(tmp_path, "sbom.json")
        summary = ScanSummary(
            results=[
                ScanResult(scanner="osv", findings=[self._finding("CVE-1")], metadata={}),
                ScanResult(scanner="grype", findings=[self._finding("CVE-2")], metadata={}),
            ],
            severity_threshold=None,
        )
        merged = _merge_sbom_summaries([(info, summary)], severity_threshold=None)

        by_scanner = {r.scanner: r for r in merged.results}
        assert set(by_scanner.keys()) == {"osv", "grype"}


class TestSbomBatchResilience:
    """A per-SBOM failure must not abort the rest of the batch."""

    def _setup_project(self, tmp_path):
        # Minimal argus.yml so `argus scan` doesn't bail at config load.
        (tmp_path / "argus.yml").write_text(
            'version: "1.0"\n'
            "scanners:\n"
            "  osv:\n"
            "    enabled: true\n"
            "reporting:\n"
            "  formats: [json]\n"
            "execution:\n"
            "  backend: auto\n"
        )

    def _sbom_dir(self, tmp_path, names):
        """Create a tmp dir with N minimally-valid CycloneDX JSON SBOMs."""
        import json as _json
        d = tmp_path / "sboms"
        d.mkdir()
        for name in names:
            (d / name).write_text(_json.dumps({
                "bomFormat": "CycloneDX", "specVersion": "1.5", "components": [],
            }))
        return d

    def _run(self, tmp_path, sbom_arg, engine_run):
        """Invoke cmd_scan with engine.run monkeypatched to `engine_run`."""
        from argus.cli import cmd_scan
        from argus.core.config import ArgusConfig, ExecutionConfig, ReportingConfig
        import argparse

        self._setup_project(tmp_path)

        # Minimal in-memory config that skips actual config loading.
        cfg = ArgusConfig(
            reporting=ReportingConfig(
                output_dir=str(tmp_path / "out"),
                formats=[],
                severity_threshold=None,
            ),
            execution=ExecutionConfig(),
        )
        # monkeypatch via argparse.Namespace + sys.monkeypatch not available here;
        # use pytest's monkeypatch through the fixture instead.
        return cmd_scan, cfg, argparse, tmp_path, sbom_arg, engine_run

    def test_one_bad_sbom_does_not_abort_batch(self, tmp_path, monkeypatch):
        """First SBOM raises mid-batch → second SBOM still runs; exit=EXIT_ERROR."""
        from argus.cli import cmd_scan, EXIT_ERROR, EXIT_SUCCESS
        from argus.core.config import ArgusConfig, ExecutionConfig, ReportingConfig
        from argus.core.models import ScanSummary
        import argparse

        self._setup_project(tmp_path)
        sboms = self._sbom_dir(tmp_path, ["a.json", "b.json", "c.json"])

        cfg = ArgusConfig(
            reporting=ReportingConfig(
                output_dir=str(tmp_path / "out"),
                formats=[],
                severity_threshold=None,
            ),
            execution=ExecutionConfig(),
        )
        monkeypatch.setattr(
            "argus.core.config.ArgusConfig.load", lambda _p: cfg,
        )

        seen: list[str] = []

        def fake_run(self, **kwargs):
            sbom_path = kwargs.get("sbom_path", "")
            seen.append(sbom_path)
            # a.json blows up mid-batch; others succeed with zero findings.
            if sbom_path.endswith("a.json"):
                raise RuntimeError("Docker daemon vanished")
            return ScanSummary(results=[], severity_threshold=None)

        monkeypatch.setattr("argus.core.engine.ArgusEngine.run", fake_run)
        monkeypatch.setattr(
            "argus.core.engine.ArgusEngine.register_scanner",
            lambda self, _s: None,
        )
        monkeypatch.setattr(
            "argus.core.engine.ArgusEngine.__init__",
            lambda self, _cfg: (
                setattr(self, "config", cfg) or setattr(self, "_scanners", {"osv": object})
            ),
        )
        monkeypatch.setattr(
            "argus.scanners.get_available_scanners", lambda: [],
        )
        monkeypatch.setattr(
            "argus.reporters.get_reporter", lambda fmt: __import__("unittest.mock").mock.MagicMock(),
        )
        monkeypatch.setattr("argus.audit.get_logger", lambda *a, **kw: __import__("logging").getLogger("test"))
        monkeypatch.setattr("argus.audit.create_manifest", lambda **kw: __import__("unittest.mock").mock.MagicMock(execution_backend=None))
        monkeypatch.setattr("argus.audit.finalize_manifest", lambda *a, **kw: None)

        args = argparse.Namespace(
            command="scan", scanner=None, path=".", config=str(tmp_path / "argus.yml"),
            formats=None, severity_threshold=None, output_dir=str(tmp_path / "out"),
            list=False, verbose=False, exclude="", no_default_excludes=False,
            dry_run=False, fail_fast=False, timeout=None, no_parallel=False,
            allow_local_versions=False, no_cache=False, no_timestamp=True,
            no_spinner=True, output_vars=None, discover=None, images=None,
            scanners=None, target=None, port=None, env_vars=None,
            scan_type="baseline", startup_timeout=60, check_tools=False,
            sbom=str(sboms),
        )
        rc = cmd_scan(args)

        # All three SBOMs were attempted despite a.json raising
        assert len(seen) == 3
        assert any(p.endswith("a.json") for p in seen)
        assert any(p.endswith("b.json") for p in seen)
        assert any(p.endswith("c.json") for p in seen)
        # Exit is EXIT_ERROR (batch had a failure), NOT mid-batch abort
        assert rc == EXIT_ERROR

    def test_clean_batch_returns_success(self, tmp_path, monkeypatch):
        """Every SBOM scans cleanly → EXIT_SUCCESS."""
        from argus.cli import cmd_scan, EXIT_SUCCESS
        from argus.core.config import ArgusConfig, ExecutionConfig, ReportingConfig
        from argus.core.models import ScanSummary
        import argparse

        self._setup_project(tmp_path)
        sboms = self._sbom_dir(tmp_path, ["a.json", "b.json"])

        cfg = ArgusConfig(
            reporting=ReportingConfig(
                output_dir=str(tmp_path / "out"),
                formats=[],
                severity_threshold=None,
            ),
            execution=ExecutionConfig(),
        )
        monkeypatch.setattr("argus.core.config.ArgusConfig.load", lambda _p: cfg)

        monkeypatch.setattr(
            "argus.core.engine.ArgusEngine.run",
            lambda self, **kw: ScanSummary(results=[], severity_threshold=None),
        )
        monkeypatch.setattr(
            "argus.core.engine.ArgusEngine.register_scanner",
            lambda self, _s: None,
        )
        monkeypatch.setattr(
            "argus.core.engine.ArgusEngine.__init__",
            lambda self, _cfg: (
                setattr(self, "config", cfg) or setattr(self, "_scanners", {"osv": object})
            ),
        )
        monkeypatch.setattr("argus.scanners.get_available_scanners", lambda: [])
        monkeypatch.setattr(
            "argus.reporters.get_reporter", lambda fmt: __import__("unittest.mock").mock.MagicMock(),
        )
        monkeypatch.setattr("argus.audit.get_logger", lambda *a, **kw: __import__("logging").getLogger("test"))
        monkeypatch.setattr("argus.audit.create_manifest", lambda **kw: __import__("unittest.mock").mock.MagicMock(execution_backend=None))
        monkeypatch.setattr("argus.audit.finalize_manifest", lambda *a, **kw: None)

        args = argparse.Namespace(
            command="scan", scanner=None, path=".", config=str(tmp_path / "argus.yml"),
            formats=None, severity_threshold=None, output_dir=str(tmp_path / "out"),
            list=False, verbose=False, exclude="", no_default_excludes=False,
            dry_run=False, fail_fast=False, timeout=None, no_parallel=False,
            allow_local_versions=False, no_cache=False, no_timestamp=True,
            no_spinner=True, output_vars=None, discover=None, images=None,
            scanners=None, target=None, port=None, env_vars=None,
            scan_type="baseline", startup_timeout=60, check_tools=False,
            sbom=str(sboms),
        )
        rc = cmd_scan(args)
        assert rc == EXIT_SUCCESS


class TestDryRun:
    """End-to-end coverage for --dry-run output."""

    def _setup_project(self, tmp_path):
        (tmp_path / "argus.yml").write_text(
            'version: "1.0"\n'
            "scanners:\n"
            "  bandit:\n"
            "    enabled: true\n"
            "reporting:\n"
            "  formats: [terminal]\n"
            "execution:\n"
            "  backend: auto\n"
        )

    def test_dry_run_prints_plan_and_exits_success(self, tmp_path, capsys, monkeypatch):
        self._setup_project(tmp_path)
        (tmp_path / ".bandit").write_text("[bandit]\nskips = [\"B101\"]\n")
        monkeypatch.chdir(tmp_path)

        from argus.cli import cmd_scan
        import argparse

        args = argparse.Namespace(
            command="scan",
            scanner=None,
            path=str(tmp_path),
            config="argus.yml",
            formats=None,
            severity_threshold=None,
            output_dir=None,
            list=False,
            verbose=False,
            exclude="",
            no_default_excludes=False,
            dry_run=True,
            fail_fast=False,
            timeout=None,
            no_parallel=False,
            allow_local_versions=False,
            no_cache=False,
            no_timestamp=False,
            no_spinner=True,
            output_vars=None,
            discover=None,
            images=None,
            scanners=None,
            target=None,
            port=None,
            env_vars=None,
            scan_type="baseline",
            startup_timeout=60,
            check_tools=False,
        )
        result = cmd_scan(args)
        assert result == EXIT_SUCCESS

        out = capsys.readouterr().out
        assert "dry-run" in out
        assert "bandit" in out
        assert ".bandit" in out  # auto-discovered config surfaced
        assert "Exclusion patterns" in out

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


class TestCmdMcp:
    """``argus mcp`` UX guards.

    The MCP server uses stdio transport: it speaks JSON-RPC on
    stdin/stdout and any stray write to stdout would corrupt the
    protocol. So all human feedback must go to stderr — and we
    DO need feedback, otherwise users running ``argus mcp``
    interactively see a silent terminal and assume it hung.
    """

    def _stub_server(self, monkeypatch):
        """Replace ``create_server`` with a stub whose .run() returns
        immediately, so the test never actually starts a real MCP loop."""
        class _StubServer:
            def __init__(self):
                self.run_called_with = None

            def run(self, transport):
                self.run_called_with = transport

        stub = _StubServer()
        # cmd_mcp does ``from argus.mcp import create_server`` lazily,
        # so patch the import target by injecting a fake module.
        import sys
        import types
        fake = types.ModuleType("argus.mcp")
        fake.create_server = lambda: stub
        monkeypatch.setitem(sys.modules, "argus.mcp", fake)
        return stub

    def test_startup_banner_goes_to_stderr_not_stdout(self, monkeypatch, capsys):
        # stdout is the JSON-RPC channel — anything we write there
        # would corrupt the protocol. The banner must land on stderr.
        from argus.cli import cmd_mcp
        import argparse as _argparse

        self._stub_server(monkeypatch)
        rc = cmd_mcp(_argparse.Namespace())
        captured = capsys.readouterr()
        assert rc == EXIT_SUCCESS
        assert captured.out == "", "stdout must stay empty for the protocol"
        assert "argus MCP server starting" in captured.err

    def test_run_invoked_with_stdio_transport(self, monkeypatch):
        from argus.cli import cmd_mcp
        import argparse as _argparse

        stub = self._stub_server(monkeypatch)
        cmd_mcp(_argparse.Namespace())
        assert stub.run_called_with == "stdio"

    def test_interactive_hint_only_when_stderr_is_a_tty(self, monkeypatch, capsys):
        # When invoked by an MCP client (subprocess with piped stderr)
        # the hint adds noise to client logs without helping anyone.
        # Only humans staring at a real terminal benefit from it.
        from argus.cli import cmd_mcp
        import argparse as _argparse
        import sys as _sys

        self._stub_server(monkeypatch)

        # Non-tty stderr (the default during pytest capture) — no hint.
        monkeypatch.setattr(_sys.stderr, "isatty", lambda: False)
        cmd_mcp(_argparse.Namespace())
        err_no_tty = capsys.readouterr().err
        assert "argus MCP server starting" in err_no_tty
        assert "Press Ctrl+C" not in err_no_tty

        # tty stderr — hint included.
        self._stub_server(monkeypatch)
        monkeypatch.setattr(_sys.stderr, "isatty", lambda: True)
        cmd_mcp(_argparse.Namespace())
        err_tty = capsys.readouterr().err
        assert "argus MCP server starting" in err_tty
        assert "Press Ctrl+C" in err_tty

    def test_missing_extra_returns_friendly_error(self, monkeypatch, capsys):
        from argus.cli import cmd_mcp
        import argparse as _argparse
        import builtins

        # Force the lazy ``from argus.mcp import create_server`` to fail.
        real_import = builtins.__import__
        def fake_import(name, *a, **kw):
            if name == "argus.mcp":
                raise ImportError("No module named 'mcp'")
            return real_import(name, *a, **kw)
        monkeypatch.setattr(builtins, "__import__", fake_import)

        rc = cmd_mcp(_argparse.Namespace())
        assert rc == EXIT_ERROR
        err = capsys.readouterr().err
        assert "argus-security[mcp]" in err
