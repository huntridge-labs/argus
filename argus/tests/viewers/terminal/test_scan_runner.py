"""Unit tests for the terminal viewer's scan-runner argv construction.

Pure (no Textual, no subprocess): these pin the exact ``argus scan``
command the TUI overlay runs, and the "where do new runs land?" logic
the runs sidebar relies on to find them afterwards.
"""

from __future__ import annotations

import sys
from pathlib import Path

from argus.core.run_discovery import RESULTS_FILENAME
from argus.viewers.terminal.scan_runner import (
    build_scan_argv,
    format_command,
    resolve_output_base,
)


class TestBuildScanArgv:
    def test_defaults_request_json_and_no_spinner(self):
        argv = build_scan_argv()
        assert argv[:4] == [sys.executable, "-m", "argus", "scan"]
        # JSON is non-negotiable — the viewers consume argus-results.json.
        assert "--format" in argv and "json" in argv
        assert "terminal" in argv
        assert "--no-spinner" in argv
        assert argv[argv.index("--path") + 1] == "."

    def test_specific_scanner_is_positional_after_scan(self):
        argv = build_scan_argv(scanner="bandit")
        assert argv[:5] == [sys.executable, "-m", "argus", "scan", "bandit"]

    def test_config_and_output_dir_flags(self):
        argv = build_scan_argv(config="argus.yml", output_dir=Path("out"))
        assert argv[argv.index("--config") + 1] == "argus.yml"
        assert argv[argv.index("--output-dir") + 1] == "out"

    def test_no_spinner_can_be_disabled(self):
        assert "--no-spinner" not in build_scan_argv(no_spinner=False)

    def test_custom_path(self):
        argv = build_scan_argv(path="src/")
        assert argv[argv.index("--path") + 1] == "src/"


class TestResolveOutputBase:
    def test_none_defaults_to_argus_results(self):
        assert resolve_output_base(None) == Path("argus-results")

    def test_single_run_dir_resolves_to_parent(self, tmp_path):
        run = tmp_path / "2026-06-12"
        run.mkdir()
        (run / RESULTS_FILENAME).write_text("{}", encoding="utf-8")
        assert resolve_output_base(str(run)) == run.parent

    def test_runs_parent_dir_resolves_to_itself(self, tmp_path):
        # A directory that isn't itself a single run stays as-is.
        assert resolve_output_base(str(tmp_path)) == tmp_path


class TestFormatCommand:
    def test_collapses_python_module_invocation_to_argus(self):
        argv = [sys.executable, "-m", "argus", "scan", "bandit"]
        assert format_command(argv) == "argus scan bandit"

    def test_quotes_arguments_with_spaces(self):
        argv = [sys.executable, "-m", "argus", "scan", "--path", "my dir"]
        rendered = format_command(argv)
        assert "'my dir'" in rendered
        assert rendered.startswith("argus scan")

    def test_non_module_argv_passes_through(self):
        # Defensive: a plain argv that doesn't match the -m argus shape
        # is rendered verbatim rather than mangled.
        assert format_command(["argus", "scan"]) == "argus scan"
