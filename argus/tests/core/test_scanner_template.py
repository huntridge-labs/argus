"""Tests for argus.core.scanner_template.

Locks in the contract: every scanner that calls run_subprocess_scan
goes through this code path, so any regression here breaks every
migrated scanner at once.
"""

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from argus.core.models import Finding, Severity
from argus.core.scanner_template import ScanPaths, run_subprocess_scan


# --------------------------------------------------------------------- #
# Test doubles                                                          #
# --------------------------------------------------------------------- #


class _FakeScanner:
    """Minimal scanner satisfying the protocol shape."""

    name = "fake"

    def __init__(self, args=None, parse=None):
        self._args = args or []
        self._parse = parse or (lambda p: [])

    def build_args(self, paths: ScanPaths, config: dict) -> list[str]:
        # Echo the paths into the command so tests can assert wiring.
        return ["fake", "--in", paths.workspace, "--out", paths.output] + self._args

    def parse_results(self, output_path: Path):
        return self._parse(output_path)


def _completed(stdout: str = "", stderr: str = "", returncode: int = 0):
    return subprocess.CompletedProcess(
        args=["fake"], returncode=returncode, stdout=stdout, stderr=stderr,
    )


# --------------------------------------------------------------------- #
# Happy paths                                                           #
# --------------------------------------------------------------------- #


class TestRunSubprocessScan:

    def test_writes_findings_when_output_file_exists(self, tmp_path):
        finding = Finding(id="X", severity=Severity.HIGH, title="t", scanner="fake")
        scanner = _FakeScanner(parse=lambda p: [finding])

        def fake_run(cmd, **kwargs):
            # The template wires ScanPaths.output into argv; write to it.
            output_path = Path(cmd[cmd.index("--out") + 1])
            output_path.write_text("{}")
            return _completed()

        with patch("subprocess.run", side_effect=fake_run):
            result = run_subprocess_scan(scanner, str(tmp_path))

        assert result.scanner == "fake"
        assert result.findings == [finding]
        assert "error" not in result.metadata

    def test_passes_workspace_path_through_to_build_args(self, tmp_path):
        scanner = _FakeScanner()

        captured: dict = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            output_path = Path(cmd[cmd.index("--out") + 1])
            output_path.write_text("{}")
            return _completed()

        with patch("subprocess.run", side_effect=fake_run):
            run_subprocess_scan(scanner, "/some/workspace")

        assert "/some/workspace" in captured["cmd"]
        # Output path lives inside a tempdir (not under workspace).
        out_idx = captured["cmd"].index("--out")
        assert "/some/workspace" not in captured["cmd"][out_idx + 1]

    def test_passes_config_through_to_build_args(self, tmp_path):
        # Tool-specific knobs (lockfile, exclude, config_file, sbom_path) live
        # in config, not on ScanPaths — the helper hands the config dict
        # straight through to ``build_args(paths, config)``.
        seen: list[dict] = []

        class CapturingScanner:
            name = "fake"

            def build_args(self, paths, config):
                seen.append(config)
                return ["fake", "--out", paths.output]

            def parse_results(self, output_path):
                return []

        def fake_run(cmd, **kwargs):
            output_path = Path(cmd[cmd.index("--out") + 1])
            output_path.write_text("{}")
            return _completed()

        with patch("subprocess.run", side_effect=fake_run):
            run_subprocess_scan(
                CapturingScanner(),
                str(tmp_path),
                config={"config_file": ".bandit", "sbom_path": "/tmp/x.spdx.json"},
            )

        assert seen[0]["config_file"] == ".bandit"
        assert seen[0]["sbom_path"] == "/tmp/x.spdx.json"

    def test_unpacks_passed_count_tuple(self, tmp_path):
        # checkov-style return: (findings, passed_count_int)
        scanner = _FakeScanner(parse=lambda p: ([], 42))

        def fake_run(cmd, **kwargs):
            output_path = Path(cmd[cmd.index("--out") + 1])
            output_path.write_text("{}")
            return _completed()

        with patch("subprocess.run", side_effect=fake_run):
            result = run_subprocess_scan(scanner, str(tmp_path))

        assert result.metadata.get("passed_count") == 42

    def test_unpacks_metadata_dict_tuple(self, tmp_path):
        scanner = _FakeScanner(parse=lambda p: ([], {"warnings": 3}))

        def fake_run(cmd, **kwargs):
            output_path = Path(cmd[cmd.index("--out") + 1])
            output_path.write_text("{}")
            return _completed()

        with patch("subprocess.run", side_effect=fake_run):
            result = run_subprocess_scan(scanner, str(tmp_path))

        assert result.metadata.get("warnings") == 3

    def test_falls_back_to_stdout_when_no_output_file(self, tmp_path):
        scanner = _FakeScanner(parse=lambda p: [Finding(
            id="Y", severity=Severity.LOW, title="from stdout", scanner="fake",
        )])

        def fake_run(cmd, **kwargs):
            # Don't write the output file — emit on stdout instead.
            return _completed(stdout=json.dumps({"data": []}))

        with patch("subprocess.run", side_effect=fake_run):
            result = run_subprocess_scan(scanner, str(tmp_path))

        assert len(result.findings) == 1
        assert result.findings[0].title == "from stdout"

    def test_overrides_output_filename(self, tmp_path):
        captured: dict = {}

        class SarifScanner:
            name = "sarif-fake"

            def build_args(self, paths, config):
                captured["output"] = paths.output
                return ["fake", "--out", paths.output]

            def parse_results(self, output_path):
                return []

        def fake_run(cmd, **kwargs):
            Path(cmd[cmd.index("--out") + 1]).write_text("{}")
            return _completed()

        with patch("subprocess.run", side_effect=fake_run):
            run_subprocess_scan(
                SarifScanner(), str(tmp_path), output_filename="results.sarif",
            )

        assert captured["output"].endswith("results.sarif")


# --------------------------------------------------------------------- #
# Failure paths                                                         #
# --------------------------------------------------------------------- #


class TestFailures:

    def test_missing_binary_returns_error_metadata(self, tmp_path):
        scanner = _FakeScanner()
        with patch("subprocess.run", side_effect=FileNotFoundError(2, "no such file", "fake")):
            result = run_subprocess_scan(scanner, str(tmp_path))
        assert result.findings == []
        assert "Tool not found" in result.metadata.get("error", "")

    def test_timeout_returns_error_metadata(self, tmp_path):
        scanner = _FakeScanner()
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("fake", 5)):
            result = run_subprocess_scan(scanner, str(tmp_path), timeout=5)
        assert "timed out" in result.metadata.get("error", "")

    def test_no_output_no_stdout_returns_error_metadata(self, tmp_path):
        scanner = _FakeScanner()
        with patch(
            "subprocess.run",
            return_value=_completed(stdout="", stderr="boom", returncode=2),
        ):
            result = run_subprocess_scan(scanner, str(tmp_path))
        err = result.metadata.get("error", "")
        assert "No output produced" in err
        assert "boom" in err

    def test_unexpected_exception_propagates(self, tmp_path):
        # Bugs in scanner.parse_results shouldn't be silently translated.
        scanner = _FakeScanner(parse=lambda p: (_ for _ in ()).throw(ValueError("bad json")))

        def fake_run(cmd, **kwargs):
            Path(cmd[cmd.index("--out") + 1]).write_text("{}")
            return _completed()

        with patch("subprocess.run", side_effect=fake_run):
            with pytest.raises(ValueError, match="bad json"):
                run_subprocess_scan(scanner, str(tmp_path))


# --------------------------------------------------------------------- #
# ScanPaths                                                             #
# --------------------------------------------------------------------- #


class TestScanPaths:

    def test_holds_workspace_and_output(self):
        paths = ScanPaths(workspace="/in", output="/out/r.json")
        assert paths.workspace == "/in"
        assert paths.output == "/out/r.json"

    def test_frozen(self):
        paths = ScanPaths(workspace="/in", output="/out")
        with pytest.raises(Exception):  # FrozenInstanceError or AttributeError
            paths.workspace = "/other"  # type: ignore[misc]
