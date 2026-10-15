"""Tests for argus.scanners.opengrep — OpengrepScanner."""

import subprocess
from pathlib import Path

import pytest

from argus.core.config import ArgusConfig
from argus.core.engine import ArgusEngine
from argus.core.models import Severity
from argus.scanners.opengrep import OpengrepScanner


class TestOpengrepParseResults:
    """Test OpengrepScanner.parse_results with fixture data."""

    def test_parse_results_with_findings(self, fixtures_dir):
        scanner = OpengrepScanner()
        path = fixtures_dir / "opengrep" / "results-with-findings.json"
        findings = scanner.parse_results(path)

        assert len(findings) == 4

        severities = [f.severity for f in findings]
        # ERROR -> HIGH, WARNING -> MEDIUM (x2), INFO -> INFO
        assert severities.count(Severity.HIGH) == 1
        assert severities.count(Severity.MEDIUM) == 2
        assert severities.count(Severity.INFO) == 1

    def test_parse_results_zero_findings(self, fixtures_dir):
        scanner = OpengrepScanner()
        path = fixtures_dir / "opengrep" / "results-zero-findings.json"
        findings = scanner.parse_results(path)

        assert len(findings) == 0

    def test_finding_fields(self, fixtures_dir):
        scanner = OpengrepScanner()
        path = fixtures_dir / "opengrep" / "results-with-findings.json"
        findings = scanner.parse_results(path)

        # HIGH finding (ERROR severity)
        high = [f for f in findings if f.severity == Severity.HIGH][0]
        assert high.id == "python.security.audit.dangerous-subprocess-use"
        assert high.scanner == "opengrep"
        assert high.cwe == "CWE-78"
        assert "shell.py:15" in high.location


class TestOpengrepScannerMeta:
    """Test OpengrepScanner metadata methods."""

    def test_name(self):
        assert OpengrepScanner().name == "opengrep"

    def test_install_command(self):
        cmd = OpengrepScanner().install_command()
        assert cmd is not None
        assert "opengrep" in cmd


class TestOpengrepExecution:
    """Keep local and container commands compatible with their entrypoints."""

    @pytest.mark.parametrize("config,expected_args", [
        ({}, ["--json", "--output", "/output/results.json", "/workspace"]),
        (
            {"config": "rules with spaces.yml"},
            ["--json", "--output", "/output/results.json",
             "--config", "rules with spaces.yml", "/workspace"],
        ),
    ])
    def test_container_does_not_repeat_entrypoint(
        self, monkeypatch, tmp_path, fixtures_dir, config, expected_args,
    ):
        scanner = OpengrepScanner()
        engine = ArgusEngine(ArgusConfig.from_dict({
            "execution": {"backend": "docker", "verify_image_signatures": False},
        }))
        engine._no_cache = True
        monkeypatch.setattr(engine, "_pull_image", lambda image: True)
        monkeypatch.setattr(engine, "_get_image_digest", lambda image: "sha256:test")
        monkeypatch.setattr(engine, "_detect_runtime", lambda: "docker")
        fixture = fixtures_dir / "opengrep" / "results-with-findings.json"
        commands = []

        def run_container(cmd, **kwargs):
            commands.append(cmd)
            output_mount = next(arg for arg in cmd if arg.endswith(":/output"))
            output = Path(output_mount.removesuffix(":/output")) / "results.json"
            output.write_text(fixture.read_text(encoding="utf-8"), encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        monkeypatch.setattr(subprocess, "run", run_container)
        result = engine._run_in_container(scanner, str(tmp_path), config)

        assert len(commands) == 1
        command = commands[0]
        image_index = command.index(scanner.container_image)
        assert command[image_index + 1:] == expected_args
        entrypoint_index = command.index("--entrypoint")
        assert entrypoint_index < image_index
        assert command[entrypoint_index + 1] == "opengrep"
        assert len(result.findings) == 4
        assert result.metadata["execution"] == "container"
        assert not result.metadata.get("execution_failed")
        assert not result.metadata.get("parse_failed")

    @pytest.mark.parametrize("config,expected_options", [
        ({}, []),
        ({"config": "rules with spaces.yml"}, ["--config", "rules with spaces.yml"]),
    ])
    def test_local_keeps_executable(
        self, monkeypatch, tmp_path, fixtures_dir, config, expected_options,
    ):
        fixture = fixtures_dir / "opengrep" / "results-with-findings.json"
        commands = []

        def run_local(cmd, **kwargs):
            commands.append(cmd)
            output = Path(cmd[cmd.index("--output") + 1])
            output.write_text(fixture.read_text(encoding="utf-8"), encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        monkeypatch.setattr(subprocess, "run", run_local)
        result = OpengrepScanner().scan(str(tmp_path), config)

        assert len(commands) == 1
        command = commands[0]
        assert command[:3] == ["opengrep", "--json", "--output"]
        assert command[4:] == expected_options + [str(tmp_path)]
        assert len(result.findings) == 4
        assert not result.metadata.get("execution_failed")
        assert not result.metadata.get("parse_failed")
