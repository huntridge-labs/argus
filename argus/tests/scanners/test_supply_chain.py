"""Tests for argus.scanners.supply_chain — SupplyChainScanner."""

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

from argus.core.models import Severity
from argus.scanners.supply_chain import SupplyChainScanner


class TestZizmorParseResults:
    """Test SupplyChainScanner.parse_zizmor_results."""

    def test_parse_with_findings(self, fixtures_dir):
        scanner = SupplyChainScanner()
        path = fixtures_dir / "supply-chain" / "zizmor-results-with-findings.json"
        findings = scanner.parse_zizmor_results(path)

        assert len(findings) == 5

        severities = [f.severity for f in findings]
        # template-injection: 9.0 -> CRITICAL
        # unpinned-uses: 5.0 -> MEDIUM
        # excessive-permissions: 6.0 -> MEDIUM
        # ref-confusion: 3.0 -> LOW
        # github-env: 0.0 -> LOW
        assert severities.count(Severity.CRITICAL) == 1
        assert severities.count(Severity.MEDIUM) == 2
        assert severities.count(Severity.LOW) == 2

    def test_parse_clean(self, fixtures_dir):
        scanner = SupplyChainScanner()
        path = fixtures_dir / "supply-chain" / "zizmor-results-clean.json"
        findings = scanner.parse_zizmor_results(path)

        assert len(findings) == 0

    def test_finding_fields(self, fixtures_dir):
        scanner = SupplyChainScanner()
        path = fixtures_dir / "supply-chain" / "zizmor-results-with-findings.json"
        findings = scanner.parse_zizmor_results(path)

        crit = [f for f in findings if f.severity == Severity.CRITICAL][0]
        assert crit.id == "template-injection"
        assert crit.scanner == "supply-chain"
        assert crit.metadata["tool"] == "zizmor"
        assert crit.metadata["security_severity"] == 9.0
        assert "pr-title.yml" in crit.location


class TestActionlintParseResults:
    """Test SupplyChainScanner.parse_actionlint_results."""

    def test_parse_with_findings(self, fixtures_dir):
        scanner = SupplyChainScanner()
        path = fixtures_dir / "supply-chain" / "actionlint-results-with-findings.json"
        findings = scanner.parse_actionlint_results(path)

        assert len(findings) == 3
        assert all(f.severity == Severity.LOW for f in findings)

    def test_parse_clean(self, fixtures_dir):
        scanner = SupplyChainScanner()
        path = fixtures_dir / "supply-chain" / "actionlint-results-clean.json"
        findings = scanner.parse_actionlint_results(path)

        assert len(findings) == 0

    def test_finding_fields(self, fixtures_dir):
        scanner = SupplyChainScanner()
        path = fixtures_dir / "supply-chain" / "actionlint-results-with-findings.json"
        findings = scanner.parse_actionlint_results(path)

        first = findings[0]
        assert first.id.startswith("actionlint-")
        assert first.scanner == "supply-chain"
        assert first.metadata["tool"] == "actionlint"
        assert first.location is not None


class TestSupplyChainParseResultsAutoDetect:
    """Test SupplyChainScanner.parse_results auto-detection."""

    def test_detects_sarif_format(self, fixtures_dir):
        scanner = SupplyChainScanner()
        path = fixtures_dir / "supply-chain" / "zizmor-results-with-findings.json"
        findings = scanner.parse_results(path)
        assert len(findings) == 5

    def test_detects_json_array_format(self, fixtures_dir):
        scanner = SupplyChainScanner()
        path = fixtures_dir / "supply-chain" / "actionlint-results-with-findings.json"
        findings = scanner.parse_results(path)
        assert len(findings) == 3


class TestSupplyChainScannerMeta:
    """Test SupplyChainScanner metadata methods."""

    def test_name(self):
        assert SupplyChainScanner().name == "supply-chain"

    def test_install_command(self):
        cmd = SupplyChainScanner().install_command()
        assert cmd is not None
        assert "zizmor" in cmd
        assert "actionlint" in cmd


# -- Minimal SARIF and actionlint stubs for subprocess mocking -----------

_EMPTY_SARIF = json.dumps({"$schema": "", "version": "2.1.0", "runs": []})


def _make_completed_process(stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=stderr,
    )


def _which_side_effect(tools: set[str]):
    """Return a side-effect function for shutil.which that resolves
    only the tools listed in *tools*."""
    def _which(name):
        return f"/usr/bin/{name}" if name in tools else None
    return _which


class TestSupplyChainConfig:
    """Test config passthrough in SupplyChainScanner.scan()."""

    @patch("argus.scanners.supply_chain.shutil.which")
    @patch("argus.scanners.supply_chain.subprocess.run")
    def test_scan_passes_persona_to_zizmor(self, mock_run, mock_which):
        mock_which.side_effect = _which_side_effect({"zizmor"})
        mock_run.return_value = _make_completed_process(stdout=_EMPTY_SARIF)

        scanner = SupplyChainScanner()
        scanner.scan("/repo", config={"persona": "auditor"})

        args = mock_run.call_args_list[0].args[0]
        assert "--persona" in args
        assert "auditor" in args

    @patch("argus.scanners.supply_chain.shutil.which")
    @patch("argus.scanners.supply_chain.subprocess.run")
    def test_scan_passes_zizmor_config(self, mock_run, mock_which, tmp_path):
        mock_which.side_effect = _which_side_effect({"zizmor"})
        mock_run.return_value = _make_completed_process(stdout=_EMPTY_SARIF)

        config_file = tmp_path / "zizmor.yml"
        config_file.write_text("rules: {}")

        scanner = SupplyChainScanner()
        scanner.scan("/repo", config={"zizmor_config": str(config_file)})

        args = mock_run.call_args_list[0].args[0]
        assert "--config" in args
        assert str(config_file) in args

    @patch("argus.scanners.supply_chain.shutil.which")
    @patch("argus.scanners.supply_chain.subprocess.run")
    def test_scan_skips_actionlint_when_disabled(self, mock_run, mock_which):
        mock_which.side_effect = _which_side_effect({"zizmor", "actionlint"})
        mock_run.return_value = _make_completed_process(stdout=_EMPTY_SARIF)

        scanner = SupplyChainScanner()
        scanner.scan("/repo", config={"run_actionlint": "false"})

        # Only zizmor should have been invoked
        assert mock_run.call_count == 1
        args = mock_run.call_args_list[0].args[0]
        assert args[0] == "zizmor"

    @patch("argus.scanners.supply_chain.shutil.which")
    @patch("argus.scanners.supply_chain.subprocess.run")
    def test_scan_runs_actionlint_by_default(self, mock_run, mock_which):
        mock_which.side_effect = _which_side_effect({"zizmor", "actionlint"})
        mock_run.return_value = _make_completed_process(stdout=_EMPTY_SARIF)

        scanner = SupplyChainScanner()
        scanner.scan("/repo", config={})

        # Both zizmor and actionlint should have been invoked
        assert mock_run.call_count == 2
        invoked_tools = [c.args[0][0] for c in mock_run.call_args_list]
        assert "zizmor" in invoked_tools
        assert "actionlint" in invoked_tools

    @patch("argus.scanners.supply_chain.shutil.which")
    @patch("argus.scanners.supply_chain.subprocess.run")
    def test_scan_passes_github_token_via_env(self, mock_run, mock_which):
        mock_which.side_effect = _which_side_effect({"zizmor"})
        mock_run.return_value = _make_completed_process(stdout=_EMPTY_SARIF)

        scanner = SupplyChainScanner()
        scanner.scan("/repo", config={"github_token": "test-token"})

        env_kwarg = mock_run.call_args_list[0].kwargs.get("env")
        assert env_kwarg is not None
        assert env_kwarg["GITHUB_TOKEN"] == "test-token"

    @patch("argus.scanners.supply_chain.shutil.which")
    @patch("argus.scanners.supply_chain.subprocess.run")
    def test_scan_github_token_falls_back_to_env(
        self, mock_run, mock_which, monkeypatch,
    ):
        monkeypatch.setenv("GITHUB_TOKEN", "env-fallback-token")
        mock_which.side_effect = _which_side_effect({"zizmor"})
        mock_run.return_value = _make_completed_process(stdout=_EMPTY_SARIF)

        scanner = SupplyChainScanner()
        scanner.scan("/repo", config={})

        env_kwarg = mock_run.call_args_list[0].kwargs.get("env")
        assert env_kwarg is not None
        assert env_kwarg["GITHUB_TOKEN"] == "env-fallback-token"


class TestSupplyChainContainerArgs:
    """Test SupplyChainScanner.container_args()."""

    def test_container_args_default(self):
        scanner = SupplyChainScanner()
        args = scanner.container_args()

        assert isinstance(args, list)
        assert args[0] == "sh"
        assert args[1] == "-c"
        # The shell command should reference both tools
        shell_cmd = args[2]
        assert "zizmor" in shell_cmd
        assert "actionlint" in shell_cmd

    def test_container_args_with_persona(self):
        scanner = SupplyChainScanner()
        args = scanner.container_args(config={"persona": "auditor"})

        # Current implementation does not vary container_args by config,
        # so verify the default structure is still returned intact.
        assert isinstance(args, list)
        assert len(args) == 3
        assert "zizmor" in args[2]
