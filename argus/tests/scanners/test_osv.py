"""Tests for argus.scanners.osv — OsvScanner."""

import pytest

from argus.core.models import Severity
from argus.core.scanner_template import ScanPaths
from argus.scanners.osv import OsvScanner


_LOCAL = ScanPaths(workspace=".", output="/tmp/out.json")
_CONTAINER = ScanPaths(workspace="/workspace", output="/output/results.json")


class TestOsvParseResults:
    """Test OsvScanner.parse_results with fixture data."""

    def test_parse_results_with_findings(self, fixtures_dir):
        scanner = OsvScanner()
        path = fixtures_dir / "osv" / "results-with-findings.json"
        findings = scanner.parse_results(path)

        assert len(findings) == 4

        severities = [f.severity for f in findings]
        assert severities.count(Severity.CRITICAL) == 1
        assert severities.count(Severity.HIGH) == 1
        assert severities.count(Severity.MEDIUM) == 1
        assert severities.count(Severity.LOW) == 1

    def test_parse_results_zero_findings(self, fixtures_dir):
        scanner = OsvScanner()
        path = fixtures_dir / "osv" / "results-zero-findings.json"
        findings = scanner.parse_results(path)

        assert len(findings) == 0

    def test_finding_fields(self, fixtures_dir):
        scanner = OsvScanner()
        path = fixtures_dir / "osv" / "results-with-findings.json"
        findings = scanner.parse_results(path)

        # CRITICAL finding is lodash command injection
        crit = [f for f in findings if f.severity == Severity.CRITICAL][0]
        assert crit.id == "GHSA-jfh8-c2jp-5v3q"
        assert crit.cve == "CVE-2021-23337"
        assert crit.cwe == "CWE-77"
        assert crit.scanner == "osv"
        assert crit.metadata["package_name"] == "lodash"

        # LOW finding is pip
        low = [f for f in findings if f.severity == Severity.LOW][0]
        assert low.metadata["package_name"] == "pip"


class TestOsvScannerMeta:
    """Test OsvScanner metadata methods."""

    def test_name(self):
        assert OsvScanner().name == "osv"

    def test_install_command(self):
        cmd = OsvScanner().install_command()
        assert cmd is not None

    def test_supports_sbom(self):
        assert OsvScanner.supports_sbom is True


class TestOsvSbomMode:
    """SBOM mode (config['sbom_path'] set) → uses ``-L`` (osv-scanner v2)."""

    def test_local_uses_sbom_flag(self):
        args = OsvScanner().build_args(_LOCAL, {"sbom_path": "/shared/sbom.json"})
        assert "-L" in args
        assert "/shared/sbom.json" in args
        # SBOM mode never adds --recursive or the workspace path.
        assert "--recursive" not in args
        assert "." not in args

    def test_container_uses_sbom_flag_with_mount_path(self):
        args = OsvScanner().build_args(_CONTAINER, {
            "sbom_path": "/host/sbom.json",
            "sbom_mount_path": "/sbom/sbom.json",
        })
        assert "-L" in args
        assert "/sbom/sbom.json" in args
        assert "scan" in args
        assert "--format" in args

    def test_sbom_mode_ignores_lockfile_and_recursive(self):
        args = OsvScanner().build_args(_CONTAINER, {
            "sbom_path": "/host/sbom.json",
            "sbom_mount_path": "/sbom/sbom.json",
            "lockfile": "requirements.txt",
            "recursive": True,
        })
        assert "-L" in args
        assert "/sbom/sbom.json" in args
        assert "requirements.txt" not in " ".join(args)
        assert "--recursive" not in args

    def test_container_sbom_fallback_to_workspace_path(self):
        """No sbom_mount_path → fall back to ``<workspace>/<sbom_path>``."""
        args = OsvScanner().build_args(_CONTAINER, {
            "sbom_path": "my-sbom.spdx.json",
        })
        assert "-L" in args
        assert "/workspace/my-sbom.spdx.json" in args


class TestOsvSourceMode:
    """Non-SBOM mode — ``scan source`` with optional lockfile / recursive / config."""

    def test_config_file_passed_as_workspace_relative_config_flag(self):
        args = OsvScanner().build_args(_CONTAINER, {
            "config_file": "osv-scanner.toml",
        })
        assert "--config" in args
        assert "/workspace/osv-scanner.toml" in args
        assert "source" in args  # source mode

    def test_lockfile_disables_recursive(self):
        args = OsvScanner().build_args(_CONTAINER, {"lockfile": "requirements.txt"})
        assert "-L" in args
        assert "/workspace/requirements.txt" in args
        # When -L lockfile is set, the workspace path and --recursive are dropped.
        assert "--recursive" not in args

    def test_recursive_default_true(self):
        args = OsvScanner().build_args(_CONTAINER, {})
        assert "--recursive" in args
        assert "/workspace" in args
