"""Tests for argus.scanners.osv — OsvScanner."""

import pytest

from argus.core.models import Severity
from argus.scanners.osv import OsvScanner


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
    """OSV should accept an SBOM via config['sbom_path'] and add --sbom."""

    def test_local_command_uses_sbom_flag(self):
        from pathlib import Path
        scanner = OsvScanner()
        cmd = scanner._build_command(
            path=".",
            output_file=Path("/tmp/out.json"),
            config={"sbom_path": "/shared/sbom.json"},
        )
        assert "--sbom" in cmd
        assert "/shared/sbom.json" in cmd
        # --recursive / path arg should NOT appear in SBOM mode
        assert "--recursive" not in cmd
        assert "." not in cmd

    def test_container_args_use_sbom_flag(self):
        """osv-scanner v2 uses `-L` for SBOM input."""
        args = OsvScanner().container_args({
            "sbom_path": "/host/sbom.json",
            "sbom_mount_path": "/sbom/sbom.json",
        })
        # v2 CLI: scan -L <sbom> instead of deprecated --sbom
        assert "-L" in args
        assert "/sbom/sbom.json" in args
        assert "scan" in args
        assert "--format" in args

    def test_sbom_mode_ignores_lockfile_and_recursive(self):
        """SBOM mode ignores lockfile/recursive options — uses only the SBOM."""
        args = OsvScanner().container_args({
            "sbom_path": "/host/sbom.json",
            "sbom_mount_path": "/sbom/sbom.json",
            "lockfile": "requirements.txt",
            "recursive": True,
        })
        # SBOM mode uses -L for the SBOM, but lockfile/recursive are ignored
        assert "-L" in args
        assert "/sbom/sbom.json" in args
        # The specific lockfile should NOT appear
        assert "requirements.txt" not in " ".join(args)
        assert "--recursive" not in args

    def test_container_args_sbom_fallback_path(self):
        """When sbom_mount_path is not provided, fall back to /workspace/{sbom_path}."""
        args = OsvScanner().container_args({
            "sbom_path": "my-sbom.spdx.json",
            # No sbom_mount_path — should fall back
        })
        assert "-L" in args
        assert "/workspace/my-sbom.spdx.json" in args


class TestOsvContainerArgs:
    """Test OsvScanner.container_args for non-SBOM modes."""

    def test_container_args_with_config_file(self):
        """config_file should be passed via --config flag."""
        args = OsvScanner().container_args({
            "config_file": "osv-scanner.toml",
        })
        assert "--config" in args
        assert "/workspace/osv-scanner.toml" in args
        # Should be in source scan mode
        assert "source" in args
