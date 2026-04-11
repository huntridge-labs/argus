"""Tests for argus.scanners.opengrep — OpengrepScanner."""

import pytest

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
