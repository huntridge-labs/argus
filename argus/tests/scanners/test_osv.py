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
