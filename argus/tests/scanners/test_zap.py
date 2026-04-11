"""Tests for argus.scanners.zap — ZapScanner."""

import pytest

from argus.core.models import Severity
from argus.scanners.zap import ZapScanner


class TestZapParseResults:
    """Test ZapScanner.parse_results with fixture data."""

    def test_parse_baseline_scan(self, fixtures_dir):
        scanner = ZapScanner()
        path = fixtures_dir / "zap" / "results-baseline-scan.json"
        findings = scanner.parse_results(path)

        assert len(findings) == 3

        severities = [f.severity for f in findings]
        # riskcode 1 -> LOW (x2), riskcode 2 -> MEDIUM (x1)
        assert severities.count(Severity.HIGH) == 0
        assert severities.count(Severity.MEDIUM) == 1
        assert severities.count(Severity.LOW) == 2

    def test_parse_zero_findings(self, fixtures_dir):
        scanner = ZapScanner()
        path = fixtures_dir / "zap" / "results-zero-findings.json"
        findings = scanner.parse_results(path)

        assert len(findings) == 0

    def test_finding_fields(self, fixtures_dir):
        scanner = ZapScanner()
        path = fixtures_dir / "zap" / "results-baseline-scan.json"
        findings = scanner.parse_results(path)

        # Medium finding is Cross-Domain Misconfiguration
        medium = [f for f in findings if f.severity == Severity.MEDIUM][0]
        assert medium.id == "10098"
        assert medium.scanner == "zap"
        assert medium.cwe == "CWE-264"
        assert medium.location is not None
        assert "instance_count" in medium.metadata

        # LOW findings should have CWE set
        low_findings = [f for f in findings if f.severity == Severity.LOW]
        for finding in low_findings:
            assert finding.cwe is not None


class TestZapScannerMeta:
    """Test ZapScanner metadata methods."""

    def test_name(self):
        assert ZapScanner().name == "zap"

    def test_install_command(self):
        cmd = ZapScanner().install_command()
        assert cmd is not None
