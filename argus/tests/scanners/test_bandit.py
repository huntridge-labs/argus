"""Tests for argus.scanners.bandit — BanditScanner."""

import pytest

from argus.core.models import Severity
from argus.scanners.bandit import BanditScanner


class TestBanditParseResults:
    """Test BanditScanner.parse_results with fixture data."""

    def test_parse_results_with_findings(self, fixtures_dir):
        scanner = BanditScanner()
        path = fixtures_dir / "bandit" / "results-with-findings.json"
        findings = scanner.parse_results(path)

        assert len(findings) == 6

        severities = [f.severity for f in findings]
        assert severities.count(Severity.HIGH) == 2
        assert severities.count(Severity.MEDIUM) == 3
        assert severities.count(Severity.LOW) == 1

    def test_parse_results_zero_findings(self, fixtures_dir):
        scanner = BanditScanner()
        path = fixtures_dir / "bandit" / "results-zero-findings.json"
        findings = scanner.parse_results(path)

        assert len(findings) == 0

    def test_finding_fields(self, fixtures_dir):
        scanner = BanditScanner()
        path = fixtures_dir / "bandit" / "results-with-findings.json"
        findings = scanner.parse_results(path)

        first = findings[0]
        assert first.id == "B403"
        assert first.severity == Severity.HIGH
        assert first.scanner == "bandit"
        assert first.cwe == "CWE-502"
        assert "app.py:12" in first.location
        assert first.metadata["test_name"] == "blacklist"


class TestBanditScannerMeta:
    """Test BanditScanner metadata methods."""

    def test_name(self):
        assert BanditScanner().name == "bandit"

    def test_install_command(self):
        cmd = BanditScanner().install_command()
        assert cmd is not None
        assert "bandit" in cmd
