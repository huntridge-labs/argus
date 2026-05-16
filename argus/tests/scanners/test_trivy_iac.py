"""Tests for argus.scanners.trivy_iac — TrivyIacScanner."""

import pytest

from argus.core.models import Severity
from argus.scanners.trivy_iac import TrivyIacScanner


class TestTrivyIacParseResults:
    """Test TrivyIacScanner.parse_results with fixture data."""

    def test_parse_results_with_findings(self, fixtures_dir):
        scanner = TrivyIacScanner()
        path = fixtures_dir / "trivy-iac" / "results-with-findings.json"
        findings = scanner.parse_results(path)

        assert len(findings) == 4

        severities = [f.severity for f in findings]
        assert severities.count(Severity.CRITICAL) == 1
        assert severities.count(Severity.HIGH) == 1
        assert severities.count(Severity.MEDIUM) == 1
        assert severities.count(Severity.LOW) == 1

    def test_parse_results_zero_findings(self, fixtures_dir):
        scanner = TrivyIacScanner()
        path = fixtures_dir / "trivy-iac" / "results-zero-findings.json"
        findings = scanner.parse_results(path)

        assert len(findings) == 0

    def test_finding_fields(self, fixtures_dir):
        scanner = TrivyIacScanner()
        path = fixtures_dir / "trivy-iac" / "results-with-findings.json"
        findings = scanner.parse_results(path)

        # First finding is from main.tf (HIGH - S3 encryption)
        high = [f for f in findings if f.severity == Severity.HIGH][0]
        assert high.id == "AVD-AWS-0086"
        assert "encryption" in high.title.lower()
        assert high.scanner == "trivy-iac"
        assert "main.tf" in high.location

        # Critical finding from ec2.tf
        crit = [f for f in findings if f.severity == Severity.CRITICAL][0]
        assert crit.id == "AVD-AWS-0028"
        assert "ec2.tf" in crit.location


class TestTrivyIacScannerMeta:
    """Test TrivyIacScanner metadata methods."""

    def test_name(self):
        assert TrivyIacScanner().name == "trivy-iac"

    def test_install_command(self):
        cmd = TrivyIacScanner().install_command()
        assert cmd is not None
        assert "trivy" in cmd
