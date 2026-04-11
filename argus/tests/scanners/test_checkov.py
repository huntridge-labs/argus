"""Tests for argus.scanners.checkov — CheckovScanner."""

import pytest

from argus.core.models import Severity
from argus.scanners.checkov import CheckovScanner


class TestCheckovParseResults:
    """Test CheckovScanner.parse_results with fixture data."""

    def test_parse_results_with_findings(self, fixtures_dir):
        scanner = CheckovScanner()
        path = fixtures_dir / "checkov" / "results-with-findings.json"
        findings = scanner.parse_results(path)

        assert len(findings) == 5

        severities = [f.severity for f in findings]
        assert severities.count(Severity.HIGH) == 2
        assert severities.count(Severity.MEDIUM) == 2
        assert severities.count(Severity.LOW) == 1

    def test_parse_results_zero_findings(self, fixtures_dir):
        scanner = CheckovScanner()
        path = fixtures_dir / "checkov" / "results-zero-findings.json"
        findings = scanner.parse_results(path)

        assert len(findings) == 0

    def test_finding_fields(self, fixtures_dir):
        scanner = CheckovScanner()
        path = fixtures_dir / "checkov" / "results-with-findings.json"
        findings = scanner.parse_results(path)

        first = findings[0]
        assert first.id == "CKV_AWS_79"
        assert first.severity == Severity.HIGH
        assert first.scanner == "checkov"
        assert first.location is not None
        assert first.metadata["resource"] == "aws_instance.web"
        assert "guideline" in first.metadata

    def test_file_path_leading_slash_stripped(self, fixtures_dir):
        scanner = CheckovScanner()
        path = fixtures_dir / "checkov" / "results-with-findings.json"
        findings = scanner.parse_results(path)

        for finding in findings:
            if finding.location:
                # Location should not start with /
                file_part = finding.location.split(":")[0]
                assert not file_part.startswith("/")


class TestCheckovScannerMeta:
    """Test CheckovScanner metadata methods."""

    def test_name(self):
        assert CheckovScanner().name == "checkov"

    def test_install_command(self):
        cmd = CheckovScanner().install_command()
        assert cmd is not None
        assert "checkov" in cmd
