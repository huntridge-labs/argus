"""Tests for argus.scanners.gitleaks — GitleaksScanner."""

import pytest

from argus.core.models import Severity
from argus.scanners.gitleaks import GitleaksScanner


class TestGitleaksParseResults:
    """Test GitleaksScanner.parse_results with fixture data."""

    def test_parse_results_with_findings(self, fixtures_dir):
        scanner = GitleaksScanner()
        path = fixtures_dir / "gitleaks" / "results-with-findings.json"
        findings = scanner.parse_results(path)

        assert len(findings) == 3
        assert all(f.severity == Severity.HIGH for f in findings)

    def test_parse_results_zero_findings(self, fixtures_dir):
        scanner = GitleaksScanner()
        path = fixtures_dir / "gitleaks" / "results-zero-findings.json"
        findings = scanner.parse_results(path)

        assert len(findings) == 0

    def test_finding_fields(self, fixtures_dir):
        scanner = GitleaksScanner()
        path = fixtures_dir / "gitleaks" / "results-with-findings.json"
        findings = scanner.parse_results(path)

        first = findings[0]
        assert first.id == "github-pat"
        assert first.severity == Severity.HIGH
        assert first.scanner == "gitleaks"
        assert "config.py:12" in first.location
        assert first.metadata["commit"] == "abc123def456"
        assert first.metadata["rule_id"] == "github-pat"


class TestGitleaksScannerMeta:
    """Test GitleaksScanner metadata methods."""

    def test_name(self):
        assert GitleaksScanner().name == "gitleaks"

    def test_install_command(self):
        cmd = GitleaksScanner().install_command()
        assert cmd is not None
