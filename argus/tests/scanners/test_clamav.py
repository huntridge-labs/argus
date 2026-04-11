"""Tests for argus.scanners.clamav — ClamavScanner."""

import pytest

from argus.core.models import Severity
from argus.scanners.clamav import ClamavScanner


class TestClamavParseResults:
    """Test ClamavScanner.parse_results and parse_results_text."""

    def test_parse_results_with_findings(self, fixtures_dir):
        scanner = ClamavScanner()
        path = fixtures_dir / "clamav" / "results-with-findings.txt"
        findings = scanner.parse_results(path)

        assert len(findings) == 2
        assert all(f.severity == Severity.CRITICAL for f in findings)

    def test_parse_results_clean(self, fixtures_dir):
        scanner = ClamavScanner()
        path = fixtures_dir / "clamav" / "results-clean.txt"
        findings = scanner.parse_results(path)

        assert len(findings) == 0

    def test_parse_results_text_with_findings(self, fixtures_dir):
        scanner = ClamavScanner()
        path = fixtures_dir / "clamav" / "results-with-findings.txt"
        text = path.read_text()
        findings = scanner.parse_results_text(text)

        assert len(findings) == 2

    def test_finding_fields(self, fixtures_dir):
        scanner = ClamavScanner()
        path = fixtures_dir / "clamav" / "results-with-findings.txt"
        findings = scanner.parse_results(path)

        first = findings[0]
        assert first.id == "Win.Trojan.Generic-1234567"
        assert first.severity == Severity.CRITICAL
        assert "Malware detected" in first.title
        assert first.location == "/workspace/uploads/malicious.exe"
        assert first.scanner == "clamav"

    def test_parse_results_text_empty(self):
        scanner = ClamavScanner()
        findings = scanner.parse_results_text("")
        assert len(findings) == 0


class TestClamavScannerMeta:
    """Test ClamavScanner metadata methods."""

    def test_name(self):
        assert ClamavScanner().name == "clamav"

    def test_install_command(self):
        cmd = ClamavScanner().install_command()
        assert cmd is not None
        assert "clamav" in cmd
