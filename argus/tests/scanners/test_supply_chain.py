"""Tests for argus.scanners.supply_chain — SupplyChainScanner."""

import pytest

from argus.core.models import Severity
from argus.scanners.supply_chain import SupplyChainScanner


class TestZizmorParseResults:
    """Test SupplyChainScanner.parse_zizmor_results."""

    def test_parse_with_findings(self, fixtures_dir):
        scanner = SupplyChainScanner()
        path = fixtures_dir / "supply-chain" / "zizmor-results-with-findings.json"
        findings = scanner.parse_zizmor_results(path)

        assert len(findings) == 5

        severities = [f.severity for f in findings]
        # template-injection: 9.0 -> CRITICAL
        # unpinned-uses: 5.0 -> MEDIUM
        # excessive-permissions: 6.0 -> MEDIUM
        # ref-confusion: 3.0 -> LOW
        # github-env: 0.0 -> LOW
        assert severities.count(Severity.CRITICAL) == 1
        assert severities.count(Severity.MEDIUM) == 2
        assert severities.count(Severity.LOW) == 2

    def test_parse_clean(self, fixtures_dir):
        scanner = SupplyChainScanner()
        path = fixtures_dir / "supply-chain" / "zizmor-results-clean.json"
        findings = scanner.parse_zizmor_results(path)

        assert len(findings) == 0

    def test_finding_fields(self, fixtures_dir):
        scanner = SupplyChainScanner()
        path = fixtures_dir / "supply-chain" / "zizmor-results-with-findings.json"
        findings = scanner.parse_zizmor_results(path)

        crit = [f for f in findings if f.severity == Severity.CRITICAL][0]
        assert crit.id == "template-injection"
        assert crit.scanner == "supply-chain"
        assert crit.metadata["tool"] == "zizmor"
        assert crit.metadata["security_severity"] == 9.0
        assert "pr-title.yml" in crit.location


class TestActionlintParseResults:
    """Test SupplyChainScanner.parse_actionlint_results."""

    def test_parse_with_findings(self, fixtures_dir):
        scanner = SupplyChainScanner()
        path = fixtures_dir / "supply-chain" / "actionlint-results-with-findings.json"
        findings = scanner.parse_actionlint_results(path)

        assert len(findings) == 3
        assert all(f.severity == Severity.LOW for f in findings)

    def test_parse_clean(self, fixtures_dir):
        scanner = SupplyChainScanner()
        path = fixtures_dir / "supply-chain" / "actionlint-results-clean.json"
        findings = scanner.parse_actionlint_results(path)

        assert len(findings) == 0

    def test_finding_fields(self, fixtures_dir):
        scanner = SupplyChainScanner()
        path = fixtures_dir / "supply-chain" / "actionlint-results-with-findings.json"
        findings = scanner.parse_actionlint_results(path)

        first = findings[0]
        assert first.id.startswith("actionlint-")
        assert first.scanner == "supply-chain"
        assert first.metadata["tool"] == "actionlint"
        assert first.location is not None


class TestSupplyChainParseResultsAutoDetect:
    """Test SupplyChainScanner.parse_results auto-detection."""

    def test_detects_sarif_format(self, fixtures_dir):
        scanner = SupplyChainScanner()
        path = fixtures_dir / "supply-chain" / "zizmor-results-with-findings.json"
        findings = scanner.parse_results(path)
        assert len(findings) == 5

    def test_detects_json_array_format(self, fixtures_dir):
        scanner = SupplyChainScanner()
        path = fixtures_dir / "supply-chain" / "actionlint-results-with-findings.json"
        findings = scanner.parse_results(path)
        assert len(findings) == 3


class TestSupplyChainScannerMeta:
    """Test SupplyChainScanner metadata methods."""

    def test_name(self):
        assert SupplyChainScanner().name == "supply-chain"

    def test_install_command(self):
        cmd = SupplyChainScanner().install_command()
        assert cmd is not None
        assert "zizmor" in cmd
        assert "actionlint" in cmd
