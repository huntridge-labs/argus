"""Tests for argus.scanners.container — ContainerScanner."""

import pytest

from argus.core.models import Finding, Severity
from argus.scanners.container import ContainerScanner


class TestContainerTrivyResults:
    """Test ContainerScanner.parse_trivy_results."""

    def test_parse_with_findings(self, fixtures_dir):
        scanner = ContainerScanner()
        path = fixtures_dir / "trivy" / "results-with-findings.json"
        findings = scanner.parse_trivy_results(path)

        assert len(findings) == 4

        severities = [f.severity for f in findings]
        assert severities.count(Severity.CRITICAL) == 1
        assert severities.count(Severity.HIGH) == 1
        assert severities.count(Severity.MEDIUM) == 1
        assert severities.count(Severity.LOW) == 1

    def test_parse_zero_findings(self, fixtures_dir):
        scanner = ContainerScanner()
        path = fixtures_dir / "trivy" / "results-zero-findings.json"
        findings = scanner.parse_trivy_results(path)

        assert len(findings) == 0

    def test_finding_fields(self, fixtures_dir):
        scanner = ContainerScanner()
        path = fixtures_dir / "trivy" / "results-with-findings.json"
        findings = scanner.parse_trivy_results(path)

        crit = [f for f in findings if f.severity == Severity.CRITICAL][0]
        assert crit.id == "CVE-2023-1234"
        assert crit.cve == "CVE-2023-1234"
        assert crit.cwe == "CWE-787"
        assert crit.scanner == "container"
        assert crit.metadata["tool"] == "trivy"
        assert crit.metadata["package"] == "libssl1.1"
        assert "libssl1.1@" in crit.location


class TestContainerGrypeResults:
    """Test ContainerScanner.parse_grype_results."""

    def test_parse_with_findings(self, fixtures_dir):
        scanner = ContainerScanner()
        path = fixtures_dir / "grype" / "results-with-findings.json"
        findings = scanner.parse_grype_results(path)

        assert len(findings) == 4

        severities = [f.severity for f in findings]
        assert severities.count(Severity.CRITICAL) == 1
        assert severities.count(Severity.HIGH) == 1
        assert severities.count(Severity.MEDIUM) == 1
        assert severities.count(Severity.LOW) == 1

    def test_parse_zero_findings(self, fixtures_dir):
        scanner = ContainerScanner()
        path = fixtures_dir / "grype" / "results-zero-findings.json"
        findings = scanner.parse_grype_results(path)

        assert len(findings) == 0

    def test_finding_fields(self, fixtures_dir):
        scanner = ContainerScanner()
        path = fixtures_dir / "grype" / "results-with-findings.json"
        findings = scanner.parse_grype_results(path)

        crit = [f for f in findings if f.severity == Severity.CRITICAL][0]
        assert crit.id == "CVE-2023-1234"
        assert crit.cve == "CVE-2023-1234"
        assert crit.scanner == "container"
        assert crit.metadata["tool"] == "grype"
        assert crit.metadata["package"] == "libssl1.1"


class TestContainerDeduplication:
    """Test ContainerScanner CVE deduplication logic."""

    def test_merge_deduplicates_by_cve(self):
        scanner = ContainerScanner()
        target: list[Finding] = []
        seen_cves: set[str] = set()

        findings_a = [
            Finding(
                id="CVE-2023-1234",
                severity=Severity.CRITICAL,
                title="vuln A",
                cve="CVE-2023-1234",
            ),
            Finding(
                id="CVE-2023-5678",
                severity=Severity.HIGH,
                title="vuln B",
                cve="CVE-2023-5678",
            ),
        ]
        findings_b = [
            Finding(
                id="CVE-2023-1234",
                severity=Severity.CRITICAL,
                title="vuln A from grype",
                cve="CVE-2023-1234",
            ),
            Finding(
                id="CVE-2023-9999",
                severity=Severity.LOW,
                title="vuln C",
                cve="CVE-2023-9999",
            ),
        ]

        scanner._merge_findings(findings_a, target, seen_cves)
        scanner._merge_findings(findings_b, target, seen_cves)

        assert len(target) == 3
        cve_ids = [f.cve for f in target]
        assert cve_ids.count("CVE-2023-1234") == 1

    def test_merge_keeps_findings_without_cve(self):
        scanner = ContainerScanner()
        target: list[Finding] = []
        seen_cves: set[str] = set()

        findings = [
            Finding(id="NO-CVE-1", severity=Severity.LOW, title="no cve 1"),
            Finding(id="NO-CVE-2", severity=Severity.LOW, title="no cve 2"),
        ]

        scanner._merge_findings(findings, target, seen_cves)
        assert len(target) == 2


class TestContainerScannerMeta:
    """Test ContainerScanner metadata methods."""

    def test_name(self):
        assert ContainerScanner().name == "container"

    def test_install_command(self):
        cmd = ContainerScanner().install_command()
        assert cmd is not None
