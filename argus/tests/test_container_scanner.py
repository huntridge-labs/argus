"""Tests for argus.container.scanner — results, summary, deduplication."""

from argus.container.scanner import (
    ContainerScanResult,
    ContainerScanSummary,
    deduplicate_findings,
)
from argus.core.models import Finding, Severity


def _finding(cve=None, severity=Severity.HIGH, fid="F1", scanner="trivy"):
    """Shorthand to create a Finding with optional CVE."""
    return Finding(
        id=fid,
        severity=severity,
        title=f"Finding {fid}",
        cve=cve,
        scanner=scanner,
    )


class TestContainerScanResult:
    """Test ContainerScanResult severity counts and properties."""

    def test_severity_counts(self):
        result = ContainerScanResult(
            name="app",
            image_ref="app:latest",
            combined_findings=[
                _finding(severity=Severity.CRITICAL),
                _finding(severity=Severity.CRITICAL),
                _finding(severity=Severity.HIGH),
                _finding(severity=Severity.MEDIUM),
                _finding(severity=Severity.LOW),
                _finding(severity=Severity.LOW),
                _finding(severity=Severity.LOW),
            ],
        )
        assert result.critical_count == 2
        assert result.high_count == 1
        assert result.medium_count == 1
        assert result.low_count == 3
        assert result.total_count == 7

    def test_unique_count_deduplicates_cves(self):
        result = ContainerScanResult(
            name="app",
            image_ref="app:latest",
            combined_findings=[
                _finding(cve="CVE-2024-0001", fid="F1"),
                _finding(cve="CVE-2024-0001", fid="F2"),
                _finding(cve="CVE-2024-0002", fid="F3"),
            ],
        )
        assert result.unique_count == 2

    def test_unique_count_non_cve_always_counted(self):
        result = ContainerScanResult(
            name="app",
            image_ref="app:latest",
            combined_findings=[
                _finding(cve="CVE-2024-0001", fid="F1"),
                _finding(cve=None, fid="F2"),
                _finding(cve=None, fid="F3"),
            ],
        )
        # 1 unique CVE + 2 non-CVE findings = 3
        assert result.unique_count == 3

    def test_empty_findings(self):
        result = ContainerScanResult(
            name="empty", image_ref="empty:latest",
        )
        assert result.critical_count == 0
        assert result.total_count == 0
        assert result.unique_count == 0

    def test_build_failure_defaults(self):
        result = ContainerScanResult(
            name="broken",
            image_ref="broken:latest",
            build_success=False,
            scan_error="Docker build failed",
        )
        assert not result.build_success
        assert result.scan_error == "Docker build failed"
        assert result.total_count == 0


class TestDeduplicateFindings:
    """Test deduplicate_findings merging logic."""

    def test_trivy_takes_precedence(self):
        trivy = [_finding(cve="CVE-2024-0001", fid="T1", scanner="trivy")]
        grype = [_finding(cve="CVE-2024-0001", fid="G1", scanner="grype")]
        combined = deduplicate_findings(trivy, grype)
        assert len(combined) == 1
        assert combined[0].id == "T1"

    def test_non_overlapping_cves_all_included(self):
        trivy = [_finding(cve="CVE-2024-0001", fid="T1")]
        grype = [_finding(cve="CVE-2024-0002", fid="G1")]
        combined = deduplicate_findings(trivy, grype)
        assert len(combined) == 2

    def test_non_cve_findings_always_included(self):
        trivy = [_finding(cve=None, fid="T1")]
        grype = [_finding(cve=None, fid="G1")]
        combined = deduplicate_findings(trivy, grype)
        assert len(combined) == 2

    def test_mixed_cve_and_non_cve(self):
        trivy = [
            _finding(cve="CVE-2024-0001", fid="T1"),
            _finding(cve=None, fid="T2"),
        ]
        grype = [
            _finding(cve="CVE-2024-0001", fid="G1"),
            _finding(cve=None, fid="G2"),
        ]
        combined = deduplicate_findings(trivy, grype)
        # T1 (CVE), T2 (non-CVE), G2 (non-CVE) = 3
        # G1 is a duplicate of T1 so excluded
        assert len(combined) == 3
        ids = [f.id for f in combined]
        assert "T1" in ids
        assert "T2" in ids
        assert "G2" in ids

    def test_empty_inputs(self):
        assert deduplicate_findings([], []) == []

    def test_only_trivy(self):
        trivy = [_finding(cve="CVE-2024-0001", fid="T1")]
        combined = deduplicate_findings(trivy, [])
        assert len(combined) == 1

    def test_only_grype(self):
        grype = [_finding(cve="CVE-2024-0001", fid="G1")]
        combined = deduplicate_findings([], grype)
        assert len(combined) == 1

    def test_duplicate_within_trivy(self):
        trivy = [
            _finding(cve="CVE-2024-0001", fid="T1"),
            _finding(cve="CVE-2024-0001", fid="T2"),
        ]
        combined = deduplicate_findings(trivy, [])
        assert len(combined) == 1
        assert combined[0].id == "T1"


class TestContainerScanSummary:
    """Test ContainerScanSummary aggregation."""

    def _make_result(self, name, findings):
        return ContainerScanResult(
            name=name,
            image_ref=f"{name}:latest",
            combined_findings=findings,
        )

    def test_aggregation_across_results(self):
        r1 = self._make_result("app", [
            _finding(severity=Severity.CRITICAL, cve="CVE-2024-0001"),
            _finding(severity=Severity.HIGH, cve="CVE-2024-0002"),
        ])
        r2 = self._make_result("worker", [
            _finding(severity=Severity.CRITICAL, cve="CVE-2024-0003"),
            _finding(severity=Severity.LOW, cve="CVE-2024-0004"),
        ])
        summary = ContainerScanSummary(results=[r1, r2])
        assert summary.critical_count == 2
        assert summary.high_count == 1
        assert summary.medium_count == 0
        assert summary.low_count == 1
        assert summary.total_count == 4

    def test_unique_count_across_results(self):
        shared_cve = _finding(cve="CVE-2024-0001")
        r1 = self._make_result("app", [shared_cve])
        r2 = self._make_result("worker", [
            _finding(cve="CVE-2024-0001", fid="G1"),
            _finding(cve="CVE-2024-0002", fid="G2"),
        ])
        summary = ContainerScanSummary(results=[r1, r2])
        # CVE-2024-0001 counted once, CVE-2024-0002 once = 2
        assert summary.unique_count == 2

    def test_container_count(self):
        summary = ContainerScanSummary(results=[
            self._make_result("a", []),
            self._make_result("b", []),
            self._make_result("c", []),
        ])
        assert summary.container_count == 3

    def test_build_failures(self):
        ok = self._make_result("ok", [])
        fail = ContainerScanResult(
            name="fail", image_ref="fail:latest", build_success=False,
        )
        summary = ContainerScanSummary(results=[ok, fail])
        assert summary.build_failures == 1

    def test_empty_summary(self):
        summary = ContainerScanSummary()
        assert summary.total_count == 0
        assert summary.unique_count == 0
        assert summary.container_count == 0
        assert summary.build_failures == 0
