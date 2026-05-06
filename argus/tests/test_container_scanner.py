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


class TestContainerScanResultDockerfileFields:
    """``dockerfile`` / ``context`` should flow with the result so a security
    reviewer can trace any artifact back to its source without cross-
    referencing the workflow."""

    def test_remote_pull_entry_leaves_dockerfile_empty(self):
        # Default (remote pull) — both empty strings.
        result = ContainerScanResult(name="x", image_ref="x:1")
        assert result.dockerfile == ""
        assert result.context == ""

    def test_build_entry_carries_dockerfile_and_context(self):
        result = ContainerScanResult(
            name="myapp",
            image_ref="myapp:argus-scan",
            dockerfile="docker/Dockerfile.app",
            context=".",
        )
        assert result.dockerfile == "docker/Dockerfile.app"
        assert result.context == "."


class TestCanonicalContainerMetadata:
    """The cli helper that maps ContainerScanResult → ScanResult metadata.

    Locks in the dict shape so security reviewers and the audit-archive
    layer always see ``dockerfile_path`` for build-mode targets.
    """

    def test_remote_pull_omits_dockerfile_keys(self):
        from argus.cli import _canonical_container_metadata
        result = ContainerScanResult(name="x", image_ref="x:1")
        meta = _canonical_container_metadata(result)
        assert meta["image_ref"] == "x:1"
        assert meta["build_success"] is True
        assert "dockerfile_path" not in meta
        assert "context_path" not in meta

    def test_build_entry_includes_dockerfile_path(self):
        from argus.cli import _canonical_container_metadata
        result = ContainerScanResult(
            name="myapp",
            image_ref="myapp:argus-scan",
            dockerfile="docker/Dockerfile.app",
            context=".",
        )
        meta = _canonical_container_metadata(result)
        assert meta["dockerfile_path"] == "docker/Dockerfile.app"
        assert meta["context_path"] == "."

    def test_scanner_errors_surfaced(self):
        from argus.cli import _canonical_container_metadata
        result = ContainerScanResult(
            name="x", image_ref="x:1",
            scanner_errors={"trivy": "DB pull failed"},
        )
        meta = _canonical_container_metadata(result)
        assert meta["scanner_errors"] == {"trivy": "DB pull failed"}


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


class TestDeduplicationEdgeCases:
    """Additional edge cases for CVE deduplication logic."""

    def test_same_cve_different_severity_keeps_first(self):
        """When same CVE appears with different severities, first wins."""
        combined = deduplicate_findings(
            trivy=[
                _finding(cve="CVE-2024-0001", severity=Severity.CRITICAL, fid="T1"),
            ],
            grype=[
                _finding(cve="CVE-2024-0001", severity=Severity.HIGH, fid="G1"),
            ],
        )
        assert len(combined) == 1
        assert combined[0].severity == Severity.CRITICAL

    def test_none_cve_never_deduped(self):
        """Findings without CVE are always included, never deduped."""
        combined = deduplicate_findings(
            trivy=[
                _finding(cve=None, fid="T1"),
                _finding(cve=None, fid="T2"),
            ],
            grype=[
                _finding(cve=None, fid="G1"),
            ],
        )
        assert len(combined) == 3

    def test_empty_string_cve_not_deduped(self):
        """Empty string CVE should not be treated as a dedup key."""
        combined = deduplicate_findings(
            trivy=[
                _finding(cve="", fid="T1"),
                _finding(cve="", fid="T2"),
            ],
            grype=[],
        )
        assert len(combined) == 2

    def test_large_set_performance(self):
        """Dedup should handle hundreds of findings efficiently."""
        trivy = [_finding(cve=f"CVE-2024-{i:04d}", fid=f"T{i}") for i in range(200)]
        grype = [_finding(cve=f"CVE-2024-{i:04d}", fid=f"G{i}") for i in range(200)]
        combined = deduplicate_findings(trivy, grype)
        # All 200 unique CVEs from trivy, zero duplicates from grype
        assert len(combined) == 200

    def test_dedup_preserves_order(self):
        """Trivy findings should come before grype findings."""
        combined = deduplicate_findings(
            trivy=[
                _finding(cve="CVE-A", fid="T1"),
                _finding(cve="CVE-B", fid="T2"),
            ],
            grype=[
                _finding(cve="CVE-C", fid="G1"),
            ],
        )
        assert [f.id for f in combined] == ["T1", "T2", "G1"]
