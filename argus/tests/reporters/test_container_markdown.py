"""Tests for argus.reporters.container_markdown — ContainerMarkdownReporter."""

from pathlib import Path

import pytest

from argus.container.scanner import ContainerScanResult, ContainerScanSummary
from argus.core.models import Finding, Severity
from argus.reporters.container_markdown import ContainerMarkdownReporter


def _finding(
    severity=Severity.HIGH,
    cve=None,
    fid="F1",
    scanner="trivy",
    package="libcurl",
    installed="7.68.0",
    fixed="7.68.1",
):
    return Finding(
        id=fid,
        severity=severity,
        title=f"Finding {fid}",
        cve=cve,
        scanner=scanner,
        metadata={
            "package": package,
            "installed_version": installed,
            "fixed_version": fixed,
        },
    )


def _make_result(
    name="app",
    findings=None,
    trivy=None,
    grype=None,
    build_success=True,
    scan_error="",
):
    return ContainerScanResult(
        name=name,
        image_ref=f"{name}:latest",
        trivy_findings=trivy or [],
        grype_findings=grype or [],
        combined_findings=findings or [],
        build_success=build_success,
        scan_error=scan_error,
    )


def _make_summary(results=None):
    return ContainerScanSummary(results=results or [])


class TestReportCreatesFile:
    """Test report() writes container-scan.md."""

    def test_creates_file(self, tmp_path):
        reporter = ContainerMarkdownReporter()
        summary = _make_summary([_make_result()])
        filepath = reporter.report(summary, output_dir=tmp_path)
        assert filepath.exists()
        assert filepath.name == "container-scan.md"

    def test_creates_output_dir_if_missing(self, tmp_path):
        reporter = ContainerMarkdownReporter()
        summary = _make_summary([_make_result()])
        nested = tmp_path / "nested" / "dir"
        filepath = reporter.report(summary, output_dir=nested)
        assert filepath.exists()


class TestReportSingle:
    """Test report_single() for CI matrix jobs."""

    def test_creates_named_file(self, tmp_path):
        reporter = ContainerMarkdownReporter()
        result = _make_result(name="myapp")
        filepath = reporter.report_single(result, output_dir=tmp_path)
        assert filepath.exists()
        assert filepath.name == "myapp.md"

    def test_content_has_container_detail(self, tmp_path):
        reporter = ContainerMarkdownReporter()
        result = _make_result(
            name="web",
            findings=[_finding(cve="CVE-2024-0001")],
            trivy=[_finding(cve="CVE-2024-0001")],
        )
        filepath = reporter.report_single(result, output_dir=tmp_path)
        content = filepath.read_text()
        assert "web" in content
        assert "CVE-2024-0001" in content


class TestBuildCombinedReport:
    """Test build_combined_report() stitching sections together."""

    def test_combines_sections(self, tmp_path):
        reporter = ContainerMarkdownReporter()
        r1 = _make_result(name="app")
        r2 = _make_result(name="worker")

        f1 = reporter.report_single(r1, output_dir=tmp_path)
        f2 = reporter.report_single(r2, output_dir=tmp_path)

        summary = _make_summary([r1, r2])
        combined = ContainerMarkdownReporter.build_combined_report(
            [f1, f2], summary,
        )
        assert "app" in combined
        assert "worker" in combined
        assert "Combined Findings Summary" in combined

    def test_combined_with_artifacts_url(self, tmp_path):
        reporter = ContainerMarkdownReporter()
        r1 = _make_result(name="app")
        f1 = reporter.report_single(r1, output_dir=tmp_path)

        summary = _make_summary([r1])
        combined = ContainerMarkdownReporter.build_combined_report(
            [f1], summary, artifacts_url="https://example.com/artifacts",
        )
        assert "https://example.com/artifacts" in combined


class TestSeverityTable:
    """Test that output contains severity table with correct counts."""

    def test_severity_counts_in_summary(self, tmp_path):
        findings = [
            _finding(severity=Severity.CRITICAL, cve="CVE-C1", fid="C1"),
            _finding(severity=Severity.CRITICAL, cve="CVE-C2", fid="C2"),
            _finding(severity=Severity.HIGH, cve="CVE-H1", fid="H1"),
            _finding(severity=Severity.MEDIUM, cve="CVE-M1", fid="M1"),
            _finding(severity=Severity.LOW, cve="CVE-L1", fid="L1"),
        ]
        result = _make_result(findings=findings, trivy=findings)
        summary = _make_summary([result])

        reporter = ContainerMarkdownReporter()
        filepath = reporter.report(summary, output_dir=tmp_path)
        content = filepath.read_text()

        # Combined summary should have counts
        assert "**2**" in content  # critical
        assert "**1**" in content  # high, medium, low each


class TestContainerDetailSections:
    """Test per-container detail sections in output."""

    def test_detail_section_present(self, tmp_path):
        findings = [_finding(cve="CVE-2024-0001")]
        result = _make_result(
            name="webapp",
            findings=findings,
            trivy=findings,
        )
        summary = _make_summary([result])

        reporter = ContainerMarkdownReporter()
        filepath = reporter.report(summary, output_dir=tmp_path)
        content = filepath.read_text()

        assert "webapp" in content
        assert "webapp:latest" in content
        assert "CVE-2024-0001" in content

    def test_multiple_containers(self, tmp_path):
        r1 = _make_result(
            name="api",
            findings=[_finding(cve="CVE-A")],
            trivy=[_finding(cve="CVE-A")],
        )
        r2 = _make_result(
            name="worker",
            findings=[_finding(cve="CVE-B", fid="F2")],
            grype=[_finding(cve="CVE-B", fid="F2")],
        )
        summary = _make_summary([r1, r2])

        reporter = ContainerMarkdownReporter()
        filepath = reporter.report(summary, output_dir=tmp_path)
        content = filepath.read_text()

        assert "api" in content
        assert "worker" in content

    def test_findings_table_has_package_info(self, tmp_path):
        f = _finding(
            cve="CVE-2024-0001",
            package="openssl",
            installed="1.1.1",
            fixed="1.1.2",
        )
        result = _make_result(findings=[f], trivy=[f])
        summary = _make_summary([result])

        reporter = ContainerMarkdownReporter()
        filepath = reporter.report(summary, output_dir=tmp_path)
        content = filepath.read_text()

        assert "openssl" in content
        assert "1.1.1" in content
        assert "1.1.2" in content


class TestEmptyResults:
    """Test empty results produce clean output."""

    def test_no_vulnerabilities_message(self, tmp_path):
        result = _make_result(name="clean", findings=[], trivy=[], grype=[])
        summary = _make_summary([result])

        reporter = ContainerMarkdownReporter()
        filepath = reporter.report(summary, output_dir=tmp_path)
        content = filepath.read_text()

        assert "No vulnerabilities" in content
        assert "clean" in content

    def test_zero_counts_in_summary(self, tmp_path):
        result = _make_result(findings=[])
        summary = _make_summary([result])

        reporter = ContainerMarkdownReporter()
        filepath = reporter.report(summary, output_dir=tmp_path)
        content = filepath.read_text()

        assert "**0**" in content


class TestBuildFailure:
    """Test build failure produces error section."""

    def test_build_failure_section(self, tmp_path):
        result = _make_result(
            name="broken",
            build_success=False,
            scan_error="Docker build failed",
        )
        summary = _make_summary([result])

        reporter = ContainerMarkdownReporter()
        filepath = reporter.report(summary, output_dir=tmp_path)
        content = filepath.read_text()

        assert "broken" in content
        assert "Build failed" in content

    def test_scan_error_section(self, tmp_path):
        result = _make_result(
            name="errored",
            scan_error="OS error: No space left on device",
        )
        summary = _make_summary([result])

        reporter = ContainerMarkdownReporter()
        filepath = reporter.report(summary, output_dir=tmp_path)
        content = filepath.read_text()

        assert "Scan error" in content
        assert "errored" in content

    def test_build_failure_count_in_summary(self, tmp_path):
        ok = _make_result(name="ok")
        fail = _make_result(name="fail", build_success=False)
        summary = _make_summary([ok, fail])

        reporter = ContainerMarkdownReporter()
        filepath = reporter.report(summary, output_dir=tmp_path)
        content = filepath.read_text()

        assert "Build Failures:** 1" in content
