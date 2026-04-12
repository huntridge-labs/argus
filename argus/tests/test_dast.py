"""Tests for argus.dast — dataclass construction and aggregation properties."""

import pytest

from argus.core.models import Finding, Severity
from argus.dast.inspect import ImageInfo
from argus.dast.runner import DastTarget
from argus.dast.engine import DastScanResult, DastScanSummary


# ---------------------------------------------------------------------------
# Helper: create findings with specific severities
# ---------------------------------------------------------------------------

def _finding(severity: Severity, title: str = "test") -> Finding:
    return Finding(
        id=f"TST-{severity.value}",
        severity=severity,
        title=title,
        scanner="test",
    )


# =====================================================================
# ImageInfo
# =====================================================================

class TestImageInfo:
    """Test ImageInfo dataclass construction and defaults."""

    def test_basic_creation(self):
        info = ImageInfo(image_ref="nginx:latest")
        assert info.image_ref == "nginx:latest"
        assert info.exposed_ports == []
        assert info.entrypoint == []
        assert info.cmd == []
        assert info.env == {}

    def test_creation_with_all_fields(self):
        info = ImageInfo(
            image_ref="myapp:v1",
            exposed_ports=[8080, 443],
            entrypoint=["/bin/sh"],
            cmd=["-c", "echo hello"],
            env={"NODE_ENV": "production"},
        )
        assert info.image_ref == "myapp:v1"
        assert info.exposed_ports == [8080, 443]
        assert info.entrypoint == ["/bin/sh"]
        assert info.cmd == ["-c", "echo hello"]
        assert info.env == {"NODE_ENV": "production"}


# =====================================================================
# DastTarget
# =====================================================================

class TestDastTarget:
    """Test DastTarget dataclass construction and defaults."""

    def test_basic_creation(self):
        target = DastTarget(name="app", image_ref="myapp:latest")
        assert target.name == "app"
        assert target.image_ref == "myapp:latest"
        assert target.container_id == ""
        assert target.network_name == ""
        assert target.host == "localhost"
        assert target.port == 0
        assert target.url == ""
        assert target.healthy is False

    def test_creation_with_overrides(self):
        target = DastTarget(
            name="web",
            image_ref="web:v2",
            container_id="abc123",
            network_name="argus-dast-web",
            host="127.0.0.1",
            port=8080,
            url="http://127.0.0.1:8080/",
            healthy=True,
        )
        assert target.container_id == "abc123"
        assert target.port == 8080
        assert target.healthy is True


# =====================================================================
# DastScanResult
# =====================================================================

class TestDastScanResult:
    """Test DastScanResult severity count properties."""

    def test_empty_findings(self):
        result = DastScanResult(name="app", image_ref="app:latest")
        assert result.critical_count == 0
        assert result.high_count == 0
        assert result.medium_count == 0
        assert result.low_count == 0
        assert result.total_count == 0

    def test_severity_counts(self):
        findings = [
            _finding(Severity.CRITICAL),
            _finding(Severity.CRITICAL),
            _finding(Severity.HIGH),
            _finding(Severity.MEDIUM),
            _finding(Severity.MEDIUM),
            _finding(Severity.MEDIUM),
            _finding(Severity.LOW),
        ]
        result = DastScanResult(
            name="app",
            image_ref="app:latest",
            findings=findings,
        )
        assert result.critical_count == 2
        assert result.high_count == 1
        assert result.medium_count == 3
        assert result.low_count == 1
        assert result.total_count == 7

    def test_defaults(self):
        result = DastScanResult(name="x", image_ref="x:1")
        assert result.target_url == ""
        assert result.port == 0
        assert result.started is True
        assert result.healthy is True
        assert result.scan_error == ""


# =====================================================================
# DastScanSummary
# =====================================================================

class TestDastScanSummary:
    """Test DastScanSummary aggregation properties."""

    def test_empty_summary(self):
        summary = DastScanSummary()
        assert summary.target_count == 0
        assert summary.healthy_count == 0
        assert summary.total_count == 0
        assert summary.scan_failures == 0

    def test_target_count(self):
        results = [
            DastScanResult(name="a", image_ref="a:1"),
            DastScanResult(name="b", image_ref="b:1"),
            DastScanResult(name="c", image_ref="c:1"),
        ]
        summary = DastScanSummary(results=results)
        assert summary.target_count == 3

    def test_healthy_count(self):
        results = [
            DastScanResult(name="a", image_ref="a:1", healthy=True),
            DastScanResult(name="b", image_ref="b:1", healthy=False),
            DastScanResult(name="c", image_ref="c:1", healthy=True),
        ]
        summary = DastScanSummary(results=results)
        assert summary.healthy_count == 2

    def test_aggregated_severity_counts(self):
        results = [
            DastScanResult(
                name="a", image_ref="a:1",
                findings=[
                    _finding(Severity.CRITICAL),
                    _finding(Severity.HIGH),
                ],
            ),
            DastScanResult(
                name="b", image_ref="b:1",
                findings=[
                    _finding(Severity.MEDIUM),
                    _finding(Severity.LOW),
                    _finding(Severity.LOW),
                ],
            ),
        ]
        summary = DastScanSummary(results=results)
        assert summary.critical_count == 1
        assert summary.high_count == 1
        assert summary.medium_count == 1
        assert summary.low_count == 2
        assert summary.total_count == 5

    def test_scan_failures(self):
        results = [
            DastScanResult(name="a", image_ref="a:1", scan_error=""),
            DastScanResult(name="b", image_ref="b:1", scan_error="timeout"),
            DastScanResult(name="c", image_ref="c:1", scan_error="crash"),
        ]
        summary = DastScanSummary(results=results)
        assert summary.scan_failures == 2
