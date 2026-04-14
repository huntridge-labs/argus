"""Tests for CLI container/DAST routing, output helpers, and lifecycle detection."""

import argparse
import json

import pytest

from argus.cli import (
    _is_container_lifecycle,
    _is_dast_lifecycle,
    _print_container_terminal,
    _print_dast_terminal,
    _write_container_json,
    _write_dast_json,
    _write_dast_markdown,
    cmd_scan,
)


# ---------------------------------------------------------------------------
# Helpers to build Namespace objects that mimic parsed CLI args
# ---------------------------------------------------------------------------

def _base_scan_namespace(**overrides) -> argparse.Namespace:
    """Return a Namespace with all scan-related defaults."""
    defaults = {
        "command": "scan",
        "scanner": None,
        "path": ".",
        "config": None,
        "output_dir": None,
        "severity_threshold": None,
        "formats": None,
        "list": False,
        "verbose": False,
        "discover": None,
        "images": None,
        "scanners": None,
        "target": None,
        "port": None,
        "env_vars": None,
        "scan_type": "baseline",
        "startup_timeout": 60,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


# ---------------------------------------------------------------------------
# Minimal stub classes for container / DAST summaries
# ---------------------------------------------------------------------------

class _ContainerResult:
    def __init__(self, name="img", image_ref="img:latest", build_success=True,
                 total_count=3, critical_count=1, high_count=1, medium_count=1,
                 low_count=0, unique_count=2, combined_findings=None):
        self.name = name
        self.image_ref = image_ref
        self.build_success = build_success
        self.total_count = total_count
        self.critical_count = critical_count
        self.high_count = high_count
        self.medium_count = medium_count
        self.low_count = low_count
        self.unique_count = unique_count
        self.combined_findings = combined_findings or []


class _ContainerSummary:
    def __init__(self, results=None):
        self.results = results or [_ContainerResult()]

    @property
    def container_count(self):
        return len(self.results)

    @property
    def build_failures(self):
        return sum(1 for r in self.results if not r.build_success)

    @property
    def total_count(self):
        return sum(r.total_count for r in self.results)

    @property
    def unique_count(self):
        return sum(r.unique_count for r in self.results)


class _DastResult:
    def __init__(self, name="app", target_url="http://localhost:8080/",
                 healthy=True, scan_error="", findings=None):
        self.name = name
        self.target_url = target_url
        self.healthy = healthy
        self.scan_error = scan_error
        self.findings = findings or []

    @property
    def critical_count(self):
        return sum(1 for f in self.findings if getattr(f, 'severity', None)
                   and f.severity.value == 'critical')

    @property
    def high_count(self):
        return sum(1 for f in self.findings if getattr(f, 'severity', None)
                   and f.severity.value == 'high')

    @property
    def medium_count(self):
        return sum(1 for f in self.findings if getattr(f, 'severity', None)
                   and f.severity.value == 'medium')

    @property
    def low_count(self):
        return sum(1 for f in self.findings if getattr(f, 'severity', None)
                   and f.severity.value == 'low')

    @property
    def info_count(self):
        return sum(1 for f in self.findings if getattr(f, 'severity', None)
                   and f.severity.value == 'info')


class _DastSummary:
    def __init__(self, results=None):
        self.results = results or [_DastResult()]

    @property
    def target_count(self):
        return len(self.results)

    @property
    def healthy_count(self):
        return sum(1 for r in self.results if r.healthy)

    @property
    def total_count(self):
        return sum(len(r.findings) for r in self.results)

    @property
    def critical_count(self):
        return sum(r.critical_count for r in self.results)

    @property
    def high_count(self):
        return sum(r.high_count for r in self.results)

    @property
    def medium_count(self):
        return sum(r.medium_count for r in self.results)

    @property
    def low_count(self):
        return sum(r.low_count for r in self.results)

    @property
    def info_count(self):
        return sum(r.info_count for r in self.results)


# =====================================================================
# _is_container_lifecycle
# =====================================================================

class TestIsContainerLifecycle:
    """Test _is_container_lifecycle detection."""

    def test_returns_true_with_discover(self):
        args = _base_scan_namespace(discover=".")
        assert _is_container_lifecycle(args) is True

    def test_returns_true_with_image(self):
        args = _base_scan_namespace(images=["nginx:latest"])
        assert _is_container_lifecycle(args) is True

    def test_returns_false_without_lifecycle_flags(self):
        args = _base_scan_namespace()
        assert _is_container_lifecycle(args) is False


# =====================================================================
# _is_dast_lifecycle
# =====================================================================

class TestIsDastLifecycle:
    """Test _is_dast_lifecycle detection."""

    def test_returns_true_with_target(self):
        args = _base_scan_namespace(target="http://localhost:3000")
        assert _is_dast_lifecycle(args) is True

    def test_returns_true_with_image(self):
        args = _base_scan_namespace(images=["myapp:latest"])
        assert _is_dast_lifecycle(args) is True

    def test_returns_false_without_lifecycle_flags(self):
        args = _base_scan_namespace()
        assert _is_dast_lifecycle(args) is False


# =====================================================================
# cmd_scan routing
# =====================================================================

class TestCmdScanRouting:
    """Test cmd_scan routes to the correct handler."""

    def test_routes_to_container_with_discover(self, monkeypatch):
        called = {}

        def fake_container_scan(args):
            called["container"] = True
            return 0

        monkeypatch.setattr("argus.cli._cmd_container_scan", fake_container_scan)
        args = _base_scan_namespace(scanner="container", discover=".")
        result = cmd_scan(args)

        assert called.get("container") is True
        assert result == 0

    def test_routes_to_dast_with_target(self, monkeypatch):
        called = {}

        def fake_dast_scan(args):
            called["dast"] = True
            return 0

        monkeypatch.setattr("argus.cli._cmd_dast_scan", fake_dast_scan)
        args = _base_scan_namespace(scanner="zap", target="http://localhost:3000")
        result = cmd_scan(args)

        assert called.get("dast") is True
        assert result == 0

    def test_routes_to_source_scan_for_other_scanners(self, monkeypatch):
        called = {}

        def fake_source_scan(args):
            called["source"] = True
            return 0

        monkeypatch.setattr("argus.cli._cmd_source_scan", fake_source_scan)
        args = _base_scan_namespace(scanner="bandit")
        result = cmd_scan(args)

        assert called.get("source") is True
        assert result == 0


# =====================================================================
# _print_container_terminal
# =====================================================================

class TestPrintContainerTerminal:
    """Test _print_container_terminal produces expected stdout."""

    def test_produces_output(self, capsys):
        summary = _ContainerSummary()
        _print_container_terminal(summary)
        captured = capsys.readouterr()

        assert "Container Security Scan Results" in captured.out
        assert "Containers scanned: 1" in captured.out
        assert "Build failures:     0" in captured.out

    def test_shows_build_failed(self, capsys):
        results = [_ContainerResult(name="bad", build_success=False)]
        summary = _ContainerSummary(results=results)
        _print_container_terminal(summary)
        captured = capsys.readouterr()

        assert "BUILD FAILED" in captured.out


# =====================================================================
# _write_container_json
# =====================================================================

class TestWriteContainerJson:
    """Test _write_container_json creates valid JSON file."""

    def test_creates_json_file(self, tmp_path):
        summary = _ContainerSummary()
        output_dir = str(tmp_path / "out")
        _write_container_json(summary, output_dir)

        json_file = tmp_path / "out" / "container-scan.json"
        assert json_file.exists()

        data = json.loads(json_file.read_text())
        assert data["container_count"] == 1
        assert data["build_failures"] == 0
        assert len(data["results"]) == 1


# =====================================================================
# _print_dast_terminal
# =====================================================================

class TestPrintDastTerminal:
    """Test _print_dast_terminal produces expected stdout."""

    def test_produces_output(self, capsys):
        summary = _DastSummary()
        _print_dast_terminal(summary)
        captured = capsys.readouterr()

        assert "DAST Security Scan Results" in captured.out
        assert "Targets scanned: 1" in captured.out
        assert "Healthy targets: 1" in captured.out

    def test_shows_not_healthy(self, capsys):
        results = [_DastResult(name="sick", healthy=False)]
        summary = _DastSummary(results=results)
        _print_dast_terminal(summary)
        captured = capsys.readouterr()

        assert "NOT HEALTHY" in captured.out

    def test_shows_scan_error(self, capsys):
        results = [_DastResult(name="err", scan_error="timeout")]
        summary = _DastSummary(results=results)
        _print_dast_terminal(summary)
        captured = capsys.readouterr()

        assert "SCAN ERROR" in captured.out


# =====================================================================
# _write_dast_markdown
# =====================================================================

class TestWriteDastMarkdown:
    """Test _write_dast_markdown creates markdown file."""

    def test_creates_markdown_file(self, tmp_path):
        summary = _DastSummary()
        output_dir = str(tmp_path / "out")
        _write_dast_markdown(summary, output_dir)

        md_file = tmp_path / "out" / "dast-scan.md"
        assert md_file.exists()

        content = md_file.read_text()
        assert "# DAST Security Scan Results" in content
        assert "**Targets:** 1" in content

    def test_unhealthy_target_note(self, tmp_path):
        results = [_DastResult(name="down", healthy=False)]
        summary = _DastSummary(results=results)
        output_dir = str(tmp_path / "out")
        _write_dast_markdown(summary, output_dir)

        content = (tmp_path / "out" / "dast-scan.md").read_text()
        assert "Target not healthy" in content


# =====================================================================
# _write_dast_json
# =====================================================================

class TestWriteDastJson:
    """Test _write_dast_json creates valid JSON file."""

    def test_creates_json_file(self, tmp_path):
        summary = _DastSummary()
        output_dir = str(tmp_path / "out")
        _write_dast_json(summary, output_dir)

        json_file = tmp_path / "out" / "dast-scan.json"
        assert json_file.exists()

        data = json.loads(json_file.read_text())
        assert data["target_count"] == 1
        assert data["healthy_count"] == 1
        assert len(data["results"]) == 1
