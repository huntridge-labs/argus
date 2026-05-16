"""Tests for the scan metadata panel on the dashboard.

Exercises the _scan_metadata extractor plus the dashboard rendering
of scanner versions, durations, container execution, and image
digests. Metadata lives inside ScanResult.metadata today; the panel
surfaces what's there without failing on missing fields.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient   # noqa: E402

from argus.viewers.browser.app import _scan_metadata, create_app   # noqa: E402


def _write_scan(dir_path: Path, scanner_blocks: list[dict]) -> Path:
    """Drop a results JSON with explicit per-scanner metadata."""
    results = []
    for block in scanner_blocks:
        results.append({
            "scanner": block["scanner"],
            "findings": block.get("findings", []),
            "raw_report": None,
            "sarif_report": None,
            "metadata": block.get("metadata", {}),
            "critical_count": 0, "high_count": 0,
            "medium_count": 0, "low_count": 0, "total_count": 0,
        })
    payload = {"severity_threshold": None, "results": results}
    p = dir_path / "argus-results.json"
    p.write_text(json.dumps(payload))
    return p


class TestScanMetadataExtractor:
    def test_none_summary_returns_none(self):
        assert _scan_metadata(None, None) is None

    def test_collects_per_scanner_execution_fields(self, tmp_path):
        # Fake the ScanSummary via the real loader so we test the
        # extractor against actual models, not dict shims.
        from argus.viewers.terminal.loader import load_summary

        _write_scan(tmp_path, [{
            "scanner": "bandit",
            "metadata": {
                "execution": "container",
                "image": "ghcr.io/huntridge-labs/argus/scanner-bandit:0.7.0",
                "digest": "sha256:abc123",
                "tool_version": "1.7.5",
                "duration_ms": 250,
            },
        }])
        scan_summary, resolved = load_summary(tmp_path / "argus-results.json")

        md = _scan_metadata(scan_summary, resolved)
        assert md is not None
        assert md["scanner_count"] == 1
        assert md["scanners"][0]["scanner"] == "bandit"
        assert md["scanners"][0]["tool_version"] == "1.7.5"
        assert md["scanners"][0]["execution"] == "container"
        assert md["scanners"][0]["digest"] == "sha256:abc123"
        assert md["scanners"][0]["duration_ms"] == 250
        assert md["total_duration_ms"] == 250

    def test_sums_durations_across_scanners(self, tmp_path):
        from argus.viewers.terminal.loader import load_summary
        _write_scan(tmp_path, [
            {"scanner": "bandit", "metadata": {"duration_ms": 100}},
            {"scanner": "grype",  "metadata": {"duration_ms": 250}},
            {"scanner": "trivy",  "metadata": {"duration_ms": 75}},
        ])
        scan_summary, resolved = load_summary(tmp_path / "argus-results.json")
        md = _scan_metadata(scan_summary, resolved)
        assert md["total_duration_ms"] == 425
        assert md["scanner_count"] == 3

    def test_total_duration_none_when_no_scanner_reported(self, tmp_path):
        # Older scans without duration_ms metadata — total should be
        # None (not zero) so the template hides the "0s total" line
        # rather than implying an instant scan.
        from argus.viewers.terminal.loader import load_summary
        _write_scan(tmp_path, [{"scanner": "bandit", "metadata": {}}])
        scan_summary, resolved = load_summary(tmp_path / "argus-results.json")
        md = _scan_metadata(scan_summary, resolved)
        assert md["total_duration_ms"] is None

    def test_scan_file_and_mtime_captured(self, tmp_path):
        from argus.viewers.terminal.loader import load_summary
        p = _write_scan(tmp_path, [{"scanner": "bandit", "metadata": {}}])
        scan_summary, resolved = load_summary(p)
        md = _scan_metadata(scan_summary, resolved)
        assert md["scan_file"] == str(resolved)
        # Non-null mtime — browsers render via the small JS helper.
        assert md["scan_mtime"] is not None


class TestScanMetadataUI:
    def test_panel_renders_on_dashboard_when_scan_loaded(self, tmp_path):
        _write_scan(tmp_path, [{
            "scanner": "bandit",
            "metadata": {
                "execution": "container",
                "image": "img:1.0",
                "digest": "sha256:abc",
                "tool_version": "1.7",
                "duration_ms": 120,
            },
        }])
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/")
        assert "scan-metadata" in resp.text
        assert "Scan metadata" in resp.text
        # Per-scanner row surfaces its tool version + duration.
        assert "1.7" in resp.text
        assert "120 ms" in resp.text
        # Digest shown for container executions so audit questions
        # have the SHA-pinned image handy.
        assert "sha256:abc" in resp.text

    def test_panel_absent_for_empty_state(self, tmp_path):
        # No scan loaded → no metadata panel.
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/")
        assert "Scan metadata" not in resp.text

    def test_panel_survives_missing_duration(self, tmp_path):
        # Older scans without duration_ms should still render rather
        # than crashing the page.
        _write_scan(tmp_path, [{"scanner": "bandit", "metadata": {"tool_version": "1.7"}}])
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/")
        assert resp.status_code == 200
        assert "scan-metadata" in resp.text
        # Em-dash for the missing duration column.
        assert "—" in resp.text

    def test_scanner_count_chip_renders(self, tmp_path):
        _write_scan(tmp_path, [
            {"scanner": "bandit", "metadata": {"duration_ms": 100}},
            {"scanner": "grype",  "metadata": {"duration_ms": 200}},
        ])
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/")
        # Summary chips show scanner count + total duration so the
        # collapsed panel still conveys something useful at rest.
        assert "2 scanners" in resp.text
        assert "0.3s total" in resp.text

    def test_mtime_js_loaded(self, tmp_path):
        _write_scan(tmp_path, [{"scanner": "bandit", "metadata": {}}])
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/")
        # scan-mtime.js humanizes the epoch timestamp client-side.
        assert "scan-mtime.js" in resp.text
