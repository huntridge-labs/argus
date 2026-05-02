"""Unit tests for argus.viewers.terminal.loader — results-file discovery + parse."""

from __future__ import annotations

import json

import pytest

from argus.viewers.terminal.loader import (
    RESULTS_FILENAME,
    flatten_findings,
    load_summary,
    locate_results,
)
from argus.core.models import Finding, ScanResult, ScanSummary, Severity


def _sample_payload(severities=("critical", "high")):
    """Build a minimal argus-results.json payload with N findings."""
    findings = []
    for i, sev in enumerate(severities):
        findings.append({
            "id": f"CVE-2026-{i:04d}",
            "severity": sev,
            "title": f"test finding {i}",
            "description": "",
            "location": f"pkg{i}@1.0.{i}",
            "cwe": None,
            "cve": f"CVE-2026-{i:04d}",
            "scanner": "trivy",
            "metadata": {"package": f"pkg{i}", "installed_version": f"1.0.{i}"},
        })
    return {
        "severity_threshold": None,
        "results": [
            {
                "scanner": "trivy",
                "findings": findings,
                "raw_report": None,
                "sarif_report": None,
                "metadata": {},
                "critical_count": sum(1 for s in severities if s == "critical"),
                "high_count": sum(1 for s in severities if s == "high"),
                "medium_count": 0,
                "low_count": 0,
                "total_count": len(severities),
            },
        ],
    }


class TestLocateResults:
    def test_default_path_when_none(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        expected = tmp_path / "argus-results" / RESULTS_FILENAME
        expected.parent.mkdir()
        expected.write_text("{}")
        # locate_results returns a relative path when called with None;
        # resolve both sides to compare absolute paths.
        from pathlib import Path
        assert Path(locate_results(None)).resolve() == expected.resolve()

    def test_directory_path_resolves_to_json(self, tmp_path):
        d = tmp_path / "run-01"
        d.mkdir()
        (d / RESULTS_FILENAME).write_text("{}")
        assert locate_results(d) == d / RESULTS_FILENAME

    def test_file_path_used_as_is(self, tmp_path):
        f = tmp_path / "custom.json"
        f.write_text("{}")
        assert locate_results(f) == f

    def test_missing_raises_with_hint(self, tmp_path):
        with pytest.raises(FileNotFoundError, match="argus scan --format json"):
            locate_results(tmp_path / "nope")


class TestLoadSummary:
    def test_loads_valid_summary(self, tmp_path):
        f = tmp_path / RESULTS_FILENAME
        f.write_text(json.dumps(_sample_payload()))
        summary, resolved = load_summary(f)
        assert isinstance(summary, ScanSummary)
        assert resolved == f
        assert summary.total_count == 2

    def test_rejects_non_object_payload(self, tmp_path):
        f = tmp_path / RESULTS_FILENAME
        f.write_text(json.dumps([1, 2, 3]))
        with pytest.raises(ValueError, match="not a valid argus results file"):
            load_summary(f)


class TestFlattenFindings:
    def test_returns_every_finding_across_results(self):
        a = Finding(id="A", severity=Severity.HIGH, title="a", scanner="trivy")
        b = Finding(id="B", severity=Severity.MEDIUM, title="b", scanner="grype")
        c = Finding(id="C", severity=Severity.LOW, title="c", scanner="osv")
        summary = ScanSummary(results=[
            ScanResult(scanner="trivy", findings=[a]),
            ScanResult(scanner="grype", findings=[b, c]),
        ])
        assert flatten_findings(summary) == [a, b, c]

    def test_reannotates_missing_scanner_from_enclosing_result(self):
        """Older fixtures leave Finding.scanner blank — we should fill it in."""
        f = Finding(id="X", severity=Severity.HIGH, title="x", scanner="")
        summary = ScanSummary(results=[ScanResult(scanner="osv", findings=[f])])
        out = flatten_findings(summary)
        assert out[0].scanner == "osv"
