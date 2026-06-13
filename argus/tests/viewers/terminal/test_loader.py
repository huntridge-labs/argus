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


class TestRunLayoutResolution:
    """``argus scan`` writes ``argus-results/<timestamp>/`` + a ``latest``
    symlink. locate_results must find the run from the *parent* dir.

    Regression: bare ``argus`` → "View findings" flickered straight back to
    the home screen because the loader only checked the non-existent
    ``argus-results/argus-results.json`` and raised, so the findings app
    exited on mount.
    """

    def test_resolves_latest_symlink(self, tmp_path):
        base = tmp_path / "argus-results"
        run = base / "2026-06-13T23-33-33Z"
        run.mkdir(parents=True)
        (run / RESULTS_FILENAME).write_text(json.dumps(_sample_payload()))
        (base / "latest").symlink_to(run)
        resolved = locate_results(base)
        assert resolved.resolve() == (run / RESULTS_FILENAME).resolve()

    def test_none_resolves_latest_under_cwd(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        run = tmp_path / "argus-results" / "2026-06-13T23-33-33Z"
        run.mkdir(parents=True)
        (run / RESULTS_FILENAME).write_text(json.dumps(_sample_payload()))
        (tmp_path / "argus-results" / "latest").symlink_to(run)
        from pathlib import Path
        assert Path(locate_results(None)).resolve() == (run / RESULTS_FILENAME).resolve()

    def test_resolves_newest_run_without_symlink(self, tmp_path):
        import os
        base = tmp_path / "results"
        old = base / "2026-01-01T00-00-00Z"
        new = base / "2026-06-01T00-00-00Z"
        old.mkdir(parents=True)
        new.mkdir(parents=True)
        (old / RESULTS_FILENAME).write_text(json.dumps(_sample_payload(("low",))))
        (new / RESULTS_FILENAME).write_text(json.dumps(_sample_payload(("critical", "high"))))
        os.utime(old / RESULTS_FILENAME, (1_000_000, 1_000_000))
        os.utime(new / RESULTS_FILENAME, (2_000_000, 2_000_000))
        assert locate_results(base) == new / RESULTS_FILENAME

    def test_direct_drop_still_wins_over_latest(self, tmp_path):
        base = tmp_path / "argus-results"
        base.mkdir()
        (base / RESULTS_FILENAME).write_text("{}")
        run = base / "2026-01-01T00-00-00Z"
        run.mkdir()
        (run / RESULTS_FILENAME).write_text(json.dumps(_sample_payload()))
        (base / "latest").symlink_to(run)
        assert locate_results(base) == base / RESULTS_FILENAME


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


class TestMissingResultsRoutesThroughDiagnoser:
    """Regression: locate_results' FileNotFoundError must include the
    config-aware remediation hint, not just the bare "file not found"
    message. Both viewers surface this exception verbatim."""

    def test_error_includes_diagnoser_remediation(self, tmp_path, monkeypatch):
        # No argus.yml anywhere → generic-hint branch of the diagnoser.
        monkeypatch.chdir(tmp_path)
        with pytest.raises(FileNotFoundError) as excinfo:
            locate_results(str(tmp_path))
        msg = str(excinfo.value)
        # File is identified.
        assert RESULTS_FILENAME in msg
        # Both fix paths are surfaced.
        assert "argus scan --format json" in msg
        assert "reporting.formats" in msg

    def test_error_calls_out_config_root_cause_when_json_omitted(self, tmp_path, monkeypatch):
        """Targeted hint when argus.yml is present but missing 'json'."""
        (tmp_path / "argus.yml").write_text(
            "reporting:\n  formats:\n    - terminal\n    - sarif\n"
        )
        monkeypatch.chdir(tmp_path)
        with pytest.raises(FileNotFoundError) as excinfo:
            locate_results(str(tmp_path))
        msg = str(excinfo.value)
        # Targeted-branch markers.
        assert "Detected" in msg
        assert "argus.yml" in msg
        assert "'terminal'" in msg and "'sarif'" in msg
