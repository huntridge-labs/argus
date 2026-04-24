"""Tests for the /diff route and the picker compare-select UI.

Exercises the new/fixed/severity-changed/still-open bucketing end-to-end
from two argus-results.json files, error handling (missing params,
out-of-scope paths, malformed JSON), and the picker markup that drives
the selection flow.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient   # noqa: E402

from argus.serve.app import create_app   # noqa: E402


def _write_results(dir_path: Path, findings: list[dict]) -> Path:
    """Drop a minimal-but-valid results JSON and return its path."""
    # Compute severity buckets for the single results block. All the
    # fixture scans in this file use one scanner so we put everything
    # in a single block.
    scanner_name = findings[0]["scanner"] if findings else "grype"
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    payload = {
        "severity_threshold": None,
        "results": [{
            "scanner": scanner_name,
            "findings": findings,
            "raw_report": None, "sarif_report": None, "metadata": {},
            "critical_count": counts["critical"],
            "high_count": counts["high"],
            "medium_count": counts["medium"],
            "low_count": counts["low"],
            "total_count": len(findings),
        }],
    }
    p = dir_path / "argus-results.json"
    p.write_text(json.dumps(payload))
    return p


def _finding(id_: str, severity: str = "high", location: str = "pkg",
             scanner: str = "grype", title: str | None = None,
             cve: str | None = None):
    return {
        "id": id_,
        "severity": severity,
        "title": title or f"finding {id_}",
        "description": "",
        "location": location,
        "cwe": None,
        "cve": cve,
        "scanner": scanner,
        "metadata": {},
    }


class TestDiffRoute:
    def test_new_findings_bucket(self, tmp_path):
        # Before has one finding; After has the same finding plus a new one.
        before_dir = tmp_path / "run-1"
        after_dir = tmp_path / "run-2"
        before_dir.mkdir()
        after_dir.mkdir()
        _write_results(before_dir, [_finding("CVE-A", location="pkg1")])
        _write_results(after_dir, [
            _finding("CVE-A", location="pkg1"),
            _finding("CVE-B", location="pkg2", severity="critical"),
        ])

        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get(f"/diff?a={before_dir}&b={after_dir}")
        assert resp.status_code == 200
        # The new finding shows up in the New section; the fixed + changed
        # tally reads zero, still-open has CVE-A.
        assert "CVE-B" in resp.text
        assert "1</strong> new" in resp.text
        assert "0</strong> fixed" in resp.text

    def test_fixed_findings_bucket(self, tmp_path):
        before_dir = tmp_path / "run-1"
        after_dir = tmp_path / "run-2"
        before_dir.mkdir()
        after_dir.mkdir()
        _write_results(before_dir, [
            _finding("CVE-A", location="pkg1"),
            _finding("CVE-B", location="pkg2"),
        ])
        _write_results(after_dir, [_finding("CVE-A", location="pkg1")])

        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get(f"/diff?a={before_dir}&b={after_dir}")
        assert resp.status_code == 200
        assert "1</strong> fixed" in resp.text
        assert "CVE-B" in resp.text

    def test_severity_changed_bucket(self, tmp_path):
        before_dir = tmp_path / "run-1"
        after_dir = tmp_path / "run-2"
        before_dir.mkdir()
        after_dir.mkdir()
        _write_results(before_dir, [_finding("CVE-A", severity="medium", location="pkg1")])
        _write_results(after_dir, [_finding("CVE-A", severity="high", location="pkg1")])

        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get(f"/diff?a={before_dir}&b={after_dir}")
        assert resp.status_code == 200
        assert "1</strong> severity changed" in resp.text

    def test_missing_params_renders_error_not_500(self, tmp_path):
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/diff")
        assert resp.status_code == 200
        assert "Need both" in resp.text or "Need both" in resp.text.lower().replace("need both", "Need both")
        # Either order explicit — just confirm we didn't 500 and the
        # error prompts the user toward the picker.
        assert "picker" in resp.text.lower()

    def test_one_param_missing_renders_error(self, tmp_path):
        before_dir = tmp_path / "run-1"
        before_dir.mkdir()
        _write_results(before_dir, [_finding("CVE-A")])
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get(f"/diff?a={before_dir}")
        assert resp.status_code == 200
        assert "picker" in resp.text.lower()

    def test_out_of_scope_path_rejected(self, tmp_path):
        # Launch scoped to a subdir; try to diff across its boundary.
        scoped = tmp_path / "scoped"
        scoped.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        _write_results(outside, [_finding("CVE-A")])

        app = create_app(root=str(scoped))
        client = TestClient(app)
        resp = client.get(f"/diff?a={outside}&b={outside}")
        assert resp.status_code == 200
        assert "outside the scan root" in resp.text

    def test_malformed_results_shows_error(self, tmp_path):
        good_dir = tmp_path / "good"
        bad_dir = tmp_path / "bad"
        good_dir.mkdir()
        bad_dir.mkdir()
        _write_results(good_dir, [_finding("CVE-A")])
        (bad_dir / "argus-results.json").write_text("not-json {")

        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get(f"/diff?a={good_dir}&b={bad_dir}")
        assert resp.status_code == 200
        assert "Could not load" in resp.text

    def test_identical_scans_show_all_still_open(self, tmp_path):
        run_dir = tmp_path / "run"
        run_dir.mkdir()
        _write_results(run_dir, [
            _finding("CVE-A", location="pkg1"),
            _finding("CVE-B", location="pkg2"),
        ])
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get(f"/diff?a={run_dir}&b={run_dir}")
        assert resp.status_code == 200
        assert "0</strong> new" in resp.text
        assert "0</strong> fixed" in resp.text
        assert "2</strong> still open" in resp.text

    def test_both_scan_labels_surfaced_in_header(self, tmp_path):
        before_dir = tmp_path / "run-1"
        after_dir = tmp_path / "run-2"
        before_dir.mkdir()
        after_dir.mkdir()
        _write_results(before_dir, [_finding("CVE-A")])
        _write_results(after_dir, [_finding("CVE-A")])

        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get(f"/diff?a={before_dir}&b={after_dir}")
        # Both scan paths make it into the header breadcrumb so users
        # can tell which direction the diff flows.
        assert str(before_dir.resolve()) in resp.text
        assert str(after_dir.resolve()) in resp.text
        assert "Before" in resp.text
        assert "After" in resp.text


class TestPickerCompareUI:
    """The picker now surfaces checkboxes on scan-ready rows and loads
    picker-compare.js so two selections enable the Compare button."""

    def test_picker_renders_checkboxes_on_scan_rows(self, tmp_path):
        run_a = tmp_path / "run-a"
        run_b = tmp_path / "run-b"
        run_a.mkdir()
        run_b.mkdir()
        _write_results(run_a, [_finding("CVE-A")])
        _write_results(run_b, [_finding("CVE-B")])

        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get(f"/picker?path={tmp_path}")
        assert "picker-compare-cb" in resp.text
        # Checkbox data-attr carries the scan path so JS can build the
        # /diff URL without re-parsing the table.
        assert f'data-scan-path="{run_a.resolve()}"' in resp.text or \
               f'data-scan-path="{run_a}"' in resp.text

    def test_non_scan_rows_do_not_get_checkbox(self, tmp_path):
        # A plain subdirectory without argus-results.json shouldn't
        # render a checkbox — there's nothing to diff.
        (tmp_path / "just-a-folder").mkdir()
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get(f"/picker?path={tmp_path}")
        assert "just-a-folder" in resp.text
        # Count of checkboxes should be zero since no row is scan-ready.
        assert resp.text.count("picker-compare-cb") == 0

    def test_compare_bar_and_js_loaded(self, tmp_path):
        run_a = tmp_path / "run-a"
        run_a.mkdir()
        _write_results(run_a, [_finding("CVE-A")])
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get(f"/picker?path={tmp_path}")
        assert "picker-compare-bar" in resp.text
        assert "picker-compare.js" in resp.text
