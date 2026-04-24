"""Tests for the recent-scans header dropdown + its collector helper."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient   # noqa: E402

from argus.serve.app import _collect_recent_scans, create_app   # noqa: E402


def _write_results(dir_path: Path, count: int = 1) -> Path:
    """Drop a valid argus-results.json with ``count`` dummy findings."""
    findings = [{
        "id": f"CVE-{i}", "severity": "low", "title": "x",
        "description": "", "location": f"pkg-{i}",
        "cwe": None, "cve": None, "scanner": "grype",
        "metadata": {},
    } for i in range(count)]
    payload = {
        "severity_threshold": None,
        "results": [{
            "scanner": "grype",
            "findings": findings,
            "raw_report": None, "sarif_report": None, "metadata": {},
            "critical_count": 0, "high_count": 0,
            "medium_count": 0, "low_count": count, "total_count": count,
        }],
    }
    p = dir_path / "argus-results.json"
    p.write_text(json.dumps(payload))
    return p


class TestCollectRecentScans:
    def test_lists_subdirs_when_root_is_parent(self, tmp_path):
        # launch_root is a parent-of-runs; each subdir is a separate scan.
        (tmp_path / "run-1").mkdir()
        (tmp_path / "run-2").mkdir()
        _write_results(tmp_path / "run-1", count=3)
        _write_results(tmp_path / "run-2", count=7)

        scans = _collect_recent_scans(tmp_path)
        labels = {s["label"] for s in scans}
        assert labels == {"run-1", "run-2"}
        # Finding count peeked from the JSON.
        counts = {s["label"]: s["count"] for s in scans}
        assert counts == {"run-1": 3, "run-2": 7}

    def test_skips_non_scan_subdirs(self, tmp_path):
        (tmp_path / "run-1").mkdir()
        _write_results(tmp_path / "run-1", count=1)
        # Empty folder — no argus-results.json — should not appear.
        (tmp_path / "just-a-folder").mkdir()

        scans = _collect_recent_scans(tmp_path)
        labels = [s["label"] for s in scans]
        assert labels == ["run-1"]

    def test_looks_at_parent_when_launch_root_is_itself_a_scan(self, tmp_path):
        # argus serve <one-scan-dir> → launch_root contains argus-results.json.
        # Recent-scans should show siblings in the parent, not treat the
        # scan's own subdirs (if any) as runs.
        run = tmp_path / "run-1"
        run.mkdir()
        sibling = tmp_path / "run-2"
        sibling.mkdir()
        _write_results(run, count=1)
        _write_results(sibling, count=1)

        scans = _collect_recent_scans(run)
        labels = {s["label"] for s in scans}
        # Includes both run-1 (the launch root) and run-2 (sibling).
        assert labels == {"run-1", "run-2"}

    def test_sorts_newest_first(self, tmp_path):
        old = tmp_path / "older"
        new = tmp_path / "newer"
        old.mkdir()
        new.mkdir()
        _write_results(old)
        time.sleep(0.02)
        _write_results(new)

        scans = _collect_recent_scans(tmp_path)
        assert [s["label"] for s in scans] == ["newer", "older"]

    def test_symlink_deduplicates_against_its_target(self, tmp_path):
        # "latest" pointing at "run-1" is the argus scan convention;
        # without dedup the dropdown would show both rows for the same
        # real run.
        run = tmp_path / "run-1"
        run.mkdir()
        _write_results(run)
        (tmp_path / "latest").symlink_to(run, target_is_directory=True)

        scans = _collect_recent_scans(tmp_path)
        # One entry only; the resolved path collapses both candidates.
        assert len(scans) == 1

    def test_current_flag_set_when_resolved_matches(self, tmp_path):
        run1 = tmp_path / "run-1"
        run2 = tmp_path / "run-2"
        run1.mkdir()
        run2.mkdir()
        _write_results(run1)
        _write_results(run2)

        results_file = run1 / "argus-results.json"
        scans = _collect_recent_scans(tmp_path, current=results_file)
        by_label = {s["label"]: s for s in scans}
        assert by_label["run-1"]["is_current"] is True
        assert by_label["run-2"]["is_current"] is False

    def test_empty_root_returns_empty_list(self, tmp_path):
        assert _collect_recent_scans(tmp_path) == []

    def test_malformed_scan_falls_back_to_zero_count(self, tmp_path):
        run = tmp_path / "run-1"
        run.mkdir()
        (run / "argus-results.json").write_text("not json {")

        scans = _collect_recent_scans(tmp_path)
        # Malformed → still surface the run but with count=0 so the user
        # isn't silently hidden from a broken run.
        assert len(scans) == 1
        assert scans[0]["count"] == 0

    def test_non_dict_json_payload_doesnt_crash_peek(self, tmp_path):
        # A well-formed JSON file whose TOP-LEVEL value isn't a dict
        # (a bare list, for example) must not crash _collect_recent_scans.
        # This actually surfaced across tests: argus.browse.loader has
        # a test that writes a list-shaped argus-results.json to its
        # tmp_path, and pytest's shared session root meant the picker
        # walk could trip on that sibling while running a serve test.
        # Every nested lookup is type-guarded so any shape -> count=0.
        run = tmp_path / "run-list"
        run.mkdir()
        (run / "argus-results.json").write_text("[1, 2, 3]")
        scans = _collect_recent_scans(tmp_path)
        assert len(scans) == 1
        assert scans[0]["count"] == 0

    def test_dict_with_non_list_results_doesnt_crash(self, tmp_path):
        run = tmp_path / "run-weird"
        run.mkdir()
        (run / "argus-results.json").write_text('{"results": "oops"}')
        scans = _collect_recent_scans(tmp_path)
        assert len(scans) == 1
        assert scans[0]["count"] == 0

    def test_result_block_without_findings_list_doesnt_crash(self, tmp_path):
        run = tmp_path / "run-weird"
        run.mkdir()
        (run / "argus-results.json").write_text(
            '{"results": [{"scanner": "x", "findings": "not-a-list"}]}'
        )
        scans = _collect_recent_scans(tmp_path)
        assert len(scans) == 1
        assert scans[0]["count"] == 0

    def test_limit_caps_list_size(self, tmp_path):
        for i in range(20):
            d = tmp_path / f"run-{i:02d}"
            d.mkdir()
            _write_results(d)

        scans = _collect_recent_scans(tmp_path, limit=5)
        assert len(scans) == 5


class TestRecentScansHeaderDropdown:
    """Header renders the dropdown when there are 2+ scan-ready dirs."""

    def test_dropdown_renders_when_multiple_scans_exist(self, tmp_path):
        (tmp_path / "run-1").mkdir()
        (tmp_path / "run-2").mkdir()
        _write_results(tmp_path / "run-1")
        _write_results(tmp_path / "run-2")

        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/")
        assert "recent-scans-menu" in resp.text
        assert "Recent runs" in resp.text
        assert "run-1" in resp.text
        assert "run-2" in resp.text

    def test_dropdown_hidden_for_single_scan_deployments(self, tmp_path):
        # Use a subdir as launch root so the parent (tmp_path) is
        # guaranteed to have no sibling scans — pytest's session-wide
        # tmp_path hierarchy can otherwise contain leftover scan
        # fixtures from other tests and leak a false positive here.
        root = tmp_path / "project"
        root.mkdir()
        _write_results(root)   # only scan is launch_root itself

        app = create_app(root=str(root))
        client = TestClient(app)
        resp = client.get("/")
        # Exactly one entry → don't render the dropdown noise.
        assert "recent-scans-menu" not in resp.text

    def test_current_scan_highlighted_in_dropdown(self, tmp_path):
        run1 = tmp_path / "run-1"
        run2 = tmp_path / "run-2"
        run1.mkdir()
        run2.mkdir()
        _write_results(run1)
        _write_results(run2)

        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get(f"/?scan={run1}")
        # The active scan picks up aria-current + the highlight class.
        assert "recent-scans-current" in resp.text
        assert 'aria-current="true"' in resp.text

    def test_dropdown_also_renders_on_findings_page(self, tmp_path):
        (tmp_path / "run-1").mkdir()
        (tmp_path / "run-2").mkdir()
        _write_results(tmp_path / "run-1")
        _write_results(tmp_path / "run-2")

        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/findings")
        assert "recent-scans-menu" in resp.text

    def test_dropdown_also_renders_on_picker_page(self, tmp_path):
        (tmp_path / "run-1").mkdir()
        (tmp_path / "run-2").mkdir()
        _write_results(tmp_path / "run-1")
        _write_results(tmp_path / "run-2")

        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/picker")
        assert "recent-scans-menu" in resp.text

    def test_dropdown_href_preserves_scan_switching(self, tmp_path):
        run1 = tmp_path / "run-1"
        run2 = tmp_path / "run-2"
        run1.mkdir()
        run2.mkdir()
        _write_results(run1)
        _write_results(run2)

        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/")
        # Each row links to /?scan=<path>; clicking switches runs.
        assert f"scan={run1}".replace("/", "%2F") in resp.text or str(run1) in resp.text
        assert f"scan={run2}".replace("/", "%2F") in resp.text or str(run2) in resp.text
