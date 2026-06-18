"""Unit tests for argus.core.run_discovery — the shared scan-run finder.

UI-free and dependency-free: these run without either viewer's optional
extra installed. They pin the contract both the terminal sidebar and the
browser picker / recent-runs dropdown rely on.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from argus.core.models import Severity
from argus.core.run_discovery import (
    RESULTS_FILENAME,
    discover_runs,
    is_within,
    list_directory,
    peek_run_stats,
)


def _write_results(dir_path: Path, *, severities: list[str] | None = None) -> Path:
    """Drop a valid argus-results.json whose findings have ``severities``."""
    dir_path.mkdir(parents=True, exist_ok=True)
    findings = [
        {"id": f"F-{i}", "severity": sev, "title": "t", "scanner": "trivy"}
        for i, sev in enumerate(severities or [])
    ]
    payload = {
        "results": [{"scanner": "trivy", "findings": findings}],
    }
    target = dir_path / RESULTS_FILENAME
    target.write_text(json.dumps(payload), encoding="utf-8")
    return target


class TestIsWithin:
    def test_descendant_is_within(self, tmp_path):
        child = tmp_path / "a" / "b"
        child.mkdir(parents=True)
        assert is_within(child.resolve(), tmp_path.resolve()) is True

    def test_self_is_within(self, tmp_path):
        assert is_within(tmp_path.resolve(), tmp_path.resolve()) is True

    def test_sibling_prefix_not_within(self, tmp_path):
        # /foo-bar must not match root /foo (the relative_to guard).
        root = tmp_path / "foo"
        sibling = tmp_path / "foo-bar"
        root.mkdir()
        sibling.mkdir()
        assert is_within(sibling.resolve(), root.resolve()) is False


class TestPeekRunStats:
    def test_counts_and_worst_severity(self, tmp_path):
        results = _write_results(tmp_path, severities=["low", "critical", "high"])
        count, worst = peek_run_stats(results)
        assert count == 3
        assert worst == Severity.CRITICAL

    def test_valid_empty_scan_is_zero_not_none(self, tmp_path):
        results = _write_results(tmp_path, severities=[])
        count, worst = peek_run_stats(results)
        assert count == 0
        assert worst is None

    def test_malformed_json_returns_none_count(self, tmp_path):
        broken = tmp_path / RESULTS_FILENAME
        broken.write_text("{not valid json", encoding="utf-8")
        assert peek_run_stats(broken) == (None, None)

    def test_non_dict_top_level_returns_none(self, tmp_path):
        listy = tmp_path / RESULTS_FILENAME
        listy.write_text("[1, 2, 3]", encoding="utf-8")
        assert peek_run_stats(listy) == (None, None)

    def test_unreadable_file_returns_none(self, tmp_path):
        missing = tmp_path / "nope" / RESULTS_FILENAME
        assert peek_run_stats(missing) == (None, None)

    def test_findings_without_severity_are_counted_but_skip_worst(self, tmp_path):
        target = tmp_path / RESULTS_FILENAME
        target.write_text(
            json.dumps({"results": [{"findings": [{"id": "x"}, {"id": "y"}]}]}),
            encoding="utf-8",
        )
        count, worst = peek_run_stats(target)
        assert count == 2
        assert worst is None

    def test_non_list_findings_block_is_skipped(self, tmp_path):
        target = tmp_path / RESULTS_FILENAME
        target.write_text(
            json.dumps({"results": [{"findings": "oops"}, {"findings": [{"severity": "low"}]}]}),
            encoding="utf-8",
        )
        count, worst = peek_run_stats(target)
        assert count == 1
        assert worst == Severity.LOW


class TestDiscoverRuns:
    def test_lists_sibling_runs_newest_first(self, tmp_path):
        _write_results(tmp_path / "run-1", severities=["low"])
        _write_results(tmp_path / "run-2", severities=["high", "high"])
        # Make run-2 newer than run-1.
        os.utime(tmp_path / "run-2" / RESULTS_FILENAME, (2_000_000, 2_000_000))
        os.utime(tmp_path / "run-1" / RESULTS_FILENAME, (1_000_000, 1_000_000))

        runs = discover_runs(tmp_path)
        assert [r["label"] for r in runs] == ["run-2", "run-1"]
        by_label = {r["label"]: r for r in runs}
        assert by_label["run-2"]["count"] == 2
        assert by_label["run-2"]["worst_severity"] == Severity.HIGH
        assert by_label["run-1"]["worst_severity"] == Severity.LOW

    def test_launch_root_is_a_run_dir_finds_siblings(self, tmp_path):
        run = tmp_path / "run-1"
        sibling = tmp_path / "run-2"
        _write_results(run, severities=["low"])
        _write_results(sibling, severities=["low"])
        # Point at one run dir; discovery should still surface its sibling.
        runs = discover_runs(run)
        assert {r["label"] for r in runs} == {"run-1", "run-2"}

    def test_is_current_flag(self, tmp_path):
        _write_results(tmp_path / "run-1", severities=["low"])
        _write_results(tmp_path / "run-2", severities=["low"])
        results_file = tmp_path / "run-1" / RESULTS_FILENAME
        runs = discover_runs(tmp_path, current=results_file)
        by_label = {r["label"]: r for r in runs}
        assert by_label["run-1"]["is_current"] is True
        assert by_label["run-2"]["is_current"] is False

    def test_malformed_run_surfaced_with_zero_count(self, tmp_path):
        broken = tmp_path / "broken"
        broken.mkdir()
        (broken / RESULTS_FILENAME).write_text("{bad", encoding="utf-8")
        runs = discover_runs(tmp_path)
        assert len(runs) == 1
        assert runs[0]["count"] == 0
        assert runs[0]["worst_severity"] is None

    def test_symlink_latest_is_deduped(self, tmp_path):
        run = tmp_path / "2026-06-12"
        _write_results(run, severities=["low"])
        latest = tmp_path / "latest"
        try:
            latest.symlink_to(run, target_is_directory=True)
        except (OSError, NotImplementedError):
            return  # platform without symlink support — nothing to assert
        runs = discover_runs(tmp_path)
        # Only one entry survives the symlink-resolved de-dup.
        assert len(runs) == 1

    def test_limit_caps_results(self, tmp_path):
        for i in range(5):
            _write_results(tmp_path / f"run-{i}", severities=["low"])
        runs = discover_runs(tmp_path, limit=3)
        assert len(runs) == 3

    def test_empty_root_returns_empty(self, tmp_path):
        assert discover_runs(tmp_path) == []


class TestListDirectory:
    def test_dirs_before_files_and_flags_scan_ready(self, tmp_path):
        _write_results(tmp_path / "run-01", severities=["low", "low", "high"])
        (tmp_path / "notes.txt").write_text("hi", encoding="utf-8")
        entries, err = list_directory(tmp_path, show_hidden=False)
        assert err is None
        # Directory sorts before the file.
        assert entries[0]["name"] == "run-01"
        assert entries[0]["is_dir"] is True
        assert entries[0]["has_results"] is True
        assert entries[0]["finding_count"] == 3

    def test_hidden_filtered_by_default(self, tmp_path):
        (tmp_path / ".secret").mkdir()
        (tmp_path / "node_modules").mkdir()
        (tmp_path / "visible").mkdir()
        names = {e["name"] for e in list_directory(tmp_path, show_hidden=False)[0]}
        assert names == {"visible"}

    def test_show_hidden_surfaces_everything(self, tmp_path):
        (tmp_path / ".secret").mkdir()
        names = {e["name"] for e in list_directory(tmp_path, show_hidden=True)[0]}
        assert ".secret" in names

    def test_results_file_flagged(self, tmp_path):
        _write_results(tmp_path, severities=["low"])
        entries, _ = list_directory(tmp_path, show_hidden=False)
        results = [e for e in entries if e["is_results_file"]]
        assert len(results) == 1
        assert results[0]["name"] == RESULTS_FILENAME

    def test_malformed_scan_dir_finding_count_none(self, tmp_path):
        broken = tmp_path / "broken-scan"
        broken.mkdir()
        (broken / RESULTS_FILENAME).write_text("{bad", encoding="utf-8")
        entries, _ = list_directory(tmp_path, show_hidden=False)
        by_name = {e["name"]: e for e in entries}
        assert by_name["broken-scan"]["has_results"] is True
        assert by_name["broken-scan"]["finding_count"] is None
