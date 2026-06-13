"""Unit tests for argus.core.trends (Phase 8 — dependency-free charts)."""

from __future__ import annotations

from argus.core.models import Finding, Severity
from argus.core.trends import (
    bar_chart,
    run_count_series,
    scanner_breakdown,
    severity_breakdown,
    sparkline,
    trend_summary,
)


def _f(severity=Severity.HIGH, scanner="bandit"):
    return Finding(id="x", severity=severity, title="t", scanner=scanner)


class TestSparkline:
    def test_empty(self):
        assert sparkline([]) == ""

    def test_monotonic_rises(self):
        s = sparkline([0, 1, 2, 3, 4, 5, 6, 7])
        assert s[0] == "▁" and s[-1] == "█" and len(s) == 8

    def test_all_equal_is_flat(self):
        s = sparkline([4, 4, 4])
        assert len(set(s)) == 1 and len(s) == 3

    def test_length_matches_input(self):
        assert len(sparkline([3, 1, 4, 1, 5, 9, 2])) == 7


class TestBarChart:
    def test_empty(self):
        assert bar_chart([]) == []

    def test_largest_is_full_width(self):
        rows = bar_chart([("a", 10), ("b", 5)], width=10)
        assert rows[0].count("█") == 10
        assert rows[1].count("█") == 5
        assert rows[0].endswith("10") and rows[1].endswith("5")

    def test_labels_aligned(self):
        rows = bar_chart([("short", 1), ("longerlabel", 1)])
        # both bars start at the same column (labels left-padded to width)
        assert rows[0].index("█") == rows[1].index("█")


class TestBreakdowns:
    def test_severity_ordered_most_severe_first(self):
        findings = [_f(Severity.LOW), _f(Severity.CRITICAL), _f(Severity.LOW), _f(Severity.HIGH)]
        out = severity_breakdown(findings)
        assert out[0] == (Severity.CRITICAL, 1)
        assert out[-1] == (Severity.LOW, 2)

    def test_scanner_ordered_by_count_desc(self):
        findings = [_f(scanner="bandit"), _f(scanner="osv"), _f(scanner="bandit")]
        out = scanner_breakdown(findings)
        assert out[0] == ("bandit", 2)
        assert ("osv", 1) in out

    def test_missing_scanner_is_unknown(self):
        assert scanner_breakdown([_f(scanner="")]) == [("unknown", 1)]


class TestRunSeries:
    def test_oldest_to_newest(self):
        # discover_runs is newest-first; series reads oldest→newest
        runs = [{"count": 9}, {"count": 12}, {"count": 5}]
        assert run_count_series(runs) == [5, 12, 9]

    def test_none_count_is_zero(self):
        assert run_count_series([{"count": None}, {"count": 3}]) == [3, 0]

    def test_trend_summary_delta(self):
        assert "↓3 vs previous run" in trend_summary([{"count": 9}, {"count": 12}])
        assert "↑2 vs previous run" in trend_summary([{"count": 5}, {"count": 3}])

    def test_trend_summary_needs_two_runs(self):
        assert trend_summary([{"count": 5}]) == ""

    def test_trend_summary_no_change(self):
        assert "no change" in trend_summary([{"count": 5}, {"count": 5}])
