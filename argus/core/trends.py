"""Visual analytics for the dashboard — sparklines + bar charts (Phase 8).

Pure, dependency-free, UI-free. Charts are rendered with Unicode block
characters (▁▂▃▄▅▆▇█ for sparklines, █ for bars), so they work in any
terminal with no extra package — the most security-conscious default for a
supply-chain tool (no new dependency surface). The terminal dashboard
renders the strings these functions return; richer ``textual-plotext`` charts
are a possible future opt-in, not a requirement.

Two data sources:
- ``discover_runs`` history → a findings-over-time **sparkline** + a
  "are we getting more or less secure?" delta.
- the current findings → **bar charts** by severity and by scanner.
"""

from __future__ import annotations

from collections import Counter
from typing import Iterable, Sequence

from argus.core.models import Finding, Severity

_SPARK = "▁▂▃▄▅▆▇█"


def sparkline(values: Sequence[float]) -> str:
    """Render a Unicode sparkline for ``values`` (left→right order given).

    All-equal (or single) series render as a flat mid-height line; an empty
    series is an empty string.
    """
    nums = [float(v) for v in values]
    if not nums:
        return ""
    low, high = min(nums), max(nums)
    if high == low:
        return _SPARK[len(_SPARK) // 2] * len(nums)
    span = high - low
    last = len(_SPARK) - 1
    return "".join(_SPARK[int((v - low) / span * last + 0.5)] for v in nums)


def bar_chart(items: Sequence[tuple[str, int]], *, width: int = 22) -> list[str]:
    """Horizontal Unicode bar chart: ``"label   ████····  12"`` per row.

    Bars are scaled to the largest value. Empty input → ``[]``.
    """
    if not items:
        return []
    largest = max((v for _, v in items), default=0) or 1
    label_w = max(len(label) for label, _ in items)
    rows: list[str] = []
    for label, value in items:
        filled = int(round(value / largest * width))
        bar = "█" * filled + "·" * (width - filled)
        rows.append(f"{label:<{label_w}}  {bar}  {value}")
    return rows


def severity_breakdown(findings: Iterable[Finding]) -> list[tuple[Severity, int]]:
    """Count findings per severity, ordered most→least severe."""
    counts: Counter[Severity] = Counter(f.severity for f in findings)
    return [(sev, counts[sev]) for sev in sorted(counts, reverse=True)]


def scanner_breakdown(findings: Iterable[Finding]) -> list[tuple[str, int]]:
    """Count findings per scanner, ordered by count desc then name."""
    counts: Counter[str] = Counter((f.scanner or "unknown") for f in findings)
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))


def run_count_series(runs: Sequence[dict]) -> list[int]:
    """Total findings per run, oldest→newest.

    ``discover_runs`` yields runs newest-first; the sparkline reads
    left→right as oldest→newest, so we reverse. A run whose count failed to
    parse (``None``) counts as 0.
    """
    return [int(run.get("count") or 0) for run in reversed(list(runs))]


def trend_summary(runs: Sequence[dict]) -> str:
    """One-line "current vs previous run" delta, or ``""`` with <2 runs."""
    counts = run_count_series(runs)
    if len(counts) < 2:
        return ""
    current, previous = counts[-1], counts[-2]
    delta = current - previous
    arrow = "↑" if delta > 0 else ("↓" if delta < 0 else "→")
    suffix = "no change" if delta == 0 else f"{arrow}{abs(delta)} vs previous run"
    return f"{current} findings · {suffix}"
