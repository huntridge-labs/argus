"""Shared view logic for findings — consumed by both the TUI and (future) web UI.

Everything in this module is *pure*: no I/O, no Textual imports, no Jinja.
The goal is one source of truth for:

- Severity ordering + glyphs (so CLI, TUI, web render severities consistently).
- Filter / sort / search state (``ViewState``).
- Per-finding detail structure (``finding_detail_rows``) — a list of
  ``(label, value)`` pairs that each front-end templates itself.
- Aggregate summary metrics (``compute_summary``) for executive dashboards.

Keeping this UI-free means unit tests run without Textual installed and the
same code powers a future ``argus serve`` web view without duplicating logic.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from argus.core.models import Finding, Severity


# Ordered from most to least severe. The TUI's "severity desc" sort reuses
# index position — CRITICAL at 0 means it naturally sorts first in an
# ascending sort. Keep the order stable; tests assert on it.
SEVERITY_ORDER: list[Severity] = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
    Severity.UNKNOWN,
]

SEVERITY_GLYPH: dict[Severity, str] = {
    Severity.CRITICAL: "🚨 CRIT",
    Severity.HIGH:     "⚠️  HIGH",
    Severity.MEDIUM:   "🟡 MED ",
    Severity.LOW:      "🔵 LOW ",
    Severity.INFO:     "ℹ️  INFO",
    Severity.UNKNOWN:  "❓ ??? ",
}

# Human-readable labels for each sort mode — kept in lockstep with the
# cycle order enforced by the app's ``action_cycle_sort``. A drift test in
# the browse test suite asserts the cycle order and these labels stay aligned.
SORT_LABELS: dict[str, str] = {
    "severity_desc": "Severity (high → low)",
    "severity_asc":  "Severity (low → high)",
    "package":       "Package (A → Z)",
    "id":            "Finding ID",
}


@dataclass
class ViewState:
    """Filter + sort + search selections applied to a flat finding list.

    Intentionally UI-free: the TUI and (future) web UI both build one of
    these from their own widgets / query params and call ``matches`` /
    ``sort_key_fn`` to project findings into the visible set.
    """

    min_severity: Severity | None = None      # None = all severities
    query: str = ""
    sort_key: str = "severity_desc"
    product: str | None = None                # metadata.sbom_source filter
    scanner: str | None = None                # Finding.scanner filter

    def matches(self, f: Finding) -> bool:
        """True when the finding satisfies every active filter."""
        if self.min_severity is not None and f.severity < self.min_severity:
            return False
        if self.product:
            # unique_products() buckets sbom_source-less findings under
            # the literal "(no product)" label; the filter side needs
            # to agree or that bucket becomes unreachable from the UI.
            source = f.metadata.get("sbom_source") or "(no product)"
            if source != self.product:
                return False
        if self.scanner and (f.scanner or "") != self.scanner:
            return False
        if self.query:
            haystack = " ".join([
                f.id or "",
                f.title or "",
                f.location or "",
                f.cve or "",
                f.scanner or "",
            ]).lower()
            if self.query.lower() not in haystack:
                return False
        return True

    def sort_key_fn(self):
        """Return a comparator-ready key function for the current sort mode.

        Python's ``sorted()`` is ascending; for severity DESC (highest
        severity first) we rely on ``SEVERITY_ORDER`` already being in
        descending order (CRITICAL at index 0) so the natural index yields
        the right ordering. Secondary key: finding id — deterministic
        output when two findings share a severity.
        """
        if self.sort_key == "severity_desc":
            return lambda f: (
                SEVERITY_ORDER.index(f.severity) if f.severity in SEVERITY_ORDER else 99,
                f.id,
            )
        if self.sort_key == "severity_asc":
            return lambda f: (
                -SEVERITY_ORDER.index(f.severity) if f.severity in SEVERITY_ORDER else -99,
                f.id,
            )
        if self.sort_key == "package":
            return lambda f: ((f.location or "").lower(), f.id)
        return lambda f: (f.id, f.severity.value)


# ---------------------------------------------------------------------------
# Pure renderers — take a Finding, return a structured shape each front-end
# templates itself. No markup, no HTML.
# ---------------------------------------------------------------------------

def finding_detail_rows(f: Finding) -> list[tuple[str, str]]:
    """Return a ``[(label, value), ...]`` list for the detail pane.

    A stable, front-end-agnostic shape. The TUI renders each row as Textual
    markup; a future web view would render them as ``<dl>`` / table rows.
    Values are pre-formatted strings (package@version, etc.) so front-ends
    don't replicate the formatting rules here.
    """
    pkg = f.metadata.get("package") or "—"
    installed = f.metadata.get("installed_version") or "—"
    fixed = f.metadata.get("fixed_version") or "—"
    sbom_source = f.metadata.get("sbom_source") or "—"
    return [
        ("Scanner",  f.scanner or "—"),
        ("CVE",      f.cve or "—"),
        ("CWE",      f.cwe or "—"),
        ("Package",  f"{pkg} @ {installed}"),
        ("Fix",      fixed),
        ("Location", f.location or "—"),
        ("SBOM",     sbom_source),
    ]


# ---------------------------------------------------------------------------
# Aggregate summaries — used by the executive dashboard and the web view.
# ---------------------------------------------------------------------------

def unique_products(findings: Iterable[Finding]) -> list[str]:
    """Return every distinct ``metadata.sbom_source`` value, sorted.

    Findings without an ``sbom_source`` tag fall under ``"(no product)"``
    so the product picker and grouped views always have somewhere to put
    them rather than dropping them.
    """
    seen: set[str] = set()
    for f in findings:
        seen.add(f.metadata.get("sbom_source") or "(no product)")
    return sorted(seen)


def unique_scanners(findings: Iterable[Finding]) -> list[str]:
    """Return every distinct ``Finding.scanner`` value, sorted."""
    return sorted({f.scanner or "(unknown)" for f in findings})


def severity_counts(findings: Iterable[Finding]) -> dict[Severity, int]:
    """Return counts keyed by ``Severity`` in ``SEVERITY_ORDER``.

    Every severity bucket is present (possibly zero) so dashboards can
    render a complete breakdown without defaulting missing keys themselves.
    """
    counts: dict[Severity, int] = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        if f.severity in counts:
            counts[f.severity] += 1
    return counts


def compute_summary(findings: list[Finding], *, top_n: int = 3) -> dict:
    """Executive-dashboard payload: per-product + per-scanner breakdowns.

    Returns a shape designed for both TUI rendering and JSON serialization
    (every value is built-in-typed):

    ``{
        "total": int,
        "by_severity": {Severity: int, ...},
        "per_product": [
            {"product": str, "total": int, "by_severity": {...},
             "top": [Finding-as-dict, ...]},
            ...
        ],
        "per_scanner": [{"scanner": str, "total": int}, ...],
        "quality_warnings": [str, ...],   # picked up from metadata.warning
    }``

    The per-product "top N" criticals/highs are findings projected to
    dicts (via ``Finding.to_dict``) so the web view can consume them
    directly without importing the Finding dataclass.
    """
    per_product: list[dict] = []
    for product in unique_products(findings):
        members = [
            f for f in findings
            if (f.metadata.get("sbom_source") or "(no product)") == product
        ]
        # Project top N by severity desc, deterministic by id as the tie-breaker.
        ordered = sorted(
            members,
            key=lambda f: (
                SEVERITY_ORDER.index(f.severity) if f.severity in SEVERITY_ORDER else 99,
                f.id,
            ),
        )
        per_product.append({
            "product": product,
            "total": len(members),
            "by_severity": {
                s.value: n for s, n in severity_counts(members).items()
            },
            "top": [f.to_dict() for f in ordered[:top_n]],
        })

    per_scanner: list[dict] = []
    for scanner in unique_scanners(findings):
        members = [f for f in findings if (f.scanner or "(unknown)") == scanner]
        per_scanner.append({"scanner": scanner, "total": len(members)})

    # Quality warnings are surfaced by individual scanners (e.g. grype's
    # "source.target=unknown"). De-dup by message so the dashboard doesn't
    # show the same warning N times for a batch scan where every SBOM
    # produced it.
    warnings: list[str] = []
    for f in findings:
        msg = f.metadata.get("warning")
        if msg and msg not in warnings:
            warnings.append(msg)

    return {
        "total": len(findings),
        "by_severity": {
            s.value: n for s, n in severity_counts(findings).items()
        },
        "per_product": per_product,
        "per_scanner": per_scanner,
        "quality_warnings": warnings,
    }
