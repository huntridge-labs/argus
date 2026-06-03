"""Per-scope views of a scan, written into scope subdirectories.

Additive organization layered over the canonical root artifacts: the aggregate
``argus-results.json`` (plus ``argus-summary.md`` and, when requested, the
SARIF / OpenVEX artifacts) stay at the output-dir root for backward
compatibility, while this writes FILTERED views under ``security/``, ``lint/``,
and ``supply-chain/`` so each audience finds its slice co-located. The
``supply-chain/`` view additionally hosts the consolidated OpenVEX document —
its natural home, as a cross-scanner, scope-level artifact.
"""

from __future__ import annotations

from pathlib import Path

from argus.core.models import ScanResult, ScanSummary
from argus.core.scopes import SCOPE_SECURITY, SCOPE_SUPPLY_CHAIN, scope_for_finding


def _scope_summary(summary: ScanSummary, scope: str) -> ScanSummary:
    """A ScanSummary holding only the findings in ``scope``, preserving the
    per-scanner result grouping the reporters rely on."""
    results: list[ScanResult] = []
    for result in summary.results:
        kept = [f for f in result.findings if scope_for_finding(f) == scope]
        if kept:
            results.append(ScanResult(
                scanner=result.scanner,
                findings=kept,
                metadata=dict(result.metadata or {}),
            ))
    return ScanSummary(results=results, scan_context=summary.scan_context)


def write_scope_views(summary: ScanSummary, output_dir, formats=None) -> list[Path]:
    """Write per-scope views under ``output_dir``; return the written paths.

    Always writes ``<scope>/argus-results.json`` + ``<scope>/argus-summary.md``
    for each non-empty scope. ``security/argus-results.sarif`` and
    ``supply-chain/argus-results.openvex.json`` are written only when those
    formats are requested (mirroring the root), so a view never emits a format
    the scan did not ask for.
    """
    from argus.reporters import get_reporter

    requested = {f.lower() for f in (formats or [])}
    root = Path(output_dir)
    written: list[Path] = []
    scopes_present = {
        scope_for_finding(f) for result in summary.results for f in result.findings
    }
    for scope in sorted(scopes_present):
        sub = root / scope
        sub.mkdir(parents=True, exist_ok=True)
        scoped = _scope_summary(summary, scope)
        written.append(get_reporter("json").report(scoped, sub))
        written.append(get_reporter("markdown").report(scoped, sub))
        if scope == SCOPE_SECURITY and "sarif" in requested:
            written.append(get_reporter("sarif").report(scoped, sub))
        if scope == SCOPE_SUPPLY_CHAIN and "openvex" in requested:
            # The OpenVEX reporter self-filters to CVE + component findings.
            written.append(get_reporter("openvex").report(scoped, sub))
    return written
