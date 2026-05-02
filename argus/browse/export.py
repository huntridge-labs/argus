"""Export writers for the findings browser.

Each writer takes a list of ``Finding`` objects plus a destination
path and serializes them in the target format. All writers share a
single filename convention (``argus-findings-<timestamp>-<scope>.<ext>``)
built by :func:`make_export_path` so repeated exports at different
filters don't collide and the filename itself reveals what's inside.

Kept separate from ``app.py`` so the writers are trivially unit-testable
without Textual, and the app module only has to wire them into the
Textual action methods.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from pathlib import Path
from typing import Iterable

from argus.core.models import Finding, Severity


# Columns used by the CSV writer — kept as a module constant so the
# export tests can assert on the header shape without duplicating the
# list.
CSV_COLUMNS = [
    "severity", "id", "cve", "scanner",
    "package", "installed_version", "fixed_version",
    "location", "title", "sbom_source",
]


def make_export_path(
    fmt: str,
    *,
    scope: str = "all",
    now: datetime | None = None,
    directory: Path | None = None,
) -> Path:
    """Build a timestamped absolute path for an export.

    ``fmt`` is the extension suffix (``csv``, ``json``, ``md``, ``sarif``).
    ``scope`` is embedded in the filename so repeated exports from
    different filters don't clobber each other. ``directory`` defaults
    to the current working directory — tests pass a tmp_path.
    """
    stamp = (now or datetime.now()).strftime("%Y%m%d-%H%M%S")
    base = Path(directory) if directory else Path.cwd()
    return (base / f"argus-findings-{stamp}-{scope}.{fmt}").resolve()


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------

def render_csv(findings: Iterable[Finding]) -> str:
    """Return findings as a CSV string.

    Pure-in-memory rendering so callers that don't want a file (e.g.
    ``argus serve`` returning a Response body) can skip the filesystem
    entirely. The TUI's ``write_csv`` wraps this for the file path.
    """
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(CSV_COLUMNS)
    for f in findings:
        writer.writerow([
            f.severity.value, f.id, f.cve or "", f.scanner or "",
            f.metadata.get("package", ""),
            f.metadata.get("installed_version", ""),
            f.metadata.get("fixed_version", ""),
            f.location or "", f.title or "",
            f.metadata.get("sbom_source", ""),
        ])
    return buf.getvalue()


def write_csv(findings: Iterable[Finding], dest: Path) -> Path:
    """Write findings as CSV to ``dest``. Returns the resolved path."""
    dest = Path(dest).resolve()
    dest.write_text(render_csv(findings), encoding="utf-8")
    return dest


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

def render_json(findings: Iterable[Finding]) -> str:
    """Return findings as a pretty-printed JSON string.

    Matches the shape used inside ``argus-results.json`` for per-finding
    records, so downstream consumers can pipe the export back through
    other argus tooling (e.g. a future ``argus report`` subcommand)
    without a shape translation step.
    """
    payload = [f.to_dict() for f in findings]
    return json.dumps(payload, indent=2, ensure_ascii=False)


def write_json(findings: Iterable[Finding], dest: Path) -> Path:
    """Write findings as JSON to ``dest``."""
    dest = Path(dest).resolve()
    dest.write_text(render_json(findings), encoding="utf-8")
    return dest


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------

_SEVERITY_ICON = {
    Severity.CRITICAL: "🚨",
    Severity.HIGH:     "⚠️",
    Severity.MEDIUM:   "🟡",
    Severity.LOW:      "🔵",
    Severity.INFO:     "ℹ️",
    Severity.UNKNOWN:  "❓",
}


def render_markdown(findings: Iterable[Finding], *, now: datetime | None = None) -> str:
    """Return findings as a Markdown table — paste-ready for tickets / PRs.

    Pipes in table cells are escaped so a CVE title containing ``|``
    doesn't break the row. The column set mirrors the CSV writer's so
    the two formats carry the same data. ``now`` is injectable for
    deterministic test fixtures; production callers pass ``None``.
    """
    lines: list[str] = [
        "# Argus Findings Export",
        "",
        f"Generated {(now or datetime.now()).isoformat(timespec='seconds')}",
        "",
        "| Sev | ID | Scanner | Package | Fix | Location | SBOM | Title |",
        "|-----|----|---------|---------|-----|----------|------|-------|",
    ]
    for f in findings:
        icon = _SEVERITY_ICON.get(f.severity, "?")
        pkg = f.metadata.get("package", "")
        installed = f.metadata.get("installed_version", "")
        fixed = f.metadata.get("fixed_version", "") or "—"
        pkg_cell = f"{pkg}@{installed}" if pkg else "—"
        title = (f.title or "").replace("|", "\\|")
        location = (f.location or "—").replace("|", "\\|")
        sbom = f.metadata.get("sbom_source", "—")
        lines.append(
            f"| {icon} {f.severity.value.capitalize()} | {f.id} "
            f"| {f.scanner or '—'} | {pkg_cell} | {fixed} "
            f"| `{location}` | {sbom} | {title} |"
        )
    return "\n".join(lines) + "\n"


def write_markdown(findings: Iterable[Finding], dest: Path) -> Path:
    """Write findings as a Markdown table to ``dest``."""
    dest = Path(dest).resolve()
    dest.write_text(render_markdown(findings), encoding="utf-8")
    return dest


# ---------------------------------------------------------------------------
# SARIF (v2.1.0) — a minimal but valid report
# ---------------------------------------------------------------------------

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH:     "error",
    Severity.MEDIUM:   "warning",
    Severity.LOW:      "note",
    Severity.INFO:     "note",
    Severity.UNKNOWN:  "none",
}


def render_sarif(findings: Iterable[Finding]) -> str:
    """Return findings as a SARIF 2.1.0 JSON string — the format
    GitHub Code Security and most dashboards consume.

    We emit one ``run`` per scanner so viewers that group-by-run see
    the same grouping a user would expect. Rule metadata is minimal
    (id + description + default severity level); detailed CVSS /
    references are left to the underlying scanners' richer SARIF
    output, which users can still access via the SDK's native sarif
    reporter.
    """
    by_scanner: dict[str, list[Finding]] = {}
    for f in findings:
        by_scanner.setdefault(f.scanner or "unknown", []).append(f)

    runs = []
    for scanner_name, scanner_findings in sorted(by_scanner.items()):
        # Rule objects — one per distinct finding id in this run.
        rules_by_id: dict[str, dict] = {}
        for f in scanner_findings:
            rule_id = f.id or "UNKNOWN"
            if rule_id not in rules_by_id:
                rules_by_id[rule_id] = {
                    "id": rule_id,
                    "shortDescription": {"text": f.title or rule_id},
                    "defaultConfiguration": {"level": _SARIF_LEVEL.get(f.severity, "none")},
                }

        results = []
        for f in scanner_findings:
            location = f.location or f.metadata.get("package") or "unknown"
            results.append({
                "ruleId": f.id or "UNKNOWN",
                "level": _SARIF_LEVEL.get(f.severity, "none"),
                "message": {"text": f.description or f.title or f.id or ""},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": location},
                    },
                }],
                "properties": {
                    "severity": f.severity.value,
                    "cve": f.cve,
                    "package": f.metadata.get("package"),
                    "installedVersion": f.metadata.get("installed_version"),
                    "fixedVersion": f.metadata.get("fixed_version"),
                    "sbomSource": f.metadata.get("sbom_source"),
                },
            })

        runs.append({
            "tool": {
                "driver": {
                    "name": scanner_name,
                    "informationUri": "https://argus.huntridgelabs.com",
                    "rules": list(rules_by_id.values()),
                },
            },
            "results": results,
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": runs,
    }
    return json.dumps(sarif, indent=2)


def write_sarif(findings: Iterable[Finding], dest: Path) -> Path:
    """Write findings as SARIF 2.1.0 to ``dest``."""
    dest = Path(dest).resolve()
    dest.write_text(render_sarif(findings), encoding="utf-8")
    return dest


# ---------------------------------------------------------------------------
# Dispatch tables — format → (callable, file extension, HTTP content type).
# TUI path uses WRITERS (writes to a Path). Web path uses RENDERERS (returns
# a string) and CONTENT_TYPES to build the HTTP Response.
# ---------------------------------------------------------------------------

WRITERS = {
    "csv":      (write_csv,      "csv"),
    "json":     (write_json,     "json"),
    "markdown": (write_markdown, "md"),
    "sarif":    (write_sarif,    "sarif"),
}

RENDERERS = {
    "csv":      (render_csv,      "csv"),
    "json":     (render_json,     "json"),
    "markdown": (render_markdown, "md"),
    "sarif":    (render_sarif,    "sarif"),
}

# MIME types for the /export HTTP route. text/* when the content is
# safe to display as plain text in a browser; application/json for
# structured payloads where browsers' JSON viewers are useful.
CONTENT_TYPES = {
    "csv":      "text/csv; charset=utf-8",
    "json":     "application/json; charset=utf-8",
    "markdown": "text/markdown; charset=utf-8",
    "sarif":    "application/sarif+json; charset=utf-8",
}


def available_formats() -> list[str]:
    """Return the list of supported format keys, sorted."""
    return sorted(WRITERS.keys())
