"""Reachability heuristic — is a vulnerable dependency actually imported?

Phase 12, first cut. The holy grail of vulnerability noise reduction is "is
the vulnerable code actually *reachable*?" — true call-graph analysis. That's
hard and ecosystem-specific, so it stays roadmap-only research. What ships
here is a cheap, honest proxy: **does the project's source even import the
vulnerable package?** A dependency that's declared but never imported is a
strong "likely unused → lower real risk" signal; one that's imported
everywhere is not exonerated, but it's clearly in play.

Deliberately labelled "imported in source" (not "reachable") so it's never
over-claimed. UI-free + dependency-free: a bounded, early-exiting source
scan with the build/vendor dirs skipped. Covers the two ecosystems the Fix
engine already handles (pip / npm); others report ``unknown``.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from argus.core.models import Finding

REACHABILITY_IMPORTED = "imported"
REACHABILITY_NOT_IMPORTED = "not-imported"
REACHABILITY_UNKNOWN = "unknown"

_PYTHON_GLOBS = ("*.py",)
_JS_GLOBS = ("*.js", "*.ts", "*.jsx", "*.tsx", "*.mjs", "*.cjs")

_SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv", ".tox",
    "dist", "build", ".eggs", "vendor", ".mypy_cache", "htmlcov",
}

_LABELS = {
    REACHABILITY_IMPORTED: "✓ imported in source",
    REACHABILITY_NOT_IMPORTED: "not imported (likely unused)",
    REACHABILITY_UNKNOWN: "unknown",
}


def ecosystem_of(finding: Finding) -> str | None:
    """Best-effort ecosystem ("python" / "javascript") from a finding.

    Reads the PURL type when present, else the ``ecosystem`` metadata key.
    Returns ``None`` for ecosystems this heuristic doesn't cover.
    """
    meta = finding.metadata or {}
    purl = (meta.get("purl") or "").lower()
    if purl.startswith("pkg:pypi/"):
        return "python"
    if purl.startswith("pkg:npm/"):
        return "javascript"
    eco = (meta.get("ecosystem") or "").strip().lower()
    if eco in ("pypi", "python", "pip"):
        return "python"
    if eco in ("npm", "node", "javascript"):
        return "javascript"
    return None


def package_of(finding: Finding) -> str:
    """The package name a finding is about, or ``""`` for non-dependency findings."""
    meta = finding.metadata or {}
    return (meta.get("package") or meta.get("package_name") or "").strip()


def _python_patterns(package: str) -> list[re.Pattern[str]]:
    # PyPI dist name → import name: hyphens become underscores; take the top
    # package. Best-effort (some dists import under a different name).
    module = re.split(r"[\[<>=!;\s]", package, 1)[0].replace("-", "_").lower()
    top = module.split(".")[0]
    if not top:
        return []
    return [re.compile(rf"^\s*(?:import|from)\s+{re.escape(top)}(?:[.\s]|$)", re.MULTILINE)]


def _js_patterns(package: str) -> list[re.Pattern[str]]:
    pkg = re.escape(package)
    return [re.compile(
        rf"""(?:require\(\s*['"]{pkg}(?:/[^'"]*)?['"]"""
        rf"""|(?:import|export)[^;\n]*['"]{pkg}(?:/[^'"]*)?['"])"""
    )]


def _patterns(package: str, ecosystem: str) -> list[re.Pattern[str]]:
    if ecosystem == "python":
        return _python_patterns(package)
    if ecosystem == "javascript":
        return _js_patterns(package)
    return []


def _globs(ecosystem: str) -> tuple[str, ...]:
    return _PYTHON_GLOBS if ecosystem == "python" else _JS_GLOBS


def _source_files(root: Path, globs: Iterable[str], max_files: int) -> Iterable[Path]:
    count = 0
    for pattern in globs:
        for path in root.rglob(pattern):
            if any(part in _SKIP_DIRS for part in path.parts):
                continue
            yield path
            count += 1
            if count >= max_files:
                return


def is_imported(
    package: str, ecosystem: str | None, *, root: Path, max_files: int = 3000,
) -> str:
    """Heuristically classify whether ``package`` is imported under ``root``.

    Returns ``REACHABILITY_IMPORTED`` on the first matching import,
    ``REACHABILITY_NOT_IMPORTED`` if none match after scanning, or
    ``REACHABILITY_UNKNOWN`` when the ecosystem/package is unsupported. The
    scan is bounded (``max_files``) and early-exits on the first hit.
    """
    patterns = _patterns(package, ecosystem or "")
    if not package or not patterns:
        return REACHABILITY_UNKNOWN
    scanned = 0
    for path in _source_files(root, _globs(ecosystem), max_files):
        scanned += 1
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if any(p.search(text) for p in patterns):
            return REACHABILITY_IMPORTED
    return REACHABILITY_NOT_IMPORTED if scanned else REACHABILITY_UNKNOWN


def reachability_label(status: str) -> str:
    """Human label for a reachability status."""
    return _LABELS.get(status, _LABELS[REACHABILITY_UNKNOWN])


def reachability_of(finding: Finding, *, root: Path, max_files: int = 3000) -> str:
    """Convenience: classify a finding's package reachability under ``root``.

    Non-dependency findings (no package) return ``REACHABILITY_UNKNOWN``.
    """
    package = package_of(finding)
    if not package:
        return REACHABILITY_UNKNOWN
    return is_imported(package, ecosystem_of(finding), root=root, max_files=max_files)
