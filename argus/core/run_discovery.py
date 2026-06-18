"""Scan-run discovery — shared, UI-free helpers for locating argus runs.

Both viewers answer the same question before they can show anything:
"which argus-results.json files live under this directory, and what's
in them?" The browser used this to power its ``/picker`` file browser
and the header's "recent runs" dropdown; the terminal viewer uses the
same data to drive its runs sidebar and run-switching.

Keeping the logic here (pure: no Textual, no FastAPI, no Jinja) means:

- One implementation of "is this directory a scan?", the finding-count
  peek, and the ``latest/`` symlink de-dup — so the two front-ends can
  never disagree about what counts as a run.
- Unit tests that run without either viewer's optional extra installed.

Return shapes are plain ``dict``s (not dataclasses) because the browser
templates already consume them by key and the existing browser tests
assert on those keys. New consumers should treat the documented keys as
the contract.
"""

from __future__ import annotations

import json
from pathlib import Path

from argus.core.findings_view import SEVERITY_ORDER
from argus.core.models import Severity


# Canonical name of the JSON artifact the ``json`` reporter writes and
# every viewer consumes. Lives here (core) so both the loader and the
# discovery helpers share one definition; ``loader`` re-exports it for
# backwards-compatible ``from ...loader import RESULTS_FILENAME`` imports.
RESULTS_FILENAME = "argus-results.json"


# Build/cache noise hidden from the default picker listing. Surfaced only
# when the caller explicitly opts in (``show_hidden=True``) — a user
# digging for a scan stashed inside one of these can still find it.
HIDDEN_BY_DEFAULT: frozenset[str] = frozenset({
    "node_modules", ".git", ".venv", "venv", "__pycache__",
    ".tox", ".pytest_cache", ".mypy_cache",
})


def is_within(child: Path, root: Path) -> bool:
    """Return True if ``child`` is ``root`` itself or a descendant of it.

    Both paths must already be resolved (symlinks followed, absolute).
    Uses ``relative_to`` rather than string-prefix matching so we don't
    false-positive on ``/foo-bar`` when the root is ``/foo``.
    """
    try:
        child.relative_to(root)
    except ValueError:
        return False
    return True


def peek_run_stats(results_file: Path) -> tuple[int | None, Severity | None]:
    """Cheaply read ``results_file`` for ``(finding_count, worst_severity)``.

    Doesn't construct a ScanSummary — just walks the raw ``results[].
    findings[]`` arrays counting entries and tracking the most severe
    finding seen. Every access is type-guarded so a malformed results
    file degrades gracefully rather than raising.

    ``finding_count`` is ``None`` when the file couldn't be read or
    parsed (unreadable, invalid JSON, or not a JSON object) — distinct
    from ``0``, which means a valid scan that simply found nothing.
    Callers that want to surface a run regardless map ``None`` to ``0``;
    the picker keeps ``None`` so it can flag a broken results file.

    ``worst_severity`` is the ``Severity`` with the lowest
    ``SEVERITY_ORDER`` index (CRITICAL beats HIGH beats …); ``None`` when
    there are no findings or none carried a recognizable severity.
    """
    count = 0
    worst_index: int | None = None
    try:
        with results_file.open(encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None, None
    if not isinstance(data, dict):
        return None, None
    for result in data.get("results", []) or []:
        if not isinstance(result, dict):
            continue
        findings = result.get("findings") or []
        if not isinstance(findings, list):
            continue
        for finding in findings:
            count += 1
            if not isinstance(finding, dict):
                continue
            raw = finding.get("severity")
            if not raw:
                continue
            try:
                severity = Severity.from_string(str(raw))
            except (KeyError, ValueError):
                continue
            if severity in SEVERITY_ORDER:
                idx = SEVERITY_ORDER.index(severity)
                if worst_index is None or idx < worst_index:
                    worst_index = idx
    worst = SEVERITY_ORDER[worst_index] if worst_index is not None else None
    return count, worst


def discover_runs(
    launch_root: Path, current: Path | None = None, *, limit: int = 12,
) -> list[dict]:
    """Return scan-ready directories under ``launch_root``, newest first.

    Each entry::

        {
            "path":           absolute path to the scan dir (string),
            "label":          short display name (dir basename),
            "is_current":     True if this dir is the loaded scan,
            "count":          finding count peeked from the JSON,
            "worst_severity": Severity | None (most severe finding),
            "mtime":          results-file mtime as epoch seconds,
        }

    Scope rules:
    - If ``launch_root`` itself contains ``argus-results.json``, treat it
      as a single run and look at its *parent* for sibling runs (the
      common "pointed at one run dir" case).
    - Otherwise iterate ``launch_root``'s immediate subdirs and keep the
      scan-ready ones (the "pointed at a runs parent" case).

    Both cases de-dup via the symlink-resolved directory so ``latest/``
    collapses into the timestamped run it points at. ``limit`` caps the
    list (12 ≈ a fortnight of daily runs without drowning the nav).
    """
    launch_root = launch_root.resolve()
    parent = (
        launch_root.parent
        if (launch_root / RESULTS_FILENAME).is_file()
        else launch_root
    )

    try:
        candidates = list(parent.iterdir())
    except (PermissionError, FileNotFoundError):
        return []

    # Include the parent itself when it's a direct scan drop.
    if (parent / RESULTS_FILENAME).is_file():
        candidates.insert(0, parent)

    current_resolved = _resolve_current(current)
    seen: set[Path] = set()
    runs: list[dict] = []
    for candidate in candidates:
        run = _describe_run(candidate, current_resolved, seen)
        if run is not None:
            runs.append(run)

    runs.sort(key=lambda r: r["mtime"], reverse=True)
    return runs[:limit]


def _resolve_current(current: Path | None) -> Path | None:
    """Normalize the caller's "current scan" to a directory for matching.

    Callers pass either the run directory or the ``argus-results.json``
    inside it; collapse a file to its parent so it lines up with the
    resolved candidate directories ``discover_runs`` compares against.
    """
    if current is None:
        return None
    resolved = current.resolve()
    return resolved.parent if resolved.is_file() else resolved


def _describe_run(
    candidate: Path, current_resolved: Path | None, seen: set[Path],
) -> dict | None:
    """Build one ``discover_runs`` entry, or ``None`` to skip ``candidate``.

    Skips non-directories, dirs without a direct ``argus-results.json``,
    and symlink-duplicates already seen. Unreadable dirs are skipped
    rather than failing the whole listing.
    """
    try:
        if not candidate.is_dir():
            return None
        results_file = candidate / RESULTS_FILENAME
        if not results_file.is_file():
            return None
        resolved = candidate.resolve()
        if resolved in seen:
            return None
        seen.add(resolved)

        count, worst = peek_run_stats(results_file)
        return {
            "path": str(candidate),
            "label": candidate.name,
            "is_current": (
                current_resolved is not None and resolved == current_resolved
            ),
            # A malformed results file still surfaces as a run (count 0)
            # so the user can see — and re-open — it, rather than having
            # it silently vanish from the sidebar.
            "count": count or 0,
            "worst_severity": worst,
            "mtime": results_file.stat().st_mtime,
        }
    except (PermissionError, OSError):
        return None


def list_directory(
    base: Path, *, show_hidden: bool,
) -> tuple[list[dict], str | None]:
    """Return ``(entries, error)`` for a single directory level.

    Explicitly non-recursive — callers navigate one level at a time.
    Each entry::

        {
            "name":            bare filename,
            "path":            absolute path (string),
            "is_dir":          True for directories,
            "is_results_file": True for an argus-results.json file,
            "has_results":     True for a dir containing one directly,
            "finding_count":   count if has_results else None,
        }

    Directories first, then files, alphabetical within each group.
    Dotfiles and well-known build/cache dirs are hidden unless
    ``show_hidden`` is set.
    """
    try:
        raw = sorted(base.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
    except PermissionError as exc:
        return [], f"Permission denied: {exc}"
    except OSError as exc:
        return [], f"Could not list directory: {exc}"

    entries: list[dict] = []
    for item in raw:
        name = item.name
        if not show_hidden and (name.startswith(".") or name in HIDDEN_BY_DEFAULT):
            continue

        is_dir = item.is_dir()
        is_results_file = not is_dir and name == RESULTS_FILENAME

        has_results = False
        finding_count = None
        if is_dir:
            candidate = item / RESULTS_FILENAME
            if candidate.is_file():
                has_results = True
                finding_count, _ = peek_run_stats(candidate)

        entries.append({
            "name": name,
            "path": str(item),
            "is_dir": is_dir,
            "is_results_file": is_results_file,
            "has_results": has_results,
            "finding_count": finding_count,
        })

    return entries, None
