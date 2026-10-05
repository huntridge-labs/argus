"""Path exclusion handling — reads ignore files and builds unified exclude set.

Argus automatically respects .gitignore, .dockerignore, and tool-specific
path ignore files (.semgrepignore). Combined with --exclude CLI patterns and
argus.yml config, this produces the exclusion set applied pre-scan and
post-scan.

A tool-specific ignore file applies to its own tool only. ``.semgrepignore``
is written for opengrep; a ``**/*.json`` line there must not drop OSV's
package-lock.json findings, and ``tests/`` must not hide bandit's.
"""

import logging
from collections.abc import Callable
from fnmatch import fnmatch
from pathlib import Path

logger = logging.getLogger("argus")

# Ignore files read automatically, in order of precedence. Repo-wide ones
# apply to every scanner.
_IGNORE_FILES = [
    ".gitignore",
    ".dockerignore",
]

# Tool-specific ignore files that list PATHS, and the only scanners they
# apply to. ``.trivyignore`` and ``.gitleaksignore`` are not here on
# purpose: they list rule/CVE IDs and finding fingerprints, which the tools
# apply themselves (see ``tool_config.IGNORE_FILE_RULES``).
_SCANNER_IGNORE_FILES = {
    ".semgrepignore": ("opengrep",),
}

# Paths always excluded (build artifacts, dependencies, caches).
#
# ``argus-results`` is included because repeated scans otherwise
# snowball-detect their own prior raw output (e.g. checkov flagging
# ``argus-results/<ts>/raw/gitleaks/results.json`` for Base64 high
# entropy strings on every subsequent run). Even with raw-output
# persistence flipped off by default, users who opt in with
# ``--keep-raw`` should not see their own forensic artifacts surface
# as findings.
_BUILTIN_EXCLUDES = [
    "node_modules",
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    ".tox",
    ".pytest_cache",
    ".mypy_cache",
    "htmlcov",
    "coverage",
    ".eggs",
    "*.egg-info",
    "dist",
    "build",
    "argus-results",
]


def build_exclusion_set(
    scan_path: str = ".",
    cli_excludes: str = "",
    config_excludes: str = "",
    use_defaults: bool = True,
    scanner: str | None = None,
) -> list[str]:
    """Build exclusion patterns from all sources, for one scanner.

    Sources (merged in this order; all are additive unless
    ``use_defaults=False`` suppresses 1 and 2):
      1. Built-in defaults (node_modules, .git, __pycache__, etc.)
      2. Ignore files: .gitignore and .dockerignore for every scanner, plus
         the tool-specific file for ``scanner`` (e.g. .semgrepignore for
         opengrep). ``scanner=None`` gets the repo-wide files only.
      3. argus.yml scanner-level exclude config
      4. --exclude CLI flag

    Returns a deduplicated list of exclusion patterns.
    """
    patterns: list[str] = list(_BUILTIN_EXCLUDES) if use_defaults else []

    if use_defaults:
        root = Path(scan_path)
        for ignore_file in ignore_files_for(scanner):
            path = root / ignore_file
            if path.is_file():
                file_patterns = _parse_ignore_file(path)
                if file_patterns:
                    patterns.extend(file_patterns)
                    logger.info(
                        "Loaded %d exclusion pattern(s) from %s",
                        len(file_patterns),
                        ignore_file,
                    )

    # Add config-level excludes
    if config_excludes:
        config_parts = [p.strip() for p in config_excludes.split(",") if p.strip()]
        patterns.extend(config_parts)

    # Add CLI excludes
    if cli_excludes:
        cli_parts = [p.strip() for p in cli_excludes.split(",") if p.strip()]
        patterns.extend(cli_parts)

    # Deduplicate while preserving order
    seen = set()
    unique = []
    for p in patterns:
        if p not in seen:
            seen.add(p)
            unique.append(p)

    return unique


def ignore_files_for(scanner: str | None) -> list[str]:
    """The ignore files that apply to ``scanner``, in precedence order."""
    own = [
        name for name, owners in _SCANNER_IGNORE_FILES.items()
        if scanner is not None and scanner in owners
    ]
    return [*_IGNORE_FILES, *own]


def log_exclusion_set(patterns: list[str]) -> None:
    """Log the full exclusion set for forensic audit trail."""
    if not patterns:
        logger.info("No path exclusions active")
        return

    logger.info(
        "Excluding %d path pattern(s): %s",
        len(patterns),
        ", ".join(patterns[:20]) + ("..." if len(patterns) > 20 else ""),
    )
    logger.debug("Full exclusion set: %s", patterns)


def is_excluded(path: str, patterns: list[str]) -> bool:
    """Check if a file path matches any exclusion pattern.

    Each pattern is matched four ways so typical user inputs all work:
      - Substring match (``node_modules`` excludes any path containing it).
      - ``fnmatch`` per path component (``*.test.py`` excludes leaves).
      - ``**``-aware glob against the full path (``**/tests/**``).
      - ``**``-aware glob against the path's POSIX form (covers Windows).
    """
    posix_path = path.replace("\\", "/")
    parts = Path(path).parts
    for pattern in patterns:
        if pattern in path:
            return True
        if _doublestar_match(pattern, path) or _doublestar_match(pattern, posix_path):
            return True
        for part in parts:
            if fnmatch(part, pattern):
                return True
    return False


def _doublestar_match(pattern: str, path: str) -> bool:
    """Segment-aware glob match supporting ``**`` = "any number of segments".

    Splits both inputs on ``/`` and matches segment-by-segment so
    ``**/tests/**`` matches ``src/foo/tests/bar.py`` but NOT
    ``src/contests/run.py`` — a regex-based approach leaks across
    segment boundaries on the latter and produces a false positive.
    The callers need the segment-boundary semantics to match user
    intent (and how gitignore / semgrep / rg all interpret ``**``).
    """
    path_segs = [s for s in path.replace("\\", "/").split("/") if s]
    pat_segs = [s for s in pattern.split("/") if s]
    if not pat_segs:
        return False

    # Leading ``**`` is the explicit "anywhere" marker; otherwise try every
    # starting offset so patterns like ``tests/*.py`` still match a nested
    # ``src/tests/foo.py`` (matches historical substring-friendly behavior
    # users rely on for ignore-file entries).
    if pat_segs[0] == "**":
        return _seg_match_anchored(pat_segs, path_segs)
    for start in range(len(path_segs) + 1):
        if _seg_match_anchored(pat_segs, path_segs[start:]):
            return True
    return False


def _seg_match_anchored(pat: list[str], path: list[str]) -> bool:
    """Anchored segment match — first ``pat`` segment must match first ``path``.

    Recurses over the segment lists, with ``**`` consuming zero or more
    path segments greedily with backtrack.
    """
    if not pat:
        return not path
    head = pat[0]
    if head == "**":
        rest = pat[1:]
        if not rest:
            return True  # trailing ** matches any (or zero) remaining segments
        for i in range(len(path) + 1):
            if _seg_match_anchored(rest, path[i:]):
                return True
        return False
    if not path:
        return False
    if fnmatch(path[0], head):
        return _seg_match_anchored(pat[1:], path[1:])
    return False


def filter_findings(findings: list, patterns: list[str]) -> tuple[list, int]:
    """Filter findings whose location matches exclusion patterns.

    Returns (filtered_findings, excluded_count).
    """
    if not patterns:
        return findings, 0

    kept = []
    excluded = 0
    for finding in findings:
        location = getattr(finding, "location", "") or ""
        if location and is_excluded(location, patterns):
            excluded += 1
        else:
            kept.append(finding)

    return kept, excluded


def filter_skipped_rules(
    findings: list,
    skip_ids: list[str],
    rule_ids: Callable[[object], set[str]] | None = None,
) -> tuple[list, int]:
    """Drop findings whose rule ID is listed in ``skip_check``.

    Lets ``skip_check`` in argus.yml work for every scanner, including tools
    with no skip-by-ID flag (Trivy). Matching is case-insensitive.
    ``rule_ids`` lets a scanner offer aliases (Trivy's ``AWS-0017`` is also
    ``AVD-AWS-0017``). Returns (kept_findings, skipped_count).
    """
    if not skip_ids:
        return findings, 0
    skip = {s.upper() for s in skip_ids}
    ids_for = rule_ids or (lambda finding: {finding.id})
    kept = [
        f for f in findings
        if not {i.upper() for i in ids_for(f) if i} & skip
    ]
    return kept, len(findings) - len(kept)


def _parse_ignore_file(path: Path) -> list[str]:
    """Parse a .gitignore-style file into exclusion patterns.

    Skips comments and empty lines. Strips trailing slashes.
    Does not handle negation (!) patterns — those are rare and
    complex to implement correctly.
    """
    patterns = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("!"):
                # Negation patterns not supported — skip
                continue
            # Strip trailing slash (directory indicator)
            line = line.rstrip("/")
            if line:
                patterns.append(line)
    except (OSError, UnicodeDecodeError):
        logger.debug("Failed to read ignore file: %s", path)

    return patterns
