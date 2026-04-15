"""Path exclusion handling — reads ignore files and builds unified exclude set.

Argus automatically respects .gitignore, .dockerignore, and tool-specific
ignore files. Combined with --exclude CLI patterns and argus.yml config,
this produces a single exclusion set applied pre-scan and post-scan.
"""

import logging
from fnmatch import fnmatch
from pathlib import Path

logger = logging.getLogger("argus")

# Ignore files read automatically, in order of precedence
_IGNORE_FILES = [
    ".gitignore",
    ".dockerignore",
    ".semgrepignore",
    ".trivyignore",
    ".gitleaksignore",
]

# Paths always excluded (build artifacts, dependencies, caches)
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
]


def build_exclusion_set(
    scan_path: str = ".",
    cli_excludes: str = "",
    config_excludes: str = "",
) -> list[str]:
    """Build unified exclusion patterns from all sources.

    Sources (in order):
    1. Built-in defaults (node_modules, .git, __pycache__, etc.)
    2. Ignore files (.gitignore, .dockerignore, etc.)
    3. argus.yml scanner-level exclude config
    4. --exclude CLI flag

    Returns a deduplicated list of exclusion patterns.
    """
    patterns: list[str] = list(_BUILTIN_EXCLUDES)

    # Read ignore files from the scan root
    root = Path(scan_path)
    for ignore_file in _IGNORE_FILES:
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
    """Check if a file path matches any exclusion pattern."""
    for pattern in patterns:
        # Direct substring match (existing behavior)
        if pattern in path:
            return True
        # Glob-style match against each path component
        parts = Path(path).parts
        for part in parts:
            if fnmatch(part, pattern):
                return True
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
