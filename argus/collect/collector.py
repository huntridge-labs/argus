"""Collect and organize per-scanner results into a unified audit package.

Platform-agnostic: works on any directory of per-scanner results,
regardless of how they were gathered (GitHub download-artifact,
GitLab dependencies, Jenkins stash, or manual copy).

Input convention:
    collected/
    ├── argus-results-bandit/
    │   ├── argus.log
    │   ├── argus-audit.json
    │   ├── argus-results.json
    │   └── argus-results.sarif
    ├── argus-results-gitleaks/
    │   └── ...
    └── argus-results-osv/
        └── ...

Output:
    argus-audit-package/
    ├── argus-combined.log          # All logs merged, sorted by timestamp
    ├── argus-audit.json            # Combined manifest
    ├── summary.md                  # Combined markdown
    └── scanners/
        ├── bandit/
        │   ├── argus-results.json
        │   ├── argus-results.sarif
        │   └── argus-audit.json
        ├── gitleaks/
        │   └── ...
        └── osv/
            └── ...
"""

import logging
import shutil
from pathlib import Path

from .merger import (
    inventory_artifacts,
    merge_logs,
    merge_manifests,
    merge_summaries,
)

logger = logging.getLogger("argus.collect")


def collect_results(
    input_dir: str | Path,
    output_dir: str | Path = "./argus-audit-package",
) -> Path:
    """Collect per-scanner results into a unified audit package.

    Discovers scanner result directories by convention
    (``argus-results-*`` prefix or any subdirectory containing
    ``argus.log`` or ``argus-audit.json``).

    Returns the path to the output directory.
    """
    input_path = Path(input_dir)
    output_path = Path(output_dir)

    if not input_path.is_dir():
        logger.error("Input directory not found: %s", input_path)
        return output_path

    # Discover scanner result directories
    scanner_dirs = _discover_scanner_dirs(input_path)
    if not scanner_dirs:
        # ``argus collect`` is for the CI-matrix layout where each
        # scanner writes to its own ``argus-results-<scanner>/`` dir
        # before they're merged. If the input looks like a local
        # ``argus-results/`` (timestamped per-run subdirs + a
        # ``latest`` symlink), say so explicitly instead of just
        # "no result dirs found" — issue #168-L.
        if any(
            child.is_dir() and (child / "argus-results.json").exists()
            for child in input_path.iterdir()
        ) or (input_path / "latest").is_symlink():
            logger.warning(
                "%s looks like a local-layout argus-results/ directory "
                "(per-run timestamped subdirs). `argus collect` expects "
                "CI-matrix layout (argus-results-<scanner>/) — point "
                "it at the artifact root from your CI matrix run, or "
                "use `argus report` against an individual run dir.",
                input_path,
            )
        else:
            logger.warning("No scanner result directories found in %s", input_path)
        return output_path

    logger.info(
        "Found %d scanner result dir(s): %s",
        len(scanner_dirs),
        [d.name for d in scanner_dirs],
    )

    # Prepare output
    output_path.mkdir(parents=True, exist_ok=True)
    scanners_dir = output_path / "scanners"

    # Collect files from each scanner
    log_files: list[Path] = []
    manifest_files: list[Path] = []
    summary_files: list[Path] = []

    for scanner_dir in sorted(scanner_dirs):
        scanner_name = _extract_scanner_name(scanner_dir)
        dest = scanners_dir / scanner_name
        dest.mkdir(parents=True, exist_ok=True)

        logger.debug("Collecting %s → %s", scanner_dir.name, dest)

        # Copy all files to the per-scanner directory
        for src_file in scanner_dir.iterdir():
            if src_file.is_file():
                shutil.copy2(src_file, dest / src_file.name)

        # Track files for merging
        log_file = scanner_dir / "argus.log"
        if log_file.exists():
            log_files.append(log_file)

        manifest_file = scanner_dir / "argus-audit.json"
        if manifest_file.exists():
            manifest_files.append(manifest_file)

        summary_file = scanner_dir / "argus-summary.md"
        if summary_file.exists():
            summary_files.append(summary_file)

    # Merge logs (sorted by timestamp across all scanners)
    if log_files:
        merge_logs(log_files, output_path / "argus-combined.log")

    # Merge manifests (combined provenance and findings)
    if manifest_files:
        merge_manifests(manifest_files, output_path / "argus-audit.json")

    # Merge markdown summaries
    if summary_files:
        merge_summaries(summary_files, output_path / "summary.md")

    # Final artifact inventory with hashes
    manifest_path = output_path / "argus-audit.json"
    if manifest_path.exists():
        inventory_artifacts(output_path, manifest_path)

    logger.info(
        "Audit package created: %s (%d scanner(s), %d log(s), %d manifest(s))",
        output_path,
        len(scanner_dirs),
        len(log_files),
        len(manifest_files),
    )

    return output_path


def _discover_scanner_dirs(input_path: Path) -> list[Path]:
    """Find directories containing argus results.

    Matches by convention:
    1. Directories named ``argus-results-{scanner}`` (the CI-matrix
       artifact layout this command was designed for).
    2. Any subdirectory containing ``argus.log`` or ``argus-audit.json``
       (fallback for unconventional naming).

    Skipped:
    - The ``latest`` symlink — duplicates whatever it points at.
    - Per-run timestamp dirs (``2026-05-17T01-46-56Z``) — these are
      local ``argus scan`` output, not per-scanner CI artifacts.
      Treating them as "scanners" mis-labels every run as if it were
      a distinct scanner (issue #168-L).
    """
    import re
    # ISO-8601-ish timestamps as written by argus' run-dir creator:
    # ``YYYY-MM-DDTHH-MM-SSZ`` (note the ``-`` separators in the time
    # portion — Windows can't have ``:`` in filenames).
    timestamp_re = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z$")

    dirs: list[Path] = []

    for child in input_path.iterdir():
        if not child.is_dir():
            continue

        # Skip the ``latest`` symlink — it points at a sibling we'll
        # see directly. Including it double-counts the most recent run.
        if child.is_symlink() and child.name == "latest":
            continue

        # Skip per-run timestamp dirs — local layout, not per-scanner.
        if timestamp_re.match(child.name):
            continue

        # Convention: argus-results-{scanner_name}
        if child.name.startswith("argus-results-"):
            dirs.append(child)
            continue

        # Fallback: any dir with argus artifacts
        if (child / "argus.log").exists() or (child / "argus-audit.json").exists():
            dirs.append(child)

    return dirs


def _extract_scanner_name(scanner_dir: Path) -> str:
    """Extract scanner name from directory name.

    argus-results-bandit → bandit
    argus-results-trivy-iac → trivy-iac
    some-other-dir → some-other-dir
    """
    name = scanner_dir.name
    if name.startswith("argus-results-"):
        return name[len("argus-results-"):]
    return name
