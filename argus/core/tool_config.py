"""Canonical config-file discovery for scanner tools.

Many of the tools Argus wraps (bandit, trivy, checkov, osv-scanner, opengrep)
do NOT auto-discover their canonical config from the working directory —
they require the caller to pass ``-c``/``--config``/``--config-file``
explicitly. Without that, users who drop a ``.bandit`` or ``.checkov.yaml``
at the project root see their suppressions silently ignored.

This module centralizes the discovery + resolution logic so every scanner
wrapper can report a consistent ``ConfigResolution`` — what it tried, what
it found, and where the answer came from. The actual CLI flag stays in
each scanner's ``container_args()`` / ``_build_command()`` because the
flag text varies per tool.

Resolution precedence (first match wins):
  1. Explicit ``config_file:`` in ``argus.yml`` — always wins, no discovery.
  2. Auto-discovery from the scanner's canonical candidate list.
  3. None — scanner runs with its built-in defaults.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger("argus")


@dataclass
class ConfigCandidate:
    """A potential config file the scanner should look for."""

    filename: str
    required_section: str | None = None
    """If set (e.g., 'tool.bandit'), only match when the file declares this
    TOML section — pyproject.toml is only valid for bandit when
    [tool.bandit] is actually present."""


@dataclass
class ConfigResolution:
    """How a scanner's config_file was resolved, for transparent logging."""

    scanner: str
    source: str  # "explicit", "discovered", "none"
    path: str | None = None
    candidates_tried: list[str] = field(default_factory=list)

    def log_line(self) -> str:
        """One-line summary suitable for scan startup logs."""
        if self.source == "explicit":
            return f"{self.scanner}: using {self.path} (from argus.yml)"
        if self.source == "discovered":
            return f"{self.scanner}: auto-discovered {self.path}"
        # source == "none"
        if self.candidates_tried:
            return (
                f"{self.scanner}: no config file — looked for "
                f"{', '.join(self.candidates_tried)}"
            )
        return f"{self.scanner}: no config file (tool has no canonical discovery)"


# Per-scanner discovery rules. Order matters — first match wins.
# Keep this table adjacent to the module docstring so drift is obvious.
DISCOVERY_RULES: dict[str, list[ConfigCandidate]] = {
    "bandit": [
        ConfigCandidate("pyproject.toml", required_section="tool.bandit"),
        ConfigCandidate(".bandit"),
        ConfigCandidate("bandit.yaml"),
        ConfigCandidate("bandit.yml"),
    ],
    "trivy-iac": [
        ConfigCandidate("trivy.yaml"),
        ConfigCandidate("trivy.yml"),
    ],
    "checkov": [
        ConfigCandidate(".checkov.yaml"),
        ConfigCandidate(".checkov.yml"),
    ],
    "osv": [
        ConfigCandidate("osv-scanner.toml"),
    ],
    "opengrep": [
        ConfigCandidate("semgrep.yml"),
        ConfigCandidate("semgrep.yaml"),
        ConfigCandidate(".semgrep.yml"),
        ConfigCandidate(".semgrep.yaml"),
    ],
}


def resolve_config(
    scanner_name: str,
    scan_root: str,
    explicit: str | None,
) -> ConfigResolution:
    """Resolve a scanner's config file path using the precedence rules.

    Returns a ConfigResolution describing the outcome. Callers read
    ``.path`` to decide whether to pass ``-c``/``--config`` to the tool.
    """
    if explicit:
        return ConfigResolution(
            scanner=scanner_name,
            source="explicit",
            path=explicit,
        )

    rules = DISCOVERY_RULES.get(scanner_name, [])
    root = Path(scan_root)
    tried: list[str] = []
    for candidate in rules:
        tried.append(candidate.filename)
        target = root / candidate.filename
        if not target.is_file():
            continue
        if candidate.required_section and not _has_toml_section(
            target, candidate.required_section
        ):
            continue
        return ConfigResolution(
            scanner=scanner_name,
            source="discovered",
            path=str(target),
            candidates_tried=tried,
        )

    return ConfigResolution(
        scanner=scanner_name,
        source="none",
        candidates_tried=tried,
    )


def _has_toml_section(path: Path, section: str) -> bool:
    """Return True if the TOML file defines the given (possibly dotted) section.

    ``tool.bandit`` means ``[tool.bandit]`` — we walk the dotted segments
    so this stays correct for any TOML file, not just pyproject.toml.
    Uses stdlib tomllib (3.11+) so no new dependency.
    """
    try:
        import tomllib
    except ImportError:  # pragma: no cover — 3.10 shim not supported upstream
        return False
    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError):
        return False
    cursor = data
    for segment in section.split("."):
        if not isinstance(cursor, dict) or segment not in cursor:
            return False
        cursor = cursor[segment]
    return True


def log_resolutions(resolutions: list[ConfigResolution]) -> None:
    """Emit one INFO line per resolution for scan-startup transparency."""
    if not resolutions:
        return
    logger.info("Scanner config resolution:")
    for res in resolutions:
        logger.info("  %s", res.log_line())


def format_resolutions_for_display(resolutions: list[ConfigResolution]) -> str:
    """Multi-line string for --dry-run / terminal output."""
    if not resolutions:
        return "(no scanners selected)"
    lines = ["Scanner config resolution:"]
    for res in resolutions:
        lines.append(f"  {res.log_line()}")
    return "\n".join(lines)
