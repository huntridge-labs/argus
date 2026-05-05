"""Friendly diagnostics for the missing-``argus-results.json`` pitfall.

UI-free helpers shared by the terminal and browser viewers (and the
``argus view --check`` flag). When the user lands on ``argus view``
without a results file, the most common root cause is *config* —
``reporting.formats`` in ``argus.yml`` doesn't include ``json``, so
the previous ``argus scan`` run wrote terminal/markdown/SARIF but not
the JSON file the viewers actually consume. Surface that distinction
in the error itself so users don't have to guess.
"""

from __future__ import annotations

from pathlib import Path

# Same precedence as ``argus.core.config._DEFAULT_CONFIG_NAMES``. Kept
# separate (not imported) so the diagnoser can run without dragging in
# the rest of the config-loading machinery.
_CONFIG_NAMES = ("argus.yml", "argus.yaml", ".argus.yml", ".argus.yaml")

_RESULTS_FILENAME = "argus-results.json"


def diagnose_missing_results(searched_path: Path) -> str:
    """Build a remediation-rich error message for a missing results JSON.

    The string returned is suitable for raising as a ``FileNotFoundError``
    *and* for displaying verbatim in the browser viewer's empty-state.
    Wrapping at ~78 columns so long terminals don't reflow it weirdly.
    """
    lines: list[str] = [
        f"Error: {_RESULTS_FILENAME} not found at {searched_path}.",
        "",
        "Hint: argus view requires JSON scan output.",
        "",
    ]

    config_path = _find_nearby_argus_config()
    formats = _read_reporting_formats(config_path) if config_path else None

    if config_path is not None and formats is not None and "json" not in formats:
        # Targeted hint: we know exactly why the file is missing.
        lines.extend([
            f"Detected {config_path.name} at {config_path}, but its",
            f"reporting.formats is {formats!r} — 'json' isn't included, so",
            "argus scan didn't write the file argus view reads.",
            "",
            "Fix (choose one):",
            f"  • Add 'json' to reporting.formats in {config_path.name}, then rerun:",
            "      argus scan",
            "  • Or, one-shot from the CLI:",
            "      argus scan --format json --no-timestamp",
            "",
            f"Then retry: argus view {_retry_arg(searched_path)}",
        ])
    else:
        # Generic hint: config is absent or already lists json (different
        # cause — wrong path, scan never ran, output dir mismatch, etc.).
        lines.extend([
            "Run a scan that emits JSON, then retry. Two ways:",
            "  • Add 'json' to reporting.formats in argus.yml and run:",
            "      argus scan",
            "  • Or, one-shot from the CLI:",
            "      argus scan --format json --no-timestamp",
            "",
            f"Then retry: argus view {_retry_arg(searched_path)}",
        ])

    return "\n".join(lines)


def _retry_arg(searched_path: Path) -> str:
    """Best-guess argument the user should pass back to ``argus view``.

    If the search hit a file (``…/argus-results.json``), point the user
    at its parent directory. Otherwise, echo the directory we tried.
    Falls back to a literal ``<results-dir>`` placeholder when the path
    is empty/relative-only.
    """
    if searched_path.name == _RESULTS_FILENAME:
        target = searched_path.parent
    else:
        target = searched_path
    rendered = str(target)
    return rendered if rendered not in ("", ".") else "<results-dir>"


def _find_nearby_argus_config(start: Path | None = None) -> Path | None:
    """Walk up from ``start`` (default cwd) looking for an argus config.

    Returns the first ``argus.yml`` (or other accepted name) we find at
    or above the starting directory. ``None`` if we hit the filesystem
    root without finding one — that's the "no config" branch the
    diagnoser falls back to a generic hint for.
    """
    current = (start or Path.cwd()).resolve()
    while True:
        for name in _CONFIG_NAMES:
            candidate = current / name
            if candidate.is_file():
                return candidate
        if current.parent == current:
            return None
        current = current.parent


def _read_reporting_formats(config_path: Path) -> list[str] | None:
    """Read ``reporting.formats`` from an argus config file.

    Returns the list of format names, or ``None`` when:
      - PyYAML can't parse the file (syntax error)
      - the ``reporting.formats`` key is absent
      - the value isn't a list

    Any of those means we can't make a confident "json missing from
    formats" claim, so the caller should fall back to the generic hint.
    Defensive about exceptions because this runs from the error path —
    we don't want a broken argus.yml to mask the original missing-file
    diagnostic.
    """
    try:
        import yaml
    except ImportError:  # pragma: no cover — pyyaml is a hard SDK dep
        return None

    try:
        text = config_path.read_text(encoding="utf-8")
    except OSError:
        return None

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        return None

    if not isinstance(data, dict):
        return None

    reporting = data.get("reporting")
    if not isinstance(reporting, dict):
        return None

    formats = reporting.get("formats")
    if not isinstance(formats, list):
        return None

    return [str(f) for f in formats]


__all__ = ["diagnose_missing_results"]
