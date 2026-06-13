"""UI-free model for the Console's Init wizard (Phase 3).

Textual-free (imports only ``argus.init`` + stdlib) so the wizard's logic is
unit-testable in CI without the ``[terminal]`` extra. It's a thin wrapper
over the *pure* detection + config-generation functions in ``argus.init`` —
no detection logic is reimplemented here:

    detect_project        → what languages / manifests / CI the repo has
    generate_config       → the proposed argus.yml for those signals
    _extract_enabled_scanners / _check_local_readiness → review metadata

``InitScreen`` (in ``console.py``) renders the :class:`InitPlan` this module
builds, lets the user toggle the proposed scanners (reusing
``config_editor``), then writes ``argus.yml`` via :func:`write_config`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from argus.init import (
    SIGNAL_LABELS,
    _check_local_readiness,
    _extract_enabled_scanners,
    detect_project,
    generate_config,
)

# Canonical config filename the wizard writes.
CONFIG_FILENAME = "argus.yml"


@dataclass(frozen=True)
class DetectedCategory:
    """One detected project signal, ready for display."""

    key: str          # detect_project key, e.g. "python"
    label: str        # human label from SIGNAL_LABELS
    example: str      # first evidence path, e.g. "src/app.py"
    count: int        # number of evidence paths


@dataclass(frozen=True)
class InitPlan:
    """What the wizard detected plus the argus.yml it proposes to write."""

    root: Path
    categories: list[DetectedCategory] = field(default_factory=list)
    proposed_scanners: list[str] = field(default_factory=list)
    yaml: str = ""
    readiness: dict[str, int] | None = None
    config_path: Path = field(default_factory=lambda: Path(CONFIG_FILENAME))
    config_exists: bool = False


def detected_categories(signals: dict[str, list[str]]) -> list[DetectedCategory]:
    """Turn ``detect_project`` output into ordered, display-ready categories."""
    categories: list[DetectedCategory] = []
    for key, evidence in signals.items():
        categories.append(DetectedCategory(
            key=key,
            label=SIGNAL_LABELS.get(key, key),
            example=evidence[0] if evidence else "",
            count=len(evidence),
        ))
    return categories


def build_plan(root: Path, *, detect: bool = True) -> InitPlan:
    """Detect ``root`` and assemble the proposal — pure, no writes.

    Mirrors the first half of ``argus.init.run_init`` (detect → generate →
    summarise) but stops short of writing, so the wizard can show the plan
    and let the user adjust it first.
    """
    signals = detect_project(root) if detect else {}
    yaml_text = generate_config(signals)
    scanners = _extract_enabled_scanners(yaml_text)
    config_path = root / CONFIG_FILENAME
    return InitPlan(
        root=root,
        categories=detected_categories(signals),
        proposed_scanners=scanners,
        yaml=yaml_text,
        readiness=_check_local_readiness(scanners),
        config_path=config_path,
        config_exists=config_path.is_file(),
    )


def readiness_line(readiness: dict[str, int] | None) -> str:
    """One-line readiness summary, or ``""`` when unavailable."""
    if not readiness:
        return ""
    local = readiness.get("local", 0)
    container = readiness.get("container", 0)
    missing = readiness.get("missing", 0)
    parts = [f"{local} ready locally", f"{container} via container"]
    parts.append(f"{missing} missing" if missing else "0 missing")
    return " · ".join(parts)


def summary_line(plan: InitPlan) -> str:
    """A single human line describing the plan for the wizard header."""
    if plan.categories:
        labels = ", ".join(c.label for c in plan.categories)
        detected = f"detected {labels}"
    else:
        detected = "no project signals detected — proposing safe defaults"
    scanners = f"{len(plan.proposed_scanners)} scanners proposed"
    return f"{detected}   ·   {scanners}"


def write_config(config_path: Path, content: str, *, force: bool = False) -> Path:
    """Write ``content`` to ``config_path``.

    Raises :class:`FileExistsError` when the file already exists and
    ``force`` is False — mirroring ``argus init``'s overwrite guard so the
    wizard never silently clobbers a user's config.
    """
    if config_path.exists() and not force:
        raise FileExistsError(config_path)
    config_path.write_text(content, encoding="utf-8")
    return config_path
