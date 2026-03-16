"""Validates docsite.yml and per-action .docsite.yml files.

Run via ``python scripts/build-docs.py --validate`` or import
``validate()`` directly.
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml


_REQUIRED_TOP_KEYS = {"repo_url", "categories", "excluded_actions", "excluded_workflows"}
_REQUIRED_CATEGORY_KEYS = {"label", "icon"}


def validate(repo_root: Path) -> bool:
    """Validate all docsite configuration.  Returns True if valid."""
    errors: list[str] = []
    warnings: list[str] = []

    # ── docsite.yml ──────────────────────────────────────────────────────
    config_path = repo_root / "docsite.yml"
    if not config_path.exists():
        errors.append(f"docsite.yml not found at {config_path}")
        _report(errors, warnings)
        return False

    try:
        data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        errors.append(f"docsite.yml is not valid YAML: {exc}")
        _report(errors, warnings)
        return False

    # Required top-level keys
    missing_top = _REQUIRED_TOP_KEYS - set(data.keys())
    for key in sorted(missing_top):
        errors.append(f"docsite.yml missing required key: '{key}'")

    # Validate repo_url
    repo_url = data.get("repo_url", "")
    if repo_url and not str(repo_url).startswith("http"):
        errors.append(f"docsite.yml repo_url must be a URL, got: '{repo_url}'")

    # Validate categories structure
    categories = data.get("categories") or {}
    defined_categories = set(categories.keys())
    for cat_key, cat_meta in categories.items():
        if not isinstance(cat_meta, dict):
            errors.append(f"docsite.yml category '{cat_key}' must be a mapping")
            continue
        missing_cat = _REQUIRED_CATEGORY_KEYS - set(cat_meta.keys())
        for key in sorted(missing_cat):
            errors.append(f"docsite.yml category '{cat_key}' missing required key: '{key}'")

    # ── Per-action .docsite.yml files ────────────────────────────────────
    actions_dir = repo_root / ".github" / "actions"
    excluded = set(data.get("excluded_actions") or [])

    if not actions_dir.exists():
        warnings.append(f"Actions directory not found: {actions_dir}")
    else:
        for action_dir in sorted(actions_dir.iterdir()):
            if not action_dir.is_dir():
                continue
            action_name = action_dir.name

            if action_name in excluded:
                continue

            docsite_path = action_dir / ".docsite.yml"
            if not docsite_path.exists():
                errors.append(
                    f"Action '{action_name}' missing .docsite.yml"
                    f" (add it or add '{action_name}' to excluded_actions)"
                )
                continue

            try:
                action_data = yaml.safe_load(
                    docsite_path.read_text(encoding="utf-8"),
                ) or {}
            except Exception as exc:
                errors.append(
                    f"Action '{action_name}' .docsite.yml is not valid YAML: {exc}"
                )
                continue

            cat = action_data.get("category")
            if not cat:
                errors.append(
                    f"Action '{action_name}' .docsite.yml missing 'category' key"
                )
            elif defined_categories and cat not in defined_categories:
                errors.append(
                    f"Action '{action_name}' uses category '{cat}'"
                    f" which is not defined in docsite.yml categories"
                )

    _report(errors, warnings)
    return len(errors) == 0


def _report(errors: list[str], warnings: list[str]) -> None:
    """Print validation results."""
    for w in warnings:
        print(f"  ⚠️  {w}")
    for e in errors:
        print(f"  ❌ {e}")

    if errors:
        print(f"\n❌ Validation failed with {len(errors)} error(s)")
    else:
        print("✅ docsite configuration is valid")
