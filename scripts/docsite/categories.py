"""Category resolution — reads .docsite.yml from each action directory."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from . import config


@dataclass
class ActionCategoryInfo:
    """Metadata declared in an action's .docsite.yml file."""

    category: str
    sidebar_label: str | None = None


def load_docsite_config(action_dir: Path) -> ActionCategoryInfo | None:
    """Load .docsite.yml from an action directory, or return None."""
    config_path = action_dir / ".docsite.yml"
    if not config_path.exists():
        return None
    try:
        data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except Exception:
        return None
    category = data.get("category")
    if not category:
        return None
    return ActionCategoryInfo(
        category=category,
        sidebar_label=data.get("sidebar_label"),
    )


def action_category(action_name: str, actions_dir: Path) -> str:
    """Resolve an action's category from its .docsite.yml, or 'other'."""
    info = load_docsite_config(actions_dir / action_name)
    if info:
        return info.category
    return "other"


def get_categorized_actions(actions_dir: Path) -> dict[str, list[str]]:
    """Build category → action-name list from .docsite.yml files.

    Actions without .docsite.yml land in "other".
    """
    all_actions = sorted(
        d.name for d in actions_dir.iterdir()
        if d.is_dir() and d.name not in config.EXCLUDED_ACTIONS
    )

    result: dict[str, list[str]] = {}
    for name in all_actions:
        cat = action_category(name, actions_dir)
        result.setdefault(cat, []).append(name)

    return {k: sorted(v) for k, v in result.items() if v}


def category_label(cat: str) -> str:
    """Human-readable label for a category key."""
    return config.CATEGORY_LABELS.get(cat, cat.replace("-", " ").title())


def category_icon(cat: str) -> str:
    """Emoji icon for a category key."""
    return config.CATEGORY_ICONS.get(cat, "🆕")
