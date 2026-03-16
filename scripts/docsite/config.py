"""Site configuration — loaded from repo-level docsite.yml at build time.

Call ``load_site_config(repo_root)`` once at the start of a build.
There are NO fallback defaults — ``docsite.yml`` must be complete.
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml


# ─── Module-level state (populated by load_site_config) ─────────────────────

CATEGORY_LABELS: dict[str, str] = {}
CATEGORY_ICONS: dict[str, str] = {}
EXCLUDED_ACTIONS: set[str] = set()
EXCLUDED_WORKFLOWS: set[str] = set()
EXCLUDED_GUIDE_DIRS: set[str] = set()
GITHUB_BLOB: str = ""
GROUP_LABELS: dict[str, str] = {}


# ─── Loader ──────────────────────────────────────────────────────────────────

_REQUIRED_TOP_KEYS = {"repo_url", "categories", "excluded_actions", "excluded_workflows"}


def load_site_config(repo_root: Path) -> None:
    """Read ``docsite.yml`` from *repo_root* and populate module-level state.

    Exits with an error if the file is missing or incomplete.
    """
    global CATEGORY_LABELS, CATEGORY_ICONS
    global EXCLUDED_ACTIONS, EXCLUDED_WORKFLOWS, EXCLUDED_GUIDE_DIRS
    global GITHUB_BLOB, GROUP_LABELS

    config_path = repo_root / "docsite.yml"
    if not config_path.exists():
        print(f"❌ {config_path} not found — required for doc site generation")
        sys.exit(1)

    try:
        data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        print(f"❌ Failed to parse {config_path}: {exc}")
        sys.exit(1)

    # Validate required top-level keys
    missing = _REQUIRED_TOP_KEYS - set(data.keys())
    if missing:
        print(f"❌ docsite.yml missing required keys: {', '.join(sorted(missing))}")
        sys.exit(1)

    # Repo URL → GITHUB_BLOB
    repo_url = str(data["repo_url"]).rstrip("/")
    GITHUB_BLOB = f"{repo_url}/blob/main"

    # Categories
    categories_raw = data.get("categories") or {}
    CATEGORY_LABELS = {}
    CATEGORY_ICONS = {}
    for key, meta in categories_raw.items():
        if not isinstance(meta, dict):
            continue
        CATEGORY_LABELS[key] = meta.get("label", key.replace("-", " ").title())
        CATEGORY_ICONS[key] = meta.get("icon", "🆕")

    # Input group labels
    GROUP_LABELS = dict(data.get("input_group_labels") or {})

    # Exclusions
    EXCLUDED_ACTIONS = set(data.get("excluded_actions") or [])
    EXCLUDED_WORKFLOWS = set(data.get("excluded_workflows") or [])
    EXCLUDED_GUIDE_DIRS = set(data.get("excluded_guide_dirs") or [])
