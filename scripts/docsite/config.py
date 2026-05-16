"""Site configuration — loaded from repo-level docsite.yml at build time.

Call ``load_site_config(repo_root, ref=...)`` once at the start of a
build. There are NO fallback defaults — ``docsite.yml`` must be
complete. The ``ref`` argument controls the git ref used in the
``GITHUB_BLOB`` rewrite (e.g. ``main``, ``v0.7.2``, or a PR head SHA)
so that versioned doc URLs link to the matching blob URLs instead of
always hardcoding ``main``.
"""

from __future__ import annotations

import os
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


def _resolve_blob_ref(ref: str | None) -> str:
    """Resolve the git ref to use in GITHUB_BLOB rewrites.

    Precedence (highest first):
      1. The ``ref`` argument (caller-supplied — typically the docsite
         CLI ``--ref`` flag).
      2. ``ARGUS_DOCS_REF`` env var (CI sets this per trigger: tag for
         release events, head SHA for pull requests, ``main`` for push
         events).
      3. Fallback ``"main"`` — preserves legacy behavior when neither
         is supplied, matching what every published-docs URL points at
         today.
    """
    if ref:
        return ref
    env = os.environ.get("ARGUS_DOCS_REF", "").strip()
    if env:
        return env
    return "main"


def load_site_config(repo_root: Path, *, ref: str | None = None) -> None:
    """Read ``docsite.yml`` from *repo_root* and populate module-level state.

    Exits with an error if the file is missing or incomplete.

    ``ref`` controls the git ref encoded in ``GITHUB_BLOB`` — used by
    ``rewrite_repo_links`` to turn relative markdown links into
    absolute ``github.com/.../blob/<ref>/<path>`` URLs. Versioned
    builds pass the release tag here so doc URLs at
    ``/argus/v0.7.2/`` point at matching blob URLs at
    ``/blob/v0.7.2/`` instead of drifting onto ``main``.
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
    blob_ref = _resolve_blob_ref(ref)
    GITHUB_BLOB = f"{repo_url}/blob/{blob_ref}"

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
