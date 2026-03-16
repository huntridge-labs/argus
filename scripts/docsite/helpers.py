"""Low-level file I/O and YAML helpers."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from . import config


def read(path: Path) -> str:
    """Read a file, returning empty string if it doesn't exist."""
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""


def write(path: Path, content: str) -> None:
    """Write content to *path*, creating parent directories as needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def parse_action_yml(path: Path) -> dict:
    """Parse an action.yml file, returning {} on any error."""
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}


def get_version(repo_root: Path) -> str:
    """Read the project version from version.yaml."""
    raw = read(repo_root / "version.yaml").strip()
    return raw.split()[0] if raw else "latest"


def rewrite_repo_links(content: str, source_rel: str) -> str:
    """Rewrite relative markdown links to absolute GitHub blob URLs.

    Action READMEs contain links like ``../../CHANGELOG.md`` which resolve
    within the repo but break inside the generated docs tree.  This resolves
    each relative link against *source_rel* and, if it escapes the docs tree,
    rewrites it to a GitHub blob URL.
    """
    source_dir = Path(source_rel).parent

    def _rewrite(m: re.Match) -> str:
        prefix = m.group(1)   # [text](
        raw = m.group(2)      # the relative path
        suffix = m.group(3)   # )

        # Skip anchors, absolute URLs, and template expressions
        if raw.startswith(("#", "http://", "https://", "${{", "mailto:")):
            return m.group(0)

        # Strip optional anchor from path for resolution
        anchor = ""
        if "#" in raw:
            raw, anchor = raw.rsplit("#", 1)
            anchor = f"#{anchor}"

        resolved = (source_dir / raw).as_posix()
        # Normalise away ../ segments
        parts: list[str] = []
        for p in resolved.split("/"):
            if p == "..":
                if parts:
                    parts.pop()
            elif p and p != ".":
                parts.append(p)
        clean = "/".join(parts)

        return f"{prefix}{config.GITHUB_BLOB}/{clean}{anchor}{suffix}"

    return re.sub(r'(\[[^\]]*\]\()([^)\s]+)(\))', _rewrite, content)
