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
    """Rewrite relative markdown links for the generated docs site.

    Links that point to content hosted on the docsite (guide pages from
    ``docs/`` and action READMEs from ``.github/actions/``) are rewritten to
    page-relative paths so they stay within the versioned docsite. All other
    relative links are rewritten to absolute GitHub blob URLs so they still
    resolve.

    The source page's docsite path is computed up-front so docsite-internal
    links resolve relative to the rendered page's location (not relative to
    docs_dir root) — without that, a link from ``guides/view-terminal.md``
    to ``guides/cli-reference.md`` was being interpreted as
    ``guides/guides/cli-reference.md`` and failing ``mkdocs --strict``.
    """
    source_dir = Path(source_rel).parent

    # Compute the source page's docsite location for relative-link math.
    # When the source has no docsite mapping (e.g. README.md in repo root)
    # fall back to root-relative paths.
    source_docsite = _to_docsite_path(source_rel)
    source_docsite_dir = (
        Path(source_docsite).parent if source_docsite else Path(".")
    )

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

        # Rewrite docsite-hosted targets to a path relative to the
        # rendered source page. Mkdocs interprets unprefixed paths
        # relative to the current page's directory, not docs_dir root.
        docsite_path = _to_docsite_path(clean)
        if docsite_path is not None:
            import os.path
            target_relative = os.path.relpath(
                docsite_path, start=str(source_docsite_dir),
            )
            return f"{prefix}{target_relative}{anchor}{suffix}"

        return f"{prefix}{config.GITHUB_BLOB}/{clean}{anchor}{suffix}"

    return re.sub(r'(\[[^\]]*\]\()([^)\s]+)(\))', _rewrite, content)


def _to_docsite_path(repo_path: str) -> str | None:
    """Map a resolved repo-relative path to a docsite-relative path.

    Returns ``None`` when the path doesn't correspond to a docsite page.

    Mappings:
      ``docs/<name>.md``                    → ``guides/<name>.md``
      ``docs/<sub>/<name>.md``              → ``guides/<sub>/<name>.md``
      ``docs/images/<rest>``                → ``../images/<rest>`` (from guides)
      ``.github/actions/<name>/README.md``  → ``actions/<name>.md``

    Note: we emit ``.md`` rather than the bare-directory form
    (``guides/<name>/``) so ``mkdocs build --strict`` can resolve and
    validate the target. Material renders the same URL either way
    (issue #167-6).
    """
    # docs/images/... — image assets copied into docs_out/images/. Guide
    # pages reference them as relative paths like ``images/...``; the
    # rewriter resolves those to ``docs/images/...``. Return the
    # docsite-root path; ``rewrite_repo_links`` then computes the
    # correct ``../images/...`` relative to the source page's location
    # (issue #167-1).
    images_match = re.match(r'^docs/images/(.+)$', repo_path)
    if images_match:
        return f"images/{images_match.group(1)}"

    # docs/<sub>/<name>.md → guides/<sub>/<name>.md (preserves nesting
    # for ``migration/`` and ``troubleshooting/`` sub-trees). When the
    # subdirectory is in ``EXCLUDED_GUIDE_DIRS`` (e.g. ``developer/``
    # — internal-only pages that don't ship to the docsite), fall
    # through so the rewriter sends the link to GitHub blob instead
    # of producing a dead docsite-relative reference.
    nested_match = re.match(r'^docs/([^/]+)/(.+)\.md$', repo_path)
    if nested_match and nested_match.group(1) not in config.EXCLUDED_GUIDE_DIRS:
        return f"guides/{nested_match.group(1)}/{nested_match.group(2)}.md"

    # docs/*.md → guides/*.md (top-level guides)
    docs_match = re.match(r'^docs/([^/]+)\.md$', repo_path)
    if docs_match:
        return f"guides/{docs_match.group(1)}.md"

    # .github/actions/<name>/README.md → actions/<name>.md
    action_match = re.match(
        r'^\.github/actions/([^/]+)/README\.md$', repo_path,
    )
    if action_match:
        return f"actions/{action_match.group(1)}.md"

    return None
