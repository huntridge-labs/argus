"""Index page generators — overview pages for actions, workflows, and home."""

from __future__ import annotations

import re
from pathlib import Path

from .categories import (
    category_icon,
    category_label,
    get_categorized_actions,
)
from . import config
from .helpers import parse_action_yml, read, rewrite_repo_links
from .parsers import parse_workflow_meta


def make_actions_index(actions_dir: Path, version: str) -> str:
    """Generate the composite-actions overview page with categorised tables."""
    lines = [
        "# Composite Actions\n",
        "All Argus scanner and utility actions."
        " Each is self-contained and usable independently.\n",
    ]

    categories = get_categorized_actions(actions_dir)
    for cat, members in categories.items():
        icon = category_icon(cat)
        label = category_label(cat)
        rows: list[str] = []
        for action_name in members:
            action_dir = actions_dir / action_name
            if not action_dir.exists():
                continue
            meta = parse_action_yml(action_dir / "action.yml")
            desc = (meta.get("description") or "").split("\n")[0].strip().rstrip(".")
            rows.append(f"| [`{action_name}`]({action_name}.md) | {desc} |")
        if rows:
            lines.append(f"## {icon} {label}\n")
            lines.append("| Action | Description |")
            lines.append("|--------|-------------|")
            lines.extend(rows)
            lines.append("")

    return "\n".join(lines)


def make_workflows_index(workflows_dir: Path, version: str) -> str:
    """Generate the reusable-workflows overview page."""
    lines = [
        "# Reusable Workflows\n",
        "Thin workflow wrappers for `workflow_call`. "
        "For direct action use see [Composite Actions](../actions/index.md).\n",
    ]

    main = workflows_dir / "reusable-security-hardening.yml"
    scanner_wfs = sorted(workflows_dir.glob("scanner-*.yml"))
    other_wfs = sorted([
        p for p in workflows_dir.glob("*.yml")
        if p != main and p not in scanner_wfs
        and not p.stem.startswith("test-")
        and p.stem not in config.EXCLUDED_WORKFLOWS
    ])

    if main.exists():
        lines += [
            "## Main Hardening Pipeline\n",
            "| Workflow | Description |",
            "|----------|-------------|",
            "| [`reusable-security-hardening`](reusable-security-hardening.md) | "
            "Full security hardening pipeline — entry point for most users |",
            "",
        ]

    if scanner_wfs:
        lines += [
            "## Individual Scanner Workflows\n",
            "| Workflow | Description |",
            "|----------|-------------|",
        ]
        for wf in scanner_wfs:
            meta = parse_workflow_meta(wf)
            lines.append(f"| [`{wf.stem}`]({wf.stem}.md) | {meta['name']} |")
        lines.append("")

    if other_wfs:
        lines += [
            "## Utility Workflows\n",
            "| Workflow | Description |",
            "|----------|-------------|",
        ]
        for wf in other_wfs:
            meta = parse_workflow_meta(wf)
            lines.append(f"| [`{wf.stem}`]({wf.stem}.md) | {meta['name']} |")
        lines.append("")

    return "\n".join(lines)


def make_home(repo_root: Path, version: str) -> str:
    """Generate the home page from the repo README."""
    readme = read(repo_root / "README.md")
    if not readme:
        return (
            f"# Argus\n\nOSS-first GitHub Actions security hardening"
            f" — Huntridge Labs. Version `{version}`.\n"
        )
    # Add markdown attribute to div tags so md_in_html processes badges
    readme = re.sub(r'<div\b([^>]*)>', r'<div markdown\1>', readme)
    # Rewrite local image paths to assets/
    readme = readme.replace('img/', 'assets/')
    # Rewrite relative links to GitHub blob URLs
    readme = rewrite_repo_links(readme, "README.md")
    return readme
