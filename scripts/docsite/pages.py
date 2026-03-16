"""Markdown page generators for individual actions and workflows."""

from __future__ import annotations

import re
from pathlib import Path

from .categories import action_category, category_icon, load_docsite_config
from . import config
from .diagrams import make_workflow_diagram
from .helpers import parse_action_yml, read, rewrite_repo_links
from .parsers import parse_workflow_full


def make_action_page(action_dir: Path, version: str) -> str:
    """Generate a documentation page for a single composite action."""
    action_name = action_dir.name
    meta = parse_action_yml(action_dir / "action.yml")
    readme = read(action_dir / "README.md")

    # Allow .docsite.yml to override the display name
    docsite = load_docsite_config(action_dir)
    name = (docsite.sidebar_label if docsite and docsite.sidebar_label
            else meta.get("name", action_name))

    description = meta.get("description", "").strip()
    description = re.split(r"\*\*Usage Example", description)[0].strip()
    inputs = meta.get("inputs") or {}
    outputs = meta.get("outputs") or {}

    lines = [f"# {name}\n"]

    short_desc = description.split("\n")[0].strip().rstrip(".")
    if short_desc:
        lines.append(f"{short_desc}\n")

    lines.append("```yaml")
    lines.append(f"uses: huntridge-labs/argus/.github/actions/{action_name}@{version}")
    lines.append("```\n")

    if readme:
        readme_body = re.sub(r"^#\s+.+\n", "", readme, count=1).strip()
        source_rel = f".github/actions/{action_name}/README.md"
        readme_body = rewrite_repo_links(readme_body, source_rel)
        lines.append(readme_body)
        lines.append("")
        return "\n".join(lines)

    # Fallback: auto-generate tables from action.yml
    if inputs:
        lines.append("## Inputs\n")
        lines.append("| Input | Description | Required | Default |")
        lines.append("|-------|-------------|----------|---------|")
        for key, val in inputs.items():
            if not isinstance(val, dict):
                continue
            desc = str(val.get("description", "")).replace("\n", " ").strip()
            req = "Yes" if val.get("required") else "No"
            default = str(val.get("default", "")).strip() or "—"
            lines.append(f"| `{key}` | {desc} | {req} | `{default}` |")
        lines.append("")

    if outputs:
        lines.append("## Outputs\n")
        lines.append("| Output | Description |")
        lines.append("|--------|-------------|")
        for key, val in outputs.items():
            if not isinstance(val, dict):
                continue
            desc = str(val.get("description", "")).replace("\n", " ").strip()
            lines.append(f"| `{key}` | {desc} |")
        lines.append("")

    return "\n".join(lines)


def make_workflow_page(
    workflow_path: Path,
    actions_dir: Path,
    version: str,
    docs_out: Path | None = None,
) -> str:
    """Generate a documentation page for a reusable workflow."""
    workflow_name = workflow_path.stem
    wf = parse_workflow_full(workflow_path)

    lines = [f"# {wf['name']}\n"]

    if wf["description"]:
        lines.append(f"{wf['description']}\n")

    lines.append("```yaml")
    lines.append(
        f"uses: huntridge-labs/argus/.github/workflows/{workflow_name}.yml@{version}"
    )
    lines.append("```\n")

    # Interactive pipeline diagram
    has_matrix = any(j.get("has_matrix") for j in wf["jobs"].values())
    if has_matrix and docs_out:
        diagram = make_workflow_diagram(wf["jobs"], workflow_name, docs_out)
        if diagram:
            lines.append("## Pipeline\n")
            lines.append(diagram)
            lines.append("")

    _render_triggers(lines, wf)
    _render_permissions(lines, wf)
    _render_inputs(lines, wf)
    _render_secrets(lines, wf)
    _render_jobs(lines, wf, actions_dir)
    _render_used_actions_summary(lines, wf, actions_dir)

    return "\n".join(lines)


# ─── Section renderers (keep make_workflow_page readable) ────────────────────

def _render_triggers(lines: list[str], wf: dict) -> None:
    if not wf["triggers"]:
        return
    trigger_labels = {
        "workflow_call": "Reusable (called by other workflows)",
        "workflow_dispatch": "Manual dispatch",
        "push": "Push",
        "pull_request": "Pull request",
        "pull_request_target": "Pull request target",
        "schedule": "Scheduled",
    }
    lines.append("## Triggers\n")
    for t in wf["triggers"]:
        lines.append(f"- **{trigger_labels.get(t, t)}**")
    lines.append("")


def _render_permissions(lines: list[str], wf: dict) -> None:
    if not wf["permissions"]:
        return
    lines.append("## Permissions\n")
    lines.append("| Scope | Access |")
    lines.append("|-------|--------|")
    for scope, access in wf["permissions"].items():
        lines.append(f"| `{scope}` | `{access}` |")
    lines.append("")


def _render_inputs(lines: list[str], wf: dict) -> None:
    inputs = wf["inputs"]
    if not inputs:
        return
    lines.append("## Inputs\n")

    groups: dict[str, list] = {}
    general: list = []
    for key, val in inputs.items():
        if not isinstance(val, dict):
            continue
        desc = str(val.get("description", ""))
        desc_prefix_match = re.match(r"^(\w+):\s", desc)
        key_parts = key.split("_")
        key_prefix = key_parts[0] if len(key_parts) >= 2 else None

        if desc_prefix_match:
            group_key = desc_prefix_match.group(1).lower()
            groups.setdefault(group_key, []).append((key, val))
        elif key_prefix and key_prefix in (
            "codeql", "zap", "osv", "gitleaks", "bandit", "dependency",
        ):
            groups.setdefault(key_prefix, []).append((key, val))
        else:
            general.append((key, val))

    def render_input_table(items: list) -> None:
        lines.append("| Input | Description | Required | Default |")
        lines.append("|-------|-------------|----------|---------|")
        for key, val in items:
            desc = str(val.get("description", "")).replace("\n", " ").strip()
            desc = re.sub(r"^\w+:\s*", "", desc)
            if len(desc) > 120:
                desc = desc[:117] + "..."
            req = "Yes" if val.get("required") else "No"
            default = str(val.get("default", "")).strip() or "—"
            input_type = val.get("type", "")
            type_badge = f" *{input_type}*" if input_type else ""
            lines.append(f"| `{key}` | {desc}{type_badge} | {req} | `{default}` |")
        lines.append("")

    if general:
        render_input_table(general)
    for group_key, items in groups.items():
        label = config.GROUP_LABELS.get(group_key, group_key.upper())
        lines.append(f"### {label} Options\n")
        render_input_table(items)


def _render_secrets(lines: list[str], wf: dict) -> None:
    if not wf["secrets"]:
        return
    lines.append("## Secrets\n")
    lines.append("| Secret | Description | Required |")
    lines.append("|--------|-------------|----------|")
    for key, val in wf["secrets"].items():
        if not isinstance(val, dict):
            continue
        desc = str(val.get("description", "")).replace("\n", " ").strip()
        req = "Yes" if val.get("required") else "No"
        lines.append(f"| `{key}` | {desc} | {req} |")
    lines.append("")


def _render_jobs(lines: list[str], wf: dict, actions_dir: Path) -> None:
    if not wf["jobs"]:
        return
    lines.append("## Jobs\n")
    for job_id, job in wf["jobs"].items():
        lines.append(f"### `{job_id}` — {job['name']}\n")
        details: list[str] = []
        if job["runs_on"]:
            details.append(f"**Runs on:** `{job['runs_on']}`")
        if job["timeout"]:
            details.append(f"**Timeout:** {job['timeout']} minutes")
        if job["needs"]:
            needs = job["needs"] if isinstance(job["needs"], list) else [job["needs"]]
            details.append(f"**Depends on:** {', '.join(f'`{n}`' for n in needs)}")
        if job["continue_on_error"]:
            details.append("**Continue on error:** Yes")
        if job["condition"]:
            cond = str(job["condition"]).strip()
            if len(cond) < 100:
                details.append(f"**Condition:** `{cond}`")
        if details:
            lines.append(" · ".join(details) + "\n")

        if job["steps"]:
            lines.append("**Steps:**\n")
            for i, step in enumerate(job["steps"], 1):
                name = step["name"]
                if step["uses"]:
                    lines.append(f"{i}. {name} — `{step['uses']}`")
                else:
                    lines.append(f"{i}. {name}")
            lines.append("")

        visible_actions = [a for a in job["actions_used"] if a not in config.EXCLUDED_ACTIONS]
        if visible_actions:
            lines.append("**Actions used:**\n")
            for action_name in visible_actions:
                action_dir = actions_dir / action_name
                meta_a = (
                    parse_action_yml(action_dir / "action.yml")
                    if action_dir.exists() else {}
                )
                label = meta_a.get("name", action_name)
                cat = action_category(action_name, actions_dir)
                icon = category_icon(cat)
                lines.append(
                    f"- {icon} [`{action_name}`](../actions/{action_name}.md) — {label}"
                )
            lines.append("")


def _render_used_actions_summary(
    lines: list[str], wf: dict, actions_dir: Path,
) -> None:
    visible_used = [a for a in wf["used_actions"] if a not in config.EXCLUDED_ACTIONS]
    if not visible_used:
        return
    lines.append("## All Composite Actions Referenced\n")
    for action_name in visible_used:
        action_dir = actions_dir / action_name
        meta_a = (
            parse_action_yml(action_dir / "action.yml")
            if action_dir.exists() else {}
        )
        label = meta_a.get("name", action_name)
        cat = action_category(action_name, actions_dir)
        icon = category_icon(cat)
        lines.append(
            f"- {icon} [`{action_name}`](../actions/{action_name}.md) — {label}"
        )
    lines.append("")
