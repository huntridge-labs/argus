"""Architecture overview page: one overview diagram plus one per pipeline.

Reads ``data_flow.stages`` and ``data_flow.pipelines`` from
``.ai/architecture.yaml`` and writes ``architecture.md``, the first
page under "Architecture" in the docsite. The interactive map
(``architecture.py``) is the second page, for exploring.

Every diagram is generated from the YAML, so changing a pipeline means
editing ``.ai/architecture.yaml``, never this page.

Each pipeline step may carry a ``per`` value. Consecutive steps with
the same ``per`` are drawn inside one "For each <per>" box, which is
how the per-scanner and per-image loops show up.
"""

from __future__ import annotations

import html
from pathlib import Path
from typing import Any

import yaml

MAP_PAGE = "architecture-map.md"


class PipelineDataError(ValueError):
    """``data_flow`` in ``.ai/architecture.yaml`` is missing or malformed."""


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------


def load_data_flow(architecture: dict[str, Any]) -> tuple[list[dict], list[dict]]:
    """Return ``(stages, pipelines)`` after checking their shape.

    Raises:
        PipelineDataError: naming the first problem found, so a bad
            edit to the YAML fails the build with a clear message.
    """
    data_flow = architecture.get("data_flow")
    if not isinstance(data_flow, dict):
        raise PipelineDataError("data_flow is missing from .ai/architecture.yaml")

    stages = data_flow.get("stages")
    pipelines = data_flow.get("pipelines")
    if not isinstance(stages, list) or not stages:
        raise PipelineDataError("data_flow.stages must be a non-empty list")
    if not isinstance(pipelines, list) or not pipelines:
        raise PipelineDataError("data_flow.pipelines must be a non-empty list")

    _check_items(stages, "data_flow.stages", ("id", "label", "detail"))
    _check_items(
        pipelines, "data_flow.pipelines", ("id", "name", "entrypoint", "steps"),
    )
    for pipeline in pipelines:
        where = f"data_flow.pipelines[{pipeline['id']}].steps"
        if not isinstance(pipeline["steps"], list) or not pipeline["steps"]:
            raise PipelineDataError(f"{where} must be a non-empty list")
        _check_items(pipeline["steps"], where, ("id", "label", "detail"))
    return stages, pipelines


def _check_items(items: list, where: str, required: tuple[str, ...]) -> None:
    seen: set[str] = set()
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            raise PipelineDataError(f"{where}[{i}] must be a mapping")
        missing = [key for key in required if not item.get(key)]
        if missing:
            raise PipelineDataError(
                f"{where}[{i}] is missing {', '.join(missing)}"
            )
        if item["id"] in seen:
            raise PipelineDataError(f"{where} has a duplicate id: {item['id']}")
        seen.add(item["id"])


# --------------------------------------------------------------------------
# Mermaid
# --------------------------------------------------------------------------


def _mermaid_text(text: str) -> str:
    """Escape text for a quoted Mermaid label."""
    return (
        str(text)
        .replace('"', "#quot;")
        .replace("<", "#lt;")
        .replace(">", "#gt;")
    )


def _node_id(raw: str) -> str:
    return "n_" + "".join(c if c.isalnum() else "_" for c in raw)


def overview_mermaid(stages: list[dict[str, Any]]) -> str:
    """One left-to-right chain through every overview stage."""
    lines = ["flowchart LR"]
    for stage in stages:
        lines.append(f'    {_node_id(stage["id"])}["{_mermaid_text(stage["label"])}"]')
    ids = [_node_id(stage["id"]) for stage in stages]
    lines.append("    " + " --> ".join(ids))
    return "\n".join(lines)


def pipeline_mermaid(pipeline: dict[str, Any]) -> str:
    """A top-down chain of steps, with ``per`` runs grouped in a subgraph."""
    lines = ["flowchart TD"]
    entry = _node_id(f"{pipeline['id']}-entry")
    lines.append(f'    {entry}(["{_mermaid_text(pipeline["entrypoint"])}"])')

    group_index = 0
    current_per: str | None = None
    for step in pipeline["steps"]:
        per = step.get("per")
        if per != current_per:
            if current_per is not None:
                lines.append("    end")
            if per is not None:
                group_index += 1
                group = _node_id(f"{pipeline['id']}-loop-{group_index}")
                lines.append(
                    f'    subgraph {group}["For each {_mermaid_text(per)}"]'
                )
            current_per = per
        indent = "        " if per is not None else "    "
        node = _node_id(f"{pipeline['id']}-{step['id']}")
        lines.append(f'{indent}{node}["{_mermaid_text(step["label"])}"]')
    if current_per is not None:
        lines.append("    end")

    chain = [entry] + [
        _node_id(f"{pipeline['id']}-{step['id']}") for step in pipeline["steps"]
    ]
    lines.append("    " + " --> ".join(chain))
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Markdown
# --------------------------------------------------------------------------


def _table_cell(text: str) -> str:
    """One-line, HTML-escaped table cell (``<name>`` would vanish as a tag)."""
    flat = " ".join(str(text).split())
    return html.escape(flat, quote=False).replace("|", "\\|")


def render_overview_markdown(
    architecture: dict[str, Any],
    docs_root: Path,
    map_page: str | None = MAP_PAGE,
) -> Path:
    """Write ``docs_root/architecture.md`` and return its path.

    Args:
        architecture: Parsed ``.ai/architecture.yaml``.
        docs_root: The MkDocs ``docs/`` directory.
        map_page: The interactive map's page, linked from the overview.
            ``None`` when the map couldn't be built, so the overview
            doesn't link to a page that isn't there.
    """
    stages, pipelines = load_data_flow(architecture)

    out: list[str] = [
        "---",
        "title: Architecture",
        "---",
        "",
        "# Architecture",
        "",
        "<!-- Generated by scripts/docsite/pipelines.py from data_flow in "
        ".ai/architecture.yaml. Edit the YAML, not this page. -->",
        "",
        "Every way of running Argus ends the same way: scanners produce findings, "
        "reporters write them out, and everything downstream reads one file, "
        "`argus-results.json`.",
        "",
        "```mermaid",
        overview_mermaid(stages),
        "```",
        "",
        "| Stage | What happens |",
        "|---|---|",
    ]
    out += [
        f"| **{_table_cell(stage['label'])}** | {_table_cell(stage['detail'])} |"
        for stage in stages
    ]
    out.append("")
    if map_page:
        out += [
            "To see every component and how they connect, open the "
            f"[interactive map]({map_page}).",
            "",
        ]

    out += [
        "## Pipelines",
        "",
        "The same stages, step by step, for each way Argus runs.",
        "",
    ]
    for pipeline in pipelines:
        out += [f"### {pipeline['name']}", "", f"`{pipeline['entrypoint']}`", ""]
        adrs = pipeline.get("adrs") or []
        if adrs:
            out += [f"Decisions: {', '.join(adrs)}", ""]
        out += ["```mermaid", pipeline_mermaid(pipeline), "```", ""]
        out += [
            '??? info "Steps"',
            "",
            "    | Step | What happens |",
            "    |---|---|",
        ]
        for step in pipeline["steps"]:
            label = f"**{_table_cell(step['label'])}**"
            if step.get("per"):
                label += f"<br><small>for each {_table_cell(step['per'])}</small>"
            out.append(f"    | {label} | {_table_cell(step['detail'])} |")
        out.append("")

    path = Path(docs_root) / "architecture.md"
    path.write_text("\n".join(out), encoding="utf-8")
    return path


def render_overview_from_repo(
    repo_root: Path, docs_root: Path, map_page: str | None = MAP_PAGE,
) -> Path:
    """Load ``.ai/architecture.yaml`` from ``repo_root`` and render the overview."""
    arch_path = Path(repo_root) / ".ai" / "architecture.yaml"
    with arch_path.open(encoding="utf-8") as fh:
        architecture = yaml.safe_load(fh) or {}
    return render_overview_markdown(architecture, docs_root, map_page=map_page)
