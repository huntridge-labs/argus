"""Workflow YAML parsing — extracts rich metadata from reusable workflows."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from .helpers import read


def parse_workflow_full(workflow_path: Path) -> dict:
    """Parse a workflow YAML into a rich metadata dict."""
    content = read(workflow_path)
    try:
        data = yaml.safe_load(content) or {}
    except Exception:
        data = {}

    # Extract header comments as description
    header_comments: list[str] = []
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            header_comments.append(stripped.lstrip("# ").strip())
        elif stripped and not stripped.startswith("---"):
            break

    # PyYAML parses 'on:' as boolean True, so check both keys
    on_block = data.get("on") or data.get(True) or {}
    workflow_call = on_block.get("workflow_call", {}) if isinstance(on_block, dict) else {}
    workflow_call = workflow_call or {}

    triggers = list(on_block.keys()) if isinstance(on_block, dict) else []

    # Extract action references
    action_pattern = r"uses:\s+huntridge-labs/argus/\.github/actions/([\w-]+)"
    used_actions = sorted(set(re.findall(action_pattern, content)))

    # Extract jobs
    jobs: dict[str, dict] = {}
    for job_id, job_data in (data.get("jobs") or {}).items():
        if not isinstance(job_data, dict):
            continue
        strategy = job_data.get("strategy") or {}
        has_matrix = bool(strategy.get("matrix"))

        job_info = {
            "name": job_data.get("name", job_id),
            "runs_on": job_data.get("runs-on", ""),
            "timeout": job_data.get("timeout-minutes"),
            "condition": job_data.get("if", ""),
            "needs": job_data.get("needs", []),
            "continue_on_error": job_data.get("continue-on-error", False),
            "has_matrix": has_matrix,
            "matrix_data": strategy.get("matrix", {}),
            "max_parallel": strategy.get("max-parallel"),
            "fail_fast": strategy.get("fail-fast", True),
        }

        steps = job_data.get("steps") or []
        job_info["steps"] = [
            {"name": s.get("name", ""), "uses": s.get("uses", "")}
            for s in steps if isinstance(s, dict) and s.get("name")
        ]
        job_info["actions_used"] = [
            re.search(r"\.github/actions/([\w-]+)", s.get("uses", "")).group(1)
            for s in steps if isinstance(s, dict)
            and s.get("uses", "").startswith("huntridge-labs/argus/")
            and re.search(r"\.github/actions/([\w-]+)", s.get("uses", ""))
        ]
        jobs[job_id] = job_info

    return {
        "name": data.get("name", workflow_path.stem),
        "description": "\n".join(header_comments) if header_comments else "",
        "triggers": triggers,
        "inputs": workflow_call.get("inputs") or {},
        "secrets": workflow_call.get("secrets") or {},
        "permissions": data.get("permissions") or {},
        "jobs": jobs,
        "used_actions": used_actions,
    }


def parse_workflow_meta(workflow_path: Path) -> dict:
    """Lightweight parse — just extract the workflow name."""
    try:
        data = yaml.safe_load(read(workflow_path)) or {}
        return {"name": data.get("name", workflow_path.stem)}
    except Exception:
        return {"name": workflow_path.stem}
