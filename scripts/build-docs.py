#!/usr/bin/env python3
"""
Argus Documentation Builder
Generates a full MkDocs site from the repo structure.

Usage:
    python scripts/build-docs.py [--repo-root PATH] [--output-dir PATH]
    mkdocs serve   # preview
    mkdocs build   # static output
"""

import argparse
import re
import shutil
import sys
from pathlib import Path

import yaml


# ─── Helpers ──────────────────────────────────────────────────────────────────

def read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def parse_action_yml(path: Path) -> dict:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        data = {}
    return data


def get_version(repo_root: Path) -> str:
    raw = read(repo_root / "version.yaml").strip()
    return raw.split()[0] if raw else "latest"


# ─── Category classification ──────────────────────────────────────────────────

# Excluded from docs — internal plumbing, not hardening products
EXCLUDED_ACTIONS = {"comment-pr", "get-job-id"}
EXCLUDED_WORKFLOWS = {
    "release", "release-preview", "dependabot-auto-merge", "aicac",
    "docs", "security-reusable-demo",
}
# Guides subdirectories to exclude — internal project logistics, not user-facing
EXCLUDED_GUIDE_DIRS = {"developer"}

SCANNER_CATEGORIES = {
    "sast": ["scanner-bandit", "scanner-codeql", "scanner-opengrep"],
    "secrets": ["scanner-gitleaks"],
    "container": ["parse-container-config", "scanner-container", "scanner-container-summary", "scanner-syft"],
    "dependency": ["scanner-osv", "scanner-dependency-review"],
    "iac": ["scanner-trivy-iac", "scanner-checkov"],
    "compliance": ["scn-detector"],
    "malware": ["scanner-clamav"],
    "dast": ["parse-zap-config", "scanner-zap", "scanner-zap-summary"],
    "linting": [
        "linter-dockerfile", "linter-javascript", "linter-json",
        "linter-python", "linter-terraform", "linter-yaml", "linting-summary",
    ],
    "utility": [
        "security-summary",
    ],
}

CATEGORY_LABELS = {
    "sast": "SAST",
    "secrets": "Secrets Detection",
    "container": "Container Security",
    "dependency": "Dependency Scanning",
    "iac": "Infrastructure Security",
    "compliance": "Compliance & Change Control",
    "malware": "Malware Detection",
    "dast": "DAST",
    "linting": "Code Quality & Linting",
    "utility": "Utility & Reporting",
}

CATEGORY_ICONS = {
    "sast": "🔍",
    "secrets": "🔑",
    "container": "📦",
    "dependency": "🔗",
    "iac": "🏗️",
    "compliance": "📋",
    "malware": "🛡️",
    "dast": "🕷️",
    "linting": "✅",
    "utility": "⚙️",
}


GITHUB_BLOB = "https://github.com/huntridge-labs/argus/blob/main"


def rewrite_repo_links(content: str, source_rel: str) -> str:
    """Rewrite relative markdown links to absolute GitHub URLs.

    Action READMEs contain links like ``../../CHANGELOG.md`` which resolve
    within the repo but break inside the generated docs tree. This function
    resolves each relative link against *source_rel* (the file's path inside
    the repo, e.g. ``.github/actions/scanner-container/README.md``) and, if
    it escapes the docs tree, rewrites it to a GitHub blob URL.
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
        parts = []
        for p in resolved.split("/"):
            if p == "..":
                if parts:
                    parts.pop()
            elif p and p != ".":
                parts.append(p)
        clean = "/".join(parts)

        return f"{prefix}{GITHUB_BLOB}/{clean}{anchor}{suffix}"

    return re.sub(r'(\[[^\]]*\]\()([^)\s]+)(\))', _rewrite, content)


def action_category(action_name: str) -> str:
    for cat, members in SCANNER_CATEGORIES.items():
        if action_name in members:
            return cat
    return "utility"


# ─── Workflow parsing ─────────────────────────────────────────────────────────

def parse_workflow_full(workflow_path: Path) -> dict:
    """Parse a workflow YAML into a rich metadata dict."""
    content = read(workflow_path)
    try:
        data = yaml.safe_load(content) or {}
    except Exception:
        data = {}

    # Extract header comments as description
    header_comments = []
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

    # Extract triggers
    triggers = list(on_block.keys()) if isinstance(on_block, dict) else []

    # Extract action references
    action_pattern = r"uses:\s+huntridge-labs/argus/\.github/actions/([\w-]+)"
    used_actions = sorted(set(re.findall(action_pattern, content)))

    # Extract jobs
    jobs = {}
    for job_id, job_data in (data.get("jobs") or {}).items():
        if not isinstance(job_data, dict):
            continue
        strategy = job_data.get("strategy") or {}
        has_matrix = bool(strategy.get("matrix"))
        matrix_data = strategy.get("matrix", {})
        # Detect max-parallel for display
        max_parallel = strategy.get("max-parallel")
        fail_fast = strategy.get("fail-fast", True)

        job_info = {
            "name": job_data.get("name", job_id),
            "runs_on": job_data.get("runs-on", ""),
            "timeout": job_data.get("timeout-minutes"),
            "condition": job_data.get("if", ""),
            "needs": job_data.get("needs", []),
            "continue_on_error": job_data.get("continue-on-error", False),
            "has_matrix": has_matrix,
            "matrix_data": matrix_data,
            "max_parallel": max_parallel,
            "fail_fast": fail_fast,
        }
        # Extract steps summary
        steps = job_data.get("steps") or []
        job_info["steps"] = [
            {
                "name": s.get("name", ""),
                "uses": s.get("uses", ""),
            }
            for s in steps if isinstance(s, dict) and s.get("name")
        ]
        # Extract actions used in this job
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
    try:
        data = yaml.safe_load(read(workflow_path)) or {}
        return {"name": data.get("name", workflow_path.stem)}
    except Exception:
        return {"name": workflow_path.stem}


# ─── Diagram generation ───────────────────────────────────────────────────────

def _get_needs(job: dict) -> list:
    needs = job.get("needs", [])
    return [needs] if isinstance(needs, str) else list(needs)


def make_workflow_diagram(jobs: dict, workflow_name: str, docs_out: Path) -> str:
    """Generate an interactive zoomable pipeline diagram as a standalone HTML page.

    Returns markdown with an iframe embed. The HTML page uses Mermaid.js with
    svg-pan-zoom for mouse/touch zoom and pan — similar to GitHub's Actions view.
    """
    if len(jobs) < 2:
        return ""

    def nid(job_id: str) -> str:
        return job_id.replace("-", "_")

    def node_def(job_id: str, job: dict, is_fan_in: bool) -> str:
        label = job["name"]
        n = nid(job_id)
        if job.get("has_matrix"):
            # Count matrix dimensions to show potential parallelism
            matrix = job.get("matrix_data", {})
            dim_counts = [
                len(v) for k, v in matrix.items()
                if isinstance(v, list) and k not in ("include", "exclude")
            ] if isinstance(matrix, dict) else []
            parallel = 1
            for c in dim_counts:
                parallel *= c
            mp_parts = []
            if parallel > 1:
                mp_parts.append(f"{parallel} parallel")
            elif job.get("max_parallel"):
                mp_parts.append(f"max {job['max_parallel']}")
            mp_label = f" · {' · '.join(mp_parts)}" if mp_parts else ""
            return f'{n}(["{label}\\n⟐ matrix{mp_label}"])'
        if is_fan_in:
            return f'{n}[["{label}"]]'
        return f'{n}["{label}"]'

    fan_in = {jid for jid, j in jobs.items() if len(_get_needs(j)) >= 3}
    roots = [jid for jid in jobs if not _get_needs(jobs[jid])]
    has_matrix_jobs = any(j.get("has_matrix") for j in jobs.values())
    has_summary_jobs = bool(fan_in)
    # "Scanner" = jobs that are neither root, matrix, nor fan-in
    has_scanner_jobs = any(
        jid not in roots and jid not in fan_in and not jobs[jid].get("has_matrix")
        for jid in jobs
    )

    # Build Mermaid definition
    mermaid_lines = ["flowchart LR"]
    for jid, job in jobs.items():
        mermaid_lines.append(f"    {node_def(jid, job, jid in fan_in)}")
    mermaid_lines.append("")
    for jid, j in jobs.items():
        for dep in _get_needs(j):
            if dep in jobs:
                mermaid_lines.append(f"    {nid(dep)} --> {nid(jid)}")
    mermaid_lines.append("")

    matrix_ids = [nid(jid) for jid, j in jobs.items() if j.get("has_matrix")]
    if matrix_ids:
        mermaid_lines.append("    classDef matrix fill:#4a148c,stroke:#7c43bd,color:#fff,stroke-width:2px")
        mermaid_lines.append(f"    class {','.join(matrix_ids)} matrix")
    fan_in_ids = [nid(jid) for jid in fan_in]
    if fan_in_ids:
        mermaid_lines.append("    classDef summary fill:#1b5e20,stroke:#4caf50,color:#fff,stroke-width:2px")
        mermaid_lines.append(f"    class {','.join(fan_in_ids)} summary")
    if roots:
        root_ids = [nid(r) for r in roots]
        mermaid_lines.append("    classDef coordinator fill:#0d47a1,stroke:#42a5f5,color:#fff,stroke-width:2px")
        mermaid_lines.append(f"    class {','.join(root_ids)} coordinator")

    mermaid_def = "\n".join(mermaid_lines)

    # Build dynamic legend entries based on what's actually in the diagram
    has_coordinator = bool(roots)
    legend_entries = []
    if has_coordinator:
        legend_entries.append('<span class="legend-dot" style="background:#42a5f5"></span>Coordinator')
    if has_matrix_jobs:
        legend_entries.append('<span class="legend-dot" style="background:#7c43bd"></span>Matrix job')
    if has_summary_jobs:
        legend_entries.append('<span class="legend-dot" style="background:#4caf50"></span>Summary')
    if has_scanner_jobs:
        legend_entries.append('<span class="legend-dot" style="background:#555"></span>Scanner')
    legend_html = "<br>\n  ".join(legend_entries)

    # Generate standalone HTML with pan/zoom
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ background: #1a1a2e; overflow: hidden; font-family: sans-serif; }}
  #container {{
    width: 100vw; height: 100vh;
    overflow: hidden; position: relative; cursor: grab;
  }}
  #container.grabbing {{ cursor: grabbing; }}
  #diagram {{ transform-origin: 0 0; position: absolute; }}
  #controls {{
    position: fixed; bottom: 12px; right: 12px; display: flex; gap: 6px; z-index: 10;
  }}
  #controls button {{
    background: #2d2d44; color: #ccc; border: 1px solid #555;
    border-radius: 4px; padding: 6px 12px; cursor: pointer; font-size: 14px;
  }}
  #controls button:hover {{ background: #3d3d54; }}
  #legend {{
    position: fixed; top: 12px; left: 12px; z-index: 10;
    background: #2d2d44; border: 1px solid #555; border-radius: 6px;
    padding: 10px 14px; color: #ccc; font-size: 12px; line-height: 1.8;
  }}
  .legend-dot {{
    display: inline-block; width: 10px; height: 10px;
    border-radius: 2px; margin-right: 6px; vertical-align: middle;
  }}
</style>
</head>
<body>
<div id="legend">
  {legend_html}
</div>
<div id="controls">
  <button onclick="zoomBy(1.3)">+</button>
  <button onclick="zoomBy(0.7)">&minus;</button>
  <button onclick="resetView()">Fit</button>
</div>
<div id="container">
  <div id="diagram">
    <pre class="mermaid">
{mermaid_def}
    </pre>
  </div>
</div>
<script src="https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.min.js"></script>
<script>
  mermaid.initialize({{ startOnLoad: true, theme: 'dark', flowchart: {{ useMaxWidth: false }} }});

  let scale = 1, tx = 0, ty = 0, dragging = false, sx, sy;
  const container = document.getElementById('container');
  const diagram = document.getElementById('diagram');

  function apply() {{ diagram.style.transform = `translate(${{tx}}px,${{ty}}px) scale(${{scale}})`; }}
  function zoomBy(f) {{ scale *= f; apply(); }}
  function resetView() {{
    const svg = diagram.querySelector('svg');
    if (!svg) return;
    const cw = container.clientWidth, ch = container.clientHeight;
    const sw = svg.scrollWidth, sh = svg.scrollHeight;
    scale = Math.min(cw / sw, ch / sh) * 0.9;
    tx = (cw - sw * scale) / 2;
    ty = (ch - sh * scale) / 2;
    apply();
  }}

  container.addEventListener('wheel', e => {{
    e.preventDefault();
    const f = e.deltaY < 0 ? 1.1 : 0.9;
    const rect = container.getBoundingClientRect();
    const mx = e.clientX - rect.left, my = e.clientY - rect.top;
    tx = mx - (mx - tx) * f;
    ty = my - (my - ty) * f;
    scale *= f;
    apply();
  }}, {{ passive: false }});

  container.addEventListener('mousedown', e => {{ dragging = true; sx = e.clientX - tx; sy = e.clientY - ty; container.classList.add('grabbing'); }});
  window.addEventListener('mousemove', e => {{ if (dragging) {{ tx = e.clientX - sx; ty = e.clientY - sy; apply(); }} }});
  window.addEventListener('mouseup', () => {{ dragging = false; container.classList.remove('grabbing'); }});

  // After Mermaid renders, add stacked-card effect to matrix nodes
  setTimeout(() => {{
    document.querySelectorAll('.node.matrix').forEach(node => {{
      const rect = node.querySelector('rect, .label-container');
      if (!rect) return;
      // Clone two shadow copies behind the node to create a "stack" effect
      for (let i = 2; i >= 1; i--) {{
        const shadow = rect.cloneNode(true);
        shadow.setAttribute('transform', `translate(${{i * 4}}, ${{i * 4}})`);
        shadow.style.opacity = 1 - i * 0.3;
        node.insertBefore(shadow, node.firstChild);
      }}
    }});
  }}, 400);

  // Auto-fit after render
  setTimeout(resetView, 500);
</script>
</body>
</html>"""

    # Write HTML file into assets (served as static files by MkDocs)
    diagrams_dir = docs_out / "assets" / "diagrams"
    diagrams_dir.mkdir(parents=True, exist_ok=True)
    html_filename = f"{workflow_name}.html"
    (diagrams_dir / html_filename).write_text(html, encoding="utf-8")

    # Return iframe embed markdown
    job_count = len(jobs)
    matrix_count = sum(1 for j in jobs.values() if j.get("has_matrix"))
    caption = f"{job_count} jobs"
    if matrix_count:
        caption += f" ({matrix_count} matrix)"
    caption += " · scroll to zoom · drag to pan"

    return (
        f'<iframe src="../../assets/diagrams/{html_filename}" '
        f'style="width:100%;height:500px;border:1px solid #333;border-radius:8px;" '
        f'loading="lazy"></iframe>\n\n'
        f'*{caption}*'
    )


# ─── Page generators ──────────────────────────────────────────────────────────

def make_action_page(action_dir: Path, version: str) -> str:
    action_name = action_dir.name
    meta = parse_action_yml(action_dir / "action.yml")
    readme = read(action_dir / "README.md")

    name = meta.get("name", action_name)
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


def make_workflow_page(workflow_path: Path, actions_dir: Path, version: str, docs_out: Path = None) -> str:
    workflow_name = workflow_path.stem
    wf = parse_workflow_full(workflow_path)

    lines = [f"# {wf['name']}\n"]

    # Description from header comments
    if wf["description"]:
        lines.append(f"{wf['description']}\n")

    lines.append("```yaml")
    lines.append(f"uses: huntridge-labs/argus/.github/workflows/{workflow_name}.yml@{version}")
    lines.append("```\n")

    # Interactive pipeline diagram (only for workflows with matrix jobs)
    has_matrix = any(j.get("has_matrix") for j in wf["jobs"].values())
    if has_matrix and docs_out:
        diagram = make_workflow_diagram(wf["jobs"], workflow_name, docs_out)
        if diagram:
            lines.append("## Pipeline\n")
            lines.append(diagram)
            lines.append("")

    # Triggers
    if wf["triggers"]:
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

    # Permissions
    if wf["permissions"]:
        lines.append("## Permissions\n")
        lines.append("| Scope | Access |")
        lines.append("|-------|--------|")
        for scope, access in wf["permissions"].items():
            lines.append(f"| `{scope}` | `{access}` |")
        lines.append("")

    # Inputs — group by description prefix (e.g. "ZAP:", "OSV:") or key prefix
    inputs = wf["inputs"]
    if inputs:
        lines.append("## Inputs\n")

        # Detect natural groups from description prefixes like "ZAP:", "OSV:"
        # or from key prefixes like zap_*, osv_*, codeql_*
        groups = {}
        general = []
        for key, val in inputs.items():
            if not isinstance(val, dict):
                continue
            desc = str(val.get("description", ""))
            # Check for "PREFIX:" pattern in description
            desc_prefix_match = re.match(r"^(\w+):\s", desc)
            # Check for key prefix with 2+ parts
            key_parts = key.split("_")
            key_prefix = key_parts[0] if len(key_parts) >= 2 else None

            if desc_prefix_match:
                group_key = desc_prefix_match.group(1).lower()
                groups.setdefault(group_key, []).append((key, val))
            elif key_prefix and key_prefix in ("codeql", "zap", "osv", "gitleaks", "bandit", "dependency"):
                groups.setdefault(key_prefix, []).append((key, val))
            else:
                general.append((key, val))

        def render_input_table(items):
            lines.append("| Input | Description | Required | Default |")
            lines.append("|-------|-------------|----------|---------|")
            for key, val in items:
                desc = str(val.get("description", "")).replace("\n", " ").strip()
                # Strip "PREFIX: " from description since it's in the heading
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

        GROUP_LABELS = {
            "codeql": "CodeQL",
            "zap": "ZAP (DAST)",
            "osv": "OSV (Dependency)",
            "gitleaks": "Gitleaks",
            "bandit": "Bandit",
            "dependency": "Dependency Review",
        }
        for group_key, items in groups.items():
            label = GROUP_LABELS.get(group_key, group_key.upper())
            lines.append(f"### {label} Options\n")
            render_input_table(items)

    # Secrets
    if wf["secrets"]:
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

    # Jobs
    if wf["jobs"]:
        lines.append("## Jobs\n")
        for job_id, job in wf["jobs"].items():
            lines.append(f"### `{job_id}` — {job['name']}\n")
            details = []
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

            # Steps
            if job["steps"]:
                lines.append("**Steps:**\n")
                for i, step in enumerate(job["steps"], 1):
                    name = step["name"]
                    if step["uses"]:
                        lines.append(f"{i}. {name} — `{step['uses']}`")
                    else:
                        lines.append(f"{i}. {name}")
                lines.append("")

            # Actions cross-links (skip excluded actions)
            visible_actions = [a for a in job["actions_used"] if a not in EXCLUDED_ACTIONS]
            if visible_actions:
                lines.append("**Actions used:**\n")
                for action_name in visible_actions:
                    action_dir = actions_dir / action_name
                    meta_a = parse_action_yml(action_dir / "action.yml") if action_dir.exists() else {}
                    label = meta_a.get("name", action_name)
                    cat = action_category(action_name)
                    icon = CATEGORY_ICONS.get(cat, "•")
                    lines.append(f"- {icon} [`{action_name}`](../actions/{action_name}.md) — {label}")
                lines.append("")

    # Summary of all actions used (skip excluded actions)
    visible_used = [a for a in wf["used_actions"] if a not in EXCLUDED_ACTIONS]
    if visible_used:
        lines.append("## All Composite Actions Referenced\n")
        for action_name in visible_used:
            action_dir = actions_dir / action_name
            meta_a = parse_action_yml(action_dir / "action.yml") if action_dir.exists() else {}
            label = meta_a.get("name", action_name)
            cat = action_category(action_name)
            icon = CATEGORY_ICONS.get(cat, "•")
            lines.append(f"- {icon} [`{action_name}`](../actions/{action_name}.md) — {label}")
        lines.append("")

    return "\n".join(lines)


def make_actions_index(actions_dir: Path, version: str) -> str:
    lines = [
        "# Composite Actions\n",
        "All Argus scanner and utility actions. Each is self-contained and usable independently.\n",
    ]
    for cat, members in SCANNER_CATEGORIES.items():
        icon = CATEGORY_ICONS[cat]
        label = CATEGORY_LABELS[cat]
        rows = []
        for action_name in members:
            action_dir = actions_dir / action_name
            if not action_dir.exists():
                continue
            meta = parse_action_yml(action_dir / "action.yml")
            name = meta.get("name", action_name)
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
        and p.stem not in EXCLUDED_WORKFLOWS
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
    readme = read(repo_root / "README.md")
    if not readme:
        return f"# Argus\n\nOSS-first GitHub Actions security hardening — Huntridge Labs. Version `{version}`.\n"
    # Add markdown attribute to div tags so md_in_html processes badges
    readme = re.sub(r'<div\b([^>]*)>', r'<div markdown\1>', readme)
    # Rewrite local image paths to assets/
    readme = readme.replace('img/', 'assets/')
    # Rewrite relative links to GitHub blob URLs
    readme = rewrite_repo_links(readme, "README.md")
    return readme


# ─── MkDocs config ────────────────────────────────────────────────────────────

def build_mkdocs_config(version: str, nav: list) -> str:
    config = {
        "site_name": "Argus Docs",
        "site_description": "OSS-first GitHub Actions security hardening — Huntridge Labs",
        "site_url": "https://huntridge-labs.github.io/argus/",
        "repo_url": "https://github.com/huntridge-labs/argus",
        "repo_name": "huntridge-labs/argus",
        "edit_uri": "edit/main/docs/",
        "theme": {
            "name": "material",
            "logo": "assets/HL.png",
            "favicon": "assets/argus-no-bg.png",
            "palette": [
                {
                    "media": "(prefers-color-scheme: light)",
                    "scheme": "default",
                    "primary": "black",
                    "accent": "deep orange",
                    "toggle": {"icon": "material/weather-night", "name": "Switch to dark mode"},
                },
                {
                    "media": "(prefers-color-scheme: dark)",
                    "scheme": "slate",
                    "primary": "black",
                    "accent": "deep orange",
                    "toggle": {"icon": "material/weather-sunny", "name": "Switch to light mode"},
                },
            ],
            "features": [
                "navigation.instant",
                "navigation.tabs",
                "navigation.tabs.sticky",
                "navigation.sections",
                "navigation.expand",
                "navigation.path",
                "navigation.top",
                "search.suggest",
                "search.highlight",
                "content.code.copy",
                "content.code.annotate",
                "toc.follow",
            ],
            "font": {"text": "Inter", "code": "JetBrains Mono"},
        },
        "plugins": ["search"],
        "markdown_extensions": [
            "admonition",
            "pymdownx.details",
            "pymdownx.superfences",
            "pymdownx.highlight",
            "pymdownx.inlinehilite",
            "pymdownx.tabbed",
            "pymdownx.snippets",
            "attr_list",
            "md_in_html",
            "tables",
            "toc",
        ],
        "extra": {
            "version": {"provider": "mike", "default": "latest"},
            "social": [
                {"icon": "fontawesome/brands/github", "link": "https://github.com/huntridge-labs/argus"},
            ],
        },
        "extra_css": ["assets/custom.css"],
        "nav": nav,
    }
    output = yaml.dump(config, default_flow_style=False, allow_unicode=True, sort_keys=False)
    # Replace pymdownx.superfences with custom_fences config for Mermaid
    # PyYAML can't serialize !!python/name: tags, so we do it via string replacement
    output = output.replace(
        "- pymdownx.superfences\n",
        "- pymdownx.superfences:\n"
        "    custom_fences:\n"
        "      - name: mermaid\n"
        "        class: mermaid\n"
        "        format: !!python/name:pymdownx.superfences.fence_code_format\n",
    )
    return output


# ─── GitHub Pages deploy workflow ─────────────────────────────────────────────

DEPLOY_WORKFLOW = """\
name: Deploy Docs

on:
  push:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: write

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        with:
          fetch-depth: 0

      - uses: actions/setup-python@v6
        with:
          python-version: '3.12'

      - name: Install dependencies
        run: pip install mkdocs mkdocs-material pyyaml

      - name: Build docs
        run: python scripts/build-docs.py --output-dir /tmp/argus-docs

      - name: Deploy to GitHub Pages
        run: |
          cd /tmp/argus-docs
          mkdocs gh-deploy --force --remote-branch gh-pages
"""


# ─── Main build ───────────────────────────────────────────────────────────────

def build(repo_root: Path, output_dir: Path) -> None:
    version = get_version(repo_root)
    actions_dir = repo_root / ".github" / "actions"
    workflows_dir = repo_root / ".github" / "workflows"
    docs_out = output_dir / "docs"

    print(f"🔨 Building Argus docs v{version}")
    print(f"   Repo:   {repo_root}")
    print(f"   Output: {output_dir}")

    if docs_out.exists():
        shutil.rmtree(docs_out)
    docs_out.mkdir(parents=True)

    # Assets
    assets_dir = docs_out / "assets"
    assets_dir.mkdir()

    # Custom CSS — slogan under site name (first topic only, not page title)
    write(assets_dir / "custom.css", (
        ".md-header__topic {\n"
        "  height: 48px;\n"
        "  display: flex;\n"
        "  align-items: center;\n"
        "}\n"
        ".md-header__topic:first-child .md-ellipsis {\n"
        "  display: flex;\n"
        "  flex-direction: column;\n"
        "  line-height: 1.2;\n"
        "}\n"
        ".md-header__topic:first-child .md-ellipsis::after {\n"
        '  content: "Perception is Protection";\n'
        "  font-size: 0.55em;\n"
        "  opacity: 0.6;\n"
        "  font-weight: 400;\n"
        "  letter-spacing: 0.05em;\n"
        "}\n"
    ))

    # Copy repo images into assets (for README badge/logo references)
    img_dir = repo_root / "img"
    if img_dir.exists():
        for img_file in img_dir.iterdir():
            if img_file.is_file():
                shutil.copy2(img_file, assets_dir / img_file.name)

    # Core pages
    write(docs_out / "index.md", make_home(repo_root, version))

    quick_start = read(repo_root / "QUICK-START.md")
    if quick_start:
        write(docs_out / "quick-start.md", quick_start)

    changelog = read(repo_root / "CHANGELOG.md")
    if changelog:
        write(docs_out / "changelog.md", changelog)

    for fname in ("CONTRIBUTING.md", "SECURITY.md", "CODE_OF_CONDUCT.md"):
        content = read(repo_root / fname)
        if content:
            write(docs_out / fname.lower(), content)

    # Existing docs/ pages
    existing_docs_dir = repo_root / "docs"
    extra_pages = {}
    if existing_docs_dir.exists():
        for md_file in existing_docs_dir.rglob("*.md"):
            rel = md_file.relative_to(existing_docs_dir)
            # Skip internal logistics directories
            if rel.parts[0] in EXCLUDED_GUIDE_DIRS:
                continue
            content = read(md_file)
            source_rel = f"docs/{rel}"
            content = rewrite_repo_links(content, source_rel)
            write(docs_out / "guides" / rel, content)
            extra_pages[str(rel)] = f"guides/{rel}"

    # Actions (exclude internal plumbing)
    actions_out = docs_out / "actions"
    write(actions_out / "index.md", make_actions_index(actions_dir, version))
    all_action_dirs = sorted([
        d for d in actions_dir.iterdir()
        if d.is_dir() and d.name not in EXCLUDED_ACTIONS
    ])
    for action_dir in all_action_dirs:
        write(actions_out / f"{action_dir.name}.md", make_action_page(action_dir, version))
    print(f"   ✅ Generated {len(all_action_dirs)} action pages")

    # Workflows (exclude internal/non-hardening)
    workflows_out = docs_out / "workflows"
    write(workflows_out / "index.md", make_workflows_index(workflows_dir, version))
    public_workflows = [
        p for p in sorted(workflows_dir.glob("*.yml"))
        if not p.stem.startswith("test-")
        and p.stem not in EXCLUDED_WORKFLOWS
    ]
    for wf in public_workflows:
        write(workflows_out / f"{wf.stem}.md", make_workflow_page(wf, actions_dir, version, docs_out))
    print(f"   ✅ Generated {len(public_workflows)} workflow pages")

    # Examples
    examples_dir = repo_root / "examples"
    examples_out = docs_out / "examples"
    if examples_dir.exists():
        examples_readme = read(examples_dir / "README.md")
        if examples_readme:
            examples_readme = rewrite_repo_links(examples_readme, "examples/README.md")
        write(examples_out / "index.md", examples_readme or "# Examples\n")
        for yml_file in sorted(examples_dir.rglob("*.yml")):
            rel = yml_file.relative_to(examples_dir)
            content = read(yml_file)
            page = f"# `{yml_file.name}`\n\n```yaml\n{content}\n```\n"
            write(examples_out / str(rel).replace(".yml", ".md"), page)

    # Nav
    actions_nav = [{"Overview": "actions/index.md"}]
    for cat, members in SCANNER_CATEGORIES.items():
        icon = CATEGORY_ICONS[cat]
        label = CATEGORY_LABELS[cat]
        cat_entries = []
        for action_name in members:
            if (actions_dir / action_name).exists():
                meta = parse_action_yml(actions_dir / action_name / "action.yml")
                display = meta.get("name", action_name)
                cat_entries.append({display: f"actions/{action_name}.md"})
        if cat_entries:
            actions_nav.append({f"{icon} {label}": cat_entries})

    main_wf = workflows_dir / "reusable-security-hardening.yml"
    scanner_wfs_nav = [
        {parse_workflow_meta(p)["name"]: f"workflows/{p.stem}.md"}
        for p in sorted(workflows_dir.glob("scanner-*.yml"))
    ]
    other_wfs_nav = [
        {parse_workflow_meta(p)["name"]: f"workflows/{p.stem}.md"}
        for p in sorted(workflows_dir.glob("*.yml"))
        if p != main_wf
        and not p.stem.startswith("scanner-")
        and not p.stem.startswith("test-")
        and p.stem not in EXCLUDED_WORKFLOWS
    ]
    workflows_nav = [
        {"Overview": "workflows/index.md"},
        {"Reusable Security Hardening": "workflows/reusable-security-hardening.md"},
    ]
    if scanner_wfs_nav:
        workflows_nav.append({"Individual Scanners": scanner_wfs_nav})
    if other_wfs_nav:
        workflows_nav.append({"Utility Workflows": other_wfs_nav})

    guides_nav = [
        {Path(k).stem.replace("-", " ").title(): v}
        for k, v in sorted(extra_pages.items())
    ]

    nav = [
        {"Home": "index.md"},
        {"Quick Start": "quick-start.md"},
        {"Actions": actions_nav},
        {"Workflows": workflows_nav},
        {"Changelog": "changelog.md"},
    ]
    if guides_nav:
        nav.insert(4, {"Guides": guides_nav})
    if (examples_out / "index.md").exists():
        nav.insert(-1, {"Examples": "examples/index.md"})

    write(output_dir / "mkdocs.yml", build_mkdocs_config(version, nav))
    print(f"   ✅ mkdocs.yml written")
    print(f"\n✨ Done!\n")
    print(f"   cd {output_dir} && mkdocs serve\n")


def main():
    parser = argparse.ArgumentParser(description="Build Argus docs site")
    parser.add_argument(
        "--repo-root",
        default=str(Path(__file__).resolve().parent.parent),
        help="Path to Argus repo root (default: parent of scripts/)",
    )
    parser.add_argument(
        "--output-dir",
        default=str(Path(__file__).resolve().parent.parent / "site-build"),
        help="Output directory for mkdocs project (default: <repo>/site-build)",
    )
    parser.add_argument(
        "--write-deploy-workflow",
        action="store_true",
        help="Write .github/workflows/docs.yml for GitHub Pages auto-deploy",
    )
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    output_dir = Path(args.output_dir).resolve()

    if not (repo_root / ".github").exists():
        print(f"❌ {repo_root} doesn't look like the Argus repo (.github not found)")
        sys.exit(1)

    build(repo_root, output_dir)

    if args.write_deploy_workflow:
        dest = repo_root / ".github" / "workflows" / "docs.yml"
        if not dest.exists():
            write(dest, DEPLOY_WORKFLOW)
            print(f"   ✅ Created .github/workflows/docs.yml")


if __name__ == "__main__":
    main()
