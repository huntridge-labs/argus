"""Interactive Mermaid workflow diagrams with pan/zoom."""

from __future__ import annotations

from pathlib import Path


def _get_needs(job: dict) -> list[str]:
    needs = job.get("needs", [])
    return [needs] if isinstance(needs, str) else list(needs)


def _nid(job_id: str) -> str:
    return job_id.replace("-", "_")


def _node_def(job_id: str, job: dict, is_fan_in: bool) -> str:
    label = job["name"]
    n = _nid(job_id)
    if job.get("has_matrix"):
        matrix = job.get("matrix_data", {})
        dim_counts = [
            len(v) for k, v in matrix.items()
            if isinstance(v, list) and k not in ("include", "exclude")
        ] if isinstance(matrix, dict) else []
        parallel = 1
        for c in dim_counts:
            parallel *= c
        mp_parts: list[str] = []
        if parallel > 1:
            mp_parts.append(f"{parallel} parallel")
        elif job.get("max_parallel"):
            mp_parts.append(f"max {job['max_parallel']}")
        mp_label = f" · {' · '.join(mp_parts)}" if mp_parts else ""
        return f'{n}(["{label}\\n⟐ matrix{mp_label}"])'
    if is_fan_in:
        return f'{n}[["{label}"]]'
    return f'{n}["{label}"]'


def make_workflow_diagram(
    jobs: dict,
    workflow_name: str,
    docs_out: Path,
) -> str:
    """Generate an interactive pipeline diagram as a standalone HTML page.

    Returns markdown with an iframe embed.  The HTML page uses Mermaid.js
    with mouse/touch zoom and pan — similar to GitHub's Actions view.
    """
    if len(jobs) < 2:
        return ""

    fan_in = {jid for jid, j in jobs.items() if len(_get_needs(j)) >= 3}
    roots = [jid for jid in jobs if not _get_needs(jobs[jid])]
    has_matrix_jobs = any(j.get("has_matrix") for j in jobs.values())
    has_summary_jobs = bool(fan_in)
    has_scanner_jobs = any(
        jid not in roots and jid not in fan_in and not jobs[jid].get("has_matrix")
        for jid in jobs
    )

    # Mermaid definition
    mermaid_lines = ["flowchart LR"]
    for jid, job in jobs.items():
        mermaid_lines.append(f"    {_node_def(jid, job, jid in fan_in)}")
    mermaid_lines.append("")
    for jid, j in jobs.items():
        for dep in _get_needs(j):
            if dep in jobs:
                mermaid_lines.append(f"    {_nid(dep)} --> {_nid(jid)}")
    mermaid_lines.append("")

    matrix_ids = [_nid(jid) for jid, j in jobs.items() if j.get("has_matrix")]
    if matrix_ids:
        mermaid_lines.append(
            "    classDef matrix fill:#4a148c,stroke:#7c43bd,color:#fff,stroke-width:2px"
        )
        mermaid_lines.append(f"    class {','.join(matrix_ids)} matrix")
    fan_in_ids = [_nid(jid) for jid in fan_in]
    if fan_in_ids:
        mermaid_lines.append(
            "    classDef summary fill:#1b5e20,stroke:#4caf50,color:#fff,stroke-width:2px"
        )
        mermaid_lines.append(f"    class {','.join(fan_in_ids)} summary")
    if roots:
        root_ids = [_nid(r) for r in roots]
        mermaid_lines.append(
            "    classDef coordinator fill:#0d47a1,stroke:#42a5f5,color:#fff,stroke-width:2px"
        )
        mermaid_lines.append(f"    class {','.join(root_ids)} coordinator")

    mermaid_def = "\n".join(mermaid_lines)

    # Dynamic legend
    legend_entries: list[str] = []
    if roots:
        legend_entries.append(
            '<span class="legend-dot" style="background:#42a5f5"></span>Coordinator'
        )
    if has_matrix_jobs:
        legend_entries.append(
            '<span class="legend-dot" style="background:#7c43bd"></span>Matrix job'
        )
    if has_summary_jobs:
        legend_entries.append(
            '<span class="legend-dot" style="background:#4caf50"></span>Summary'
        )
    if has_scanner_jobs:
        legend_entries.append(
            '<span class="legend-dot" style="background:#555"></span>Scanner'
        )
    legend_html = "<br>\n  ".join(legend_entries)

    html = _render_diagram_html(mermaid_def, legend_html)

    # Write HTML file into assets
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


def _render_diagram_html(mermaid_def: str, legend_html: str) -> str:
    """Render the standalone HTML page for a Mermaid diagram."""
    return f"""<!DOCTYPE html>
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
