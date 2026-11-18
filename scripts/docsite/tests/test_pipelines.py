"""Tests for ``scripts/docsite/pipelines.py``, the architecture overview page."""

from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml

from docsite.pipelines import (
    MAP_PAGE,
    PipelineDataError,
    load_data_flow,
    overview_mermaid,
    pipeline_mermaid,
    render_overview_from_repo,
    render_overview_markdown,
)

REPO_ROOT = Path(__file__).resolve().parents[3]


def _architecture() -> dict:
    return {
        "data_flow": {
            "stages": [
                {"id": "config", "label": "Config", "detail": "argus.yml"},
                {"id": "results", "label": "argus-results.json", "detail": "The artifact"},
            ],
            "pipelines": [
                {
                    "id": "source-scan",
                    "name": "Source scan",
                    "entrypoint": "argus scan <scanner>",
                    "adrs": ["ADR-013"],
                    "steps": [
                        {"id": "load", "label": "Load config", "detail": "Loads it"},
                        {"id": "run", "label": "Run", "per": "scanner", "detail": "Runs"},
                        {"id": "parse", "label": "Parse", "per": "scanner",
                         "detail": "Writes <output_dir>/raw | keeps it"},
                        {"id": "report", "label": "Report", "detail": "Reports"},
                    ],
                },
            ],
        },
    }


class TestLoadDataFlow:
    def test_returns_stages_and_pipelines(self):
        stages, pipelines = load_data_flow(_architecture())
        assert [s["id"] for s in stages] == ["config", "results"]
        assert [p["id"] for p in pipelines] == ["source-scan"]

    def test_missing_data_flow(self):
        with pytest.raises(PipelineDataError, match="data_flow is missing"):
            load_data_flow({})

    @pytest.mark.parametrize("key", ["stages", "pipelines"])
    def test_empty_list(self, key):
        arch = _architecture()
        arch["data_flow"][key] = []
        with pytest.raises(PipelineDataError, match=f"data_flow.{key}"):
            load_data_flow(arch)

    def test_missing_field_is_named(self):
        arch = _architecture()
        del arch["data_flow"]["pipelines"][0]["steps"][1]["detail"]
        with pytest.raises(PipelineDataError, match=r"steps\[1\] is missing detail"):
            load_data_flow(arch)

    def test_duplicate_id(self):
        arch = _architecture()
        arch["data_flow"]["stages"][1]["id"] = "config"
        with pytest.raises(PipelineDataError, match="duplicate id: config"):
            load_data_flow(arch)

    def test_non_mapping_item(self):
        arch = _architecture()
        arch["data_flow"]["stages"].append("not a mapping")
        with pytest.raises(PipelineDataError, match="must be a mapping"):
            load_data_flow(arch)

    def test_empty_steps(self):
        arch = _architecture()
        arch["data_flow"]["pipelines"][0]["steps"] = []
        with pytest.raises(PipelineDataError, match="is missing steps"):
            load_data_flow(arch)

    def test_steps_not_a_list(self):
        arch = _architecture()
        arch["data_flow"]["pipelines"][0]["steps"] = "load, run"
        with pytest.raises(PipelineDataError, match="steps must be a non-empty list"):
            load_data_flow(arch)


class TestMermaid:
    def test_overview_is_one_chain(self):
        stages, _ = load_data_flow(_architecture())
        out = overview_mermaid(stages)
        assert out.startswith("flowchart LR")
        assert "n_config --> n_results" in out

    def test_pipeline_groups_per_steps_in_one_subgraph(self):
        _, pipelines = load_data_flow(_architecture())
        out = pipeline_mermaid(pipelines[0])
        assert out.count("subgraph") == 1
        assert 'subgraph n_source_scan_loop_1["For each scanner"]' in out
        lines = out.splitlines()
        start = next(i for i, line in enumerate(lines) if "subgraph" in line)
        end = lines.index("    end", start)
        inside = "\n".join(lines[start:end])
        assert "n_source_scan_run" in inside
        assert "n_source_scan_parse" in inside
        assert "n_source_scan_load" not in inside
        assert "n_source_scan_report" not in inside

    def test_pipeline_chain_runs_through_every_step(self):
        _, pipelines = load_data_flow(_architecture())
        out = pipeline_mermaid(pipelines[0])
        assert (
            "n_source_scan_entry --> n_source_scan_load --> n_source_scan_run"
            " --> n_source_scan_parse --> n_source_scan_report"
        ) in out

    def test_labels_are_escaped(self):
        _, pipelines = load_data_flow(_architecture())
        out = pipeline_mermaid(pipelines[0])
        assert "argus scan #lt;scanner#gt;" in out
        assert "<scanner>" not in out

    def test_separate_per_runs_get_separate_subgraphs(self):
        pipeline = copy.deepcopy(_architecture()["data_flow"]["pipelines"][0])
        pipeline["steps"][3]["per"] = "image"
        out = pipeline_mermaid(pipeline)
        assert out.count("subgraph") == 2
        assert 'loop_2["For each image"]' in out


class TestRenderOverviewMarkdown:
    def test_writes_architecture_md(self, tmp_path):
        path = render_overview_markdown(_architecture(), tmp_path)
        assert path == tmp_path / "architecture.md"
        text = path.read_text(encoding="utf-8")
        assert text.count("```mermaid") == 2
        assert "### Source scan" in text
        assert "Decisions: ADR-013" in text
        assert f"]({MAP_PAGE})" in text

    def test_table_cells_escape_html_and_pipes(self, tmp_path):
        text = render_overview_markdown(_architecture(), tmp_path).read_text(
            encoding="utf-8",
        )
        assert "&lt;output_dir&gt;/raw \\| keeps it" in text
        assert "**Run**<br><small>for each scanner</small>" in text

    def test_no_map_link_when_map_missing(self, tmp_path):
        text = render_overview_markdown(
            _architecture(), tmp_path, map_page=None,
        ).read_text(encoding="utf-8")
        assert MAP_PAGE not in text

    def test_bad_data_flow_raises(self, tmp_path):
        with pytest.raises(PipelineDataError):
            render_overview_markdown({}, tmp_path)
        assert not (tmp_path / "architecture.md").exists()

    def test_from_repo(self, tmp_path):
        repo = tmp_path / "repo"
        (repo / ".ai").mkdir(parents=True)
        (repo / ".ai" / "architecture.yaml").write_text(
            yaml.safe_dump(_architecture()), encoding="utf-8",
        )
        docs = tmp_path / "docs"
        docs.mkdir()
        path = render_overview_from_repo(repo, docs)
        assert path.exists()


class TestRealArchitectureYaml:
    """The checked-in ``.ai/architecture.yaml`` must render."""

    def test_repo_data_flow_is_valid(self):
        with (REPO_ROOT / ".ai" / "architecture.yaml").open(encoding="utf-8") as fh:
            architecture = yaml.safe_load(fh)
        stages, pipelines = load_data_flow(architecture)
        assert {p["id"] for p in pipelines} == {
            "source-scan", "container-scan", "composite-action", "mcp",
        }
        assert stages[0]["id"] == "config"
        assert stages[-1]["id"] == "consumers"
