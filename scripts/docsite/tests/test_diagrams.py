"""Tests for docsite.diagrams module."""

from __future__ import annotations

from pathlib import Path

from docsite.diagrams import (
    _get_needs,
    _nid,
    _node_def,
    _render_diagram_html,
    make_workflow_diagram,
)


class TestGetNeeds:
    def test_string_needs(self):
        assert _get_needs({"needs": "setup"}) == ["setup"]

    def test_list_needs(self):
        assert _get_needs({"needs": ["a", "b"]}) == ["a", "b"]

    def test_no_needs(self):
        assert _get_needs({}) == []

    def test_empty_list(self):
        assert _get_needs({"needs": []}) == []


class TestNid:
    def test_replaces_hyphens(self):
        assert _nid("scanner-bandit") == "scanner_bandit"

    def test_no_hyphens(self):
        assert _nid("setup") == "setup"

    def test_multiple_hyphens(self):
        assert _nid("a-b-c-d") == "a_b_c_d"


class TestNodeDef:
    def test_simple_node(self):
        result = _node_def("build", {"name": "Build"}, is_fan_in=False)
        assert result == 'build["Build"]'

    def test_fan_in_node(self):
        result = _node_def("summary", {"name": "Summary"}, is_fan_in=True)
        assert result == 'summary[["Summary"]]'

    def test_matrix_node_with_parallel(self):
        job = {
            "name": "Scan",
            "has_matrix": True,
            "matrix_data": {"os": ["ubuntu", "macos"], "python": ["3.11", "3.12"]},
        }
        result = _node_def("scan", job, is_fan_in=False)
        assert "matrix" in result
        assert "4 parallel" in result
        assert "⟐" in result

    def test_matrix_node_single_dimension(self):
        job = {
            "name": "Test",
            "has_matrix": True,
            "matrix_data": {"os": ["ubuntu"]},
        }
        result = _node_def("test", job, is_fan_in=False)
        assert "⟐ matrix" in result
        # 1 parallel shouldn't show count
        assert "1 parallel" not in result

    def test_matrix_node_max_parallel(self):
        job = {
            "name": "Test",
            "has_matrix": True,
            "matrix_data": {"os": ["ubuntu"]},
            "max_parallel": 3,
        }
        result = _node_def("test", job, is_fan_in=False)
        assert "max 3" in result

    def test_matrix_node_non_dict_matrix_data(self):
        job = {"name": "Test", "has_matrix": True, "matrix_data": "something"}
        result = _node_def("test", job, is_fan_in=False)
        assert "⟐ matrix" in result

    def test_matrix_excludes_include_exclude_keys(self):
        job = {
            "name": "Scan",
            "has_matrix": True,
            "matrix_data": {
                "os": ["ubuntu", "macos"],
                "include": [{"os": "windows"}],
                "exclude": [{"os": "macos"}],
            },
        }
        result = _node_def("scan", job, is_fan_in=False)
        assert "2 parallel" in result

    def test_hyphenated_job_id(self):
        result = _node_def("my-job", {"name": "My Job"}, is_fan_in=False)
        assert result.startswith("my_job")


class TestMakeWorkflowDiagram:
    def test_returns_empty_for_single_job(self, tmp_path):
        jobs = {"build": {"name": "Build"}}
        result = make_workflow_diagram(jobs, "test", tmp_path)
        assert result == ""

    def test_generates_iframe_for_multi_job(self, tmp_path):
        jobs = {
            "setup": {"name": "Setup"},
            "build": {"name": "Build", "needs": "setup"},
        }
        result = make_workflow_diagram(jobs, "test-wf", tmp_path)
        assert "iframe" in result
        assert "test-wf.html" in result
        assert (tmp_path / "assets" / "diagrams" / "test-wf.html").exists()

    def test_html_file_contains_mermaid(self, tmp_path):
        jobs = {
            "setup": {"name": "Setup"},
            "build": {"name": "Build", "needs": "setup"},
        }
        make_workflow_diagram(jobs, "mermaid-test", tmp_path)
        html = (tmp_path / "assets" / "diagrams" / "mermaid-test.html").read_text()
        assert "mermaid" in html
        assert "flowchart LR" in html

    def test_edges_between_jobs(self, tmp_path):
        jobs = {
            "a": {"name": "Job A"},
            "b": {"name": "Job B", "needs": "a"},
            "c": {"name": "Job C", "needs": ["a", "b"]},
        }
        make_workflow_diagram(jobs, "edges", tmp_path)
        html = (tmp_path / "assets" / "diagrams" / "edges.html").read_text()
        assert "a --> b" in html
        assert "a --> c" in html
        assert "b --> c" in html

    def test_fan_in_detection(self, tmp_path):
        jobs = {
            "a": {"name": "A"},
            "b": {"name": "B"},
            "c": {"name": "C"},
            "summary": {"name": "Summary", "needs": ["a", "b", "c"]},
        }
        make_workflow_diagram(jobs, "fan-in", tmp_path)
        html = (tmp_path / "assets" / "diagrams" / "fan-in.html").read_text()
        assert "classDef summary" in html
        assert "Summary" in html

    def test_matrix_styling(self, tmp_path):
        jobs = {
            "setup": {"name": "Setup"},
            "scan": {
                "name": "Scan",
                "needs": "setup",
                "has_matrix": True,
                "matrix_data": {"scanner": ["a", "b"]},
            },
        }
        make_workflow_diagram(jobs, "matrix", tmp_path)
        html = (tmp_path / "assets" / "diagrams" / "matrix.html").read_text()
        assert "classDef matrix" in html

    def test_root_coordinator_styling(self, tmp_path):
        jobs = {
            "setup": {"name": "Setup"},
            "build": {"name": "Build", "needs": "setup"},
        }
        make_workflow_diagram(jobs, "root", tmp_path)
        html = (tmp_path / "assets" / "diagrams" / "root.html").read_text()
        assert "classDef coordinator" in html

    def test_caption_includes_job_count(self, tmp_path):
        jobs = {
            "a": {"name": "A"},
            "b": {"name": "B", "needs": "a"},
            "c": {"name": "C", "needs": "a"},
        }
        result = make_workflow_diagram(jobs, "count", tmp_path)
        assert "3 jobs" in result

    def test_caption_includes_matrix_count(self, tmp_path):
        jobs = {
            "a": {"name": "A"},
            "b": {"name": "B", "needs": "a", "has_matrix": True, "matrix_data": {}},
        }
        result = make_workflow_diagram(jobs, "mc", tmp_path)
        assert "1 matrix" in result

    def test_legend_entries(self, tmp_path):
        jobs = {
            "setup": {"name": "Setup"},
            "scan": {
                "name": "Scan",
                "needs": "setup",
                "has_matrix": True,
                "matrix_data": {"s": ["a", "b"]},
            },
            "lint": {"name": "Lint", "needs": "setup"},
            "summary": {
                "name": "Summary",
                "needs": ["setup", "scan", "lint"],
            },
        }
        make_workflow_diagram(jobs, "legend", tmp_path)
        html = (tmp_path / "assets" / "diagrams" / "legend.html").read_text()
        assert "Coordinator" in html
        assert "Matrix job" in html
        assert "Summary" in html
        assert "Scanner" in html

    def test_skips_edges_to_nonexistent_deps(self, tmp_path):
        jobs = {
            "a": {"name": "A"},
            "b": {"name": "B", "needs": "nonexistent"},
        }
        # Should not raise
        make_workflow_diagram(jobs, "skip", tmp_path)
        html = (tmp_path / "assets" / "diagrams" / "skip.html").read_text()
        assert "nonexistent" not in html


class TestRenderDiagramHtml:
    def test_contains_mermaid_script(self):
        html = _render_diagram_html("flowchart LR\n  A --> B", "")
        assert "mermaid" in html
        assert "cdn.jsdelivr.net" in html

    def test_contains_legend(self):
        legend = '<span class="legend-dot">Test</span>'
        html = _render_diagram_html("flowchart LR", legend)
        assert legend in html

    def test_contains_zoom_controls(self):
        html = _render_diagram_html("flowchart LR", "")
        assert "zoomBy" in html
        assert "resetView" in html

    def test_contains_pan_handlers(self):
        html = _render_diagram_html("flowchart LR", "")
        assert "mousedown" in html
        assert "mousemove" in html
        assert "mouseup" in html

    def test_dark_theme(self):
        html = _render_diagram_html("flowchart LR", "")
        assert "theme: 'dark'" in html
        assert "#1a1a2e" in html
