"""Tests for docsite.pages module."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from docsite import config
from docsite.pages import (
    _render_inputs,
    _render_jobs,
    _render_permissions,
    _render_secrets,
    _render_triggers,
    _render_used_actions_summary,
    make_action_page,
    make_workflow_page,
)


@pytest.fixture(autouse=True)
def _reset_config():
    """Reset config state between tests."""
    config.CATEGORY_LABELS = {"sast": "SAST", "secrets": "Secrets Detection"}
    config.CATEGORY_ICONS = {"sast": "🔍", "secrets": "🔑"}
    config.EXCLUDED_ACTIONS = set()
    config.EXCLUDED_WORKFLOWS = set()
    config.EXCLUDED_GUIDE_DIRS = set()
    config.GITHUB_BLOB = "https://github.com/huntridge-labs/argus/blob/main"
    config.GROUP_LABELS = {"codeql": "CodeQL"}
    yield


# ─── make_action_page ─────────────────────────────────────────────────────────


class TestMakeActionPage:
    def test_includes_action_name_as_heading(self, tmp_repo: Path):
        action_dir = tmp_repo / ".github" / "actions" / "scanner-bandit"
        page = make_action_page(action_dir, "0.5.0")
        assert "# Bandit Python Scanner" in page

    def test_includes_usage_snippet(self, tmp_repo: Path):
        action_dir = tmp_repo / ".github" / "actions" / "scanner-bandit"
        page = make_action_page(action_dir, "0.5.0")
        assert "scanner-bandit@0.5.0" in page

    def test_includes_readme_content(self, tmp_repo: Path):
        action_dir = tmp_repo / ".github" / "actions" / "scanner-bandit"
        page = make_action_page(action_dir, "0.5.0")
        assert "Scans Python code for vulnerabilities" in page

    def test_strips_readme_h1(self, tmp_repo: Path):
        action_dir = tmp_repo / ".github" / "actions" / "scanner-bandit"
        page = make_action_page(action_dir, "0.5.0")
        # The h1 from README should be stripped (page has its own h1)
        assert page.count("# Bandit") == 1

    def test_short_description_from_action_yml(self, tmp_repo: Path):
        action_dir = tmp_repo / ".github" / "actions" / "scanner-bandit"
        page = make_action_page(action_dir, "0.5.0")
        assert "Run Bandit security linter on Python code" in page

    def test_fallback_inputs_table_when_no_readme(self, tmp_repo: Path):
        action_dir = tmp_repo / ".github" / "actions" / "scanner-gitleaks"
        # Remove README to trigger fallback
        readme = action_dir / "README.md"
        if readme.exists():
            readme.unlink()
        page = make_action_page(action_dir, "0.5.0")
        assert "## Inputs" not in page  # No inputs defined for gitleaks fixture

    def test_fallback_generates_input_table(self, tmp_repo: Path):
        action_dir = tmp_repo / ".github" / "actions" / "scanner-bandit"
        # Remove README to trigger fallback table generation
        (action_dir / "README.md").unlink()
        page = make_action_page(action_dir, "0.5.0")
        assert "## Inputs" in page
        assert "`scan_path`" in page
        assert "`fail_on_severity`" in page

    def test_fallback_generates_output_table(self, tmp_repo: Path):
        action_dir = tmp_repo / ".github" / "actions" / "scanner-bandit"
        (action_dir / "README.md").unlink()
        page = make_action_page(action_dir, "0.5.0")
        assert "## Outputs" in page
        assert "`total_count`" in page

    def test_skips_non_dict_inputs(self, tmp_repo: Path):
        action_dir = tmp_repo / ".github" / "actions" / "scanner-gitleaks"
        (action_dir / "action.yml").write_text(yaml.dump({
            "name": "Test",
            "description": "Test action",
            "inputs": {"bad_input": "not a dict", "good_input": {"description": "works"}},
            "outputs": {},
            "runs": {"using": "composite", "steps": []},
        }))
        if (action_dir / "README.md").exists():
            (action_dir / "README.md").unlink()
        page = make_action_page(action_dir, "0.5.0")
        assert "`good_input`" in page
        assert "`bad_input`" not in page

    def test_skips_non_dict_outputs(self, tmp_repo: Path):
        action_dir = tmp_repo / ".github" / "actions" / "scanner-gitleaks"
        (action_dir / "action.yml").write_text(yaml.dump({
            "name": "Test",
            "description": "Test action",
            "inputs": {},
            "outputs": {"bad": "not a dict", "good": {"description": "ok"}},
            "runs": {"using": "composite", "steps": []},
        }))
        if (action_dir / "README.md").exists():
            (action_dir / "README.md").unlink()
        page = make_action_page(action_dir, "0.5.0")
        assert "`good`" in page
        assert "`bad`" not in page

    def test_docsite_sidebar_label_override(self, tmp_repo: Path):
        action_dir = tmp_repo / ".github" / "actions" / "scanner-bandit"
        (action_dir / ".docsite.yml").write_text("category: sast\nsidebar_label: Custom Name\n")
        page = make_action_page(action_dir, "0.5.0")
        assert "# Custom Name" in page

    def test_strips_usage_example_from_description(self, tmp_repo: Path):
        action_dir = tmp_repo / ".github" / "actions" / "scanner-gitleaks"
        (action_dir / "action.yml").write_text(yaml.dump({
            "name": "Test",
            "description": "Scan for secrets.**Usage Example**\n```yaml\nuses: ...\n```",
            "inputs": {},
            "outputs": {},
            "runs": {"using": "composite", "steps": []},
        }))
        page = make_action_page(action_dir, "0.5.0")
        assert "Scan for secrets" in page
        assert "Usage Example" not in page

    def test_missing_action_yml(self, tmp_repo: Path):
        action_dir = tmp_repo / ".github" / "actions" / "scanner-gitleaks"
        (action_dir / "action.yml").unlink()
        if (action_dir / "README.md").exists():
            (action_dir / "README.md").unlink()
        # Should not raise
        page = make_action_page(action_dir, "0.5.0")
        assert "# scanner-gitleaks" in page


# ─── make_workflow_page ───────────────────────────────────────────────────────


class TestMakeWorkflowPage:
    def test_includes_workflow_name(self, tmp_repo: Path, sample_workflow: Path):
        page = make_workflow_page(
            sample_workflow,
            tmp_repo / ".github" / "actions",
            "0.5.0",
        )
        assert "# Security Scan" in page

    def test_includes_usage_snippet(self, tmp_repo: Path, sample_workflow: Path):
        page = make_workflow_page(
            sample_workflow,
            tmp_repo / ".github" / "actions",
            "0.5.0",
        )
        assert "security-scan.yml@0.5.0" in page

    def test_includes_triggers(self, tmp_repo: Path, sample_workflow: Path):
        page = make_workflow_page(
            sample_workflow,
            tmp_repo / ".github" / "actions",
            "0.5.0",
        )
        assert "## Triggers" in page
        assert "Push" in page

    def test_includes_permissions(self, tmp_repo: Path, sample_workflow: Path):
        page = make_workflow_page(
            sample_workflow,
            tmp_repo / ".github" / "actions",
            "0.5.0",
        )
        assert "## Permissions" in page
        assert "`contents`" in page
        assert "`security-events`" in page

    def test_includes_inputs(self, tmp_repo: Path, sample_workflow: Path):
        page = make_workflow_page(
            sample_workflow,
            tmp_repo / ".github" / "actions",
            "0.5.0",
        )
        assert "## Inputs" in page
        assert "`scanners`" in page

    def test_includes_secrets(self, tmp_repo: Path, sample_workflow: Path):
        page = make_workflow_page(
            sample_workflow,
            tmp_repo / ".github" / "actions",
            "0.5.0",
        )
        assert "## Secrets" in page
        assert "`GITHUB_TOKEN`" in page

    def test_includes_jobs(self, tmp_repo: Path, sample_workflow: Path):
        page = make_workflow_page(
            sample_workflow,
            tmp_repo / ".github" / "actions",
            "0.5.0",
        )
        assert "## Jobs" in page
        assert "`bandit`" in page
        assert "`gitleaks`" in page

    def test_includes_description(self, tmp_repo: Path, sample_workflow: Path):
        page = make_workflow_page(
            sample_workflow,
            tmp_repo / ".github" / "actions",
            "0.5.0",
        )
        assert "Security Scan Workflow" in page or "Runs all security scanners" in page

    def test_generates_diagram_for_matrix_workflow(self, tmp_repo: Path):
        wf_content = """\
name: Matrix Workflow
on:
  workflow_call:
jobs:
  setup:
    name: Setup
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
  scan:
    name: Scan
    needs: setup
    runs-on: ubuntu-latest
    strategy:
      matrix:
        scanner: [bandit, gitleaks]
    steps:
      - uses: actions/checkout@v4
"""
        wf_path = tmp_repo / ".github" / "workflows" / "matrix.yml"
        wf_path.write_text(wf_content)
        docs_out = tmp_repo / "docs-out"
        page = make_workflow_page(
            wf_path,
            tmp_repo / ".github" / "actions",
            "0.5.0",
            docs_out=docs_out,
        )
        assert "## Pipeline" in page
        assert "iframe" in page


# ─── Section renderers ────────────────────────────────────────────────────────


class TestRenderTriggers:
    def test_known_triggers(self):
        lines: list[str] = []
        wf = {"triggers": ["push", "pull_request", "workflow_call"]}
        _render_triggers(lines, wf)
        content = "\n".join(lines)
        assert "## Triggers" in content
        assert "Push" in content
        assert "Pull request" in content
        assert "Reusable" in content

    def test_empty_triggers(self):
        lines: list[str] = []
        _render_triggers(lines, {"triggers": []})
        assert lines == []

    def test_unknown_trigger_uses_raw_name(self):
        lines: list[str] = []
        _render_triggers(lines, {"triggers": ["custom_event"]})
        assert any("custom_event" in l for l in lines)


class TestRenderPermissions:
    def test_renders_table(self):
        lines: list[str] = []
        wf = {"permissions": {"contents": "read", "issues": "write"}}
        _render_permissions(lines, wf)
        content = "\n".join(lines)
        assert "## Permissions" in content
        assert "`contents`" in content

    def test_empty_permissions(self):
        lines: list[str] = []
        _render_permissions(lines, {"permissions": {}})
        assert lines == []


class TestRenderInputs:
    def test_renders_general_inputs(self):
        lines: list[str] = []
        wf = {"inputs": {"scan_path": {"description": "Path to scan", "required": True}}}
        _render_inputs(lines, wf)
        content = "\n".join(lines)
        assert "## Inputs" in content
        assert "`scan_path`" in content

    def test_groups_by_description_prefix(self):
        lines: list[str] = []
        wf = {"inputs": {
            "codeql_language": {"description": "CodeQL: Language to scan"},
            "codeql_queries": {"description": "CodeQL: Query suite"},
        }}
        _render_inputs(lines, wf)
        assert any("CodeQL" in l for l in lines)

    def test_groups_by_key_prefix(self):
        lines: list[str] = []
        wf = {"inputs": {
            "codeql_language": {"description": "Language to scan"},
            "codeql_queries": {"description": "Query suite"},
        }}
        _render_inputs(lines, wf)
        assert any("CodeQL" in l for l in lines)

    def test_truncates_long_descriptions(self):
        lines: list[str] = []
        long_desc = "A" * 200
        wf = {"inputs": {"x": {"description": long_desc}}}
        _render_inputs(lines, wf)
        content = "\n".join(lines)
        assert "..." in content

    def test_empty_inputs(self):
        lines: list[str] = []
        _render_inputs(lines, {"inputs": {}})
        assert lines == []

    def test_skips_non_dict_inputs(self):
        lines: list[str] = []
        wf = {"inputs": {"bad": "not a dict"}}
        _render_inputs(lines, wf)
        assert "bad" not in "\n".join(lines)

    def test_shows_type_badge(self):
        lines: list[str] = []
        wf = {"inputs": {"x": {"description": "test", "type": "boolean"}}}
        _render_inputs(lines, wf)
        assert any("*boolean*" in l for l in lines)


class TestRenderSecrets:
    def test_renders_table(self):
        lines: list[str] = []
        wf = {"secrets": {"GITHUB_TOKEN": {"description": "Token", "required": True}}}
        _render_secrets(lines, wf)
        content = "\n".join(lines)
        assert "## Secrets" in content
        assert "`GITHUB_TOKEN`" in content

    def test_empty_secrets(self):
        lines: list[str] = []
        _render_secrets(lines, {"secrets": {}})
        assert lines == []

    def test_skips_non_dict_secrets(self):
        lines: list[str] = []
        wf = {"secrets": {"bad": "not a dict", "good": {"description": "ok"}}}
        _render_secrets(lines, wf)
        assert any("`good`" in l for l in lines)
        content = "\n".join(lines)
        assert "`bad`" not in content


class TestRenderJobs:
    def _make_job(self, **overrides):
        base = {
            "name": "Test Job",
            "runs_on": "ubuntu-latest",
            "timeout": None,
            "needs": [],
            "continue_on_error": False,
            "condition": None,
            "steps": [],
            "actions_used": [],
            "has_matrix": False,
        }
        base.update(overrides)
        return base

    def test_renders_job_heading(self, tmp_repo: Path):
        lines: list[str] = []
        wf = {"jobs": {"build": self._make_job(name="Build")}}
        _render_jobs(lines, wf, tmp_repo / ".github" / "actions")
        assert any("`build`" in l for l in lines)

    def test_renders_runs_on(self, tmp_repo: Path):
        lines: list[str] = []
        wf = {"jobs": {"build": self._make_job()}}
        _render_jobs(lines, wf, tmp_repo / ".github" / "actions")
        assert any("ubuntu-latest" in l for l in lines)

    def test_renders_timeout(self, tmp_repo: Path):
        lines: list[str] = []
        wf = {"jobs": {"build": self._make_job(timeout=30)}}
        _render_jobs(lines, wf, tmp_repo / ".github" / "actions")
        assert any("30" in l for l in lines)

    def test_renders_needs(self, tmp_repo: Path):
        lines: list[str] = []
        wf = {"jobs": {"build": self._make_job(needs=["setup", "lint"])}}
        _render_jobs(lines, wf, tmp_repo / ".github" / "actions")
        assert any("`setup`" in l for l in lines)

    def test_renders_continue_on_error(self, tmp_repo: Path):
        lines: list[str] = []
        wf = {"jobs": {"build": self._make_job(continue_on_error=True)}}
        _render_jobs(lines, wf, tmp_repo / ".github" / "actions")
        assert any("Continue on error" in l for l in lines)

    def test_renders_condition(self, tmp_repo: Path):
        lines: list[str] = []
        wf = {"jobs": {"build": self._make_job(condition="always()")}}
        _render_jobs(lines, wf, tmp_repo / ".github" / "actions")
        assert any("always()" in l for l in lines)

    def test_skips_long_condition(self, tmp_repo: Path):
        lines: list[str] = []
        long_cond = "a" * 150
        wf = {"jobs": {"build": self._make_job(condition=long_cond)}}
        _render_jobs(lines, wf, tmp_repo / ".github" / "actions")
        assert long_cond not in "\n".join(lines)

    def test_renders_steps(self, tmp_repo: Path):
        lines: list[str] = []
        steps = [
            {"name": "Checkout", "uses": "actions/checkout@v4"},
            {"name": "Run tests", "uses": None},
        ]
        wf = {"jobs": {"build": self._make_job(steps=steps)}}
        _render_jobs(lines, wf, tmp_repo / ".github" / "actions")
        assert any("Checkout" in l and "actions/checkout@v4" in l for l in lines)
        assert any("Run tests" in l for l in lines)

    def test_renders_actions_used_with_links(self, tmp_repo: Path):
        lines: list[str] = []
        wf = {"jobs": {"build": self._make_job(actions_used=["scanner-bandit"])}}
        _render_jobs(lines, wf, tmp_repo / ".github" / "actions")
        assert any("scanner-bandit" in l and "../actions/" in l for l in lines)

    def test_excludes_excluded_actions(self, tmp_repo: Path):
        config.EXCLUDED_ACTIONS = {"scanner-bandit"}
        lines: list[str] = []
        wf = {"jobs": {"build": self._make_job(actions_used=["scanner-bandit"])}}
        _render_jobs(lines, wf, tmp_repo / ".github" / "actions")
        assert not any("Actions used" in l for l in lines)

    def test_empty_jobs(self, tmp_repo: Path):
        lines: list[str] = []
        _render_jobs(lines, {"jobs": {}}, tmp_repo / ".github" / "actions")
        assert lines == []

    def test_string_needs_wrapped_in_list(self, tmp_repo: Path):
        lines: list[str] = []
        wf = {"jobs": {"build": self._make_job(needs="setup")}}
        _render_jobs(lines, wf, tmp_repo / ".github" / "actions")
        assert any("`setup`" in l for l in lines)


class TestRenderUsedActionsSummary:
    def test_renders_summary(self, tmp_repo: Path):
        lines: list[str] = []
        wf = {"used_actions": ["scanner-bandit"]}
        _render_used_actions_summary(lines, wf, tmp_repo / ".github" / "actions")
        content = "\n".join(lines)
        assert "## All Composite Actions Referenced" in content
        assert "scanner-bandit" in content

    def test_excludes_excluded_actions(self, tmp_repo: Path):
        config.EXCLUDED_ACTIONS = {"scanner-bandit"}
        lines: list[str] = []
        wf = {"used_actions": ["scanner-bandit"]}
        _render_used_actions_summary(lines, wf, tmp_repo / ".github" / "actions")
        assert lines == []

    def test_empty_used_actions(self, tmp_repo: Path):
        lines: list[str] = []
        _render_used_actions_summary(lines, {"used_actions": []}, tmp_repo / ".github" / "actions")
        assert lines == []

    def test_nonexistent_action_uses_name_as_label(self, tmp_repo: Path):
        lines: list[str] = []
        wf = {"used_actions": ["nonexistent-action"]}
        _render_used_actions_summary(lines, wf, tmp_repo / ".github" / "actions")
        assert any("nonexistent-action" in l for l in lines)
