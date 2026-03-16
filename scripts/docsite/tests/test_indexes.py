"""Tests for docsite.indexes — overview page generation."""

from __future__ import annotations

from pathlib import Path

import pytest

from docsite import config
from docsite.indexes import make_actions_index, make_home, make_workflows_index


@pytest.fixture(autouse=True)
def _load_config(tmp_repo: Path):
    """Load config before index tests."""
    config.load_site_config(tmp_repo)
    yield


class TestMakeActionsIndex:
    """Tests for make_actions_index()."""

    def test_contains_header(self, tmp_repo: Path):
        actions_dir = tmp_repo / ".github" / "actions"
        result = make_actions_index(actions_dir, "0.5.0")
        assert "# Composite Actions" in result

    def test_contains_category_sections(self, tmp_repo: Path):
        actions_dir = tmp_repo / ".github" / "actions"
        result = make_actions_index(actions_dir, "0.5.0")
        assert "🔍 SAST" in result
        assert "🔑 Secrets Detection" in result

    def test_contains_action_links(self, tmp_repo: Path):
        actions_dir = tmp_repo / ".github" / "actions"
        result = make_actions_index(actions_dir, "0.5.0")
        assert "scanner-bandit" in result
        assert "scanner-gitleaks" in result

    def test_excludes_excluded_actions(self, tmp_repo: Path):
        actions_dir = tmp_repo / ".github" / "actions"
        result = make_actions_index(actions_dir, "0.5.0")
        assert "comment-pr" not in result

    def test_includes_descriptions(self, tmp_repo: Path):
        actions_dir = tmp_repo / ".github" / "actions"
        result = make_actions_index(actions_dir, "0.5.0")
        assert "Bandit security linter" in result


class TestMakeWorkflowsIndex:
    """Tests for make_workflows_index()."""

    def test_contains_header(self, tmp_repo: Path, sample_workflow: Path):
        wf_dir = tmp_repo / ".github" / "workflows"
        result = make_workflows_index(wf_dir, "0.5.0")
        assert "# Reusable Workflows" in result

    def test_excludes_test_workflows(self, tmp_repo: Path):
        wf_dir = tmp_repo / ".github" / "workflows"
        (wf_dir / "test-actions.yml").write_text("name: Test Actions\non: push\njobs: {}\n")
        (wf_dir / "scanner-bandit.yml").write_text("name: Bandit\non: push\njobs: {}\n")
        result = make_workflows_index(wf_dir, "0.5.0")
        assert "test-actions" not in result

    def test_excludes_excluded_workflows(self, tmp_repo: Path):
        wf_dir = tmp_repo / ".github" / "workflows"
        (wf_dir / "release.yml").write_text("name: Release\non: push\njobs: {}\n")
        result = make_workflows_index(wf_dir, "0.5.0")
        assert "release" not in result

    def test_shows_main_pipeline(self, tmp_repo: Path):
        wf_dir = tmp_repo / ".github" / "workflows"
        (wf_dir / "reusable-security-hardening.yml").write_text(
            "name: Security Hardening\non: push\njobs: {}\n",
        )
        result = make_workflows_index(wf_dir, "0.5.0")
        assert "Main Hardening Pipeline" in result

    def test_shows_scanner_workflows(self, tmp_repo: Path):
        wf_dir = tmp_repo / ".github" / "workflows"
        (wf_dir / "scanner-bandit.yml").write_text("name: Bandit\non: push\njobs: {}\n")
        result = make_workflows_index(wf_dir, "0.5.0")
        assert "scanner-bandit" in result


class TestMakeHome:
    """Tests for make_home()."""

    def test_uses_readme_content(self, tmp_repo: Path):
        result = make_home(tmp_repo, "0.5.0")
        assert "Argus" in result
        assert "Test readme" in result

    def test_rewrites_image_paths(self, tmp_repo: Path):
        (tmp_repo / "README.md").write_text('![logo](img/logo.png)\n')
        result = make_home(tmp_repo, "0.5.0")
        assert "assets/logo.png" in result
        assert "img/logo.png" not in result

    def test_adds_markdown_attr_to_divs(self, tmp_repo: Path):
        (tmp_repo / "README.md").write_text('<div align="center">\nHello\n</div>\n')
        result = make_home(tmp_repo, "0.5.0")
        assert '<div markdown align="center">' in result

    def test_fallback_when_no_readme(self, tmp_path: Path):
        empty_dir = tmp_path / "empty-repo"
        empty_dir.mkdir()
        result = make_home(empty_dir, "1.0.0")
        assert "Argus" in result
        assert "1.0.0" in result
