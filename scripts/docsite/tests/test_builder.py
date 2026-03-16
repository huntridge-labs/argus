"""Tests for docsite.builder — main build orchestration."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from docsite import config
from docsite.builder import build


@pytest.fixture(autouse=True)
def _reset_config():
    """Reset config state between tests."""
    config.CATEGORY_LABELS = {}
    config.CATEGORY_ICONS = {}
    config.EXCLUDED_ACTIONS = set()
    config.EXCLUDED_WORKFLOWS = set()
    config.EXCLUDED_GUIDE_DIRS = set()
    config.GITHUB_BLOB = ""
    config.GROUP_LABELS = {}
    yield


class TestBuild:
    """Tests for build()."""

    def test_creates_output_directory(self, tmp_repo: Path, tmp_path: Path):
        out = tmp_path / "output"
        build(tmp_repo, out)
        assert out.exists()
        assert (out / "docs").exists()

    def test_generates_mkdocs_yml(self, tmp_repo: Path, tmp_path: Path):
        out = tmp_path / "output"
        build(tmp_repo, out)
        mkdocs_yml = out / "mkdocs.yml"
        assert mkdocs_yml.exists()
        content = mkdocs_yml.read_text()
        assert "site_name" in content

    def test_generates_index_page(self, tmp_repo: Path, tmp_path: Path):
        out = tmp_path / "output"
        build(tmp_repo, out)
        assert (out / "docs" / "index.md").exists()

    def test_generates_action_pages(self, tmp_repo: Path, tmp_path: Path):
        out = tmp_path / "output"
        build(tmp_repo, out)
        actions_dir = out / "docs" / "actions"
        assert actions_dir.exists()
        assert (actions_dir / "index.md").exists()
        assert (actions_dir / "scanner-bandit.md").exists()
        assert (actions_dir / "scanner-gitleaks.md").exists()

    def test_excludes_excluded_actions(self, tmp_repo: Path, tmp_path: Path):
        out = tmp_path / "output"
        build(tmp_repo, out)
        assert not (out / "docs" / "actions" / "comment-pr.md").exists()

    def test_generates_workflow_pages(
        self, tmp_repo: Path, tmp_path: Path, sample_workflow: Path,
    ):
        out = tmp_path / "output"
        build(tmp_repo, out)
        wf_dir = out / "docs" / "workflows"
        assert wf_dir.exists()
        assert (wf_dir / "index.md").exists()
        assert (wf_dir / "security-scan.md").exists()

    def test_copies_custom_css(self, tmp_repo: Path, tmp_path: Path):
        out = tmp_path / "output"
        build(tmp_repo, out)
        assert (out / "docs" / "assets" / "custom.css").exists()

    def test_copies_images(self, tmp_repo: Path, tmp_path: Path):
        (tmp_repo / "img" / "logo.png").write_text("fake-image")
        out = tmp_path / "output"
        build(tmp_repo, out)
        assert (out / "docs" / "assets" / "logo.png").exists()

    def test_generates_guide_pages(self, tmp_repo: Path, tmp_path: Path):
        (tmp_repo / "docs" / "scanners.md").write_text("# Scanner Guide\n")
        out = tmp_path / "output"
        build(tmp_repo, out)
        assert (out / "docs" / "guides" / "scanners.md").exists()

    def test_clean_rebuilds(self, tmp_repo: Path, tmp_path: Path):
        out = tmp_path / "output"
        build(tmp_repo, out)
        # Build again — should clean and rebuild
        build(tmp_repo, out)
        assert (out / "docs" / "index.md").exists()

    def test_generates_examples(self, tmp_repo: Path, tmp_path: Path):
        examples_dir = tmp_repo / "examples"
        examples_dir.mkdir()
        (examples_dir / "security-scan.yml").write_text(
            "name: Example\non: push\njobs: {}\n",
        )
        out = tmp_path / "output"
        build(tmp_repo, out)
        assert (out / "docs" / "examples").exists()

    def test_nav_structure(self, tmp_repo: Path, tmp_path: Path):
        out = tmp_path / "output"
        build(tmp_repo, out)
        mkdocs_content = (out / "mkdocs.yml").read_text()
        assert "Home" in mkdocs_content
        assert "Actions" in mkdocs_content
