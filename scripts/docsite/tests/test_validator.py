"""Tests for docsite.validator — configuration validation."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from docsite.validator import validate


class TestValidate:
    """Tests for validate()."""

    def test_valid_config_passes(self, tmp_repo: Path):
        assert validate(tmp_repo) is True

    def test_missing_docsite_yml_fails(self, tmp_path: Path):
        (tmp_path / ".github" / "actions").mkdir(parents=True)
        assert validate(tmp_path) is False

    def test_invalid_yaml_fails(self, tmp_path: Path):
        (tmp_path / ".github" / "actions").mkdir(parents=True)
        (tmp_path / "docsite.yml").write_text(": : {{{\n")
        assert validate(tmp_path) is False

    def test_missing_required_top_keys_fails(self, tmp_path: Path):
        (tmp_path / ".github" / "actions").mkdir(parents=True)
        (tmp_path / "docsite.yml").write_text(
            yaml.dump({"repo_url": "https://example.com"}),
        )
        assert validate(tmp_path) is False

    def test_invalid_repo_url_fails(self, tmp_repo: Path):
        cfg = yaml.safe_load((tmp_repo / "docsite.yml").read_text())
        cfg["repo_url"] = "not-a-url"
        (tmp_repo / "docsite.yml").write_text(yaml.dump(cfg, allow_unicode=True))
        assert validate(tmp_repo) is False

    def test_category_not_dict_fails(self, tmp_repo: Path):
        cfg = yaml.safe_load((tmp_repo / "docsite.yml").read_text())
        cfg["categories"]["broken"] = "not-a-dict"
        (tmp_repo / "docsite.yml").write_text(yaml.dump(cfg, allow_unicode=True))
        assert validate(tmp_repo) is False

    def test_category_missing_label_fails(self, tmp_repo: Path):
        cfg = yaml.safe_load((tmp_repo / "docsite.yml").read_text())
        cfg["categories"]["incomplete"] = {"icon": "🔍"}
        (tmp_repo / "docsite.yml").write_text(yaml.dump(cfg, allow_unicode=True))
        assert validate(tmp_repo) is False

    def test_category_missing_icon_fails(self, tmp_repo: Path):
        cfg = yaml.safe_load((tmp_repo / "docsite.yml").read_text())
        cfg["categories"]["incomplete"] = {"label": "Incomplete"}
        (tmp_repo / "docsite.yml").write_text(yaml.dump(cfg, allow_unicode=True))
        assert validate(tmp_repo) is False

    def test_action_missing_docsite_yml_fails(self, tmp_repo: Path):
        # Add an action without .docsite.yml
        new_action = tmp_repo / ".github" / "actions" / "scanner-new"
        new_action.mkdir()
        assert validate(tmp_repo) is False

    def test_action_invalid_yaml_fails(self, tmp_repo: Path):
        action_dir = tmp_repo / ".github" / "actions" / "scanner-bad"
        action_dir.mkdir()
        (action_dir / ".docsite.yml").write_text(": : {{{\n")
        assert validate(tmp_repo) is False

    def test_action_missing_category_key_fails(self, tmp_repo: Path):
        action_dir = tmp_repo / ".github" / "actions" / "scanner-nocat"
        action_dir.mkdir()
        (action_dir / ".docsite.yml").write_text("sidebar_label: Foo\n")
        assert validate(tmp_repo) is False

    def test_action_unknown_category_fails(self, tmp_repo: Path):
        action_dir = tmp_repo / ".github" / "actions" / "scanner-unknown"
        action_dir.mkdir()
        (action_dir / ".docsite.yml").write_text("category: nonexistent\n")
        assert validate(tmp_repo) is False

    def test_excluded_actions_skipped(self, tmp_repo: Path):
        # comment-pr is excluded and has no .docsite.yml — should still pass
        assert validate(tmp_repo) is True

    def test_missing_actions_dir_warns(self, tmp_path: Path):
        cfg = {
            "repo_url": "https://github.com/org/repo",
            "categories": {"sast": {"label": "SAST", "icon": "🔍"}},
            "excluded_actions": [],
            "excluded_workflows": [],
        }
        (tmp_path / "docsite.yml").write_text(yaml.dump(cfg, allow_unicode=True))
        # No .github/actions/ — should warn but pass
        assert validate(tmp_path) is True

    def test_non_directory_children_skipped(self, tmp_repo: Path):
        # Add a file (not directory) in the actions dir
        (tmp_repo / ".github" / "actions" / "README.md").write_text("# Actions\n")
        assert validate(tmp_repo) is True

    def test_empty_docsite_yml_in_action_fails(self, tmp_repo: Path):
        action_dir = tmp_repo / ".github" / "actions" / "scanner-empty"
        action_dir.mkdir()
        (action_dir / ".docsite.yml").write_text("")
        assert validate(tmp_repo) is False
