"""Tests for docsite.config — site configuration loading."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from docsite import config


@pytest.fixture(autouse=True)
def _reset_config():
    """Reset module-level state between tests."""
    config.CATEGORY_LABELS = {}
    config.CATEGORY_ICONS = {}
    config.EXCLUDED_ACTIONS = set()
    config.EXCLUDED_WORKFLOWS = set()
    config.EXCLUDED_GUIDE_DIRS = set()
    config.GITHUB_BLOB = ""
    config.GROUP_LABELS = {}
    yield


class TestLoadSiteConfig:
    """Tests for load_site_config()."""

    def test_loads_valid_config(self, tmp_repo: Path):
        config.load_site_config(tmp_repo)

        assert config.CATEGORY_LABELS == {"sast": "SAST", "secrets": "Secrets Detection"}
        assert config.CATEGORY_ICONS == {"sast": "🔍", "secrets": "🔑"}
        assert config.EXCLUDED_ACTIONS == {"comment-pr"}
        assert config.EXCLUDED_WORKFLOWS == {"release"}
        assert config.GITHUB_BLOB == "https://github.com/huntridge-labs/argus/blob/main"
        assert config.GROUP_LABELS == {"codeql": "CodeQL"}

    def test_missing_docsite_yml_exits(self, tmp_path: Path):
        (tmp_path / ".github").mkdir(parents=True)
        with pytest.raises(SystemExit):
            config.load_site_config(tmp_path)

    def test_invalid_yaml_exits(self, tmp_path: Path):
        (tmp_path / ".github").mkdir(parents=True)
        (tmp_path / "docsite.yml").write_text(": : invalid yaml {{{\n")
        with pytest.raises(SystemExit):
            config.load_site_config(tmp_path)

    def test_missing_required_keys_exits(self, tmp_path: Path):
        (tmp_path / ".github").mkdir(parents=True)
        (tmp_path / "docsite.yml").write_text(yaml.dump({"repo_url": "https://example.com"}))
        with pytest.raises(SystemExit):
            config.load_site_config(tmp_path)

    def test_repo_url_trailing_slash_stripped(self, tmp_repo: Path):
        cfg = yaml.safe_load((tmp_repo / "docsite.yml").read_text())
        cfg["repo_url"] = "https://github.com/org/repo/"
        (tmp_repo / "docsite.yml").write_text(yaml.dump(cfg, allow_unicode=True))

        config.load_site_config(tmp_repo)
        assert config.GITHUB_BLOB == "https://github.com/org/repo/blob/main"

    def test_empty_exclusions_become_empty_sets(self, tmp_repo: Path):
        cfg = yaml.safe_load((tmp_repo / "docsite.yml").read_text())
        cfg["excluded_actions"] = None
        cfg["excluded_workflows"] = None
        (tmp_repo / "docsite.yml").write_text(yaml.dump(cfg, allow_unicode=True))

        config.load_site_config(tmp_repo)
        assert config.EXCLUDED_ACTIONS == set()
        assert config.EXCLUDED_WORKFLOWS == set()

    def test_category_without_dict_value_skipped(self, tmp_repo: Path):
        cfg = yaml.safe_load((tmp_repo / "docsite.yml").read_text())
        cfg["categories"]["broken"] = "not-a-dict"
        (tmp_repo / "docsite.yml").write_text(yaml.dump(cfg, allow_unicode=True))

        config.load_site_config(tmp_repo)
        assert "broken" not in config.CATEGORY_LABELS

    def test_missing_input_group_labels(self, tmp_repo: Path):
        cfg = yaml.safe_load((tmp_repo / "docsite.yml").read_text())
        del cfg["input_group_labels"]
        (tmp_repo / "docsite.yml").write_text(yaml.dump(cfg, allow_unicode=True))

        config.load_site_config(tmp_repo)
        assert config.GROUP_LABELS == {}

    def test_missing_excluded_guide_dirs(self, tmp_repo: Path):
        config.load_site_config(tmp_repo)
        assert config.EXCLUDED_GUIDE_DIRS == set()

    def test_excluded_guide_dirs_loaded(self, tmp_repo: Path):
        cfg = yaml.safe_load((tmp_repo / "docsite.yml").read_text())
        cfg["excluded_guide_dirs"] = ["developer", "internal"]
        (tmp_repo / "docsite.yml").write_text(yaml.dump(cfg, allow_unicode=True))

        config.load_site_config(tmp_repo)
        assert config.EXCLUDED_GUIDE_DIRS == {"developer", "internal"}
