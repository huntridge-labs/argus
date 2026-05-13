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


class TestBlobRefResolution:
    """``GITHUB_BLOB`` reflects the per-build git ref so versioned docs
    link to matching ``/blob/<version>/`` URLs instead of always
    hardcoding ``main``.
    """

    def test_explicit_ref_arg_wins(self, tmp_repo: Path, monkeypatch):
        # Even with an env var set, the explicit kwarg wins.
        monkeypatch.setenv("ARGUS_DOCS_REF", "env-ref")
        config.load_site_config(tmp_repo, ref="v0.7.2")
        assert config.GITHUB_BLOB.endswith("/blob/v0.7.2")

    def test_env_var_used_when_no_explicit_ref(
        self, tmp_repo: Path, monkeypatch,
    ):
        monkeypatch.setenv("ARGUS_DOCS_REF", "abc123def456")
        config.load_site_config(tmp_repo)
        assert config.GITHUB_BLOB.endswith("/blob/abc123def456")

    def test_fallback_to_main_when_no_ref_or_env(
        self, tmp_repo: Path, monkeypatch,
    ):
        monkeypatch.delenv("ARGUS_DOCS_REF", raising=False)
        config.load_site_config(tmp_repo)
        assert config.GITHUB_BLOB.endswith("/blob/main")

    def test_empty_string_ref_arg_falls_through_to_env(
        self, tmp_repo: Path, monkeypatch,
    ):
        """An empty-string ``ref`` should NOT count as a real value —
        the resolver falls through to the env var. This protects
        against the CI script accidentally passing ``--ref=``."""
        monkeypatch.setenv("ARGUS_DOCS_REF", "v9.9.9")
        config.load_site_config(tmp_repo, ref="")
        assert config.GITHUB_BLOB.endswith("/blob/v9.9.9")

    def test_whitespace_env_var_falls_back_to_main(
        self, tmp_repo: Path, monkeypatch,
    ):
        """An env var that's just whitespace doesn't count as a ref —
        otherwise a CI step that exports ``ARGUS_DOCS_REF=`` (e.g. a
        missing variable in a templated shell script) would produce a
        ``/blob//`` URL that 404s on everything."""
        monkeypatch.setenv("ARGUS_DOCS_REF", "   ")
        config.load_site_config(tmp_repo)
        assert config.GITHUB_BLOB.endswith("/blob/main")

    def test_repo_url_with_ref(self, tmp_repo: Path):
        """The ref is appended AFTER the repo_url's ``/blob/`` segment."""
        cfg = yaml.safe_load((tmp_repo / "docsite.yml").read_text())
        cfg["repo_url"] = "https://github.com/myorg/myrepo"
        (tmp_repo / "docsite.yml").write_text(
            yaml.dump(cfg, allow_unicode=True),
        )
        config.load_site_config(tmp_repo, ref="v1.2.3")
        assert config.GITHUB_BLOB == "https://github.com/myorg/myrepo/blob/v1.2.3"

    def test_build_threads_ref_through(self, tmp_repo: Path, tmp_path: Path):
        """End-to-end: ``build(..., ref=...)`` propagates into
        ``GITHUB_BLOB`` so generated pages get the right blob URLs."""
        from docsite.builder import build

        out = tmp_path / "out"
        build(tmp_repo, out, ref="v3.14.15")
        assert config.GITHUB_BLOB.endswith("/blob/v3.14.15")
