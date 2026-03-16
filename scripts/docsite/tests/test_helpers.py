"""Tests for docsite.helpers — file I/O and link rewriting."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from docsite import config
from docsite.helpers import (
    get_version,
    parse_action_yml,
    read,
    rewrite_repo_links,
    write,
)


class TestRead:
    """Tests for read()."""

    def test_reads_existing_file(self, tmp_path: Path):
        f = tmp_path / "test.txt"
        f.write_text("hello world")
        assert read(f) == "hello world"

    def test_returns_empty_for_missing_file(self, tmp_path: Path):
        assert read(tmp_path / "nonexistent.txt") == ""

    def test_reads_utf8(self, tmp_path: Path):
        f = tmp_path / "unicode.txt"
        f.write_text("héllo wörld 🔍", encoding="utf-8")
        assert read(f) == "héllo wörld 🔍"


class TestWrite:
    """Tests for write()."""

    def test_writes_file(self, tmp_path: Path):
        f = tmp_path / "out.txt"
        write(f, "content")
        assert f.read_text() == "content"

    def test_creates_parent_dirs(self, tmp_path: Path):
        f = tmp_path / "a" / "b" / "c" / "out.txt"
        write(f, "nested")
        assert f.read_text() == "nested"

    def test_overwrites_existing(self, tmp_path: Path):
        f = tmp_path / "out.txt"
        f.write_text("old")
        write(f, "new")
        assert f.read_text() == "new"


class TestParseActionYml:
    """Tests for parse_action_yml()."""

    def test_parses_valid_action(self, tmp_path: Path):
        f = tmp_path / "action.yml"
        f.write_text(yaml.dump({"name": "Test", "description": "A test action"}))
        result = parse_action_yml(f)
        assert result["name"] == "Test"

    def test_returns_empty_dict_for_missing_file(self, tmp_path: Path):
        assert parse_action_yml(tmp_path / "missing.yml") == {}

    def test_returns_empty_dict_for_invalid_yaml(self, tmp_path: Path):
        f = tmp_path / "bad.yml"
        f.write_text(": : {{{\n")
        assert parse_action_yml(f) == {}

    def test_returns_empty_dict_for_empty_file(self, tmp_path: Path):
        f = tmp_path / "empty.yml"
        f.write_text("")
        assert parse_action_yml(f) == {}


class TestGetVersion:
    """Tests for get_version()."""

    def test_reads_version_from_file(self, tmp_path: Path):
        (tmp_path / "version.yaml").write_text("1.2.3\n")
        assert get_version(tmp_path) == "1.2.3"

    def test_handles_version_with_extra_text(self, tmp_path: Path):
        (tmp_path / "version.yaml").write_text("1.0.0 extra stuff\n")
        assert get_version(tmp_path) == "1.0.0"

    def test_returns_latest_for_missing_file(self, tmp_path: Path):
        assert get_version(tmp_path) == "latest"

    def test_returns_latest_for_empty_file(self, tmp_path: Path):
        (tmp_path / "version.yaml").write_text("")
        assert get_version(tmp_path) == "latest"


class TestRewriteRepoLinks:
    """Tests for rewrite_repo_links()."""

    @pytest.fixture(autouse=True)
    def _set_github_blob(self):
        config.GITHUB_BLOB = "https://github.com/org/repo/blob/main"
        yield

    def test_rewrites_relative_link(self):
        content = "[changelog](../../../CHANGELOG.md)"
        result = rewrite_repo_links(content, ".github/actions/scanner-x/README.md")
        assert "https://github.com/org/repo/blob/main/CHANGELOG.md" in result

    def test_preserves_absolute_urls(self):
        content = "[docs](https://example.com/docs)"
        result = rewrite_repo_links(content, "README.md")
        assert result == content

    def test_preserves_anchor_links(self):
        content = "[section](#usage)"
        result = rewrite_repo_links(content, "README.md")
        assert result == content

    def test_preserves_template_expressions(self):
        content = "[link](${{ github.server_url }})"
        result = rewrite_repo_links(content, "README.md")
        assert result == content

    def test_preserves_mailto_links(self):
        content = "[email](mailto:test@example.com)"
        result = rewrite_repo_links(content, "README.md")
        assert result == content

    def test_handles_anchor_in_relative_link(self):
        content = "[section](../../docs/guide.md#setup)"
        result = rewrite_repo_links(content, ".github/actions/x/README.md")
        assert "#setup" in result
        assert "guide.md" in result

    def test_normalizes_parent_segments(self):
        content = "[file](../../../top-level.md)"
        result = rewrite_repo_links(content, "a/b/c/README.md")
        assert "top-level.md" in result
        # Should not have ../
        assert "../" not in result

    def test_rewrites_multiple_links(self):
        content = "[a](../x.md) and [b](../y.md)"
        result = rewrite_repo_links(content, "dir/README.md")
        assert result.count("https://github.com/org/repo/blob/main/") == 2
