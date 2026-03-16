"""Tests for docsite.categories — action categorization."""

from __future__ import annotations

from pathlib import Path

import pytest

from docsite import config
from docsite.categories import (
    ActionCategoryInfo,
    action_category,
    category_icon,
    category_label,
    get_categorized_actions,
    load_docsite_config,
)


@pytest.fixture(autouse=True)
def _load_config(tmp_repo: Path):
    """Ensure config is loaded before category tests."""
    config.load_site_config(tmp_repo)
    yield


class TestLoadDocsiteConfig:
    """Tests for load_docsite_config()."""

    def test_loads_valid_config(self, tmp_repo: Path):
        action_dir = tmp_repo / ".github" / "actions" / "scanner-bandit"
        info = load_docsite_config(action_dir)

        assert info is not None
        assert info.category == "sast"
        assert info.sidebar_label is None

    def test_with_sidebar_label(self, tmp_path: Path):
        action_dir = tmp_path / "my-action"
        action_dir.mkdir()
        (action_dir / ".docsite.yml").write_text(
            "category: sast\nsidebar_label: My Custom Label\n",
        )

        info = load_docsite_config(action_dir)
        assert info is not None
        assert info.category == "sast"
        assert info.sidebar_label == "My Custom Label"

    def test_missing_file_returns_none(self, tmp_path: Path):
        action_dir = tmp_path / "no-config"
        action_dir.mkdir()

        assert load_docsite_config(action_dir) is None

    def test_invalid_yaml_returns_none(self, tmp_path: Path):
        action_dir = tmp_path / "bad-yaml"
        action_dir.mkdir()
        (action_dir / ".docsite.yml").write_text(": : {{{\n")

        assert load_docsite_config(action_dir) is None

    def test_missing_category_key_returns_none(self, tmp_path: Path):
        action_dir = tmp_path / "no-category"
        action_dir.mkdir()
        (action_dir / ".docsite.yml").write_text("sidebar_label: Foo\n")

        assert load_docsite_config(action_dir) is None

    def test_empty_file_returns_none(self, tmp_path: Path):
        action_dir = tmp_path / "empty"
        action_dir.mkdir()
        (action_dir / ".docsite.yml").write_text("")

        assert load_docsite_config(action_dir) is None


class TestActionCategory:
    """Tests for action_category()."""

    def test_returns_category_from_docsite_yml(self, tmp_repo: Path):
        actions_dir = tmp_repo / ".github" / "actions"
        assert action_category("scanner-bandit", actions_dir) == "sast"

    def test_returns_other_when_no_config(self, tmp_repo: Path):
        actions_dir = tmp_repo / ".github" / "actions"
        # comment-pr has no .docsite.yml
        assert action_category("comment-pr", actions_dir) == "other"

    def test_returns_other_for_nonexistent_action(self, tmp_repo: Path):
        actions_dir = tmp_repo / ".github" / "actions"
        assert action_category("nonexistent", actions_dir) == "other"


class TestGetCategorizedActions:
    """Tests for get_categorized_actions()."""

    def test_groups_actions_by_category(self, tmp_repo: Path):
        actions_dir = tmp_repo / ".github" / "actions"
        result = get_categorized_actions(actions_dir)

        assert "sast" in result
        assert "scanner-bandit" in result["sast"]
        assert "secrets" in result
        assert "scanner-gitleaks" in result["secrets"]

    def test_excludes_excluded_actions(self, tmp_repo: Path):
        actions_dir = tmp_repo / ".github" / "actions"
        result = get_categorized_actions(actions_dir)

        all_actions = [a for actions in result.values() for a in actions]
        assert "comment-pr" not in all_actions

    def test_actions_sorted_within_category(self, tmp_repo: Path):
        actions_dir = tmp_repo / ".github" / "actions"
        # Add another sast action
        zz_dir = actions_dir / "scanner-aaa"
        zz_dir.mkdir()
        (zz_dir / ".docsite.yml").write_text("category: sast\n")

        result = get_categorized_actions(actions_dir)
        assert result["sast"] == ["scanner-aaa", "scanner-bandit"]

    def test_empty_categories_excluded(self, tmp_repo: Path):
        actions_dir = tmp_repo / ".github" / "actions"
        result = get_categorized_actions(actions_dir)

        for cat, members in result.items():
            assert len(members) > 0


class TestCategoryHelpers:
    """Tests for category_label() and category_icon()."""

    def test_known_category_label(self):
        assert category_label("sast") == "SAST"

    def test_unknown_category_label_fallback(self):
        assert category_label("unknown-cat") == "Unknown Cat"

    def test_known_category_icon(self):
        assert category_icon("sast") == "🔍"

    def test_unknown_category_icon_fallback(self):
        assert category_icon("unknown-cat") == "🆕"
