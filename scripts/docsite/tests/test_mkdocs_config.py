"""Tests for docsite.mkdocs_config — MkDocs configuration generation."""

from __future__ import annotations

import yaml

from docsite.mkdocs_config import build_mkdocs_config


class TestBuildMkdocsConfig:
    """Tests for build_mkdocs_config()."""

    def test_returns_valid_yaml(self):
        result = build_mkdocs_config("1.0.0", [{"Home": "index.md"}])
        # The mermaid fence_code_format line uses !!python/name which
        # can't be safe_loaded, so check structure manually
        assert "site_name: Argus Docs" in result

    def test_includes_version_provider(self):
        result = build_mkdocs_config("1.0.0", [])
        assert "mike" in result

    def test_includes_material_theme(self):
        result = build_mkdocs_config("1.0.0", [])
        assert "name: material" in result

    def test_includes_nav(self):
        nav = [{"Home": "index.md"}, {"Guide": "guide.md"}]
        result = build_mkdocs_config("1.0.0", nav)
        assert "Home" in result
        assert "Guide" in result

    def test_includes_mermaid_fence_config(self):
        result = build_mkdocs_config("1.0.0", [])
        assert "custom_fences:" in result
        assert "name: mermaid" in result
        assert "fence_code_format" in result

    def test_includes_dark_light_palette(self):
        result = build_mkdocs_config("1.0.0", [])
        assert "prefers-color-scheme: light" in result
        assert "prefers-color-scheme: dark" in result

    def test_includes_custom_css(self):
        result = build_mkdocs_config("1.0.0", [])
        assert "assets/custom.css" in result

    def test_includes_search_plugin(self):
        result = build_mkdocs_config("1.0.0", [])
        assert "search" in result

    def test_includes_code_copy_feature(self):
        result = build_mkdocs_config("1.0.0", [])
        assert "content.code.copy" in result

    def test_includes_navigation_features(self):
        result = build_mkdocs_config("1.0.0", [])
        assert "navigation.tabs" in result
        assert "navigation.top" in result
        # ``navigation.instant`` is intentionally absent — it swaps
        # article content via fetch but doesn't re-run inline scripts,
        # so the architecture page (which bootstraps from an inline
        # ``<script>``) renders blank on first nav until a reload.
        assert "navigation.instant" not in result
