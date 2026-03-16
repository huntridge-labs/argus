"""MkDocs configuration generator."""

from __future__ import annotations

import yaml


def build_mkdocs_config(version: str, nav: list) -> str:
    """Generate mkdocs.yml content for an Argus documentation site."""
    config = {
        "site_name": "Argus Docs",
        "site_description": (
            "OSS-first GitHub Actions security hardening — Huntridge Labs"
        ),
        "site_url": "https://huntridge-labs.github.io/argus/",
        "repo_url": "https://github.com/huntridge-labs/argus",
        "repo_name": "huntridge-labs/argus",
        "edit_uri": "edit/main/docs/",
        "theme": {
            "name": "material",
            "logo": "assets/HL.png",
            "favicon": "assets/argus-no-bg.png",
            "palette": [
                {
                    "media": "(prefers-color-scheme: light)",
                    "scheme": "default",
                    "primary": "black",
                    "accent": "deep orange",
                    "toggle": {
                        "icon": "material/weather-night",
                        "name": "Switch to dark mode",
                    },
                },
                {
                    "media": "(prefers-color-scheme: dark)",
                    "scheme": "slate",
                    "primary": "black",
                    "accent": "deep orange",
                    "toggle": {
                        "icon": "material/weather-sunny",
                        "name": "Switch to light mode",
                    },
                },
            ],
            "features": [
                "navigation.instant",
                "navigation.tabs",
                "navigation.tabs.sticky",
                "navigation.sections",
                "navigation.expand",
                "navigation.path",
                "navigation.top",
                "search.suggest",
                "search.highlight",
                "content.code.copy",
                "content.code.annotate",
                "toc.follow",
            ],
            "font": {"text": "Inter", "code": "JetBrains Mono"},
        },
        "plugins": ["search"],
        "markdown_extensions": [
            "admonition",
            "pymdownx.details",
            "pymdownx.superfences",
            "pymdownx.highlight",
            "pymdownx.inlinehilite",
            "pymdownx.tabbed",
            "pymdownx.snippets",
            "attr_list",
            "md_in_html",
            "tables",
            "toc",
        ],
        "extra": {
            "version": {"provider": "mike", "default": "latest"},
            "social": [
                {
                    "icon": "fontawesome/brands/github",
                    "link": "https://github.com/huntridge-labs/argus",
                },
            ],
        },
        "extra_css": ["assets/custom.css"],
        "nav": nav,
    }
    output = yaml.dump(
        config, default_flow_style=False, allow_unicode=True, sort_keys=False,
    )
    # Replace pymdownx.superfences with custom_fences config for Mermaid.
    # PyYAML can't serialise !!python/name: tags, so we do it via string replacement.
    output = output.replace(
        "- pymdownx.superfences\n",
        "- pymdownx.superfences:\n"
        "    custom_fences:\n"
        "      - name: mermaid\n"
        "        class: mermaid\n"
        "        format: !!python/name:pymdownx.superfences.fence_code_format\n",
    )
    return output
