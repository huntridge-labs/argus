"""Tests for the light/dark theme toggle.

The actual palette swap happens via CSS custom properties — these
tests assert the toggle button renders, the JS loads, and the CSS
contains both theme blocks. Runtime toggle behavior is JS-land
and covered by the live UI walkthrough rather than a headless unit.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient   # noqa: E402

from argus.serve.app import create_app   # noqa: E402


class TestThemeToggleUI:
    def test_toggle_button_renders_in_header(self, tmp_path):
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/")
        # Button with the theme-toggle class + id is in the header.
        assert 'id="theme-toggle"' in resp.text
        assert "theme-toggle" in resp.text
        # Accessible label is present so screen readers can announce it.
        assert 'aria-label="Toggle color theme"' in resp.text

    def test_toggle_script_loaded(self, tmp_path):
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/")
        assert "theme-toggle.js" in resp.text

    def test_toggle_renders_on_every_page(self, tmp_path):
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        for path in ("/", "/findings", "/picker"):
            resp = client.get(path)
            assert 'id="theme-toggle"' in resp.text, (
                f"theme toggle missing on {path}"
            )


class TestThemeCssBothVariants:
    """Both palette tokens must be in the stylesheet so the toggle
    can swap them at runtime. Each theme's deep-bg is the canary."""

    def test_dark_palette_present(self, tmp_path):
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/static/argus.css")
        # Dark palette is the :root default.
        assert "#0b0f0d" in resp.text
        # Explicit [data-theme="dark"] block also exists for users
        # who override a light OS preference.
        assert '[data-theme="dark"]' in resp.text

    def test_light_palette_present(self, tmp_path):
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/static/argus.css")
        # Light palette is anchored on these three tokens.
        assert "#f5f7f0" in resp.text  # light deep-bg
        assert '[data-theme="light"]' in resp.text
        # And auto-activates for users with a light OS preference.
        assert "prefers-color-scheme: light" in resp.text

    def test_on_accent_token_keeps_ctas_readable(self, tmp_path):
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/static/argus.css")
        # Both themes pin the CTA text color to argus-on-accent
        # (which stays dark in both themes) so lime buttons never
        # flip to low-contrast off-white on top of lime.
        assert "--argus-on-accent" in resp.text
        assert "color: var(--argus-on-accent)" in resp.text
