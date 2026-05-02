"""Phase SA tests for the browser interface — package scaffolding.

Covers:
- ``argus view browser`` CLI parsing and defaults
- Friendly ``ViewerUnavailable`` error when the [browser] extra isn't installed
- /healthz route on the FastAPI app (skipped when extra not installed)

Route tests use httpx.AsyncClient via FastAPI's TestClient so they
don't need a live uvicorn; the full-stack uvicorn startup is exercised
manually during development and by CI integration tests later.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from argus.cli import build_parser, cmd_view, EXIT_ERROR


class TestViewBrowserSubcommandParsing:
    def test_view_browser_default_args(self):
        parser = build_parser()
        args = parser.parse_args(["view", "browser"])
        assert args.command == "view"
        assert args.interface_pos == "browser"
        assert args.path is None
        assert args.port == 8080
        # Auto-open is the default; the negative flag is opt-in.
        assert args.no_open is False

    def test_view_browser_with_path(self):
        parser = build_parser()
        args = parser.parse_args(["view", "browser", "/path/to/results"])
        assert args.interface_pos == "browser"
        assert args.path == "/path/to/results"

    def test_view_browser_custom_port(self):
        parser = build_parser()
        args = parser.parse_args(["view", "browser", "--port", "9090"])
        assert args.port == 9090

    def test_view_browser_no_open_flag(self):
        parser = build_parser()
        args = parser.parse_args(["view", "browser", "--no-open"])
        assert args.no_open is True

    def test_should_open_browser_respects_no_open(self):
        """`--no-open` always wins over the TTY default."""
        from argus.cli import _should_open_browser
        import argparse as _argparse
        ns = _argparse.Namespace(no_open=True)
        assert _should_open_browser(ns) is False

    def test_should_open_browser_defaults_to_false_under_capsys(self):
        """Under pytest's capsys, stdout isn't a TTY, so we don't auto-open."""
        from argus.cli import _should_open_browser
        import argparse as _argparse
        ns = _argparse.Namespace(no_open=False)
        # capsys captures stdout to a buffer with no isatty support — same
        # shape as a CI runner or a piped invocation.
        assert _should_open_browser(ns) is False

    def test_view_interface_flag_form(self):
        parser = build_parser()
        args = parser.parse_args(["view", "--interface=browser", "--port", "9090"])
        assert args.interface_flag == "browser"
        assert args.port == 9090


class TestBrowserViewerUnavailableFriendlyError:
    def test_missing_extra_returns_exit_error_and_prints_hint(self, capsys):
        """When FastAPI isn't installed, cmd_view exits EXIT_ERROR with a hint."""
        from argus.viewers.browser import ViewerUnavailable
        import argparse

        def fake_launch(**_kwargs):
            raise ViewerUnavailable(
                "The browser interface needs the 'browser' extra. "
                "Install it with: pip install 'argus-security[browser]'"
            )

        with patch("argus.viewers.browser.launch", fake_launch):
            rc = cmd_view(argparse.Namespace(
                interface_pos="browser",
                interface_flag=None,
                path=None,
                port=8080,
                no_open=True,
            ))
        assert rc == EXIT_ERROR
        err = capsys.readouterr().err
        assert "argus-security[browser]" in err


# ---------------------------------------------------------------------------
# Route tests — only meaningful when the [browser] extra is present.
# FastAPI's TestClient spins up the app without uvicorn.
# ---------------------------------------------------------------------------

fastapi = pytest.importorskip("fastapi")


class TestHealthzRoute:
    def test_healthz_returns_ok_and_root(self, tmp_path):
        from fastapi.testclient import TestClient
        from argus.viewers.browser.app import create_app

        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/healthz")
        assert resp.status_code == 200
        payload = resp.json()
        assert payload["status"] == "ok"
        # Root was resolved; TestClient gives us the absolute path.
        assert str(tmp_path.resolve()) == payload["root"]

    def test_healthz_defaults_root_to_cwd_when_none(self, tmp_path, monkeypatch):
        from fastapi.testclient import TestClient
        from argus.viewers.browser.app import create_app

        monkeypatch.chdir(tmp_path)
        app = create_app(root=None)
        client = TestClient(app)
        resp = client.get("/healthz")
        assert resp.status_code == 200
        # Defaulting to cwd is what the picker starts navigating from
        # when the user launches `argus view browser` with no path arg.
        assert str(tmp_path.resolve()) == resp.json()["root"]


class TestFaviconRoute:
    def test_favicon_served_as_png(self, tmp_path):
        # Browsers request /favicon.ico ahead of parsing <link rel="icon">;
        # the PNG we ship is served as image/png but reachable at the
        # traditional .ico URL so devtools stays quiet.
        from fastapi.testclient import TestClient
        from argus.viewers.browser.app import create_app

        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/favicon.ico")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "image/png"
        # Sanity: the PNG signature is the first 8 bytes.
        assert resp.content[:8] == b"\x89PNG\r\n\x1a\n"

    def test_base_template_links_favicon(self, tmp_path):
        from fastapi.testclient import TestClient
        from argus.viewers.browser.app import create_app

        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/")
        assert 'rel="icon"' in resp.text
        assert "/static/favicon.png" in resp.text
