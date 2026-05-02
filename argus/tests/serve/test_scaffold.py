"""Phase SA tests for argus serve — package scaffolding.

Covers:
- CLI subcommand parsing and defaults
- Friendly ServeUnavailable error when the [serve] extra isn't installed
- /healthz route on the FastAPI app (skipped when extra not installed)

Route tests use httpx.AsyncClient via FastAPI's TestClient so they
don't need a live uvicorn; the full-stack uvicorn startup is exercised
manually during development and by CI integration tests later.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from argus.cli import build_parser, cmd_serve, EXIT_ERROR


class TestServeSubcommandParsing:
    def test_serve_default_args(self):
        parser = build_parser()
        args = parser.parse_args(["serve"])
        assert args.command == "serve"
        assert args.root is None
        assert args.port == 8080
        assert args.open_browser is False

    def test_serve_with_root_path(self):
        parser = build_parser()
        args = parser.parse_args(["serve", "/path/to/results"])
        assert args.root == "/path/to/results"

    def test_serve_custom_port(self):
        parser = build_parser()
        args = parser.parse_args(["serve", "--port", "9090"])
        assert args.port == 9090

    def test_serve_open_flag(self):
        parser = build_parser()
        args = parser.parse_args(["serve", "--open"])
        assert args.open_browser is True


class TestServeUnavailableFriendlyError:
    def test_missing_extra_returns_exit_error_and_prints_hint(self, capsys):
        """When FastAPI isn't installed, cmd_serve exits EXIT_ERROR with a hint."""
        from argus.serve import ServeUnavailable
        import argparse

        def fake_launch(**_kwargs):
            raise ServeUnavailable(
                "The local web UI needs the 'serve' extra. "
                "Install it with: pip install 'argus-security[serve]'"
            )

        with patch("argus.serve.launch", fake_launch):
            rc = cmd_serve(argparse.Namespace(
                root=None, port=8080, open_browser=False,
            ))
        assert rc == EXIT_ERROR
        err = capsys.readouterr().err
        assert "argus-security[serve]" in err


# ---------------------------------------------------------------------------
# Route tests — only meaningful when the [serve] extra is present.
# FastAPI's TestClient spins up the app without uvicorn.
# ---------------------------------------------------------------------------

fastapi = pytest.importorskip("fastapi")


class TestHealthzRoute:
    def test_healthz_returns_ok_and_root(self, tmp_path):
        from fastapi.testclient import TestClient
        from argus.serve.app import create_app

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
        from argus.serve.app import create_app

        monkeypatch.chdir(tmp_path)
        app = create_app(root=None)
        client = TestClient(app)
        resp = client.get("/healthz")
        assert resp.status_code == 200
        # Defaulting to cwd is what the picker starts navigating from
        # when the user launches `argus serve` with no path arg.
        assert str(tmp_path.resolve()) == resp.json()["root"]


class TestFaviconRoute:
    def test_favicon_served_as_png(self, tmp_path):
        # Browsers request /favicon.ico ahead of parsing <link rel="icon">;
        # the PNG we ship is served as image/png but reachable at the
        # traditional .ico URL so devtools stays quiet.
        from fastapi.testclient import TestClient
        from argus.serve.app import create_app

        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/favicon.ico")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "image/png"
        # Sanity: the PNG signature is the first 8 bytes.
        assert resp.content[:8] == b"\x89PNG\r\n\x1a\n"

    def test_base_template_links_favicon(self, tmp_path):
        from fastapi.testclient import TestClient
        from argus.serve.app import create_app

        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/")
        assert 'rel="icon"' in resp.text
        assert "/static/favicon.png" in resp.text
