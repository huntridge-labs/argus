"""FastAPI application factory and uvicorn runner for ``argus serve``.

Phase SA shape: the app is created with a ``/healthz`` route only, so
the subcommand scaffolding, import-guard, and uvicorn invocation can be
exercised end-to-end before the dashboard / findings / picker routes
land in subsequent phases.

The app is deliberately bound to ``127.0.0.1``; there is no ``--bind``
flag by design. Localhost-only is the product shape — no auth, no
multi-user, no CSRF or session handling to implement. Any future
network-exposed deployment is a separate design decision.
"""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import JSONResponse


logger = logging.getLogger("argus.serve")


def create_app(root: str | None = None) -> FastAPI:
    """Build the FastAPI app, stashing the picker root path on app.state.

    ``root`` is the filesystem starting point for the picker: either a
    directory that will be used as-is, or a single argus-results.json
    that loads the dashboard immediately. Validation of the path (does
    it exist? is it a valid results file?) is deferred to route
    handlers in later phases so startup stays cheap.
    """
    app = FastAPI(
        title="Argus",
        description="Local read-only view of argus scan findings.",
        version="0.1.0",  # independent of argus SDK version
        docs_url=None,   # no /docs — this is a user-facing UI, not an API
        redoc_url=None,
    )
    app.state.root = Path(root).resolve() if root else Path.cwd()

    @app.get("/healthz")
    async def healthz() -> JSONResponse:
        """Liveness check. Returns the effective picker root.

        Handy for scripts that poll the server during startup and for
        smoke-testing the uvicorn binding behind a reverse proxy in
        the rare ``--bind`` case users set up themselves.
        """
        return JSONResponse({
            "status": "ok",
            "root": str(app.state.root),
        })

    return app


def run_app(
    *,
    root: str | None,
    port: int,
    open_browser: bool,
) -> int:
    """Create the app and serve it via uvicorn on ``127.0.0.1:<port>``.

    Returns 0 on a clean shutdown (Ctrl+C), 2 on an error during bind
    or serve. The ``open_browser`` flag opens the user's default
    browser at the server URL after uvicorn starts listening.
    """
    import uvicorn

    app = create_app(root=root)
    url = f"http://127.0.0.1:{port}"

    if open_browser:
        # ``webbrowser`` is stdlib, handles URL-vs-file dispatch and the
        # platform opener shell-out internally, and doesn't require the
        # [browse] extra (``argus.browse.app._platform_opener_argv`` is
        # path-oriented and would mis-route a URL). Not fatal on failure
        # — uvicorn still prints the URL below.
        import webbrowser
        try:
            webbrowser.open(url, new=1)
        except Exception as exc:   # noqa: BLE001 — webbrowser can raise broadly on headless systems
            logger.debug("webbrowser.open failed: %s — skipping auto-open", exc)

    logger.info("argus serve listening on %s (Ctrl+C to stop)", url)
    print(f"argus serve listening on {url} — Ctrl+C to stop")

    try:
        uvicorn.run(app, host="127.0.0.1", port=port, log_level="info")
    except KeyboardInterrupt:
        return 0
    except OSError as exc:
        logger.error("uvicorn failed to bind: %s", exc)
        print(f"Error: uvicorn failed to bind on {url}: {exc}")
        return 2
    return 0
