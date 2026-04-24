"""FastAPI application factory and uvicorn runner for ``argus serve``.

Phase SB shape: ``/`` renders the executive-summary dashboard when a
scan is in scope (either the launch root pointed at an
``argus-results.json`` directly, or the request's ``?scan=<path>``
query param resolves to one). ``/healthz`` stays for liveness checks.

The app is deliberately bound to ``127.0.0.1``; there is no ``--bind``
flag by design. Localhost-only is the product shape — no auth, no
multi-user, no CSRF or session handling to implement. Any future
network-exposed deployment is a separate design decision.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from argus.browse.loader import RESULTS_FILENAME, flatten_findings, load_summary
from argus.core.findings_view import (
    ViewState,
    compute_summary,
    unique_products,
    unique_scanners,
)
from argus.core.models import Severity


logger = logging.getLogger("argus.serve")

_SERVE_DIR = Path(__file__).resolve().parent
_TEMPLATES_DIR = _SERVE_DIR / "templates"
_STATIC_DIR = _SERVE_DIR / "static"

# Strict CSP — matches the <meta http-equiv> tag in base.html.j2. Kept
# in sync at both layers so the protection doesn't silently evaporate
# if the meta tag gets dropped.
_CSP = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'"


def _resolve_scan(
    raw: str | None,
    *,
    launch_root: Path,
) -> tuple[Path | None, str | None]:
    """Return ``(results_file_path, error_message)`` for a scan reference.

    Resolution rules:
      1. If the caller supplied a path (via ``?scan=...``), use it.
      2. Otherwise fall back to the server's launch root.
      3. If the resolved path points at a directory, look for
         ``argus-results.json`` inside it.
      4. If the resolved path is a file, use it as-is.
      5. If nothing matches, return ``(None, "reason")`` so the view
         can render the empty-state placeholder with an actionable
         error.
    """
    target = Path(raw).expanduser() if raw else launch_root
    try:
        target = target.resolve()
    except OSError as exc:
        return None, f"Could not resolve path: {exc}"

    if not target.exists():
        return None, f"Path does not exist: {target}"

    if target.is_dir():
        candidate = target / RESULTS_FILENAME
        if candidate.is_file():
            return candidate, None
        return None, (
            f"No {RESULTS_FILENAME} inside {target}. "
            "Pick a results directory or pass a specific JSON path via ?scan=..."
        )

    if target.is_file():
        return target, None

    return None, f"Unsupported path kind: {target}"


def create_app(root: str | None = None) -> FastAPI:
    """Build the FastAPI app, wire templates / static, register routes."""
    app = FastAPI(
        title="Argus",
        description="Local read-only view of argus scan findings.",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
    )
    app.state.root = Path(root).resolve() if root else Path.cwd()

    templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))
    app.state.templates = templates
    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

    @app.middleware("http")
    async def _csp_headers(request: Request, call_next):
        """Attach the CSP + click-jacking headers to every response.

        Belt-and-suspenders: the base template also sets a CSP via
        ``<meta http-equiv>``, but headers are the primary defense
        (they apply to non-HTML responses and can't be stripped by a
        downstream template edit).
        """
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = _CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    @app.get("/healthz")
    async def healthz() -> JSONResponse:
        return JSONResponse({
            "status": "ok",
            "root": str(app.state.root),
        })

    def _load_scan(scan: str | None) -> tuple[object, Path | None, str | None]:
        """Shared scan-loading helper used by every view route.

        Returns ``(scan_summary, resolved_path, error_message)``. Exactly
        one of summary and error_message is populated — callers use that
        to decide between rendering data and the empty-state placeholder.
        """
        results_path, error = _resolve_scan(scan, launch_root=app.state.root)
        if error is not None:
            return None, None, error
        try:
            scan_summary, resolved = load_summary(results_path)
            return scan_summary, resolved, None
        except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
            return None, None, str(exc)

    @app.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request, scan: str | None = None) -> Response:
        """Executive-summary dashboard for the active scan context.

        ``?scan=<path>`` overrides the launch root — makes the URL
        bookmarkable and lets the future picker hand off a chosen
        scan by pointing back at ``/?scan=...``.
        """
        scan_summary, resolved, error = _load_scan(scan)
        summary = None
        if scan_summary is not None:
            summary = compute_summary(flatten_findings(scan_summary), top_n=3)
        return templates.TemplateResponse(
            request=request,
            name="summary.html.j2",
            context={
                "scan_param": scan,
                "scan_label": str(resolved) if resolved else None,
                "summary": summary,
                "error": error,
            },
        )

    @app.get("/findings", response_class=HTMLResponse)
    async def findings(
        request: Request,
        scan: str | None = None,
        min_severity: str | None = None,
        product: str | None = None,
        scanner: str | None = None,
        q: str | None = None,
    ) -> Response:
        """Filterable findings table.

        Every filter is a query param so the URL is bookmarkable and
        the page stays refresh-safe. Filtering happens through the
        shared ``ViewState`` so the server's idea of "match" and the
        TUI's are identical — one source of truth for severity / query
        / product / scanner semantics.
        """
        scan_summary, resolved, error = _load_scan(scan)
        context = {
            "scan_param": scan,
            "scan_label": str(resolved) if resolved else None,
            "summary": scan_summary,
            "error": error,
            "view": {
                "min_severity": min_severity,
                "product": product,
                "scanner": scanner,
                "query": q,
            },
            "products": [],
            "scanners": [],
            "visible": [],
            "total": 0,
        }
        if scan_summary is not None:
            all_findings = flatten_findings(scan_summary)
            context["total"] = len(all_findings)
            context["products"] = unique_products(all_findings)
            context["scanners"] = unique_scanners(all_findings)

            # Translate the ``min_severity`` string to the enum used by
            # ViewState. An unknown value falls back to None (no filter)
            # rather than 500-ing — user-supplied URLs are untrusted.
            min_sev_enum = None
            if min_severity:
                try:
                    min_sev_enum = Severity.from_string(min_severity)
                    if min_sev_enum == Severity.UNKNOWN and min_severity.lower() != "unknown":
                        min_sev_enum = None
                except (KeyError, ValueError):
                    min_sev_enum = None

            view_state = ViewState(
                min_severity=min_sev_enum,
                query=q or "",
                product=product or None,
                scanner=scanner or None,
            )
            context["visible"] = [
                f for f in all_findings if view_state.matches(f)
            ]

        return templates.TemplateResponse(
            request=request,
            name="findings.html.j2",
            context=context,
        )

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
