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
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from argus.browse.loader import RESULTS_FILENAME, flatten_findings, load_summary
from argus.core.findings_view import (
    ViewState,
    compute_summary,
    finding_detail_rows,
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
# if the meta tag gets dropped. Every style lives in static/argus.css;
# we deliberately drop 'unsafe-inline' for style-src so a future
# template edit that re-introduces an inline style= will fail loudly
# in devtools rather than silently loosen the policy.
_CSP = "default-src 'self'; style-src 'self'; script-src 'self'"


def _is_within(child: Path, root: Path) -> bool:
    """Return True if ``child`` is ``root`` itself or a descendant of it.

    Both paths must already be resolved (symlinks followed, absolute).
    Uses ``relative_to`` rather than string-prefix matching so we don't
    false-positive on ``/foo-bar`` when the root is ``/foo``.
    """
    try:
        child.relative_to(root)
    except ValueError:
        return False
    return True


def _resolve_scan(
    raw: str | None,
    *,
    launch_root: Path,
) -> tuple[Path | None, str | None]:
    """Return ``(results_file_path, error_message)`` for a scan reference.

    Resolution rules, applied in order:
      1. If the caller supplied a path (via ``?scan=...``), use it.
         Otherwise fall back to the server's launch root.
      2. Reject anything that resolves outside ``launch_root`` — this
         is a read-only localhost UI, but a cross-site GET could still
         poke the filesystem for file-existence oracles otherwise.
         Relaunch ``argus serve`` with a broader ``--root`` if you
         genuinely need access to a wider tree.
      3. If the resolved path is a file → use it as-is.
      4. If it's a directory:
         a. ``<dir>/argus-results.json`` exists → load it.
         b. ``<dir>/latest/argus-results.json`` exists → load it.
            This matches ``argus scan``'s own output convention:
            scans write to a timestamped subdir like
            ``argus-results/2026-04-24T14-54-13Z/`` and maintain a
            ``latest`` symlink pointing at it. Users pointing ``argus
            serve`` at the parent ``argus-results/`` directory expect
            the latest run to load automatically.
         c. Any subdir has an ``argus-results.json`` directly inside
            → error message nudges to the picker (multiple choices —
            we don't want to pick for the user).
         d. Else → plain "no scan here" error.
      5. If it's neither file nor directory → error.

    ``(None, "reason")`` tells the route to render the empty-state
    placeholder with an actionable message.
    """
    target = Path(raw).expanduser() if raw else launch_root
    try:
        target = target.resolve()
    except OSError as exc:
        return None, f"Could not resolve path: {exc}"

    if not _is_within(target, launch_root):
        return None, (
            f"Path is outside the scan root ({launch_root}). "
            "Relaunch with a broader --root to access wider trees."
        )

    if not target.exists():
        return None, f"Path does not exist: {target}"

    if target.is_file():
        return target, None

    if target.is_dir():
        # 3a. Direct hit on the scan JSON.
        direct = target / RESULTS_FILENAME
        if direct.is_file():
            return direct, None

        # 3b. ``latest/`` fallback — argus scan maintains this symlink
        # (or directory) as part of its default output layout.
        latest_child = target / "latest" / RESULTS_FILENAME
        if latest_child.is_file():
            return latest_child.resolve(), None

        # 3c. Parent-of-runs case: the user pointed at a directory
        # whose subdirs each hold a run. We don't auto-pick which
        # one — too many ways that goes wrong (most recent by mtime
        # vs. filename, symlink chasing, etc.) — but we tell the
        # user where to go.
        subdirs_with_results = [
            d for d in target.iterdir()
            if d.is_dir() and (d / RESULTS_FILENAME).is_file()
        ]
        if subdirs_with_results:
            return None, (
                f"No {RESULTS_FILENAME} directly inside {target}, but "
                f"{len(subdirs_with_results)} subdir(s) contain one. "
                f"Use the picker to choose a specific run."
            )

        return None, (
            f"No {RESULTS_FILENAME} inside {target}. "
            "Pick a results directory or pass a specific JSON path via ?scan=..."
        )

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

        Referrer-Policy: scan paths and filter state travel through
        query params. We don't want those leaking to external sites
        when the user clicks the footer link out, so set the policy
        to ``no-referrer`` rather than the browser default.
        """
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = _CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.get("/healthz")
    async def healthz() -> JSONResponse:
        return JSONResponse({
            "status": "ok",
            "root": str(app.state.root),
        })

    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon() -> Response:
        # Browsers hit /favicon.ico on the first page load before
        # parsing <link rel="icon">, so route it here instead of
        # letting the 404 show up in devtools for every session.
        # The PNG is served with image/png; browsers accept this
        # even though the path ends in .ico.
        return FileResponse(_STATIC_DIR / "favicon.png", media_type="image/png")

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

    # Sort keys the findings route accepts. A crafted URL with a
    # non-whitelisted value quietly falls back to the default; we
    # never surface a 500 for a bad query string. Mapping lives next
    # to the route so it stays in view during review.
    _ALLOWED_SORTS = {
        "severity_asc", "severity_desc",
        "id", "id_desc",
        "location", "location_desc",
        "scanner", "scanner_desc",
    }

    @app.get("/findings", response_class=HTMLResponse)
    async def findings(
        request: Request,
        scan: str | None = None,
        min_severity: str | None = None,
        product: str | None = None,
        scanner: str | None = None,
        q: str | None = None,
        sort: str | None = None,
        partial: int = 0,
    ) -> Response:
        """Filterable findings table.

        Every filter is a query param so the URL is bookmarkable and
        the page stays refresh-safe. Filtering happens through the
        shared ``ViewState`` so the server's idea of "match" and the
        TUI's are identical — one source of truth for severity / query
        / product / scanner semantics.
        """
        scan_summary, resolved, error = _load_scan(scan)
        # Clamp sort to the allowlist or fall back to the default so a
        # typo in the URL doesn't bubble into KeyError territory.
        active_sort = sort if sort in _ALLOWED_SORTS else "severity_desc"
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
                "sort": active_sort,
            },
            "products": [],
            "scanners": [],
            "visible": [],
            "total": 0,
            "severity_hint": None,
            # Expose the shared detail-row builder to the template so
            # the disclosure <details> inside each row renders the same
            # fields the TUI's detail pane does. Using the function
            # directly keeps the two front-ends in lockstep — both read
            # from finding_detail_rows(f) and neither invents its own
            # formatting.
            "detail_rows": finding_detail_rows,
        }
        if scan_summary is not None:
            all_findings = flatten_findings(scan_summary)
            context["total"] = len(all_findings)
            context["products"] = unique_products(all_findings)
            context["scanners"] = unique_scanners(all_findings)

            # Translate the ``min_severity`` string to the enum used by
            # ViewState. An unknown value falls back to None (no filter)
            # rather than 500-ing — user-supplied URLs are untrusted.
            # If the value was non-empty but didn't parse, surface a
            # quiet hint so the user knows why they got back the
            # unfiltered set.
            min_sev_enum = None
            severity_hint = None
            if min_severity:
                try:
                    min_sev_enum = Severity.from_string(min_severity)
                    if min_sev_enum == Severity.UNKNOWN and min_severity.lower() != "unknown":
                        min_sev_enum = None
                        severity_hint = (
                            f"Unrecognized severity '{min_severity}' — "
                            "showing all findings. Valid: critical, high, "
                            "medium, low, info."
                        )
                except (KeyError, ValueError):
                    min_sev_enum = None
                    severity_hint = (
                        f"Unrecognized severity '{min_severity}' — "
                        "showing all findings."
                    )
            context["severity_hint"] = severity_hint

            view_state = ViewState(
                min_severity=min_sev_enum,
                query=q or "",
                product=product or None,
                scanner=scanner or None,
                sort_key=active_sort,
            )
            matched = [f for f in all_findings if view_state.matches(f)]
            matched.sort(key=view_state.sort_key_fn(), reverse=view_state.sort_reverse)
            context["visible"] = matched

            # Auto-hide columns that are empty for every visible row.
            # Bandit, lint-* and SAST scanners never emit package /
            # fix / sbom_source — showing an all-em-dash column for
            # them is just visual noise. When any visible row has
            # content for a column we keep it, so mixed-scanner runs
            # still show every column that anyone uses.
            context["show_columns"] = {
                "package": any(f.metadata.get("package") for f in matched),
                "fix": any(f.metadata.get("fixed_version") for f in matched),
                "sbom": any(f.metadata.get("sbom_source") for f in matched),
            }
        else:
            # No scan loaded → template paths that check show_columns
            # still need the dict keys to exist; default to True so
            # no branch throws on access during error-state rendering.
            context["show_columns"] = {"package": True, "fix": True, "sbom": True}

        # ?partial=1 returns just the table fragment for auto-filter.js
        # to swap in, skipping the layout. Non-JS clients never set it
        # and get the full render. Sharing the context dict + the
        # _findings_table.html.j2 partial keeps the two paths in lockstep.
        template_name = (
            "_findings_table.html.j2" if partial else "findings.html.j2"
        )
        return templates.TemplateResponse(
            request=request,
            name=template_name,
            context=context,
        )

    @app.get("/picker", response_class=HTMLResponse)
    async def picker(
        request: Request,
        path: str | None = None,
        show_hidden: int = 0,
    ) -> Response:
        """Lightweight file-browser picker.

        One directory level at a time — explicitly not recursive, per
        the SD scoping decision. Users navigate by clicking into
        subdirs; each listed entry is flagged scan-ready when it
        contains an ``argus-results.json`` directly inside it, so
        nested results show up as one-click targets without us doing
        a full filesystem walk.
        """
        base = Path(path).expanduser() if path else app.state.root
        try:
            base = base.resolve()
        except OSError as exc:
            return templates.TemplateResponse(
                request=request,
                name="picker.html.j2",
                context={
                    "current": str(base),
                    "parent": None,
                    "entries": [],
                    "error": f"Cannot resolve path: {exc}",
                    "has_results": False,
                    "show_hidden": bool(show_hidden),
                    "scan_param": None,
                    "scan_label": None,
                },
            )

        # Keep the picker scoped to the launch root for the same
        # reason _resolve_scan is: this is a localhost-only tool but
        # a crafted cross-site GET could otherwise probe the filesystem
        # (directory listings, finding-count peeks on argus-results.json
        # files outside the root). Relaunching with a broader --root is
        # the escape hatch.
        if not _is_within(base, app.state.root):
            return templates.TemplateResponse(
                request=request,
                name="picker.html.j2",
                context={
                    "current": str(app.state.root),
                    "parent": None,
                    "entries": [],
                    "error": (
                        f"{base} is outside the scan root "
                        f"({app.state.root}). Relaunch with a broader "
                        "--root to navigate wider trees."
                    ),
                    "has_results": False,
                    "show_hidden": bool(show_hidden),
                    "scan_param": None,
                    "scan_label": None,
                },
            )

        if not base.exists() or not base.is_dir():
            return templates.TemplateResponse(
                request=request,
                name="picker.html.j2",
                context={
                    "current": str(base),
                    "parent": None,
                    "entries": [],
                    "error": (
                        f"{base} is not a directory. "
                        "Pick a folder; individual JSON files can be loaded "
                        "via the dashboard URL (?scan=...)."
                    ),
                    "has_results": False,
                    "show_hidden": bool(show_hidden),
                    "scan_param": None,
                    "scan_label": None,
                },
            )

        entries, error = _list_directory(base, show_hidden=bool(show_hidden))
        has_results = (base / RESULTS_FILENAME).is_file()

        # Only offer a "..  parent directory" link when the parent is
        # still inside the launch root. Stepping up past the root would
        # immediately hit the scope error above, so suppress the link
        # rather than offering a dead end.
        parent = base.parent if base.parent != base else None
        if parent is not None and not _is_within(parent, app.state.root):
            parent = None

        return templates.TemplateResponse(
            request=request,
            name="picker.html.j2",
            context={
                "current": str(base),
                "parent": str(parent) if parent is not None else None,
                "entries": entries,
                "error": error,
                "has_results": has_results,
                "show_hidden": bool(show_hidden),
                # Picker isn't scoped to a loaded scan — clear the header
                # breadcrumb so users don't think they're still in scan
                # context while they're actively switching away from it.
                "scan_param": None,
                "scan_label": None,
            },
        )

    return app


# Common noise in argus workflows; hidden from the default picker listing
# but surfaced via ``?show_hidden=1`` when the user actually needs to dig.
_HIDDEN_BY_DEFAULT = {
    "node_modules", ".git", ".venv", "venv", "__pycache__",
    ".tox", ".pytest_cache", ".mypy_cache",
}


def _list_directory(
    base: Path,
    *,
    show_hidden: bool,
) -> tuple[list[dict], str | None]:
    """Return ``(entries, error)`` for picker consumption.

    Each entry dict carries:
      - ``name``    : bare filename
      - ``path``    : absolute path (string, ready for URL encoding)
      - ``is_dir``  : True if it's a directory
      - ``is_results_file`` : True if it's named argus-results.json
      - ``has_results``    : True if it's a directory that contains
                             argus-results.json directly inside
      - ``finding_count``  : total findings if has_results (cheap
                             read — one open+json.load) else None

    Directories first, then files, alphabetical within each group.
    Readability trumps performance here: picker content is interactive
    and users wait at the rendering boundary, so we do the small I/O
    that makes the status column useful.
    """
    import json as _json
    try:
        raw = sorted(base.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
    except PermissionError as exc:
        return [], f"Permission denied: {exc}"
    except OSError as exc:
        return [], f"Could not list directory: {exc}"

    entries: list[dict] = []
    for item in raw:
        name = item.name
        # Filter rules: hide dotfiles and the well-known build/cache
        # directories unless the user explicitly opted in.
        if not show_hidden and (
            name.startswith(".") or name in _HIDDEN_BY_DEFAULT
        ):
            continue

        is_dir = item.is_dir()
        is_results_file = not is_dir and name == RESULTS_FILENAME

        has_results = False
        finding_count = None
        if is_dir:
            candidate = item / RESULTS_FILENAME
            if candidate.is_file():
                has_results = True
                # Peek at the finding count so the picker row can
                # advertise scan size — users picking among dated
                # scan dirs can see which one had activity worth
                # looking at. Best-effort only; a parse failure
                # reduces to "no count shown" rather than erroring.
                try:
                    data = _json.loads(candidate.read_text(encoding="utf-8"))
                    finding_count = sum(
                        len(r.get("findings", []))
                        for r in data.get("results", [])
                    )
                except (OSError, _json.JSONDecodeError, TypeError):
                    finding_count = None

        entries.append({
            "name": name,
            "path": str(item),
            "is_dir": is_dir,
            "is_results_file": is_results_file,
            "has_results": has_results,
            "finding_count": finding_count,
        })

    return entries, None


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
