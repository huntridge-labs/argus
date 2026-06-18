"""FastAPI application factory and uvicorn runner for ``argus view browser``.

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
import os
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from argus.viewers.browser.log_view import filter_entries, load_log
from argus.viewers.terminal.export import CONTENT_TYPES, RENDERERS
from argus.viewers.terminal.loader import RESULTS_FILENAME, flatten_findings, load_summary
from argus.core.run_discovery import (
    discover_runs as _collect_recent_scans,
    is_within as _is_within,
    list_directory as _list_directory,
)
from argus.core.findings_view import (
    ViewState,
    compute_summary,
    diff_scans,
    finding_detail_rows,
    unique_products,
    unique_scanners,
)
from argus.core.models import Severity
from argus.core import svg_charts, trends
from argus.core.enrichment import EnrichmentService, is_cve, risk_badge, risk_score


logger = logging.getLogger("argus.viewers.browser")

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
         Relaunch ``argus view browser`` with a broader path if you
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

        # No results anywhere under the target. Defer to the shared
        # diagnoser so the message identifies the likely root cause —
        # most often the user's argus.yml lists 'reporting.formats'
        # without 'json', so the previous scan never wrote the file
        # the viewers consume.
        from argus.viewers.diagnose import diagnose_missing_results
        return None, diagnose_missing_results(direct)

    return None, f"Unsupported path kind: {target}"


def _scan_metadata(scan_summary, resolved: Path | None) -> dict | None:
    """Extract the meta-panel shape from a loaded ScanSummary.

    Surfaces the pieces that are actually present in argus-results.json
    today (per-scanner tool version / duration / container image /
    digest + file mtime) plus optional fields like ``commit_sha`` that
    future scans may start emitting. Missing keys render as em-dashes
    in the template rather than failing the page.

    Returns None when no scan is loaded so the template can skip the
    panel entirely instead of showing an empty shell.
    """
    if scan_summary is None:
        return None

    scanners: list[dict] = []
    total_duration_ms = 0
    has_any_duration = False
    for r in scan_summary.results:
        md = getattr(r, "metadata", {}) or {}
        duration = md.get("duration_ms")
        if isinstance(duration, (int, float)):
            total_duration_ms += int(duration)
            has_any_duration = True
        scanners.append({
            "scanner": getattr(r, "scanner", None) or "unknown",
            "tool_version": md.get("tool_version"),
            "duration_ms": duration,
            "execution": md.get("execution"),   # "container" | "local" | None
            "image": md.get("image"),
            "digest": md.get("digest"),
            "total_count": getattr(r, "total_count", 0),
        })

    # File metadata — resolved is the actual argus-results.json path;
    # mtime is the closest approximation of "when was this scan run"
    # without relying on a top-level timestamp field we don't yet emit.
    scan_file = None
    scan_mtime = None
    if resolved is not None:
        scan_file = str(resolved)
        try:
            scan_mtime = resolved.stat().st_mtime
        except OSError:
            scan_mtime = None

    return {
        "scan_file": scan_file,
        "scan_mtime": scan_mtime,
        "scanner_count": len(scanners),
        "scanners": scanners,
        "total_duration_ms": total_duration_ms if has_any_duration else None,
    }


def _context_bar(scan_summary, resolved: Path | None) -> dict | None:
    """Persistent scan-context strip for the sticky bar under the header (B0 IA).

    Surfaces the identity of the scan currently in scope — project, source
    commit, when it ran, and the finding count — so that context follows the
    user down every primary view rather than living only on the dashboard.

    Returns ``None`` when no scan is loaded (picker, diff, error states) so the
    bar is simply omitted rather than rendering an empty shell. ``project`` is
    the repo-root (or cwd) basename when the scan recorded one, falling back to
    the results directory name.
    """
    if scan_summary is None:
        return None
    ctx = getattr(scan_summary, "scan_context", None)
    repo_root = (ctx.repo_root or ctx.cwd) if ctx else ""
    project = Path(repo_root).name if repo_root else (resolved.parent.name if resolved else "")
    mtime = None
    if resolved is not None:
        try:
            mtime = resolved.stat().st_mtime
        except OSError:
            mtime = None
    return {
        "project": project or "scan",
        "commit": (ctx.commit_sha[:7] if ctx and ctx.commit_sha else ""),
        "mtime": mtime,
        "total": scan_summary.total_count,
    }


# Plugin seam (open-core extension point). Third-party / enterprise packages
# register a ``register(app)`` callable under this entry-point group to add
# routes or capabilities to the browser viewer (e.g. a server-side PDF report).
# Mirrors the ``argus.reporters`` entry-point pattern. The OSS viewer ships no
# plugins, so this is a no-op by default.
_BROWSER_PLUGIN_GROUP = "argus.viewers.browser_plugins"


def _discover_browser_plugins() -> list:
    """Load ``register(app)`` callables from the browser-plugin entry-point group.

    A broken or missing entry point is logged and skipped — discovery never
    raises, so a bad plugin can't stop the viewer from starting.
    """
    from importlib.metadata import entry_points

    plugins: list = []
    try:
        eps = entry_points(group=_BROWSER_PLUGIN_GROUP)
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("browser plugin discovery failed: %s", exc)
        return plugins
    for ep in eps:
        try:
            plugins.append(ep.load())
        except Exception as exc:
            logger.warning("browser plugin '%s' failed to load: %s", ep.name, exc)
    return plugins


def _mount_browser_plugins(app: FastAPI, plugins: list | None) -> None:
    """Let installed plugins register extra routes/capabilities on ``app``.

    ``plugins`` is a list of ``register(app)`` callables; ``None`` discovers
    them via the ``argus.viewers.browser_plugins`` entry-point group. A plugin
    that raises is logged and skipped so one bad plugin can't take down the
    viewer. Plugins read ``app.state`` (notably ``root`` and ``load_scan``) and
    add routes via the FastAPI ``app`` (e.g. an add-on that generates a report).
    """
    if plugins is None:
        plugins = _discover_browser_plugins()
    for register in plugins:
        try:
            register(app)
        except Exception as exc:
            logger.warning("browser plugin failed to register: %s", exc)


def create_app(
    root: str | None = None,
    *,
    enrich: bool | None = None,
    enrichment_service: object | None = None,
    browser_plugins: list | None = None,
) -> FastAPI:
    """Build the FastAPI app, wire templates / static, register routes.

    ``enrich`` opts into the risk (EPSS / CISA KEV) + reachability columns
    (Phase B2). It is **off by default**, preserving the read-only /
    no-egress posture: only when enabled does the server reach the EPSS/KEV
    APIs or scan local source. ``None`` reads ``ARGUS_VIEW_ENRICH`` from the
    environment. ``enrichment_service`` is injectable for tests.

    ``browser_plugins`` is the extension seam: a list of ``register(app)``
    callables (``None`` discovers them via the ``argus.viewers.browser_plugins``
    entry-point group). OSS ships none; enterprise / third-party packages use it
    to add routes (e.g. the server-side PDF report). Injectable for tests.
    """
    app = FastAPI(
        title="Argus",
        description="Local read-only view of argus scan findings.",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
    )
    app.state.root = Path(root).resolve() if root else Path.cwd()
    app.state.enrich = (
        os.environ.get("ARGUS_VIEW_ENRICH", "").strip().lower() in ("1", "true", "yes")
        if enrich is None else bool(enrich)
    )
    app.state.enrichment_service = enrichment_service

    import time as _time
    templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))
    templates.env.globals["static_v"] = int(_time.time())
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

    def _base_context(resolved: Path | None = None, scan_summary=None) -> dict:
        """Shared context keys threaded into every HTML render.

        Recent scans power the header dropdown — always visible so
        switching runs is one click. ``resolved`` is the currently
        loaded scan (if any) so the dropdown can highlight it. Routes
        that don't have a single "current" scan (the picker, the diff
        view) pass ``None``; nothing is highlighted but the list still
        renders.

        ``scan_summary`` (when the route has already loaded one) feeds the
        sticky scan-context bar under the header — project / commit / scan
        time / finding count. Routes without a single loaded scan leave it
        ``None`` and the bar is omitted.
        """
        return {
            "recent_scans": _collect_recent_scans(app.state.root, resolved),
            "scan_context_bar": _context_bar(scan_summary, resolved),
        }

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

    def _dashboard_charts(
        findings: list, recent_scans: list[dict], *, total: int | None = None,
    ) -> dict:
        """Inline SVG charts for the dashboard (Phase B1).

        Dependency-free (``argus.core.svg_charts`` over ``argus.core.trends``
        data): a severity donut, a findings-over-time trend (from the run
        history that powers the header dropdown), and a by-scanner bar chart.
        ``total`` is the summary's authoritative finding count, shown in the
        donut centre so it always matches the "Total findings" card. The
        trend is omitted with fewer than two runs.
        """
        series = trends.run_count_series(recent_scans)
        return {
            "severity": svg_charts.severity_donut(
                trends.severity_breakdown(findings), size=180, center=total,
            ),
            "trend": svg_charts.trend_line(series, width=300, height=90) if len(series) >= 2 else "",
            "scanners": svg_charts.bar_chart(trends.scanner_breakdown(findings)[:6], width=340),
        }

    @app.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request, scan: str | None = None) -> Response:
        """Executive-summary dashboard for the active scan context.

        ``?scan=<path>`` overrides the launch root — makes the URL
        bookmarkable and lets the future picker hand off a chosen
        scan by pointing back at ``/?scan=...``.
        """
        scan_summary, resolved, error = _load_scan(scan)
        base = _base_context(resolved, scan_summary)
        summary = None
        charts = None
        if scan_summary is not None:
            findings = flatten_findings(scan_summary)
            summary = compute_summary(findings, top_n=3)
            charts = _dashboard_charts(
                findings, base.get("recent_scans") or [], total=summary.get("total"),
            )
        return templates.TemplateResponse(
            request=request,
            name="summary.html.j2",
            context={
                **base,
                "scan_param": scan,
                "scan_label": str(resolved) if resolved else None,
                "summary": summary,
                "charts": charts,
                "metadata": _scan_metadata(scan_summary, resolved),
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

    def _resolve_min_sev(raw: str | None) -> tuple[Severity | None, str | None]:
        """Translate a query-param severity string into the enum + hint.

        Unknown values fall back to None rather than 500-ing — user
        URLs are untrusted. When the caller passed something non-empty
        that we didn't recognize, we also return a short hint so the
        UI can quietly surface the fallback rather than leave the user
        wondering why their filter was ignored.
        """
        if not raw:
            return None, None
        try:
            enum_val = Severity.from_string(raw)
            if enum_val == Severity.UNKNOWN and raw.lower() != "unknown":
                return None, (
                    f"Unrecognized severity '{raw}' — showing all findings. "
                    "Valid: critical, high, medium, low, info."
                )
            return enum_val, None
        except (KeyError, ValueError):
            return None, f"Unrecognized severity '{raw}' — showing all findings."

    def _filter_and_sort(
        findings,
        *,
        min_severity: str | None,
        product: str | None,
        scanner: str | None,
        q: str | None,
        sort: str | None,
    ):
        """Apply the shared query-param filter + sort pipeline.

        Used by both ``/findings`` (render) and ``/export`` (serialize)
        so they operate on identical subsets — no format-specific
        filtering logic means copy/pasting a filter URL between the
        two endpoints is guaranteed to return matching data.
        """
        min_sev_enum, _hint = _resolve_min_sev(min_severity)
        active_sort = sort if sort in _ALLOWED_SORTS else "severity_desc"
        view_state = ViewState(
            min_severity=min_sev_enum,
            query=q or "",
            product=product or None,
            scanner=scanner or None,
            sort_key=active_sort,
        )
        matched = [f for f in findings if view_state.matches(f)]
        matched.sort(key=view_state.sort_key_fn(), reverse=view_state.sort_reverse)
        return matched

    def _build_risk_cells(findings: list) -> list:
        """Per-row risk (EPSS / CISA KEV) cells, aligned with ``findings``.

        Opt-in path only (``app.state.enrich``): fetches EPSS/CISA KEV for the
        CVEs in view (cached, offline-degrading). Returns a list the same
        length as ``findings`` (``None`` where a row has no CVE signal).

        Reachability is deliberately *not* surfaced here: it scans source
        files, which belongs in the trusted-shell terminal viewer (Phase 12),
        not the read-only browser. The browser stays read-only / no-source-scan.
        """
        cves = sorted({f.cve.upper() for f in findings if f.cve and is_cve(f.cve)})
        service = app.state.enrichment_service or EnrichmentService()
        risk_map = service.enrich(cves) if cves else {}
        cells: list = []
        for f in findings:
            enr = risk_map.get(f.cve.upper()) if f.cve else None
            if enr is None:
                cells.append(None)
                continue
            cells.append({
                "badge": risk_badge(enr),
                "score": round(risk_score(f.severity, enr) * 100),
            })
        return cells

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
            **_base_context(resolved, scan_summary),
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

            # Surface the severity hint when the caller passed a value
            # we didn't recognize; the helper also returns it so both
            # /findings and /export behave identically on bad input.
            _, severity_hint = _resolve_min_sev(min_severity)
            context["severity_hint"] = severity_hint

            matched = _filter_and_sort(
                all_findings,
                min_severity=min_severity,
                product=product,
                scanner=scanner,
                q=q,
                sort=active_sort,
            )
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
            # Risk (EPSS/KEV) + reachability columns — opt-in (Phase B2).
            context["enrich_on"] = app.state.enrich
            context["risk_cells"] = (
                _build_risk_cells(matched) if app.state.enrich else []
            )
        else:
            # No scan loaded → template paths that check show_columns
            # still need the dict keys to exist; default to True so
            # no branch throws on access during error-state rendering.
            context["show_columns"] = {"package": True, "fix": True, "sbom": True}
            context["enrich_on"] = False
            context["risk_cells"] = []

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

    @app.get("/export")
    async def export(
        scan: str | None = None,
        min_severity: str | None = None,
        product: str | None = None,
        scanner: str | None = None,
        q: str | None = None,
        sort: str | None = None,
        format: str = "csv",
        download: int = 0,
    ) -> Response:
        """Serialize the current filtered view to CSV / JSON / MD / SARIF.

        The filter query params mirror ``/findings`` exactly — filter
        on the web page, copy the URL, swap the prefix to ``/export``,
        done. ``?download=1`` sets a Content-Disposition: attachment
        header so the browser saves-to-disk; without it the response
        is inline (used by the Copy-to-clipboard JS which just reads
        the fetch body).

        Unknown ``format`` values return 400 rather than a default —
        silently substituting would mask a typo in the caller's URL.
        """
        if format not in RENDERERS:
            valid = ", ".join(sorted(RENDERERS.keys()))
            return Response(
                content=f"Unknown format '{format}'. Valid: {valid}.",
                status_code=400,
                media_type="text/plain; charset=utf-8",
            )

        scan_summary, resolved, error = _load_scan(scan)
        if scan_summary is None:
            return Response(
                content=f"No scan loaded: {error or 'unknown error'}",
                status_code=404,
                media_type="text/plain; charset=utf-8",
            )

        findings = _filter_and_sort(
            flatten_findings(scan_summary),
            min_severity=min_severity,
            product=product,
            scanner=scanner,
            q=q,
            sort=sort,
        )

        render_fn, ext = RENDERERS[format]
        body = render_fn(findings)

        headers = {}
        if download:
            # Timestamped + scope-labeled filename so repeat downloads
            # don't clobber; matches the make_export_path shape the
            # TUI uses.
            from datetime import datetime
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            scope_bits = [
                f"{k}-{v}" for k, v in [
                    ("sev", min_severity),
                    ("prod", product),
                    ("scanner", scanner),
                ] if v
            ]
            scope = "-".join(scope_bits) if scope_bits else "all"
            filename = f"argus-findings-{stamp}-{scope}.{ext}"
            headers["Content-Disposition"] = f'attachment; filename="{filename}"'

        return Response(
            content=body,
            media_type=CONTENT_TYPES[format],
            headers=headers,
        )

    @app.get("/diff", response_class=HTMLResponse)
    async def diff(
        request: Request,
        a: str | None = None,
        b: str | None = None,
    ) -> Response:
        """Compare two scans and render a new/fixed/changed/unchanged view.

        Both ``a`` and ``b`` are full paths (or paths into a run dir
        whose ``argus-results.json`` / ``latest/argus-results.json``
        we resolve the same way the dashboard does). The scope rule
        from _resolve_scan applies — trying to diff something outside
        the launch root fails with the standard error.

        Finding identity is (scanner, id, location); see
        argus.core.findings_view.diff_scans for the bucketing rules.
        """
        context = {
            **_base_context(None),
            "a_label": None,
            "b_label": None,
            "a_param": a,
            "b_param": b,
            "diff": None,
            "error": None,
            # Scope the breadcrumb bar to neither scan — diff is a
            # two-scan view, the header's single-scan crumb doesn't
            # apply here.
            "scan_param": None,
            "scan_label": None,
            "detail_rows": finding_detail_rows,
        }

        if not a or not b:
            context["error"] = (
                "Need both ?a= and ?b= to compare. Select two scans in "
                "the picker and click Compare selected."
            )
            return templates.TemplateResponse(
                request=request,
                name="diff.html.j2",
                context=context,
            )

        a_summary, a_path, a_err = _load_scan(a)
        b_summary, b_path, b_err = _load_scan(b)
        if a_err or b_err:
            # Join both errors so users see every reason loading failed
            # rather than chasing them one at a time.
            parts = [p for p in (a_err, b_err) if p]
            context["error"] = "Could not load scan(s): " + " | ".join(parts)
            return templates.TemplateResponse(
                request=request,
                name="diff.html.j2",
                context=context,
            )

        context["a_label"] = str(a_path) if a_path else a
        context["b_label"] = str(b_path) if b_path else b
        context["diff"] = diff_scans(
            flatten_findings(a_summary),
            flatten_findings(b_summary),
        )
        return templates.TemplateResponse(
            request=request,
            name="diff.html.j2",
            context=context,
        )

    # Whitelist for the ``?level=`` query param. Anything else is
    # silently treated as "no level filter" — same posture as the
    # findings route's severity handling. Stored uppercase so the
    # template can match against ``active_level`` directly.
    _VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}

    @app.get("/log", response_class=HTMLResponse)
    async def log_view(
        request: Request,
        scan: str | None = None,
        level: str | None = None,
        q: str | None = None,
    ) -> Response:
        """Read-only viewer for ``argus.log`` next to the active scan.

        Same shape as ``/findings``: filter bar (level + search), a
        scrollable monospace pane, and bookmarkable URL state. Logs
        live next to ``argus-results.json`` in the timestamped run
        dir, so resolving the scan also resolves the log path.
        """
        scan_summary, resolved, error = _load_scan(scan)
        log_data = load_log(resolved.parent) if resolved else None

        # Normalize the user-supplied level to our canonical set. The
        # short ``WARN`` form maps onto ``WARNING`` for parity with
        # Python's logging module — same as ``log_view._canonicalize_level``.
        active_level = (level or "").upper()
        if active_level == "WARN":
            active_level = "WARNING"
        if active_level not in _VALID_LOG_LEVELS:
            active_level = ""

        entries: list = []
        total = 0
        if log_data is not None:
            all_entries, _line_count = log_data
            total = len(all_entries)
            entries = filter_entries(
                all_entries,
                min_level=active_level or None,
                query=q,
            )

        return templates.TemplateResponse(
            request=request,
            name="log.html.j2",
            context={
                **_base_context(resolved, scan_summary),
                "scan_param": scan,
                "scan_label": str(resolved) if resolved else None,
                "log_available": log_data is not None,
                "entries": entries,
                "total_entries": total,
                "active_level": active_level,
                "query": q or "",
                "error": error,
            },
        )

    @app.get("/log/raw")
    async def log_raw(scan: str | None = None) -> Response:
        """Stream the raw ``argus.log`` file for offline analysis.

        Served as ``text/plain`` with a Content-Disposition attachment
        so the browser saves rather than rendering — easier to grep,
        diff, or paste into an issue. 404 when the log doesn't exist
        rather than a misleading empty 200.
        """
        _, resolved, _error = _load_scan(scan)
        if resolved is None:
            return Response("Scan not found.", status_code=404, media_type="text/plain")
        log_path = resolved.parent / "argus.log"
        if not log_path.exists():
            return Response("Log not found.", status_code=404, media_type="text/plain")
        return FileResponse(
            log_path,
            media_type="text/plain",
            filename=log_path.name,
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
                    **_base_context(None),
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
                    **_base_context(None),
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
                    **_base_context(None),
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
                **_base_context(None),
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

    # Plugin seam: expose the scan-resolution + report-render helpers that
    # extension packages build on (e.g. an add-on that generates a report
    # resolves the active scan via load_scan), then let installed plugins
    # register their routes. OSS ships no plugins, so this is a no-op by default.
    app.state.load_scan = _load_scan
    _mount_browser_plugins(app, browser_plugins)

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
        # [browse] extra (``argus.viewers.terminal.app._platform_opener_argv`` is
        # path-oriented and would mis-route a URL). Not fatal on failure
        # — uvicorn still prints the URL below.
        import webbrowser
        try:
            webbrowser.open(url, new=1)
        except Exception as exc:   # noqa: BLE001 — webbrowser can raise broadly on headless systems
            logger.debug("webbrowser.open failed: %s — skipping auto-open", exc)

    logger.info("argus view browser listening on %s (Ctrl+C to stop)", url)
    print(f"argus view browser listening on {url} — Ctrl+C to stop")

    try:
        uvicorn.run(app, host="127.0.0.1", port=port, log_level="info")
    except KeyboardInterrupt:
        return 0
    except OSError as exc:
        logger.error("uvicorn failed to bind: %s", exc)
        print(f"Error: uvicorn failed to bind on {url}: {exc}")
        return 2
    return 0
