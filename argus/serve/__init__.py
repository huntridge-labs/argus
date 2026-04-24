"""Local read-only web UI — ``argus serve``.

A FastAPI app bundled with the argus SDK that serves the same findings
as the argus-results.json produced by ``argus scan``. Scoped to a
single user on localhost — no auth system, no database, no mutations.
Intended for owners/managers/execs who want easy insight into their
products without digging through CI or learning a TUI.

Two front-ends share the renderer:
- TUI  (argus browse)      → Textual widgets wrapping finding_detail_rows
- Web  (argus serve, here) → Jinja templates consuming the same dict

Both read from argus.core.findings_view so filter/sort/summary logic
is identical across surfaces.

This package is optional: install with ``pip install argus-security[serve]``.
Importing it without the extra raises :class:`ServeUnavailable` with an
install hint rather than a bare ImportError.
"""

from __future__ import annotations


class ServeUnavailable(RuntimeError):
    """Raised when ``argus serve`` is invoked without the ``serve`` extra."""


def _require_web_stack() -> None:
    """Import-guard so the CLI can surface a friendly install hint.

    Three packages are load-bearing: FastAPI (the framework), Jinja2
    (templates), and uvicorn (ASGI server). python-multipart is pulled in
    transitively by FastAPI when we add form endpoints; surfacing it
    individually here makes the missing-dep error more actionable if
    that slips from an upstream change.
    """
    missing: list[str] = []
    for mod in ("fastapi", "jinja2", "uvicorn"):
        try:
            __import__(mod)
        except ImportError:
            missing.append(mod)
    if missing:
        raise ServeUnavailable(
            "The local web UI needs the 'serve' extra. "
            "Install it with: pip install 'argus-security[serve]' "
            f"(missing: {', '.join(missing)})"
        )


def launch(
    root: str | None = None,
    *,
    port: int = 8080,
    open_browser: bool = False,
) -> int:
    """Start the local argus serve web UI.

    Returns a process-style exit code suitable for ``sys.exit()``. The
    app module is imported lazily so importing ``argus.serve.launch``
    doesn't crash when FastAPI isn't installed.

    Binds to ``127.0.0.1`` only — localhost-only is the product shape
    (see argus/serve/app.py docstring). There is no ``--bind`` flag by
    design; if a future deployment needs network exposure, that's a
    separate design decision that requires auth etc.
    """
    _require_web_stack()
    from argus.serve.app import run_app
    return run_app(root=root, port=port, open_browser=open_browser)


__all__ = ["ServeUnavailable", "launch"]
