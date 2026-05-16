"""Terminal interface for ``argus view`` — Textual-based findings TUI.

A full-screen terminal app for triaging an argus scan result set.
Loads ``argus-results.json`` (produced by the ``json`` reporter) and
presents a two-pane layout: findings list on the left, selected-finding
detail on the right, plus keyboard-driven filter/sort/search.

Selected by ``argus view --interface=terminal`` (or simply
``argus view terminal``). Optional install:

    pip install 'argus-security[terminal]'

Importing this package without the ``textual`` extra raises
:class:`argus.viewers.ViewerUnavailable` with an actionable install
hint instead of a bare ``ImportError`` deep in the CLI stack.
"""

from __future__ import annotations

from argus.viewers import ViewerUnavailable


def _require_textual() -> None:
    """Import-guard so the CLI can surface a friendly message on missing deps."""
    try:
        import textual  # noqa: F401
    except ImportError as exc:
        raise ViewerUnavailable(
            "The terminal interface needs the 'terminal' extra. "
            "Install it with: pip install 'argus-security[terminal]'"
        ) from exc


def launch(results_dir: str | None = None) -> int:
    """Launch the terminal interface against ``results_dir``.

    Returns the process-style exit code suitable for ``sys.exit()``. The
    import of the app module is deferred so importing
    ``argus.viewers.terminal.launch`` doesn't crash when ``textual`` isn't
    installed.
    """
    _require_textual()
    from argus.viewers.terminal.app import run_app
    return run_app(results_dir)


__all__ = ["ViewerUnavailable", "launch"]
