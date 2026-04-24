"""Interactive findings browser — ``argus browse``.

A Textual-based TUI for triaging an argus scan result set. Loads
``argus-results.json`` (produced by the ``json`` reporter) and presents
a two-pane layout: findings list on the left, selected-finding detail
on the right, plus keyboard-driven filter/sort/search.

This package is optional: install with ``pip install argus-security[browse]``.
Importing ``argus.browse`` without the ``textual`` extra raises
``BrowseUnavailable`` with an actionable install hint instead of a
bare ``ImportError`` deep in the CLI stack.
"""

from __future__ import annotations


class BrowseUnavailable(RuntimeError):
    """Raised when ``argus browse`` is invoked without the ``browse`` extra."""


def _require_textual():
    """Import-guard so the CLI can surface a friendly message on missing deps."""
    try:
        import textual  # noqa: F401
    except ImportError as exc:
        raise BrowseUnavailable(
            "The interactive findings browser needs the 'browse' extra. "
            "Install it with: pip install 'argus-security[browse]'"
        ) from exc


def launch(results_dir: str | None = None) -> int:
    """Launch the browse TUI against ``results_dir``.

    Returns the process-style exit code suitable for ``sys.exit()``. The
    import of the app module is deferred so importing
    ``argus.browse.launch`` doesn't crash when ``textual`` isn't installed.
    """
    _require_textual()
    from argus.browse.app import run_app
    return run_app(results_dir)


__all__ = ["BrowseUnavailable", "launch"]
