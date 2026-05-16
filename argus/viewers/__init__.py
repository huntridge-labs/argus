"""Argus viewer packages — terminal and browser interfaces.

The ``argus view`` CLI command dispatches to one of two viewer
implementations under this package:

- ``argus.viewers.terminal``: full-screen Textual TUI (``--interface=terminal``)
- ``argus.viewers.browser``: localhost FastAPI web UI (``--interface=browser``)

Both surfaces share the UI-free findings logic in ``argus.core.findings_view``
so filter/sort/summary behavior matches across them.

Each viewer is an *optional* extra:

- ``pip install 'argus-security[terminal]'`` for the terminal interface
- ``pip install 'argus-security[browser]'`` for the browser interface

Importing a viewer without its extra raises :class:`ViewerUnavailable`
with an actionable install hint instead of a bare ``ImportError`` deep
in the CLI stack.
"""

from __future__ import annotations


class ViewerUnavailable(RuntimeError):
    """Raised when a viewer is invoked without its required extra.

    Replaces the v0.x ``BrowseUnavailable`` and ``ServeUnavailable``
    classes. The message includes the specific install command for the
    missing interface so the user can act on the error directly.
    """


__all__ = ["ViewerUnavailable"]
