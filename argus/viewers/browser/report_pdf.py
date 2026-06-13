"""HTML→PDF rendering for the formal report (Phase B4), behind ``[report]``.

The PDF is generated *server-side* (not via the browser's print dialog) so the
artifact is deterministic and one click away: same input scan → same document,
no per-browser print-CSS quirks. WeasyPrint is the engine — pure-Python, OSS
(BSD), no headless-browser dependency — but it pulls heavy native libraries
(Pango, cairo, …), so it lives behind the opt-in ``[report]`` extra rather than
in the base ``[browser]`` install.

The import is lazy and guarded: ``argus view browser`` runs fine without the
extra, and the ``/report.pdf`` route degrades to a friendly install hint while
the on-screen ``/report`` HTML view (printable via the browser, Cmd/Ctrl-P →
Save as PDF) stays fully available.
"""

from __future__ import annotations

from pathlib import Path

from argus.viewers import ViewerUnavailable

_INSTALL_HINT = (
    "The formal PDF report needs the 'report' extra. Install it with:\n"
    "    pip install 'argus-security[report]'\n"
    "Without it, open /report and use your browser's Print → Save as PDF."
)


def is_available() -> bool:
    """True when WeasyPrint can be imported (the ``[report]`` extra is in)."""
    try:
        import weasyprint  # noqa: F401
    except ImportError:
        return False
    return True


def render_pdf(html: str, *, stylesheet: str | Path, base_url: str) -> bytes:
    """Render *html* to PDF bytes using WeasyPrint + the report stylesheet.

    ``stylesheet`` is the on-disk path to ``report.css`` — passed explicitly
    rather than via the document's ``<link>`` so WeasyPrint never attempts an
    HTTP fetch (the served HTML omits the link in PDF mode). ``base_url``
    anchors any remaining relative references.

    Raises :class:`ViewerUnavailable` with an actionable hint when WeasyPrint
    is not installed, so callers surface a clean message instead of an
    ImportError traceback.
    """
    try:
        from weasyprint import CSS, HTML
    except ImportError as exc:  # pragma: no cover - exercised via is_available()
        raise ViewerUnavailable(_INSTALL_HINT) from exc

    document = HTML(string=html, base_url=base_url)
    return document.write_pdf(stylesheets=[CSS(filename=str(stylesheet))])
