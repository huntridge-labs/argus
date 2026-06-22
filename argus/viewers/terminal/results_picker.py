"""Pure row formatting for the terminal viewer's results picker.

The picker is a filesystem browser the findings viewer opens when it can't
resolve a scan in the launch directory, and on demand (the ``o`` key) to load
results from another project. The Textual ``OptionList`` that renders it lives
in ``app.py``; everything here is pure string/id work over the entries
``argus.core.run_discovery.list_directory`` produces, so it's unit-testable
without Textual.

Each row's option id encodes what selecting it *does*, so the screen doesn't
need to re-stat the filesystem to decide:

    ``__up__``        → go to the parent directory
    ``dir::<path>``   → descend into a plain directory
    ``load::<path>``  → load this scan (a results-bearing dir or the file)

Only directories and ``argus-results.json`` files are shown — other files are
noise for a "find me a scan" picker.
"""

from __future__ import annotations

UP_ID = "__up__"
_DIR_PREFIX = "dir::"
_LOAD_PREFIX = "load::"


def picker_rows(entries: list[dict], *, include_parent: bool) -> list[tuple[str, str]]:
    """Return ``[(option_id, display)]`` for one directory level.

    ``entries`` is a ``list_directory`` result. ``include_parent`` adds a
    ``..`` row (omitted at a filesystem root). Directories that directly
    contain a scan — and ``argus-results.json`` files — become ``load::``
    rows (with a finding-count peek); plain directories become ``dir::``
    rows the screen descends into. Everything else is dropped.
    """
    rows: list[tuple[str, str]] = []
    if include_parent:
        rows.append((UP_ID, "📁  .."))
    for entry in entries:
        path = entry.get("path", "")
        name = entry.get("name", "")
        if entry.get("is_results_file"):
            rows.append((f"{_LOAD_PREFIX}{path}", f"📄  {name}   [dim]· scan results[/dim]"))
        elif entry.get("is_dir"):
            if entry.get("has_results"):
                count = entry.get("finding_count")
                tag = f"{count} findings" if count is not None else "scan"
                rows.append((f"{_LOAD_PREFIX}{path}", f"📁  {name}/   [green]● {tag}[/green]"))
            else:
                rows.append((f"{_DIR_PREFIX}{path}", f"📁  {name}/"))
        # non-dir, non-results files are intentionally skipped
    return rows


def decode_id(option_id: str | None) -> tuple[str, str | None]:
    """Decode a picker option id into ``(action, path)``.

    ``action`` is ``"up"``, ``"dir"``, ``"load"``, or ``"none"`` (for an
    unrecognised / placeholder id). ``path`` is ``None`` for ``up`` / ``none``.
    """
    if not option_id:
        return "none", None
    if option_id == UP_ID:
        return "up", None
    if option_id.startswith(_DIR_PREFIX):
        return "dir", option_id[len(_DIR_PREFIX):]
    if option_id.startswith(_LOAD_PREFIX):
        return "load", option_id[len(_LOAD_PREFIX):]
    return "none", None
