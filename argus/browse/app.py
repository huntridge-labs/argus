"""Textual app for interactive findings browsing.

Two-pane layout:
  - Left  (DataTable): list of findings, filterable by severity and query
  - Right (Static):    detail view of the currently selected finding
  - Footer:            key-binding hints and active filter / sort status

Keyboard shortcuts (bindings defined on the App class so they appear in
the footer automatically):
  j / k         — move down / up in the findings list
  / (slash)     — focus the search input
  1 / 2 / 3 / 4 — filter to CRITICAL / HIGH+ / MEDIUM+ / ALL severities
  s             — cycle sort (severity desc, severity asc, package, id)
  e             — export the currently filtered view to CSV
  q             — quit
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.command import Hit, Hits, Provider
from textual.containers import Container, Horizontal, Vertical
from textual.reactive import reactive
from textual.widgets import DataTable, Footer, Header, Input, Static

from argus.browse.loader import flatten_findings, load_summary
from argus.core.models import Finding, Severity


_SEVERITY_ORDER = [
    Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
    Severity.LOW, Severity.INFO, Severity.UNKNOWN,
]
_SEVERITY_GLYPH = {
    Severity.CRITICAL: "🚨 CRIT",
    Severity.HIGH:     "⚠️  HIGH",
    Severity.MEDIUM:   "🟡 MED ",
    Severity.LOW:      "🔵 LOW ",
    Severity.INFO:     "ℹ️  INFO",
    Severity.UNKNOWN:  "❓ ??? ",
}

# Human-readable labels for each sort mode, surfaced both in the notify
# toast on `s` and in the column header arrow. Keep in lockstep with
# ``ViewState.sort_key_fn()`` below.
_SORT_LABELS = {
    "severity_desc": "Severity (high → low)",
    "severity_asc":  "Severity (low → high)",
    "package":       "Package (A → Z)",
    "id":            "Finding ID",
}


@dataclass
class ViewState:
    """Filter + sort selections applied to the finding list."""

    min_severity: Severity | None = None  # None = all
    query: str = ""
    sort_key: str = "severity_desc"

    def matches(self, f: Finding) -> bool:
        """True when the finding satisfies the current filter."""
        if self.min_severity is not None and f.severity < self.min_severity:
            return False
        if self.query:
            haystack = " ".join([
                f.id or "",
                f.title or "",
                f.location or "",
                f.cve or "",
                f.scanner or "",
            ]).lower()
            if self.query.lower() not in haystack:
                return False
        return True

    def sort_key_fn(self):
        """Return a comparator-ready key function for the current sort.

        Python's ``sorted()`` is ascending; for severity DESC (highest
        severity first) we rely on ``_SEVERITY_ORDER`` already being in
        descending order (CRITICAL at index 0) so the natural index
        yields the right ordering. Secondary key: finding id, for
        deterministic output when two findings share a severity.
        """
        if self.sort_key == "severity_desc":
            return lambda f: (
                _SEVERITY_ORDER.index(f.severity) if f.severity in _SEVERITY_ORDER else 99,
                f.id,
            )
        if self.sort_key == "severity_asc":
            return lambda f: (
                -_SEVERITY_ORDER.index(f.severity) if f.severity in _SEVERITY_ORDER else -99,
                f.id,
            )
        if self.sort_key == "package":
            return lambda f: ((f.location or "").lower(), f.id)
        return lambda f: (f.id, f.severity.value)


class ArgusBrowseCommands(Provider):
    """Expose the browse app's actions in Textual's Ctrl+P command palette.

    Without this, the palette only shows framework builtins (Keys,
    Maximize, Quit, Screenshot, Theme) — useful but not the commands
    a user actually wants to find by name. Each entry yields a
    ``Hit`` whose callback invokes the matching ``action_*`` method
    on the BrowseApp so palette-driven invocations are identical to
    key-bound ones.
    """

    async def search(self, query: str) -> Hits:
        matcher = self.matcher(query)
        app = self.app
        # (label, help text, action callable) — keep in sync with BINDINGS.
        commands = [
            ("Search findings",          "Focus the search box", app.action_focus_search),
            ("Filter: Critical only",    "Show only CRITICAL findings", app.action_filter_critical),
            ("Filter: High severity and above", "Show HIGH + CRITICAL findings", app.action_filter_high),
            ("Filter: Medium severity and above", "Show MEDIUM + HIGH + CRITICAL findings", app.action_filter_medium),
            ("Filter: All severities",   "Clear the severity filter", app.action_filter_all),
            ("Sort: Cycle sort mode",    "Cycle severity desc → asc → package → id", app.action_cycle_sort),
            ("Export: CSV of current view", "Write the filtered findings to a timestamped CSV", app.action_export_csv),
            ("Open: Last export",        "Open the last export with the system's default app", app.action_open_last_export),
            ("Reveal: Last export",      "Show the last export in the OS file manager", app.action_reveal_last_export),
        ]
        for label, help_text, callback in commands:
            score = matcher.match(label)
            if score > 0:
                yield Hit(
                    score,
                    matcher.highlight(label),
                    callback,
                    help=help_text,
                )


class SearchInput(Input):
    """Search box that returns focus to the findings table on ESC.

    Textual's default Input binding for ``escape`` is blur-only, so
    users get stranded in the search box until they click elsewhere.
    We hard-bind ``escape`` to shift focus back to the DataTable so a
    single keystroke drops the user back into navigation.
    """

    BINDINGS = [
        Binding("escape", "back_to_table", "Back to list", show=False),
    ]

    def action_back_to_table(self) -> None:
        table = self.app.query_one(DataTable)
        table.focus()


class FindingDetail(Static):
    """Right pane — plain-text detail view for the selected finding."""

    def update_finding(self, f: Finding | None) -> None:
        if f is None:
            self.update("[dim]Select a finding to see details.[/dim]")
            return
        fix = f.metadata.get("fixed_version") or "—"
        pkg = f.metadata.get("package") or "—"
        installed = f.metadata.get("installed_version") or "—"
        sbom_source = f.metadata.get("sbom_source") or "—"
        warning = f.metadata.get("warning")
        lines = [
            f"[bold]{f.id}[/bold]   {_SEVERITY_GLYPH.get(f.severity, '?')}",
            "",
            f"[b]Scanner:[/b]   {f.scanner or '—'}",
            f"[b]CVE:[/b]       {f.cve or '—'}",
            f"[b]CWE:[/b]       {f.cwe or '—'}",
            f"[b]Package:[/b]   {pkg} @ {installed}",
            f"[b]Fix:[/b]       {fix}",
            f"[b]Location:[/b]  {f.location or '—'}",
            f"[b]SBOM:[/b]      {sbom_source}",
            "",
            "[b]Title[/b]",
            f.title or "—",
        ]
        if f.description and f.description != f.title:
            lines += ["", "[b]Description[/b]", f.description]
        if warning:
            lines += ["", f"[yellow]{warning}[/yellow]"]
        self.update("\n".join(lines))


class BrowseApp(App):
    """Main Textual app — loads findings, wires filters, renders panes."""

    # Merge our custom command provider with Textual's defaults (Keys,
    # Maximize, Quit, Screenshot, Theme) so the Ctrl+P palette finds
    # both argus-specific and framework-level commands.
    COMMANDS = App.COMMANDS | {ArgusBrowseCommands}

    CSS = """
    Screen { layout: vertical; }
    #search { height: 3; }
    #body { layout: horizontal; }
    #list-pane { width: 55%; }
    #detail-pane { width: 45%; padding: 0 2; }
    DataTable { height: 1fr; }
    Static#detail { height: 1fr; border: solid $accent; padding: 1 2; }
    #status { height: 1; dock: bottom; background: $panel; padding: 0 1; }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("slash", "focus_search", "Search", show=True, key_display="/"),
        Binding("1", "filter_critical", "Crit only"),
        Binding("2", "filter_high", "High+"),
        Binding("3", "filter_medium", "Med+"),
        Binding("4", "filter_all", "All"),
        Binding("s", "cycle_sort", "Sort"),
        Binding("e", "export_csv", "Export"),
        Binding("o", "open_last_export", "Open export"),
        Binding("r", "reveal_last_export", "Reveal in files"),
        Binding("j", "cursor_down", "Down", show=False),
        Binding("k", "cursor_up", "Up", show=False),
    ]

    results_path: reactive[str] = reactive("")

    def __init__(self, results_dir: str | None):
        super().__init__()
        self._results_dir = results_dir
        self.all_findings: list[Finding] = []
        self.view_state = ViewState()
        self._visible: list[Finding] = []

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        yield SearchInput(
            placeholder="Search (id, title, location, CVE, scanner)… ESC to return to list",
            id="search",
        )
        with Container(id="body"):
            with Vertical(id="list-pane"):
                yield DataTable(id="findings", cursor_type="row", zebra_stripes=True)
            with Vertical(id="detail-pane"):
                yield FindingDetail(id="detail")
        yield Static(id="status")
        yield Footer()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def on_mount(self) -> None:
        self.title = "argus browse"
        try:
            summary, resolved = load_summary(self._results_dir)
        except (FileNotFoundError, ValueError) as exc:
            self.exit(message=f"\n{exc}\n", return_code=1)
            return
        self.sub_title = str(resolved)
        self.all_findings = flatten_findings(summary)
        table = self.query_one(DataTable)
        # Column keys are kept so we can re-label the active sort column
        # with an arrow glyph whenever the sort cycles.
        self._col_keys = table.add_columns(
            "Sev", "ID", "Package@Version", "Scanner", "Location",
        )
        self._refresh_list()
        self._update_sort_indicator()

    # ------------------------------------------------------------------
    # Filter / sort / search
    # ------------------------------------------------------------------

    def _refresh_list(self) -> None:
        """Rebuild the DataTable + status bar from the current view state."""
        table = self.query_one(DataTable)
        table.clear()
        self._visible = sorted(
            (f for f in self.all_findings if self.view_state.matches(f)),
            key=self.view_state.sort_key_fn(),
        )
        for f in self._visible:
            pkg = f.metadata.get("package")
            installed = f.metadata.get("installed_version")
            pkg_label = f"{pkg}@{installed}" if pkg else (f.location or "—")
            table.add_row(
                _SEVERITY_GLYPH.get(f.severity, "?"),
                f.id[:36],
                pkg_label[:36],
                f.scanner or "—",
                (f.location or "—")[:40],
            )
        self._update_status()
        if self._visible:
            table.cursor_coordinate = (0, 0)
            self._update_detail(0)
        else:
            self.query_one("#detail", FindingDetail).update_finding(None)

    def _update_status(self) -> None:
        total = len(self.all_findings)
        shown = len(self._visible)
        sev_label = (
            f"≥ {self.view_state.min_severity.value}"
            if self.view_state.min_severity else "all severities"
        )
        query = f" · query='{self.view_state.query}'" if self.view_state.query else ""
        sort = self.view_state.sort_key.replace("_", " ")
        self.query_one("#status", Static).update(
            f"[b]{shown}[/b] / {total} findings · filter: {sev_label}{query} · sort: {sort}"
        )

    def _update_detail(self, row: int) -> None:
        if 0 <= row < len(self._visible):
            self.query_one("#detail", FindingDetail).update_finding(self._visible[row])

    # ------------------------------------------------------------------
    # Event hooks
    # ------------------------------------------------------------------

    def on_data_table_row_highlighted(self, event) -> None:  # pragma: no cover
        self._update_detail(event.cursor_row)

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "search":
            self.view_state.query = event.value
            self._refresh_list()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        # Enter in the search box — hand focus back to the findings table
        # so keyboard shortcuts keep working without another tab press.
        if event.input.id == "search":
            self.query_one(DataTable).focus()

    # ------------------------------------------------------------------
    # Actions (keyboard bindings)
    # ------------------------------------------------------------------

    def action_focus_search(self) -> None:
        self.query_one("#search", Input).focus()

    def action_filter_critical(self) -> None:
        self.view_state.min_severity = Severity.CRITICAL
        self._refresh_list()

    def action_filter_high(self) -> None:
        self.view_state.min_severity = Severity.HIGH
        self._refresh_list()

    def action_filter_medium(self) -> None:
        self.view_state.min_severity = Severity.MEDIUM
        self._refresh_list()

    def action_filter_all(self) -> None:
        self.view_state.min_severity = None
        self._refresh_list()

    def action_cycle_sort(self) -> None:
        order = ["severity_desc", "severity_asc", "package", "id"]
        i = order.index(self.view_state.sort_key)
        self.view_state.sort_key = order[(i + 1) % len(order)]
        self._refresh_list()
        self._update_sort_indicator()
        # Toast on every press so the user sees the new mode without
        # having to hunt the status bar on each cycle.
        self.notify(
            f"Sorted by {_SORT_LABELS[self.view_state.sort_key]}",
            severity="information", timeout=2,
        )

    def _update_sort_indicator(self) -> None:
        """Append ↓/↑ to the active sort column's header label.

        DataTable allows updating a column's ``label`` via its
        internal Column object. We restore the base labels on every
        call so switching columns leaves no stale indicator behind.
        """
        table = self.query_one(DataTable)
        base_labels = ["Sev", "ID", "Package@Version", "Scanner", "Location"]
        # When running under stubbed textual in tests, columns may be
        # an empty mapping or missing; bail silently so the test path
        # (which only exercises view-state logic) stays green.
        if not getattr(self, "_col_keys", None):
            return
        arrow_col = None
        arrow_glyph = ""
        if self.view_state.sort_key == "severity_desc":
            arrow_col, arrow_glyph = 0, " ↓"
        elif self.view_state.sort_key == "severity_asc":
            arrow_col, arrow_glyph = 0, " ↑"
        elif self.view_state.sort_key == "package":
            arrow_col, arrow_glyph = 2, " ↓"
        elif self.view_state.sort_key == "id":
            arrow_col, arrow_glyph = 1, " ↓"
        for idx, key in enumerate(self._col_keys):
            try:
                col = table.columns[key]
            except (KeyError, TypeError):
                continue
            label = base_labels[idx]
            if idx == arrow_col:
                label += arrow_glyph
            col.label = label

    def action_cursor_down(self) -> None:
        self.query_one(DataTable).action_cursor_down()

    def action_cursor_up(self) -> None:
        self.query_one(DataTable).action_cursor_up()

    def action_export_csv(self) -> None:
        """Dump the currently visible findings to a timestamped CSV.

        The filename includes a timestamp plus the active severity
        filter so repeated exports don't clobber each other and so the
        filename itself reveals what's inside. The toast shows the
        absolute path plus a ``file://`` URI that most modern
        terminals (iTerm2, WezTerm, VS Code, Windows Terminal)
        auto-linkify, and remembers the path for the ``o`` key which
        opens the file via the platform's native opener.
        """
        import csv
        from datetime import datetime

        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        scope = (
            self.view_state.min_severity.value
            if self.view_state.min_severity else "all"
        )
        dest = Path(f"argus-findings-{stamp}-{scope}.csv").resolve()
        with open(dest, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow([
                "severity", "id", "cve", "scanner",
                "package", "installed_version", "fixed_version",
                "location", "title", "sbom_source",
            ])
            for f in self._visible:
                writer.writerow([
                    f.severity.value, f.id, f.cve or "", f.scanner or "",
                    f.metadata.get("package", ""),
                    f.metadata.get("installed_version", ""),
                    f.metadata.get("fixed_version", ""),
                    f.location or "", f.title or "",
                    f.metadata.get("sbom_source", ""),
                ])
        self._last_export_path = dest
        uri = dest.as_uri()
        self.notify(
            f"Exported {len(self._visible)} finding(s) to:\n"
            f"{dest}\n"
            f"{uri}\n"
            f"Press [b]o[/b] to open with default app · "
            f"[b]r[/b] to reveal in file manager.",
            severity="information",
            timeout=12,
        )

    def action_open_last_export(self) -> None:
        """Open the most recent export with the platform's default app.

        macOS → ``open`` (hands off to the file's default handler —
        .csv opens in Numbers / Excel / LibreOffice depending on
        what's registered). Linux → ``xdg-open``. Windows → ``start``.
        When nothing has been exported yet, or the file has been
        deleted out from under us, we toast a friendly reminder
        rather than erroring out.
        """
        self._spawn_with_opener(
            mode="open",
            no_export_msg="No export yet. Press [b]e[/b] to export the current filter first.",
            unavailable_msg="No known opener for this platform. File: {path}",
            success_msg="Opening {name}…",
        )

    def action_reveal_last_export(self) -> None:
        """Reveal the most recent export in the OS file manager.

        macOS → ``open -R`` (Finder with the file selected).
        Windows → ``explorer /select,<path>`` (same experience).
        Linux → there's no universal "select in file manager" verb,
        so we open the containing directory with ``xdg-open`` —
        most users can find the file visually from there.
        """
        self._spawn_with_opener(
            mode="reveal",
            no_export_msg="No export yet. Press [b]e[/b] to export the current filter first.",
            unavailable_msg="No known file-manager command for this platform. File: {path}",
            success_msg="Revealing {name} in file manager…",
        )

    def _spawn_with_opener(
        self,
        *,
        mode: str,
        no_export_msg: str,
        unavailable_msg: str,
        success_msg: str,
    ) -> None:
        """Shared plumbing for open/reveal — validates, spawns, toasts."""
        path = getattr(self, "_last_export_path", None)
        if not path or not Path(path).exists():
            self.notify(no_export_msg, severity="warning", timeout=4)
            return
        argv = _platform_opener_argv(mode, Path(path))
        if argv is None:
            self.notify(unavailable_msg.format(path=path), severity="warning", timeout=6)
            return
        import subprocess
        try:
            subprocess.Popen(
                argv,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            self.notify(
                success_msg.format(name=path.name, path=path),
                severity="information", timeout=2,
            )
        except OSError as exc:
            self.notify(
                f"Couldn't launch opener ({exc}). File: {path}",
                severity="error", timeout=8,
            )


def _platform_opener_argv(mode: str, path: Path) -> list[str] | None:
    """Return the subprocess argv for ``open``/``reveal`` on this platform.

    ``mode="open"``    — hand the file to its default application.
    ``mode="reveal"``  — show the file (or containing folder) in the
                         OS file manager. On Linux there's no standard
                         "highlight this file" verb across file
                         managers, so we open the parent directory.

    Returns ``None`` when we don't know how to service the request on
    this platform. Callers shell out via ``Popen(argv)`` — never a
    shell string — so paths with spaces or quotes are safe.
    """
    import sys
    p = str(path)
    if sys.platform == "darwin":
        if mode == "open":
            return ["open", p]
        if mode == "reveal":
            return ["open", "-R", p]        # reveal in Finder
    elif sys.platform.startswith("linux"):
        if mode == "open":
            return ["xdg-open", p]
        if mode == "reveal":
            # No portable "select file" action across file managers;
            # opening the parent directory is the lowest-common
            # denominator for "show me where this lives."
            return ["xdg-open", str(path.parent)]
    elif sys.platform == "win32":
        if mode == "open":
            # ``start`` is a cmd builtin; the empty "" is the window-
            # title positional that ``start`` requires.
            return ["cmd", "/c", "start", "", p]
        if mode == "reveal":
            return ["explorer", f"/select,{p}"]
    return None


# Backwards-compat shim for tests that imported the prior helper. Kept
# so existing unit tests stay meaningful without a rewrite; the new
# code path uses _platform_opener_argv instead.
def _platform_opener() -> tuple[str | None, list[str]]:
    """Legacy shape: ``(command, extra_args_before_path)`` for mode='open'.

    Prefer ``_platform_opener_argv`` in new call sites — it handles
    both open and reveal, and returns the full argv so callers never
    reconstruct it.
    """
    import sys
    if sys.platform == "darwin":
        return "open", []
    if sys.platform.startswith("linux"):
        return "xdg-open", []
    if sys.platform == "win32":
        return "cmd", ["/c", "start", ""]
    return None, []


def run_app(results_dir: str | None = None) -> int:
    """Create + run the app. Returns the exit code."""
    app = BrowseApp(results_dir=results_dir)
    app.run()
    return app.return_code or 0
