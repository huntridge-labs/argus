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
        """Dump the currently visible findings to findings-export.csv."""
        import csv
        dest = Path("argus-findings-export.csv")
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
        self.notify(
            f"Exported {len(self._visible)} finding(s) → {dest}",
            severity="information", timeout=4,
        )


def run_app(results_dir: str | None = None) -> int:
    """Create + run the app. Returns the exit code."""
    app = BrowseApp(results_dir=results_dir)
    app.run()
    return app.return_code or 0
