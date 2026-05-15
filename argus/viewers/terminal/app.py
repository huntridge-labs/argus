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
  space         — toggle selection on the focused row
  a             — select every row in the current filter
  A (shift+a)   — clear all selections
  e             — export the currently filtered view (or the selection) to CSV
  C (shift+c)   — copy CVE IDs of selected findings to the clipboard
  q             — quit
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.command import Hit, Hits, Provider
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import DataTable, Footer, Header, Input, OptionList, Static
from textual.widgets.option_list import Option

from argus.viewers.terminal import mouse_actions
from argus.viewers.terminal.loader import flatten_findings, load_summary
from argus.core.config import ArgusConfig, ViewConfig
from argus.core.findings_view import (
    SEVERITY_GLYPH,
    SEVERITY_ORDER,
    SORT_LABELS,
    ViewState,
    compute_summary,
    diff_scans,
    finding_detail_rows,
    unique_products,
    unique_scanners,
)
from argus.core.models import Finding, Severity


# Module-local aliases preserved so downstream tests that introspected the
# old private names still work. New code should import from
# ``argus.core.findings_view``.
_SEVERITY_ORDER = SEVERITY_ORDER
_SEVERITY_GLYPH = SEVERITY_GLYPH
_SORT_LABELS = SORT_LABELS


# ViewState lives in argus.core.findings_view now — imported at the top
# of this module — so the TUI and the future web UI share one filter/sort
# implementation. The alias kept here retains backwards compat for any
# test that monkeypatched ``argus.viewers.terminal.app.ViewState``.


_HELP_TEXT = """\
[b]argus view (terminal)[/b] — interactive findings triage

[b]Navigate[/b]
  [b]↑/↓[/b] or [b]j/k[/b]   move selection
  [b]mouse[/b]            click a row to select · scroll-wheel to scroll
  [b]enter[/b]            open finding detail (auto-shown on highlight)
  [b]tab[/b]              jump between panes

[b]Search & filter[/b]
  [b]/[/b]                focus search (matches id, title, location, CVE, scanner)
  [b]ESC[/b]              exit search back to the findings list
  [b]1[/b]                show only CRITICAL findings
  [b]2[/b]                HIGH severity and above
  [b]3[/b]                MEDIUM and above
  [b]4[/b]                all severities (clear filter)
  [b]p[/b]                pick a product (SBOM source) to focus on
  [b]N[/b]                pick a scanner to focus on (shift+n)

[b]Multi-select (batch actions)[/b]
  [b]space[/b]            toggle selection on the focused row
  [b]a[/b]                select every row in the current filter
  [b]A[/b]                clear all selections (shift+a)
  [b]c[/b]                copy selected findings' CVE IDs to the clipboard
                   (falls back to <scanner>:<id> when no CVE)
                   When nothing is selected, [b]e[/b] still exports the
                   filtered view; with a selection, [b]e[/b] exports
                   only the selected rows.

[b]Sort[/b]
  [b]s[/b]                cycle: Severity desc → Severity asc → Package → ID
                   active column shows ↓/↑ in its header

[b]Export[/b]
  [b]e[/b]                export the currently filtered view (or selection) as CSV
                   (timestamped filename, stored in cwd)
  [b]o[/b]                open the last export with your default app
                   (Numbers/Excel/LibreOffice on macOS; default handler elsewhere)
  [b]r[/b]                reveal the last export in your file manager
                   (Finder on macOS, Explorer on Windows, parent dir on Linux)
  [dim](JSON, Markdown, SARIF formats available via ctrl+p → "Export: …")[/dim]

[b]Other[/b]
  [b]d[/b]                executive summary dashboard
                   (totals, per-product, per-scanner, quality warnings)
  [b]D[/b] (shift+d)      scan-over-scan diff — compare current findings
                   against another argus-results.json. Buckets: new,
                   fixed, severity-changed, still-open.
  [b]ctrl+p[/b]           command palette — fuzzy-search every action by name
                   (also shows Textual builtins: Keys help, Theme, Screenshot)
  [b]?[/b]                show this help
  [b]q[/b]                quit

[dim]Press ?, ESC, or q to dismiss.[/dim]
"""


class _BackgroundDismissMixin:
    """Mixin that dismisses a modal when the user clicks its backdrop.

    Textual's ``ModalScreen`` doesn't ship with click-outside-to-close
    behavior — Esc / q / explicit close buttons are the keyboard
    affordances, but mouse users expect the dim background area to
    be a dismiss target. The mixin adds that single behavior.

    Implementation: ``on_click`` fires for every click bubbling up to
    the screen. ``event.widget is self`` is the way to distinguish a
    click on the empty area (handled by the screen itself) from a
    click inside the modal body (handled by whichever child widget
    received it first). The body click is left untouched; the
    background click dismisses with ``None`` so the screen's
    callback (when one is wired) receives a falsy result and treats
    it as a cancel.

    Plain class, not a generic — mixed in before ``ModalScreen`` /
    ``ModalScreen[T]`` so generic propagation stays clean.
    """

    def on_click(self, event) -> None:  # pragma: no cover — UI event
        if event.widget is self:
            self.dismiss(None)


class HelpScreen(_BackgroundDismissMixin, ModalScreen):
    """Full-screen modal overlay with the keyboard-shortcut reference.

    Kept as curated sectioned text rather than a mechanical dump of
    ``BINDINGS`` — groupings and one-line explanations matter more
    than listing every key alphabetically. A test cross-checks that
    every binding description is still referenced so we don't drift
    silently when a new binding gets added.
    """

    BINDINGS = [
        Binding("escape", "app.pop_screen", show=False),
        Binding("q", "app.pop_screen", show=False),
        Binding("question_mark", "app.pop_screen", show=False, key_display="?"),
    ]

    CSS = """
    HelpScreen {
        align: center middle;
    }
    #help-body {
        background: $surface;
        border: thick $accent;
        width: 80%;
        max-width: 90;
        max-height: 90%;
        height: auto;
    }
    #help-body > Static { padding: 1 2; }
    """

    def compose(self) -> ComposeResult:
        # VerticalScroll is focusable and ships with arrow-key, page-up/
        # down, home/end bindings, so wrapping the help text in one is
        # what lets ↑/↓ scroll the modal. Without it, the Static was
        # effectively read-only via mouse-wheel only.
        with VerticalScroll(id="help-body"):
            yield Static(_HELP_TEXT)

    def on_mount(self) -> None:
        # Land focus on the scroll container so arrow keys work the
        # moment the help opens (no need to click first).
        self.query_one("#help-body", VerticalScroll).focus()


_PICKER_CSS = """
PickerScreen {
    align: center middle;
}
#picker-body {
    background: $surface;
    border: thick $accent;
    padding: 0 1;
    width: 70%;
    max-width: 80;
    height: auto;
    max-height: 70%;
}
#picker-body > Static { padding: 1 1 0 1; }
"""


class DashboardScreen(_BackgroundDismissMixin, ModalScreen):
    """Executive-summary overlay — scan totals, per-product + per-scanner breakdowns.

    Intended for owners / managers / execs who want a quick answer to
    "what's the state of our security posture?" without navigating the
    findings list. Uses ``compute_summary`` from the shared findings_view
    module so a future web view renders an identical dashboard.
    """

    BINDINGS = [
        Binding("escape", "app.pop_screen", show=False),
        Binding("q", "app.pop_screen", show=False),
        Binding("d", "app.pop_screen", show=False),
    ]

    CSS = """
    DashboardScreen { align: center middle; }
    #dashboard-body {
        background: $surface;
        border: thick $accent;
        padding: 1 2;
        width: 90%;
        max-width: 120;
        height: auto;
        max-height: 90%;
    }
    """

    def __init__(self, all_findings: list[Finding], source_label: str):
        super().__init__()
        self._findings = all_findings
        self._source_label = source_label

    def compose(self) -> ComposeResult:
        summary = compute_summary(self._findings, top_n=3)
        lines: list[str] = [
            "[b]🛡  Argus Executive Summary[/b]",
            f"[dim]{self._source_label}[/dim]",
            "",
            f"[b]Total findings:[/b] {summary['total']}",
        ]

        # Severity breakdown — one-line ledger.
        by_sev = summary["by_severity"]
        sev_parts: list[str] = []
        for sev, icon in (
            ("critical", "🚨"), ("high", "⚠️"), ("medium", "🟡"),
            ("low", "🔵"), ("info", "ℹ️"),
        ):
            count = by_sev.get(sev, 0)
            if count:
                sev_parts.append(f"{icon} {sev.capitalize()}: [b]{count}[/b]")
        if sev_parts:
            lines.append("  " + "   ".join(sev_parts))
        lines.append("")

        # Quality warnings (SPDX-2.1, purl coverage, "unknown scan
        # subject" from grype, ...) — loud so execs don't misread an
        # empty scan as "we're clean."
        warnings = summary.get("quality_warnings") or []
        if warnings:
            lines.append("[b yellow]Quality warnings[/b yellow]")
            for w in warnings:
                lines.append(f"  [yellow]•[/yellow] {w}")
            lines.append("")

        # Per-product breakdown — the dimension execs actually care about.
        per_product = summary.get("per_product") or []
        if per_product:
            lines.append("[b]Per product[/b]")
            for entry in per_product:
                p = entry["product"]
                counts = entry["by_severity"]
                crit = counts.get("critical", 0)
                high = counts.get("high", 0)
                total = entry["total"]
                header = (
                    f"  [b]{p}[/b]   total [b]{total}[/b]   "
                    f"crit [red]{crit}[/red]   high [yellow]{high}[/yellow]"
                )
                lines.append(header)
                for top in entry["top"][:3]:
                    sev = top["severity"].capitalize()
                    title = top["title"][:80]
                    pkg = top.get("metadata", {}).get("package") or "—"
                    version = top.get("metadata", {}).get("installed_version") or "—"
                    lines.append(
                        f"    [dim]·[/dim] [b]{sev}[/b] {top['id']}  "
                        f"[dim]({pkg}@{version})[/dim]  {title}"
                    )
            lines.append("")

        # Per-scanner contribution.
        per_scanner = summary.get("per_scanner") or []
        if per_scanner:
            lines.append("[b]Per scanner[/b]")
            for entry in per_scanner:
                lines.append(f"  {entry['scanner']}: [b]{entry['total']}[/b]")
            lines.append("")

        lines.append("[dim]Press ESC, q, or d to return to the findings list.[/dim]")

        with Container(id="dashboard-body"):
            yield Static("\n".join(lines))


class ProductPickerScreen(_BackgroundDismissMixin, ModalScreen[str | None]):
    """Modal list of discovered products (SBOM sources) for filtering.

    Returns the chosen product name when the user picks one, the
    sentinel ``"(clear)"`` to reset the filter, or ``None`` on ESC.
    Built on Textual's ``OptionList`` so keyboard navigation (j/k,
    arrows, enter) works out of the box.
    """

    BINDINGS = [
        Binding("escape", "dismiss", show=False),
        Binding("q", "dismiss", show=False),
    ]

    CSS = _PICKER_CSS

    def __init__(self, products: list[str], current: str | None):
        super().__init__()
        self._products = products
        self._current = current

    def compose(self) -> ComposeResult:
        with Container(id="picker-body"):
            yield Static(
                "[b]Filter by product[/b] · enter to select · ESC to cancel"
            )
            options = [Option("(all products)", id="__all__")]
            for product in self._products:
                prefix = "✔ " if product == self._current else "  "
                options.append(Option(f"{prefix}{product}", id=product))
            yield OptionList(*options, id="picker-list")

    def on_option_list_option_selected(
        self, event: OptionList.OptionSelected
    ) -> None:
        option_id = str(event.option.id) if event.option.id else None
        if option_id == "__all__":
            self.dismiss("(clear)")
        else:
            self.dismiss(option_id)

    def action_dismiss(self) -> None:
        self.dismiss(None)


class ScannerPickerScreen(_BackgroundDismissMixin, ModalScreen[str | None]):
    """Same shape as ProductPickerScreen, but for the Scanner dimension."""

    BINDINGS = [
        Binding("escape", "dismiss", show=False),
        Binding("q", "dismiss", show=False),
    ]

    CSS = _PICKER_CSS

    def __init__(self, scanners: list[str], current: str | None):
        super().__init__()
        self._scanners = scanners
        self._current = current

    def compose(self) -> ComposeResult:
        with Container(id="picker-body"):
            yield Static(
                "[b]Filter by scanner[/b] · enter to select · ESC to cancel"
            )
            options = [Option("(all scanners)", id="__all__")]
            for scanner in self._scanners:
                prefix = "✔ " if scanner == self._current else "  "
                options.append(Option(f"{prefix}{scanner}", id=scanner))
            yield OptionList(*options, id="picker-list")

    def on_option_list_option_selected(
        self, event: OptionList.OptionSelected
    ) -> None:
        option_id = str(event.option.id) if event.option.id else None
        if option_id == "__all__":
            self.dismiss("(clear)")
        else:
            self.dismiss(option_id)

    def action_dismiss(self) -> None:
        self.dismiss(None)


class DiffPickerScreen(_BackgroundDismissMixin, ModalScreen[str | None]):
    """Modal that asks the user to type / paste a comparison-scan path.

    The companion ``argus-results.json`` for the comparison can live
    anywhere on disk — there's no enforced search root from the TUI
    side (unlike the browser interface, which is bound to its launch
    root by design). We accept a directory or a direct file path,
    same shape ``argus.viewers.terminal.loader.locate_results``
    accepts.

    Returns the entered path on submit, or ``None`` on ESC. The caller
    is responsible for actually loading the second scan and wiring up
    the resulting ``DiffScreen``.
    """

    BINDINGS = [
        Binding("escape", "dismiss", show=False),
        Binding("q", "dismiss", show=False),
    ]

    CSS = _PICKER_CSS

    def compose(self) -> ComposeResult:
        with Container(id="picker-body"):
            yield Static(
                "[b]Compare against scan…[/b] · enter a path to another "
                "argus-results.json (or a results directory) · ESC to cancel"
            )
            yield Input(
                placeholder="./run-2026-04-24/argus-results.json",
                id="diff-path",
            )

    def on_mount(self) -> None:
        self.query_one("#diff-path", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "diff-path":
            value = (event.value or "").strip()
            if not value:
                self.dismiss(None)
                return
            self.dismiss(value)

    def action_dismiss(self) -> None:
        self.dismiss(None)


class DiffScreen(_BackgroundDismissMixin, ModalScreen):
    """Scan-over-scan diff overlay — buckets findings by how they moved.

    Renders the four buckets returned by
    ``argus.core.findings_view.diff_scans`` (new, fixed, severity-changed,
    still-open) with counts at the top and a per-bucket listing below.
    Identity tuple is (scanner, id, location); a finding whose severity
    shifts but whose key persists lands in ``severity_changed`` rather
    than being double-counted in ``new`` + ``fixed``.

    The detail pane on the main app already knows how to render any
    finding via ``finding_detail_rows``; we mirror that here as text so
    the diff overlay remains a one-screen read without a second pane.
    """

    BINDINGS = [
        Binding("escape", "app.pop_screen", show=False),
        Binding("q", "app.pop_screen", show=False),
        Binding("D", "app.pop_screen", show=False),
    ]

    CSS = """
    DiffScreen { align: center middle; }
    #diff-body {
        background: $surface;
        border: thick $accent;
        padding: 1 2;
        width: 90%;
        max-width: 130;
        height: auto;
        max-height: 90%;
    }
    """

    def __init__(
        self,
        before: list[Finding],
        after: list[Finding],
        *,
        before_label: str,
        after_label: str,
    ):
        super().__init__()
        self._before = before
        self._after = after
        self._before_label = before_label
        self._after_label = after_label

    def compose(self) -> ComposeResult:
        diff = diff_scans(self._before, self._after)
        new = diff["new"]
        fixed = diff["fixed"]
        sev = diff["severity_changed"]
        still = diff["still_open"]

        lines: list[str] = [
            "[b]🔀 Scan-over-scan diff[/b]",
            f"[dim]Before: {self._before_label}[/dim]",
            f"[dim]After:  {self._after_label}[/dim]",
            "",
            (
                f"[b green]{len(new)}[/b green] new  ·  "
                f"[b yellow]{len(fixed)}[/b yellow] fixed  ·  "
                f"[b magenta]{len(sev)}[/b magenta] severity changed  ·  "
                f"[b]{len(still)}[/b] still open"
            ),
            "",
        ]

        # Per-bucket sections — every section renders even when empty so
        # the user can confirm the bucket's contents at a glance rather
        # than guessing why a label is missing.
        lines += self._render_bucket("[b green]New[/b green]", new)
        lines += self._render_bucket("[b yellow]Fixed[/b yellow]", fixed)
        lines += self._render_severity_changed(sev)
        lines += self._render_bucket("[b]Still open[/b]", still)

        lines.append("")
        lines.append("[dim]Press ESC, q, or D to return to the findings list.[/dim]")

        with VerticalScroll(id="diff-body"):
            yield Static("\n".join(lines))

    def on_mount(self) -> None:
        # Land focus on the scroll container so arrow keys work the
        # moment the diff opens (no need to click first).
        self.query_one("#diff-body", VerticalScroll).focus()

    def _render_bucket(
        self, header: str, findings: list[Finding]
    ) -> list[str]:
        """Render a flat list bucket (new / fixed / still-open)."""
        lines = [header + f" [dim]({len(findings)})[/dim]"]
        if not findings:
            lines.append("  [dim](none)[/dim]")
            lines.append("")
            return lines
        for f in findings[:25]:
            lines.append(f"  {_one_line(f)}")
        if len(findings) > 25:
            lines.append(
                f"  [dim]… {len(findings) - 25} more (filter or use "
                f"the browser interface for the full list)[/dim]"
            )
        lines.append("")
        return lines

    def _render_severity_changed(
        self, pairs: list[dict]
    ) -> list[str]:
        """Render the severity_changed bucket — pairs of before/after."""
        lines = [
            f"[b magenta]Severity changed[/b magenta] [dim]({len(pairs)})[/dim]"
        ]
        if not pairs:
            lines.append("  [dim](none)[/dim]")
            lines.append("")
            return lines
        for pair in pairs[:25]:
            b = pair["before"]
            a = pair["after"]
            before_glyph = _SEVERITY_GLYPH.get(b.severity, "?")
            after_glyph = _SEVERITY_GLYPH.get(a.severity, "?")
            lines.append(
                f"  {a.id:<24}  {before_glyph} → {after_glyph}  "
                f"[dim]{(a.location or a.scanner or '')[:60]}[/dim]"
            )
        if len(pairs) > 25:
            lines.append(
                f"  [dim]… {len(pairs) - 25} more[/dim]"
            )
        lines.append("")
        return lines


_MENU_CSS = """
ContextMenuScreen { align: center middle; }
ContextMenuScreen > Vertical {
    width: 60; height: auto; padding: 1 2;
    border: round $accent; background: $surface;
}
ContextMenuScreen #menu-title { content-align: left middle; text-style: bold; padding: 0 0 1 0; }
ContextMenuScreen OptionList { height: auto; max-height: 12; }
ContextMenuScreen #hint { color: $text-muted; padding: 1 0 0 0; content-align: left middle; }
"""


class ContextMenuScreen(_BackgroundDismissMixin, ModalScreen[str | None]):
    """Right-click / row-click context menu for a finding.

    Lists the actions that target the selected row directly:
      - Open advisory page (NVD / CVE.org / GHSA, per ``view.cve_source``)
      - Open file:line locally (in $EDITOR / VS Code / ...)
      - Open file:line in remote git (GitHub / GitLab blob URL)
      - Open package page (PyPI / npm)
      - Copy CVE to clipboard
      - Export selection (route to existing ``e`` action)

    Items that don't apply to this finding are filtered out before
    the modal mounts — a Bandit finding with no CVE, no file path,
    and no package@version location gets only "Export selection".
    """

    CSS = _MENU_CSS
    BINDINGS = [
        Binding("escape", "dismiss(None)", "Cancel", show=True),
        Binding("q", "dismiss(None)", "Quit"),
    ]

    def __init__(self, finding: Finding, view_config: ViewConfig):
        super().__init__()
        self._finding = finding
        self._view_config = view_config
        # Decide which menu items apply to this finding.
        self._items: list[tuple[str, str]] = []
        if finding.cve or self._looks_like_advisory(finding.id):
            advisory = finding.cve or finding.id
            self._items.append(
                (f"Open advisory: {advisory}", f"open_advisory:{advisory}"),
            )
        if mouse_actions.parse_file_line(finding.location):
            self._items.append(("Open file in local editor", "open_local"))
            self._items.append(("Open file on remote (git blob URL)", "open_remote"))
        if (
            finding.location
            and "@" in finding.location
            and not mouse_actions.parse_file_line(finding.location)
        ):
            self._items.append(("Open package on registry", "open_package"))
        if finding.cve:
            self._items.append((f"Copy CVE to clipboard ({finding.cve})", "copy_cve"))
        self._items.append(("Export current selection / view", "export"))

    @staticmethod
    def _looks_like_advisory(value: str | None) -> bool:
        if not value:
            return False
        upper = value.upper()
        return upper.startswith("CVE-") or upper.startswith("GHSA-")

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static(
                f"⚙ {self._finding.id or '—'}  ·  Actions",
                id="menu-title",
            )
            yield OptionList(
                *(Option(label, id=key) for label, key in self._items),
                id="menu-list",
            )
            yield Static("↑↓ Enter to select  ·  Esc to cancel", id="hint")

    def on_option_list_option_selected(  # pragma: no cover — UI event
        self, event: OptionList.OptionSelected,
    ) -> None:
        self.dismiss(event.option.id or None)


_PROMPT_CSS = """
OpenLocationPromptScreen { align: center middle; }
OpenLocationPromptScreen > Vertical {
    width: 60; height: auto; padding: 1 2;
    border: round $accent; background: $surface;
}
OpenLocationPromptScreen #prompt-title { text-style: bold; padding: 0 0 1 0; }
OpenLocationPromptScreen OptionList { height: auto; }
OpenLocationPromptScreen #hint { color: $text-muted; padding: 1 0 0 0; }
"""


class OpenLocationPromptScreen(_BackgroundDismissMixin, ModalScreen[str | None]):
    """Tiny modal asking 'local or remote?' when view.open_location == 'ask'.

    Returns ``"local"``, ``"remote"``, or ``None`` (dismissed).
    """

    CSS = _PROMPT_CSS
    BINDINGS = [
        Binding("escape", "dismiss(None)", "Cancel"),
        Binding("l", "dismiss('local')", "Local"),
        Binding("r", "dismiss('remote')", "Remote"),
    ]

    def __init__(self, location: str):
        super().__init__()
        self._location = location

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static(f"Open {self._location}", id="prompt-title")
            yield OptionList(
                Option("Local — open in $EDITOR / VS Code", id="local"),
                Option("Remote — open at commit on GitHub / GitLab", id="remote"),
            )
            yield Static("L for local  ·  R for remote  ·  Esc to cancel", id="hint")

    def on_option_list_option_selected(  # pragma: no cover — UI event
        self, event: OptionList.OptionSelected,
    ) -> None:
        self.dismiss(event.option.id or None)


def _one_line(f: Finding) -> str:
    """One-line summary of a finding for the diff bucket lists.

    Keeps the diff overlay scannable without recreating the full
    DataTable detail pane. Severity glyph + ID + location/scanner is
    enough to identify the row; users wanting the full detail can
    cross-reference the main findings list.
    """
    glyph = _SEVERITY_GLYPH.get(f.severity, "?")
    locator = f.location or f.scanner or "—"
    return f"{glyph}  {(f.id or '—')[:30]:<30}  [dim]{locator[:60]}[/dim]"


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
            ("Help: Show keyboard shortcuts", "Open the full help overlay", app.action_show_help),
            ("Dashboard: Executive summary", "Open the exec-summary overlay (totals, per-product, per-scanner)", app.action_show_dashboard),
            ("Diff: Compare against another scan", "Pick another argus-results.json and bucket changes (new / fixed / severity-changed / still-open)", app.action_diff_against),
            ("Search findings",          "Focus the search box", app.action_focus_search),
            ("Filter: Critical only",    "Show only CRITICAL findings", app.action_filter_critical),
            ("Filter: High severity and above", "Show HIGH + CRITICAL findings", app.action_filter_high),
            ("Filter: Medium severity and above", "Show MEDIUM + HIGH + CRITICAL findings", app.action_filter_medium),
            ("Filter: All severities",   "Clear the severity filter", app.action_filter_all),
            ("Product: Pick a product filter", "Filter findings by SBOM source / product", app.action_pick_product),
            ("Scanner: Pick a scanner filter", "Filter findings by reporting scanner", app.action_pick_scanner),
            ("Sort: Cycle sort mode",    "Cycle severity desc → asc → package → id", app.action_cycle_sort),
            ("Export: CSV of current view", "Write the filtered findings (or selection) to a timestamped CSV", app.action_export_csv),
            ("Export: JSON",             "Write the filtered findings (or selection) as JSON", app.action_export_json),
            ("Export: Markdown",         "Write the filtered findings (or selection) as a paste-ready Markdown table", app.action_export_markdown),
            ("Export: SARIF",            "Write the filtered findings (or selection) as SARIF 2.1.0", app.action_export_sarif),
            ("Open: Last export",        "Open the last export with the system's default app", app.action_open_last_export),
            ("Reveal: Last export",      "Show the last export in the OS file manager", app.action_reveal_last_export),
            ("Select: Toggle row",       "Toggle multi-select on the focused row (space)", app.action_toggle_selection),
            ("Select: All visible",      "Add every visible row to the selection (a)", app.action_select_all),
            ("Select: Clear",            "Clear all multi-select selections (shift+a)", app.action_clear_selection),
            ("Copy: Selected CVE IDs",   "Copy selected findings' CVE IDs to the clipboard (c)", app.action_copy_cves),
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
    """Search box that returns focus to the findings table on ESC / ↓.

    Textual's default Input binding for ``escape`` is blur-only, so
    users get stranded in the search box until they click elsewhere.
    We hard-bind ``escape`` to shift focus back to the DataTable so a
    single keystroke drops the user back into navigation.

    ``down`` / ``up`` here also exit search and move focus to the
    findings table — that's the natural keystroke users try after
    typing a query and wanting to scan the matches, and the default
    Input behavior (which only navigates within the input field) is a
    dead end.
    """

    BINDINGS = [
        Binding("escape", "back_to_table", "Back to list", show=False),
        Binding("down", "into_table", "Into list", show=False),
        Binding("up", "into_table", "Into list", show=False),
    ]

    def action_back_to_table(self) -> None:
        table = self.app.query_one(DataTable)
        table.focus()

    def action_into_table(self) -> None:
        # Same as ESC for now — the table preserves its cursor position,
        # so refocusing is enough to let arrow keys keep navigating from
        # wherever the user left off.
        self.action_back_to_table()


class FindingDetail(Static):
    """Right pane — plain-text detail view for the selected finding.

    Content structure comes from ``finding_detail_rows`` in the shared
    core module so the TUI and a future web view stay aligned. This
    widget only handles the Textual-markup wrapping.
    """

    def update_finding(self, f: Finding | None) -> None:
        if f is None:
            self.update("[dim]Select a finding to see details.[/dim]")
            return

        # CVE / GHSA + ``location`` are the high-signal click targets:
        # one opens the upstream advisory, the other opens the file in
        # editor or git blob. Wrap them in Textual's ``[@click=...]``
        # markup so the rendered text becomes interactive without
        # refactoring the pane into per-cell widgets.
        header_id = self._linkify_id(f)
        glyph = _SEVERITY_GLYPH.get(f.severity, "?")
        lines = [f"[bold]{header_id}[/bold]   {glyph}", ""]

        rows = finding_detail_rows(f)
        for label, value in rows:
            rendered = self._linkify_value(label, value)
            lines.append(f"[b]{label}:[/b]".ljust(13) + f" {rendered}")
        lines += ["", "[b]Title[/b]", f.title or "—"]
        if f.description and f.description != f.title:
            lines += ["", "[b]Description[/b]", f.description]
        warning = f.metadata.get("warning")
        if warning:
            lines += ["", f"[yellow]{warning}[/yellow]"]
        self.update("\n".join(lines))

    @staticmethod
    def _linkify_id(f: Finding) -> str:
        """If the finding ID is a CVE / GHSA, render it as a click target."""
        target = f.cve or f.id or ""
        if not target:
            return f.id or "—"
        upper = target.upper()
        if upper.startswith("CVE-") or upper.startswith("GHSA-"):
            # ``app.`` prefix routes the markup-action call to the
            # BrowseApp instance — Static widgets don't look up
            # action_* methods on the App by default; the namespace
            # is required.
            return f"[@click=app.action_open_advisory('{target}')]{f.id}[/]"
        return f.id or "—"

    @staticmethod
    def _linkify_value(label: str, value: str) -> str:
        """Wrap location / package values in click handlers when applicable."""
        if not value or value == "—":
            return value
        # Location row covers both file:line and package@version shapes.
        # Routing happens in ``BrowseApp.action_open_location``.
        if label.lower() in ("location", "file", "path", "package"):
            # Escape single quotes for the action-argument literal.
            safe = value.replace("'", "\\'")
            return f"[@click=app.action_open_location('{safe}')]{value}[/]"
        return value


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
    /* Mouse hover: row gets a subtle accent background so the
       click target the user is about to land on is obvious.
       Cell-level emphasis stays with the cursor (keyboard focus)
       so keyboard and mouse don't fight for the visual lead. */
    DataTable > .datatable--hover {
        background: $boost;
    }
    Static#detail { height: 1fr; border: solid $accent; padding: 1 2; }
    /* CVE / file:line / package links in the detail pane render
       as Textual ``[@click=...]`` markup; underlining them on
       hover signals "this is interactive" the same way a browser
       does. */
    Static#detail .clickable:hover {
        text-style: underline;
        color: $accent;
    }
    #status { height: 1; dock: bottom; background: $panel; padding: 0 1; }
    /* Status-bar filter chips are clickable; underline on hover. */
    #status .chip:hover {
        text-style: underline;
    }
    """

    # Footer-visible bindings are kept tight so the bar fits common
    # terminal widths (~80 cols). Less-used actions (open / reveal
    # exports, product / scanner pickers) are hidden with show=False —
    # they remain bound, listed in the ? help screen, and discoverable
    # via the Ctrl+P command palette.
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("question_mark", "show_help", "Help", key_display="?"),
        Binding("slash", "focus_search", "Search", show=True, key_display="/"),
        Binding("1", "filter_critical", "Crit"),
        Binding("2", "filter_high", "≥High"),
        Binding("3", "filter_medium", "≥Med"),
        Binding("4", "filter_all", "All sev"),
        Binding("s", "cycle_sort", "Sort"),
        Binding("e", "export_csv", "CSV"),
        Binding("d", "show_dashboard", "Dash"),
        # Scan-over-scan diff. ``d`` is taken by the dashboard, so the
        # capital form (shift+d) drives the diff picker. Keeps both
        # overlays one keystroke away from the findings list.
        Binding("D", "diff_against", "Diff", show=True),
        # Multi-select — drives the bulk-action workflows (export N rows,
        # paste a CVE list into a bug tracker). ``space``/``a``/``A``
        # manage the selection set; ``c`` copies CVEs from it. ``e``
        # already existed; its action method now picks the selection
        # over the filtered view when one is active.
        Binding("space", "toggle_selection", "Select", show=True),
        Binding("a", "select_all", "Select all", show=False),
        Binding("A", "clear_selection", "Clear sel", show=False),
        Binding("c", "copy_cves", "Copy CVEs", show=True),
        Binding("o", "open_last_export", "Open export", show=False),
        Binding("r", "reveal_last_export", "Reveal export", show=False),
        Binding("p", "pick_product", "Product", show=False),
        # Scanner picker moved to ``shift+n`` to free ``c`` for the
        # multi-select clipboard action. Still discoverable via the
        # Ctrl+P command palette and via the Help overlay.
        Binding("N", "pick_scanner", "Scanner", show=False),
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
        # Selection set keyed by stable Finding identity so a row that
        # gets filtered out and back in retains its selection. We use
        # ``id(f)`` rather than serializing the Finding because Finding
        # is a frozen dataclass with all-defaults-comparable fields and
        # ``hash(Finding)`` depends on the full content equality model.
        # Storing the live object reference is the cheapest stable key
        # for an in-memory session.
        self._selected: set[int] = set()
        # Load ``view:`` config (cve_source / open_location / editor)
        # from any argus.yml the user has in cwd or beside results_dir.
        # ArgusConfig.load() auto-detects and falls back to defaults if
        # no file is present — the TUI works fine with the defaults
        # (NVD for CVEs, "ask" prompt for file:line). Loaded once at
        # mount; no live-reload.
        self._view_config: ViewConfig = self._load_view_config()
        # Cache the repo root + scan commit SHA so file:line → git
        # blob URL doesn't re-walk + re-shell on every click. Resolved
        # lazily on first remote-open request.
        self._repo_root: Path | None = None
        self._scan_ref: str = "HEAD"
        # Scan-time context (cwd + repo_root + commit_sha) read off
        # the loaded ScanSummary in on_mount. Lets the click handlers
        # strip absolute-path prefixes coming from container / CI scans
        # and use the right commit SHA for git blob URLs. None when
        # the scan didn't capture context (older results, or scans
        # built outside the engine).
        from argus.core.models import ScanContext as _SC
        self._scan_context: _SC | None = None

    @staticmethod
    def _load_view_config() -> ViewConfig:
        """Best-effort ArgusConfig.view load. Always returns a usable
        ViewConfig — defaults if nothing's on disk or anything errors."""
        try:
            return ArgusConfig.load().view
        except Exception:  # pragma: no cover — defensive
            return ViewConfig()

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        yield SearchInput(
            placeholder="Search (id, title, location, CVE, scanner)… "
                        "↓ or ESC to return to list",
            id="search",
        )
        with Container(id="body"):
            with Vertical(id="list-pane"):
                yield DataTable(
                    id="findings",
                    cursor_type="row",
                    zebra_stripes=True,
                )
            with Vertical(id="detail-pane"):
                yield FindingDetail(id="detail")
        yield Static(id="status")
        yield Footer()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def on_mount(self) -> None:
        self.title = "argus view (terminal)"
        try:
            summary, resolved = load_summary(self._results_dir)
        except (FileNotFoundError, ValueError) as exc:
            self.exit(message=f"\n{exc}\n", return_code=1)
            return
        self.sub_title = str(resolved)
        self.all_findings = flatten_findings(summary)
        # Read scan-time context (cwd / repo_root / commit_sha) off the
        # loaded summary. Older argus-results.json files predate the
        # field — leave self._scan_context as None and the click
        # handlers fall back to their previous best-effort behavior.
        self._scan_context = getattr(summary, "scan_context", None)
        if self._scan_context is not None and self._scan_context.commit_sha:
            # Pin the remote-URL ref to the commit the scan actually
            # saw rather than the contributor's local HEAD.
            self._scan_ref = self._scan_context.commit_sha
        table = self.query_one(DataTable)
        # Hover-tooltips on the mouse contract. Set after construction
        # because Textual 8.x's DataTable / Static constructors don't
        # accept ``tooltip=`` directly — the attribute lives on Widget
        # and is settable on a mounted instance.
        table.tooltip = (
            "Click row to select · Click again or right-click for actions "
            "· Click column header to sort"
        )
        self.query_one("#detail", FindingDetail).tooltip = (
            "Click an underlined value (CVE / file:line / package) "
            "to open it in your browser or editor"
        )
        # Column keys are kept so we can re-label the active sort column
        # with an arrow glyph whenever the sort cycles. The leading
        # checkbox column ("✓") is updated row-by-row as the selection
        # changes — it stays unsorted (selection is a per-row state,
        # not a sort key).
        self._col_keys = table.add_columns(
            " ", "Sev", "ID", "Package@Version", "Scanner", "Location",
        )
        self._refresh_list()
        self._update_sort_indicator()
        # Open into the findings list, not the search box. The search
        # input is the first focusable child by yield order, so without
        # this users land in the search field and find that ↑/↓ edit
        # the query rather than navigating findings.
        table.focus()

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
                "✓" if id(f) in self._selected else " ",
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

        # Status-bar chips render as Textual ``[@click=...]`` markup so
        # the mouse can manipulate filters directly. Each chip:
        #   - the severity chip cycles back to "all" on click
        #   - product / scanner / query chips clear that one filter
        #   - the sort chip cycles sort modes
        # The keyboard bindings still work in parallel.
        # ``app.`` prefix routes the click action to BrowseApp; Static
        # widgets don't dispatch action_* methods locally and the
        # markup needs the explicit namespace.
        parts: list[str] = []
        if self.view_state.min_severity:
            parts.append(
                f"[@click=app.action_filter_all]≥ "
                f"{self.view_state.min_severity.value}[/]"
            )
        else:
            parts.append("all severities")
        if self.view_state.product:
            parts.append(
                f"[@click=app.action_clear_product]product="
                f"{self.view_state.product}[/]"
            )
        if self.view_state.scanner:
            parts.append(
                f"[@click=app.action_clear_scanner]scanner="
                f"{self.view_state.scanner}[/]"
            )
        if self.view_state.query:
            # Escape single quotes so the markup parser doesn't break on
            # user-typed query text.
            safe = self.view_state.query.replace("'", "\\'")
            parts.append(
                f"[@click=app.action_clear_query]query='{safe}'[/]"
            )
        sort = self.view_state.sort_key.replace("_", " ")
        sort_chip = f"[@click=app.action_cycle_sort]{sort}[/]"

        selection_str = (
            f" · [b]{len(self._selected)}[/b] selected"
            if self._selected else ""
        )
        self.query_one("#status", Static).update(
            f"[b]{shown}[/b] / {total} findings · "
            f"filter: {' · '.join(parts)} · sort: {sort_chip}"
            f"{selection_str}"
        )

    def _update_detail(self, row: int) -> None:
        if 0 <= row < len(self._visible):
            self.query_one("#detail", FindingDetail).update_finding(self._visible[row])

    # ------------------------------------------------------------------
    # Event hooks
    # ------------------------------------------------------------------

    def on_data_table_row_highlighted(self, event) -> None:  # pragma: no cover
        self._update_detail(event.cursor_row)

    def on_data_table_header_selected(self, event) -> None:  # pragma: no cover
        """Mouse: click a column header → cycle through sort modes.

        Wires the same path as the ``s`` keyboard binding so mouse and
        keyboard behave identically. Textual's DataTable fires this
        on left-click of any column-header cell.
        """
        self.action_cycle_sort()

    def on_data_table_row_selected(self, event) -> None:  # pragma: no cover
        """Mouse: click a row (or Enter on focused row) → context menu.

        Pushes ContextMenuScreen for the highlighted finding. Single-
        click still moves the cursor + updates the detail pane via
        ``on_data_table_row_highlighted`` first; this fires on the
        secondary click on the same row (Textual emits RowSelected on
        a fresh click of the already-focused row, mimicking double-
        click semantics on most platforms).
        """
        row = event.cursor_row
        if 0 <= row < len(self._visible):
            self._push_context_menu(self._visible[row])

    def on_mouse_down(self, event) -> None:  # pragma: no cover
        """Right-click on a findings-table row → open context menu.

        Mouse button 3 is the conventional right-click; Textual surfaces
        it via the same MouseDown event family. We discriminate on
        ``event.button`` and resolve the underlying row via the
        DataTable's cursor coordinate (mouse hover-and-right-click
        first moves the cursor, then fires button-3).
        """
        if getattr(event, "button", 0) != 3:
            return
        try:
            table = self.query_one(DataTable)
        except Exception:  # widget not mounted yet
            return
        row = table.cursor_row
        if 0 <= row < len(self._visible):
            self._push_context_menu(self._visible[row])

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

    def action_show_help(self) -> None:
        self.push_screen(HelpScreen())

    def action_pick_product(self) -> None:
        products = unique_products(self.all_findings)
        if not products:
            self.notify(
                "No products — findings have no 'sbom_source' metadata.",
                severity="warning", timeout=3,
            )
            return

        def _on_pick(choice: str | None) -> None:
            if choice is None:
                return  # ESC / cancel
            if choice == "(clear)":
                self.view_state.product = None
            else:
                self.view_state.product = choice
            self._refresh_list()

        self.push_screen(
            ProductPickerScreen(products, self.view_state.product),
            _on_pick,
        )

    def action_show_dashboard(self) -> None:
        self.push_screen(
            DashboardScreen(self.all_findings, source_label=self.sub_title or ""),
        )

    def action_diff_against(self) -> None:
        """Open the comparison-scan picker (shift+d).

        On submit, loads the picked scan via the same loader the main
        app uses (``argus.viewers.terminal.loader.load_summary`` →
        ``flatten_findings``), then pushes a ``DiffScreen`` overlay
        that buckets findings via the shared
        ``argus.core.findings_view.diff_scans`` function. The
        currently-loaded scan is treated as the "after" side and the
        picked scan as the "before" side — that's the natural framing
        when you've just opened the latest results and want to know
        what changed since the previous run.
        """
        def _on_pick(choice: str | None) -> None:
            if choice is None:
                return
            try:
                summary, resolved = load_summary(choice)
            except FileNotFoundError as exc:
                self.notify(
                    f"Couldn't load comparison scan: {exc}",
                    severity="error", timeout=8,
                )
                return
            except (ValueError, OSError) as exc:
                # ValueError covers malformed JSON / wrong shape; OSError
                # covers permission / decode failures from read_text.
                self.notify(
                    f"Couldn't parse comparison scan: {exc}",
                    severity="error", timeout=8,
                )
                return

            before_findings = flatten_findings(summary)
            self.push_screen(
                DiffScreen(
                    before=before_findings,
                    after=self.all_findings,
                    before_label=str(resolved),
                    after_label=self.sub_title or "(current scan)",
                ),
            )

        self.push_screen(DiffPickerScreen(), _on_pick)

    def action_pick_scanner(self) -> None:
        scanners = unique_scanners(self.all_findings)
        if not scanners:
            self.notify(
                "No scanners reported in this results set.",
                severity="warning", timeout=3,
            )
            return

        def _on_pick(choice: str | None) -> None:
            if choice is None:
                return
            if choice == "(clear)":
                self.view_state.scanner = None
            else:
                self.view_state.scanner = choice
            self._refresh_list()

        self.push_screen(
            ScannerPickerScreen(scanners, self.view_state.scanner),
            _on_pick,
        )

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

    # Clear-one-filter helpers — invoked from the status-bar chips'
    # ``[@click=...]`` markup. Mouse-only; no keyboard binding (the
    # picker modals already handle keyboard clear via Esc → no selection).
    def action_clear_product(self) -> None:  # pragma: no cover — UI
        self.view_state.product = None
        self._refresh_list()

    def action_clear_scanner(self) -> None:  # pragma: no cover — UI
        self.view_state.scanner = None
        self._refresh_list()

    def action_clear_query(self) -> None:  # pragma: no cover — UI
        self.view_state.query = ""
        # Also clear the visible search input so the chip + input stay
        # in sync — otherwise clicking the chip would clear the filter
        # but leave the old query in the search box, confusing the user.
        try:
            self.query_one("#search", Input).value = ""
        except Exception:  # widget not mounted yet
            pass
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

        Column 0 is the multi-select checkbox column — never a sort
        target — so the data-column offsets all start at 1.
        """
        table = self.query_one(DataTable)
        base_labels = [" ", "Sev", "ID", "Package@Version", "Scanner", "Location"]
        # When running under stubbed textual in tests, columns may be
        # an empty mapping or missing; bail silently so the test path
        # (which only exercises view-state logic) stays green.
        if not getattr(self, "_col_keys", None):
            return
        arrow_col = None
        arrow_glyph = ""
        if self.view_state.sort_key == "severity_desc":
            arrow_col, arrow_glyph = 1, " ↓"
        elif self.view_state.sort_key == "severity_asc":
            arrow_col, arrow_glyph = 1, " ↑"
        elif self.view_state.sort_key == "package":
            arrow_col, arrow_glyph = 3, " ↓"
        elif self.view_state.sort_key == "id":
            arrow_col, arrow_glyph = 2, " ↓"
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

    # ------------------------------------------------------------------
    # Multi-select actions
    # ------------------------------------------------------------------

    def _focused_row_index(self) -> int | None:
        """Return the visible-row index the cursor is on, or None.

        Wraps DataTable's ``cursor_coordinate`` attribute so the action
        handlers don't have to handle "table has no cursor yet" / stub
        objects in tests. Returns ``None`` when no row is focusable
        (empty filter set, table not yet mounted).
        """
        try:
            table = self.query_one(DataTable)
        except Exception:
            return None
        coord = getattr(table, "cursor_coordinate", None)
        if coord is None:
            return None
        try:
            row = coord[0]
        except (TypeError, IndexError):
            return None
        if not isinstance(row, int) or row < 0 or row >= len(self._visible):
            return None
        return row

    def action_toggle_selection(self) -> None:
        """Toggle selection on the focused row (``space`` keybind).

        No-op when no row is focused (e.g. empty filter result). The
        cursor position is preserved across the refresh so the user can
        space-down-space-down through a list without losing their
        place.
        """
        row = self._focused_row_index()
        if row is None:
            return
        finding = self._visible[row]
        key = id(finding)
        if key in self._selected:
            self._selected.discard(key)
        else:
            self._selected.add(key)
        self._refresh_keep_cursor(row)

    def action_select_all(self) -> None:
        """Select every row in the current filter (``a`` keybind).

        Adds to — rather than replaces — the existing selection so a
        user who already cherry-picked a few rows from another filter
        doesn't lose them. The status bar's "N selected" count makes
        the cumulative effect visible.
        """
        if not self._visible:
            return
        for f in self._visible:
            self._selected.add(id(f))
        # Keep cursor where it is so the user can keep navigating.
        row = self._focused_row_index() or 0
        self._refresh_keep_cursor(row)
        self.notify(
            f"Selected {len(self._visible)} visible row(s).",
            severity="information", timeout=2,
        )

    def action_clear_selection(self) -> None:
        """Drop every selected row (``A`` / shift+a keybind).

        Clears the *global* selection set, not just the visible
        portion. That matches the keybind name ("clear") — users who
        want a per-filter clear can re-select-all then refine.
        """
        if not self._selected:
            return
        count = len(self._selected)
        self._selected.clear()
        row = self._focused_row_index() or 0
        self._refresh_keep_cursor(row)
        self.notify(
            f"Cleared {count} selection(s).",
            severity="information", timeout=2,
        )

    def _refresh_keep_cursor(self, row: int) -> None:
        """Re-render the table while keeping the cursor on ``row``.

        ``_refresh_list`` re-seats the cursor at row 0 by design (it's
        the right behavior after a filter change), but the multi-select
        flow is high-frequency: hitting ``space`` ten times to mark a
        run of rows shouldn't fling the cursor back to the top each
        time. This thin wrapper restores the cursor afterward.
        """
        self._refresh_list()
        try:
            table = self.query_one(DataTable)
        except Exception:
            return
        if 0 <= row < len(self._visible):
            try:
                table.cursor_coordinate = (row, 0)
            except Exception:
                pass

    def action_copy_cves(self) -> None:
        """Copy selected findings' CVE IDs to the clipboard (``c`` keybind).

        One identifier per line. Falls back to ``<scanner>:<id>`` for
        rows without a CVE so a SAST or secret-scanner finding still
        ends up in a paste-ready form. Toast names the mechanism that
        worked (pyperclip / pbcopy / xclip / wl-copy / clip) so users
        can debug "did it land in the X11 selection or the GNOME
        Wayland one?" cases.
        """
        from argus.viewers.terminal.clipboard import (
            copy_to_clipboard,
            format_findings_for_clipboard,
        )
        if not self._selected:
            self.notify(
                "No findings selected. Use [b]space[/b] to toggle a row "
                "or [b]a[/b] to select the current filter.",
                severity="warning", timeout=4,
            )
            return
        # Preserve the current visible order in the clipboard payload —
        # the user's filter+sort already tells them which view they
        # were in, and pasting should reflect that ordering. Selected
        # rows that aren't in the current filter still go in (so a
        # cross-filter selection doesn't silently drop entries) but
        # land at the end.
        in_view = [f for f in self._visible if id(f) in self._selected]
        in_view_ids = {id(f) for f in in_view}
        out_of_view = [
            f for f in self.all_findings
            if id(f) in self._selected and id(f) not in in_view_ids
        ]
        ordered = in_view + out_of_view
        payload = format_findings_for_clipboard(ordered)
        ok, mechanism = copy_to_clipboard(payload)
        n = len(ordered)
        if ok:
            self.notify(
                f"{n} CVE(s) copied to clipboard via {mechanism}.",
                severity="information", timeout=3,
            )
        else:
            self.notify(
                "No clipboard mechanism available "
                "(install pyperclip, xclip, wl-copy, pbcopy, or clip). "
                f"{n} finding(s) would have been copied.",
                severity="warning", timeout=6,
            )

    # Format dispatch lives in argus.viewers.terminal.export — these action methods
    # just wrap the shared writers with filename assembly and toast.

    def action_export_csv(self) -> None:
        """Export the current view (or selection if non-empty) as CSV (bound to ``e``)."""
        self._export_in_format("csv")

    def action_export_json(self) -> None:
        """Export the current view (or selection if non-empty) as JSON."""
        self._export_in_format("json")

    def action_export_markdown(self) -> None:
        """Export the current view (or selection if non-empty) as Markdown."""
        self._export_in_format("markdown")

    def action_export_sarif(self) -> None:
        """Export the current view (or selection if non-empty) as SARIF 2.1.0."""
        self._export_in_format("sarif")

    def _export_in_format(self, fmt: str) -> None:
        from argus.viewers.terminal.export import WRITERS, make_export_path
        writer, extension = WRITERS[fmt]
        # Selection-aware export: when the user has marked a subset, we
        # export only those rows; without a selection, the previous
        # "filtered view" semantics still apply. The scope label in the
        # filename reflects which path we took so a "selection" export
        # never silently overwrites a "filter" export.
        if self._selected:
            findings = [
                f for f in self.all_findings if id(f) in self._selected
            ]
            scope = "selection"
        else:
            findings = self._visible
            scope = (
                self.view_state.min_severity.value
                if self.view_state.min_severity else "all"
            )
        dest = make_export_path(extension, scope=scope)
        writer(findings, dest)
        self._last_export_path = dest
        uri = dest.as_uri()
        self.notify(
            f"Exported {len(findings)} finding(s) as {fmt.upper()} to:\n"
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

    # ------------------------------------------------------------------
    # Mouse-first actions: open advisories, files, packages, context menu.
    # The handlers are thin wrappers around argus.viewers.terminal.
    # mouse_actions so they stay easy to unit-test without Textual.
    # ------------------------------------------------------------------

    def _push_context_menu(self, finding: Finding) -> None:  # pragma: no cover
        """Push the right-click / row-click menu for ``finding``."""

        def _on_choice(choice: str | None) -> None:
            if not choice:
                return
            if choice.startswith("open_advisory:"):
                self.action_open_advisory(choice.split(":", 1)[1])
            elif choice == "open_local":
                self.action_open_local_file(finding.location or "")
            elif choice == "open_remote":
                self.action_open_remote_file(finding.location or "")
            elif choice == "open_package":
                self.action_open_package(finding.location or "")
            elif choice == "copy_cve" and finding.cve:
                from argus.viewers.terminal.clipboard import copy_to_clipboard
                ok, _mechanism = copy_to_clipboard(finding.cve)
                self.notify(
                    f"Copied {finding.cve} to clipboard"
                    if ok else f"Clipboard unavailable — {finding.cve}",
                    severity="information" if ok else "warning", timeout=2,
                )
            elif choice == "export":
                self.action_export_csv()

        self.push_screen(
            ContextMenuScreen(finding, self._view_config),
            _on_choice,
        )

    def action_open_advisory(self, advisory_id: str) -> None:  # pragma: no cover
        """Open a CVE / GHSA advisory page in the default browser.

        Triggered from:
          - ``[@click=action_open_advisory('CVE-xxxx')]`` markup in the
            detail pane (single-click on the rendered ID).
          - The ``Open advisory`` item in the row context menu.
          - The command palette (when discoverable).
        """
        url = mouse_actions.advisory_url_for_id(
            advisory_id, self._view_config.cve_source,
        )
        if not url:
            self.notify(
                f"No advisory source for {advisory_id!r}",
                severity="warning", timeout=3,
            )
            return
        if mouse_actions.open_in_browser(url):
            self.notify(f"Opened {advisory_id}", severity="information", timeout=2)
        else:
            self.notify(
                f"Couldn't open browser for {url}",
                severity="error", timeout=5,
            )

    def action_open_location(self, location: str) -> None:  # pragma: no cover
        """Dispatch a file:line / package@version click per ``view.open_location``.

        Routes:
          - ``ask`` (default): mini modal lets the user pick local / remote
          - ``local``: shell out to $EDITOR / VS Code with the file:line
          - ``remote``: open at the scan's commit SHA on the git remote
        """
        if not location:
            return
        # Package@version? Route to registry instead — the local /
        # remote split doesn't apply.
        if mouse_actions.parse_file_line(location) is None and "@" in location:
            self.action_open_package(location)
            return

        mode = self._view_config.open_location
        if mode == "local":
            self.action_open_local_file(location)
        elif mode == "remote":
            self.action_open_remote_file(location)
        else:  # "ask"
            def _on_pick(choice: str | None) -> None:
                if choice == "local":
                    self.action_open_local_file(location)
                elif choice == "remote":
                    self.action_open_remote_file(location)

            self.push_screen(OpenLocationPromptScreen(location), _on_pick)

    def _repo_relative_path(self, path: Path) -> Path:
        """Thin wrapper over ``mouse_actions.strip_scan_prefix``.

        Kept as an instance method so the action handlers can call it
        without threading ``scan_context`` through every call site.
        The actual logic lives in mouse_actions so it can be unit-
        tested without spinning up the Textual app.
        """
        return mouse_actions.strip_scan_prefix(path, self._scan_context)

    def action_open_local_file(self, location: str) -> None:  # pragma: no cover
        """Shell out to the user's editor at ``file:line``.

        Editor resolution lives in ``mouse_actions.open_file_local`` and
        honors (in order): ``view.editor`` config, ``$VISUAL``, ``$EDITOR``,
        VS Code's ``code -g``, ``xdg-open`` / ``open``.

        Path resolution: strips the scan-time repo prefix (so paths
        from container / CI scans become repo-relative), then maps
        them onto the viewer's local repo root before opening.
        """
        parsed = mouse_actions.parse_file_line(location)
        if not parsed:
            self.notify(
                f"Can't parse as a file path: {location!r}",
                severity="warning", timeout=3,
            )
            return
        path, line = parsed
        repo_relative = self._repo_relative_path(path)
        # If we successfully made it repo-relative, resolve against the
        # local checkout. Else keep whatever we had — absolute paths
        # that don't match the scan prefix may still exist on the host.
        if repo_relative != path or not path.is_absolute():
            repo_root = self._resolve_repo_root()
            candidate = (repo_root or Path.cwd()) / repo_relative
            if candidate.exists():
                path = candidate
            else:
                path = repo_relative if repo_relative != path else path
        opened = mouse_actions.open_file_local(
            path, line=line, editor=self._view_config.editor or None,
        )
        if opened:
            display = f"{path.name}" + (f":{line}" if line else "")
            self.notify(f"Opened {display}", severity="information", timeout=2)
        else:
            hint = (
                f"Couldn't open {path}. "
                f"File doesn't exist locally — scans run in a container "
                f"or CI emit paths the host can't see directly. "
                f"Try the Remote option, or set ``view.editor`` in argus.yml."
                if not path.exists()
                else f"Couldn't open {path} — no editor on PATH "
                f"and no $EDITOR / $VISUAL set"
            )
            self.notify(hint, severity="error", timeout=8)

    def action_open_remote_file(self, location: str) -> None:  # pragma: no cover
        """Open ``file:line`` on the git origin remote at the scan's SHA.

        Uses the scan-time commit SHA (when the scan captured one) so
        the link points at the code the scan actually saw, not whatever
        the contributor's HEAD happens to be. Strips the scan-time
        cwd / repo_root prefix off absolute paths so the URL points
        at the right file in the repo (not a non-existent
        ``/workspace/...`` subpath).
        """
        parsed = mouse_actions.parse_file_line(location)
        if not parsed:
            self.notify(
                f"Can't parse as a file path: {location!r}",
                severity="warning", timeout=3,
            )
            return
        path, line = parsed
        rel_path = self._repo_relative_path(path)
        if rel_path.is_absolute():
            # Couldn't normalize to repo-relative — likely a scan
            # without ``scan_context`` and an absolute path. Best-effort:
            # leave it alone and let git_blob_url's lstrip handle the
            # leading slash.
            self.notify(
                "Absolute path with no scan context — remote URL may "
                "point at the wrong file. Re-run the scan with a "
                "current argus build to capture scan_context.",
                severity="warning", timeout=6,
            )
        repo_root = self._resolve_repo_root()
        if not repo_root:
            self.notify(
                "Not inside a git repo — can't construct a remote URL",
                severity="warning", timeout=4,
            )
            return
        url = mouse_actions.git_blob_url(
            repo_root, rel_path, line, self._scan_ref,
        )
        if not url:
            self.notify(
                "Couldn't build a remote URL (no origin remote, "
                "or unrecognized remote shape)",
                severity="warning", timeout=4,
            )
            return
        if mouse_actions.open_in_browser(url):
            self.notify(f"Opened {url}", severity="information", timeout=2)
        else:
            self.notify(
                f"Couldn't open browser for {url}",
                severity="error", timeout=5,
            )

    def action_open_package(self, location: str) -> None:  # pragma: no cover
        """Open the registry page (PyPI / npm) for a ``name@version`` finding."""
        url = mouse_actions.package_url(location)
        if not url:
            self.notify(
                f"No registry URL for {location!r}",
                severity="warning", timeout=3,
            )
            return
        if mouse_actions.open_in_browser(url):
            self.notify(f"Opened registry page", severity="information", timeout=2)
        else:
            self.notify(
                f"Couldn't open browser for {url}",
                severity="error", timeout=5,
            )

    def _resolve_repo_root(self) -> Path | None:
        """Cached walk-up for ``.git``; starts from results_dir or cwd."""
        if self._repo_root is not None:
            return self._repo_root
        start = Path(self._results_dir or ".").resolve()
        root = mouse_actions.find_repo_root(start)
        if root is None:
            root = mouse_actions.find_repo_root(Path.cwd())
        self._repo_root = root
        return root


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
