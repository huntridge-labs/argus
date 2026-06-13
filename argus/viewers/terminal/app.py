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
  b             — toggle the runs sidebar (switch between discovered scan runs)
  R (shift+r)   — run ``argus scan`` in-app and reload results when it finishes
  F (shift+f)   — apply a deterministic Tier-1 fix (dependency bump) with diff preview
  q             — quit
"""

from __future__ import annotations

import re
from pathlib import Path

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.command import Hit, Hits, Provider
from textual.containers import Container, Vertical, VerticalScroll
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import DataTable, Footer, Header, Input, OptionList, Static
from textual.widgets.option_list import Option

from argus.viewers.terminal import mouse_actions, runs_sidebar, scan_runner
from argus.viewers.terminal.loader import flatten_findings, load_summary
from argus.core.config import ArgusConfig, ViewConfig
from argus.core.run_discovery import discover_runs
from argus.core import remediation
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
from argus.core.enrichment import (
    Enrichment,
    EnrichmentService,
    enrichment_detail_rows,
    is_cve,
    risk_badge,
)
from argus.core import ai_triage, reachability, suppressions, trends
from argus.core.models import Finding, Severity


# Module-local aliases preserved so downstream tests that introspected the
# old private names still work. New code should import from
# ``argus.core.findings_view``.
_SEVERITY_ORDER = SEVERITY_ORDER
_SEVERITY_GLYPH = SEVERITY_GLYPH
_SORT_LABELS = SORT_LABELS


# Textual markup actions look like ``app.action_open_location('arg')`` —
# the markup parser already validated the shape before emitting the
# meta, so a forgiving regex is fine here. Group 1 = action name,
# group 3 = the single string argument.
_ACTION_RE = re.compile(r"app\.(action_\w+)\(\s*(['\"])(.*?)\2\s*\)")


def _parse_click_action(action_str: str) -> tuple[str | None, str | None]:
    """Extract action name and string arg from a Textual ``@click`` meta value.

    Returns ``(None, None)`` for shapes we don't recognize so callers
    can no-op rather than crash on a malformed meta string.
    """
    if not action_str:
        return None, None
    match = _ACTION_RE.match(action_str.strip())
    if not match:
        return None, None
    return match.group(1), match.group(3)


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

[b]Runs & scanning[/b]
  [b]b[/b]                toggle the runs sidebar — switch between the scan
                   runs discovered next to the current one (newest first,
                   worst-severity glyph per run). Click or Enter to load one.
  [b]R[/b]                run a scan (shift+r) — launches argus scan, streams
                   its output in an overlay, and reloads results when it
                   finishes. Blank scanner = all enabled scanners.
  [b]F[/b]                fix (shift+f) — propose a deterministic dependency
                   bump for the focused finding (or every fixable row in the
                   selection), preview the diff, and apply it. Re-scan to confirm.

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

    def __init__(
        self,
        all_findings: list[Finding],
        source_label: str,
        runs: list[dict] | None = None,
    ):
        super().__init__()
        self._findings = all_findings
        self._source_label = source_label
        self._runs = runs or []

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

        # Trend + charts (Phase 8) — dependency-free Unicode visuals.
        for chart_line in self._chart_lines():
            lines.append(chart_line)

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

    def _chart_lines(self) -> list[str]:
        """Dependency-free Unicode charts for the dashboard (Phase 8)."""
        out: list[str] = []
        series = trends.run_count_series(self._runs)
        if len(series) >= 2:
            out.append("[b]Findings over time[/b]")
            out.append(
                f"  {trends.sparkline(series)}   "
                f"[dim]{trends.trend_summary(self._runs)}[/dim]"
            )
            out.append("")
        sev_items = [
            (f"{_SEVERITY_GLYPH.get(sev, '?')} {sev.value.capitalize()}", count)
            for sev, count in trends.severity_breakdown(self._findings)
        ]
        if sev_items:
            out.append("[b]By severity[/b]")
            out.extend(f"  {row}" for row in trends.bar_chart(sev_items))
            out.append("")
        scanner_items = trends.scanner_breakdown(self._findings)[:8]
        if scanner_items:
            out.append("[b]By scanner[/b]")
            out.extend(f"  {row}" for row in trends.bar_chart(scanner_items))
            out.append("")
        return out


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
    /* ``solid`` corners (┌ ┐ └ ┘) align more crisply than ``round``
       on macOS Terminal.app's default font; the rounded glyphs
       (╭ ╮ ╰ ╯) often wobble against the horizontal/vertical bars
       depending on the font's box-drawing metrics. */
    border: solid $accent; background: $surface;
    /* Clip anything inside so OptionList's highlight bar can't
       extend past the right border. */
    overflow: hidden;
}
ContextMenuScreen #menu-title { content-align: left middle; text-style: bold; padding: 0 0 1 0; }
ContextMenuScreen OptionList { width: 1fr; height: auto; max-height: 12; }
ContextMenuScreen #hint { color: $text-muted; padding: 1 0 0 0; content-align: left middle; }
"""


def _anchor_menu(
    screen, anchor: tuple[int, int] | None, *, menu_width: int, item_count: int,
) -> None:  # pragma: no cover — UI geometry
    """Position a context-menu screen's box at the right-click point.

    A right-click menu belongs at the cursor, not the screen centre.
    Leaves the CSS-centred placement untouched when ``anchor`` is None
    (keyboard / row-select invocation) or the menu body can't be found.
    The box height is derived from the item count plus fixed chrome
    (title + hint + padding + border) so we can clamp before a measured
    layout pass; ``clamp_menu_offset`` slides it back on-screen near an
    edge.
    """
    if anchor is None:
        return
    try:
        menu = screen.query_one(Vertical)
    except Exception:
        return
    menu_height = item_count + 6
    x, y = mouse_actions.clamp_menu_offset(
        anchor[0], anchor[1], menu_width, menu_height,
        screen.size.width, screen.size.height,
    )
    screen.styles.align_horizontal = "left"
    screen.styles.align_vertical = "top"
    menu.styles.offset = (x, y)


class ContextMenuScreen(_BackgroundDismissMixin, ModalScreen[str | None]):
    """Right-click / row-click context menu for a finding.

    Lists the actions that target the selected row directly:
      - Open advisory page (NVD / CVE.org / GHSA, per ``view.cve_source``)
      - Open file:line locally (in $EDITOR / VS Code / ...)
      - Open file:line in remote git (GitHub / GitLab blob URL)
      - Open package page (PyPI / npm)
      - Export selection (route to existing ``e`` action)

    Copying values isn't in the menu — terminal selection-copy
    already covers that workflow, and the right-click menu is
    reserved for actions terminals can't service themselves.

    Items that don't apply to this finding are filtered out before
    the modal mounts — a Bandit finding with no CVE, no file path,
    and no package@version location gets only "Export selection".
    """

    CSS = _MENU_CSS
    BINDINGS = [
        Binding("escape", "dismiss(None)", "Cancel", show=True),
        Binding("q", "dismiss(None)", "Quit"),
    ]

    # Matches the ``width: 60`` in _MENU_CSS — used to clamp the anchored
    # position so the box never spills off the right edge.
    _MENU_WIDTH = 60

    def __init__(
        self,
        finding: Finding,
        view_config: ViewConfig,
        anchor: tuple[int, int] | None = None,
    ):
        super().__init__()
        self._finding = finding
        self._view_config = view_config
        self._anchor = anchor
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
        if remediation.is_fixable(finding):
            pkg = finding.metadata.get("package")
            fixed = finding.metadata.get("fixed_version")
            self._items.append((f"⚒ Apply fix: {pkg} → {fixed}", "fix"))
        self._items.append(("Export current selection / view", "export"))

    def on_mount(self) -> None:  # pragma: no cover — UI geometry
        _anchor_menu(
            self, self._anchor,
            menu_width=self._MENU_WIDTH, item_count=len(self._items),
        )

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
    border: solid $accent; background: $surface;
    overflow: hidden;
}
OpenLocationPromptScreen #prompt-title { text-style: bold; padding: 0 0 1 0; }
OpenLocationPromptScreen OptionList { width: 1fr; height: auto; }
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


_SPAN_MENU_CSS = """
SpanContextMenuScreen { align: center middle; }
SpanContextMenuScreen > Vertical {
    width: 70; height: auto; padding: 1 2;
    border: solid $accent; background: $surface;
    overflow: hidden;
}
SpanContextMenuScreen #menu-title { content-align: left middle; text-style: bold; padding: 0 0 1 0; }
SpanContextMenuScreen OptionList { width: 1fr; height: auto; max-height: 10; }
SpanContextMenuScreen #hint { color: $text-muted; padding: 1 0 0 0; content-align: left middle; }
"""


class SpanContextMenuScreen(_BackgroundDismissMixin, ModalScreen[str | None]):
    """Narrow right-click menu for a single clickable span.

    The per-finding ``ContextMenuScreen`` ships every action that could
    apply to the row; this screen renders only the actions relevant to
    the span the user actually right-clicked (a path, a CVE link, a
    package@version). Keeps the menu scannable when the user knows
    exactly what they want to do.

    Items are a list of ``(label, action_key)`` tuples; the parent
    dispatches on the action key when the modal dismisses.
    """

    CSS = _SPAN_MENU_CSS
    BINDINGS = [
        Binding("escape", "dismiss(None)", "Cancel", show=True),
        Binding("q", "dismiss(None)", "Quit"),
    ]

    # Matches the ``width: 70`` in _SPAN_MENU_CSS.
    _MENU_WIDTH = 70

    def __init__(
        self,
        title: str,
        items: list[tuple[str, str]],
        anchor: tuple[int, int] | None = None,
    ):
        super().__init__()
        self._title = title
        self._items = items
        self._anchor = anchor

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static(self._title, id="menu-title")
            yield OptionList(
                *(Option(label, id=key) for label, key in self._items),
                id="menu-list",
            )
            yield Static("↑↓ Enter to select  ·  Esc to cancel", id="hint")

    def on_mount(self) -> None:  # pragma: no cover — UI geometry
        _anchor_menu(
            self, self._anchor,
            menu_width=self._MENU_WIDTH, item_count=len(self._items),
        )

    def on_option_list_option_selected(  # pragma: no cover — UI event
        self, event: OptionList.OptionSelected,
    ) -> None:
        self.dismiss(event.option.id or None)


_EXPLAIN_CSS = """
ExplainScreen { align: center middle; }
ExplainScreen > Vertical {
    width: 88%; max-width: 110; height: 70%;
    border: thick $accent; background: $surface; padding: 1 2;
}
ExplainScreen #explain-title { text-style: bold; padding: 0 0 1 0; }
ExplainScreen #explain-scroll { height: 1fr; border: solid $accent; padding: 0 1; }
ExplainScreen #explain-hint { color: $text-muted; padding: 1 0 0 0; }
"""


class ExplainScreen(_BackgroundDismissMixin, ModalScreen):
    """AI explanation overlay for a finding (Phase 10).

    Runs the model call in a thread so the UI never blocks, then shows the
    text. The runner is injectable for tests; model output is advisory only
    (a suggested fix would still go through the Phase-1 diff gate).
    """

    CSS = _EXPLAIN_CSS
    BINDINGS = [
        Binding("escape", "dismiss", "Close", show=True),
        Binding("q", "dismiss", show=False),
    ]

    def __init__(self, finding, provider, *, enrichment_summary="", runner=None, label=""):
        super().__init__()
        self._finding = finding
        self._provider = provider
        self._enrichment_summary = enrichment_summary
        self._runner = runner or ai_triage.triage_explain
        self._label = label

    def compose(self) -> ComposeResult:  # pragma: no cover — UI
        with Vertical():
            title = f"🤖 Explain · {self._finding.id}"
            if self._label:
                title += f"   [dim]{self._label}[/dim]"
            yield Static(title, id="explain-title")
            with VerticalScroll(id="explain-scroll"):
                yield Static("[dim]Thinking…[/dim]", id="explain-text")
            yield Static("esc to close  ·  AI output is advisory — verify before acting", id="explain-hint")

    def on_mount(self) -> None:  # pragma: no cover — UI/worker
        self.run_worker(self._work, thread=True, exclusive=True)

    def _work(self) -> None:  # pragma: no cover — worker thread
        try:
            text = self._runner(
                self._finding, provider=self._provider,
                enrichment_summary=self._enrichment_summary,
            )
        except Exception as exc:  # model/network failure → show, don't crash
            text = f"[red]AI request failed:[/red] {exc}"
        self.call_from_thread(self._show, text or "[dim](no response)[/dim]")

    def _show(self, text: str) -> None:  # pragma: no cover — UI
        self.query_one("#explain-text", Static).update(text)


_SUPPRESS_CSS = """
SuppressScreen { align: center middle; }
SuppressScreen > Vertical {
    width: 78; height: auto; padding: 1 2;
    border: thick $accent; background: $surface; overflow: hidden;
}
SuppressScreen #suppress-title { text-style: bold; padding: 0 0 1 0; }
SuppressScreen .label { color: $text-muted; }
SuppressScreen Input { margin: 0 0 1 0; }
SuppressScreen #suppress-actions { height: auto; border: none; background: transparent; }
SuppressScreen #suppress-hint { color: $text-muted; padding: 1 0 0 0; }
"""


class SuppressScreen(_BackgroundDismissMixin, ModalScreen[dict | None]):
    """Capture a triage decision for the focused finding / selection.

    Dismisses with ``{"action": <key>, "reason": <text>}`` when a status is
    picked, or ``None`` on cancel. ``action`` is a key of
    ``suppressions.ACTIONS``; the caller turns it into an OpenVEX statement +
    ignore-file entries via ``argus.core.suppressions``.
    """

    CSS = _SUPPRESS_CSS
    BINDINGS = [Binding("escape", "dismiss(None)", "Cancel", show=True)]

    def __init__(self, count: int):
        super().__init__()
        self._count = count

    def compose(self) -> ComposeResult:  # pragma: no cover — UI
        with Vertical():
            yield Static(f"⊘ Triage {self._count} finding(s)", id="suppress-title")
            yield Static("Reason (recorded in the VEX audit trail):", classes="label")
            yield Input(
                placeholder="e.g. vendored dep · not reachable · mitigated at WAF",
                id="suppress-reason",
            )
            yield Static("Status:", classes="label")
            yield OptionList(
                *(
                    Option(suppressions.ACTION_LABELS[key], id=key)
                    for key in suppressions.ACTIONS
                ),
                id="suppress-actions",
            )
            yield Static(
                "type a reason  ·  enter → status list  ·  ↑↓ + enter pick  ·  esc cancel",
                id="suppress-hint",
            )

    def on_mount(self) -> None:  # pragma: no cover — UI
        self.query_one("#suppress-reason", Input).focus()

    def on_input_submitted(self, event: "Input.Submitted") -> None:  # pragma: no cover — UI
        self.query_one("#suppress-actions", OptionList).focus()

    def on_option_list_option_selected(  # pragma: no cover — UI
        self, event: OptionList.OptionSelected,
    ) -> None:
        reason = self.query_one("#suppress-reason", Input).value.strip()
        self.dismiss({"action": event.option.id, "reason": reason})


_RUN_PROMPT_CSS = """
RunScanPromptScreen { align: center middle; }
RunScanPromptScreen > Vertical {
    width: 72; height: auto; padding: 1 2;
    border: solid $accent; background: $surface; overflow: hidden;
}
RunScanPromptScreen #title { text-style: bold; padding: 0 0 1 0; }
RunScanPromptScreen Input { margin: 0 0 1 0; }
RunScanPromptScreen .label { color: $text-muted; }
RunScanPromptScreen #hint { color: $text-muted; padding: 1 0 0 0; }
"""


class RunScanPromptScreen(_BackgroundDismissMixin, ModalScreen[dict | None]):
    """Collect scan parameters before launching ``argus scan``.

    Returns ``{"scanner": str | None, "path": str}`` on submit (Enter in
    either field), or ``None`` on cancel. A blank scanner means "all
    enabled scanners from the config" — the same default as a bare
    ``argus scan``.
    """

    CSS = _RUN_PROMPT_CSS
    BINDINGS = [
        Binding("escape", "dismiss(None)", "Cancel", show=True),
    ]

    def __init__(self, default_path: str = "."):
        super().__init__()
        self._default_path = default_path

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static("▶ Run a scan", id="title")
            yield Static("Scanner (blank = all enabled):", classes="label")
            yield Input(placeholder="e.g. bandit, gitleaks, osv", id="scan-scanner")
            yield Static("Path to scan:", classes="label")
            yield Input(value=self._default_path, id="scan-path")
            yield Static("Enter to run  ·  Esc to cancel", id="hint")

    def on_mount(self) -> None:  # pragma: no cover — UI event
        self.query_one("#scan-scanner", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:  # pragma: no cover — UI event
        scanner = self.query_one("#scan-scanner", Input).value.strip() or None
        path = self.query_one("#scan-path", Input).value.strip() or "."
        self.dismiss({"scanner": scanner, "path": path})


_RUN_OUTPUT_CSS = """
RunScanScreen { align: center middle; }
RunScanScreen > Vertical {
    width: 90%; max-width: 130; height: 80%;
    border: thick $accent; background: $surface; padding: 1 2;
}
RunScanScreen #run-cmd { text-style: bold; padding: 0 0 1 0; }
RunScanScreen #run-output { height: 1fr; border: solid $accent; padding: 0 1; }
RunScanScreen #run-status { padding: 1 0 0 0; color: $text-muted; }
"""

# Cap the in-memory output buffer so a chatty scan can't grow the pane
# unbounded; we keep the tail (where the summary + exit live).
_RUN_LOG_MAX_LINES = 2000
_RUN_LOG_VISIBLE_LINES = 500


class RunScanScreen(ModalScreen[str | None]):
    """Run ``argus scan`` as a subprocess, streaming its output live.

    Dismisses with the path of the freshly-written run on success (so
    the caller can load it), or ``None`` if the scan failed or was
    cancelled. Output streams into a scrolling pane; the subprocess is
    terminated if the user cancels before it finishes.

    The streaming + subprocess machinery is UI glue (``# pragma: no
    cover``); the testable pieces — argv construction and the post-run
    "which run do I load?" decision — live in
    ``argus.viewers.terminal.scan_runner`` and ``discover_runs``.
    """

    CSS = _RUN_OUTPUT_CSS
    BINDINGS = [
        Binding("escape", "cancel", "Cancel / Close", show=True),
    ]

    def __init__(self, argv: list[str], *, launch_root: Path):
        super().__init__()
        self._argv = argv
        self._launch_root = launch_root
        self._lines: list[str] = []
        self._proc = None
        self._finished = False
        self._result_path: str | None = None

    def compose(self) -> ComposeResult:  # pragma: no cover — UI
        with Vertical():
            yield Static(scan_runner.format_command(self._argv), id="run-cmd")
            with VerticalScroll(id="run-output"):
                yield Static("", id="run-log")
            yield Static("Running…  ·  Esc to cancel", id="run-status")

    def on_mount(self) -> None:  # pragma: no cover — UI/worker
        self.run_worker(self._stream(), exclusive=True)

    async def _stream(self) -> None:  # pragma: no cover — subprocess streaming
        import asyncio
        try:
            self._proc = await asyncio.create_subprocess_exec(
                *self._argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
        except OSError as exc:
            self._append(f"Failed to launch scan: {exc}")
            self._mark_done(success=False)
            return
        if self._proc.stdout is not None:
            async for raw in self._proc.stdout:
                self._append(raw.decode(errors="replace").rstrip("\n"))
        code = await self._proc.wait()
        self._mark_done(success=(code == 0), code=code)

    def _append(self, line: str) -> None:  # pragma: no cover — UI
        self._lines.append(line)
        if len(self._lines) > _RUN_LOG_MAX_LINES:
            self._lines = self._lines[-_RUN_LOG_MAX_LINES:]
        try:
            self.query_one("#run-log", Static).update(
                "\n".join(self._lines[-_RUN_LOG_VISIBLE_LINES:])
            )
            self.query_one("#run-output", VerticalScroll).scroll_end(animate=False)
        except Exception:
            pass

    def _mark_done(self, *, success: bool, code: int | None = None) -> None:  # pragma: no cover — UI
        self._finished = True
        if success:
            runs = discover_runs(self._launch_root)
            self._result_path = runs[0]["path"] if runs else None
            msg = "✓ Scan complete  ·  Enter to load results  ·  Esc to close"
        else:
            msg = f"✗ Scan failed (exit {code})  ·  Esc to close"
        try:
            self.query_one("#run-status", Static).update(msg)
        except Exception:
            pass

    def action_cancel(self) -> None:  # pragma: no cover — UI
        if self._proc is not None and not self._finished:
            try:
                self._proc.terminate()
            except (ProcessLookupError, OSError):
                pass
        self.dismiss(self._result_path if self._finished else None)

    def on_key(self, event) -> None:  # pragma: no cover — UI
        if getattr(event, "key", None) == "enter" and self._finished:
            self.dismiss(self._result_path)


_FIX_CSS = """
FixScreen { align: center middle; }
FixScreen > Vertical {
    width: 90%; max-width: 110; height: auto; max-height: 90%;
    border: thick $accent; background: $surface; padding: 1 2;
}
FixScreen #fix-title { text-style: bold; padding: 0 0 1 0; }
FixScreen #fix-body { height: auto; max-height: 1fr; }
FixScreen #fix-hint { color: $text-muted; padding: 1 0 0 0; }
"""


def render_fix_preview(remediations: list) -> str:
    """Build the Fix overlay's markup body from proposed remediations.

    Pure (no Textual) so it's unit-testable: shows each fix's title, the
    unified diff (escaped) for file edits, or the command for fallbacks.
    """
    def _esc(s: str) -> str:
        return s.replace("[", r"\[").replace("]", r"\]")

    lines: list[str] = []
    for rem in remediations:
        marker = "[green]✓[/green]" if rem.confidence == "high" else "[yellow]~[/yellow]"
        lines.append(f"{marker} [b]{_esc(rem.title)}[/b]")
        if rem.diff:
            for dl in rem.diff.splitlines():
                if dl.startswith("+") and not dl.startswith("+++"):
                    lines.append(f"[green]{_esc(dl)}[/green]")
                elif dl.startswith("-") and not dl.startswith("---"):
                    lines.append(f"[red]{_esc(dl)}[/red]")
                else:
                    lines.append(f"[dim]{_esc(dl)}[/dim]")
        elif rem.command:
            lines.append(f"  [dim]run:[/dim] {_esc(' '.join(rem.command))}")
        if rem.note:
            lines.append(f"  [dim]{_esc(rem.note)}[/dim]")
        lines.append("")
    return "\n".join(lines).rstrip()


class FixScreen(_BackgroundDismissMixin, ModalScreen[bool]):
    """Preview proposed Tier-1 fixes and apply them on confirm.

    Diff-first: nothing touches the working tree until the user presses
    Enter / a. ``apply`` is delegated to ``argus.core.remediation`` by the
    parent on a ``True`` dismissal; this screen is the reviewer.
    """

    CSS = _FIX_CSS
    BINDINGS = [
        Binding("escape", "dismiss(False)", "Cancel", show=True),
        Binding("a", "dismiss(True)", "Apply", show=True),
        Binding("enter", "dismiss(True)", "Apply", show=False),
    ]

    def __init__(self, remediations: list):
        super().__init__()
        self._remediations = remediations

    def compose(self) -> ComposeResult:  # pragma: no cover — UI
        applicable = sum(1 for r in self._remediations if r.is_applicable)
        with Vertical():
            yield Static(
                f"⚒  Apply {len(self._remediations)} fix(es)  "
                f"[dim]({applicable} edit file(s) directly)[/dim]",
                id="fix-title",
            )
            with VerticalScroll(id="fix-body"):
                yield Static(render_fix_preview(self._remediations))
            yield Static(
                "enter / a apply   ·   esc cancel", id="fix-hint",
            )

    def on_mount(self) -> None:  # pragma: no cover — UI
        self.query_one("#fix-body", VerticalScroll).focus()


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
            ("Runs: Toggle the runs sidebar", "Show / hide the list of discovered scan runs and switch between them (b)", app.action_toggle_runs),
            ("Scan: Run argus scan", "Launch argus scan from the TUI, stream output, and reload results when done (shift+r)", app.action_run_scan),
            ("Fix: Apply a Tier-1 dependency bump", "Propose + preview + apply a deterministic fix for the focused finding or selection (shift+f)", app.action_fix),
            ("Intel: Enrich with EPSS + CISA KEV", "Fetch exploit-probability + known-exploited intelligence for the CVEs in view (i)", app.action_enrich),
            ("Triage: Suppress / accept-risk (VEX)", "Record a triage decision to OpenVEX + .trivyignore/.gitleaksignore for the focused finding or selection (shift+s)", app.action_suppress),
            ("AI: Explain this finding", "Ask a local (Ollama) or cloud model to explain the focused finding (x)", app.action_explain),
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


_PLACEHOLDER_CHARS = set("—-@ \t")
"""Characters that, on their own, signal "no data" in detail rows.

``finding_detail_rows`` uses em-dash (``—``) for missing fields, and
the Package row composes ``f"{pkg} @ {installed}"`` so an unset
package becomes ``"— @ —"``. Detail-pane rendering treats any value
made up of only these characters as a placeholder — no click target.
"""


def _looks_placeholder(value: str) -> bool:
    """Return True when ``value`` is entirely placeholder characters."""
    return bool(value) and all(ch in _PLACEHOLDER_CHARS for ch in value)


class FindingDetail(Static):
    """Right pane — plain-text detail view for the selected finding.

    Content structure comes from ``finding_detail_rows`` in the shared
    core module so the TUI and a future web view stay aligned. This
    widget only handles the Textual-markup wrapping.
    """

    def update_finding(
        self,
        f: Finding | None,
        source_block: str | None = None,
        enrichment: "Enrichment | None" = None,
        reachability: str | None = None,
    ) -> None:
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
        badge = risk_badge(enrichment)
        badge_md = f"   [b]{badge}[/b]" if badge else ""
        lines = [f"[bold]{header_id}[/bold]   {glyph}{badge_md}", ""]

        # Enrichment rows (EPSS / KEV / Risk) append after the core rows when
        # the finding's CVE has been enriched; empty otherwise.
        rows = finding_detail_rows(f) + enrichment_detail_rows(f.severity, enrichment)
        if reachability:
            rows = rows + [("Reachability", reachability)]
        for label, value in rows:
            rendered = self._linkify_value(label, value)
            lines.append(f"[b]{label}:[/b]".ljust(13) + f" {rendered}")
        lines += ["", "[b]Title[/b]", f.title or "—"]
        if f.description and f.description != f.title:
            lines += ["", "[b]Description[/b]", f.description]
        # Source-context block — only present when ``location`` is a
        # file:line and the file resolved to a local checkout. The
        # caller (BrowseApp._update_detail) pre-formats the markup so
        # this widget stays UI-only and the read-and-format logic is
        # testable without Textual.
        if source_block:
            lines += ["", "[b]Source[/b]", source_block]
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
        """Wrap location / package values in click handlers when applicable.

        Skips placeholder values where the underlying data is missing
        (``—``, ``— @ —``, etc.) so users don't get a clickable cell
        that fails to parse. The Package row uses ``f"{pkg} @ {installed}"``
        with em-dash defaults, so ``— @ —`` means "no package data" —
        not a real ``name@version`` value.
        """
        if not value or _looks_placeholder(value):
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
    /* Runs sidebar — hidden until toggled with ``b``. Fixed width so the
       findings list keeps the lion's share of the row; the findings list
       flexes (1fr) to fill whatever the sidebar + detail pane leave. */
    #runs-pane { width: 30; display: none; }
    #runs-pane.-visible { display: block; }
    #runs-title { text-style: bold; padding: 0 1; }
    #runs-list { height: 1fr; }
    #list-pane { width: 1fr; }
    #detail-pane { width: 46%; padding: 0 2; }
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
        # Runs sidebar + in-app scan runner. ``b`` toggles the list of
        # discovered scan runs (switch between them without relaunching);
        # ``R`` (shift+r) launches ``argus scan`` and reloads results when
        # it finishes. Lowercase ``r`` stays the reveal-export action.
        Binding("b", "toggle_runs", "Runs", show=True),
        Binding("R", "run_scan", "Run scan", show=True),
        # Deterministic Tier-1 fix (dependency bump) for the focused finding
        # — or every fixable row in the multi-select set. Diff-first: shows
        # the proposed change before touching anything.
        Binding("F", "fix", "Fix", show=True),
        # Live vulnerability intelligence: fetch EPSS (exploit probability) +
        # CISA KEV (actively-exploited) for the CVEs in view and re-prioritise
        # by real-world risk. Opt-in / offline-degrading — only reaches out
        # when pressed.
        Binding("i", "enrich", "Intel", show=True),
        # Bulk triage: record a decision (false-positive / not-exploitable /
        # accept-risk / under-investigation) for the focused finding or the
        # whole selection, writing an OpenVEX audit trail + scanner ignore
        # entries so the next scan honours it.
        Binding("S", "suppress", "Suppress", show=True),
        # AI-assisted triage: ask a local (Ollama) or cloud model to explain
        # the focused finding. Opt-in, local-first, no key required to use
        # Argus — stays off with a hint when nothing is configured.
        Binding("x", "explain", "Explain", show=True),
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
        # Live vulnerability intelligence (Phase 6): CVE → Enrichment, filled
        # on demand by ``action_enrich`` (``i``). Empty until the user asks,
        # so the viewer never reaches the network unprompted.
        self._enrichment: dict[str, Enrichment] = {}
        # Injectable for tests; None ⇒ a default service (env-driven offline
        # detection, on-disk cache) is built on first ``action_enrich``.
        self._enrichment_service: EnrichmentService | None = None
        # AI triage (Phase 10): a (provider, label) override for tests; None ⇒
        # resolved from the environment (local Ollama / cloud key) on demand.
        self._ai_provider_override: tuple[object | None, str] | None = None
        # Reachability (Phase 12): cache the "imported in source?" heuristic
        # per ecosystem:package so the bounded source scan runs at most once
        # per dependency, not on every detail-pane refresh.
        self._reachability_cache: dict[str, str] = {}
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
        # Last hover (row_index, click_action) seen by on_mouse_move.
        # Used to dedup tooltip updates — mouse_move fires per pixel
        # of movement, so we skip work when the meta hasn't changed.
        self._last_hover_key: tuple[int | None, str | None] = (None, None)
        # Runs sidebar state. ``_launch_root`` is the directory we scan
        # for sibling runs (resolved in on_mount); ``_current_results_path``
        # is the run currently loaded (for the "● you are here" marker);
        # ``_runs`` is the last discover_runs() result, indexed by the
        # OptionList selection handler. ``_anchor`` carries the last
        # right-click screen coordinate so context menus open at the
        # cursor rather than screen-centre.
        self._launch_root: Path = self._compute_launch_root()
        self._current_results_path: Path | None = None
        self._runs: list[dict] = []
        self._menu_anchor: tuple[int, int] | None = None

    @staticmethod
    def _load_view_config() -> ViewConfig:
        """Best-effort ArgusConfig.view load. Always returns a usable
        ViewConfig — defaults if nothing's on disk or anything errors."""
        try:
            return ArgusConfig.load().view
        except Exception:  # pragma: no cover — defensive
            return ViewConfig()

    def _compute_launch_root(self) -> Path:
        """Directory the runs sidebar searches for sibling scan runs.

        Falls back to ``argus-results`` (argus scan's default output
        home) when launched without an explicit path, matching the
        loader's own default. ``discover_runs`` handles the "this is
        itself a single run" case by walking up to the parent, so we
        don't need to second-guess the shape here.
        """
        return (
            Path(self._results_dir).resolve()
            if self._results_dir else Path("argus-results").resolve()
        )

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        yield SearchInput(
            placeholder="Search (id, title, location, CVE, scanner)… "
                        "↓ or ESC to return to list",
            id="search",
        )
        with Container(id="body"):
            with Vertical(id="runs-pane"):
                yield Static("Runs", id="runs-title")
                yield OptionList(id="runs-list")
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
        self._current_results_path = resolved
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
        # Initial tooltip is the generic blurb; ``on_mouse_move`` swaps
        # it for a per-row summary (severity / id / package / first
        # line of description) once the cursor lands on a real row.
        # Discoverability of the underlined click targets stays in the
        # help screen (``?``).
        table.tooltip = (
            "Hover a row for finding details · "
            "Right-click for actions · "
            "Click a column header to sort"
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
        # Discover sibling runs and fill the (initially hidden) sidebar.
        self._populate_runs()
        # Open into the findings list, not the search box. The search
        # input is the first focusable child by yield order, so without
        # this users land in the search field and find that ↑/↓ edit
        # the query rather than navigating findings.
        table.focus()

    # ------------------------------------------------------------------
    # Runs sidebar + run switching
    # ------------------------------------------------------------------

    def _populate_runs(self) -> None:
        """Discover sibling runs and (re)fill the runs sidebar OptionList.

        Auto-reveals the sidebar the first time more than one run is
        found, so the switch-runs affordance is discoverable without
        the user knowing the ``b`` keybind; once revealed it stays put.
        Defensive against a missing widget (mid-recompose / stubbed
        tests) — a failed lookup just skips the refresh.
        """
        from textual.widgets.option_list import Option
        self._runs = discover_runs(
            self._launch_root, current=self._current_results_path,
        )
        try:
            option_list = self.query_one("#runs-list", OptionList)
        except Exception:
            return
        option_list.clear_options()
        current = (
            str(self._current_results_path) if self._current_results_path else None
        )
        for run in self._runs:
            is_current = run.get("path") == current
            option_list.add_option(
                Option(
                    runs_sidebar.format_run_row(run, current=is_current),
                    id=runs_sidebar.run_option_id(run),
                )
            )
        # Reveal automatically once there's more than one run to choose
        # between; below that the sidebar would just be visual noise.
        if len(self._runs) > 1:
            self._set_runs_visible(True)

    def _set_runs_visible(self, visible: bool) -> None:
        """Show or hide the runs pane. No-op if the pane isn't mounted."""
        try:
            pane = self.query_one("#runs-pane")
        except Exception:
            return
        pane.display = visible

    def action_toggle_runs(self) -> None:
        """Toggle the runs sidebar (``b``) and focus it when revealed."""
        try:
            pane = self.query_one("#runs-pane")
        except Exception:
            return
        now_visible = not bool(pane.display)
        pane.display = now_visible
        if now_visible:
            try:
                self.query_one("#runs-list", OptionList).focus()
            except Exception:
                pass
        else:
            try:
                self.query_one(DataTable).focus()
            except Exception:
                pass

    def on_option_list_option_selected(  # pragma: no cover — UI event
        self, event,
    ) -> None:
        """Switch to the run the user picked in the sidebar.

        Only the main-screen runs list reaches this handler — picker
        modals are separate screens that consume their own selections —
        but we still guard on the widget id so an unrelated future
        OptionList can't accidentally trigger a run switch.
        """
        option_list = getattr(event, "option_list", None)
        if option_list is None or getattr(option_list, "id", None) != "runs-list":
            return
        path = getattr(event.option, "id", None)
        if path:
            self._switch_run(path)

    def _switch_run(self, path: str) -> None:
        """Load the run at ``path`` in place, keeping filters/sort.

        Resets the multi-select set (it keyed off the previous run's
        finding objects) but preserves the active severity/product/
        scanner/search filters — switching runs to compare the same
        slice across scans is the common motivation. Surfaces load
        failures as a toast rather than crashing the session.
        """
        try:
            summary, resolved = load_summary(path)
        except (FileNotFoundError, ValueError, OSError) as exc:
            self.notify(
                f"Couldn't load run: {exc}", severity="error", timeout=6,
            )
            return
        self.all_findings = flatten_findings(summary)
        self._current_results_path = resolved
        self.sub_title = str(resolved)
        self._scan_context = getattr(summary, "scan_context", None)
        if self._scan_context is not None and self._scan_context.commit_sha:
            self._scan_ref = self._scan_context.commit_sha
        # New run → the old selection's object identities are stale.
        self._selected.clear()
        self._refresh_list()
        self._populate_runs()

    def action_run_scan(self) -> None:  # pragma: no cover — UI event
        """Launch ``argus scan`` from inside the TUI (``R``).

        Prompts for scanner + path, streams the scan in an overlay, and
        reloads the freshly-written run when it finishes successfully.
        """
        def _on_params(params: dict | None) -> None:
            if not params:
                return
            output_base = scan_runner.resolve_output_base(self._results_dir)
            argv = scan_runner.build_scan_argv(
                scanner=params.get("scanner"),
                path=params.get("path") or ".",
                output_dir=output_base,
            )

            def _on_done(new_path: str | None) -> None:
                if new_path:
                    self._switch_run(new_path)
                    self.notify(
                        "Loaded the new scan results.",
                        severity="information", timeout=3,
                    )

            self.push_screen(
                RunScanScreen(argv, launch_root=self._launch_root), _on_done,
            )

        self.push_screen(RunScanPromptScreen(), _on_params)

    def action_fix(self) -> None:  # pragma: no cover — UI event
        """Apply a Tier-1 fix to the selection (or the focused finding) (``F``).

        Targets the multi-select set when one is active, else the focused
        row. Proposes a deterministic remediation per finding, previews the
        diffs in a FixScreen, and applies on confirm.
        """
        if self._selected:
            targets = [f for f in self.all_findings if id(f) in self._selected]
        else:
            row = self._focused_row_index()
            targets = [self._visible[row]] if row is not None else []
        self._fix_findings(targets)

    def _fix_findings(self, findings: list[Finding]) -> None:  # pragma: no cover — UI
        """Propose + preview + apply Tier-1 fixes for ``findings``."""
        if not findings:
            return
        repo_root = self._resolve_repo_root() or Path.cwd()
        proposals = [
            rem for rem in (
                remediation.propose(f, repo_root=repo_root) for f in findings
            ) if rem is not None
        ]
        if not proposals:
            self.notify(
                "No automatic fix available for the selected finding(s). "
                "Tier-1 fixes cover dependency bumps with a known fixed version.",
                severity="warning", timeout=5,
            )
            return

        def _on_confirm(apply_it: bool | None) -> None:
            if not apply_it:
                return
            applied, failed = 0, 0
            messages: list[str] = []
            for rem in proposals:
                result = remediation.apply(rem, repo_root=repo_root)
                if result.ok:
                    applied += 1
                else:
                    failed += 1
                    messages.append(result.message)
            summary = f"Applied {applied} fix(es)."
            if failed:
                summary += f" {failed} need manual steps: " + " | ".join(messages[:3])
            summary += " Re-run the scan ([b]R[/b]) to confirm."
            self.notify(
                summary,
                severity="information" if applied else "warning",
                timeout=10,
            )

        self.push_screen(FixScreen(proposals), _on_confirm)

    # ------------------------------------------------------------------
    # Filter / sort / search
    # ------------------------------------------------------------------

    def _refresh_list(self) -> None:
        """Rebuild the DataTable + status bar from the current view state.

        Defensive: if the DataTable is missing from the screen (race
        with screen recompose, mid-shutdown, etc.) we bail rather
        than crash. Observed in practice when typing into the search
        input during a screen transition.
        """
        try:
            table = self.query_one(DataTable)
        except Exception:
            return
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
        if not (0 <= row < len(self._visible)):
            return
        finding = self._visible[row]
        block = self._source_context_block(finding)
        enrichment = self._enrichment.get(finding.cve.upper()) if finding.cve else None
        self.query_one("#detail", FindingDetail).update_finding(
            finding, source_block=block, enrichment=enrichment,
            reachability=self._reachability_label(finding),
        )

    def _reachability_label(self, finding: Finding) -> str | None:
        """The "imported in source?" label for a dependency finding (Phase 12).

        Returns ``None`` for non-dependency / unsupported-ecosystem findings.
        Cached per ecosystem:package so the bounded source scan runs once.
        """
        package = reachability.package_of(finding)
        ecosystem = reachability.ecosystem_of(finding)
        if not package or ecosystem is None:
            return None
        key = f"{ecosystem}:{package}"
        if key not in self._reachability_cache:
            root = self._resolve_repo_root() or Path.cwd()
            self._reachability_cache[key] = reachability.is_imported(
                package, ecosystem, root=root, max_files=1500,
            )
        return reachability.reachability_label(self._reachability_cache[key])

    def action_enrich(self) -> None:  # pragma: no cover — UI/worker
        """Fetch EPSS + CISA KEV intelligence for the CVEs in view (``i``).

        Opt-in and offline-degrading: only reaches the network when pressed,
        runs in a thread so the UI never blocks, and no-ops cleanly when
        offline or when no CVE-identified findings are present.
        """
        cves = sorted({f.cve for f in self.all_findings if is_cve(f.cve)})
        if not cves:
            self.notify("No CVE-identified findings to enrich.", severity="information")
            return
        service = self._enrichment_service or EnrichmentService()
        if service.offline:
            self.notify(
                "Offline — enrichment needs network access (EPSS + CISA KEV).",
                severity="warning",
            )
            return
        self.notify(
            f"Fetching EPSS + CISA KEV for {len(cves)} CVEs…", severity="information",
        )
        self.run_worker(
            lambda: self._enrich_work(service, cves), thread=True, exclusive=True,
        )

    def _enrich_work(  # pragma: no cover — worker thread
        self, service: EnrichmentService, cves: list[str],
    ) -> None:
        result = service.enrich(cves)
        self.call_from_thread(self._apply_enrichment, result)

    def _apply_enrichment(  # pragma: no cover — UI
        self, result: dict[str, Enrichment],
    ) -> None:
        self._enrichment.update(result)
        kev = sum(1 for e in result.values() if e.kev)
        epss = [e.epss for e in result.values() if e.epss is not None]
        top = round(max(epss) * 100) if epss else 0
        self.notify(
            f"Enriched {len(result)} CVEs · {kev} in CISA KEV · top EPSS {top}%",
            severity="information",
        )
        self._update_detail(self.query_one(DataTable).cursor_row)

    def action_suppress(self) -> None:  # pragma: no cover — UI
        """Triage the focused finding / selection → OpenVEX + ignore files (``S``).

        Prompts for a status + reason, then writes an OpenVEX statement (the
        audit trail) and the matching ``.trivyignore`` / ``.gitleaksignore``
        entries so the next scan honours the decision.
        """
        targets = self._suppress_targets()
        if not targets:
            self.notify("No findings to triage.", severity="information")
            return

        def _after(result: dict | None) -> None:
            if result:
                self._apply_suppression(targets, result["action"], result["reason"])

        self.push_screen(SuppressScreen(len(targets)), _after)

    def _suppress_targets(self) -> list[Finding]:  # pragma: no cover — UI
        if self._selected:
            return [f for f in self.all_findings if id(f) in self._selected]
        row = self.query_one(DataTable).cursor_row
        return [self._visible[row]] if 0 <= row < len(self._visible) else []

    def _apply_suppression(  # pragma: no cover — UI
        self, targets: list[Finding], action: str, reason: str,
    ) -> None:
        decisions = [
            suppressions.decision_for(
                action,
                cve=f.cve or "",
                product=self._suppress_product(f),
                reason=reason,
                scanner=f.scanner,
            )
            for f in targets
        ]
        repo_root = self._resolve_repo_root() or Path.cwd()
        written = suppressions.write_suppressions(repo_root, decisions)
        if written:
            artifacts = ", ".join(sorted(written))
            self.notify(
                f"Triaged {len(targets)} finding(s) → {artifacts}",
                severity="information",
            )
        else:
            self.notify(
                "Nothing written — findings need a CVE or fingerprint to record.",
                severity="warning",
            )

    @staticmethod
    def _suppress_product(finding: Finding) -> str:  # pragma: no cover — UI
        meta = finding.metadata or {}
        return (meta.get("purl") or meta.get("fingerprint") or "").strip()

    def action_explain(self) -> None:  # pragma: no cover — UI
        """Ask a local/cloud model to explain the focused finding (``x``).

        Local-first and opt-in: uses a local Ollama endpoint when enabled,
        a cloud provider when a key is set, and otherwise stays off with a
        hint (no silent egress, no key required to use Argus).
        """
        row = self.query_one(DataTable).cursor_row
        if not (0 <= row < len(self._visible)):
            self.notify("Select a finding to explain.", severity="information")
            return
        finding = self._visible[row]
        provider, label = self._ai_provider_override or ai_triage.provider_from_env()
        if provider is None:
            self.notify(
                "AI is off — set ARGUS_AI_LOCAL=1 for a local Ollama model, "
                "or ARGUS_AI_PROVIDER + an API key for a cloud model.",
                severity="warning", timeout=8,
            )
            return
        enr = self._enrichment.get(finding.cve.upper()) if finding.cve else None
        self.push_screen(ExplainScreen(
            finding, provider, enrichment_summary=risk_badge(enr), label=label,
        ))

    def _source_context_block(self, finding: Finding) -> str | None:
        """Render the ``[bold]Source[/bold]`` block for the detail pane.

        Returns Textual markup with line numbers and the offending
        line highlighted, or ``None`` when no source is available
        (location isn't file:line, or the file doesn't resolve
        locally, or the file isn't readable).
        """
        if not finding.location:
            return None
        parsed = mouse_actions.parse_file_line(finding.location)
        if not parsed:
            return None
        path, line = parsed
        if line is None:
            return None
        repo_root = self._resolve_repo_root() or Path.cwd()
        local = self._resolve_local_path(path, repo_root)
        if local is None:
            return None
        context = mouse_actions.read_source_context(local, line)
        if not context:
            return None
        # Display relative to the repo root when possible so the
        # header doesn't leak the user's home-directory layout.
        try:
            display_path = local.relative_to(repo_root)
        except ValueError:
            display_path = local
        # NOTE: ``rich.markup.escape`` only escapes bracket sequences
        # that pattern-match a tag (e.g. ``[dim]``). A bare ``[`` at
        # end of line — common in Python source (``docker_cmd = [``)
        # — slips through and breaks Textual's parser. We replace
        # every ``[`` and ``]`` unconditionally so source content
        # renders verbatim, then add our own markup tags around it.
        def _escape(s: str) -> str:
            return s.replace("[", r"\[").replace("]", r"\]")
        header = f"[dim]{_escape(str(display_path))}:{line}[/dim]"
        rendered: list[str] = [header]
        for line_no, text, is_flagged in context:
            safe_text = _escape(text)
            if is_flagged:
                # Bold yellow on the flagged line + a chevron marker
                # so the row jumps out even in a monochrome terminal.
                rendered.append(
                    f"[bold yellow]>{line_no:5d} | {safe_text}[/]"
                )
            else:
                rendered.append(
                    f"[dim] {line_no:5d} |[/dim] {safe_text}"
                )
        return "\n".join(rendered)

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
        """Right-click → open the right context menu for what's under the cursor.

        Textual emits ``MouseDown(button=3)`` for right-clicks. We
        discriminate by what the cursor is actually over using the
        ``event.style.meta`` payload (the same meta that drives the
        ``[@click=...]`` markup), giving us per-span precision without
        coordinate math:

          - meta has ``@click`` → cursor is on a clickable span in the
            detail pane (path, CVE link, package). Open a *narrow*
            context menu scoped to that span.
          - meta has ``row`` → cursor is on a DataTable row. Open the
            per-finding context menu for that row.
          - neither → no-op (right-clicking the search box, footer,
            empty space).

        ``meta['row']`` is the row at the click position, which is
        what users expect (not the keyboard cursor row, which may be
        stale).
        """
        if getattr(event, "button", 0) != 3:
            return
        meta = self._event_meta(event)
        anchor = self._event_anchor(event)

        click_action = meta.get("@click", "")
        if click_action:
            self._push_span_context_menu(click_action, anchor=anchor)
            return

        if "row" in meta:
            row = meta["row"]
            if isinstance(row, int) and 0 <= row < len(self._visible):
                self._push_context_menu(self._visible[row], anchor=anchor)

    @staticmethod
    def _event_anchor(event) -> tuple[int, int] | None:  # pragma: no cover — UI
        """Screen-cell coordinate of a mouse event, for anchoring menus.

        Returns ``None`` when the event doesn't carry screen coords so
        the menu falls back to its centred placement.
        """
        x = getattr(event, "screen_x", None)
        y = getattr(event, "screen_y", None)
        if isinstance(x, int) and isinstance(y, int):
            return x, y
        return None

    def on_mouse_move(self, event) -> None:  # pragma: no cover
        """Update tooltips contextually as the cursor moves.

        Two cases share this handler so we can dedup with a single key:

          - Over a DataTable row → set ``table.tooltip`` to the
            finding's severity/id/package/short description so the
            user can preview before clicking.
          - Over an ``@click`` span in the detail pane → set
            ``detail.tooltip`` to an action-specific hint
            ("Click to open file · right-click for actions").

        ``meta`` carries the same payload as the click events, so we
        get per-span resolution without parsing rendered text.
        """
        meta = self._event_meta(event)
        row_idx = meta.get("row") if isinstance(meta.get("row"), int) else None
        click_action = meta.get("@click") or None

        key = (row_idx, click_action)
        if key == self._last_hover_key:
            return
        self._last_hover_key = key

        # Detail pane: tooltip describes the span under the cursor.
        try:
            detail = self.query_one("#detail", FindingDetail)
        except Exception:
            detail = None
        if detail is not None:
            detail.tooltip = self._span_tooltip_text(click_action) if click_action else None

        # Findings table: tooltip previews the finding under the cursor.
        try:
            table = self.query_one(DataTable)
        except Exception:
            return
        if row_idx is not None and 0 <= row_idx < len(self._visible):
            table.tooltip = self._finding_tooltip_text(self._visible[row_idx])
        else:
            table.tooltip = (
                "Hover a row for finding details · "
                "Right-click for actions · "
                "Click a column header to sort"
            )

    @staticmethod
    def _event_meta(event) -> dict:
        """Pull the style ``meta`` dict off a mouse event defensively.

        Textual sometimes hands us events with ``style=None`` (e.g.,
        the cursor moved off any rendered cell) — guard against that
        so the handler can't blow up on missing attributes.
        """
        style = getattr(event, "style", None)
        meta = getattr(style, "meta", None) if style is not None else None
        return meta or {}

    def _span_tooltip_text(self, click_action: str) -> str | None:
        """Action-specific tooltip text for a span in the detail pane."""
        name, arg = _parse_click_action(click_action)
        if name == "action_open_advisory":
            return f"Click to open {arg or 'advisory'} · Right-click for actions"
        if name == "action_open_location":
            if arg and mouse_actions.parse_file_line(arg):
                return "Click to open file · Right-click for editor / GitHub / copy"
            if arg and "@" in arg:
                return "Click to open package page · Right-click for actions"
            return "Click to open · Right-click for actions"
        return None

    @staticmethod
    def _finding_tooltip_text(f: Finding) -> str:
        """Multi-line summary of a finding for the per-row hover tooltip."""
        sev = f.severity.value.upper() if f.severity else "?"
        ident = f.id or "—"
        pkg = f.metadata.get("package")
        installed = f.metadata.get("installed_version")
        pkg_label = (
            f"{pkg}@{installed}" if pkg
            else (f.location or f.scanner or "—")
        )
        desc = (f.description or f.title or "").strip()
        # Keep the preview short — tooltips wrap badly on most terminals
        # so a single trimmed line is what users actually read.
        if len(desc) > 180:
            desc = desc[:180].rstrip() + "…"
        if not desc:
            desc = "(no description)"
        return f"{sev}  {ident}\n{pkg_label}\n{desc}"

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
            DashboardScreen(
                self.all_findings, source_label=self.sub_title or "", runs=self._runs,
            ),
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

        Textual stores ``Column.label`` as a ``rich.text.Text`` (see
        ``DataTable.add_column`` — it does ``Text.from_markup(label)``
        on the way in). Assigning a raw ``str`` here would leave the
        column in a mixed state and cause the next render to throw
        in the DataTable internals — observed in the wild as the
        list pane going entirely black after a header-click sort.
        Round-trip through ``Text.from_markup`` so the type matches
        what Textual handed back at ``add_columns`` time.
        """
        from rich.text import Text
        try:
            table = self.query_one(DataTable)
        except Exception:
            return
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
            col.label = Text.from_markup(label)

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

    def _push_context_menu(  # pragma: no cover
        self, finding: Finding, anchor: tuple[int, int] | None = None,
    ) -> None:
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
            elif choice == "fix":
                self._fix_findings([finding])
            elif choice == "export":
                self.action_export_csv()

        self.push_screen(
            ContextMenuScreen(finding, self._view_config, anchor=anchor),
            _on_choice,
        )

    def _push_span_context_menu(  # pragma: no cover
        self, click_action: str, anchor: tuple[int, int] | None = None,
    ) -> None:
        """Push a narrow context menu for the right-clicked span.

        Unlike ``_push_context_menu`` (which lists every action that
        could apply to the row), this only lists actions relevant to
        the specific span the user right-clicked — file path → open
        in editor / GitHub / copy; CVE link → open advisory / copy;
        package@version → open registry / copy. The argument is
        already parsed out of the ``@click`` meta so we don't have to
        re-derive it from the finding.
        """
        name, arg = _parse_click_action(click_action)
        if not name or arg is None:
            return

        if name == "action_open_advisory":
            title = f"⚙ {arg}"
            items = [
                ("Open advisory in browser", "open_advisory"),
            ]

            def _on_choice(choice: str | None) -> None:
                if choice == "open_advisory":
                    self.action_open_advisory(arg)

        elif name == "action_open_location":
            title = f"⚙ {arg}"
            if mouse_actions.parse_file_line(arg):
                items = [
                    ("Open file in local editor", "open_local"),
                    ("Open file on remote (git blob URL)", "open_remote"),
                ]
            elif "@" in arg:
                items = [
                    ("Open package on registry", "open_package"),
                ]
            else:
                # No actionable item — drop the menu rather than ship
                # an empty box. The user can still select/copy the
                # rendered span text from the terminal itself.
                return

            def _on_choice(choice: str | None) -> None:
                if choice == "open_local":
                    self.action_open_local_file(arg)
                elif choice == "open_remote":
                    self.action_open_remote_file(arg)
                elif choice == "open_package":
                    self.action_open_package(arg)
        else:
            return

        self.push_screen(SpanContextMenuScreen(title, items, anchor=anchor), _on_choice)

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

        Path resolution tries (in order):
          1. ``scan_context``-driven prefix strip (most accurate)
          2. Known CI / container prefix heuristics for older scans
             that pre-date the ``scan_context`` field
          3. The original path as last resort

        First candidate whose ``<local_repo_root>/<rel>`` exists wins.
        """
        parsed = mouse_actions.parse_file_line(location)
        if not parsed:
            self.notify(
                f"Can't parse as a file path: {location!r}",
                severity="warning", timeout=3,
            )
            return
        path, line = parsed

        repo_root = self._resolve_repo_root() or Path.cwd()
        resolved = self._resolve_local_path(path, repo_root)
        if resolved is None:
            # No candidate exists on the local checkout. Surface the
            # candidates we tried so the user can spot the issue
            # (wrong scan host, missing local clone, etc.).
            candidates = mouse_actions.candidate_relative_paths(
                path, self._scan_context,
            )
            tried = " / ".join(str(c) for c in candidates[:3])
            self.notify(
                f"File not found locally. Tried: {tried}. "
                f"Scan ran in a container or CI — open Remote instead, "
                f"or re-scan locally to capture matching paths.",
                severity="error", timeout=8,
            )
            return

        opened = mouse_actions.open_file_local(
            resolved, line=line, editor=self._view_config.editor or None,
        )
        if opened:
            display = f"{resolved.name}" + (f":{line}" if line else "")
            self.notify(f"Opened {display}", severity="information", timeout=2)
        else:
            self.notify(
                f"Couldn't launch editor for {resolved}. "
                f"Set ``view.editor`` in argus.yml or export $EDITOR.",
                severity="error", timeout=6,
            )

    def _resolve_local_path(
        self, path: Path, repo_root: Path,
    ) -> Path | None:
        """Pick the first candidate-relative-path that exists locally.

        Returns the absolute local path, or ``None`` when no candidate
        resolves to an existing file. Shared by the local-open and
        remote-open actions so they agree on which repo-relative
        interpretation of a scan-time path to use.
        """
        for rel in mouse_actions.candidate_relative_paths(
            path, self._scan_context,
        ):
            if rel.is_absolute():
                if rel.exists():
                    return rel
                continue
            candidate = repo_root / rel
            if candidate.exists():
                return candidate
        return None

    def action_open_remote_file(self, location: str) -> None:  # pragma: no cover
        """Open ``file:line`` on the git origin remote at the scan's SHA.

        Path resolution picks the first repo-relative candidate that
        exists on the local checkout (so heuristic prefix stripping
        for old scans still produces a working URL). When no
        candidate exists locally, falls back to the most-specific
        heuristic strip — at least the URL has a chance of resolving
        if the file simply wasn't pulled to this clone.

        Before opening, runs two lightweight checks so dead links
        produce a warning instead of a 404 in the user's browser:

          1. ``git status --porcelain`` on the local file — warn if
             modified or untracked (the URL points at scan-time bytes
             which won't match local).
          2. HTTP HEAD on the constructed URL — warn if non-2xx, with
             the URL in the notification so the user can copy and
             inspect.

        Uses the scan-time commit SHA (when the scan captured one)
        so the link points at the code the scan actually saw, not
        whatever the contributor's HEAD happens to be.
        """
        parsed = mouse_actions.parse_file_line(location)
        if not parsed:
            self.notify(
                f"Can't parse as a file path: {location!r}",
                severity="warning", timeout=3,
            )
            return
        path, line = parsed

        repo_root = self._resolve_repo_root()
        if not repo_root:
            self.notify(
                "Not inside a git repo — can't construct a remote URL",
                severity="warning", timeout=4,
            )
            return

        rel_path = self._pick_remote_rel_path(path, repo_root)
        if rel_path is None or rel_path.is_absolute():
            self.notify(
                "Couldn't normalize the scan-time path to repo-relative. "
                "Re-run the scan with a current argus build so "
                "scan_context is captured.",
                severity="warning", timeout=6,
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

        # Dirty-state check: if the local file diverges from the
        # scan-time bytes, the URL still points at what the scan saw
        # but the user's local view is different. Warn but don't block.
        warnings: list[str] = []
        status = mouse_actions.git_file_status(repo_root, rel_path)
        if status == "modified":
            warnings.append(
                f"Local {rel_path} has uncommitted changes — "
                "remote view won't match.",
            )
        elif status == "untracked":
            warnings.append(
                f"Local {rel_path} is untracked — "
                "remote view may not exist on the branch.",
            )

        # URL preflight: HEAD the URL to catch 404s before launching
        # the browser. Short timeout so we don't freeze the UI when
        # the network is slow.
        ok, status_msg = mouse_actions.verify_remote_url(url, timeout=2.0)
        if not ok:
            joined = " ".join(warnings) + " " if warnings else ""
            self.notify(
                f"Remote URL returned {status_msg}.\n{url}\n"
                f"{joined}File / commit may not be on remote yet — "
                f"push your branch first, or copy the URL to inspect.",
                severity="warning", timeout=10,
            )
            return

        if warnings:
            # Surface the dirty-state warning before opening so the
            # user knows what they're looking at.
            self.notify(" ".join(warnings), severity="warning", timeout=5)

        if mouse_actions.open_in_browser(url):
            self.notify(f"Opened {url}", severity="information", timeout=2)
        else:
            self.notify(
                f"Couldn't open browser for {url}",
                severity="error", timeout=5,
            )

    def _pick_remote_rel_path(
        self, path: Path, repo_root: Path,
    ) -> Path | None:
        """Choose the best repo-relative path for a remote git URL.

        Strategy:
          1. If any candidate exists on the local checkout, use that
             (high-confidence — local proves the path is right).
          2. Else fall back to the first non-absolute candidate.
             Better to ship a URL that might resolve than no URL.
          3. If the path is already relative, just return it.
        """
        candidates = mouse_actions.candidate_relative_paths(
            path, self._scan_context,
        )
        for rel in candidates:
            if rel.is_absolute():
                continue
            if (repo_root / rel).exists():
                return rel
        for rel in candidates:
            if not rel.is_absolute():
                return rel
        return None

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
            self.notify("Opened registry page", severity="information", timeout=2)
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
