"""Argus Console — the interactive TUI launched by bare ``argus``.

A screen-based Textual app that fronts the whole local workflow: a home
launcher (scan / view findings / configure / init / settings / docs) over
the same UI-free core (`run_discovery`, `scan_runner`, the findings
viewer). It's what bare ``argus`` opens in an interactive terminal;
``argus view`` still deep-links straight to the findings viewer.

Design rules (see docs/developer/CONSOLE-ROADMAP.md):
- Logic lives in textual-free modules (`console_model`, `console_config`)
  so it's unit-tested in CI without the ``[terminal]`` extra; the screens
  here are thin and mostly ``# pragma: no cover`` UI glue.
- Findings and Init are reached by exiting the console with a sentinel
  that ``launch`` acts on, then returning to the console — no nested
  Textual apps. Scan, Settings, and Docs are in-app screens.
"""

from __future__ import annotations

import os
import subprocess
from functools import partial
from pathlib import Path

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.command import Hit, Hits, Provider
from textual.containers import Center, Vertical, VerticalScroll
from textual.screen import ModalScreen, Screen
from textual.theme import Theme
from textual.widgets import Footer, OptionList, Static
from textual.widgets.option_list import Option

from argus.core import console_config, terminal_caps
from argus.core.console_config import ConsoleSettings
from argus.viewers.terminal import config_editor, console_model, init_wizard

# Sentinel the app exits with so ``launch`` can hand off to the findings
# viewer (its own full-screen surface) and then return to the console.
# Init and Configure are now in-app screens (no hand-off needed).
_HANDOFF_FINDINGS = "findings"


def _argus_theme(accent: str) -> Theme:
    """Build the bespoke ``argus-dark`` theme (Argus brand colours).

    At the default accent it's the website's green-primary / lime-accent
    duotone; choosing a different accent recolours the primary + accent to
    that hue while keeping the deep green-black base.
    """
    pal = console_model.ARGUS_DARK_PALETTE
    if accent == console_config.DEFAULT_ACCENT:
        primary, accent_color = pal["primary"], pal["accent"]
    else:
        primary = accent_color = console_model.accent_hex(accent)
    return Theme(
        name="argus-dark",
        primary=primary,
        secondary=pal["secondary"],
        accent=accent_color,
        foreground=pal["foreground"],
        background=pal["background"],
        surface=pal["surface"],
        panel=pal["panel"],
        success=pal["success"],
        warning=pal["warning"],
        error=pal["error"],
        dark=True,
        # Widget-level variables, matching the shape Textual's built-in
        # themes provide. Omitting these leaves some widgets (OptionList
        # cursor, Footer keys) without a resolved colour, which surfaces as
        # a NoneType-visual render crash when switching away from the theme.
        variables={
            "block-cursor-background": primary,
            "block-cursor-foreground": pal["background"],
            "block-cursor-text-style": "none",
            "block-cursor-blurred-background": f"{primary} 30%",
            "footer-key-foreground": primary,
            "input-selection-background": f"{primary} 35%",
        },
    )


_DOCS_TEXT = """\
[b]Argus Console[/b]

[b]Home[/b]
  [b]↑/↓[/b]      move in the menu
  [b]enter[/b]    open the highlighted item
  [b]s[/b]        settings   ·   [b]?[/b] this help   ·   [b]q[/b] quit

[b]What each item does[/b]
  [b]Run a scan[/b]    runs ``argus scan`` and streams it live, then reloads.
  [b]View findings[/b] opens the full triage viewer (same as ``argus view``).
  [b]Configure[/b]     opens ``argus.yml`` in your $EDITOR / $VISUAL.
  [b]Initialize[/b]    runs ``argus init`` to detect the project + write config.
  [b]Settings[/b]      theme, accent colour, animations, notifications —
                 changes preview live and persist to
                 ~/.config/argus/console.yml.

[b]Good to know[/b]
  Bare ``argus`` opens this console in an interactive terminal; piped /
  CI use is unaffected. ``argus view`` still jumps straight to findings.

[dim]Press ESC or q to close.[/dim]
"""


class DocsScreen(ModalScreen):
    """Concise in-console help overlay."""

    CSS = """
    DocsScreen { align: center middle; }
    #docs-body {
        background: $surface; border: thick $accent;
        width: 80%; max-width: 84; height: auto; max-height: 90%; padding: 1 2;
    }
    """
    BINDINGS = [
        Binding("escape", "dismiss", show=False),
        Binding("q", "dismiss", show=False),
        Binding("question_mark", "dismiss", show=False, key_display="?"),
    ]

    def compose(self) -> ComposeResult:  # pragma: no cover — UI
        with VerticalScroll(id="docs-body"):
            yield Static(_DOCS_TEXT)
            yield Static(
                f"\n[b]Terminal[/b]\n  [dim]{terminal_caps.capability_summary()}[/dim]",
            )

    def on_mount(self) -> None:  # pragma: no cover — UI
        self.query_one("#docs-body", VerticalScroll).focus()


class ThemePickerScreen(Screen):
    """Live-preview theme dropdown: arrow to preview, Enter to choose, Esc to revert.

    Highlighting a theme applies it immediately so the user sees it before
    committing; Enter keeps the previewed theme, Esc restores whatever was
    active when the picker opened. A full Screen (not a ModalScreen) for the
    same reason ``SettingsScreen`` is — applying a theme while a ModalScreen is
    mounted hits a Textual 8.x render bug (NoneType visual).
    """

    CSS = """
    ThemePickerScreen { align: center middle; }
    #theme-body {
        background: $surface; border: thick $accent;
        width: 60%; max-width: 56; height: auto; max-height: 80%; padding: 1 2;
    }
    #theme-title { text-style: bold; padding: 0 0 1 0; }
    #theme-list { height: auto; max-height: 18; border: none; background: transparent; }
    #theme-hint { color: $text-muted; padding: 1 0 0 0; }
    """
    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=True),
        Binding("q", "cancel", show=False),
    ]

    def __init__(self, current: str) -> None:
        super().__init__()
        self._original = current

    def compose(self) -> ComposeResult:  # pragma: no cover — UI
        with Vertical(id="theme-body"):
            yield Static("🎨  Theme — ↑↓ to preview", id="theme-title")
            yield OptionList(
                *(
                    Option(f"{'● ' if name == self._original else '  '}{name}", id=name)
                    for name in console_config.THEMES
                ),
                id="theme-list",
            )
            yield Static(
                "↑↓ preview   ·   enter choose   ·   esc cancel", id="theme-hint",
            )

    def on_mount(self) -> None:  # pragma: no cover — UI
        option_list = self.query_one("#theme-list", OptionList)
        if self._original in console_config.THEMES:
            option_list.highlighted = console_config.THEMES.index(self._original)
        option_list.focus()

    def _preview(self, name: str) -> None:  # pragma: no cover — UI
        self.app.settings = self.app.settings.with_value("theme", name)
        self.app.apply_theme()

    def on_option_list_option_highlighted(  # pragma: no cover — UI
        self, event: OptionList.OptionHighlighted,
    ) -> None:
        if event.option and event.option.id:
            self._preview(event.option.id)

    def on_option_list_option_selected(  # pragma: no cover — UI
        self, event: OptionList.OptionSelected,
    ) -> None:
        if event.option and event.option.id:
            self._preview(event.option.id)
        self.dismiss(True)   # keep the previewed theme

    def action_cancel(self) -> None:  # pragma: no cover — UI
        # Restore whatever theme was active when the picker opened.
        self.app.settings = self.app.settings.with_value("theme", self._original)
        self.app.apply_theme()
        self.dismiss(False)


class SettingsScreen(Screen):
    """herdr-style settings: an arrow-navigable list where Enter changes the
    focused setting and the result previews live (theme opens a live-preview
    dropdown; accent applies immediately; toggles flip). Persisted on close.

    A full Screen (not a ModalScreen) on purpose: live theme application
    while a ModalScreen is mounted hits a Textual render bug
    (NoneType visual) in 8.x, and a dedicated full-screen settings page is
    the nicer surface anyway. The change logic is pure
    (``ConsoleSettings.advance`` / ``display_rows``, unit-tested); this
    screen is the thin renderer + dispatcher.
    """

    CSS = """
    SettingsScreen { align: center middle; }
    #settings-body {
        background: $surface; border: thick $accent;
        width: 70%; max-width: 72; height: auto; padding: 1 2;
    }
    #settings-title { text-style: bold; padding: 0 0 1 0; }
    #settings-list { height: auto; max-height: 16; border: none; background: transparent; }
    #settings-hint { color: $text-muted; padding: 1 0 0 0; }
    """
    BINDINGS = [
        Binding("escape", "close", "Save & close", show=True),
        Binding("q", "close", show=False),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._highlight = 0  # remembered cursor row across recompose

    def compose(self) -> ComposeResult:  # pragma: no cover — UI
        # Options are composed fresh each time (recompose on change) rather
        # than mutated in place — clear_options/add_option on a live
        # OptionList leaves a None visual that crashes on the next theme
        # repaint in Textual 8.x.
        with Vertical(id="settings-body"):
            yield Static("🎛  Settings", id="settings-title")
            yield OptionList(
                *(
                    Option(f"{label:<18}{value}", id=key)
                    for key, label, value in self.app.settings.display_rows()
                ),
                id="settings-list",
            )
            yield Static(
                "↑↓ move   ·   enter change   ·   esc save & close",
                id="settings-hint",
            )

    def on_mount(self) -> None:  # pragma: no cover — UI
        self._restore_cursor()
        self.query_one("#settings-list", OptionList).focus()

    def _restore_cursor(self) -> None:  # pragma: no cover — UI
        # Re-focus the rebuilt list after a recompose so the keyboard keeps
        # working without a mouse click (the list is composed fresh on every
        # change).
        option_list = self.query_one("#settings-list", OptionList)
        if option_list.option_count:
            option_list.highlighted = min(self._highlight, option_list.option_count - 1)
        option_list.focus()

    def on_option_list_option_selected(  # pragma: no cover — UI
        self, event: OptionList.OptionSelected,
    ) -> None:
        key = event.option.id
        if not key:
            return
        self._highlight = event.option_index
        if key == "theme":
            # Theme opens a live-preview dropdown (arrow to preview, enter to
            # choose, esc to revert) rather than cycling one step per Enter.
            def _after_pick(_chosen: object) -> None:
                # settings.theme is already set by the picker (preview/confirm
                # or revert); just rebuild the list to show the new value.
                self.refresh(recompose=True)
                self.call_after_refresh(self._restore_cursor)

            self.app.push_screen(
                ThemePickerScreen(self.app.settings.theme), _after_pick,
            )
            return
        self.app.settings = self.app.settings.advance(key)
        self.app.apply_theme()       # live preview for accent
        # Rebuild the list cleanly with the new values, then restore cursor.
        self.refresh(recompose=True)
        self.call_after_refresh(self._restore_cursor)

    def action_close(self) -> None:  # pragma: no cover — UI
        self.app.persist_settings()
        self.dismiss()


class _ChoiceScreen(ModalScreen[str | None]):
    """A dropdown-style picker for a bounded-choice (enum) config value.

    Lists the allowed options and dismisses with the chosen value (or
    ``None`` on cancel), so ``ConfigScreen`` can set an enum setting in one
    step instead of cycling through it with repeated Enter presses. A plain
    modal that never changes the theme or mutates its list while mounted —
    safe under the Textual 8.x modal constraints the Console works around.
    """

    CSS = """
    _ChoiceScreen { align: center middle; }
    #choice-body {
        background: $surface; border: thick $accent;
        width: auto; min-width: 32; max-width: 64; height: auto; padding: 1 2;
    }
    #choice-title { text-style: bold; padding: 0 0 1 0; }
    #choice-list { height: auto; max-height: 14; border: none; background: transparent; }
    #choice-hint { color: $text-muted; padding: 1 0 0 0; }
    """
    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=True),
        Binding("q", "cancel", show=False),
    ]

    def __init__(self, title: str, options: list[str], current: str) -> None:
        super().__init__()
        self._title = title
        self._options = options
        self._current = current

    def compose(self) -> ComposeResult:  # pragma: no cover — UI
        with Vertical(id="choice-body"):
            yield Static(f"Choose · {self._title}", id="choice-title")
            yield OptionList(
                *(
                    Option(
                        f"{'● ' if opt == self._current else '  '}{opt}", id=opt,
                    )
                    for opt in self._options
                ),
                id="choice-list",
            )
            yield Static(
                "↑↓ move   ·   enter select   ·   esc cancel", id="choice-hint",
            )

    def on_mount(self) -> None:  # pragma: no cover — UI
        option_list = self.query_one("#choice-list", OptionList)
        if self._current in self._options:
            option_list.highlighted = self._options.index(self._current)
        option_list.focus()

    def on_option_list_option_selected(  # pragma: no cover — UI
        self, event: OptionList.OptionSelected,
    ) -> None:
        self.dismiss(event.option.id)

    def action_cancel(self) -> None:  # pragma: no cover — UI
        self.dismiss(None)


class ConfigScreen(Screen):
    """Form editor for argus.yml — scanner toggles + key settings.

    Comment-preserving: edits go through ``config_editor`` which rewrites
    only the matched line. Changes accumulate in a working copy; ``s``
    validates and writes, ``esc`` discards. The richer free-text fields
    (output_dir, etc.) stay editable via ``$EDITOR`` for now — this v1
    covers the toggle/enum settings that are the common edits.
    """

    CSS = """
    ConfigScreen { align: center middle; }
    #config-body {
        background: $surface; border: thick $accent;
        width: 80%; max-width: 92; height: auto; max-height: 90%; padding: 1 2;
    }
    #config-title { text-style: bold; padding: 0 0 1 0; }
    #config-list { height: auto; max-height: 22; border: none; background: transparent; }
    #config-hint { color: $text-muted; padding: 1 0 0 0; }
    """
    BINDINGS = [
        Binding("s", "save", "Save", show=True),
        Binding("escape", "cancel", "Cancel", show=True),
        Binding("q", "cancel", show=False),
    ]

    def __init__(self, config_path: Path):
        super().__init__()
        self._path = config_path
        try:
            self._text = config_path.read_text(encoding="utf-8")
        except OSError:
            self._text = ""
        self._original = self._text
        self._highlight = 0

    def compose(self) -> ComposeResult:  # pragma: no cover — UI
        rows = config_editor.editable_rows(self._text)
        dirty = "  [yellow](unsaved)[/yellow]" if self._text != self._original else ""
        with Vertical(id="config-body"):
            yield Static(f"⚙  Configure · {self._path.name}{dirty}", id="config-title")
            opts = [
                Option(text, id=key)
                for key, text in config_editor.row_display(rows)
            ]
            yield OptionList(*opts, id="config-list")
            yield Static(
                "↑↓ move   ·   enter change   ·   s save   ·   esc cancel",
                id="config-hint",
            )

    def on_mount(self) -> None:  # pragma: no cover — UI
        self._restore_cursor()

    def _restore_cursor(self) -> None:  # pragma: no cover — UI
        # Re-focus after a recompose: the OptionList is rebuilt on every
        # change, so without re-focusing the new widget the arrow keys and
        # Enter silently stop working until the user clicks back in.
        option_list = self.query_one("#config-list", OptionList)
        if option_list.option_count:
            option_list.highlighted = min(self._highlight, option_list.option_count - 1)
        option_list.focus()

    def on_option_list_option_selected(  # pragma: no cover — UI
        self, event: OptionList.OptionSelected,
    ) -> None:
        key = event.option.id
        rows = {r.key: r for r in config_editor.editable_rows(self._text)}
        row = rows.get(key)
        if row is None:
            return
        self._highlight = event.option_index
        # Enum settings (bounded choices) open a chooser so the user picks
        # directly instead of pressing Enter to cycle through every option.
        # Toggles (on/off) just flip in place.
        if row.kind == "enum" and row.options:
            self._pick_enum(row)
            return
        result = config_editor.apply_row(self._text, row)
        if result is not None:
            self._text, _ = result
        self.refresh(recompose=True)
        self.call_after_refresh(self._restore_cursor)

    def _pick_enum(self, row: "config_editor.EditRow") -> None:  # pragma: no cover — UI
        def _chosen(value: str | None) -> None:
            if value is not None and value != row.value:
                new_text = config_editor.set_value(self._text, row.path, value)
                if new_text is not None:
                    self._text = new_text
            self.refresh(recompose=True)
            self.call_after_refresh(self._restore_cursor)

        self.app.push_screen(
            _ChoiceScreen(row.label, list(row.options), row.value), _chosen,
        )

    def action_save(self) -> None:  # pragma: no cover — UI
        if self._text == self._original:
            self.app.notify("No changes to save.", severity="information", timeout=3)
            self.dismiss()
            return
        error = config_editor.validate(self._text)
        if error:
            self.app.notify(f"Not saved — {error}", severity="error", timeout=8)
            return
        try:
            self._path.write_text(self._text, encoding="utf-8")
        except OSError as exc:
            self.app.notify(f"Couldn't write {self._path.name}: {exc}", severity="error", timeout=6)
            return
        self.app.notify(f"Saved {self._path.name}.", severity="information", timeout=3)
        self.dismiss()

    def action_cancel(self) -> None:  # pragma: no cover — UI
        self.dismiss()


class InitScreen(Screen):
    """Guided first-run wizard — a frontend over ``argus init``.

    Shows what detection found (``init_wizard.build_plan``), lists the
    proposed scanners as toggles (reusing ``config_editor`` over the
    generated argus.yml held in a working copy), and writes the file. No
    detection logic lives here — it's all in ``argus.init`` / ``init_wizard``.

    ``w`` writes argus.yml, ``r`` writes then offers to run the first scan.
    Dismisses with ``"scan"`` / ``"written"`` / ``None`` so the app can
    refresh the home status and optionally launch the scan runner.
    """

    CSS = """
    InitScreen { align: center middle; }
    #init-body {
        background: $surface; border: thick $accent;
        width: 84%; max-width: 96; height: auto; max-height: 92%; padding: 1 2;
    }
    #init-title { text-style: bold; padding: 0 0 1 0; }
    #init-summary { color: $text-muted; padding: 0 0 1 0; }
    #init-detected { height: auto; padding: 0 0 1 0;
                     border-bottom: dashed $panel; }
    #init-list { height: auto; max-height: 16; border: none; background: transparent; }
    #init-hint { color: $text-muted; padding: 1 0 0 0; }
    """
    BINDINGS = [
        Binding("w", "write", "Write", show=True),
        Binding("r", "write_scan", "Write & scan", show=True),
        Binding("escape", "cancel", "Cancel", show=True),
        Binding("q", "cancel", show=False),
    ]

    def __init__(self, plan: "init_wizard.InitPlan"):
        super().__init__()
        self._plan = plan
        self._text = plan.yaml
        self._highlight = 0
        self._overwrite_armed = False

    def compose(self) -> ComposeResult:  # pragma: no cover — UI
        with Vertical(id="init-body"):
            yield Static("✨  Initialize · argus.yml", id="init-title")
            yield Static(init_wizard.summary_line(self._plan), id="init-summary")
            if self._plan.categories:
                detected = "\n".join(
                    f"  ✓ {c.label}  [dim]{c.example}[/dim]"
                    for c in self._plan.categories
                )
            else:
                detected = "  [dim]no project signals detected — safe defaults proposed[/dim]"
            readiness = init_wizard.readiness_line(self._plan.readiness)
            if readiness:
                detected += f"\n  [dim]tools: {readiness}[/dim]"
            yield Static(detected, id="init-detected")
            opts = [
                Option(f"{r.label:<26}{r.value}", id=r.key)
                for r in config_editor.editable_rows(self._text)
            ]
            yield OptionList(*opts, id="init-list")
            exists = (
                "   [yellow]argus.yml exists — write overwrites[/yellow]"
                if self._plan.config_exists else ""
            )
            yield Static(
                f"enter toggle   ·   w write   ·   r write & scan   ·   esc cancel{exists}",
                id="init-hint",
            )
        yield Footer()

    def on_mount(self) -> None:  # pragma: no cover — UI
        self._restore_cursor()
        self.query_one("#init-list", OptionList).focus()

    def _restore_cursor(self) -> None:  # pragma: no cover — UI
        # Re-focus the rebuilt list after a recompose so the keyboard keeps
        # working without a mouse click.
        option_list = self.query_one("#init-list", OptionList)
        if option_list.option_count:
            option_list.highlighted = min(self._highlight, option_list.option_count - 1)
        option_list.focus()

    def on_option_list_option_selected(  # pragma: no cover — UI
        self, event: OptionList.OptionSelected,
    ) -> None:
        rows = {r.key: r for r in config_editor.editable_rows(self._text)}
        row = rows.get(event.option.id)
        if row is None:
            return
        self._highlight = event.option_index
        result = config_editor.apply_row(self._text, row)
        if result is not None:
            self._text, _ = result
        self.refresh(recompose=True)
        self.call_after_refresh(self._restore_cursor)

    def _write(self, *, then_scan: bool) -> None:  # pragma: no cover — UI
        target = self._plan.config_path
        if target.exists() and not self._overwrite_armed:
            self._overwrite_armed = True
            self.app.notify(
                f"{target.name} already exists — press the same key again to overwrite.",
                severity="warning", timeout=6,
            )
            return
        error = config_editor.validate(self._text)
        if error:
            self.app.notify(f"Not written — {error}", severity="error", timeout=8)
            return
        try:
            init_wizard.write_config(target, self._text, force=True)
        except OSError as exc:
            self.app.notify(f"Couldn't write {target.name}: {exc}", severity="error", timeout=6)
            return
        self.app.notify(f"Created {target.name}.", severity="information", timeout=3)
        self.dismiss("scan" if then_scan else "written")

    def action_write(self) -> None:  # pragma: no cover — UI
        self._write(then_scan=False)

    def action_write_scan(self) -> None:  # pragma: no cover — UI
        self._write(then_scan=True)

    def action_cancel(self) -> None:  # pragma: no cover — UI
        self.dismiss()


class SystemStatusScreen(ModalScreen):
    """Detailed system-readiness breakdown, opened from the home chip (``d``).

    One row per check — glyph, label, detail, and a remediation hint when
    something needs attention (Docker stopped, a tool missing, an image-digest
    mismatch). Read-only; ESC closes. The status itself is computed UI-free in
    ``argus.core.system_status``; this is the thin renderer.
    """

    _ROW_GLYPH = {"ok": "✔", "warn": "▲", "down": "✖"}

    CSS = """
    SystemStatusScreen { align: center middle; }
    #sysstatus-body {
        background: $surface; border: thick $accent;
        width: 80%; max-width: 88; height: auto; max-height: 90%; padding: 1 2;
    }
    #sysstatus-title { text-style: bold; padding: 0 0 1 0; }
    #sysstatus-hint { color: $text-muted; padding: 1 0 0 0; }
    """
    BINDINGS = [
        Binding("escape", "close", "Close", show=True),
        Binding("q", "close", show=False),
    ]

    def __init__(self, status) -> None:
        super().__init__()
        self._status = status

    def compose(self) -> ComposeResult:  # pragma: no cover — UI
        with Vertical(id="sysstatus-body"):
            yield Static(
                f"{self._status.glyph}  System status", id="sysstatus-title",
            )
            for check in self._status.checks:
                glyph = self._ROW_GLYPH.get(check.verdict, "•")
                yield Static(f"{glyph}  [b]{check.label}[/b] — {check.detail}")
                if check.remediation and check.verdict != "ok":
                    yield Static(f"      [dim]{check.remediation}[/dim]")
            yield Static("esc to close", id="sysstatus-hint")

    def on_mount(self) -> None:  # pragma: no cover — UI
        self.focus()

    def action_close(self) -> None:  # pragma: no cover — UI
        self.dismiss()


class HomeScreen(Screen):
    """The launcher: wordmark banner, project status, and the menu."""

    CSS = """
    HomeScreen { align: center top; }
    /* Fixed-width centred column (padding 2 each side → 72-col inner area).
       align-horizontal:center centres each child as a block. The banner is
       width:auto so it shrinks to the wordmark's own width and is centred as
       a single block — NOT text-align:center, which would centre each ASCII
       row independently and shift the shorter (rstripped) rows sideways. */
    #home { width: 76; height: auto; padding: 1 2; align-horizontal: center; }
    #banner { width: auto; color: $primary; text-style: bold; }
    #tagline { width: 100%; text-align: center; color: $text-muted; padding: 0 0 1 0; }
    #status { width: 100%; text-align: center; color: $text-muted; padding: 0 0 1 0;
              border-top: dashed $panel; border-bottom: dashed $panel; }
    #system-status { width: 100%; text-align: center; color: $text-muted; padding: 0 0 1 0; }
    #menu { height: auto; width: 72; border: round $accent; padding: 0 1; }
    """
    BINDINGS = [
        Binding("q", "app.quit", "Quit"),
        Binding("s", "menu('settings')", "Settings"),
        # System readiness (Docker / local tools / image digests). Computed in
        # the background so the home renders instantly; ``d`` expands the chip
        # into the detailed breakdown.
        Binding("d", "system_status", "System"),
        Binding("question_mark", "menu('docs')", "Help", key_display="?"),
    ]

    def compose(self) -> ComposeResult:  # pragma: no cover — UI
        with Center():
            with Vertical(id="home"):
                # Center the width:auto banner as a block (preserves the
                # ASCII rows' alignment); a Center wrapper does this reliably
                # where align-horizontal on the column doesn't.
                with Center():
                    yield Static(console_model.ARGUS_BANNER, id="banner")
                yield Static(console_model.TAGLINE, id="tagline")
                yield Static("", id="status")
                yield Static(
                    "[dim]checking system…[/dim]", id="system-status",
                )
                yield OptionList(
                    *(
                        Option(f"{item.icon}  {item.label}   [dim]{item.hint}[/dim]", id=item.key)
                        for item in console_model.MENU
                    ),
                    id="menu",
                )
        yield Footer()

    def on_mount(self) -> None:  # pragma: no cover — UI
        self._system_status = None
        self.refresh_status()
        self.query_one("#menu", OptionList).focus()
        # Probe system readiness off the UI thread (Docker info + tool version
        # checks shell out and can stall) so the home paints instantly.
        self.run_worker(self._compute_system_status, thread=True)
        if self.app.settings.motion_enabled:
            banner = self.query_one("#banner", Static)
            banner.styles.opacity = 0.0
            banner.styles.animate("opacity", value=1.0, duration=0.6)

    def refresh_status(self) -> None:  # pragma: no cover — UI
        status = console_model.home_status(
            self.app.launch_root, config_path=self.app.config_path,
        )
        self.query_one("#status", Static).update(console_model.status_line(status))

    def _compute_system_status(self) -> None:  # pragma: no cover — UI (thread)
        from argus.core import system_status
        backend = system_status.effective_backend(self.app.config_path)
        status = system_status.compute_status(
            scanner_names=system_status.COMMON_SCANNERS, backend=backend,
        )
        self.app.call_from_thread(self._apply_system_status, status)

    def _apply_system_status(self, status) -> None:  # pragma: no cover — UI
        self._system_status = status
        try:
            chip = self.query_one("#system-status", Static)
        except Exception:
            return
        chip.update(f"{status.glyph}  {status.summary}   [dim](d for details)[/dim]")

    def action_system_status(self) -> None:  # pragma: no cover — UI
        if self._system_status is None:
            self.app.notify("Still checking system status…", timeout=2)
            return
        self.app.push_screen(SystemStatusScreen(self._system_status))

    def action_menu(self, key: str) -> None:  # pragma: no cover — UI
        self.app.dispatch_menu(key)

    def on_option_list_option_selected(  # pragma: no cover — UI
        self, event: OptionList.OptionSelected,
    ) -> None:
        if event.option.id:
            self.app.dispatch_menu(event.option.id)


class ArgusConsoleCommands(Provider):
    """Command-palette provider for the Console (Ctrl+P).

    Brings the findings viewer's jump-to-action palette to the Console
    home: fuzzy-search every menu action (Scan / Findings / Configure /
    Init / Settings / Docs / Quit) and run it. Matching uses Textual's
    built-in palette matcher; each hit dispatches through the same
    ``dispatch_menu`` the menu and keybindings use, so there's one code
    path per action.
    """

    async def search(self, query: str) -> Hits:  # pragma: no cover — UI
        matcher = self.matcher(query)
        app = self.app
        for item in console_model.MENU:
            display = f"{item.icon}  {item.label}"
            score = matcher.match(display)
            if score > 0:
                yield Hit(
                    score,
                    matcher.highlight(display),
                    partial(app.dispatch_menu, item.key),
                    help=item.hint,
                )


class ConsoleApp(App):
    """Top-level Console app — owns settings, theme, and menu dispatch."""

    TITLE = "argus"
    COMMANDS = App.COMMANDS | {ArgusConsoleCommands}

    def __init__(self, results_dir: str | None = None):
        super().__init__()
        self._results_dir = results_dir
        self.launch_root = (
            Path(results_dir).resolve() if results_dir
            else Path("argus-results").resolve()
        )
        self.config_path = self._detect_config_path()
        self.settings: ConsoleSettings = console_config.load_settings()

    @staticmethod
    def _detect_config_path() -> Path:
        for name in ("argus.yml", "argus.yaml"):
            candidate = Path(name)
            if candidate.is_file():
                return candidate.resolve()
        return Path("argus.yml")

    def on_mount(self) -> None:  # pragma: no cover — UI
        self.apply_theme()
        self.push_screen(HomeScreen())

    def apply_theme(self) -> None:  # pragma: no cover — UI
        """(Re)register argus-dark with the current accent and apply the
        chosen theme, live.

        Setting the ``theme`` reactive to its current value won't re-run
        the watcher, so an accent-only change (theme name unchanged) needs
        a nudge: we bounce through another registered theme and back. That
        uses only the public reactive — no private internals — so it can't
        leave the renderer in the half-applied state a forced internal
        re-fire did.
        """
        self.register_theme(_argus_theme(self.settings.accent))
        target = self.settings.theme if self.settings.theme in self.available_themes \
            else console_config.DEFAULT_THEME
        if self.theme == target:
            self.theme = "textual-light" if target == "textual-dark" else "textual-dark"
        self.theme = target

    def persist_settings(self) -> None:  # pragma: no cover — UI
        console_config.save_settings(self.settings)

    def notify(self, *args, **kwargs):  # pragma: no cover — UI
        """Respect the notifications setting; otherwise a normal toast."""
        if getattr(self, "settings", None) and not self.settings.notifications:
            return
        return super().notify(*args, **kwargs)

    def dispatch_menu(self, key: str) -> None:  # pragma: no cover — UI
        if key == "quit":
            self.exit()
        elif key == "settings":
            self.push_screen(SettingsScreen())
        elif key == "docs":
            self.push_screen(DocsScreen())
        elif key == "scan":
            self._open_scan()
        elif key == "findings":
            self.exit(_HANDOFF_FINDINGS)
        elif key == "init":
            self._open_init()
        elif key == "configure":
            self._open_config()

    def _open_scan(self) -> None:  # pragma: no cover — UI
        from argus.viewers.terminal import scan_runner
        from argus.viewers.terminal.app import RunScanScreen

        argv = scan_runner.build_scan_argv(
            output_dir=scan_runner.resolve_output_base(self._results_dir),
        )

        def _after(_path: str | None) -> None:
            screen = self.screen
            if isinstance(screen, HomeScreen):
                screen.refresh_status()

        self.push_screen(RunScanScreen(argv, launch_root=self.launch_root), _after)

    def _open_config(self) -> None:  # pragma: no cover — UI
        """Open the form editor when an argus.yml exists, else fall back to
        $EDITOR (to create one) or nudge toward Initialize."""
        self.config_path = self._detect_config_path()
        if self.config_path.is_file():
            def _after(_result: object) -> None:
                screen = self.screen
                if isinstance(screen, HomeScreen):
                    screen.refresh_status()
            self.push_screen(ConfigScreen(self.config_path), _after)
            return
        self.notify(
            "No argus.yml yet — pick Initialize to generate one, "
            "or set $EDITOR to create it by hand.",
            severity="warning", timeout=6,
        )
        self._edit_config()

    def _open_init(self) -> None:  # pragma: no cover — UI
        """Open the init wizard over the project at the current directory.

        Detection (``build_plan`` — a filesystem walk) runs in a worker with
        an immediate "Detecting…" toast so the home isn't frozen blank while
        it works; the wizard opens when detection completes.
        """
        self.notify("Detecting project…", timeout=2)

        def _work() -> None:
            plan = init_wizard.build_plan(Path("."))
            self.call_from_thread(self._show_init, plan)

        self.run_worker(_work, thread=True)

    def _show_init(self, plan: "init_wizard.InitPlan") -> None:  # pragma: no cover — UI
        """Push the init wizard once detection has produced a plan.

        Lets the user review/toggle the proposed scanners and writes argus.yml
        in-app. On "write & scan" it hands to the scan runner; either way it
        refreshes home status.
        """
        def _after(result: object) -> None:
            self.config_path = self._detect_config_path()
            screen = self.screen
            if isinstance(screen, HomeScreen):
                screen.refresh_status()
            if result == "scan":
                self._open_scan()

        self.push_screen(InitScreen(plan), _after)

    def _edit_config(self) -> None:  # pragma: no cover — UI
        editor = os.environ.get("VISUAL") or os.environ.get("EDITOR")
        if not editor:
            return
        with self.suspend():
            subprocess.run([editor, str(self.config_path)])
        self.config_path = self._detect_config_path()
        screen = self.screen
        if isinstance(screen, HomeScreen):
            screen.refresh_status()


def launch(results_dir: str | None = None) -> int:
    """Run the Console, handling the findings hand-off in a loop.

    The console exits with a sentinel for the findings viewer (the one
    surface that needs its own full screen); we run it, then re-open the
    console. Configure and Init are handled in-app. Quitting the console
    returns its exit code.
    """
    while True:
        app = ConsoleApp(results_dir=results_dir)
        app.run()
        result = app.return_value
        if result == _HANDOFF_FINDINGS:
            from argus.viewers.terminal.app import run_app
            run_app(results_dir)
            continue
        return app.return_code or 0
