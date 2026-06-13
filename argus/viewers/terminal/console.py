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
import sys
from pathlib import Path

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Center, Vertical, VerticalScroll
from textual.screen import ModalScreen, Screen
from textual.theme import Theme
from textual.widgets import Footer, OptionList, Static
from textual.widgets.option_list import Option

from argus.core import console_config
from argus.core.console_config import ConsoleSettings
from argus.viewers.terminal import config_editor, console_model

# Sentinels the app exits with so ``launch`` can hand off to another
# full-screen surface (the findings viewer / the init CLI) and then return
# to the console.
_HANDOFF_FINDINGS = "findings"
_HANDOFF_INIT = "init"


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

    def on_mount(self) -> None:  # pragma: no cover — UI
        self.query_one("#docs-body", VerticalScroll).focus()


class SettingsScreen(Screen):
    """herdr-style settings: an arrow-navigable list where Enter changes the
    focused setting and the result previews live (theme / accent apply
    immediately; toggles flip). Persisted on close.

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
        option_list = self.query_one("#settings-list", OptionList)
        if option_list.option_count:
            option_list.highlighted = min(self._highlight, option_list.option_count - 1)

    def on_option_list_option_selected(  # pragma: no cover — UI
        self, event: OptionList.OptionSelected,
    ) -> None:
        key = event.option.id
        if not key:
            return
        self._highlight = event.option_index
        self.app.settings = self.app.settings.advance(key)
        self.app.apply_theme()       # live preview for theme / accent
        # Rebuild the list cleanly with the new values, then restore cursor.
        self.refresh(recompose=True)
        self.call_after_refresh(self._restore_cursor)

    def action_close(self) -> None:  # pragma: no cover — UI
        self.app.persist_settings()
        self.dismiss()


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
                Option(f"{r.label:<26}{r.value:<14}[dim]{r.doc}[/dim]", id=r.key)
                for r in rows
            ]
            yield OptionList(*opts, id="config-list")
            yield Static(
                "↑↓ move   ·   enter change   ·   s save   ·   esc cancel",
                id="config-hint",
            )

    def on_mount(self) -> None:  # pragma: no cover — UI
        self._restore_cursor()
        self.query_one("#config-list", OptionList).focus()

    def _restore_cursor(self) -> None:  # pragma: no cover — UI
        option_list = self.query_one("#config-list", OptionList)
        if option_list.option_count:
            option_list.highlighted = min(self._highlight, option_list.option_count - 1)

    def on_option_list_option_selected(  # pragma: no cover — UI
        self, event: OptionList.OptionSelected,
    ) -> None:
        key = event.option.id
        rows = {r.key: r for r in config_editor.editable_rows(self._text)}
        row = rows.get(key)
        if row is None:
            return
        self._highlight = event.option_index
        result = config_editor.apply_row(self._text, row)
        if result is not None:
            self._text, _ = result
        self.refresh(recompose=True)
        self.call_after_refresh(self._restore_cursor)

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
    #menu { height: auto; width: 72; border: round $accent; padding: 0 1; }
    """
    BINDINGS = [
        Binding("q", "app.quit", "Quit"),
        Binding("s", "menu('settings')", "Settings"),
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
                yield OptionList(
                    *(
                        Option(f"{item.icon}  {item.label}   [dim]{item.hint}[/dim]", id=item.key)
                        for item in console_model.MENU
                    ),
                    id="menu",
                )
        yield Footer()

    def on_mount(self) -> None:  # pragma: no cover — UI
        self.refresh_status()
        self.query_one("#menu", OptionList).focus()
        if self.app.settings.motion_enabled:
            banner = self.query_one("#banner", Static)
            banner.styles.opacity = 0.0
            banner.styles.animate("opacity", value=1.0, duration=0.6)

    def refresh_status(self) -> None:  # pragma: no cover — UI
        status = console_model.home_status(
            self.app.launch_root, config_path=self.app.config_path,
        )
        self.query_one("#status", Static).update(console_model.status_line(status))

    def action_menu(self, key: str) -> None:  # pragma: no cover — UI
        self.app.dispatch_menu(key)

    def on_option_list_option_selected(  # pragma: no cover — UI
        self, event: OptionList.OptionSelected,
    ) -> None:
        if event.option.id:
            self.app.dispatch_menu(event.option.id)


class ConsoleApp(App):
    """Top-level Console app — owns settings, theme, and menu dispatch."""

    TITLE = "argus"

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
            self.exit(_HANDOFF_INIT)
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
    """Run the Console, handling findings / init hand-offs in a loop.

    The console exits with a sentinel for the two surfaces that need their
    own full screen (the findings viewer and ``argus init``); we run that
    surface, then re-open the console. Quitting the console returns its
    exit code.
    """
    while True:
        app = ConsoleApp(results_dir=results_dir)
        app.run()
        result = app.return_value
        if result == _HANDOFF_FINDINGS:
            from argus.viewers.terminal.app import run_app
            run_app(results_dir)
            continue
        if result == _HANDOFF_INIT:
            subprocess.run([sys.executable, "-m", "argus", "init"])
            continue
        return app.return_code or 0
