"""Tests for the ``?`` help overlay — content drift guard.

The help text is hand-curated (grouped, explained) rather than a
mechanical dump of BINDINGS, so there's a real risk that adding a
new binding leaves the help stale. This suite cross-checks that
every binding key appears in the help text so drift fails the
build instead of silently shipping.
"""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path


_APP_PATH = Path(__file__).resolve().parents[2] / "browse" / "app.py"


def _load_app_module():
    """Stubbed-textual loader — same pattern as test_view_state / test_export,
    plus a real shape for Binding so the drift-guard test can introspect
    ``BINDINGS`` entries by attribute."""

    class _Permissive:
        COMMANDS = set()

        def __init__(self, *args, **kwargs): ...
        def __call__(self, *args, **kwargs): return self
        def __class_getitem__(cls, item): return cls

    class _FakeBinding:
        """Matches the real ``textual.binding.Binding`` shape enough
        for introspection tests. Positional form:
        ``Binding(key, action, description, show=True, key_display=None)``.
        """
        def __init__(self, key="", action="", description="",
                     show=True, key_display=None, **kwargs):
            self.key = key
            self.action = action
            self.description = description
            self.show = show
            self.key_display = key_display

    for mod_name in (
        "textual", "textual.app", "textual.binding", "textual.command",
        "textual.containers", "textual.reactive", "textual.screen",
        "textual.widgets",
    ):
        if mod_name not in sys.modules:
            sys.modules[mod_name] = types.ModuleType(mod_name)
    for attr, mod in (
        ("App", "textual.app"), ("ComposeResult", "textual.app"),
        ("Binding", None),  # real shape; injected below
        ("Hit", "textual.command"),
        ("Hits", "textual.command"),
        ("Provider", "textual.command"),
        ("Container", "textual.containers"),
        ("Horizontal", "textual.containers"),
        ("Vertical", "textual.containers"),
        ("reactive", "textual.reactive"),
        ("ModalScreen", "textual.screen"),
        ("DataTable", "textual.widgets"),
        ("Footer", "textual.widgets"),
        ("Header", "textual.widgets"),
        ("Input", "textual.widgets"),
        ("Static", "textual.widgets"),
    ):
        if mod is None:
            continue
        setattr(sys.modules[mod], attr, _Permissive)
    # Inject the real-shape Binding so BINDINGS entries have a `.key`.
    sys.modules["textual.binding"].Binding = _FakeBinding

    spec = importlib.util.spec_from_file_location("_browse_app_probe_help", _APP_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["_browse_app_probe_help"] = module
    spec.loader.exec_module(module)
    return module


class TestHelpCoversEveryBinding:
    """Every binding's key glyph should be mentioned in the help text."""

    # Keys we intentionally don't advertise in the ?-help overlay:
    #   j / k  — traditional vim navigation, documented under "↑/↓ or j/k"
    _IMPLICIT_KEYS = {"j", "k"}

    def test_every_user_facing_binding_is_in_the_help(self):
        module = _load_app_module()
        help_text = module._HELP_TEXT
        # Walk every binding declared on BrowseApp and confirm a human
        # can find it in the help. Implicit alternates (j/k aliases)
        # are excluded since they're covered by a dual-notation line.
        for binding in module.BrowseApp.BINDINGS:
            key = binding.key
            if key in self._IMPLICIT_KEYS:
                continue
            # `slash` / `question_mark` are the raw keycode names but
            # we surface them as the glyph in help. Map a few aliases.
            aliases = {
                "slash": "/",
                "question_mark": "?",
                "escape": "ESC",
            }
            surface = aliases.get(key, key)
            assert surface in help_text, (
                f"binding '{key}' (surface: {surface!r}) not documented in help"
            )

    def test_help_text_mentions_the_three_export_actions(self):
        module = _load_app_module()
        help_text = module._HELP_TEXT
        # Explicit spot-check for the trio users hit most often: export,
        # open, reveal — each was a road-test pain point so we want
        # them named and described, not just key-indexed.
        assert "export" in help_text.lower()
        assert "open" in help_text.lower()
        assert "reveal" in help_text.lower()

    def test_help_describes_dismissal(self):
        module = _load_app_module()
        # Users should know how to close the overlay without guessing.
        # Any of ESC / ? / q mentioned in the footer text is sufficient.
        help_text = module._HELP_TEXT
        assert "dismiss" in help_text.lower()


class TestHelpScreenBindings:
    """The HelpScreen modal exposes three dismissal keys."""

    def test_help_screen_binds_escape_q_and_question_mark(self):
        module = _load_app_module()
        keys = {b.key for b in module.HelpScreen.BINDINGS}
        assert keys == {"escape", "q", "question_mark"}
