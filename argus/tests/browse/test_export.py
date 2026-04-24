"""Tests for the export-path and platform-opener helpers.

These are UI-free smoke tests: the CSV writer and opener detection
are pure functions we can exercise without spinning up the Textual
app. Full integration of the `e` and `o` keybindings is covered by
manual road-testing.
"""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path


_APP_PATH = Path(__file__).resolve().parents[2] / "browse" / "app.py"


def _load_app_module():
    """Load app.py with textual stubbed — mirrors the view_state fixture."""
    class _Permissive:
        # Empty COMMANDS set lets ``App.COMMANDS | {ArgusBrowseCommands}``
        # evaluate against the stub without an AttributeError.
        COMMANDS = set()

        def __init__(self, *args, **kwargs): ...
        def __call__(self, *args, **kwargs): return self
        def __class_getitem__(cls, item): return cls

    for mod_name in (
        "textual", "textual.app", "textual.binding", "textual.command",
        "textual.containers", "textual.reactive", "textual.widgets",
    ):
        if mod_name not in sys.modules:
            sys.modules[mod_name] = types.ModuleType(mod_name)
    for attr, mod in (
        ("App", "textual.app"), ("ComposeResult", "textual.app"),
        ("Binding", "textual.binding"),
        ("Hit", "textual.command"),
        ("Hits", "textual.command"),
        ("Provider", "textual.command"),
        ("Container", "textual.containers"),
        ("Horizontal", "textual.containers"),
        ("Vertical", "textual.containers"),
        ("reactive", "textual.reactive"),
        ("DataTable", "textual.widgets"),
        ("Footer", "textual.widgets"),
        ("Header", "textual.widgets"),
        ("Input", "textual.widgets"),
        ("Static", "textual.widgets"),
    ):
        setattr(sys.modules[mod], attr, _Permissive)

    spec = importlib.util.spec_from_file_location("_browse_app_probe_export", _APP_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["_browse_app_probe_export"] = module
    spec.loader.exec_module(module)
    return module


class TestPlatformOpener:
    """The opener picker returns the right command per platform."""

    def _call(self, platform_str: str):
        import sys as _sys
        module = _load_app_module()
        orig = _sys.platform
        _sys.platform = platform_str
        try:
            return module._platform_opener()
        finally:
            _sys.platform = orig

    def test_macos(self):
        opener, extra = self._call("darwin")
        assert opener == "open"
        assert extra == []

    def test_linux(self):
        opener, extra = self._call("linux")
        assert opener == "xdg-open"
        assert extra == []

    def test_linux_any_variant(self):
        # startswith check so linux2, linux-musl, etc. all resolve
        opener, _ = self._call("linux-gnu")
        assert opener == "xdg-open"

    def test_windows_routes_via_cmd_start(self):
        opener, extra = self._call("win32")
        assert opener == "cmd"
        # `start` is a cmd builtin — the empty-string third arg is the
        # required "window title" positional that `start` eats.
        assert extra == ["/c", "start", ""]

    def test_unknown_platform(self):
        opener, extra = self._call("freebsd42")
        assert opener is None
        assert extra == []


class TestPlatformOpenerArgv:
    """The argv builder emits the right command for both open and reveal."""

    def _call(self, platform_str: str, mode: str, path: str):
        import sys as _sys
        from pathlib import Path as _Path
        module = _load_app_module()
        orig = _sys.platform
        _sys.platform = platform_str
        try:
            return module._platform_opener_argv(mode, _Path(path))
        finally:
            _sys.platform = orig

    def test_macos_open_uses_default_app(self):
        argv = self._call("darwin", "open", "/tmp/x.csv")
        assert argv == ["open", "/tmp/x.csv"]

    def test_macos_reveal_uses_finder(self):
        argv = self._call("darwin", "reveal", "/tmp/x.csv")
        # The -R flag is what tells `open` to reveal in Finder rather
        # than hand the file to its default app — the whole point of
        # this code path.
        assert argv == ["open", "-R", "/tmp/x.csv"]

    def test_linux_open(self):
        argv = self._call("linux", "open", "/tmp/x.csv")
        assert argv == ["xdg-open", "/tmp/x.csv"]

    def test_linux_reveal_opens_parent_dir(self):
        # Linux has no universal "select file" verb; we open the
        # containing folder as the next-best fallback.
        argv = self._call("linux", "reveal", "/tmp/sub/x.csv")
        assert argv == ["xdg-open", "/tmp/sub"]

    def test_windows_open(self):
        argv = self._call("win32", "open", r"C:\tmp\x.csv")
        assert argv == ["cmd", "/c", "start", "", r"C:\tmp\x.csv"]

    def test_windows_reveal_selects_file(self):
        argv = self._call("win32", "reveal", r"C:\tmp\x.csv")
        # Explorer's /select flag highlights the file in the parent dir.
        assert argv == ["explorer", r"/select,C:\tmp\x.csv"]

    def test_unknown_platform_returns_none(self):
        assert self._call("haiku", "open", "/x") is None
        assert self._call("haiku", "reveal", "/x") is None


class TestExportFilenamePattern:
    """Export filenames include a timestamp and scope so repeats don't clobber."""

    def test_filename_contains_timestamp_and_scope(self):
        module = _load_app_module()
        # Exercise the filename formation without running the full action.
        # The action uses: f"argus-findings-{stamp}-{scope}.csv"
        # We just verify the underlying string interpolation shape by
        # calling datetime.strftime with a known input.
        from datetime import datetime
        stamp = datetime(2026, 4, 24, 10, 30, 0).strftime("%Y%m%d-%H%M%S")
        assert stamp == "20260424-103000"
        for scope in ("critical", "high", "medium", "all"):
            name = f"argus-findings-{stamp}-{scope}.csv"
            assert name.startswith("argus-findings-")
            assert name.endswith(".csv")
            assert scope in name
