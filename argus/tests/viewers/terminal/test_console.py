"""Tests for the ConsoleApp dispatch + config logic via the stubbed-textual
loader, so they run in CI without the [terminal] extra.

The pure model / settings logic is covered in test_console_model and
test_console_config; here we verify the app glue: menu dispatch routing,
config-path detection, and notification gating.
"""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

import pytest

from argus.core.console_config import ConsoleSettings


_CONSOLE_PATH = Path(__file__).resolve().parents[3] / "viewers" / "terminal" / "console.py"


def _load_console_module():
    """Load console.py with textual stubbed."""

    class _Permissive:
        def __init__(self, *args, **kwargs): ...
        def __call__(self, *args, **kwargs): return self
        def __class_getitem__(cls, item): return cls

    modules = {
        "textual", "textual.app", "textual.binding", "textual.containers",
        "textual.screen", "textual.theme", "textual.widgets",
        "textual.widgets.option_list",
    }
    for name in modules:
        sys.modules.setdefault(name, types.ModuleType(name))
    for attr, mod in (
        ("App", "textual.app"), ("ComposeResult", "textual.app"),
        ("Binding", "textual.binding"),
        ("Center", "textual.containers"), ("Vertical", "textual.containers"),
        ("VerticalScroll", "textual.containers"),
        ("ModalScreen", "textual.screen"), ("Screen", "textual.screen"),
        ("Theme", "textual.theme"),
        ("Footer", "textual.widgets"), ("OptionList", "textual.widgets"),
        ("Static", "textual.widgets"),
        ("Option", "textual.widgets.option_list"),
    ):
        setattr(sys.modules[mod], attr, _Permissive)

    spec = importlib.util.spec_from_file_location("_argus_console_mod", _CONSOLE_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["_argus_console_mod"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def console(monkeypatch, tmp_path):
    """A ConsoleApp with isolated settings + recorded side effects."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    module = _load_console_module()
    app = module.ConsoleApp(results_dir=str(tmp_path))

    calls: dict = {"push": [], "exit": [], "scan": 0, "edit": 0}
    app.push_screen = lambda screen, *a, **k: calls["push"].append(type(screen).__name__)  # type: ignore[method-assign]
    app.exit = lambda result=None: calls["exit"].append(result)  # type: ignore[method-assign]
    app._open_scan = lambda: calls.__setitem__("scan", calls["scan"] + 1)  # type: ignore[method-assign]
    app._edit_config = lambda: calls.__setitem__("edit", calls["edit"] + 1)  # type: ignore[method-assign]
    return module, app, calls


class TestConstruction:
    def test_launch_root_from_results_dir(self, console, tmp_path):
        _module, app, _calls = console
        assert app.launch_root == tmp_path.resolve()

    def test_settings_loaded(self, console):
        _module, app, _calls = console
        assert isinstance(app.settings, ConsoleSettings)

    def test_detect_config_path_when_present(self, console, tmp_path, monkeypatch):
        _module, app, _calls = console
        monkeypatch.chdir(tmp_path)
        (tmp_path / "argus.yml").write_text("scanners: []\n")
        assert app._detect_config_path() == (tmp_path / "argus.yml").resolve()

    def test_detect_config_path_default_when_absent(self, console, tmp_path, monkeypatch):
        _module, app, _calls = console
        monkeypatch.chdir(tmp_path)
        assert app._detect_config_path() == Path("argus.yml")


class TestDispatch:
    def test_quit_exits(self, console):
        _module, app, calls = console
        app.dispatch_menu("quit")
        assert calls["exit"] == [None]

    def test_settings_pushes_settings_screen(self, console):
        _module, app, calls = console
        app.dispatch_menu("settings")
        assert "SettingsScreen" in calls["push"]

    def test_docs_pushes_docs_screen(self, console):
        _module, app, calls = console
        app.dispatch_menu("docs")
        assert "DocsScreen" in calls["push"]

    def test_scan_opens_runner(self, console):
        _module, app, calls = console
        app.dispatch_menu("scan")
        assert calls["scan"] == 1

    def test_findings_exits_with_handoff_sentinel(self, console):
        _module, app, calls = console
        app.dispatch_menu("findings")
        assert calls["exit"] and calls["exit"][0] == "findings"

    def test_init_exits_with_handoff_sentinel(self, console):
        _module, app, calls = console
        app.dispatch_menu("init")
        assert calls["exit"] and calls["exit"][0] == "init"

    def test_configure_opens_config_screen_when_present(self, console, tmp_path, monkeypatch):
        _module, app, calls = console
        monkeypatch.chdir(tmp_path)
        (tmp_path / "argus.yml").write_text("scanners:\n  bandit:\n    enabled: true\n")
        app.dispatch_menu("configure")
        assert "ConfigScreen" in calls["push"]
        assert calls["edit"] == 0

    def test_configure_falls_back_to_editor_when_absent(self, console, tmp_path, monkeypatch):
        _module, app, calls = console
        monkeypatch.chdir(tmp_path)
        app.settings = ConsoleSettings(notifications=False)  # silence the nudge toast
        app.dispatch_menu("configure")
        assert calls["edit"] == 1
        assert "ConfigScreen" not in calls["push"]


class TestNotifyGating:
    def test_notify_suppressed_when_disabled(self, console):
        _module, app, _calls = console
        app.settings = ConsoleSettings(notifications=False)
        # Should return without calling super().notify (which the stub lacks).
        assert app.notify("hello") is None


class TestConfigScreen:
    def test_reads_file_into_working_copy(self, console, tmp_path):
        module, _app, _calls = console
        cfg = tmp_path / "argus.yml"
        body = "scanners:\n  bandit:\n    enabled: true\n"
        cfg.write_text(body)
        screen = module.ConfigScreen(cfg)
        assert screen._text == body
        assert screen._original == body
        assert screen._path == cfg

    def test_missing_file_is_empty_working_copy(self, console, tmp_path):
        module, _app, _calls = console
        screen = module.ConfigScreen(tmp_path / "absent.yml")
        assert screen._text == ""
        assert screen._original == ""
