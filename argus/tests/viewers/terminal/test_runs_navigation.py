"""Tests for the runs sidebar + run switching + scan-runner wiring on BrowseApp.

Exercised via the stubbed-textual loader (same pattern as
``test_multi_select``) so they run in CI without the [terminal] extra.
The pure formatting / argv logic is covered separately in
``test_runs_sidebar`` and ``test_scan_runner``; here we verify the app
glue: discovering runs into the sidebar, switching the loaded run, and
constructing the runner overlays.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import types
from pathlib import Path

import pytest

from argus.core.models import Finding, ScanResult, ScanSummary, Severity
from argus.core.run_discovery import RESULTS_FILENAME


_APP_PATH = Path(__file__).resolve().parents[3] / "viewers" / "terminal" / "app.py"


def _load_app_module():
    """Load ``app.py`` with textual stubbed (CI has no [terminal] extra)."""

    class _Permissive:
        COMMANDS = set()

        def __init__(self, *args, **kwargs): ...
        def __call__(self, *args, **kwargs): return self
        def __class_getitem__(cls, item): return cls

    for mod_name in (
        "textual", "textual.app", "textual.binding", "textual.command",
        "textual.containers", "textual.reactive", "textual.screen",
        "textual.widgets", "textual.widgets.option_list",
    ):
        if mod_name not in sys.modules:
            sys.modules[mod_name] = types.ModuleType(mod_name)
    for attr, mod in (
        ("App", "textual.app"), ("ComposeResult", "textual.app"),
        ("Binding", "textual.binding"),
        ("Hit", "textual.command"), ("Hits", "textual.command"),
        ("Provider", "textual.command"),
        ("Container", "textual.containers"), ("Horizontal", "textual.containers"),
        ("Vertical", "textual.containers"), ("VerticalScroll", "textual.containers"),
        ("reactive", "textual.reactive"), ("ModalScreen", "textual.screen"),
        ("DataTable", "textual.widgets"), ("Footer", "textual.widgets"),
        ("Header", "textual.widgets"), ("Input", "textual.widgets"),
        ("OptionList", "textual.widgets"), ("Static", "textual.widgets"),
        ("Option", "textual.widgets.option_list"),
    ):
        setattr(sys.modules[mod], attr, _Permissive)

    spec = importlib.util.spec_from_file_location("_browse_app_runs_nav", _APP_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["_browse_app_runs_nav"] = module
    spec.loader.exec_module(module)
    return module


def _write_run(dir_path: Path, *, severities: list[Severity]) -> Path:
    """Write a round-trippable argus-results.json into ``dir_path``."""
    dir_path.mkdir(parents=True, exist_ok=True)
    findings = [
        Finding(id=f"CVE-{i}", severity=sev, title="t", scanner="trivy")
        for i, sev in enumerate(severities)
    ]
    summary = ScanSummary(results=[ScanResult(scanner="trivy", findings=findings)])
    target = dir_path / RESULTS_FILENAME
    target.write_text(json.dumps(summary.to_dict()), encoding="utf-8")
    return target


class _FakeOptionList:
    def __init__(self):
        self.options: list = []
        self.focused = False

    def clear_options(self):
        self.options.clear()

    def add_option(self, option):
        self.options.append(option)

    def focus(self):
        self.focused = True


class _FakePane:
    def __init__(self, display=False):
        self.display = display


@pytest.fixture
def app(tmp_path):
    """A BrowseApp wired with stubbed widget lookups, no Textual run."""
    module = _load_app_module()
    app = module.BrowseApp(results_dir=str(tmp_path))
    app.all_findings = []
    app._visible = []

    widgets = {
        "#runs-list": _FakeOptionList(),
        "#runs-pane": _FakePane(),
    }
    notify_calls: list[dict] = []

    def fake_query_one(selector, *args):
        if selector in widgets:
            return widgets[selector]
        # DataTable / #status / #detail — minimal permissive stubs.
        return types.SimpleNamespace(
            focus=lambda: None,
            update=lambda *a, **k: None,
            update_finding=lambda *a, **k: None,
            cursor_coordinate=(0, 0),
        )

    app.query_one = fake_query_one  # type: ignore[method-assign]
    app.notify = lambda *a, **k: notify_calls.append({"a": a, **k})  # type: ignore[method-assign]
    app._refresh_list = lambda: None  # type: ignore[method-assign]
    return module, app, widgets, notify_calls, tmp_path


class TestComputeLaunchRoot:
    def test_none_results_dir_defaults_to_argus_results(self):
        module = _load_app_module()
        a = module.BrowseApp(results_dir=None)
        assert a._launch_root == Path("argus-results").resolve()

    def test_explicit_results_dir_is_resolved(self, tmp_path):
        module = _load_app_module()
        a = module.BrowseApp(results_dir=str(tmp_path))
        assert a._launch_root == tmp_path.resolve()


class TestPopulateRuns:
    def test_fills_options_and_reveals_when_multiple_runs(self, app):
        _module, a, widgets, _notify, tmp_path = app
        _write_run(tmp_path / "run-1", severities=[Severity.LOW])
        _write_run(tmp_path / "run-2", severities=[Severity.CRITICAL])
        a._launch_root = tmp_path.resolve()

        a._populate_runs()

        assert len(widgets["#runs-list"].options) == 2
        # >1 run auto-reveals the sidebar.
        assert widgets["#runs-pane"].display is True
        assert len(a._runs) == 2

    def test_single_run_does_not_auto_reveal(self, app):
        _module, a, widgets, _notify, tmp_path = app
        _write_run(tmp_path / "only", severities=[Severity.LOW])
        a._launch_root = tmp_path.resolve()

        a._populate_runs()

        assert len(widgets["#runs-list"].options) == 1
        assert widgets["#runs-pane"].display is False


class TestToggleRuns:
    def test_toggle_flips_visibility(self, app):
        _module, a, widgets, _notify, _tmp = app
        widgets["#runs-pane"].display = False
        a.action_toggle_runs()
        assert widgets["#runs-pane"].display is True
        assert widgets["#runs-list"].focused is True
        a.action_toggle_runs()
        assert widgets["#runs-pane"].display is False


class TestSwitchRun:
    def test_loads_findings_and_marks_current(self, app):
        _module, a, _widgets, _notify, tmp_path = app
        run = tmp_path / "run-1"
        _write_run(run, severities=[Severity.HIGH, Severity.LOW])
        a._selected = {123}

        a._switch_run(str(run))

        assert len(a.all_findings) == 2
        assert a._current_results_path is not None
        assert a._current_results_path.parent == run.resolve()
        # Switching runs clears the stale (old-object-id) selection.
        assert a._selected == set()

    def test_bad_path_notifies_and_keeps_state(self, app):
        _module, a, _widgets, notify_calls, tmp_path = app
        a.all_findings = ["sentinel"]
        a._switch_run(str(tmp_path / "does-not-exist"))
        assert a.all_findings == ["sentinel"]   # unchanged
        assert notify_calls and any(
            "error" == c.get("severity") for c in notify_calls
        )


class TestEventAnchor:
    def test_returns_screen_coords(self):
        module = _load_app_module()
        ev = types.SimpleNamespace(screen_x=12, screen_y=4)
        assert module.BrowseApp._event_anchor(ev) == (12, 4)

    def test_missing_coords_returns_none(self):
        module = _load_app_module()
        ev = types.SimpleNamespace()
        assert module.BrowseApp._event_anchor(ev) is None


class TestRunnerScreensConstruct:
    def test_prompt_screen_constructs(self):
        module = _load_app_module()
        screen = module.RunScanPromptScreen(default_path="src/")
        assert screen._default_path == "src/"

    def test_run_screen_records_argv_and_launch_root(self, tmp_path):
        module = _load_app_module()
        argv = ["python", "-m", "argus", "scan"]
        screen = module.RunScanScreen(argv, launch_root=tmp_path)
        assert screen._argv == argv
        assert screen._launch_root == tmp_path
        assert screen._finished is False
        assert screen._result_path is None
