"""Tests for the TUI Fix wiring (Phase 1) via the stubbed-textual loader.

The remediation engine itself is covered in test_remediation; here we
verify the app glue: the diff preview renderer, the context-menu "fix"
item for fixable findings, and the propose→preview→apply flow on the
BrowseApp.
"""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

import pytest

from argus.core.config import ViewConfig
from argus.core.models import Finding, Severity
from argus.core.remediation import Remediation


_APP_PATH = Path(__file__).resolve().parents[3] / "viewers" / "terminal" / "app.py"


def _load_app_module():
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

    spec = importlib.util.spec_from_file_location("_browse_app_fix", _APP_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["_browse_app_fix"] = module
    spec.loader.exec_module(module)
    return module


def _dep_finding(pkg="flask", fixed="1.1.1", fid="CVE-1"):
    return Finding(
        id=fid, severity=Severity.HIGH, title="vuln", scanner="osv",
        metadata={"package": pkg, "installed_version": "1.0.0",
                  "fixed_version": fixed, "purl": f"pkg:pypi/{pkg}@1.0.0"},
    )


class TestRenderFixPreview:
    def test_diff_lines_are_coloured(self):
        module = _load_app_module()
        rem = Remediation(
            kind="dependency", title="Bump flask → 1.1.1", confidence="high",
            finding_id="CVE-1", path="requirements.txt",
            diff="--- a/requirements.txt\n+++ b/requirements.txt\n-flask==1.0.0\n+flask==1.1.1\n",
            new_text="flask==1.1.1\n",
        )
        out = module.render_fix_preview([rem])
        assert "Bump flask → 1.1.1" in out
        assert "[green]+flask==1.1.1[/green]" in out
        assert "[red]-flask==1.0.0[/red]" in out

    def test_command_fallback_rendered(self):
        module = _load_app_module()
        rem = Remediation(
            kind="dependency", title="Upgrade flask → 1.1.1 (pip)", confidence="medium",
            finding_id="CVE-1", command=["pip", "install", "flask==1.1.1"], note="re-pin after",
        )
        out = module.render_fix_preview([rem])
        assert "pip install flask==1.1.1" in out
        assert "re-pin after" in out

    def test_brackets_escaped(self):
        module = _load_app_module()
        rem = Remediation(
            kind="dependency", title="Bump x", confidence="high", finding_id="X",
            path="r.txt", diff="+x[extra]==2\n", new_text="x[extra]==2\n",
        )
        out = module.render_fix_preview([rem])
        assert r"\[extra\]" in out  # both brackets escaped so Textual markup doesn't choke


class TestContextMenuFixItem:
    def test_fixable_finding_gets_fix_item(self):
        module = _load_app_module()
        screen = module.ContextMenuScreen(_dep_finding(), ViewConfig())
        keys = [key for _label, key in screen._items]
        assert "fix" in keys

    def test_non_fixable_finding_has_no_fix_item(self):
        module = _load_app_module()
        bandit = Finding(id="B105", severity=Severity.HIGH, title="hardcoded pw",
                         scanner="bandit", location="app.py:5")
        screen = module.ContextMenuScreen(bandit, ViewConfig())
        keys = [key for _label, key in screen._items]
        assert "fix" not in keys


class TestFixFlow:
    @pytest.fixture
    def app(self, tmp_path):
        module = _load_app_module()
        app = module.BrowseApp(results_dir=str(tmp_path))
        notify_calls: list[dict] = []
        pushed: list = []

        def fake_push(screen, callback=None):
            pushed.append(screen)
            # Auto-confirm the FixScreen (simulate the user pressing Apply).
            if callback is not None:
                callback(True)

        app._resolve_repo_root = lambda: tmp_path  # type: ignore[method-assign]
        app.push_screen = fake_push  # type: ignore[method-assign]
        app.notify = lambda *a, **k: notify_calls.append({"a": a, **k})  # type: ignore[method-assign]
        return module, app, tmp_path, notify_calls, pushed

    def test_fix_applies_to_requirements(self, app):
        _module, a, tmp_path, notify_calls, pushed = app
        (tmp_path / "requirements.txt").write_text("flask==1.0.0\n")
        a._fix_findings([_dep_finding("flask", "1.1.1")])
        assert pushed and type(pushed[0]).__name__ == "FixScreen"
        assert (tmp_path / "requirements.txt").read_text() == "flask==1.1.1\n"
        assert any("Applied 1 fix" in c["a"][0] for c in notify_calls)

    def test_no_fixable_findings_warns_without_pushing(self, app):
        _module, a, _tmp, notify_calls, pushed = app
        bandit = Finding(id="B105", severity=Severity.HIGH, title="t", scanner="bandit")
        a._fix_findings([bandit])
        assert not pushed
        assert any(c.get("severity") == "warning" for c in notify_calls)

    def test_empty_targets_is_noop(self, app):
        _module, a, _tmp, notify_calls, pushed = app
        a._fix_findings([])
        assert not pushed and not notify_calls
