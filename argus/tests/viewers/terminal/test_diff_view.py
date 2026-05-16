"""Tests for the scan-over-scan diff view in the terminal viewer.

Coverage targets:
  - DiffScreen renders the four buckets returned by ``diff_scans``
    (``new`` / ``fixed`` / ``severity_changed`` / ``still_open``) with
    counts visible in the rendered text.
  - Empty diff (same scan twice) → all rows in ``still_open``.
  - All-new diff (loaded scan empty) → every "after" finding in ``new``.
  - All-fixed diff (current scan empty) → every "before" finding in
    ``fixed``.
  - Severity-changed bucketing — a finding whose
    ``(scanner, id, location)`` matches but severity differs lands in
    ``severity_changed``, not in ``new``+``fixed``.
  - Still-open bucketing — same identity tuple + same severity in both
    scans, finding persists unchanged.
  - Keybinding integration — ``D`` is bound to ``diff_against`` and the
    palette / help-text drift guard catches removals. The actual screen
    push is exercised by stubbing ``push_screen``.

Like ``test_multi_select.py``, we stub Textual at import time so the
suite runs without the [terminal] extra installed.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import types
from pathlib import Path

import pytest

from argus.core.findings_view import diff_scans
from argus.core.models import Finding, Severity


_APP_PATH = Path(__file__).resolve().parents[3] / "viewers" / "terminal" / "app.py"


# ---------------------------------------------------------------------------
# Stubbed-textual loader — same shape as test_multi_select / test_view_state.
# ---------------------------------------------------------------------------

def _load_app_module():
    """Load ``app.py`` with textual stubbed.

    Returns a fresh module object with all Textual symbols replaced by
    permissive stand-ins so we can introspect ``BINDINGS`` and call
    ``action_*`` methods without running a real Textual app.
    """

    class _Permissive:
        COMMANDS = set()

        def __init__(self, *args, **kwargs): ...
        def __call__(self, *args, **kwargs): return self
        def __class_getitem__(cls, item): return cls

    class _FakeBinding:
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
        "textual.widgets", "textual.widgets.option_list",
    ):
        if mod_name not in sys.modules:
            sys.modules[mod_name] = types.ModuleType(mod_name)
    for attr, mod in (
        ("App", "textual.app"), ("ComposeResult", "textual.app"),
        ("Hit", "textual.command"),
        ("Hits", "textual.command"),
        ("Provider", "textual.command"),
        ("Container", "textual.containers"),
        ("Horizontal", "textual.containers"),
        ("Vertical", "textual.containers"),
        ("VerticalScroll", "textual.containers"),
        ("reactive", "textual.reactive"),
        ("ModalScreen", "textual.screen"),
        ("DataTable", "textual.widgets"),
        ("Footer", "textual.widgets"),
        ("Header", "textual.widgets"),
        ("Input", "textual.widgets"),
        ("OptionList", "textual.widgets"),
        ("Option", "textual.widgets.option_list"),
        ("Static", "textual.widgets"),
    ):
        setattr(sys.modules[mod], attr, _Permissive)
    # Real-shape Binding so we can introspect .key for the drift guard.
    sys.modules["textual.binding"].Binding = _FakeBinding

    spec = importlib.util.spec_from_file_location("_browse_app_diff_view", _APP_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["_browse_app_diff_view"] = module
    spec.loader.exec_module(module)
    return module


def _f(sev, fid="X", scanner="trivy", location=None, cve=None):
    """Build a Finding tagged with the (scanner, id, location) identity tuple
    used by ``argus.core.findings_view._finding_key``."""
    return Finding(
        id=fid, severity=sev, title=f"finding {fid}",
        location=location, cve=cve, scanner=scanner,
    )


# ---------------------------------------------------------------------------
# diff_scans bucketing — exercises the shared module from this test file
# ---------------------------------------------------------------------------

class TestDiffScansBucketing:
    """The diff bucketing rules — exercised independently of the TUI.

    These tests duplicate a couple of cases from the browser-side suite
    but anchored at the source-of-truth function so a refactor of the
    shared module surfaces here too.
    """

    def test_empty_diff_when_scans_identical(self):
        # Same scan twice → nothing in new/fixed/severity_changed,
        # everything in still_open.
        a = _f(Severity.HIGH, fid="CVE-A", location="pkg1")
        b = _f(Severity.HIGH, fid="CVE-B", location="pkg2")
        out = diff_scans([a, b], [a, b])
        assert out["new"] == []
        assert out["fixed"] == []
        assert out["severity_changed"] == []
        ids = {f.id for f in out["still_open"]}
        assert ids == {"CVE-A", "CVE-B"}

    def test_all_new_when_before_is_empty(self):
        a = _f(Severity.HIGH, fid="CVE-A", location="pkg1")
        b = _f(Severity.CRITICAL, fid="CVE-B", location="pkg2")
        out = diff_scans([], [a, b])
        ids = {f.id for f in out["new"]}
        assert ids == {"CVE-A", "CVE-B"}
        assert out["fixed"] == []
        assert out["severity_changed"] == []
        assert out["still_open"] == []

    def test_all_fixed_when_after_is_empty(self):
        a = _f(Severity.HIGH, fid="CVE-A", location="pkg1")
        b = _f(Severity.CRITICAL, fid="CVE-B", location="pkg2")
        out = diff_scans([a, b], [])
        assert out["new"] == []
        ids = {f.id for f in out["fixed"]}
        assert ids == {"CVE-A", "CVE-B"}
        assert out["severity_changed"] == []
        assert out["still_open"] == []

    def test_severity_changed_replaces_new_and_fixed(self):
        # Same identity tuple but severity shifts → severity_changed,
        # NOT a (new, fixed) pair.
        before = _f(Severity.MEDIUM, fid="CVE-A", location="pkg1")
        after = _f(Severity.HIGH,    fid="CVE-A", location="pkg1")
        out = diff_scans([before], [after])
        assert out["new"] == []
        assert out["fixed"] == []
        assert len(out["severity_changed"]) == 1
        pair = out["severity_changed"][0]
        assert pair["before"].severity == Severity.MEDIUM
        assert pair["after"].severity == Severity.HIGH
        assert out["still_open"] == []

    def test_still_open_requires_same_severity(self):
        # Identity tuple matches AND severity is unchanged → still_open.
        before = _f(Severity.HIGH, fid="CVE-A", location="pkg1")
        after = _f(Severity.HIGH,  fid="CVE-A", location="pkg1")
        out = diff_scans([before], [after])
        assert out["still_open"] and out["still_open"][0].id == "CVE-A"
        assert out["new"] == []
        assert out["fixed"] == []
        assert out["severity_changed"] == []

    def test_identity_tuple_distinguishes_same_id_different_location(self):
        # Same scanner + id but different location is NOT the same
        # finding — bandit B105 in foo.py and bar.py are distinct rows.
        before = _f(Severity.HIGH, fid="B105", location="foo.py", scanner="bandit")
        after = _f(Severity.HIGH,  fid="B105", location="bar.py", scanner="bandit")
        out = diff_scans([before], [after])
        # before is fixed (no match in after), after is new.
        assert len(out["fixed"]) == 1
        assert out["fixed"][0].location == "foo.py"
        assert len(out["new"]) == 1
        assert out["new"][0].location == "bar.py"


# ---------------------------------------------------------------------------
# Keybinding integration — covers the contract between BINDINGS, the
# diff action method, and the help-text drift guard.
# ---------------------------------------------------------------------------

class TestKeybindingIntegration:
    """``D`` is bound, the action is callable, the help mentions it."""

    def test_capital_d_is_bound_to_diff_against(self):
        module = _load_app_module()
        keys = {b.key: b.action for b in module.BrowseApp.BINDINGS}
        assert "D" in keys, (
            "shift+d ('D') binding must be present so users can launch "
            "the scan-over-scan diff without leaving the keyboard"
        )
        assert keys["D"] == "diff_against"

    def test_lowercase_d_still_dashboard(self):
        # Regression guard: shifting the diff to ``D`` shouldn't have
        # disturbed the dashboard's ``d`` binding.
        module = _load_app_module()
        keys = {b.key: b.action for b in module.BrowseApp.BINDINGS}
        assert keys.get("d") == "show_dashboard"

    def test_help_text_mentions_capital_d(self):
        module = _load_app_module()
        # The ?-help drift guard would also catch this, but a dedicated
        # assertion makes the failure mode obvious if someone removes
        # the binding without updating the help.
        assert "D" in module._HELP_TEXT
        assert "diff" in module._HELP_TEXT.lower()

    def test_action_diff_against_pushes_picker(self):
        """``D`` action pushes the DiffPickerScreen, not DiffScreen.

        The diff screen needs the *result* of the picker, so the action
        method itself only opens the picker; the ``DiffScreen`` push
        happens inside the picker's callback. We stub ``push_screen`` to
        capture the screen type and confirm the wiring without running
        Textual.
        """
        module = _load_app_module()
        BrowseApp = module.BrowseApp
        DiffPickerScreen = module.DiffPickerScreen

        app = BrowseApp(results_dir=None)
        app.all_findings = []
        # The action references self.sub_title; provide a minimal value.
        app.sub_title = "(test)"

        captured: list = []

        def fake_push_screen(screen, callback=None, *args, **kwargs):
            captured.append({"screen": screen, "callback": callback})

        app.push_screen = fake_push_screen  # type: ignore[method-assign]
        app.action_diff_against()
        assert len(captured) == 1
        # We don't assert isinstance against the stub class (its
        # __class__ is the permissive stub), so check the type name.
        screen = captured[0]["screen"]
        assert type(screen).__name__ == "DiffPickerScreen"
        assert captured[0]["callback"] is not None


# ---------------------------------------------------------------------------
# action_diff_against callback — loading the second scan and pushing
# DiffScreen.
# ---------------------------------------------------------------------------

def _write_results(dir_path: Path, findings: list[Finding]) -> Path:
    """Drop a minimal results JSON shaped for ``ScanSummary.from_dict``."""
    payload = {
        "severity_threshold": None,
        "results": [{
            "scanner": findings[0].scanner if findings else "trivy",
            "findings": [f.to_dict() for f in findings],
            "raw_report": None, "sarif_report": None, "metadata": {},
            "critical_count": sum(1 for f in findings if f.severity == Severity.CRITICAL),
            "high_count": sum(1 for f in findings if f.severity == Severity.HIGH),
            "medium_count": sum(1 for f in findings if f.severity == Severity.MEDIUM),
            "low_count": sum(1 for f in findings if f.severity == Severity.LOW),
            "total_count": len(findings),
        }],
    }
    p = dir_path / "argus-results.json"
    p.write_text(json.dumps(payload))
    return p


class TestPickerCallback:
    """The picker callback loads the comparison scan and pushes DiffScreen."""

    def test_callback_loads_and_pushes_diff_screen(self, tmp_path):
        module = _load_app_module()
        BrowseApp = module.BrowseApp
        before_dir = tmp_path / "before"
        before_dir.mkdir()
        _write_results(before_dir, [
            _f(Severity.HIGH, fid="CVE-A", location="pkg1"),
        ])

        app = BrowseApp(results_dir=None)
        app.all_findings = [
            _f(Severity.HIGH, fid="CVE-B", location="pkg2"),
        ]
        app.sub_title = "(current)"

        captured: list = []

        def fake_push_screen(screen, callback=None, *args, **kwargs):
            captured.append({"screen": screen, "callback": callback})

        app.push_screen = fake_push_screen  # type: ignore[method-assign]
        app.notify = lambda *a, **k: None  # type: ignore[method-assign]

        # First push: the picker. Trigger the callback by invoking the
        # captured callback with a path string — that mirrors what the
        # real DiffPickerScreen does on submit.
        app.action_diff_against()
        picker_callback = captured[0]["callback"]
        picker_callback(str(before_dir))

        # Second push should be the DiffScreen.
        assert len(captured) == 2
        diff_screen = captured[1]["screen"]
        assert type(diff_screen).__name__ == "DiffScreen"

    def test_callback_handles_missing_path_gracefully(self, tmp_path):
        module = _load_app_module()
        BrowseApp = module.BrowseApp

        app = BrowseApp(results_dir=None)
        app.all_findings = []
        app.sub_title = "(current)"

        notify_calls: list[dict] = []
        captured: list = []

        def fake_push_screen(screen, callback=None, *args, **kwargs):
            captured.append({"screen": screen, "callback": callback})

        def fake_notify(msg, **kwargs):
            notify_calls.append({"msg": msg, **kwargs})

        app.push_screen = fake_push_screen  # type: ignore[method-assign]
        app.notify = fake_notify  # type: ignore[method-assign]

        app.action_diff_against()
        picker_callback = captured[0]["callback"]
        # Point at a path that doesn't exist — the loader will raise
        # FileNotFoundError, which we should catch and toast.
        picker_callback(str(tmp_path / "no-such-dir"))

        # Only the picker push fired; no DiffScreen.
        assert len(captured) == 1
        # An error toast went out.
        assert any("Couldn't load" in c["msg"] for c in notify_calls)

    def test_callback_does_nothing_on_cancel(self, tmp_path):
        module = _load_app_module()
        BrowseApp = module.BrowseApp

        app = BrowseApp(results_dir=None)
        app.all_findings = []
        app.sub_title = "(current)"

        captured: list = []

        def fake_push_screen(screen, callback=None, *args, **kwargs):
            captured.append({"screen": screen, "callback": callback})

        app.push_screen = fake_push_screen  # type: ignore[method-assign]
        app.notify = lambda *a, **k: None  # type: ignore[method-assign]
        app.action_diff_against()
        picker_callback = captured[0]["callback"]
        picker_callback(None)  # ESC / cancel

        # Only the picker — no follow-up DiffScreen.
        assert len(captured) == 1
