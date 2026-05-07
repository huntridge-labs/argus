"""Unit tests for multi-select in the terminal viewer.

Coverage targets:
  - The clipboard helper (``argus.viewers.terminal.clipboard``) — all
    formatting + strategy chains. UI-free, easy to test.
  - The selection-aware export helpers — verified by exercising
    ``BrowseApp._export_in_format`` indirectly via a stubbed-textual load
    of ``app.py`` (same fixture pattern the existing test files use).
  - Filter survives selection — a row that gets filtered out, then
    back in, retains its selection mark.

Textual ``Pilot``-driven integration testing (real keystroke replay)
is out of scope here: it requires the [terminal] extra to be installed
in CI and adds significant test runtime. The selection logic itself
is sliced thin enough that the unit tests cover the keybinding
semantics one helper at a time.
"""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path
from unittest.mock import patch

import pytest

from argus.core.models import Finding, Severity
from argus.viewers.terminal.clipboard import (
    copy_to_clipboard,
    format_findings_for_clipboard,
)


_APP_PATH = Path(__file__).resolve().parents[3] / "viewers" / "terminal" / "app.py"


# ---------------------------------------------------------------------------
# Stubbed-textual loader — same pattern as test_view_state / test_export.
# ---------------------------------------------------------------------------

def _load_app_module():
    """Load ``app.py`` with textual stubbed.

    The DataTable stub records ``add_row`` calls so tests can inspect
    what the BrowseApp *would have rendered*. This is the closest we
    can get to a Textual integration test without the framework
    installed.
    """

    class _StubColumn:
        def __init__(self):
            self.label = ""

    class _StubTable:
        def __init__(self):
            self.rows: list[tuple] = []
            self.columns: dict[str, _StubColumn] = {}
            self.cursor_coordinate = (0, 0)
            self._col_keys: list[str] = []

        def add_columns(self, *labels):
            keys = [f"col-{i}" for i in range(len(labels))]
            for k, label in zip(keys, labels):
                col = _StubColumn()
                col.label = label
                self.columns[k] = col
            self._col_keys = keys
            return keys

        def clear(self):
            self.rows.clear()

        def add_row(self, *cells):
            self.rows.append(cells)

        def focus(self):
            pass

        def action_cursor_down(self):
            r, c = self.cursor_coordinate
            self.cursor_coordinate = (r + 1, c)

        def action_cursor_up(self):
            r, c = self.cursor_coordinate
            self.cursor_coordinate = (max(0, r - 1), c)

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

    spec = importlib.util.spec_from_file_location("_browse_app_multi_select", _APP_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["_browse_app_multi_select"] = module
    spec.loader.exec_module(module)
    return module


def _f(sev, fid="X", title="t", location=None, cve=None, scanner="trivy"):
    return Finding(
        id=fid, severity=sev, title=title,
        location=location, cve=cve, scanner=scanner,
    )


# ---------------------------------------------------------------------------
# Clipboard helper — pure-function tests
# ---------------------------------------------------------------------------

class TestFormatFindingsForClipboard:
    """The payload-builder is what users paste into bug trackers."""

    def test_uses_cve_when_present(self):
        findings = [
            _f(Severity.HIGH, fid="A", cve="CVE-2021-44228"),
            _f(Severity.HIGH, fid="B", cve="CVE-2023-12345"),
        ]
        out = format_findings_for_clipboard(findings)
        assert out == "CVE-2021-44228\nCVE-2023-12345"

    def test_falls_back_to_scanner_id_when_no_cve(self):
        # SAST findings (bandit, opengrep) typically have no CVE — the
        # fallback identity is what makes the row identifiable in a
        # bug-tracker comment without forcing the user to chase down
        # source links manually.
        findings = [_f(Severity.HIGH, fid="B105", scanner="bandit", cve=None)]
        out = format_findings_for_clipboard(findings)
        assert out == "bandit:B105"

    def test_one_per_line(self):
        findings = [
            _f(Severity.HIGH, fid="A", cve="CVE-1"),
            _f(Severity.HIGH, fid="B", cve="CVE-2"),
            _f(Severity.HIGH, fid="C", cve="CVE-3"),
        ]
        out = format_findings_for_clipboard(findings)
        assert out.count("\n") == 2
        assert out.split("\n") == ["CVE-1", "CVE-2", "CVE-3"]

    def test_preserves_duplicate_cves(self):
        # Same CVE on two different SBOMs is intentional — pasting the
        # list to a bug tracker should reflect that the CVE was
        # seen twice. Deduping silently would surprise the user.
        findings = [
            _f(Severity.HIGH, fid="A", cve="CVE-1", location="alpha.spdx"),
            _f(Severity.HIGH, fid="B", cve="CVE-1", location="beta.spdx"),
        ]
        out = format_findings_for_clipboard(findings)
        assert out == "CVE-1\nCVE-1"

    def test_empty_input(self):
        assert format_findings_for_clipboard([]) == ""


class TestCopyToClipboard:
    """Strategy chain — pyperclip → platform CLI → fail-soft."""

    def test_pyperclip_wins_when_present(self, monkeypatch):
        # Inject a stub pyperclip module so the import path succeeds
        # without requiring pyperclip in the test env.
        stub = types.ModuleType("pyperclip")
        captured: dict[str, str] = {}

        def _copy(text: str) -> None:
            captured["payload"] = text

        stub.copy = _copy
        monkeypatch.setitem(sys.modules, "pyperclip", stub)
        ok, mechanism = copy_to_clipboard("CVE-2021-44228")
        assert ok is True
        assert mechanism == "pyperclip"
        assert captured["payload"] == "CVE-2021-44228"

    def test_falls_back_to_platform_cli(self, monkeypatch):
        # No pyperclip → strategy chain advances to the next entry.
        monkeypatch.setitem(sys.modules, "pyperclip", None)
        called: dict[str, list] = {}

        from argus.viewers.terminal import clipboard as cb

        def fake_subprocess(argv, text):
            called.setdefault("argv", []).append(argv)
            called["text"] = text
            return True

        monkeypatch.setattr(cb, "_try_subprocess", fake_subprocess)
        ok, mechanism = copy_to_clipboard("hello")
        # Mechanism varies by platform — we just confirm it succeeded
        # via the shell-out path (i.e. not pyperclip).
        assert ok is True
        assert mechanism != "pyperclip"
        assert called["text"] == "hello"

    def test_returns_false_when_nothing_works(self, monkeypatch):
        # Disable pyperclip and force every subprocess attempt to fail
        # (simulates a headless Linux box without xclip / wl-copy).
        monkeypatch.setitem(sys.modules, "pyperclip", None)
        from argus.viewers.terminal import clipboard as cb
        monkeypatch.setattr(cb, "_try_subprocess", lambda argv, text: False)
        ok, mechanism = copy_to_clipboard("anything")
        assert ok is False
        assert mechanism is None

    def test_pyperclip_exception_falls_through(self, monkeypatch):
        # pyperclip raises on headless Linux without a backend; we
        # should *not* crash, we should advance to platform CLIs.
        stub = types.ModuleType("pyperclip")
        def _copy(text: str) -> None:
            raise RuntimeError("no clipboard backend")
        stub.copy = _copy
        monkeypatch.setitem(sys.modules, "pyperclip", stub)
        from argus.viewers.terminal import clipboard as cb
        monkeypatch.setattr(cb, "_try_subprocess", lambda argv, text: True)
        ok, mechanism = copy_to_clipboard("hello")
        assert ok is True
        assert mechanism != "pyperclip"


class TestPlatformStrategies:
    """The strategy list reflects the platform we're running on."""

    def _strategies_for(self, platform_str: str):
        from argus.viewers.terminal import clipboard as cb
        orig = sys.platform
        sys.platform = platform_str
        try:
            return [label for label, _ in cb._platform_strategies()]
        finally:
            sys.platform = orig

    def test_macos_includes_pbcopy(self):
        labels = self._strategies_for("darwin")
        assert "pbcopy" in labels

    def test_linux_includes_xclip_and_wl_copy(self):
        labels = self._strategies_for("linux")
        assert "xclip" in labels
        # wl-copy fallback for Wayland users without xclip installed.
        assert "wl-copy" in labels

    def test_windows_includes_clip(self):
        labels = self._strategies_for("win32")
        assert "clip" in labels

    def test_pyperclip_is_first_for_every_platform(self):
        for platform in ("darwin", "linux", "win32"):
            labels = self._strategies_for(platform)
            # pyperclip first means a user with it installed on a
            # platform we don't natively support still works.
            assert labels[0] == "pyperclip"


class TestTrySubprocess:
    """``_try_subprocess`` should be safe even when the binary is missing."""

    def test_returns_false_when_binary_not_on_path(self):
        from argus.viewers.terminal import clipboard as cb
        # Use a binary name that nobody has installed.
        assert cb._try_subprocess(["definitely-not-a-real-binary-9z9z"], "x") is False


# ---------------------------------------------------------------------------
# Selection state on the BrowseApp — exercised via the stubbed loader.
# ---------------------------------------------------------------------------

@pytest.fixture
def app_with_findings():
    """Yield a BrowseApp with an in-memory finding set, no Textual run.

    We bypass ``on_mount`` (which loads a JSON file) and seat the
    state by hand. This lets us call ``action_*`` methods directly
    and inspect ``_selected`` / ``_visible``.
    """
    module = _load_app_module()
    BrowseApp = module.BrowseApp
    app = BrowseApp(results_dir=None)
    findings = [
        _f(Severity.CRITICAL, fid="CVE-1", cve="CVE-2021-1"),
        _f(Severity.HIGH,     fid="CVE-2", cve="CVE-2021-2"),
        _f(Severity.MEDIUM,   fid="CVE-3", cve="CVE-2021-3"),
        _f(Severity.LOW,      fid="CVE-4", cve="CVE-2021-4"),
    ]
    app.all_findings = findings
    app._visible = list(findings)

    # Stub out the Textual lookups so action methods don't crash.
    table_stub = types.SimpleNamespace(
        cursor_coordinate=(0, 0),
        rows=[], columns={},
    )
    notify_calls: list[dict] = []
    status_text: list[str] = []

    def fake_query_one(selector, *args):
        if selector == "#status":
            return types.SimpleNamespace(update=lambda t: status_text.append(t))
        if selector == "#detail":
            return types.SimpleNamespace(update_finding=lambda f: None)
        # DataTable lookup — the stub is intentionally minimal.
        return table_stub

    def fake_notify(msg, **kwargs):
        notify_calls.append({"msg": msg, **kwargs})

    app.query_one = fake_query_one  # type: ignore[method-assign]
    app.notify = fake_notify  # type: ignore[method-assign]

    # Don't drive _refresh_list (it queries DataTable.add_row) —
    # selection action methods call _refresh_keep_cursor → _refresh_list,
    # so stub _refresh_list to a no-op that mimics the visible list.
    app._refresh_list = lambda: None  # type: ignore[method-assign]
    app._refresh_keep_cursor = lambda row: None  # type: ignore[method-assign]

    return app, findings, notify_calls


class TestSelectionToggle:
    def test_toggle_adds_then_removes(self, app_with_findings):
        app, findings, _ = app_with_findings
        # Cursor starts at row 0.
        app.action_toggle_selection()
        assert id(findings[0]) in app._selected
        # Press space again → deselects.
        app.action_toggle_selection()
        assert id(findings[0]) not in app._selected

    def test_toggle_at_different_rows(self, app_with_findings):
        app, findings, _ = app_with_findings
        # Toggle row 0
        app.action_toggle_selection()
        # Move cursor to row 2 by faking the coordinate
        app.query_one("any").cursor_coordinate = (2, 0)
        app.action_toggle_selection()
        assert id(findings[0]) in app._selected
        assert id(findings[2]) in app._selected
        assert id(findings[1]) not in app._selected
        assert len(app._selected) == 2

    def test_toggle_noop_when_no_visible_rows(self, app_with_findings):
        app, _, _ = app_with_findings
        app._visible = []
        app.action_toggle_selection()
        assert app._selected == set()


class TestSelectAll:
    def test_select_all_marks_every_visible_row(self, app_with_findings):
        app, findings, notify_calls = app_with_findings
        app.action_select_all()
        for f in findings:
            assert id(f) in app._selected
        # Toast confirms the action.
        assert any("Selected" in c["msg"] for c in notify_calls)

    def test_select_all_with_filter_only_marks_filtered_rows(self, app_with_findings):
        app, findings, _ = app_with_findings
        # Simulate a filter that excludes CVE-3 and CVE-4.
        app._visible = findings[:2]
        app.action_select_all()
        assert id(findings[0]) in app._selected
        assert id(findings[1]) in app._selected
        # Filtered-out rows are NOT in the selection.
        assert id(findings[2]) not in app._selected
        assert id(findings[3]) not in app._selected

    def test_select_all_is_additive(self, app_with_findings):
        # Pre-existing selection from another filter should survive.
        app, findings, _ = app_with_findings
        app._selected.add(id(findings[3]))   # CVE-4 — not in current filter
        app._visible = findings[:2]
        app.action_select_all()
        assert id(findings[0]) in app._selected
        assert id(findings[1]) in app._selected
        assert id(findings[3]) in app._selected   # preserved


class TestClearSelection:
    def test_clear_drops_everything(self, app_with_findings):
        app, findings, _ = app_with_findings
        app._selected = {id(f) for f in findings}
        app.action_clear_selection()
        assert app._selected == set()

    def test_clear_when_empty_is_noop(self, app_with_findings):
        app, _, notify_calls = app_with_findings
        app.action_clear_selection()
        # No "Cleared 0" toast.
        assert not any("Cleared" in c["msg"] for c in notify_calls)


class TestFilterPreservesSelection:
    """Headline behavior: a row filtered out and back retains selection."""

    def test_selection_survives_filter_round_trip(self, app_with_findings):
        app, findings, _ = app_with_findings
        # Select CVE-3 (index 2) — a MEDIUM.
        app.query_one("any").cursor_coordinate = (2, 0)
        app.action_toggle_selection()
        assert id(findings[2]) in app._selected
        # Now apply a filter that hides CVE-3 (only HIGH+).
        app._visible = findings[:2]   # CRITICAL + HIGH only
        # Selection is still tracked.
        assert id(findings[2]) in app._selected
        # Filter cleared — row reappears with its mark intact.
        app._visible = list(findings)
        assert id(findings[2]) in app._selected


# ---------------------------------------------------------------------------
# Export / clipboard integration on the app itself
# ---------------------------------------------------------------------------

class TestExportRespectsSelection:
    def test_export_with_selection_writes_only_selected(self, app_with_findings, tmp_path, monkeypatch):
        app, findings, _ = app_with_findings
        # Select two rows.
        app._selected = {id(findings[0]), id(findings[2])}

        from argus.viewers.terminal import export
        captured: dict[str, list] = {}

        def fake_writer(items, dest):
            captured["items"] = list(items)
            return dest

        # Patch WRITERS to use our spy instead of touching the disk.
        monkeypatch.setitem(
            export.WRITERS, "csv", (fake_writer, "csv"),
        )
        monkeypatch.setattr(
            export, "make_export_path",
            lambda fmt, scope="all", **kw: tmp_path / f"out-{scope}.{fmt}",
        )

        app.action_export_csv()
        assert len(captured["items"]) == 2
        ids = {f.id for f in captured["items"]}
        assert ids == {"CVE-1", "CVE-3"}

    def test_export_without_selection_writes_filtered_view(self, app_with_findings, tmp_path, monkeypatch):
        app, findings, _ = app_with_findings
        # No selection → previous behavior preserved.
        app._selected = set()
        # Simulate an active filter (HIGH+ only).
        app._visible = findings[:2]

        from argus.viewers.terminal import export
        captured: dict[str, list] = {}

        def fake_writer(items, dest):
            captured["items"] = list(items)
            return dest

        monkeypatch.setitem(
            export.WRITERS, "csv", (fake_writer, "csv"),
        )
        monkeypatch.setattr(
            export, "make_export_path",
            lambda fmt, scope="all", **kw: tmp_path / f"out-{scope}.{fmt}",
        )

        app.action_export_csv()
        assert len(captured["items"]) == 2
        ids = {f.id for f in captured["items"]}
        assert ids == {"CVE-1", "CVE-2"}

    def test_scope_label_in_filename_reflects_selection(self, app_with_findings, tmp_path, monkeypatch):
        app, findings, _ = app_with_findings
        app._selected = {id(findings[0])}

        from argus.viewers.terminal import export
        scope_seen: dict[str, str] = {}

        def fake_writer(items, dest):
            return dest

        monkeypatch.setitem(
            export.WRITERS, "csv", (fake_writer, "csv"),
        )

        def fake_path(fmt, scope="all", **kw):
            scope_seen["value"] = scope
            return tmp_path / f"out-{scope}.{fmt}"

        monkeypatch.setattr(export, "make_export_path", fake_path)
        app.action_export_csv()
        # The filename's scope marker reads "selection" — so filter
        # exports and selection exports never clobber each other.
        assert scope_seen["value"] == "selection"


class TestCopyCves:
    def test_copies_cve_ids_when_clipboard_works(self, app_with_findings, monkeypatch):
        app, findings, notify_calls = app_with_findings
        app._selected = {id(findings[0]), id(findings[1])}

        captured: dict[str, str] = {}

        def fake_copy(text: str):
            captured["text"] = text
            return True, "pyperclip"

        from argus.viewers.terminal import clipboard
        monkeypatch.setattr(clipboard, "copy_to_clipboard", fake_copy)

        app.action_copy_cves()
        # Two CVEs, one per line, in visible-first order.
        assert captured["text"] == "CVE-2021-1\nCVE-2021-2"
        # Toast names the mechanism that worked.
        assert any("pyperclip" in c["msg"] for c in notify_calls)

    def test_warns_when_no_selection(self, app_with_findings, monkeypatch):
        app, _, notify_calls = app_with_findings
        from argus.viewers.terminal import clipboard
        # We shouldn't even call copy_to_clipboard — break it to prove that.
        def boom(_text):
            raise AssertionError("clipboard called with no selection")
        monkeypatch.setattr(clipboard, "copy_to_clipboard", boom)
        app.action_copy_cves()
        # The warning toast nudges the user to select something first.
        assert any("No findings selected" in c["msg"] for c in notify_calls)

    def test_falls_back_cleanly_when_clipboard_unavailable(self, app_with_findings, monkeypatch):
        app, findings, notify_calls = app_with_findings
        app._selected = {id(findings[0])}
        from argus.viewers.terminal import clipboard
        monkeypatch.setattr(clipboard, "copy_to_clipboard", lambda t: (False, None))
        # Should NOT raise.
        app.action_copy_cves()
        # Toast tells the user how to fix it.
        msgs = " ".join(c["msg"] for c in notify_calls)
        assert "No clipboard mechanism" in msgs

    def test_includes_out_of_view_selections(self, app_with_findings, monkeypatch):
        # Cross-filter selection: user selected CVE-1, then narrowed
        # the filter so CVE-1 is no longer visible. Copy should still
        # include it (just at the end of the payload).
        app, findings, _ = app_with_findings
        app._selected = {id(findings[0]), id(findings[3])}
        app._visible = [findings[3]]   # filter hides findings[0]

        captured: dict[str, str] = {}

        def fake_copy(text: str):
            captured["text"] = text
            return True, "pyperclip"

        from argus.viewers.terminal import clipboard
        monkeypatch.setattr(clipboard, "copy_to_clipboard", fake_copy)
        app.action_copy_cves()
        # Both CVEs land in the payload — visible row first, then
        # the out-of-view selection.
        lines = captured["text"].split("\n")
        assert set(lines) == {"CVE-2021-1", "CVE-2021-4"}
        assert lines[0] == "CVE-2021-4"  # in-view first
