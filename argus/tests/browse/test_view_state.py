"""Unit tests for ViewState — filter/sort/search logic in the browse TUI.

ViewState is UI-free, so we test it without importing Textual. Keeps the
test suite runnable in CI environments that don't have the ``browse``
extra installed.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from argus.core.models import Finding, Severity


_APP_PATH = Path(__file__).resolve().parents[2] / "browse" / "app.py"


@pytest.fixture
def ViewState():
    """Load ViewState from app.py WITHOUT importing textual.

    The Textual imports live at module top-level, so we can't
    ``from argus.browse.app import ViewState`` unless textual is
    installed. A direct spec-based load with the textual imports
    stubbed keeps the test hermetic.
    """
    import sys, types
    # Stub textual modules so the import doesn't fail in environments
    # without the [browse] extra installed. Each attribute is a
    # permissive callable that accepts any args / kwargs, so code paths
    # like `Binding("q", "quit", "Quit")` or `reactive("")` work without
    # needing the real textual API.
    class _Permissive:
        # Empty COMMANDS set lets ``App.COMMANDS | {ArgusBrowseCommands}``
        # evaluate against the stub without an AttributeError.
        COMMANDS = set()

        def __init__(self, *args, **kwargs): ...
        def __call__(self, *args, **kwargs): return self
        def __class_getitem__(cls, item): return cls

    for mod_name in (
        "textual", "textual.app", "textual.binding", "textual.command",
        "textual.containers", "textual.reactive", "textual.screen",
        "textual.widgets",
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
        ("ModalScreen", "textual.screen"),
        ("DataTable", "textual.widgets"),
        ("Footer", "textual.widgets"),
        ("Header", "textual.widgets"),
        ("Input", "textual.widgets"),
        ("Static", "textual.widgets"),
    ):
        setattr(sys.modules[mod], attr, _Permissive)

    spec = importlib.util.spec_from_file_location("_browse_app_probe", _APP_PATH)
    module = importlib.util.module_from_spec(spec)
    # Dataclass machinery resolves __module__ via sys.modules during class
    # creation; register the probe module before executing so @dataclass
    # doesn't blow up with AttributeError on a None module lookup.
    sys.modules["_browse_app_probe"] = module
    spec.loader.exec_module(module)
    return module.ViewState


def _f(sev, fid="X", title="t", location=None, cve=None, scanner=""):
    return Finding(
        id=fid, severity=sev, title=title,
        location=location, cve=cve, scanner=scanner,
    )


class TestFilterBySeverity:
    def test_none_matches_everything(self, ViewState):
        vs = ViewState(min_severity=None)
        assert vs.matches(_f(Severity.LOW))
        assert vs.matches(_f(Severity.CRITICAL))

    def test_high_threshold_excludes_medium(self, ViewState):
        vs = ViewState(min_severity=Severity.HIGH)
        assert not vs.matches(_f(Severity.MEDIUM))
        assert vs.matches(_f(Severity.HIGH))
        assert vs.matches(_f(Severity.CRITICAL))


class TestSearchQuery:
    def test_matches_title(self, ViewState):
        vs = ViewState(query="log4j")
        assert vs.matches(_f(Severity.HIGH, title="Log4J RCE"))
        assert not vs.matches(_f(Severity.HIGH, title="openssl heartbleed"))

    def test_matches_cve(self, ViewState):
        vs = ViewState(query="cve-2021")
        assert vs.matches(_f(Severity.HIGH, cve="CVE-2021-44228"))
        assert not vs.matches(_f(Severity.HIGH, cve="CVE-2026-1234"))

    def test_matches_location(self, ViewState):
        vs = ViewState(query="log4j")
        assert vs.matches(_f(Severity.HIGH, location="log4j-core@2.14.1"))

    def test_combined_severity_and_query(self, ViewState):
        vs = ViewState(min_severity=Severity.HIGH, query="log4j")
        assert vs.matches(_f(Severity.CRITICAL, title="log4j RCE"))
        # Right name, wrong severity
        assert not vs.matches(_f(Severity.MEDIUM, title="log4j RCE"))
        # Right severity, wrong name
        assert not vs.matches(_f(Severity.CRITICAL, title="openssl"))


class TestSort:
    def test_severity_desc_puts_critical_first(self, ViewState):
        vs = ViewState(sort_key="severity_desc")
        findings = [
            _f(Severity.LOW, fid="L"),
            _f(Severity.CRITICAL, fid="C"),
            _f(Severity.MEDIUM, fid="M"),
        ]
        ordered = sorted(findings, key=vs.sort_key_fn())
        assert [f.id for f in ordered] == ["C", "M", "L"]

    def test_severity_asc_puts_info_first(self, ViewState):
        vs = ViewState(sort_key="severity_asc")
        findings = [
            _f(Severity.CRITICAL, fid="C"),
            _f(Severity.INFO, fid="I"),
            _f(Severity.HIGH, fid="H"),
        ]
        ordered = sorted(findings, key=vs.sort_key_fn())
        assert [f.id for f in ordered] == ["I", "H", "C"]

    def test_package_sort_uses_location(self, ViewState):
        vs = ViewState(sort_key="package")
        findings = [
            _f(Severity.HIGH, fid="1", location="zlib@1.0"),
            _f(Severity.HIGH, fid="2", location="Abc@2.0"),
            _f(Severity.HIGH, fid="3", location="mname@3.0"),
        ]
        ordered = sorted(findings, key=vs.sort_key_fn())
        # Sort is case-insensitive, so Abc beats mname beats zlib.
        assert [f.id for f in ordered] == ["2", "3", "1"]


class TestSortLabels:
    """_SORT_LABELS must cover every sort mode the cycle iterates over."""

    def test_every_cycle_key_has_a_label(self, ViewState):
        # Import the module same way the fixture does — it's already loaded
        # into sys.modules as _browse_app_probe by the fixture setup.
        import sys
        module = sys.modules["_browse_app_probe"]
        cycle = ["severity_desc", "severity_asc", "package", "id"]
        for key in cycle:
            assert key in module._SORT_LABELS
            assert module._SORT_LABELS[key]  # non-empty human label
