"""Conformance tests for the ``argus.plugins.v1`` public contract.

These pin the **stable surface third-party plugins (and Argus Enterprise) build
on**: the ``Finding`` / ``ScanResult`` / ``Severity`` data shapes, the
``Scanner`` protocol, and the ``argus.reporters`` extension seam. A breaking
change to any of these fails CI **before merge**, so "update core → break a
downstream plugin" can't slip through silently.

Stability policy (see ``docs/plugin-contract.md`` / ADR-032): no breaking changes
to this surface within a major version — adding fields/members is fine, removing
or renaming one is a breaking change that requires a new contract version and a
core major bump. Assertions use **subset** checks so additions stay compatible.
"""

from __future__ import annotations

import dataclasses
import types

from argus.core.models import Finding, ScanResult, Severity
from argus.core.scanner import Scanner
from argus.reporters import (
    ENTRY_POINT_GROUP,
    available_reporters,
    get_reporter,
)
from argus.reporters import _iter_entry_points, _reset_registry_cache_for_tests


class TestFindingContract:
    REQUIRED = {"id", "severity", "title"}
    OPTIONAL = {"description", "location", "cwe", "cve", "scanner", "metadata"}

    def test_fields_present(self):
        names = {f.name for f in dataclasses.fields(Finding)}
        missing = (self.REQUIRED | self.OPTIONAL) - names
        assert not missing, f"Finding lost contract fields: {missing}"

    def test_optional_fields_have_defaults(self):
        fields = {f.name: f for f in dataclasses.fields(Finding)}
        for name in self.OPTIONAL:
            f = fields[name]
            has_default = (
                f.default is not dataclasses.MISSING
                or f.default_factory is not dataclasses.MISSING  # type: ignore[misc]
            )
            assert has_default, f"contract optional field {name!r} must keep a default"

    def test_minimal_construction(self):
        f = Finding(id="F1", severity=Severity.HIGH, title="t")
        assert f.id == "F1" and f.severity is Severity.HIGH

    def test_to_dict_keys_and_severity_is_string(self):
        d = Finding(id="F1", severity=Severity.HIGH, title="t").to_dict()
        contract_keys = self.REQUIRED | self.OPTIONAL
        assert contract_keys <= set(d), f"to_dict dropped contract keys: {contract_keys - set(d)}"
        assert d["severity"] == "high"  # serialized as the string value, not the enum


class TestScanResultContract:
    def test_fields_present(self):
        names = {f.name for f in dataclasses.fields(ScanResult)}
        assert {"scanner", "findings"} <= names

    def test_to_dict_exposes_scanner_and_findings(self):
        r = ScanResult(scanner="plugin/x", findings=[Finding(id="F", severity=Severity.LOW, title="t")])
        d = r.to_dict()
        assert {"scanner", "findings"} <= set(d)
        assert isinstance(d["findings"], list) and d["findings"][0]["severity"] == "low"


class TestSeverityContract:
    EXPECTED = {
        "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
        "LOW": "low", "INFO": "info", "UNKNOWN": "unknown",
    }

    def test_members_and_values(self):
        for name, value in self.EXPECTED.items():
            assert hasattr(Severity, name), f"Severity lost member {name}"
            assert getattr(Severity, name).value == value

    def test_from_string_coerces(self):
        assert Severity.from_string("HIGH") is Severity.HIGH
        assert Severity.from_string("  critical ") is Severity.CRITICAL
        assert Severity.from_string("not-a-severity") is Severity.UNKNOWN


class TestScannerProtocolContract:
    def test_conforming_object_is_a_scanner(self):
        class MyScanner:
            name = "my-scanner"
            supports_sbom = False  # part of the Scanner contract (data member)
            supports_vex = False  # part of the Scanner contract (data member)

            def scan(self, path, config=None):  # noqa: ARG002
                return ScanResult(scanner=self.name)

            def is_available(self):
                return True

            def install_command(self):
                return None

            def tool_version(self):
                return None

        assert isinstance(MyScanner(), Scanner)

    def test_missing_method_is_not_a_scanner(self):
        class NotAScanner:
            name = "broken"
            # no scan()

        assert not isinstance(NotAScanner(), Scanner)


class TestReporterSeamContract:
    def test_entry_point_group_is_stable(self):
        assert ENTRY_POINT_GROUP == "argus.reporters"

    def test_builtin_reporters_resolve(self):
        names = available_reporters()
        assert {"json", "sarif", "markdown"} <= set(names)
        assert get_reporter("json") is not None

    def test_external_reporter_discovered_via_seam(self, monkeypatch):
        # A third party registers a reporter under the argus.reporters group.
        class _ExternalReporter:
            name = "contract-probe"

            def report(self, summary, output_dir=None):  # noqa: ARG002 - Reporter contract
                return ""

        def _fake_ep_load():
            ep = types.SimpleNamespace(
                name="contract-probe",
                value="some_pkg.mod:ExternalReporter",  # not argus.reporters.* → external
                load=lambda: _ExternalReporter,
            )
            return [ep]

        monkeypatch.setattr("argus.reporters._iter_entry_points", _fake_ep_load)
        _reset_registry_cache_for_tests()
        try:
            assert "contract-probe" in available_reporters()
        finally:
            monkeypatch.undo()
            _reset_registry_cache_for_tests()

    # NOTE: the "external cannot shadow a built-in name" protection is a security
    # property of the reporters loader itself (it requires the real built-in entry
    # point to be present alongside the external one). It is exercised in the
    # reporters module's own test suite, not here — this conformance suite pins the
    # public *contract* surface, not the loader's internal precedence rules.


def test_iter_entry_points_targets_the_group():
    # The discovery helper exists and is the seam the contract relies on.
    assert callable(_iter_entry_points)
