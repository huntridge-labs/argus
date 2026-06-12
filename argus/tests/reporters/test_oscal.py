"""Tests for argus.reporters.oscal — OscalReporter.

Every emitted document is validated against the vendored NIST OSCAL 1.1.2
JSON schema; the test suite is the load-bearing guarantee that the reporter
produces GRC-ingestion-ready output. ``jsonschema`` is a test-only
dependency (see requirements.txt) — runtime emission needs no validator.
"""

from __future__ import annotations

import json
import os
import uuid as _uuid_mod
from pathlib import Path

import pytest
from jsonschema import Draft7Validator

from argus.core.models import Finding, ScanResult, ScanSummary, Severity
from argus.reporters.oscal import OscalReporter


_SCHEMA_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "compliance"
    / "schemas"
    / "oscal_assessment-results_schema.json"
)


def _ascii_fold_pcre(schema: dict | list) -> None:
    """In-place rewrite of PCRE \\p{L} / \\p{N} escapes to ASCII equivalents.

    The OSCAL schema uses PCRE Unicode property escapes (``\\p{L}`` for
    "any letter", ``\\p{N}`` for "any digit") in its TokenDatatype pattern.
    Python's stdlib ``re`` doesn't implement Unicode property escapes, so
    ``jsonschema`` raises ``re.PatternError`` when it tries to compile the
    schema's pattern keywords. Argus emits ASCII-only OSCAL by construction
    (UUIDs, control ids, scanner names, timestamps), so collapsing the
    Unicode classes to their ASCII subsets gives equivalent validation for
    everything we actually produce — without pulling in the third-party
    ``regex`` library as a test dependency.

    Mutates the schema dict directly; called once when the validator
    fixture is built.
    """
    if isinstance(schema, dict):
        if isinstance(schema.get("pattern"), str):
            schema["pattern"] = (
                schema["pattern"].replace(r"\p{L}", "[A-Za-z]").replace(r"\p{N}", "[0-9]")
            )
        for value in schema.values():
            _ascii_fold_pcre(value)
    elif isinstance(schema, list):
        for item in schema:
            _ascii_fold_pcre(item)


@pytest.fixture(scope="module")
def oscal_validator() -> Draft7Validator:
    """Build the OSCAL AR JSON Schema validator once per module.

    Schema parsing + validator construction is non-trivial (~130KB schema
    with deep $ref resolution), so we share one validator across all
    tests rather than rebuilding per test.
    """
    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    _ascii_fold_pcre(schema)
    return Draft7Validator(schema)


def _validate(validator: Draft7Validator, doc: dict) -> None:
    """Assert ``doc`` is a valid OSCAL Assessment Results document.

    Surfaces all errors at once rather than only the first — easier to
    diagnose schema drift in a single test run.
    """
    errors = sorted(validator.iter_errors(doc), key=lambda e: list(e.absolute_path))
    if errors:
        msg = "\n".join(
            f"  {'.'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}"
            for e in errors
        )
        raise AssertionError(f"OSCAL schema validation failed:\n{msg}")


@pytest.fixture
def summary_one_mapped_finding() -> ScanSummary:
    """ScanSummary with a single Bandit finding that hits the rule mapping."""
    result = ScanResult(
        scanner="bandit",
        findings=[
            Finding(
                id="B105",
                severity=Severity.HIGH,
                title="Hardcoded password",
                description="A password literal appears in source",
                location="app/config.py:42",
                cwe="CWE-798",
                scanner="bandit",
            ),
        ],
    )
    return ScanSummary(results=[result])


@pytest.fixture
def summary_unmapped_finding() -> ScanSummary:
    """ScanSummary with a finding that has no scanner mapping and no CWE."""
    result = ScanResult(
        scanner="some-future-scanner",
        findings=[
            Finding(
                id="FUTURE-1",
                severity=Severity.MEDIUM,
                title="Unmappable finding",
                description="Has no mapping in any tier",
                location="x.py:1",
                scanner="some-future-scanner",
            ),
        ],
    )
    return ScanSummary(results=[result])


@pytest.fixture
def summary_multi_scanner() -> ScanSummary:
    """Two scanners, mix of mapped + unmapped + multi-control findings."""
    bandit = ScanResult(
        scanner="bandit",
        findings=[
            Finding(
                id="B105",
                severity=Severity.HIGH,
                title="Hardcoded password",
                location="config.py:10",
                cwe="CWE-798",
                scanner="bandit",
            ),
            Finding(
                id="B999",  # not in mapping; hits .default
                severity=Severity.LOW,
                title="Unknown bandit rule",
                location="other.py:1",
                scanner="bandit",
            ),
        ],
    )
    future = ScanResult(
        scanner="opengrep",  # no mapping file, falls through to CWE
        findings=[
            Finding(
                id="OG-78",
                severity=Severity.HIGH,
                title="Command injection",
                location="exec.py:8",
                cwe="CWE-78",
                scanner="opengrep",
            ),
        ],
    )
    return ScanSummary(results=[bandit, future])


class TestOutput:
    """File output + structural sanity."""

    def test_writes_expected_filename(self, tmp_path, summary_one_mapped_finding):
        path = OscalReporter().report(summary_one_mapped_finding, tmp_path)
        assert path.name == "argus-results.oscal.json"
        assert path.exists()

    def test_emits_valid_json(self, tmp_path, summary_one_mapped_finding):
        path = OscalReporter().report(summary_one_mapped_finding, tmp_path)
        doc = json.loads(path.read_text())
        assert "assessment-results" in doc

    def test_creates_output_dir_if_missing(self, tmp_path, summary_one_mapped_finding):
        nested = tmp_path / "deep" / "nested" / "output"
        path = OscalReporter().report(summary_one_mapped_finding, nested)
        assert path.parent == nested
        assert path.exists()


class TestSchemaValidity:
    """Every output must validate against the vendored NIST OSCAL schema."""

    def test_mapped_finding_validates(
        self, tmp_path, summary_one_mapped_finding, oscal_validator
    ):
        path = OscalReporter().report(summary_one_mapped_finding, tmp_path)
        _validate(oscal_validator, json.loads(path.read_text()))

    def test_unmapped_finding_validates(
        self, tmp_path, summary_unmapped_finding, oscal_validator
    ):
        path = OscalReporter().report(summary_unmapped_finding, tmp_path)
        _validate(oscal_validator, json.loads(path.read_text()))

    def test_multi_scanner_validates(
        self, tmp_path, summary_multi_scanner, oscal_validator
    ):
        path = OscalReporter().report(summary_multi_scanner, tmp_path)
        _validate(oscal_validator, json.loads(path.read_text()))

    def test_empty_scan_validates(self, tmp_path, oscal_validator):
        # A scan that ran but found nothing — still has to validate.
        empty = ScanSummary(results=[ScanResult(scanner="bandit", findings=[])])
        path = OscalReporter().report(empty, tmp_path)
        _validate(oscal_validator, json.loads(path.read_text()))


class TestContentMapping:
    """Verify the Finding → OSCAL finding translation is correct."""

    def test_multi_control_finding_expands(
        self, tmp_path, summary_one_mapped_finding
    ):
        # B105 maps to [ia-5, sc-28] — one Argus finding, two OSCAL findings.
        path = OscalReporter().report(summary_one_mapped_finding, tmp_path)
        doc = json.loads(path.read_text())
        findings = doc["assessment-results"]["results"][0]["findings"]
        assert len(findings) == 2
        target_ids = sorted(f["target"]["target-id"] for f in findings)
        assert target_ids == ["ia-5", "sc-28"]

    def test_finding_status_reflects_severity(self, tmp_path):
        # HIGH severity → not-satisfied / fail.
        # INFO severity → satisfied / pass.
        # Build one of each and check both at once.
        result = ScanResult(
            scanner="bandit",
            findings=[
                Finding(id="B105", severity=Severity.HIGH, title="x", scanner="bandit"),
                Finding(id="B101", severity=Severity.INFO, title="y", scanner="bandit"),
            ],
        )
        path = OscalReporter().report(ScanSummary(results=[result]), tmp_path)
        findings = json.loads(path.read_text())["assessment-results"]["results"][0]["findings"]
        states = {f["target"]["target-id"]: f["target"]["status"]["state"] for f in findings}
        # B105 → [ia-5, sc-28] (not-satisfied), B101 → [sa-15] (satisfied)
        assert states.get("ia-5") == "not-satisfied"
        assert states.get("sc-28") == "not-satisfied"
        assert states.get("sa-15") == "satisfied"

    def test_unmapped_finding_has_sentinel_target(
        self, tmp_path, summary_unmapped_finding
    ):
        path = OscalReporter().report(summary_unmapped_finding, tmp_path)
        finding = json.loads(path.read_text())["assessment-results"]["results"][0]["findings"][0]
        assert finding["target"]["target-id"] == "argus-unmapped"
        assert finding["target"]["status"]["state"] == "not-satisfied"
        prop_names = {p["name"] for p in finding["props"]}
        assert "argus-unmapped" in prop_names
        assert "argus-rule-id" in prop_names

    def test_props_preserve_finding_metadata(self, tmp_path):
        result = ScanResult(
            scanner="bandit",
            findings=[
                Finding(
                    id="B105",
                    severity=Severity.HIGH,
                    title="x",
                    location="a.py:1",
                    cwe="CWE-798",
                    cve="CVE-2024-1",
                    scanner="bandit",
                ),
            ],
        )
        path = OscalReporter().report(ScanSummary(results=[result]), tmp_path)
        finding = json.loads(path.read_text())["assessment-results"]["results"][0]["findings"][0]
        props = {p["name"]: p["value"] for p in finding["props"]}
        assert props["argus-scanner"] == "bandit"
        assert props["argus-rule-id"] == "B105"
        assert props["argus-location"] == "a.py:1"
        assert props["argus-cwe"] == "CWE-798"
        assert props["argus-cve"] == "CVE-2024-1"
        assert props["argus-severity"] == "high"
        assert props["argus-control-source"] == "rule"

    def test_one_result_per_scanner(self, tmp_path, summary_multi_scanner):
        path = OscalReporter().report(summary_multi_scanner, tmp_path)
        results = json.loads(path.read_text())["assessment-results"]["results"]
        scanner_names = [r["title"] for r in results]
        assert any("bandit" in t for t in scanner_names)
        assert any("opengrep" in t for t in scanner_names)


class TestDeterminism:
    """Same input must produce byte-identical output (modulo timestamps).

    The metadata.last-modified field is "now" by design — GRC tools order
    successive scans by it — but every other field must be content-derived.
    """

    def test_same_scan_yields_same_uuids(self, tmp_path, summary_multi_scanner):
        reporter = OscalReporter()
        out1 = tmp_path / "run1"
        out2 = tmp_path / "run2"
        p1 = reporter.report(summary_multi_scanner, out1)
        p2 = reporter.report(summary_multi_scanner, out2)
        d1 = json.loads(p1.read_text())["assessment-results"]
        d2 = json.loads(p2.read_text())["assessment-results"]

        assert d1["uuid"] == d2["uuid"]
        for r1, r2 in zip(d1["results"], d2["results"]):
            assert r1["uuid"] == r2["uuid"]
            for f1, f2 in zip(r1["findings"], r2["findings"]):
                assert f1["uuid"] == f2["uuid"]

    def test_different_findings_yield_different_ar_uuid(self, tmp_path):
        reporter = OscalReporter()
        a = ScanSummary(results=[ScanResult(
            scanner="bandit",
            findings=[Finding(id="B105", severity=Severity.HIGH, title="a", scanner="bandit")],
        )])
        b = ScanSummary(results=[ScanResult(
            scanner="bandit",
            findings=[Finding(id="B106", severity=Severity.HIGH, title="b", scanner="bandit")],
        )])
        pa = reporter.report(a, tmp_path / "a")
        pb = reporter.report(b, tmp_path / "b")
        ua = json.loads(pa.read_text())["assessment-results"]["uuid"]
        ub = json.loads(pb.read_text())["assessment-results"]["uuid"]
        assert ua != ub

    def test_uuid_is_uuid5_format(self, tmp_path, summary_one_mapped_finding):
        path = OscalReporter().report(summary_one_mapped_finding, tmp_path)
        ar = json.loads(path.read_text())["assessment-results"]
        # The schema's UUIDDatatype pattern allows v4/v5 — our reporter emits
        # v5 specifically. Verify by parsing.
        parsed = _uuid_mod.UUID(ar["uuid"])
        assert parsed.version == 5


class TestImportApOverride:
    """ARGUS_OSCAL_IMPORT_AP_HREF must override the default self-ref."""

    def test_default_is_self_reference(self, tmp_path, summary_one_mapped_finding, monkeypatch):
        monkeypatch.delenv("ARGUS_OSCAL_IMPORT_AP_HREF", raising=False)
        path = OscalReporter().report(summary_one_mapped_finding, tmp_path)
        ar = json.loads(path.read_text())["assessment-results"]
        assert ar["import-ap"]["href"] == f"#{ar['uuid']}"

    def test_env_override_used_when_set(
        self, tmp_path, summary_one_mapped_finding, monkeypatch, oscal_validator
    ):
        monkeypatch.setenv("ARGUS_OSCAL_IMPORT_AP_HREF", "https://grc.example/ap/123.json")
        path = OscalReporter().report(summary_one_mapped_finding, tmp_path)
        doc = json.loads(path.read_text())
        assert doc["assessment-results"]["import-ap"]["href"] == "https://grc.example/ap/123.json"
        # Override must keep the doc schema-valid.
        _validate(oscal_validator, doc)
