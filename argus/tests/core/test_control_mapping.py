"""Tests for argus.core.control_mapping — finding → 800-53 control resolution."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from argus.core import control_mapping as cm
from argus.core.models import Finding, Severity


@pytest.fixture(autouse=True)
def _reset_caches():
    """Drop cached YAML between tests so monkeypatched mapping roots take effect."""
    cm._reset_cache_for_tests()
    yield
    cm._reset_cache_for_tests()


@pytest.fixture
def tmp_mappings(tmp_path, monkeypatch):
    """Point control_mapping at an empty tmp mappings dir for the test."""
    mappings = tmp_path / "mappings"
    mappings.mkdir()
    monkeypatch.setattr(cm, "_MAPPING_ROOT", mappings)
    return mappings


def _f(**kw):
    """Build a Finding with sensible defaults so tests only state what differs."""
    kw.setdefault("id", "RULE-1")
    kw.setdefault("severity", Severity.HIGH)
    kw.setdefault("title", "test finding")
    kw.setdefault("scanner", "bandit")
    return Finding(**kw)


class TestPrecedence:
    """Verify the four-tier resolution order."""

    def test_metadata_wins_over_rule_mapping(self, tmp_mappings):
        (tmp_mappings / "bandit.yaml").write_text(textwrap.dedent("""
            B999: [si-10]
        """).strip())
        finding = _f(
            id="B999",
            metadata={"nist_controls": ["AC-3", "AU-2"]},
        )
        refs = cm.map_finding(finding)
        assert [r.control_id for r in refs] == ["ac-3", "au-2"]
        assert all(r.source == "metadata" for r in refs)

    def test_rule_level_match(self, tmp_mappings):
        (tmp_mappings / "bandit.yaml").write_text("B105: [ia-5, sc-28]")
        refs = cm.map_finding(_f(id="B105"))
        assert [r.control_id for r in refs] == ["ia-5", "sc-28"]
        assert all(r.source == "rule" for r in refs)

    def test_scanner_default_only_fires_when_rule_missing(self, tmp_mappings):
        (tmp_mappings / "bandit.yaml").write_text(textwrap.dedent("""
            B105: [ia-5]
            .default: [sa-15]
        """).strip())
        # Rule hit — default must not fire on top.
        rule_hit = cm.map_finding(_f(id="B105"))
        assert [r.control_id for r in rule_hit] == ["ia-5"]
        # Unknown rule — default fires.
        miss = cm.map_finding(_f(id="B999"))
        assert [r.control_id for r in miss] == ["sa-15"]
        assert miss[0].source == "scanner-default"

    def test_cwe_fallback(self, tmp_mappings):
        (tmp_mappings / "bandit.yaml").write_text("# empty\n")
        (tmp_mappings / "cwe-to-nist.yaml").write_text("CWE-78: [si-10, si-3]")
        refs = cm.map_finding(_f(id="UNKNOWN", cwe="CWE-78"))
        assert [r.control_id for r in refs] == ["si-10", "si-3"]
        assert all(r.source == "cwe" for r in refs)

    def test_cwe_fallback_does_not_fire_when_rule_matched(self, tmp_mappings):
        (tmp_mappings / "bandit.yaml").write_text("B1: [ac-3]")
        (tmp_mappings / "cwe-to-nist.yaml").write_text("CWE-78: [si-10]")
        refs = cm.map_finding(_f(id="B1", cwe="CWE-78"))
        assert [r.control_id for r in refs] == ["ac-3"]
        assert refs[0].source == "rule"

    def test_unmapped_returns_empty(self, tmp_mappings):
        refs = cm.map_finding(_f(id="NOPE", cwe=None, scanner="unknown"))
        assert refs == []


class TestNormalization:
    """Edge cases around id casing / CWE variants / list coercion."""

    def test_control_id_lowercased(self, tmp_mappings):
        (tmp_mappings / "bandit.yaml").write_text("R: [AC-3, Si-10]")
        refs = cm.map_finding(_f(id="R"))
        assert [r.control_id for r in refs] == ["ac-3", "si-10"]

    def test_cwe_normalization_variants(self, tmp_mappings):
        (tmp_mappings / "cwe-to-nist.yaml").write_text("CWE-78: [si-10]")
        for cwe in ("CWE-78", "cwe-78", "78"):
            refs = cm.map_finding(_f(id="X", scanner="missing", cwe=cwe))
            assert [r.control_id for r in refs] == ["si-10"], f"cwe={cwe!r}"

    def test_single_string_coerced_to_list(self, tmp_mappings):
        # Single-control entry written without YAML list syntax.
        (tmp_mappings / "bandit.yaml").write_text("R: ac-3")
        refs = cm.map_finding(_f(id="R"))
        assert [r.control_id for r in refs] == ["ac-3"]

    def test_duplicate_controls_collapse(self, tmp_mappings):
        (tmp_mappings / "bandit.yaml").write_text(textwrap.dedent("""
            R: [ac-3, AC-3, ac-3]
        """).strip())
        refs = cm.map_finding(_f(id="R"))
        assert [r.control_id for r in refs] == ["ac-3"]

    def test_metadata_short_circuits_lower_tiers(self, tmp_mappings):
        # Metadata supplies ac-3; rule mapping says ac-3 + au-2. Under
        # short-circuit semantics, tier 2 doesn't run — au-2 must NOT
        # appear. The scanner that authored the metadata override is
        # asserting it knows the complete control set.
        (tmp_mappings / "bandit.yaml").write_text("R: [ac-3, au-2]")
        refs = cm.map_finding(_f(id="R", metadata={"nist_controls": ["ac-3"]}))
        assert [r.control_id for r in refs] == ["ac-3"]
        assert refs[0].source == "metadata"


class TestMalformedData:
    """The loader must degrade gracefully — broken YAML can't kill scans."""

    def test_missing_scanner_file_returns_empty(self, tmp_mappings):
        # No bandit.yaml on disk at all.
        refs = cm.map_finding(_f(id="ANY"))
        assert refs == []

    def test_malformed_yaml_logged_not_raised(self, tmp_mappings, caplog):
        (tmp_mappings / "bandit.yaml").write_text("not: [valid: yaml")
        # Even with a parse error, lookup should return empty rather than raise.
        refs = cm.map_finding(_f(id="ANY"))
        assert refs == []
        assert any(
            "failed to parse" in rec.getMessage() for rec in caplog.records
        )

    def test_yaml_top_level_not_a_dict(self, tmp_mappings, caplog):
        (tmp_mappings / "bandit.yaml").write_text("- ac-3\n- si-10\n")  # list, not dict
        refs = cm.map_finding(_f(id="ANY"))
        assert refs == []
        assert any(
            "not a YAML mapping" in rec.getMessage() for rec in caplog.records
        )

    def test_non_string_entries_ignored(self, tmp_mappings):
        (tmp_mappings / "bandit.yaml").write_text(textwrap.dedent("""
            R: [ac-3, 42, null, si-10]
        """).strip())
        refs = cm.map_finding(_f(id="R"))
        # Only the strings survive.
        assert [r.control_id for r in refs] == ["ac-3", "si-10"]

    def test_empty_scanner_string_returns_empty(self, tmp_mappings):
        # Scanner is empty — don't try to load "/.yaml".
        refs = cm.map_finding(_f(id="R", scanner=""))
        assert refs == []


class TestShippedMappings:
    """Smoke tests against the real in-repo mapping files.

    These guard against typos / structural breakage that the synthetic
    fixture tests above wouldn't catch.
    """

    def test_bandit_b105_maps_to_ia5_and_sc28(self):
        # B105 / B106 / B107 (hardcoded password) → IA-5 + SC-28.
        refs = cm.map_finding(_f(id="B105", scanner="bandit"))
        ids = [r.control_id for r in refs]
        assert "ia-5" in ids
        assert "sc-28" in ids

    def test_bandit_unknown_rule_hits_default(self):
        refs = cm.map_finding(_f(id="B9999", scanner="bandit"))
        # Bandit ships a .default of sa-15.
        assert refs and refs[0].control_id == "sa-15"
        assert refs[0].source == "scanner-default"

    def test_cwe_78_fallback_works_from_real_file(self):
        # No scanner mapping for "opengrep" yet — CWE-78 falls through.
        refs = cm.map_finding(_f(id="UNKNOWN", scanner="opengrep", cwe="CWE-78"))
        assert refs and refs[0].source == "cwe"
        assert "si-10" in [r.control_id for r in refs]

    def test_mapping_root_returns_real_path(self):
        root = cm.mapping_root()
        assert isinstance(root, Path)
        assert (root / "bandit.yaml").is_file()
        assert (root / "cwe-to-nist.yaml").is_file()
