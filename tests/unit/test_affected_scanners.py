"""Tests for scripts/ci/affected_scanners — the diff→scanner mapping that
scopes container smoke tests."""

from __future__ import annotations

from scripts.ci.affected_scanners import (
    CROSS_CUTTING,
    affected_scanners,
)


class TestAffectedScanners:
    def test_no_scanner_files_changed_returns_empty(self):
        assert affected_scanners(["README.md", "docs/scanners.md"]) == []

    def test_single_scanner_module_maps_to_its_name(self):
        # bandit lives in argus/scanners/bandit.py and registers "bandit".
        assert affected_scanners(["argus/scanners/bandit.py"]) == ["bandit"]

    def test_renamed_module_resolves_via_registry_module(self):
        # trivy_iac.py registers the hyphenated "trivy-iac" — the mapping
        # must go through cls.__module__, not a naive filename transform.
        assert affected_scanners(["argus/scanners/trivy_iac.py"]) == ["trivy-iac"]

    def test_supply_chain_underscore_to_hyphen(self):
        assert affected_scanners(["argus/scanners/supply_chain.py"]) == ["supply-chain"]

    def test_multiple_scanners(self):
        out = affected_scanners([
            "argus/scanners/bandit.py",
            "argus/scanners/gitleaks.py",
        ])
        assert out == ["bandit", "gitleaks"]

    def test_cross_cutting_change_returns_ALL(self):
        for f in CROSS_CUTTING:
            assert affected_scanners([f]) == "ALL", f

    def test_cross_cutting_wins_over_specific(self):
        # An engine change alongside a scanner change still means ALL.
        assert affected_scanners([
            "argus/scanners/bandit.py",
            "argus/core/engine.py",
        ]) == "ALL"

    def test_unrelated_argus_file_is_not_a_scanner(self):
        # A change to a non-scanner argus module maps to nothing (and is
        # not cross-cutting).
        assert affected_scanners(["argus/reporters/terminal.py"]) == []
