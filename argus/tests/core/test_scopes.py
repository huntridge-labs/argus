"""Tests for the finding scope taxonomy (report output by scope)."""

from argus.core.models import Finding, Severity
from argus.core.scopes import (
    SCOPE_LINT,
    SCOPE_SECURITY,
    SCOPE_SUPPLY_CHAIN,
    reset_scope_cache,
    scope_for_category,
    scope_for_finding,
)


def _f(scanner):
    return Finding(id="x", severity=Severity.HIGH, title="t", scanner=scanner)


class TestScopeForCategory:
    def test_linter_is_lint(self):
        assert scope_for_category("linter") == SCOPE_LINT

    def test_sca_container_supply_chain_are_supply_chain(self):
        for category in ("sca", "container", "supply-chain"):
            assert scope_for_category(category) == SCOPE_SUPPLY_CHAIN

    def test_sast_secrets_iac_dast_malware_are_security(self):
        for category in ("sast", "secrets", "iac", "dast", "malware", ""):
            assert scope_for_category(category) == SCOPE_SECURITY

    def test_lint_name_prefix_fallback(self):
        assert scope_for_category("", "lint-yaml") == SCOPE_LINT


class TestScopeForFinding:
    def setup_method(self):
        reset_scope_cache()

    def test_known_scanners_map_via_registry(self):
        assert scope_for_finding(_f("bandit")) == SCOPE_SECURITY
        assert scope_for_finding(_f("osv")) == SCOPE_SUPPLY_CHAIN
        assert scope_for_finding(_f("lint-yaml")) == SCOPE_LINT
        assert scope_for_finding(_f("mumps")) == SCOPE_SECURITY

    def test_unknown_scanner_defaults_to_security(self):
        assert scope_for_finding(_f("totally-unknown")) == SCOPE_SECURITY
