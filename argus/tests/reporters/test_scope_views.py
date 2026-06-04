"""Tests for per-scope report views (output organized by scope)."""

import json

from argus.core.models import Finding, ScanResult, ScanSummary, Severity
from argus.core.scopes import reset_scope_cache
from argus.reporters.scope_views import write_scope_views


def _f(scanner, cve=None, meta=None):
    return Finding(
        id=cve or "x", severity=Severity.HIGH, title="t",
        scanner=scanner, cve=cve, metadata=meta or {},
    )


def _mixed_summary():
    return ScanSummary(results=[ScanResult(scanner="multi", findings=[
        _f("bandit"),
        _f("gitleaks"),
        _f("lint-yaml"),
        _f("osv", cve="CVE-1", meta={
            "package_name": "lodash", "package_version": "1.0.0", "ecosystem": "npm",
        }),
    ])])


class TestScopeViews:
    def setup_method(self):
        reset_scope_cache()

    def test_writes_filtered_scope_subdirs(self, tmp_path):
        write_scope_views(
            _mixed_summary(), tmp_path, formats=["json", "markdown", "sarif", "openvex"],
        )
        # security/: bandit + gitleaks, with a SARIF view.
        security = json.loads((tmp_path / "security" / "argus-results.json").read_text())
        ids = {f["id"] for r in security["results"] for f in r["findings"]}
        assert ids == {"x"}  # bandit + gitleaks (both id "x"); lint/osv excluded
        assert (tmp_path / "security" / "argus-summary.md").exists()
        assert (tmp_path / "security" / "argus-results.sarif").exists()
        # lint/: no SARIF (security-only).
        assert (tmp_path / "lint" / "argus-results.json").exists()
        assert not (tmp_path / "lint" / "argus-results.sarif").exists()
        # supply-chain/: the OpenVEX doc with the one CVE.
        vex = json.loads(
            (tmp_path / "supply-chain" / "argus-results.openvex.json").read_text(),
        )
        assert len(vex["statements"]) == 1
        assert vex["statements"][0]["vulnerability"]["name"] == "CVE-1"

    def test_sarif_and_openvex_gated_on_requested_formats(self, tmp_path):
        write_scope_views(_mixed_summary(), tmp_path, formats=["json"])
        assert (tmp_path / "security" / "argus-results.json").exists()
        assert not (tmp_path / "security" / "argus-results.sarif").exists()
        assert not (tmp_path / "supply-chain" / "argus-results.openvex.json").exists()

    def test_only_present_scopes_are_created(self, tmp_path):
        summary = ScanSummary(results=[ScanResult(scanner="b", findings=[_f("bandit")])])
        write_scope_views(summary, tmp_path, formats=["json"])
        assert (tmp_path / "security").is_dir()
        assert not (tmp_path / "lint").exists()
        assert not (tmp_path / "supply-chain").exists()
