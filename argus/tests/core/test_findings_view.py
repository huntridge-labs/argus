"""Unit tests for argus.core.findings_view — shared renderer logic.

These tests run without Textual installed; the module is pure. They
assert the contract that both the TUI and any future web view depend
on: ViewState filter/sort semantics, detail-row shape, aggregate
summary payload.
"""

from __future__ import annotations

import pytest

from argus.core.findings_view import (
    SEVERITY_GLYPH,
    SEVERITY_ORDER,
    SORT_LABELS,
    ViewState,
    compute_summary,
    finding_detail_rows,
    severity_counts,
    unique_products,
    unique_scanners,
)
from argus.core.models import Finding, Severity


def _f(
    fid="X", sev=Severity.HIGH, title="t", location=None, cve=None,
    scanner="", sbom=None, pkg=None, installed=None, fixed=None,
):
    meta = {}
    if sbom is not None:
        meta["sbom_source"] = sbom
    if pkg is not None:
        meta["package"] = pkg
    if installed is not None:
        meta["installed_version"] = installed
    if fixed is not None:
        meta["fixed_version"] = fixed
    return Finding(
        id=fid, severity=sev, title=title,
        location=location, cve=cve, scanner=scanner, metadata=meta,
    )


class TestSeverityConstants:
    def test_order_is_descending_by_severity(self):
        # Index 0 must be the most severe — our sort_key_fn relies on it.
        assert SEVERITY_ORDER[0] == Severity.CRITICAL
        assert SEVERITY_ORDER[-1] == Severity.UNKNOWN

    def test_every_severity_has_a_glyph(self):
        for sev in SEVERITY_ORDER:
            assert sev in SEVERITY_GLYPH, f"{sev} missing glyph"


class TestViewStateFilters:
    def test_product_filter_matches_sbom_source(self):
        vs = ViewState(product="BVMS")
        assert vs.matches(_f(sbom="BVMS"))
        assert not vs.matches(_f(sbom="Transcoder"))

    def test_product_filter_excludes_missing_source_when_specific_product_selected(self):
        vs = ViewState(product="BVMS")
        assert not vs.matches(_f(sbom=None))

    def test_scanner_filter(self):
        vs = ViewState(scanner="grype")
        assert vs.matches(_f(scanner="grype"))
        assert not vs.matches(_f(scanner="trivy"))

    def test_filters_combine_with_AND_semantics(self):
        vs = ViewState(min_severity=Severity.HIGH, product="BVMS", scanner="grype")
        assert vs.matches(_f(sev=Severity.CRITICAL, sbom="BVMS", scanner="grype"))
        # Same severity + product, wrong scanner — fails
        assert not vs.matches(_f(sev=Severity.CRITICAL, sbom="BVMS", scanner="trivy"))
        # Same scanner + product, too-low severity — fails
        assert not vs.matches(_f(sev=Severity.LOW, sbom="BVMS", scanner="grype"))


class TestFindingDetailRows:
    def test_returns_stable_label_value_pairs(self):
        f = _f(
            fid="CVE-2021-44228", cve="CVE-2021-44228", scanner="grype",
            location="log4j-core@2.14.1",
            pkg="log4j-core", installed="2.14.1", fixed="2.17.1",
            sbom="BVMS.spdx",
        )
        rows = finding_detail_rows(f)
        labels = [label for label, _ in rows]
        # Order matters — the TUI renders rows in this sequence and a
        # future web view must match so users get the same hierarchy.
        assert labels == ["Scanner", "CVE", "CWE", "Package", "Fix", "Location", "SBOM"]

    def test_missing_fields_become_em_dashes(self):
        f = _f()  # minimal finding
        rows = dict(finding_detail_rows(f))
        assert rows["CVE"] == "—"
        assert rows["Fix"] == "—"
        assert rows["SBOM"] == "—"

    def test_package_row_joins_name_and_version(self):
        rows = dict(finding_detail_rows(_f(pkg="lodash", installed="4.17.20")))
        assert rows["Package"] == "lodash @ 4.17.20"


class TestSortLabelsCoverage:
    def test_every_cycle_key_has_a_label(self):
        # Whatever keys the app cycles through must have entries here.
        cycle = ["severity_desc", "severity_asc", "package", "id"]
        for k in cycle:
            assert k in SORT_LABELS
            assert SORT_LABELS[k]


class TestUniqueProducts:
    def test_distinct_sbom_sources(self):
        assert unique_products([
            _f(sbom="A"), _f(sbom="B"), _f(sbom="A"),
        ]) == ["A", "B"]

    def test_missing_sbom_source_becomes_placeholder(self):
        out = unique_products([_f(sbom="A"), _f(sbom=None)])
        assert "(no product)" in out
        assert "A" in out


class TestUniqueScanners:
    def test_empty_scanner_becomes_placeholder(self):
        out = unique_scanners([_f(scanner="grype"), _f(scanner="")])
        assert "(unknown)" in out
        assert "grype" in out


class TestSeverityCounts:
    def test_all_buckets_present_even_when_empty(self):
        counts = severity_counts([_f(sev=Severity.HIGH)])
        # Zero-filled buckets keep the dashboard renderer simple.
        for s in SEVERITY_ORDER:
            assert s in counts
        assert counts[Severity.HIGH] == 1
        assert counts[Severity.CRITICAL] == 0


class TestComputeSummary:
    def test_per_product_breakdown(self):
        findings = [
            _f(fid="1", sev=Severity.CRITICAL, sbom="A"),
            _f(fid="2", sev=Severity.HIGH,     sbom="A"),
            _f(fid="3", sev=Severity.MEDIUM,   sbom="B"),
        ]
        summary = compute_summary(findings)
        assert summary["total"] == 3
        per_product = {p["product"]: p for p in summary["per_product"]}
        assert per_product["A"]["total"] == 2
        assert per_product["B"]["total"] == 1
        assert per_product["A"]["by_severity"]["critical"] == 1

    def test_top_n_per_product_is_severity_sorted(self):
        findings = [
            _f(fid="A1", sev=Severity.LOW,      sbom="X"),
            _f(fid="A2", sev=Severity.CRITICAL, sbom="X"),
            _f(fid="A3", sev=Severity.HIGH,     sbom="X"),
        ]
        summary = compute_summary(findings, top_n=2)
        top_ids = [t["id"] for t in summary["per_product"][0]["top"]]
        # Critical then high — low falls off the top-2 cut.
        assert top_ids == ["A2", "A3"]

    def test_per_scanner_contribution(self):
        findings = [
            _f(fid="1", scanner="grype"),
            _f(fid="2", scanner="grype"),
            _f(fid="3", scanner="trivy"),
        ]
        summary = compute_summary(findings)
        per_scanner = {s["scanner"]: s["total"] for s in summary["per_scanner"]}
        assert per_scanner == {"grype": 2, "trivy": 1}

    def test_dedups_quality_warnings(self):
        # Grype emits the same warning for multiple SBOMs in a batch;
        # the dashboard shouldn't repeat it N times.
        f1 = _f(fid="1")
        f1.metadata["warning"] = "source.target=unknown — 0 findings is not trustworthy"
        f2 = _f(fid="2")
        f2.metadata["warning"] = "source.target=unknown — 0 findings is not trustworthy"
        summary = compute_summary([f1, f2])
        assert len(summary["quality_warnings"]) == 1

    def test_empty_findings(self):
        summary = compute_summary([])
        assert summary["total"] == 0
        assert summary["per_product"] == []
        assert summary["per_scanner"] == []
        assert summary["quality_warnings"] == []

    def test_summary_is_json_serializable(self):
        import json
        findings = [_f(fid="CVE-1", sev=Severity.CRITICAL, sbom="A", scanner="grype")]
        # The dashboard / web view will dump this to JSON; catching
        # non-serializable types here is cheaper than at render time.
        json.dumps(compute_summary(findings))
