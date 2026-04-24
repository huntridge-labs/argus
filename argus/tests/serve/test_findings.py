"""Phase SC tests — findings table route.

Covers query-param-driven filter behavior, ViewState sharing with the
TUI, and the empty-filter / no-match edge cases.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient   # noqa: E402

from argus.serve.app import create_app   # noqa: E402


def _write_results(dir_path: Path, payload: dict) -> Path:
    p = dir_path / "argus-results.json"
    p.write_text(json.dumps(payload))
    return p


def _multi_finding_payload():
    """Two scanners, two products, mixed severities — enough to test every filter."""
    return {
        "severity_threshold": None,
        "results": [
            {
                "scanner": "grype",
                "findings": [
                    {
                        "id": "CVE-A", "severity": "critical", "title": "log4j RCE",
                        "description": "", "location": "log4j-core@2.14.1",
                        "cwe": None, "cve": "CVE-2021-44228", "scanner": "grype",
                        "metadata": {
                            "package": "log4j-core",
                            "installed_version": "2.14.1",
                            "fixed_version": "2.17.1",
                            "sbom_source": "BVMS.spdx",
                        },
                    },
                    {
                        "id": "CVE-B", "severity": "medium", "title": "zlib overflow",
                        "description": "", "location": "zlib@1.2.12",
                        "cwe": None, "cve": "CVE-2023-45853", "scanner": "grype",
                        "metadata": {
                            "package": "zlib",
                            "installed_version": "1.2.12",
                            "sbom_source": "VRM.spdx",
                        },
                    },
                ],
                "raw_report": None, "sarif_report": None, "metadata": {},
                "critical_count": 1, "high_count": 0, "medium_count": 1,
                "low_count": 0, "total_count": 2,
            },
            {
                "scanner": "trivy",
                "findings": [
                    {
                        "id": "CVE-C", "severity": "high", "title": "openssl issue",
                        "description": "", "location": "openssl@1.1.1",
                        "cwe": None, "cve": "CVE-2023-12345", "scanner": "trivy",
                        "metadata": {
                            "package": "openssl",
                            "installed_version": "1.1.1",
                            "sbom_source": "BVMS.spdx",
                        },
                    },
                ],
                "raw_report": None, "sarif_report": None, "metadata": {},
                "critical_count": 0, "high_count": 1, "medium_count": 0,
                "low_count": 0, "total_count": 1,
            },
        ],
    }


class TestFindingsRoute:
    def test_empty_state_when_no_scan(self, tmp_path):
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/findings")
        assert resp.status_code == 200
        assert "No scan loaded" in resp.text

    def test_renders_table_with_all_findings_by_default(self, tmp_path):
        _write_results(tmp_path, _multi_finding_payload())
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/findings")
        assert resp.status_code == 200
        # All three findings from the fixture are present.
        for cve in ("CVE-2021-44228", "CVE-2023-45853", "CVE-2023-12345"):
            assert cve in resp.text
        assert "Showing <strong>3</strong> of 3" in resp.text

    def test_severity_filter_trims_to_high_and_above(self, tmp_path):
        _write_results(tmp_path, _multi_finding_payload())
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/findings?min_severity=high")
        assert resp.status_code == 200
        assert "CVE-2021-44228" in resp.text   # critical
        assert "CVE-2023-12345" in resp.text   # high
        # medium-severity zlib finding should be filtered out
        assert "CVE-2023-45853" not in resp.text

    def test_product_filter_uses_sbom_source(self, tmp_path):
        _write_results(tmp_path, _multi_finding_payload())
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/findings?product=BVMS.spdx")
        assert resp.status_code == 200
        # BVMS has log4j (critical) and openssl (high)
        assert "CVE-2021-44228" in resp.text
        assert "CVE-2023-12345" in resp.text
        # VRM's zlib should not appear
        assert "CVE-2023-45853" not in resp.text

    def test_scanner_filter(self, tmp_path):
        _write_results(tmp_path, _multi_finding_payload())
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/findings?scanner=trivy")
        assert resp.status_code == 200
        assert "CVE-2023-12345" in resp.text   # trivy finding
        # grype-only findings excluded
        assert "CVE-2021-44228" not in resp.text
        assert "CVE-2023-45853" not in resp.text

    def test_query_filter_matches_cve(self, tmp_path):
        _write_results(tmp_path, _multi_finding_payload())
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/findings?q=log4j")
        assert resp.status_code == 200
        assert "CVE-2021-44228" in resp.text
        assert "CVE-2023-45853" not in resp.text

    def test_filters_combine_with_AND_semantics(self, tmp_path):
        _write_results(tmp_path, _multi_finding_payload())
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        # CRITICAL + BVMS product — only log4j should survive
        resp = client.get("/findings?min_severity=critical&product=BVMS.spdx")
        assert resp.status_code == 200
        assert "CVE-2021-44228" in resp.text
        assert "CVE-2023-12345" not in resp.text   # high, not critical

    def test_unknown_min_severity_falls_back_to_all(self, tmp_path):
        """URL-driven input must never crash the route — bogus values
        degrade to 'no filter' rather than a 500."""
        _write_results(tmp_path, _multi_finding_payload())
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/findings?min_severity=bogus")
        assert resp.status_code == 200
        # All three findings still present (filter was ignored)
        for cve in ("CVE-2021-44228", "CVE-2023-45853", "CVE-2023-12345"):
            assert cve in resp.text

    def test_no_match_shows_actionable_empty_state(self, tmp_path):
        _write_results(tmp_path, _multi_finding_payload())
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/findings?q=zzznothingthere")
        assert resp.status_code == 200
        assert "No findings match the current filter" in resp.text
        assert "Showing <strong>0</strong> of 3" in resp.text

    def test_findings_nav_link_on_dashboard(self, tmp_path):
        _write_results(tmp_path, _multi_finding_payload())
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/")
        # Nav now points at /findings instead of being disabled
        assert "/findings" in resp.text


class TestDashboardDrillDownLinks:
    """Every summary card / row on the dashboard should be a deep-link
    into the findings view pre-filtered to the matching cut, so the
    dashboard is the entry point rather than a dead end."""

    def test_severity_card_links_to_filtered_findings(self, tmp_path):
        _write_results(tmp_path, _multi_finding_payload())
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/")
        # Critical card links the user into /findings?min_severity=critical
        assert "/findings?min_severity=critical" in resp.text
        assert "/findings?min_severity=medium" in resp.text

    def test_total_findings_card_links_to_unfiltered_findings(self, tmp_path):
        _write_results(tmp_path, _multi_finding_payload())
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/")
        # The "Total findings" tile is still clickable — just goes to
        # the unfiltered list.
        assert 'class="card" href="/findings"' in resp.text or \
               'class="card" href="/findings?' in resp.text

    def test_per_scanner_row_links_to_scanner_filter(self, tmp_path):
        _write_results(tmp_path, _multi_finding_payload())
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/")
        # Fixture uses grype + trivy; both scanner rows should drill in.
        assert "/findings?scanner=grype" in resp.text
        assert "/findings?scanner=trivy" in resp.text

    def test_per_product_row_links_to_product_filter(self, tmp_path):
        _write_results(tmp_path, _multi_finding_payload())
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/")
        # urlencode on "BVMS.spdx" leaves it alone (no special chars),
        # but products with spaces would come through as %20 in the href.
        assert "/findings?product=BVMS.spdx" in resp.text

    def test_scan_param_preserved_through_drill_down(self, tmp_path):
        # When ?scan= is active, the drill-down anchors must carry it
        # through so the user stays inside the same scan context.
        run_a = tmp_path / "run-a"
        run_a.mkdir()
        _write_results(run_a, _multi_finding_payload())

        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get(f"/?scan={run_a}")
        # Every drill-down href picks up the scan query.
        assert "&scan=" in resp.text

    def test_no_product_single_bucket_hides_section(self, tmp_path):
        # When every finding lacks sbom_source metadata, the per-product
        # breakdown would show a single "(no product)" row that adds no
        # value over the total. Hide the section rather than render it.
        single_bucket = {
            "severity_threshold": None,
            "results": [{
                "scanner": "bandit",
                "findings": [{
                    "id": "B101", "severity": "low", "title": "x",
                    "description": "", "location": "app.py:1",
                    "cwe": None, "cve": None, "scanner": "bandit",
                    "metadata": {},  # no sbom_source
                }],
                "raw_report": None, "sarif_report": None, "metadata": {},
                "critical_count": 0, "high_count": 0,
                "medium_count": 0, "low_count": 1, "total_count": 1,
            }],
        }
        _write_results(tmp_path, single_bucket)
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/")
        assert resp.status_code == 200
        assert "Per product" not in resp.text


class TestFindingDetailDisclosure:
    """Each finding row has a native <details> disclosure for its full
    detail payload — the web UI's counterpart to the TUI's detail pane."""

    def test_row_renders_details_element(self, tmp_path):
        _write_results(tmp_path, _multi_finding_payload())
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/findings")
        # Native disclosure widget present.
        assert "<details" in resp.text
        assert "<summary>" in resp.text

    def test_detail_panel_includes_core_fields(self, tmp_path):
        _write_results(tmp_path, _multi_finding_payload())
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/findings")
        # finding_detail_rows() emits a stable key set — check a few
        # of them actually land in the rendered HTML so future template
        # drift gets caught.
        assert "Scanner" in resp.text
        assert "CVE" in resp.text
        assert "Package" in resp.text
        assert "Location" in resp.text
        # And the package@version formatting used by the shared helper
        # makes it through (double-checks we aren't re-formatting locally).
        assert "log4j-core @ 2.14.1" in resp.text

    def test_detail_description_renders_when_present(self, tmp_path):
        payload = {
            "severity_threshold": None,
            "results": [{
                "scanner": "bandit",
                "findings": [{
                    "id": "B101", "severity": "high", "title": "short title",
                    "description": "A longer multi-line description\nwith detail.",
                    "location": "app.py:10", "cwe": None, "cve": None,
                    "scanner": "bandit", "metadata": {},
                }],
                "raw_report": None, "sarif_report": None, "metadata": {},
                "critical_count": 0, "high_count": 1,
                "medium_count": 0, "low_count": 0, "total_count": 1,
            }],
        }
        _write_results(tmp_path, payload)
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/findings")
        assert "A longer multi-line description" in resp.text

    def test_partial_endpoint_also_renders_detail(self, tmp_path):
        # The ?partial=1 fragment (used by auto-filter.js) must carry
        # the same disclosure markup — drift between full-page and
        # partial paths is a recurring footgun.
        _write_results(tmp_path, _multi_finding_payload())
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/findings?partial=1")
        assert "<details" in resp.text
        assert "<summary>" in resp.text


class TestSortableHeaders:
    def test_default_sort_is_severity_desc(self, tmp_path):
        _write_results(tmp_path, _multi_finding_payload())
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/findings")
        # First finding row is the highest severity (critical log4j).
        body = resp.text
        crit_idx = body.find("CVE-2021-44228")
        high_idx = body.find("CVE-D" if "CVE-D" in body else "openssl")
        med_idx = body.find("zlib")
        assert crit_idx != -1
        assert crit_idx < med_idx, "critical should come before medium"

    def test_headers_render_sort_links(self, tmp_path):
        _write_results(tmp_path, _multi_finding_payload())
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/findings")
        # On the default render, the active Severity header exposes the
        # *flipped* link — clicking it toggles to ascending. And the
        # inactive columns each offer their ascending sort as the first
        # click, so all four column sort targets should appear.
        assert "sort=severity_asc" in resp.text
        assert "sort=id" in resp.text
        assert "sort=location" in resp.text
        assert "sort=scanner" in resp.text
        assert 'aria-sort="descending"' in resp.text

    def test_clicking_active_column_flips_direction(self, tmp_path):
        _write_results(tmp_path, _multi_finding_payload())
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        # Already sorted severity_desc: next click should offer severity_asc
        resp = client.get("/findings?sort=severity_desc")
        assert "sort=severity_asc" in resp.text
        # Same in the other direction.
        resp = client.get("/findings?sort=severity_asc")
        assert "sort=severity_desc" in resp.text

    def test_inactive_columns_offer_ascending_first(self, tmp_path):
        _write_results(tmp_path, _multi_finding_payload())
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/findings?sort=severity_desc")
        # ID / Location / Scanner aren't active — their first click
        # should give the user the ascending cut.
        assert "sort=id" in resp.text
        assert "sort=location" in resp.text
        assert "sort=scanner" in resp.text

    def test_sort_by_location_ascending(self, tmp_path):
        _write_results(tmp_path, _multi_finding_payload())
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/findings?sort=location")
        body = resp.text
        # Fixture has log4j-core@2.14.1, zlib@1.2.12, openssl@1.1.1.
        # Ascending alpha by location puts "log4j-core@..." first.
        log4j_idx = body.find("log4j-core@2.14.1")
        zlib_idx = body.find("zlib@1.2.12")
        assert log4j_idx != -1 and zlib_idx != -1
        assert log4j_idx < zlib_idx

    def test_sort_by_location_descending(self, tmp_path):
        _write_results(tmp_path, _multi_finding_payload())
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/findings?sort=location_desc")
        body = resp.text
        log4j_idx = body.find("log4j-core@2.14.1")
        zlib_idx = body.find("zlib@1.2.12")
        assert log4j_idx != -1 and zlib_idx != -1
        assert zlib_idx < log4j_idx, "descending puts z-words first"

    def test_sort_preserves_filters_in_href(self, tmp_path):
        _write_results(tmp_path, _multi_finding_payload())
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        # Active filter + sort — headers must carry both into the click.
        resp = client.get("/findings?min_severity=high&scanner=grype")
        # Every sort link for this page should include the active
        # filter params so clicking doesn't reset the filter.
        assert "min_severity=high" in resp.text
        assert "scanner=grype" in resp.text

    def test_invalid_sort_falls_back_to_default(self, tmp_path):
        _write_results(tmp_path, _multi_finding_payload())
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/findings?sort=nonsense")
        # 500-proof: unknown sort silently resets to severity_desc.
        assert resp.status_code == 200
        assert 'aria-sort="descending"' in resp.text


class TestProductFilterMatchesLabel:
    def test_no_product_label_filters_matching_findings(self, tmp_path):
        # Regression: ViewState.product used the raw sbom_source for
        # comparison while unique_products() bucketed None-sources under
        # "(no product)". Clicking into the "(no product)" picker option
        # used to return zero results even when that bucket was the only
        # one with findings. Bucketing + filtering must agree.
        payload = {
            "severity_threshold": None,
            "results": [{
                "scanner": "bandit",
                "findings": [{
                    "id": "B101", "severity": "low", "title": "hardcoded pwd",
                    "description": "", "location": "app.py:1",
                    "cwe": None, "cve": None, "scanner": "bandit",
                    "metadata": {},
                }],
                "raw_report": None, "sarif_report": None, "metadata": {},
                "critical_count": 0, "high_count": 0,
                "medium_count": 0, "low_count": 1, "total_count": 1,
            }],
        }
        _write_results(tmp_path, payload)
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/findings?product=%28no+product%29")
        assert resp.status_code == 200
        # The single finding should still be visible post-filter.
        assert "B101" in resp.text
