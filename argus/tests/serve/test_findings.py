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
