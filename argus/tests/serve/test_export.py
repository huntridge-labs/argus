"""Tests for the /export route on argus serve.

Exercises filter + sort pass-through, every supported format, the
download-vs-inline content disposition, and the clipboard-copy
affordances baked into the findings template.
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


def _payload():
    return {
        "severity_threshold": None,
        "results": [{
            "scanner": "grype",
            "findings": [
                {
                    "id": "CVE-A", "severity": "critical", "title": "log4j RCE",
                    "description": "jndi", "location": "log4j-core@2.14.1",
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
                        "sbom_source": "BVMS.spdx",
                    },
                },
            ],
            "raw_report": None, "sarif_report": None, "metadata": {},
            "critical_count": 1, "high_count": 0,
            "medium_count": 1, "low_count": 0, "total_count": 2,
        }],
    }


class TestExportRoute:
    def test_csv_export_default_is_inline(self, tmp_path):
        _write_results(tmp_path, _payload())
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/export?format=csv")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "text/csv; charset=utf-8"
        # No download header when inline — copy-to-clipboard fetches rely
        # on this so the browser doesn't prompt a save dialog.
        assert "content-disposition" not in resp.headers
        # Both CVEs present, header row first.
        assert "severity,id,cve,scanner" in resp.text
        assert "CVE-2021-44228" in resp.text
        assert "CVE-2023-45853" in resp.text

    def test_download_flag_sets_attachment_header(self, tmp_path):
        _write_results(tmp_path, _payload())
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/export?format=csv&download=1")
        assert resp.status_code == 200
        cd = resp.headers["content-disposition"]
        assert cd.startswith("attachment;")
        assert "argus-findings-" in cd
        assert ".csv" in cd

    def test_json_format(self, tmp_path):
        _write_results(tmp_path, _payload())
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/export?format=json")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/json; charset=utf-8"
        data = resp.json()
        assert isinstance(data, list)
        assert {d["cve"] for d in data} == {"CVE-2021-44228", "CVE-2023-45853"}

    def test_markdown_format(self, tmp_path):
        _write_results(tmp_path, _payload())
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/export?format=markdown")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "text/markdown; charset=utf-8"
        assert "| Sev | ID | Scanner" in resp.text
        assert "log4j-core@2.14.1" in resp.text

    def test_sarif_format(self, tmp_path):
        _write_results(tmp_path, _payload())
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/export?format=sarif")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/sarif+json; charset=utf-8"
        data = resp.json()
        assert data["version"] == "2.1.0"
        # One run per scanner; fixture has only grype.
        assert len(data["runs"]) == 1
        assert data["runs"][0]["tool"]["driver"]["name"] == "grype"

    def test_filters_carry_through_to_export(self, tmp_path):
        _write_results(tmp_path, _payload())
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/export?format=csv&min_severity=high")
        # Only the critical log4j finding meets "high and above".
        assert "CVE-2021-44228" in resp.text
        assert "CVE-2023-45853" not in resp.text

    def test_sort_carries_through_to_export(self, tmp_path):
        _write_results(tmp_path, _payload())
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        # location_desc should put zlib before log4j in alpha order.
        resp = client.get("/export?format=csv&sort=location_desc")
        body = resp.text
        zlib_idx = body.find("zlib@1.2.12")
        log4j_idx = body.find("log4j-core@2.14.1")
        assert zlib_idx != -1 and log4j_idx != -1
        assert zlib_idx < log4j_idx

    def test_unknown_format_returns_400(self, tmp_path):
        _write_results(tmp_path, _payload())
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/export?format=excel")
        assert resp.status_code == 400
        # Error body names the valid formats so the caller can fix it.
        assert "csv" in resp.text
        assert "sarif" in resp.text

    def test_missing_scan_returns_404_not_500(self, tmp_path):
        # Pointing at a dir without argus-results.json should not 500.
        empty = tmp_path / "empty"
        empty.mkdir()
        app = create_app(root=str(empty))
        client = TestClient(app)
        resp = client.get("/export?format=csv")
        assert resp.status_code == 404
        assert "No scan loaded" in resp.text

    def test_filename_encodes_filter_scope(self, tmp_path):
        _write_results(tmp_path, _payload())
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/export?format=csv&download=1&min_severity=high&scanner=grype")
        cd = resp.headers["content-disposition"]
        # Filename captures the active filters so two exports from
        # different cuts don't collide on disk.
        assert "sev-high" in cd
        assert "scanner-grype" in cd


class TestExportMenuUI:
    """The findings template must render the Export menu, carry the
    current filter state into every href, and load the copy JS."""

    def test_export_menu_renders_on_findings_page(self, tmp_path):
        _write_results(tmp_path, _payload())
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/findings")
        assert "export-menu" in resp.text
        # All four formats surfaced.
        for label in ("CSV", "JSON", "Markdown", "SARIF"):
            assert ">" + label + "<" in resp.text

    def test_export_hrefs_preserve_filters_and_sort(self, tmp_path):
        _write_results(tmp_path, _payload())
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/findings?min_severity=high&sort=id")
        # Download href carries the same filters + download=1.
        assert "format=csv&min_severity=high" in resp.text
        assert "sort=id" in resp.text
        assert "download=1" in resp.text
        # Copy button carries the same URL without download=1 so the
        # fetch returns inline content.
        assert "data-export-url=" in resp.text

    def test_copy_script_is_loaded(self, tmp_path):
        _write_results(tmp_path, _payload())
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/findings")
        assert "export-copy.js" in resp.text
