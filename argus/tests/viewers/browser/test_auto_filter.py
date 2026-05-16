"""Phase SE tests — partial response for the auto-filter JS.

The auto-filter JS never gets executed in these tests; we exercise
the server-side contract that it depends on: ``?partial=1`` returns
just the table fragment (no layout chrome), the row markup matches
the full page, and the same query-param filters apply.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient   # noqa: E402

from argus.viewers.browser.app import create_app   # noqa: E402


def _write_results(dir_path: Path) -> Path:
    """Three findings across two severities for filter-round-trip tests."""
    payload = {
        "severity_threshold": None,
        "results": [
            {
                "scanner": "grype",
                "findings": [
                    {"id": "CVE-A", "severity": "critical", "title": "log4j",
                     "description": "", "location": "log4j@2.14.1", "cwe": None,
                     "cve": "CVE-2021-44228", "scanner": "grype", "metadata": {}},
                    {"id": "CVE-B", "severity": "low", "title": "trivial",
                     "description": "", "location": "x@1.0", "cwe": None,
                     "cve": None, "scanner": "grype", "metadata": {}},
                    {"id": "CVE-C", "severity": "high", "title": "openssl",
                     "description": "", "location": "openssl@1.1.1", "cwe": None,
                     "cve": "CVE-2023-12345", "scanner": "grype", "metadata": {}},
                ],
                "raw_report": None, "sarif_report": None, "metadata": {},
                "critical_count": 1, "high_count": 1, "medium_count": 0,
                "low_count": 1, "total_count": 3,
            },
        ],
    }
    p = dir_path / "argus-results.json"
    p.write_text(json.dumps(payload))
    return p


class TestFindingsPartialEndpoint:
    def test_partial_returns_table_fragment_without_layout(self, tmp_path):
        _write_results(tmp_path)
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/findings?partial=1")
        assert resp.status_code == 200
        # Fragment: no <html>, no nav, no base layout chrome.
        assert "<html" not in resp.text.lower()
        assert "<nav" not in resp.text.lower()
        # But the table markup is present.
        assert "<table" in resp.text
        # All three findings render.
        for cve in ("CVE-2021-44228", "CVE-2023-12345"):
            assert cve in resp.text
        assert "CVE-B" in resp.text  # no-CVE finding uses raw id

    def test_partial_honors_same_filters_as_full_page(self, tmp_path):
        _write_results(tmp_path)
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        full = client.get("/findings?min_severity=high")
        partial = client.get("/findings?min_severity=high&partial=1")
        assert full.status_code == 200
        assert partial.status_code == 200
        # Same CVE set in both responses — filter applied identically.
        for cve in ("CVE-2021-44228", "CVE-2023-12345"):
            assert cve in full.text
            assert cve in partial.text
        assert "CVE-B" not in partial.text   # low severity filtered out
        assert "CVE-B" not in full.text

    def test_partial_empty_state_renders_no_matches_message(self, tmp_path):
        _write_results(tmp_path)
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/findings?q=zzz-nothing&partial=1")
        assert resp.status_code == 200
        assert "No findings match the current filter" in resp.text
        # Still no layout chrome — it's the empty-state inside the
        # same partial, not a full page.
        assert "<html" not in resp.text.lower()

    def test_full_page_includes_auto_filter_script_and_form_attr(self, tmp_path):
        _write_results(tmp_path)
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/findings")
        # Script tag and form opt-in attribute both present so the
        # JS can find its form and the swap target.
        assert "/static/auto-filter.js" in resp.text
        assert "data-auto-filter" in resp.text
        assert 'id="findings-target"' in resp.text

    def test_auto_filter_js_served_from_static(self, tmp_path):
        app = create_app(root=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/static/auto-filter.js")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith(
            ("application/javascript", "text/javascript")
        )
        # Contract with auto-filter.js: must target #findings-target
        # and pick up [data-auto-filter] forms. Breaking either
        # renames requires updating the script + templates together.
        assert "findings-target" in resp.text
        assert "data-auto-filter" in resp.text
