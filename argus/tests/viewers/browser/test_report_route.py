"""Phase B4 — /report (HTML preview) + /report.pdf (server-side PDF) routes.

The HTML route is always available and exercised directly. The PDF route is
tested two ways without needing WeasyPrint installed: the guarded-degradation
path (friendly install hint) and the success path (a fake renderer injected so
we assert the response wiring — content-type, disposition, filename — without
the native dependency).
"""

from __future__ import annotations

import json

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient   # noqa: E402

from argus.viewers.browser.app import create_app   # noqa: E402


def _payload():
    return {
        "severity_threshold": "high",
        "scan_context": {"cwd": "/w", "repo_root": "/w", "commit_sha": "abc123def456789"},
        "results": [{
            "scanner": "osv",
            "findings": [
                {"id": "CVE-2021-44228", "severity": "critical", "title": "Log4Shell",
                 "cve": "CVE-2021-44228", "scanner": "osv",
                 "metadata": {"package": "log4j-core", "installed_version": "2.14.1",
                              "sbom_source": "app.spdx"}},
                {"id": "B105", "severity": "low", "title": "hardcoded password string",
                 "scanner": "bandit", "metadata": {}},
            ],
            "raw_report": None, "sarif_report": None, "metadata": {},
            "critical_count": 1, "high_count": 0, "medium_count": 0,
            "low_count": 1, "total_count": 2,
        }],
    }


def _app(tmp_path):
    (tmp_path / "argus-results.json").write_text(json.dumps(_payload()))
    return create_app(root=str(tmp_path))


class TestReportHtml:
    def test_renders_provenance_and_findings(self, tmp_path):
        resp = TestClient(_app(tmp_path)).get("/report")
        assert resp.status_code == 200
        body = resp.text
        # Provenance block: commit + Argus version + attestation status.
        assert "Provenance" in body
        assert "abc123def456" in body          # commit short (12)
        assert "Detailed findings" in body
        assert "Log4Shell" in body
        # Verdict reflects the high threshold + a critical finding → FAIL.
        assert "FAIL" in body

    def test_links_external_stylesheet_under_csp(self, tmp_path):
        # /report preview must not inline styles (strict CSP) — it links the
        # static stylesheet instead.
        resp = TestClient(_app(tmp_path)).get("/report")
        assert "/static/report.css" in resp.text
        assert resp.headers["content-security-policy"]

    def test_no_scan_renders_placeholder(self, tmp_path):
        # Empty dir → graceful "no scan" instead of a 500.
        empty = tmp_path / "empty"
        empty.mkdir()
        resp = TestClient(create_app(root=str(empty))).get("/report")
        assert resp.status_code == 200
        assert "No scan loaded" in resp.text


class TestReportPdf:
    def test_degrades_without_weasyprint(self, tmp_path, monkeypatch):
        # Force the "extra not installed" path regardless of local env.
        from argus.viewers import ViewerUnavailable
        from argus.viewers.browser import report_pdf

        def _boom(*a, **k):
            raise ViewerUnavailable("install argus-security[report]")

        monkeypatch.setattr(report_pdf, "render_pdf", _boom)
        resp = TestClient(_app(tmp_path)).get("/report.pdf")
        assert resp.status_code == 200
        assert "argus-security[report]" in resp.text

    def test_success_path_serves_pdf(self, tmp_path, monkeypatch):
        from argus.viewers.browser import report_pdf

        monkeypatch.setattr(
            report_pdf, "render_pdf", lambda html, **k: b"%PDF-1.7 fake bytes",
        )
        resp = TestClient(_app(tmp_path)).get("/report.pdf")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/pdf"
        assert resp.content.startswith(b"%PDF")
        # Filename uses the commit short for a stable, traceable artifact name.
        assert "argus-security-report-abc123def456.pdf" in resp.headers["content-disposition"]

    def test_pdf_404_when_no_scan(self, tmp_path):
        empty = tmp_path / "empty"
        empty.mkdir()
        resp = TestClient(create_app(root=str(empty))).get("/report.pdf")
        assert resp.status_code == 404
