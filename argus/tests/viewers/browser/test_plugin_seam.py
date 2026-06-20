"""Browser viewer plugin seam — the open-core extension point.

Lets installed packages (e.g. Argus Enterprise's server-side PDF report)
register extra routes via the ``argus.viewers.browser_plugins`` entry-point
group, without the OSS core depending on them. Tests inject plugins directly
(``browser_plugins=``) to avoid needing a real installed package.
"""

from __future__ import annotations

import json

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient   # noqa: E402

from argus.viewers.browser.app import create_app   # noqa: E402


def _sca_payload():
    return {
        "results": [{
            "scanner": "osv",
            "findings": [{
                "id": "CVE-2021-44228", "severity": "high", "title": "Log4Shell",
                "cve": "CVE-2021-44228", "scanner": "osv", "metadata": {},
            }],
            "raw_report": None, "sarif_report": None, "metadata": {},
            "critical_count": 0, "high_count": 1, "medium_count": 0,
            "low_count": 0, "total_count": 1,
        }],
    }


class TestPluginSeam:
    def test_no_plugins_by_default_but_helpers_exposed(self, tmp_path):
        # OSS ships no plugins; the app still builds and exposes the helper
        # surface that plugins (e.g. an add-on report) build on.
        app = create_app(root=str(tmp_path))
        assert callable(app.state.load_scan)

    def test_injected_plugin_registers_a_route(self, tmp_path):
        def register(app):
            @app.get("/__plugin_probe")
            def probe():
                return {"ok": True, "root": str(app.state.root)}

        app = create_app(root=str(tmp_path), browser_plugins=[register])
        resp = TestClient(app).get("/__plugin_probe")
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

    def test_broken_plugin_is_skipped_and_others_still_load(self, tmp_path):
        def bad(app):
            raise RuntimeError("boom")

        def good(app):
            @app.get("/__ok")
            def ok():
                return {"ok": True}

        # A raising plugin must not crash app creation, and later plugins still
        # register — one bad plugin can't take down the viewer.
        app = create_app(root=str(tmp_path), browser_plugins=[bad, good])
        assert TestClient(app).get("/__ok").status_code == 200

    def test_plugin_can_build_from_exposed_helpers(self, tmp_path):
        # Proves an add-on's pattern works end-to-end: resolve the active scan
        # via app.state.load_scan, then build its own artifact (e.g. a report)
        # from the ScanSummary using public core helpers — no OSS report needed.
        (tmp_path / "argus-results.json").write_text(json.dumps(_sca_payload()))

        def register(app):
            @app.get("/__finding_count")
            def finding_count(scan: str | None = None):
                from argus.viewers.terminal.loader import flatten_findings

                summary, resolved, error = app.state.load_scan(scan)
                if summary is None:
                    return {"count": 0, "error": error}
                return {"count": len(flatten_findings(summary))}

        app = create_app(root=str(tmp_path), browser_plugins=[register])
        resp = TestClient(app).get("/__finding_count")
        assert resp.status_code == 200
        assert resp.json()["count"] == 1


class TestReportUpsell:
    """With no report add-on, the enterprise report paths return a friendly
    402 upsell (not a bare 404); an installed plugin's route is never shadowed."""

    def test_report_paths_upsell_when_absent(self, tmp_path):
        c = TestClient(create_app(root=str(tmp_path), browser_plugins=[]))
        r = c.get("/report")
        assert r.status_code == 402
        assert "Argus Enterprise" in r.text and "huntridgelabs.com" in r.text
        assert r.headers["content-type"].startswith("text/html")
        p = c.get("/report.pdf")
        assert p.status_code == 402
        assert "huntridgelabs.com" in p.text
        assert p.headers["content-type"].startswith("text/plain")

    def test_dashboard_still_free(self, tmp_path):
        # The upsell is scoped to report paths; the free views are unaffected.
        assert TestClient(create_app(root=str(tmp_path), browser_plugins=[])).get("/").status_code == 200

    def test_installed_plugin_route_not_shadowed_by_upsell(self, tmp_path):
        def register(app):
            from fastapi import Response

            @app.get("/report")
            def real_report():
                return Response("REAL REPORT", media_type="text/plain")

        c = TestClient(create_app(root=str(tmp_path), browser_plugins=[register]))
        r = c.get("/report")
        assert r.status_code == 200 and "REAL REPORT" in r.text   # plugin wins
        # the path it did NOT claim still upsells
        assert c.get("/report.pdf").status_code == 402
