"""Phase B0 (IA) — the persistent sticky scan-context bar under the header.

Verifies the bar surfaces the active scan's identity (project · commit · time ·
finding count) on the primary views and is omitted where there's no single
scan in scope (the picker).
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
        "scan_context": {"cwd": "/build/payments-platform",
                         "repo_root": "/build/payments-platform",
                         "commit_sha": "9f4c1ab7e2d05c8831a6b4e0f7c2d9a3b5e81746"},
        "results": [{
            "scanner": "osv",
            "findings": [
                {"id": "CVE-2021-44228", "severity": "critical", "title": "Log4Shell",
                 "cve": "CVE-2021-44228", "scanner": "osv", "metadata": {}},
                {"id": "B105", "severity": "low", "title": "hardcoded password",
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


class TestContextBar:
    def test_dashboard_shows_bar_identity(self, tmp_path):
        body = TestClient(_app(tmp_path)).get("/").text
        assert 'class="scan-context-bar"' in body
        assert "payments-platform" in body          # project from repo_root basename
        assert "9f4c1ab" in body                     # commit short (7)
        assert "2 findings" in body                  # finding count

    def test_findings_shows_bar(self, tmp_path):
        body = TestClient(_app(tmp_path)).get("/findings").text
        assert 'class="scan-context-bar"' in body
        assert "payments-platform" in body

    def test_time_element_is_humanizable(self, tmp_path):
        # The bar's time carries the scan-mtime hook + a raw epoch so
        # scan-mtime.js can upgrade it (and no-JS still shows something).
        body = TestClient(_app(tmp_path)).get("/").text
        assert "scan-mtime scb-time" in body
        assert "data-epoch=" in body

    def test_singular_finding_grammar(self, tmp_path):
        payload = _payload()
        payload["results"][0]["findings"] = payload["results"][0]["findings"][:1]
        payload["results"][0]["total_count"] = 1
        payload["results"][0]["low_count"] = 0
        (tmp_path / "argus-results.json").write_text(json.dumps(payload))
        body = TestClient(create_app(root=str(tmp_path))).get("/").text
        assert "1 finding" in body
        assert "1 findings" not in body

    def test_picker_has_no_bar(self, tmp_path):
        # No single scan in scope on the picker → bar omitted.
        body = TestClient(_app(tmp_path)).get("/picker").text
        assert 'class="scan-context-bar"' not in body

    def test_project_falls_back_without_git_context(self, tmp_path):
        payload = _payload()
        del payload["scan_context"]
        (tmp_path / "argus-results.json").write_text(json.dumps(payload))
        body = TestClient(create_app(root=str(tmp_path))).get("/").text
        # No commit when there's no scan_context, but the bar still renders
        # with the finding count and a directory-derived project label.
        assert 'class="scan-context-bar"' in body
        assert "2 findings" in body
