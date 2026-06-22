"""Phase B2 — opt-in risk (EPSS/KEV) + reachability columns.

Network-free: the enrichment service is injected (a fake), so no real
EPSS/KEV fetch happens. Verifies the column is off by default (preserving
the read-only / no-egress posture) and renders when opted in.
"""

from __future__ import annotations

import json

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient   # noqa: E402

from argus.core.enrichment import Enrichment   # noqa: E402
from argus.viewers.browser.app import create_app   # noqa: E402


def _sca_payload():
    return {
        "severity_threshold": None,
        "results": [{
            "scanner": "osv",
            "findings": [{
                "id": "CVE-2021-44228", "severity": "high", "title": "Log4Shell",
                "description": "RCE via JNDI", "location": "pom.xml", "cwe": None,
                "cve": "CVE-2021-44228", "scanner": "osv",
                "metadata": {"package": "log4j-core", "installed_version": "2.14.1",
                             "fixed_version": "2.17.1", "purl": "pkg:maven/log4j-core@2.14.1"},
            }],
            "raw_report": None, "sarif_report": None, "metadata": {},
            "critical_count": 0, "high_count": 1, "medium_count": 0,
            "low_count": 0, "total_count": 1,
        }],
    }


class _FakeService:
    offline = False

    def enrich(self, cves):
        return {
            "CVE-2021-44228": Enrichment(
                "CVE-2021-44228", epss=0.97, percentile=0.99, kev=True, source="epss+kev",
            ),
        } if "CVE-2021-44228" in cves else {}


def _app(tmp_path, **kw):
    (tmp_path / "argus-results.json").write_text(json.dumps(_sca_payload()))
    return create_app(root=str(tmp_path), **kw)


class TestRiskColumnsOptIn:
    def test_off_by_default(self, tmp_path):
        # Read-only / no-egress posture: no Risk column unless opted in.
        resp = TestClient(_app(tmp_path)).get("/findings")
        assert resp.status_code == 200
        assert "<th>Risk</th>" not in resp.text

    def test_enabled_renders_risk_column(self, tmp_path):
        resp = TestClient(
            _app(tmp_path, enrich=True, enrichment_service=_FakeService())
        ).get("/findings")
        assert resp.status_code == 200
        assert "<th>Risk</th>" in resp.text
        assert "🔥KEV" in resp.text and "EPSS 97%" in resp.text
        assert "risk-score" in resp.text

    def test_env_var_opts_in(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ARGUS_VIEW_ENRICH", "1")
        app = _app(tmp_path, enrichment_service=_FakeService())  # enrich=None → env
        assert app.state.enrich is True
        assert "<th>Risk</th>" in TestClient(app).get("/findings").text

    def test_offline_service_degrades_quietly(self, tmp_path):
        class Offline:
            offline = True
            def enrich(self, cves):
                return {}
        resp = TestClient(
            _app(tmp_path, enrich=True, enrichment_service=Offline())
        ).get("/findings")
        # Column header still present (opted in), but no badge — graceful.
        assert resp.status_code == 200
        assert "<th>Risk</th>" in resp.text
        assert "🔥KEV" not in resp.text
