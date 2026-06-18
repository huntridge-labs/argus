"""Unit tests for argus.core.enrichment (Phase 6 — live vuln intelligence).

UI-free + network-free: the parse/score functions are pure, and the
service is driven with an injected HTTP getter + fake clock so caching,
TTL expiry, batching, and offline behaviour are all exercised without a
single real request.
"""

from __future__ import annotations

import json

import pytest

from argus.core.enrichment import (
    EPSS_API,
    KEV_FEED,
    Enrichment,
    EnrichmentService,
    enrichment_detail_rows,
    is_cve,
    parse_epss_response,
    parse_kev_response,
    risk_badge,
    risk_score,
)
from argus.core.models import Severity


class TestIsCve:
    @pytest.mark.parametrize("ident", ["CVE-2021-44228", "cve-2021-44228", "CVE-2023-1234567"])
    def test_accepts_cve_shapes(self, ident):
        assert is_cve(ident) is True

    @pytest.mark.parametrize("ident", ["", None, "GHSA-xxxx-yyyy-zzzz", "CVE-2021", "B001", "CVE-abc-123"])
    def test_rejects_non_cve(self, ident):
        assert is_cve(ident) is False


class TestParseEpss:
    def test_parses_rows(self):
        payload = {"data": [
            {"cve": "CVE-2021-44228", "epss": "0.97565", "percentile": "0.99977"},
            {"cve": "cve-2020-0001", "epss": "0.001", "percentile": "0.1"},
        ]}
        out = parse_epss_response(payload)
        assert out["CVE-2021-44228"] == (0.97565, 0.99977)
        assert out["CVE-2020-0001"] == (0.001, 0.1)

    def test_malformed_rows_skipped(self):
        payload = {"data": [{"cve": "CVE-1-1", "epss": "nope"}, "junk", {"no_cve": 1}]}
        out = parse_epss_response(payload)
        assert out["CVE-1-1"] == (None, None)
        assert len(out) == 1

    def test_non_dict_is_empty(self):
        assert parse_epss_response(None) == {}
        assert parse_epss_response([1, 2]) == {}


class TestParseKev:
    def test_extracts_cve_ids(self):
        payload = {"vulnerabilities": [
            {"cveID": "CVE-2021-44228", "vendorProject": "Apache"},
            {"cveID": "cve-2017-0144"},
        ]}
        assert parse_kev_response(payload) == {"CVE-2021-44228", "CVE-2017-0144"}

    def test_tolerates_bad_entries(self):
        assert parse_kev_response({"vulnerabilities": ["x", {"no_id": 1}]}) == set()

    def test_non_dict_is_empty(self):
        assert parse_kev_response(None) == set()


class TestRiskScore:
    def test_severity_only_uses_weight(self):
        assert risk_score(Severity.CRITICAL, None) == round(0.6 * 1.0, 4)
        assert risk_score(Severity.LOW, None) == round(0.6 * 0.2, 4)

    def test_epss_modulates_upward(self):
        low = risk_score(Severity.MEDIUM, Enrichment("CVE-1-1", epss=0.0))
        high = risk_score(Severity.MEDIUM, Enrichment("CVE-1-1", epss=0.9))
        assert high > low

    def test_kev_floors_at_0_9(self):
        # A LOW severity in KEV must outrank a plain CRITICAL.
        kev_low = risk_score(Severity.LOW, Enrichment("CVE-1-1", kev=True))
        assert kev_low >= 0.9
        assert kev_low > risk_score(Severity.CRITICAL, None)

    def test_clamped_to_one(self):
        assert risk_score(Severity.CRITICAL, Enrichment("CVE-1-1", epss=1.0, kev=True)) == 1.0

    def test_unknown_severity_low_floor(self):
        assert risk_score(Severity.UNKNOWN, None) == round(0.6 * 0.1, 4)


class TestRiskBadge:
    def test_kev_and_epss(self):
        badge = risk_badge(Enrichment("CVE-1-1", epss=0.73, kev=True))
        assert "🔥KEV" in badge and "EPSS 73%" in badge

    def test_epss_only(self):
        assert risk_badge(Enrichment("CVE-1-1", epss=0.05)) == "EPSS 5%"

    def test_empty_when_none(self):
        assert risk_badge(None) == ""
        assert risk_badge(Enrichment("CVE-1-1")) == ""


class TestEnrichmentDetailRows:
    def test_empty_when_unenriched(self):
        assert enrichment_detail_rows(Severity.HIGH, None) == []

    def test_includes_epss_kev_risk(self):
        rows = dict(enrichment_detail_rows(
            Severity.HIGH, Enrichment("CVE-1-1", epss=0.73, percentile=0.99, kev=True),
        ))
        assert "73.0%" in rows["EPSS"] and "percentile 99" in rows["EPSS"]
        assert "actively exploited" in rows["KEV"]
        assert rows["Risk"].endswith("/100")

    def test_not_in_kev_phrasing(self):
        rows = dict(enrichment_detail_rows(Severity.LOW, Enrichment("CVE-1-1", epss=0.01)))
        assert rows["KEV"] == "not in CISA KEV"


class _FakeHttp:
    """Records calls and serves canned EPSS / KEV payloads."""

    def __init__(self, epss=None, kev=None):
        self.calls: list[str] = []
        self._epss = epss or {}
        self._kev = kev or set()

    def __call__(self, url: str):
        self.calls.append(url)
        if url.startswith(KEV_FEED):
            return {"vulnerabilities": [{"cveID": c} for c in self._kev]}
        if url.startswith(EPSS_API):
            wanted = url.split("cve=", 1)[1].split("&", 1)[0]
            cves = wanted.replace("%2C", ",").split(",")
            return {"data": [
                {"cve": c, "epss": str(self._epss[c][0]), "percentile": str(self._epss[c][1])}
                for c in cves if c in self._epss
            ]}
        return None


class TestEnrichmentService:
    def test_enrich_merges_epss_and_kev(self, tmp_path):
        http = _FakeHttp(
            epss={"CVE-2021-44228": (0.97, 0.99)},
            kev={"CVE-2021-44228"},
        )
        svc = EnrichmentService(cache_dir=tmp_path, http_get=http, offline=False)
        out = svc.enrich(["CVE-2021-44228"])
        enr = out["CVE-2021-44228"]
        assert enr.epss == 0.97 and enr.percentile == 0.99 and enr.kev is True
        assert "epss" in enr.source and "kev" in enr.source

    def test_offline_returns_empty(self, tmp_path):
        http = _FakeHttp(epss={"CVE-1-1": (0.5, 0.5)})
        svc = EnrichmentService(cache_dir=tmp_path, http_get=http, offline=True)
        assert svc.enrich(["CVE-1-1"]) == {}
        assert http.calls == []  # never reached out

    def test_non_cve_ids_skipped(self, tmp_path):
        http = _FakeHttp()
        svc = EnrichmentService(cache_dir=tmp_path, http_get=http, offline=False)
        assert svc.enrich(["GHSA-aaaa-bbbb-cccc", "B001", ""]) == {}

    def test_caches_across_calls(self, tmp_path):
        http = _FakeHttp(epss={"CVE-1-1": (0.5, 0.5)}, kev=set())
        svc = EnrichmentService(cache_dir=tmp_path, http_get=http, offline=False)
        svc.enrich(["CVE-1-1"])
        first = len(http.calls)
        svc.enrich(["CVE-1-1"])  # second time: served from cache
        assert len(http.calls) == first  # no new requests

    def test_ttl_expiry_refetches(self, tmp_path):
        clock = {"t": 1000.0}
        http = _FakeHttp(epss={"CVE-1-1": (0.5, 0.5)})
        svc = EnrichmentService(
            cache_dir=tmp_path, http_get=http, offline=False,
            now=lambda: clock["t"], ttl_epss=100, ttl_kev=100,
        )
        svc.enrich(["CVE-1-1"])
        before = len(http.calls)
        clock["t"] += 1000  # well past TTL
        svc.enrich(["CVE-1-1"])
        assert len(http.calls) > before  # stale → refetched

    def test_http_failure_degrades(self, tmp_path):
        svc = EnrichmentService(
            cache_dir=tmp_path, http_get=lambda url: None, offline=False,
        )
        out = svc.enrich(["CVE-1-1"])
        # Still produces an entry (no signal), never raises.
        assert out["CVE-1-1"].epss is None and out["CVE-1-1"].kev is False

    def test_kev_cache_written_to_disk(self, tmp_path):
        http = _FakeHttp(kev={"CVE-9-9"})
        svc = EnrichmentService(cache_dir=tmp_path, http_get=http, offline=False)
        svc.enrich(["CVE-9-9"])
        cached = json.loads((tmp_path / "kev.json").read_text())
        assert any(v["cveID"] == "CVE-9-9" for v in cached["vulnerabilities"])
