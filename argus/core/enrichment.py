"""Live vulnerability intelligence — EPSS + CISA KEV enrichment (Phase 6).

Turns a finding from "a CVE id + severity" into "*should I care, right
now?*" by layering two free, no-auth signals onto each CVE:

- **EPSS** (FIRST.org) — the exploit-probability score: how likely this CVE
  is to be exploited in the next 30 days.
- **CISA KEV** — whether the CVE is in the Known-Exploited-Vulnerabilities
  catalog, i.e. *actively* exploited in the wild.

These re-rank findings by real-world risk: a CRITICAL with a 0.02 EPSS and
no KEV entry is less urgent than a HIGH at 0.7 EPSS that's in KEV. No OSS
scanner surfaces this today.

Design (mirrors the rest of the core):
- **UI-free** — no Textual / FastAPI; pure data + stdlib HTTP.
- **Opt-in & offline-degrading** — callers choose when to fetch; with no
  network (or ``offline``), :meth:`EnrichmentService.enrich` returns ``{}``
  and findings render exactly as before, just without the badges.
- **Privacy-safe** — only public CVE ids leave the machine, never source or
  secrets. Results cache on disk with a TTL so repeat triage is offline.
- **Testable** — the parse / score functions are pure; the service takes an
  injectable HTTP getter and clock so the cache + fetch logic is unit-tested
  with no network.
"""

from __future__ import annotations

import json
import os
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

from argus.core.models import Severity

EPSS_API = "https://api.first.org/data/v1/epss"
KEV_FEED = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

_CVE_BATCH = 100          # EPSS API accepts a comma-separated batch
_DEFAULT_TIMEOUT = 6.0    # seconds — fail fast so triage never hangs
_TTL_EPSS = 6 * 3600      # EPSS refreshes daily; 6h cache is plenty
_TTL_KEV = 24 * 3600      # KEV catalog updates ~daily


@dataclass(frozen=True)
class Enrichment:
    """The intelligence layered onto one CVE. All fields optional/None-safe."""

    cve: str
    epss: float | None = None          # exploit probability, 0..1
    percentile: float | None = None    # EPSS percentile, 0..1
    kev: bool = False                  # in CISA Known-Exploited catalog
    source: str = ""                   # which signals contributed, e.g. "epss+kev"


# Severity → base risk weight in [0, 1]. Severity still dominates; EPSS
# modulates and KEV floors (see ``risk_score``).
SEVERITY_WEIGHT: dict[Severity, float] = {
    Severity.CRITICAL: 1.0,
    Severity.HIGH: 0.8,
    Severity.MEDIUM: 0.5,
    Severity.LOW: 0.2,
    Severity.INFO: 0.05,
    Severity.UNKNOWN: 0.1,
}


def risk_score(severity: Severity, enr: Enrichment | None) -> float:
    """Blend severity + EPSS + KEV into a single 0..1 priority score.

    Severity-weighted and EPSS-modulated; a KEV (actively-exploited) entry
    floors the score at 0.9 because "exploited in the wild" outranks a
    nominal severity label. Returns the plain severity weight when no
    enrichment is available, so unenriched findings still sort sensibly.
    """
    base = SEVERITY_WEIGHT.get(severity, 0.1)
    epss = enr.epss if (enr and enr.epss is not None) else 0.0
    combined = 0.6 * base + 0.4 * epss
    if enr and enr.kev:
        combined = max(combined, 0.9)
    return round(min(1.0, combined), 4)


def risk_badge(enr: Enrichment | None) -> str:
    """Short display badge, e.g. ``"🔥KEV  EPSS 73%"``. Empty when unenriched."""
    if enr is None:
        return ""
    parts: list[str] = []
    if enr.kev:
        parts.append("🔥KEV")
    if enr.epss is not None:
        parts.append(f"EPSS {round(enr.epss * 100)}%")
    return "  ".join(parts)


def enrichment_detail_rows(
    severity: Severity, enr: Enrichment | None,
) -> list[tuple[str, str]]:
    """Detail-pane ``(label, value)`` rows for a finding's enrichment.

    Empty when unenriched, so callers can unconditionally append the result
    to ``finding_detail_rows``. Front-end-agnostic (plain strings), matching
    the shape ``finding_detail_rows`` returns.
    """
    if enr is None:
        return []
    rows: list[tuple[str, str]] = []
    if enr.epss is not None:
        pct = (
            f"  (percentile {round((enr.percentile or 0) * 100)})"
            if enr.percentile is not None else ""
        )
        rows.append(("EPSS", f"{round(enr.epss * 100, 1)}% exploit probability{pct}"))
    rows.append((
        "KEV",
        "⚠ actively exploited (CISA KEV)" if enr.kev else "not in CISA KEV",
    ))
    rows.append(("Risk", f"{round(risk_score(severity, enr) * 100)}/100"))
    return rows


def is_cve(identifier: str | None) -> bool:
    """True when ``identifier`` looks like a CVE id (the EPSS/KEV key)."""
    if not identifier:
        return False
    upper = identifier.upper()
    if not upper.startswith("CVE-"):
        return False
    parts = upper.split("-")
    return len(parts) == 3 and parts[1].isdigit() and parts[2].isdigit()


def parse_epss_response(payload: object) -> dict[str, tuple[float | None, float | None]]:
    """Parse the FIRST.org EPSS response into ``{CVE: (epss, percentile)}``.

    Tolerant of missing/malformed rows — a bad row is skipped, never raised.
    """
    out: dict[str, tuple[float | None, float | None]] = {}
    if not isinstance(payload, dict):
        return out
    for row in payload.get("data") or []:
        if not isinstance(row, dict):
            continue
        cve = str(row.get("cve", "")).upper()
        if not cve:
            continue
        out[cve] = (_as_float(row.get("epss")), _as_float(row.get("percentile")))
    return out


def parse_kev_response(payload: object) -> set[str]:
    """Parse the CISA KEV catalog into a set of uppercase CVE ids."""
    out: set[str] = set()
    if not isinstance(payload, dict):
        return out
    for vuln in payload.get("vulnerabilities") or []:
        if not isinstance(vuln, dict):
            continue
        cid = str(vuln.get("cveID", "")).upper()
        if cid:
            out.add(cid)
    return out


def _as_float(value: object) -> float | None:
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _default_http_get(url: str) -> object | None:
    """GET ``url`` and parse JSON; return ``None`` on any failure.

    Best-effort by contract: network errors, timeouts, and non-JSON bodies
    all degrade to ``None`` so enrichment never breaks triage.
    """
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "argus-enrichment"})
        with urllib.request.urlopen(request, timeout=_DEFAULT_TIMEOUT) as resp:  # noqa: S310
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None


HttpGet = Callable[[str], object | None]


def _network_disabled() -> bool:
    """Honour the common offline env vars so enrichment never reaches out."""
    return any(
        os.environ.get(var, "").strip().lower() in ("1", "true", "yes")
        for var in ("ARGUS_NO_NETWORK", "NO_NETWORK", "OFFLINE")
    )


class EnrichmentService:
    """Fetches + caches EPSS / KEV intelligence for a set of CVEs.

    HTTP and the clock are injectable so the cache + fetch logic is fully
    unit-testable offline.
    """

    def __init__(
        self,
        *,
        cache_dir: Path | None = None,
        http_get: HttpGet | None = None,
        now: Callable[[], float] = time.time,
        offline: bool | None = None,
        ttl_epss: int = _TTL_EPSS,
        ttl_kev: int = _TTL_KEV,
    ) -> None:
        self._cache_dir = cache_dir or _default_cache_dir()
        self._http_get = http_get or _default_http_get
        self._now = now
        self._offline = _network_disabled() if offline is None else offline
        self._ttl_epss = ttl_epss
        self._ttl_kev = ttl_kev

    @property
    def offline(self) -> bool:
        return self._offline

    def enrich(self, cve_ids: Iterable[str]) -> dict[str, Enrichment]:
        """Return ``{CVE: Enrichment}`` for the CVE-shaped ids given.

        Non-CVE ids (GHSA-only, scanner-internal) are skipped — EPSS/KEV are
        CVE-keyed. Returns ``{}`` when offline or given nothing to do.
        """
        cves = sorted({c.upper() for c in cve_ids if is_cve(c)})
        if not cves or self._offline:
            return {}
        kev = self._kev_set()
        epss = self._epss_map(cves)
        result: dict[str, Enrichment] = {}
        for cve in cves:
            score, pct = epss.get(cve, (None, None))
            in_kev = cve in kev
            contributed = "+".join(
                name for name, on in (("epss", score is not None), ("kev", in_kev)) if on
            )
            result[cve] = Enrichment(
                cve=cve, epss=score, percentile=pct, kev=in_kev,
                source=contributed or "none",
            )
        return result

    # -- KEV catalog (one cached file) --------------------------------------

    def _kev_set(self) -> set[str]:
        cached = self._read_cache("kev.json", self._ttl_kev)
        if cached is not None:
            return parse_kev_response(cached)
        payload = self._http_get(KEV_FEED)
        if payload is None:
            return set()
        self._write_cache("kev.json", payload)
        return parse_kev_response(payload)

    # -- EPSS scores (per-CVE map cache) ------------------------------------

    def _epss_map(self, cves: list[str]) -> dict[str, tuple[float | None, float | None]]:
        cache = self._read_epss_cache()
        fresh: dict[str, tuple[float | None, float | None]] = {}
        stale: list[str] = []
        for cve in cves:
            entry = cache.get(cve)
            if entry and (self._now() - entry.get("ts", 0)) < self._ttl_epss:
                fresh[cve] = (entry.get("epss"), entry.get("percentile"))
            else:
                stale.append(cve)
        for batch in _chunked(stale, _CVE_BATCH):
            fetched = self._fetch_epss(batch)
            now = self._now()
            for cve in batch:
                epss, pct = fetched.get(cve, (None, None))
                fresh[cve] = (epss, pct)
                cache[cve] = {"epss": epss, "percentile": pct, "ts": now}
        if stale:
            self._write_cache("epss.json", cache)
        return fresh

    def _fetch_epss(self, cves: list[str]) -> dict[str, tuple[float | None, float | None]]:
        query = urllib.parse.urlencode({"cve": ",".join(cves)})
        payload = self._http_get(f"{EPSS_API}?{query}")
        return parse_epss_response(payload) if payload is not None else {}

    def _read_epss_cache(self) -> dict[str, dict]:
        raw = self._read_cache("epss.json", ttl=None)  # per-entry TTL, not file TTL
        return raw if isinstance(raw, dict) else {}

    # -- cache primitives ---------------------------------------------------

    def _read_cache(self, name: str, ttl: int | None) -> object | None:
        path = self._cache_dir / name
        try:
            if ttl is not None and (self._now() - path.stat().st_mtime) >= ttl:
                return None
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def _write_cache(self, name: str, payload: object) -> None:
        try:
            self._cache_dir.mkdir(parents=True, exist_ok=True)
            (self._cache_dir / name).write_text(
                json.dumps(payload), encoding="utf-8",
            )
        except OSError:
            pass  # cache is best-effort; a read-only FS just means no caching


def _default_cache_dir() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "argus" / "enrichment"


def _chunked(items: list[str], size: int) -> Iterable[list[str]]:
    for start in range(0, len(items), size):
        yield items[start:start + size]
