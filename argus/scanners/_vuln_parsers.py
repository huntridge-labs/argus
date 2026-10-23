"""Shared parse helpers for trivy and grype JSON output.

These are factored out of ``container.py`` so the new standalone
``trivy`` and ``grype`` scanners (SBOM-input mode) produce Findings
with the same shape as the container scanner's bundled runs. The
container scanner still owns its orchestration logic and CVE dedup
— this module only handles "one Trivy vuln dict -> Finding" and
"one Grype match dict -> Finding", plus the report-level wrappers
that thread the vulnerability DB build date through.

Finding metadata keys (all modes):

- ``tool``, ``package``, ``installed_version``, ``fixed_version``,
  ``purl`` (unchanged since #229)
- ``advisory_id``: the distro / ecosystem advisory (ALAS, DSA, RHSA,
  GHSA) when the matcher reports one, else ``""``
- ``related_cves``: ``[{"id", "severity"}]``, the CVEs behind the
  finding with each CVE's own severity (grype ``relatedVulnerabilities``;
  trivy's CVE id with its NVD severity)
- ``os_package``: True for an OS package (``distro=`` purl qualifier,
  an apk/deb/rpm/alpm package, or a trivy ``os-pkgs`` result)
- ``matcher``: ``grype/<matcher>`` (e.g. ``grype/rpm-matcher``) or
  ``trivy``; grype also sets ``match_type``
- ``data_source``: the advisory feed (grype namespace, trivy DataSource)
- ``vulnerability_db_built``: when the matcher's vulnerability DB was
  built, ISO 8601, ``""`` when unknown (issue #495)
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from argus.core.models import Finding, Severity

_OS_PURL_TYPES = frozenset({"apk", "deb", "rpm", "alpm"})
_OS_ARTIFACT_TYPES = _OS_PURL_TYPES
# trivy's VendorSeverity uses ints: 0 unknown .. 4 critical.
_TRIVY_SEVERITY = {0: "unknown", 1: "low", 2: "medium", 3: "high", 4: "critical"}


def parse_trivy_vuln(
    vuln: dict,
    *,
    scanner_name: str = "trivy",
    result_class: str | None = None,
    db_built: str = "",
) -> Finding:
    """Convert a single Trivy vulnerability dict into a Finding.

    ``result_class`` is the enclosing result's ``Class`` (``os-pkgs`` /
    ``lang-pkgs``) when the caller has it; ``db_built`` the DB build
    date from :func:`trivy_db_built`.
    """
    vuln_id = vuln.get("VulnerabilityID", "UNKNOWN")
    pkg = vuln.get("PkgName", "")
    installed = vuln.get("InstalledVersion", "")
    fixed = vuln.get("FixedVersion", "")
    # Package URL — Trivy 0.40+ carries it under PkgIdentifier.PURL. It is the
    # canonical product key for VEX / SBOM correlation, so propagate it.
    purl = (vuln.get("PkgIdentifier") or {}).get("PURL", "")

    cwe = None
    cwe_ids = vuln.get("CweIDs") or []
    if cwe_ids:
        cwe = cwe_ids[0]

    severity = Severity.from_string(vuln.get("Severity", "UNKNOWN"))
    vendor_ids = [str(v) for v in vuln.get("VendorIDs") or [] if v]
    is_cve = vuln_id.startswith("CVE-")
    if result_class:
        os_package = result_class == "os-pkgs"
    else:
        os_package = _is_os_purl(purl)

    return Finding(
        id=vuln_id,
        severity=severity,
        title=vuln.get("Title", vuln_id),
        description=vuln.get("Description", ""),
        location=f"{pkg}@{installed}" if pkg else None,
        cwe=cwe,
        cve=vuln_id if is_cve else None,
        scanner=scanner_name,
        metadata={
            "tool": "trivy",
            "package": pkg,
            "installed_version": installed,
            "fixed_version": fixed,
            "purl": purl,
            "advisory_id": vendor_ids[0] if vendor_ids else ("" if is_cve else vuln_id),
            "related_cves": (
                [{"id": vuln_id, "severity": _trivy_nvd_severity(vuln, severity)}]
                if is_cve else []
            ),
            "os_package": os_package,
            "matcher": "trivy",
            "data_source": str((vuln.get("DataSource") or {}).get("ID") or ""),
            "vulnerability_db_built": db_built,
        },
    )


def parse_grype_match(match: dict, *, scanner_name: str = "grype", db_built: str = "") -> Finding:
    """Convert a single Grype match dict into a Finding."""
    vuln = match.get("vulnerability", {})
    artifact = match.get("artifact", {})
    vuln_id = vuln.get("id", "UNKNOWN")
    pkg_name = artifact.get("name", "")
    pkg_version = artifact.get("version", "")

    fix_versions = vuln.get("fix", {}).get("versions", [])
    fixed = ", ".join(fix_versions) if fix_versions else ""
    # Grype reports the package URL directly on the artifact.
    purl = artifact.get("purl", "")
    details = [d for d in match.get("matchDetails") or [] if isinstance(d, dict)]
    first = details[0] if details else {}
    matcher = str(first.get("matcher") or "")
    is_cve = vuln_id.startswith("CVE-")

    return Finding(
        id=vuln_id,
        severity=Severity.from_string(vuln.get("severity", "Unknown")),
        title=vuln.get("description", vuln_id),
        description=vuln.get("description", ""),
        location=f"{pkg_name}@{pkg_version}" if pkg_name else None,
        cve=vuln_id if is_cve else None,
        scanner=scanner_name,
        metadata={
            "tool": "grype",
            "package": pkg_name,
            "installed_version": pkg_version,
            "fixed_version": fixed,
            "purl": purl,
            "advisory_id": "" if is_cve else vuln_id,
            "related_cves": _grype_related_cves(match),
            "os_package": _is_os_purl(purl) or str(artifact.get("type", "")).lower() in _OS_ARTIFACT_TYPES,
            "matcher": f"grype/{matcher}" if matcher else "grype",
            "match_type": str(first.get("type") or ""),
            "data_source": str(vuln.get("namespace") or ""),
            "vulnerability_db_built": db_built,
        },
    )


def parse_trivy_report(
    data: dict, *, scanner_name: str = "trivy", db_built: str = "",
) -> list[Finding]:
    """Every vulnerability in a ``trivy --format json`` report."""
    findings: list[Finding] = []
    for result in (data.get("Results") or []) if isinstance(data, dict) else []:
        for vuln in result.get("Vulnerabilities") or []:
            findings.append(parse_trivy_vuln(
                vuln, scanner_name=scanner_name,
                result_class=result.get("Class"), db_built=db_built,
            ))
    return findings


def parse_grype_report(data: dict, *, scanner_name: str = "grype") -> list[Finding]:
    """Every match in a ``grype -o json`` report, stamped with the DB date."""
    if not isinstance(data, dict):
        return []
    built = grype_db_built(data)
    return [
        parse_grype_match(m, scanner_name=scanner_name, db_built=built)
        for m in data.get("matches") or []
    ]


def grype_db_built(data: dict) -> str:
    """The DB build date grype records in its report descriptor.

    grype v0.88+ (DB schema v6) nests it under ``db.status.built``;
    older releases put ``built`` directly on ``db``.
    """
    db = ((data.get("descriptor") or {}).get("db") or {}) if isinstance(data, dict) else {}
    status = db.get("status") if isinstance(db.get("status"), dict) else {}
    return str(status.get("built") or db.get("built") or "")


def trivy_db_built(cache_dirs: list[Path] | None = None) -> str:
    """Best-effort trivy DB build date (``UpdatedAt`` in ``db/metadata.json``).

    trivy's JSON report doesn't record its DB, so read the cache it used.
    Candidates: ``$TRIVY_CACHE_DIR``, the Argus cache mounted into the trivy
    container, and trivy's default ``~/.cache/trivy``. When several exist,
    the most recently downloaded wins. Returns ``""`` when none is found.
    """
    dirs = cache_dirs if cache_dirs is not None else _trivy_cache_candidates()
    best: tuple[str, str] | None = None
    for root in dirs:
        meta = _read_json(Path(root) / "db" / "metadata.json")
        if not meta.get("UpdatedAt"):
            continue
        key = (str(meta.get("DownloadedAt") or ""), str(meta["UpdatedAt"]))
        if best is None or key > best:
            best = key
    return best[1] if best else ""


def _trivy_cache_candidates() -> list[Path]:
    from argus.containers import _default_cache_root

    candidates = []
    if os.environ.get("TRIVY_CACHE_DIR"):
        candidates.append(Path(os.environ["TRIVY_CACHE_DIR"]))
    candidates.append(_default_cache_root() / "trivy")
    candidates.append(Path.home() / ".cache" / "trivy")
    return candidates


def _read_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _grype_related_cves(match: dict) -> list[dict]:
    related = []
    for rel in match.get("relatedVulnerabilities") or []:
        if not isinstance(rel, dict) or not str(rel.get("id", "")).startswith("CVE-"):
            continue
        severity = Severity.from_string(str(rel.get("severity") or "unknown")).value
        related.append({"id": rel["id"], "severity": severity})
    return related


def _trivy_nvd_severity(vuln: dict, fallback: Severity) -> str:
    nvd = (vuln.get("VendorSeverity") or {}).get("nvd")
    if isinstance(nvd, int) and nvd in _TRIVY_SEVERITY:
        return _TRIVY_SEVERITY[nvd]
    return fallback.value


def _is_os_purl(purl: str) -> bool:
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        return False
    ptype = purl[4:].lstrip("/").split("/", 1)[0].lower()
    return ptype in _OS_PURL_TYPES or "distro=" in purl.partition("?")[2]
