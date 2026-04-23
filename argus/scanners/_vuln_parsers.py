"""Shared parse helpers for trivy and grype JSON output.

These are factored out of ``container.py`` so the new standalone
``trivy`` and ``grype`` scanners (SBOM-input mode) produce Findings
with the same shape as the container scanner's bundled runs. The
container scanner still owns its orchestration logic and CVE dedup
— this module only handles "one Trivy vuln dict -> Finding" and
"one Grype match dict -> Finding".
"""

from __future__ import annotations

from argus.core.models import Finding, Severity


def parse_trivy_vuln(vuln: dict, *, scanner_name: str = "trivy") -> Finding:
    """Convert a single Trivy vulnerability dict into a Finding."""
    vuln_id = vuln.get("VulnerabilityID", "UNKNOWN")
    pkg = vuln.get("PkgName", "")
    installed = vuln.get("InstalledVersion", "")
    fixed = vuln.get("FixedVersion", "")

    cwe = None
    cwe_ids = vuln.get("CweIDs") or []
    if cwe_ids:
        cwe = cwe_ids[0]

    return Finding(
        id=vuln_id,
        severity=Severity.from_string(vuln.get("Severity", "UNKNOWN")),
        title=vuln.get("Title", vuln_id),
        description=vuln.get("Description", ""),
        location=f"{pkg}@{installed}" if pkg else None,
        cwe=cwe,
        cve=vuln_id if vuln_id.startswith("CVE-") else None,
        scanner=scanner_name,
        metadata={
            "tool": "trivy",
            "package": pkg,
            "installed_version": installed,
            "fixed_version": fixed,
        },
    )


def parse_grype_match(match: dict, *, scanner_name: str = "grype") -> Finding:
    """Convert a single Grype match dict into a Finding."""
    vuln = match.get("vulnerability", {})
    artifact = match.get("artifact", {})
    vuln_id = vuln.get("id", "UNKNOWN")
    pkg_name = artifact.get("name", "")
    pkg_version = artifact.get("version", "")

    fix_versions = vuln.get("fix", {}).get("versions", [])
    fixed = ", ".join(fix_versions) if fix_versions else ""

    return Finding(
        id=vuln_id,
        severity=Severity.from_string(vuln.get("severity", "Unknown")),
        title=vuln.get("description", vuln_id),
        description=vuln.get("description", ""),
        location=f"{pkg_name}@{pkg_version}" if pkg_name else None,
        cve=vuln_id if vuln_id.startswith("CVE-") else None,
        scanner=scanner_name,
        metadata={
            "tool": "grype",
            "package": pkg_name,
            "installed_version": pkg_version,
            "fixed_version": fixed,
        },
    )
