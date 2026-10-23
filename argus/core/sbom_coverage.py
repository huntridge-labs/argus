"""SBOM-mode coverage guard: flag a matcher that skipped the OS packages.

A matcher can read an SBOM, fail to work out which OS its packages belong
to, drop every OS package, and still report a clean result. With the
pinned tools this happens for trivy on syft SPDX/CycloneDX SBOMs (it reads
the OS as ``none``, or as ``amzn``, which it doesn't support) and for grype
on trivy SBOMs (it can't map the ``amazon`` distro name). Nothing in the
exit code or the finding count shows it.

The guard compares two things:

- the SBOM's OS packages (``argus.core.sbom_contents.os_packages``)
- what the matcher's own JSON output says it evaluated, which the trivy
  and grype parsers put on ``ScanResult.metadata`` as
  ``os_packages_evaluated`` / ``matcher_os``

When the SBOM has OS packages and the matcher didn't evaluate them, the
result is marked ``incomplete``. An incomplete result is never a pass:
``ScanSummary.passed`` is False and ``argus scan`` exits 2. See
ADR-492.
"""

from __future__ import annotations

import logging
from functools import lru_cache
from pathlib import Path

from argus.core.models import ScanResult
from argus.core.sbom import SbomDetectionError, detect_sbom
from argus.core.sbom_contents import os_packages, parse_purl

logger = logging.getLogger("argus")

# grype's distro types (grype/distro/type.go at v0.120.1, the pinned
# version). grype reports a recognized distro under its type name
# ("amazonlinux"); an unrecognized one comes through as the raw name
# ("amazon"), and grype then matches none of that OS's packages. Bump
# this list with the grype pin. A type grype adds later only costs a
# false "incomplete" when grype also matched no OS package at all.
GRYPE_DISTRO_TYPES = frozenset({
    "almalinux", "alpine", "amazonlinux", "archlinux", "azurelinux",
    "busybox", "centos", "chainguard", "debian", "echo", "fedora", "gentoo",
    "hummingbird", "mariner", "minimos", "opensuseleap", "oraclelinux",
    "photon", "postmarketos", "raspbian", "redhat", "rockylinux",
    "scientific", "secureos", "sles", "ubuntu", "windows", "wolfi",
})


def trivy_coverage(data: dict) -> dict:
    """Coverage signal from a ``trivy sbom --format json`` report.

    trivy writes an ``os-pkgs`` result (with or without vulnerabilities)
    whenever it evaluated the OS packages. No such result means it didn't.
    """
    os_info = ((data.get("Metadata") or {}).get("OS") or {}) if isinstance(data, dict) else {}
    family = str(os_info.get("Family") or "").strip()
    name = str(os_info.get("Name") or "").strip()
    results = (data.get("Results") or []) if isinstance(data, dict) else []
    evaluated = any(
        isinstance(r, dict) and r.get("Class") == "os-pkgs" for r in results
    )
    return {
        "os_packages_evaluated": evaluated,
        "matcher_os": " ".join(p for p in (family, name) if p) or "none",
    }


def grype_coverage(data: dict) -> dict:
    """Coverage signal from a ``grype -o json`` report.

    grype evaluated the OS packages when it recognized the distro, or when
    it matched at least one OS package (proof it had a distro to match
    against even if our type list is behind).
    """
    distro = (data.get("distro") or {}) if isinstance(data, dict) else {}
    name = str(distro.get("name") or "").strip()
    version = str(distro.get("version") or "").strip()
    matches = (data.get("matches") or []) if isinstance(data, dict) else []
    evaluated = name in GRYPE_DISTRO_TYPES or any(
        _is_os_artifact(m.get("artifact")) for m in matches if isinstance(m, dict)
    )
    return {
        "os_packages_evaluated": evaluated,
        "matcher_os": " ".join(p for p in (name, version) if p) or "none",
    }


def _is_os_artifact(artifact: object) -> bool:
    if not isinstance(artifact, dict):
        return False
    purl = parse_purl(artifact.get("purl"))
    if purl is not None:
        return purl.is_os_package
    return str(artifact.get("type", "")).lower() in {"apk", "deb", "rpm", "alpm"}


def apply_coverage_guard(result: ScanResult, sbom_path: str | Path) -> ScanResult:
    """Mark ``result`` incomplete when it skipped the SBOM's OS packages.

    Updates ``result.metadata`` in place and returns the same result.
    Leaves the result alone when the scanner reports no coverage signal
    (osv), already failed (that's reported on its own), or evaluated the
    OS packages; and when the SBOM has no OS packages or can't be read.
    """
    meta = result.metadata
    if meta.get("os_packages_evaluated") is not False:
        return result
    if meta.get("execution_failed") or meta.get("parse_failed"):
        return result

    count, distros = _os_package_summary(str(sbom_path))
    if not count:
        return result

    matcher_os = meta.get("matcher_os") or "none"
    distro_text = ", ".join(distros) if distros else "no distro qualifier"
    meta["incomplete"] = True
    meta["incomplete_os_packages"] = count
    meta["incomplete_reason"] = (
        f"{result.scanner} did not evaluate the SBOM's {count} OS package(s) "
        f"({distro_text}); it read the OS as '{matcher_os}'. Its result for "
        "those packages is not clean, they were never checked."
    )
    logger.warning("SBOM coverage: %s", meta["incomplete_reason"])
    return result


def _os_package_summary(path: str) -> tuple[int, tuple[str, ...]]:
    try:
        stat = Path(path).stat()
    except OSError:
        return 0, ()
    return _cached_summary(path, stat.st_mtime_ns, stat.st_size)


@lru_cache(maxsize=32)
def _cached_summary(path: str, _mtime_ns: int, _size: int) -> tuple[int, tuple[str, ...]]:
    # Cached per (file, mtime, size): every matcher in a run checks the
    # same SBOM, and large SBOMs are worth reading once.
    try:
        info = detect_sbom(path)
    except SbomDetectionError:
        return 0, ()
    pkgs = os_packages(info)
    distros = tuple(sorted({p.distro for p in pkgs if p.distro}))
    return len(pkgs), distros
