"""SBOM format detection for ``argus scan --sbom``.

Sniffs the file content (not the filename — vendor-provided SBOMs often
ship under arbitrary names) to identify which SBOM format we're
dealing with. We lean deliberately permissive: once we recognize the
file as a well-formed SBOM in one of the supported formats, we let the
downstream tool (grype/trivy/osv-scanner) do its own strict validation
rather than duplicating theirs here.

Supported formats:
    - CycloneDX JSON  (``bomFormat``/``specVersion`` discriminator)
    - CycloneDX XML   (``<bom xmlns="http://cyclonedx.org/..."``)
    - SPDX JSON       (``SPDXID`` / ``spdxVersion`` discriminator)
    - SPDX tag-value  (``SPDXVersion:`` header on line 1)
    - Syft JSON       (``descriptor.name == "syft"``)
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger("argus")


@dataclass(frozen=True)
class SbomInfo:
    """The result of sniffing an SBOM file."""

    path: Path
    format: str  # one of: cyclonedx-json, cyclonedx-xml, spdx-json, spdx-tv, syft-json

    @property
    def display_format(self) -> str:
        return {
            "cyclonedx-json": "CycloneDX JSON",
            "cyclonedx-xml": "CycloneDX XML",
            "spdx-json": "SPDX JSON",
            "spdx-tv": "SPDX tag-value",
            "syft-json": "Syft JSON",
        }.get(self.format, self.format)


class SbomDetectionError(ValueError):
    """Raised when the file exists but is not a recognized SBOM format."""


def detect_sbom(path: str | Path) -> SbomInfo:
    """Return SbomInfo for a file, or raise SbomDetectionError.

    The caller is responsible for ensuring the file exists; this function
    opens it for reading and sniffs the first few kilobytes to identify
    the format. Large SBOMs are fine — we never load the whole file here.
    """
    p = Path(path)
    if not p.is_file():
        raise SbomDetectionError(f"SBOM file not found: {p}")

    with open(p, "rb") as fh:
        head = fh.read(4096)

    text_head = head.decode("utf-8", errors="replace").lstrip()
    # Dispatch by the first non-whitespace character — JSON starts with {
    # or [, XML with <, tag-value with alphabetic.
    if text_head.startswith("{") or text_head.startswith("["):
        fmt = _detect_json(p)
    elif text_head.startswith("<"):
        fmt = _detect_xml(text_head)
    else:
        fmt = _detect_tag_value(text_head)

    if fmt is None:
        raise SbomDetectionError(
            f"Unrecognized SBOM format in {p}. "
            "Supported: CycloneDX (JSON/XML), SPDX (JSON/tag-value), Syft JSON."
        )
    return SbomInfo(path=p, format=fmt)


def _detect_json(path: Path) -> str | None:
    """Parse the JSON file once and dispatch on schema discriminators."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError):
        return None
    if not isinstance(data, dict):
        return None

    # Syft ships its own descriptor block — check before CycloneDX because
    # Syft's output can also carry CycloneDX fields when --output=cyclonedx-json.
    descriptor = data.get("descriptor", {})
    if isinstance(descriptor, dict) and descriptor.get("name") == "syft":
        return "syft-json"
    if data.get("bomFormat") == "CycloneDX" or "specVersion" in data and "components" in data:
        return "cyclonedx-json"
    if "spdxVersion" in data or data.get("SPDXID") is not None:
        return "spdx-json"
    return None


def _detect_xml(head: str) -> str | None:
    """CycloneDX is the only XML SBOM format the tools accept."""
    lowered = head.lower()
    if "cyclonedx.org" in lowered or "<bom" in lowered:
        return "cyclonedx-xml"
    return None


def _detect_tag_value(head: str) -> str | None:
    """SPDX tag-value format opens with a ``SPDXVersion:`` header."""
    for line in head.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("SPDXVersion:"):
            return "spdx-tv"
        # First non-comment, non-blank line that isn't SPDXVersion — bail.
        return None
    return None


# Files we never bother sniffing when walking a directory — keeps the
# per-file open()/read(4KB) cost off the hot path for files that are
# obviously not SBOMs. Sniffing is still the decider for anything that
# isn't on this list, so a mis-extensioned SBOM still works.
_DIR_WALK_SKIP_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico",
    ".pdf", ".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz",
    ".so", ".dylib", ".dll", ".exe", ".wasm",
    ".mp3", ".mp4", ".mov", ".wav",
    ".pyc", ".pyo",
})


def analyze_sbom_quality(info: SbomInfo) -> list[str]:
    """Return human-readable warnings about how well an SBOM will scan.

    Called at scan startup so the user learns *before* scanners run that
    their input will under-identify packages. Based on the empirical
    matrix we hit with downstream vendor SBOMs:

    - Trivy's SBOM parser only supports SPDX-2.2/2.3. SPDX-2.1 inputs
      are silently rejected (``Detected SBOM format format="unknown"``).
    - OSV and Grype identify packages primarily through ``purl``
      external refs. Tag-value SBOMs without purls produce 0 matches —
      the tools aren't wrong, they just have nothing to look up.

    Returns an empty list when nothing is off. Warnings are strings so
    callers can log them at whichever level they prefer.
    """
    warnings: list[str] = []
    if info.format == "spdx-tv":
        version = _read_spdx_version(info.path)
        if version and version < (2, 2):
            warnings.append(
                f"SPDX-{version[0]}.{version[1]} SBOM detected — Trivy only "
                "supports SPDX-2.2 and 2.3 and will silently reject this "
                "file. Consider converting with `pyspdxtools -i X.spdx "
                "-o X.spdx.json` before scanning."
            )
        pkg_count, purl_count = _count_spdx_tv_packages_and_purls(info.path)
        if pkg_count >= 5 and purl_count < max(1, pkg_count // 2):
            warnings.append(
                f"SBOM contains {pkg_count} package(s) but only {purl_count} "
                "have purl external references. OSV and Grype rely on purl "
                "for vulnerability lookup; coverage will be incomplete. "
                "Ask the vendor for a purl-annotated SBOM, or regenerate "
                "it with `syft dir:./source -o spdx-json`."
            )
    return warnings


def _read_spdx_version(path: Path) -> tuple[int, int] | None:
    """Parse ``SPDXVersion: SPDX-X.Y`` from a tag-value file (first 4KB)."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            head = fh.read(4096)
    except OSError:
        return None
    for line in head.splitlines():
        stripped = line.strip()
        if stripped.startswith("SPDXVersion:"):
            _, _, value = stripped.partition(":")
            value = value.strip()
            if value.upper().startswith("SPDX-"):
                value = value[5:]
            parts = value.split(".")
            if len(parts) < 2:
                return None
            try:
                return int(parts[0]), int(parts[1])
            except ValueError:
                return None
    return None


def _count_spdx_tv_packages_and_purls(path: Path) -> tuple[int, int]:
    """Return ``(package_count, purl_count)`` for a tag-value SPDX file."""
    pkg = 0
    purl = 0
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                stripped = line.lstrip()
                if stripped.startswith("PackageName:"):
                    pkg += 1
                # purl refs live inside ``ExternalRef:`` lines; match on the
                # substring rather than a strict prefix so we catch variants
                # like ``PACKAGE-MANAGER purl`` and ``PACKAGE_MANAGER purl``.
                if "purl" in stripped.lower() and "ExternalRef:" in stripped:
                    purl += 1
    except OSError:
        return 0, 0
    return pkg, purl


def discover_sbom_files(path: str | Path) -> list[SbomInfo]:
    """Return every recognizable SBOM at ``path``, recursive when a dir.

    - File path: one-item list if the file sniffs as an SBOM, else raise.
    - Directory path: walk recursively, yielding any file that sniffs
      cleanly. Files that don't parse as SBOMs are skipped silently
      (logged at DEBUG) — vendor-provided bundles routinely ship
      README.md, LICENSE, and signature files alongside the SBOM.
    - Empty or all-non-SBOM directory: returns ``[]``. Callers decide
      whether that's an error.

    Files with obviously-non-SBOM extensions (images, archives, binaries)
    are skipped without opening to keep walks of large vendor bundles
    cheap. Sniffing remains the source of truth for any remaining file.
    """
    p = Path(path)
    if not p.exists():
        raise SbomDetectionError(f"SBOM path not found: {p}")
    if p.is_file():
        return [detect_sbom(p)]
    if not p.is_dir():
        raise SbomDetectionError(
            f"SBOM path is neither file nor directory: {p}"
        )

    found: list[SbomInfo] = []
    for candidate in sorted(p.rglob("*")):
        if not candidate.is_file():
            continue
        if candidate.suffix.lower() in _DIR_WALK_SKIP_EXTENSIONS:
            continue
        try:
            found.append(detect_sbom(candidate))
        except SbomDetectionError:
            logger.debug(
                "Skipping %s — does not appear to be an SBOM", candidate,
            )
            continue
    return found
