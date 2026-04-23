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
