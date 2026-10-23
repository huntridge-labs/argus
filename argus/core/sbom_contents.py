"""Read the packages an SBOM lists, keyed by package URL (purl).

``argus.core.sbom`` only sniffs which format a file is. This module reads
the package list itself, so SBOM mode can tell what the matchers were
handed: how many packages, and which of them belong to the operating
system.

An OS package carries a ``distro=`` qualifier in its purl (for example
``pkg:rpm/amzn/openssl-libs@3.0.8?distro=amzn-2023``). That qualifier is
the most reliable OS signal an SBOM has: SBOM-level OS metadata varies by
generator and some matchers ignore it, but every generator we've seen
stamps the qualifier on each OS package. Purl types that only ever hold
OS packages (``apk``, ``deb``, ``rpm``, ``alpm``) count too, so an SBOM
that leaves the qualifier off is still recognized.
"""

from __future__ import annotations

import html
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote

from argus.core.sbom import SbomInfo

logger = logging.getLogger("argus")

OS_PURL_TYPES = frozenset({"apk", "deb", "rpm", "alpm"})

_XML_METADATA = re.compile(r"<metadata\b.*?</metadata>", re.DOTALL | re.IGNORECASE)
_XML_PURL = re.compile(r"<purl>\s*([^<]+?)\s*</purl>", re.IGNORECASE)


@dataclass(frozen=True)
class Purl:
    """A parsed package URL. Only the parts SBOM mode needs."""

    type: str
    namespace: str
    name: str
    version: str
    qualifiers: dict = field(default_factory=dict, hash=False, compare=False)

    @property
    def distro(self) -> str:
        return self.qualifiers.get("distro", "")

    @property
    def is_os_package(self) -> bool:
        return bool(self.distro) or self.type in OS_PURL_TYPES


def parse_purl(value: object) -> Purl | None:
    """Parse ``pkg:type/namespace/name@version?qualifiers#subpath``.

    Returns None for anything that isn't a purl. Lenient on purpose:
    SBOMs in the wild bend the spec, and a package we can't parse is
    simply left out of the counts.
    """
    if not isinstance(value, str) or not value.startswith("pkg:"):
        return None
    rest = value[len("pkg:"):].lstrip("/").split("#", 1)[0]
    rest, _, query = rest.partition("?")
    path, _, version = rest.rpartition("@") if "@" in rest else (rest, "", "")
    ptype, _, remainder = path.partition("/")
    if not ptype or not remainder:
        return None
    namespace, _, name = remainder.rpartition("/")
    if not name:
        return None
    return Purl(
        type=ptype.lower(),
        namespace=unquote(namespace),
        name=unquote(name),
        version=unquote(version),
        qualifiers=_parse_qualifiers(query),
    )


def _parse_qualifiers(query: str) -> dict:
    pairs = (part.partition("=") for part in query.split("&") if part)
    return {key.lower(): unquote(val) for key, _, val in pairs if key}


def read_purls(info: SbomInfo) -> list[str]:
    """Return every package purl the SBOM lists, in document order.

    The SBOM's own subject (CycloneDX ``metadata.component``) is not a
    package and is skipped. Returns ``[]`` when the file can't be read;
    format detection already accepted it, so a read failure here means
    the file changed or is truncated, and the caller decides what that
    means.
    """
    try:
        if info.format == "cyclonedx-xml":
            return _xml_purls(info.path)
        if info.format == "spdx-tv":
            return _tag_value_purls(info.path)
        data = json.loads(Path(info.path).read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError) as exc:
        logger.debug("Could not read packages from %s: %s", info.path, exc)
        return []
    if not isinstance(data, dict):
        return []
    if info.format == "syft-json":
        return _purls_from(data.get("artifacts"))
    if info.format == "spdx-json":
        return _spdx_json_purls(data)
    return _cyclonedx_json_purls(data.get("components"))


def os_packages(info: SbomInfo) -> list[Purl]:
    """Return the SBOM's OS packages (see the module docstring)."""
    parsed = (parse_purl(p) for p in read_purls(info))
    return [p for p in parsed if p is not None and p.is_os_package]


def _purls_from(items: object) -> list[str]:
    if not isinstance(items, list):
        return []
    return [
        item["purl"] for item in items
        if isinstance(item, dict) and isinstance(item.get("purl"), str) and item["purl"]
    ]


def _cyclonedx_json_purls(components: object) -> list[str]:
    if not isinstance(components, list):
        return []
    purls: list[str] = []
    for comp in components:
        if not isinstance(comp, dict):
            continue
        purls.extend(_purls_from([comp]))
        purls.extend(_cyclonedx_json_purls(comp.get("components")))
    return purls


def _spdx_json_purls(data: dict) -> list[str]:
    purls: list[str] = []
    for pkg in data.get("packages") or []:
        if not isinstance(pkg, dict):
            continue
        for ref in pkg.get("externalRefs") or []:
            if not isinstance(ref, dict):
                continue
            if str(ref.get("referenceType", "")).lower() == "purl" and ref.get("referenceLocator"):
                purls.append(str(ref["referenceLocator"]))
    return purls


def _xml_purls(path: Path) -> list[str]:
    # A regex, not an XML parser: the input is untrusted, and we only need
    # the <purl> text. Skipping <metadata> drops the SBOM's own subject.
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    body = _XML_METADATA.sub("", text)
    return [html.unescape(m) for m in _XML_PURL.findall(body)]


def _tag_value_purls(path: Path) -> list[str]:
    purls: list[str] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            stripped = line.strip()
            if not stripped.startswith("ExternalRef:"):
                continue
            parts = stripped.split()
            if len(parts) >= 4 and parts[2].lower() == "purl":
                purls.append(parts[3])
    return purls
