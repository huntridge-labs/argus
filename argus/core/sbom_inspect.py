"""``argus sbom inspect``: what an SBOM describes, before you scan it.

Reports the format and spec version, the generator, the subject (image
name and digest), the OS, package counts by purl type, and which matcher
``argus scan --sbom`` would pick (``argus.core.sbom_routing``). The OS
comes from the packages' ``distro=`` purl qualifiers first, since that
is what the matchers key on, and from SBOM-level metadata only when no
package carries one.
"""

from __future__ import annotations

import html
import json
import re
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path

from argus.core.sbom import SbomInfo, analyze_sbom_quality, detect_sbom
from argus.core.sbom_contents import parse_purl, read_generator, read_purls
from argus.core.sbom_routing import choose_matchers

_XML_SPEC = re.compile(r"cyclonedx\.org/schema/bom/(\d+(?:\.\d+)*)", re.IGNORECASE)
_XML_SUBJECT = re.compile(
    r"<metadata\b.*?<component\b(?P<attrs>[^>]*)>(?P<body>.*?)</component>",
    re.DOTALL | re.IGNORECASE,
)
_XML_TAG = r"<{0}>\s*([^<]+?)\s*</{0}>"
_DISTRO = re.compile(r"^(?P<name>.+?)-(?P<version>\d.*)$")


@dataclass(frozen=True)
class SbomReport:
    path: str
    format: str
    display_format: str
    spec_version: str
    generator: dict | None
    subject: dict | None
    os: dict | None
    packages: dict
    matcher: dict
    warnings: list

    def to_dict(self) -> dict:
        return asdict(self)


def inspect_sbom(path: str | Path) -> SbomReport:
    """Build the report for one SBOM file. Raises SbomDetectionError."""
    info = detect_sbom(path)
    data = _load_json(info)
    subject = _subject(info, data)
    purls = [p for p in read_purls(info) if p != (subject or {}).get("purl")]
    parsed = [p for p in (parse_purl(v) for v in purls) if p is not None]
    generator = read_generator(info)
    choice = choose_matchers(info)
    return SbomReport(
        path=str(info.path),
        format=info.format,
        display_format=info.display_format,
        spec_version=_spec_version(info, data),
        generator={"name": generator.name, "version": generator.version} if generator else None,
        subject=subject,
        os=_os_from_purls(parsed, info, data) or _os_from_metadata(info, data),
        packages={
            "total": len(parsed),
            "os": sum(1 for p in parsed if p.is_os_package),
            "by_type": dict(sorted(Counter(p.type for p in parsed).items())),
        },
        matcher={"matchers": list(choice.matchers), "reason": choice.reason},
        warnings=analyze_sbom_quality(info),
    )


def _load_json(info: SbomInfo) -> dict:
    if info.format in ("cyclonedx-xml", "spdx-tv"):
        return {}
    try:
        data = json.loads(Path(info.path).read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _text(info: SbomInfo) -> str:
    return Path(info.path).read_text(encoding="utf-8", errors="replace")


def _spec_version(info: SbomInfo, data: dict) -> str:
    if info.format == "cyclonedx-json":
        return str(data.get("specVersion") or "")
    if info.format == "spdx-json":
        return str(data.get("spdxVersion") or "")
    if info.format == "syft-json":
        return str((data.get("schema") or {}).get("version") or "")
    if info.format == "cyclonedx-xml":
        match = _XML_SPEC.search(_text(info))
        return match.group(1) if match else ""
    return _tag_value(info, "SPDXVersion")


def _tag_value(info: SbomInfo, key: str) -> str:
    for line in _text(info).splitlines():
        name, _, value = line.strip().partition(":")
        if name == key:
            return value.strip()
    return ""


def _subject(info: SbomInfo, data: dict) -> dict | None:
    if info.format == "cyclonedx-json":
        comp = (data.get("metadata") or {}).get("component")
        return _cyclonedx_subject(comp) if isinstance(comp, dict) else None
    if info.format == "spdx-json":
        return _spdx_subject(data)
    if info.format == "syft-json":
        return _syft_subject(data.get("source") or {})
    if info.format == "cyclonedx-xml":
        return _xml_subject(_text(info))
    name = _tag_value(info, "DocumentName")
    return {"name": name, "version": "", "type": "", "digest": "", "purl": ""} if name else None


def _cyclonedx_subject(comp: dict) -> dict:
    purl = str(comp.get("purl") or "")
    props = {p.get("name"): p.get("value") for p in comp.get("properties") or [] if isinstance(p, dict)}
    repo_digest = str(props.get("aquasecurity:trivy:RepoDigest") or "")
    return _subject_dict(
        comp.get("name"), comp.get("version"), comp.get("type"), purl,
        _purl_digest(purl) or repo_digest.rpartition("@")[2],
    )


def _spdx_subject(data: dict) -> dict | None:
    packages = [p for p in data.get("packages") or [] if isinstance(p, dict)]
    described = {
        r.get("relatedSpdxElement") for r in data.get("relationships") or []
        if isinstance(r, dict) and r.get("relationshipType") == "DESCRIBES"
    } | set(data.get("documentDescribes") or [])
    pkg = next((p for p in packages if p.get("primaryPackagePurpose") == "CONTAINER"), None)
    pkg = pkg or next((p for p in packages if p.get("SPDXID") in described), None)
    if pkg is None:
        name = data.get("name")
        return _subject_dict(name, "", "", "", "") if name else None
    purl = next(
        (str(r.get("referenceLocator")) for r in pkg.get("externalRefs") or []
         if isinstance(r, dict) and str(r.get("referenceType", "")).lower() == "purl"),
        "",
    )
    sha = next(
        (f"sha256:{c.get('checksumValue')}" for c in pkg.get("checksums") or []
         if isinstance(c, dict) and c.get("algorithm") == "SHA256"),
        "",
    )
    purpose = str(pkg.get("primaryPackagePurpose") or "").lower()
    return _subject_dict(pkg.get("name"), pkg.get("versionInfo"), purpose, purl, _purl_digest(purl) or sha)


def _syft_subject(source: dict) -> dict | None:
    if not source.get("name"):
        return None
    meta = source.get("metadata") or {}
    repo = next(iter(meta.get("repoDigests") or []), "")
    digest = str(repo).rpartition("@")[2] or str(meta.get("manifestDigest") or "")
    return _subject_dict(source.get("name"), source.get("version"), source.get("type"), "", digest)


def _xml_subject(text: str) -> dict | None:
    match = _XML_SUBJECT.search(text)
    if not match:
        return None
    body = match.group("body")
    name, version, purl = (_xml_field(body, tag) for tag in ("name", "version", "purl"))
    kind = re.search(r'type="([^"]+)"', match.group("attrs"))
    return _subject_dict(name, version, kind.group(1) if kind else "", purl, _purl_digest(purl))


def _xml_field(body: str, tag: str) -> str:
    found = re.search(_XML_TAG.format(tag), body, re.IGNORECASE)
    return html.unescape(found.group(1)) if found else ""


def _subject_dict(name, version, kind, purl, digest) -> dict:
    return {
        "name": str(name or ""),
        "version": str(version or ""),
        "type": str(kind or ""),
        "digest": str(digest or ""),
        "purl": str(purl or ""),
    }


def _purl_digest(purl: str) -> str:
    parsed = parse_purl(purl)
    if parsed and parsed.type == "oci" and parsed.version.startswith("sha256:"):
        return parsed.version
    return ""


def _os_from_purls(parsed, info: SbomInfo, data: dict) -> dict | None:
    distros = Counter(p.distro for p in parsed if p.distro)
    if not distros:
        return None
    top = distros.most_common(1)[0][0]
    match = _DISTRO.match(top)
    if match:
        name, version = match["name"], match["version"]
    elif top[:1].isdigit():
        name, version = _distro_family(parsed, top, info, data), top
    else:
        name, version = top, ""
    return {"name": name, "version": version, "source": "purl", "distros": sorted(distros)}


def _distro_family(parsed, distro: str, info: SbomInfo, data: dict) -> str:
    """The OS name for a bare ``distro=<version>`` qualifier, as trivy writes
    for apk (#516): the purls' namespace (``pkg:apk/alpine/...``), else the
    SBOM's own OS metadata, else unknown."""
    namespaces = Counter(p.namespace for p in parsed if p.distro == distro and p.namespace)
    if namespaces:
        return namespaces.most_common(1)[0][0]
    return (_os_from_metadata(info, data) or {}).get("name", "")


def _os_from_metadata(info: SbomInfo, data: dict) -> dict | None:
    found: tuple[str, str] | None = None
    if info.format == "cyclonedx-json":
        comp = next(
            (c for c in data.get("components") or []
             if isinstance(c, dict) and c.get("type") == "operating-system"),
            None,
        )
        found = (comp.get("name"), comp.get("version")) if comp else None
    elif info.format == "spdx-json":
        pkg = next(
            (p for p in data.get("packages") or []
             if isinstance(p, dict) and p.get("primaryPackagePurpose") == "OPERATING-SYSTEM"),
            None,
        )
        found = (pkg.get("name"), pkg.get("versionInfo")) if pkg else None
    elif info.format == "syft-json":
        distro = data.get("distro") or {}
        found = (distro.get("id"), distro.get("versionID")) if distro.get("id") else None
    if not found or not found[0]:
        return None
    return {
        "name": str(found[0]), "version": str(found[1] or ""),
        "source": "sbom-metadata", "distros": [],
    }


def format_terminal(report: SbomReport) -> str:
    """Human-readable report for the terminal."""
    lines = [f"SBOM:       {report.path}"]
    spec = f" ({report.spec_version})" if report.spec_version else ""
    lines.append(f"Format:     {report.display_format}{spec}")
    gen = report.generator
    lines.append(f"Generator:  {gen['name']} {gen['version']}".rstrip() if gen else "Generator:  not recorded")
    subject = report.subject
    if subject and subject["name"]:
        detail = " ".join(v for v in (subject["name"], subject["version"]) if v)
        kind = f" ({subject['type']})" if subject["type"] else ""
        lines.append(f"Subject:    {detail}{kind}")
        if subject["digest"]:
            lines.append(f"Digest:     {subject['digest']}")
    else:
        lines.append("Subject:    not recorded")
    lines.append(_os_line(report.os))
    pkgs = report.packages
    lines.append(f"Packages:   {pkgs['total']} ({pkgs['os']} OS)")
    lines.extend(f"  {ptype:<12} {count}" for ptype, count in pkgs["by_type"].items())
    matchers = ", ".join(report.matcher["matchers"])
    lines.append(f"Matcher:    {matchers} ({report.matcher['reason']})")
    lines.extend(f"Warning:    {w}" for w in report.warnings)
    return "\n".join(lines)


def _os_line(os_info: dict | None) -> str:
    if not os_info:
        return "OS:         none found"
    label = " ".join(v for v in (os_info["name"], os_info["version"]) if v)
    source = "package purls" if os_info["source"] == "purl" else "SBOM metadata"
    return f"OS:         {label} (from {source})"
