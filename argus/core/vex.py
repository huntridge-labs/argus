"""Shared OpenVEX resolution — one source of truth for every VEX-capable scanner.

VEX (Vulnerability Exploitability eXchange) documents let an operator assert
``not_affected`` / ``fixed`` for specific CVEs with a justification. Trivy and
Grype both consume OpenVEX natively (``--vex <file>``) and drop matching
findings at the source, so a single document filters both.

This module centralizes the path resolution, container-mount plumbing, and
CLI-flag construction so a scanner opts into VEX declaratively rather than
re-implementing the wiring:

    class MyScaScanner:
        supports_vex = True   # capability flag (argus.core.scanner.Scanner)

        def container_args(self, config=None):
            return [..., *vex_cli_flags(config, in_container=True)]

        def container_mounts(self, config=None):
            return vex_container_mounts(config)

        def scan(self, path, config=None):
            cmd = [..., *vex_cli_flags(config, in_container=False)]

Config surface: a scanner reads ``config['vex']`` — a single path (str) or a
list of paths. It reaches the scanner via ``scanners.<name>.vex`` in argus.yml
(threaded through ``ScannerConfig.extra``), ``containers.vex`` for the
container-lifecycle path, or the ``argus scan container --vex`` flag.

A missing file is logged and skipped rather than aborting the scan — silently
*not* suppressing keeps findings visible, which is the safe failure direction.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from argus.core.models import Finding

logger = logging.getLogger("argus")

#: In-container mount point for the Nth VEX document. Kept stable so
#: ``vex_container_mounts`` and ``vex_cli_flags(in_container=True)`` agree on
#: the path for the same document index.
_VEX_CONTAINER_TEMPLATE = "/vex/doc{idx}.json"


def _raw_paths(config: dict | None) -> list[str]:
    """Normalize ``config['vex']`` (str | list | None) to a list of strings."""
    if not config:
        return []
    raw = config.get("vex")
    if not raw:
        return []
    return [raw] if isinstance(raw, str) else [str(p) for p in raw]


def resolve_vex_documents(config: dict | None) -> list[Path]:
    """Return the existing VEX document paths named by ``config['vex']``.

    Order is preserved (callers index container mounts by position). Paths that
    don't resolve to a file are logged and dropped.
    """
    resolved: list[Path] = []
    for entry in _raw_paths(config):
        src = Path(entry).expanduser()
        if not src.is_file():
            logger.warning("VEX document not found, skipping: %s", entry)
            continue
        resolved.append(src.resolve())
    return resolved


def vex_container_mounts(config: dict | None) -> list[tuple[str, str]]:
    """``(host_path, container_path)`` pairs for bind-mounting VEX docs.

    Shape matches the engine's ``container_mounts`` hook (it adds ``-v`` and
    ``:ro`` itself). Indices align with ``vex_cli_flags(in_container=True)``.
    """
    return [
        (str(src), _VEX_CONTAINER_TEMPLATE.format(idx=idx))
        for idx, src in enumerate(resolve_vex_documents(config))
    ]


def vex_cli_flags(config: dict | None, *, in_container: bool) -> list[str]:
    """Build the ``--vex <path>`` flags trivy and grype both accept.

    ``in_container`` selects the mounted ``/vex/doc<N>.json`` paths (aligned
    with :func:`vex_container_mounts`); otherwise the resolved host paths for
    the local-binary invocation.
    """
    docs = resolve_vex_documents(config)
    flags: list[str] = []
    for idx, src in enumerate(docs):
        path = _VEX_CONTAINER_TEMPLATE.format(idx=idx) if in_container else str(src)
        flags += ["--vex", path]
    return flags


#: Statuses that tell trivy / grype to drop a finding. Only these can "miss".
_SUPPRESSING_STATUSES = frozenset({"not_affected", "fixed"})


@dataclass(frozen=True)
class UnappliedStatement:
    """A VEX statement that names a reported finding but did not suppress it."""

    vulnerability: str
    statement_product: str
    reported_purl: str
    tool: str


def _purl_key(purl: str) -> tuple[str, str]:
    """``(type/namespace/name, version)`` with spelling noise removed.

    Scanners disagree on how to spell the same package version. For the Go
    toolchain trivy emits ``pkg:golang/stdlib@v1.24.11``, grype emits
    ``pkg:golang/stdlib@1.24.11`` and govulncheck says ``go1.24.11``. The
    tools match VEX products by exact PURL, so a statement in the "wrong"
    spelling silently matches nothing. Normalising here lets us spot that.
    """
    base = purl.split("#", 1)[0].split("?", 1)[0]
    # The version separator is the "@" in the last path segment; a scoped
    # npm namespace (pkg:npm/@babel/core) carries an "@" that is not one.
    namespace, slash, last = base.rpartition("/")
    package, at, version = last.partition("@")
    if not at:
        return base, ""
    name = f"{namespace}{slash}{package}"
    for prefix in ("go", "v"):
        if version.startswith(prefix) and version[len(prefix):][:1].isdigit():
            version = version[len(prefix):]
            break
    return name, version


def _suppressing_statements(config: dict | None) -> list[tuple[str, str]]:
    """``(vulnerability, product @id)`` for every suppressing statement."""
    pairs: list[tuple[str, str]] = []
    for doc in resolve_vex_documents(config):
        try:
            data = json.loads(doc.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            logger.warning("Could not read VEX document %s: %s", doc, exc)
            continue
        for statement in data.get("statements") or []:
            if statement.get("status") not in _SUPPRESSING_STATUSES:
                continue
            vuln = (statement.get("vulnerability") or {}).get("name", "")
            for product in statement.get("products") or []:
                ids = [product.get("@id", "")]
                ids += [sub.get("@id", "") for sub in product.get("subcomponents") or []]
                pairs.extend((vuln, pid) for pid in ids if pid)
    return pairs


def unapplied_statements(
    findings: list[Finding], config: dict | None
) -> list[UnappliedStatement]:
    """Findings a suppressing VEX statement covers that the scanner still reported.

    trivy and grype drop a finding only when a statement's product PURL is an
    exact match, and say nothing when it is not. Any finding returned here is
    one the operator already declared ``not_affected`` / ``fixed`` but that
    still reaches the report, almost always because the statement spells the
    PURL differently from the scanner. Purely diagnostic: nothing is hidden or
    changed (ADR-035).
    """
    statements = _suppressing_statements(config)
    if not statements:
        return []
    misses: list[UnappliedStatement] = []
    for finding in findings:
        purl = finding.metadata.get("purl") or ""
        if not purl:
            continue
        key = _purl_key(purl)
        misses.extend(
            UnappliedStatement(
                vulnerability=vuln,
                statement_product=product,
                reported_purl=purl,
                tool=finding.metadata.get("tool", ""),
            )
            for vuln, product in statements
            if vuln == finding.id and _purl_key(product) == key
        )
    return misses
