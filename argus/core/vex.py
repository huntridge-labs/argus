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

import logging
from pathlib import Path

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
