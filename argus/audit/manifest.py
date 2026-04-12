"""Audit manifest -- the evidence package JSON.

The manifest answers the forensic questions: what was scanned, when,
how, by whom, with what tools, and what was found.  It is the single
file an investigator reaches for first.
"""

import hashlib
import json
import platform
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .platform import CIPlatform, detect_platform


@dataclass
class ScanPhase:
    """Timing data for one phase of the scan."""

    name: str
    started_at: str
    completed_at: str = ""
    duration_ms: int = 0
    status: str = "success"
    error: str = ""


@dataclass
class AuditManifest:
    """Complete audit trail for an argus scan run.

    This is the evidence package.  In a security investigation,
    this file answers: what was scanned, when, how, by whom,
    with what tools, and what was found.
    """

    # Identity
    argus_version: str = ""
    scan_id: str = ""

    # Timing
    started_at: str = ""
    completed_at: str = ""
    duration_ms: int = 0

    # Provenance (who / where)
    platform: dict = field(default_factory=dict)
    hostname: str = ""
    python_version: str = ""
    os_info: str = ""

    # What was scanned
    scan_targets: list[str] = field(default_factory=list)
    config_file: str = ""
    config_hash: str = ""

    # How it was scanned
    scanners_executed: list[str] = field(default_factory=list)
    tool_versions: dict[str, str] = field(default_factory=dict)
    container_images: dict[str, str] = field(default_factory=dict)
    execution_backend: str = ""

    # What was found (summary counts)
    findings_summary: dict = field(default_factory=dict)
    exit_code: int = 0

    # Phases (timing per scanner / step)
    phases: list[dict] = field(default_factory=list)

    # Artifact inventory
    artifacts: list[dict] = field(default_factory=list)

    def save(self, output_dir: str | Path) -> Path:
        """Write the manifest to ``argus-audit.json``."""
        dest = Path(output_dir)
        dest.mkdir(parents=True, exist_ok=True)
        filepath = dest / "argus-audit.json"
        filepath.write_text(
            json.dumps(asdict(self), indent=2, default=str),
            encoding="utf-8",
        )
        return filepath


def create_manifest(
    config_path: str | None = None,
    scan_targets: list[str] | None = None,
) -> AuditManifest:
    """Create a new audit manifest with pre-filled provenance.

    Call this at the start of a scan run, then pass the manifest through
    ``finalize_manifest`` when the scan completes.
    """
    try:
        from argus import __version__
    except ImportError:
        __version__ = "unknown"

    ci = detect_platform()
    now = datetime.now(timezone.utc).isoformat()

    config_hash = ""
    if config_path and Path(config_path).exists():
        content = Path(config_path).read_bytes()
        config_hash = hashlib.sha256(content).hexdigest()

    return AuditManifest(
        argus_version=__version__,
        scan_id=str(uuid.uuid4()),
        started_at=now,
        platform=asdict(ci),
        hostname=platform.node(),
        python_version=platform.python_version(),
        os_info=f"{platform.system()} {platform.release()}",
        scan_targets=scan_targets or [],
        config_file=config_path or "",
        config_hash=config_hash,
    )


def finalize_manifest(
    manifest: AuditManifest,
    summary: Any = None,
    exit_code: int = 0,
    output_dir: str | Path = "./argus-results",
) -> Path:
    """Finalize and save the audit manifest after scan completes.

    Fills in: completion time, duration, findings summary, and an
    inventory of every artifact in *output_dir* (with SHA-256 hashes).
    """
    now = datetime.now(timezone.utc)
    manifest.completed_at = now.isoformat()

    if manifest.started_at:
        started = datetime.fromisoformat(manifest.started_at)
        manifest.duration_ms = int((now - started).total_seconds() * 1000)

    manifest.exit_code = exit_code

    # Summarize findings if a ScanSummary is provided
    if summary and hasattr(summary, "results"):
        manifest.scanners_executed = [r.scanner for r in summary.results]
        manifest.findings_summary = {
            "critical": getattr(summary, "critical_count", 0),
            "high": getattr(summary, "high_count", 0),
            "medium": getattr(summary, "medium_count", 0),
            "low": getattr(summary, "low_count", 0),
            "total": getattr(summary, "total_count", 0),
        }
        # Capture container image digests from scan metadata
        for result in summary.results:
            meta = getattr(result, "metadata", {}) or {}
            if meta.get("image") and meta.get("digest"):
                manifest.container_images[result.scanner] = {
                    "image": meta["image"],
                    "digest": meta["digest"],
                }

    # Flush all log handlers so argus.log is complete before hashing.
    # Without this, the log file hash in the manifest won't match the
    # final file because the logger writes entries after hashing.
    import logging
    for handler in logging.getLogger("argus").handlers:
        handler.flush()

    # Inventory output artifacts (hash each file for integrity).
    # Exclude argus-audit.json (self-referential) and argus.log
    # (still being written to by the active logger).
    _EXCLUDE_FROM_HASH = {"argus-audit.json", "argus.log"}

    dest = Path(output_dir)
    if dest.exists():
        manifest.artifacts = [
            {
                "path": str(f.relative_to(dest)),
                "size_bytes": f.stat().st_size,
                "sha256": hashlib.sha256(f.read_bytes()).hexdigest(),
            }
            for f in sorted(dest.rglob("*"))
            if f.is_file() and f.name not in _EXCLUDE_FROM_HASH
        ]

    return manifest.save(output_dir)
