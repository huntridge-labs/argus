"""Container scanning lifecycle — discover, build, scan, and aggregate."""

from .discovery import ContainerTarget, discover_dockerfiles, parse_container_config
from .builder import build_image
from .scanner import (
    ContainerScanResult,
    ContainerScanSummary,
    scan_image,
    deduplicate_findings,
)
from .engine import ContainerEngine

__all__ = [
    "ContainerTarget",
    "discover_dockerfiles",
    "parse_container_config",
    "build_image",
    "ContainerScanResult",
    "ContainerScanSummary",
    "scan_image",
    "deduplicate_findings",
    "ContainerEngine",
]
