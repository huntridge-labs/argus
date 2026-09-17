"""Container scanning lifecycle — discover, build, scan, and aggregate."""

from .discovery import ContainerTarget, discover_dockerfiles, parse_container_config
from .builder import build_image
from .scanner import (
    ContainerScanResult,
    ContainerScanSummary,
    RegistryAuthError,
    scan_image,
    deduplicate_findings,
    validate_registry_auth,
)
from argus.scanners.container import validate_sub_scanners
from .engine import ContainerEngine

__all__ = [
    "ContainerTarget",
    "discover_dockerfiles",
    "parse_container_config",
    "build_image",
    "ContainerScanResult",
    "ContainerScanSummary",
    "RegistryAuthError",
    "scan_image",
    "deduplicate_findings",
    "validate_registry_auth",
    "validate_sub_scanners",
    "ContainerEngine",
]
