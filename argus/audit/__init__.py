"""Audit module -- structured logging, audit trails, and CI platform detection."""

from .logger import get_logger
from .manifest import AuditManifest, create_manifest, finalize_manifest
from .platform import CIPlatform, detect_platform
from .secrets import mask_secrets

__all__ = [
    "AuditManifest",
    "CIPlatform",
    "create_manifest",
    "detect_platform",
    "finalize_manifest",
    "get_logger",
    "mask_secrets",
]
