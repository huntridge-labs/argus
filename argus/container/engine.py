"""Container scanning lifecycle engine."""

import logging

from .builder import build_image
from .discovery import (
    ContainerTarget,
    discover_dockerfiles,
    parse_container_config,
)
from .scanner import ContainerScanResult, ContainerScanSummary, scan_image

logger = logging.getLogger("argus.container")


class ContainerEngine:
    """Orchestrates container discovery, build, scan, and reporting.

    Accepts a config dict matching the ``containers`` section of
    argus.yml::

        containers:
          images:
            - image: myapp:latest
              dockerfile: Dockerfile
          discover: true
          search_paths: [".", "docker/"]
          scanners: "trivy,grype"
          sbom: true
    """

    def __init__(self, config: dict):
        self.config = config

    def run(self) -> ContainerScanSummary:
        """Execute the full container scanning lifecycle.

        1. Discover or parse container targets
        2. Build images (if Dockerfiles provided)
        3. Scan each image with trivy + grype
        4. Deduplicate findings
        5. Return aggregated summary
        """
        targets = self._resolve_targets()
        if not targets:
            logger.warning("No container targets found")
            return ContainerScanSummary()

        logger.info("Found %d container target(s) to scan", len(targets))
        results: list[ContainerScanResult] = []

        for target in targets:
            result = self._process_target(target)
            results.append(result)

        summary = ContainerScanSummary(results=results)
        logger.info(
            "Container scan complete: %d image(s), %d total findings, "
            "%d unique, %d build failure(s)",
            summary.container_count,
            summary.total_count,
            summary.unique_count,
            summary.build_failures,
        )
        return summary

    def _process_target(self, target: ContainerTarget) -> ContainerScanResult:
        """Build (if needed) and scan a single container target."""
        if target.dockerfile:
            success = build_image(target)
            if not success:
                logger.error(
                    "Build failed for %s — skipping scan", target.name
                )
                return ContainerScanResult(
                    name=target.name,
                    image_ref=target.image_ref,
                    build_success=False,
                    scan_error=f"Docker build failed for {target.dockerfile}",
                )

        try:
            return scan_image(
                target,
                scanners=self._scanners(),
                sbom=self._sbom_enabled(),
            )
        except Exception:
            logger.exception("Scan failed for %s", target.name)
            return ContainerScanResult(
                name=target.name,
                image_ref=target.image_ref,
                scan_error=f"Scan failed for {target.image_ref}",
            )

    def _resolve_targets(self) -> list[ContainerTarget]:
        """Get targets from config or discovery."""
        targets = parse_container_config(self.config)

        # If no explicit images and no discover flag, try auto-discovery
        containers = self.config.get("containers", {})
        if not targets and not containers.get("images"):
            search_paths = containers.get("search_paths", ["."])
            targets = discover_dockerfiles(search_paths)

        return targets

    def _scanners(self) -> tuple[str, ...]:
        """Get enabled sub-scanners from config."""
        containers = self.config.get("containers", {})
        raw = containers.get("scanners", "trivy,grype")
        return tuple(s.strip().lower() for s in raw.split(",") if s.strip())

    def _sbom_enabled(self) -> bool:
        """Check if SBOM generation is enabled."""
        containers = self.config.get("containers", {})
        return containers.get("sbom", True)
