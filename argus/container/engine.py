"""Container scanning lifecycle engine.

Orchestrates discovery, build, scan, cleanup, and aggregation.
Manages resources (disk space, Docker images) to prevent exhaustion
on constrained environments like CI runners.
"""

import logging

from .builder import build_image
from .discovery import (
    ContainerTarget,
    discover_dockerfiles,
    parse_container_config,
)
from .resources import (
    check_disk_space,
    prune_dangling_images,
    prune_docker_build_cache,
    remove_docker_image,
)
from .scanner import ContainerScanResult, ContainerScanSummary, scan_image

logger = logging.getLogger("argus.container")


class ContainerEngine:
    """Orchestrates container discovery, build, scan, and reporting.

    Processes containers sequentially, cleaning up images and temp
    files after each scan to keep disk usage bounded. For CI
    parallelism, use matrix strategy in the workflow instead.

    Config dict matches the ``containers`` section of argus.yml::

        containers:
          images:
            - image: myapp:latest
              dockerfile: Dockerfile
          discover: true
          search_paths: [".", "docker/"]
          scanners: "trivy,grype"
          sbom: true
          cleanup: true          # Remove images after scanning (default)
    """

    def __init__(self, config: dict):
        self.config = config
        self._cleanup = config.get("cleanup", True)
        self._built_images: list[str] = []

    def run(self) -> ContainerScanSummary:
        """Execute the full container scanning lifecycle.

        1. Check available disk space
        2. Discover or parse container targets
        3. For each target:
           a. Check disk space (abort if critically low)
           b. Build image (if Dockerfile provided)
           c. Scan with trivy + grype
           d. Clean up image to free disk
        4. Final cleanup (dangling images, build cache)
        5. Return aggregated summary
        """
        free_bytes, sufficient = check_disk_space()
        if not sufficient:
            logger.error(
                "Insufficient disk space (%.1f GB free). "
                "Need at least 2 GB to scan containers.",
                free_bytes / (1024 ** 3),
            )
            return ContainerScanSummary()

        targets = self._resolve_targets()
        if not targets:
            logger.warning("No container targets found")
            return ContainerScanSummary()

        logger.info(
            "Scanning %d container(s) — cleanup=%s",
            len(targets),
            self._cleanup,
        )
        results: list[ContainerScanResult] = []

        for i, target in enumerate(targets, 1):
            logger.info(
                "[%d/%d] Processing %s", i, len(targets), target.name,
            )

            # Pre-scan disk check
            free_bytes, sufficient = check_disk_space()
            if not sufficient:
                logger.error(
                    "Disk space critically low before scanning %s — "
                    "aborting remaining scans",
                    target.name,
                )
                results.append(ContainerScanResult(
                    name=target.name,
                    image_ref=target.image_ref,
                    build_success=False,
                    scan_error="Aborted: insufficient disk space",
                ))
                break

            result = self._process_target(target)
            results.append(result)

            # Post-scan cleanup — free disk for the next container
            if self._cleanup:
                self._cleanup_after_scan(target)

        # Final cleanup pass
        if self._cleanup:
            self._final_cleanup()

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
                    "Build failed for %s — skipping scan", target.name,
                )
                return ContainerScanResult(
                    name=target.name,
                    image_ref=target.image_ref,
                    build_success=False,
                    scan_error=f"Docker build failed for {target.dockerfile}",
                )
            self._built_images.append(target.image_ref)

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

    def _cleanup_after_scan(self, target: ContainerTarget) -> None:
        """Clean up resources after scanning one container.

        Removes the scanned image if it was built by us (not a
        pre-existing image the user might want to keep).
        """
        if target.dockerfile and target.image_ref in self._built_images:
            removed = remove_docker_image(target.image_ref)
            if removed:
                self._built_images.remove(target.image_ref)
                logger.debug("Cleaned up built image: %s", target.image_ref)

    def _final_cleanup(self) -> None:
        """Clean up after all scans complete.

        Removes any remaining built images and prunes dangling images
        left by failed builds.
        """
        for image_ref in list(self._built_images):
            remove_docker_image(image_ref)
        self._built_images.clear()

        prune_dangling_images()

        # If disk is low after all scans, prune build cache too
        free_bytes, _ = check_disk_space()
        if free_bytes < 5 * 1024 * 1024 * 1024:
            prune_docker_build_cache()

    def _resolve_targets(self) -> list[ContainerTarget]:
        """Get targets from config or discovery."""
        targets = parse_container_config(self.config)

        if not targets and not self.config.get("images"):
            search_paths = self.config.get("search_paths", ["."])
            targets = discover_dockerfiles(search_paths)

        return targets

    def _scanners(self) -> tuple[str, ...]:
        """Get enabled sub-scanners from config."""
        raw = self.config.get("scanners", ["trivy", "grype"])
        if isinstance(raw, str):
            return tuple(s.strip().lower() for s in raw.split(",") if s.strip())
        return tuple(s.strip().lower() for s in raw if s.strip())

    def _sbom_enabled(self) -> bool:
        """Check if SBOM generation is enabled."""
        return self.config.get("sbom", True)
