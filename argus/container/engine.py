"""Container scanning lifecycle engine.

Orchestrates discovery, build, scan, cleanup, and aggregation.
Manages resources (disk space, Docker images) to prevent exhaustion
on constrained environments like CI runners.
"""

import logging
import time
from pathlib import Path
from typing import Callable

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

    def __init__(
        self,
        config: dict,
        progress_callback: "Callable[[int, int, str, str, int], None] | None" = None,
    ):
        self.config = config
        self._cleanup = config.get("cleanup", True)
        self._built_images: list[str] = []
        # Progress callback signature: (idx, total, name, phase, elapsed_ms).
        # Default is a no-op so engine code can call ``self._progress(...)``
        # unconditionally without checking. The CLI installs a callback
        # that updates the spinner message or prints a persistent INFO
        # line based on flag combination.
        self._progress: Callable[[int, int, str, str, int], None] = (
            progress_callback or (lambda *a, **kw: None)
        )

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
        targets = self._resolve_targets()
        if not targets:
            logger.warning("No container targets found")
            return ContainerScanSummary()

        check_disk_space()  # Informational only

        logger.info(
            "Scanning %d container(s) — cleanup=%s",
            len(targets),
            self._cleanup,
        )
        results: list[ContainerScanResult] = []

        total = len(targets)
        for i, target in enumerate(targets, 1):
            logger.info(
                "[%d/%d] Processing %s", i, total, target.name,
            )

            # Emit phase progress at each transition. The callback
            # decides whether to update the spinner, print a line, or
            # ignore the event based on the user's CLI flags.
            target_start = time.monotonic()
            initial_phase = "build" if target.dockerfile else "pull"
            self._progress(i, total, target.name, initial_phase, 0)

            result = self._process_target(target, idx=i, total=total, target_start=target_start)
            results.append(result)

            elapsed_ms = int((time.monotonic() - target_start) * 1000)
            self._progress(i, total, target.name, "done", elapsed_ms)

            # Post-scan cleanup — free disk for the next container.
            # Per-target ``cleanup:`` overrides the engine-level default
            # so a long-lived base image can stay cached across runs
            # while ad-hoc dev images get torn down. None on the target
            # means "no override — use the global setting".
            target_cleanup = (
                target.cleanup if target.cleanup is not None else self._cleanup
            )
            if target_cleanup:
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

    def _process_target(
        self,
        target: ContainerTarget,
        idx: int = 1,
        total: int = 1,
        target_start: float | None = None,
    ) -> ContainerScanResult:
        """Build (if needed) and scan a single container target.

        Catches disk space errors and other resource failures
        individually — a failure on one container doesn't stop
        the rest from being scanned.

        ``idx`` / ``total`` / ``target_start`` are progress-tracking
        params used to emit phase events between build and scan.
        Default values keep backward compat for direct test callers.
        """
        if target_start is None:
            target_start = time.monotonic()

        def _elapsed() -> int:
            return int((time.monotonic() - target_start) * 1000)

        if target.dockerfile:
            success = build_image(target)
            if not success:
                error_msg = f"Docker build failed for {target.dockerfile}"
                # If disk is the likely cause, say so
                free = check_disk_space()
                if free < 500 * 1024 * 1024:  # < 500 MB after failure
                    error_msg += " (possibly out of disk space)"
                logger.error(
                    "Build failed for %s — skipping scan", target.name,
                )
                return ContainerScanResult(
                    name=target.name,
                    image_ref=target.image_ref,
                    dockerfile=str(target.dockerfile) if target.dockerfile else "",
                    context=str(target.context) if target.context else "",
                    build_success=False,
                    scan_error=error_msg,
                )
            self._built_images.append(target.image_ref)

        # Build is done (or skipped for remote-pull targets); transition
        # to the scan phase so the spinner updates.
        self._progress(idx, total, target.name, "scan", _elapsed())

        try:
            # If the dispatcher set ``_raw_output_root`` in the
            # config dict, persist this target's raw scanner outputs
            # under ``<root>/<target.name>/``. Caller controls
            # whether this is set (CLI flag + config opt-out); the
            # engine just threads it through.
            raw_root = self.config.get("_raw_output_root")
            target_raw_dir = (
                Path(raw_root) / target.name if raw_root else None
            )
            return scan_image(
                target,
                scanners=self._scanners(),
                sbom=self._sbom_enabled(),
                raw_output_dir=target_raw_dir,
            )
        except OSError as exc:
            # Disk full, permission denied, etc.
            logger.error(
                "OS error scanning %s: %s", target.name, exc,
            )
            return ContainerScanResult(
                name=target.name,
                image_ref=target.image_ref,
                dockerfile=str(target.dockerfile) if target.dockerfile else "",
                context=str(target.context) if target.context else "",
                scan_error=f"OS error: {exc}",
            )
        except Exception:
            logger.exception("Scan failed for %s", target.name)
            return ContainerScanResult(
                name=target.name,
                image_ref=target.image_ref,
                dockerfile=str(target.dockerfile) if target.dockerfile else "",
                context=str(target.context) if target.context else "",
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
        free = check_disk_space()
        if free < 5 * 1024 * 1024 * 1024:
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
