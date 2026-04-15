"""Argus engine — orchestrates scanner execution and result aggregation."""

import logging
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from .config import ArgusConfig
from .models import ScanResult, ScanSummary
from .scanner import Scanner

logger = logging.getLogger("argus")


class ArgusEngine:
    """Orchestrates registered scanners and aggregates their results."""

    def __init__(self, config: ArgusConfig):
        self.config = config
        self._scanners: dict[str, Scanner] = {}

    def register_scanner(self, scanner: Scanner) -> None:
        """Register a scanner instance for use by the engine."""
        self._scanners[scanner.name] = scanner
        logger.debug(
            "Registered scanner: %s (available=%s, image=%s)",
            scanner.name,
            scanner.is_available(),
            getattr(scanner, "container_image", "none"),
        )

    def run(
        self,
        scanner_names: list[str] | None = None,
        path: str | None = None,
        fail_fast: bool = False,
        timeout: int | None = None,
        exclude: str = "",
    ) -> ScanSummary:
        """Run scanners and return an aggregated ScanSummary.

        Args:
            scanner_names: specific scanners to run (None = all enabled)
            path: override scan path for all scanners
            fail_fast: abort immediately if any scanner fails
            timeout: per-scanner timeout in seconds (None = no limit)
            exclude: comma-separated CLI exclusion patterns
        """
        from .exclusions import build_exclusion_set, log_exclusion_set

        names_to_run = self._resolve_scanner_names(scanner_names)
        logger.debug(
            "Resolved scanners to run: %s (from requested=%s)",
            names_to_run,
            scanner_names,
        )

        # Build unified exclusion set from ignore files + config + CLI
        scan_root = path or "."
        exclusion_patterns = build_exclusion_set(
            scan_path=scan_root,
            cli_excludes=exclude,
        )
        log_exclusion_set(exclusion_patterns)

        results: list[ScanResult] = []

        for name in names_to_run:
            scanner = self._scanners.get(name)
            if scanner is None:
                logger.warning(
                    "Scanner '%s' is not registered — skipping. "
                    "Registered scanners: %s",
                    name,
                    list(self._scanners.keys()),
                )
                continue

            scanner_config = self.config.get_scanner_config(name)
            scan_path = path if path is not None else scanner_config.path
            config_dict = self._build_scanner_config_dict(scanner_config)

            # Merge per-scanner excludes with global exclusion set
            scanner_exclude = config_dict.get("exclude", "")
            combined_patterns = build_exclusion_set(
                scan_path=scan_path,
                cli_excludes=exclude,
                config_excludes=scanner_exclude,
            ) if scanner_exclude else exclusion_patterns

            # Pass exclusion patterns to scanner via config
            if combined_patterns:
                config_dict["exclude"] = ",".join(combined_patterns)

            logger.info("Starting scanner: %s (path=%s)", name, scan_path)
            logger.debug("Scanner config: %s", config_dict)
            start = time.monotonic()

            try:
                result = self._run_scanner_with_timeout(
                    scanner, scan_path, config_dict, timeout,
                )

                # Post-scan safety net — filter findings from excluded paths
                if combined_patterns and result.findings:
                    from .exclusions import filter_findings
                    filtered_findings, excluded_count = filter_findings(
                        result.findings, combined_patterns,
                    )
                    if excluded_count:
                        logger.info(
                            "Filtered %d finding(s) from excluded paths for '%s'",
                            excluded_count,
                            name,
                        )
                        result = ScanResult(
                            scanner=result.scanner,
                            findings=filtered_findings,
                            raw_report=result.raw_report,
                            sarif_report=result.sarif_report,
                            metadata=result.metadata,
                        )

                elapsed = int((time.monotonic() - start) * 1000)
                logger.info(
                    "Scanner '%s' completed in %dms: %d finding(s)",
                    name,
                    elapsed,
                    result.total_count,
                )
                results.append(result)
            except Exception:
                elapsed = int((time.monotonic() - start) * 1000)
                logger.exception(
                    "Scanner '%s' failed after %dms", name, elapsed,
                )
                if fail_fast:
                    logger.error(
                        "Aborting scan — --fail-fast is set and '%s' failed",
                        name,
                    )
                    break

        return ScanSummary(
            results=results,
            severity_threshold=self.config.reporting.severity_threshold,
        )

    def get_available_scanners(self) -> list[str]:
        """Return names of registered scanners that are currently available."""
        return [
            name
            for name, scanner in self._scanners.items()
            if scanner.is_available()
        ]

    # ------------------------------------------------------------------
    # Docker execution support
    # ------------------------------------------------------------------

    def _is_docker_available(self) -> bool:
        """Check if docker CLI is available."""
        available = shutil.which("docker") is not None
        if not available:
            logger.debug("Docker CLI not found in PATH")
        return available

    def _get_image_digest(self, image: str) -> str:
        """Get the SHA256 digest of a Docker image.

        This is the immutable identifier — tags can be re-pushed,
        digests cannot. Critical for supply chain forensics.
        """
        try:
            result = subprocess.run(
                ["docker", "image", "inspect", image,
                 "--format", "{{index .RepoDigests 0}}"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0 and result.stdout.strip():
                digest = result.stdout.strip()
                # Extract just the sha256:... part if full ref is returned
                if "@" in digest:
                    return digest.split("@", 1)[1]
                return digest
            # Fallback to image ID (local builds don't have repo digests)
            result = subprocess.run(
                ["docker", "image", "inspect", image,
                 "--format", "{{.Id}}"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except (subprocess.TimeoutExpired, Exception):
            pass
        return "unknown"

    def _pull_image(self, image: str) -> bool:
        """Pull a container image based on pull policy."""
        policy = self.config.execution.pull_policy
        logger.debug("Pull policy: %s for image: %s", policy, image)

        if policy == "never":
            logger.debug("Pull policy is 'never' — checking local images only")
            result = subprocess.run(
                ["docker", "image", "inspect", image],
                capture_output=True,
            )
            found = result.returncode == 0
            if not found:
                logger.warning(
                    "Image '%s' not found locally and pull_policy=never", image,
                )
            return found

        if policy == "if-not-present":
            result = subprocess.run(
                ["docker", "image", "inspect", image],
                capture_output=True,
            )
            if result.returncode == 0:
                digest = self._get_image_digest(image)
                logger.debug(
                    "Image '%s' found locally — skipping pull (digest=%s)",
                    image,
                    digest,
                )
                return True
            logger.debug("Image '%s' not found locally — pulling", image)

        # Pull the image — may take minutes for large images.
        # Progress is visible via the CLI spinner or audit log.
        logger.info(
            "Pulling container image: %s (this may take a moment)", image,
        )
        start = time.monotonic()
        result = subprocess.run(
            ["docker", "pull", image],
            capture_output=True,
            text=True,
        )
        elapsed = int((time.monotonic() - start) * 1000)

        if result.returncode != 0:
            logger.info(
                "Native pull failed for %s (%dms), retrying with "
                "--platform linux/amd64. stderr: %s",
                image,
                elapsed,
                result.stderr.strip()[:200],
            )
            start = time.monotonic()
            result = subprocess.run(
                ["docker", "pull", "--platform", "linux/amd64", image],
                capture_output=True,
                text=True,
            )
            elapsed = int((time.monotonic() - start) * 1000)

        if result.returncode == 0:
            digest = self._get_image_digest(image)
            logger.info(
                "Pulled %s in %dms (digest=%s)", image, elapsed, digest,
            )
        else:
            logger.error(
                "Failed to pull %s after %dms. stderr: %s",
                image,
                elapsed,
                result.stderr.strip()[:300],
            )
        return result.returncode == 0

    def _resolve_image(self, scanner) -> str:
        """Resolve the full container image reference, applying registry override."""
        image = getattr(scanner, "container_image", "")
        if not image:
            return ""

        registry = self.config.execution.registry
        if registry:
            parts = image.split("/", 1)
            if len(parts) == 2 and ("." in parts[0] or ":" in parts[0]):
                image = f"{registry}/{parts[1]}"
            else:
                image = f"{registry}/{image}"
            logger.debug("Registry override: %s", image)

        return image

    def _run_in_container(
        self, scanner, path: str, config: dict | None
    ) -> ScanResult:
        """Run a scanner in a Docker container."""
        image = self._resolve_image(scanner)

        if not self._pull_image(image):
            raise RuntimeError(f"Failed to pull container image: {image}")

        digest = self._get_image_digest(image)
        logger.info(
            "Running '%s' in container: %s (digest=%s)",
            scanner.name,
            image,
            digest,
        )

        abs_path = str(Path(path).resolve())

        with tempfile.TemporaryDirectory() as output_dir:
            docker_cmd = [
                "docker", "run", "--rm",
                "-v", f"{abs_path}:/workspace:ro",
                "-v", f"{output_dir}:/output",
            ]

            entrypoint = getattr(scanner, "container_entrypoint", None)
            if entrypoint:
                docker_cmd.extend(["--entrypoint", entrypoint])
                logger.debug("Overriding entrypoint: %s", entrypoint)

            container_args = scanner.container_args(config)
            docker_cmd.extend([image] + container_args)

            logger.debug(
                "Docker command: docker run --rm -v ...:/workspace:ro "
                "-v ...:/output %s %s",
                image,
                " ".join(container_args),
            )

            start = time.monotonic()
            proc = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
            )
            elapsed = int((time.monotonic() - start) * 1000)

            logger.debug(
                "Container exited: code=%d, duration=%dms, "
                "stdout=%d bytes, stderr=%d bytes",
                proc.returncode,
                elapsed,
                len(proc.stdout),
                len(proc.stderr),
            )

            if proc.returncode != 0 and proc.stderr.strip():
                logger.debug(
                    "Container stderr: %s", proc.stderr.strip()[:500],
                )

            # Parse results from output directory
            output_path = Path(output_dir)
            result_files = (
                list(output_path.glob("*.json"))
                + list(output_path.glob("*.txt"))
                + list(output_path.glob("*.sarif"))
            )

            # Capture stdout if no output files
            if not result_files and proc.stdout.strip():
                stdout_file = output_path / "stdout.txt"
                stdout_file.write_text(proc.stdout)
                result_files = [stdout_file]
                logger.debug("No output files — captured stdout (%d bytes)", len(proc.stdout))

            if result_files:
                logger.debug(
                    "Output files: %s",
                    [f.name for f in result_files],
                )
            else:
                logger.warning(
                    "Scanner '%s' produced no output files and no stdout",
                    scanner.name,
                )

            findings = []
            metadata_extra = {}
            if result_files and hasattr(scanner, "parse_results"):
                parsed = scanner.parse_results(result_files[0])
                # parse_results may return a list or a (list, extra) tuple
                if isinstance(parsed, tuple):
                    findings, extra = parsed
                    if isinstance(extra, int):
                        metadata_extra["passed_count"] = extra
                else:
                    findings = parsed
                logger.debug(
                    "Parsed %d finding(s) from %s",
                    len(findings),
                    result_files[0].name,
                )

            return ScanResult(
                scanner=scanner.name,
                findings=findings,
                metadata={
                    "execution": "container",
                    "image": image,
                    "digest": digest,
                    **metadata_extra,
                },
            )

    def _run_scanner_with_timeout(
        self, scanner, path: str, config: dict | None,
        timeout: int | None = None,
    ) -> ScanResult:
        """Run a scanner with an optional timeout (seconds).

        Executes _run_scanner in a thread so we can enforce a wall-clock
        limit without requiring scanners to be timeout-aware.
        """
        if timeout is None:
            return self._run_scanner(scanner, path, config)

        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(self._run_scanner, scanner, path, config)
            try:
                return future.result(timeout=timeout)
            except concurrent.futures.TimeoutError:
                raise RuntimeError(
                    f"Scanner '{scanner.name}' timed out after {timeout}s"
                )

    def _run_scanner(
        self, scanner, path: str, config: dict | None
    ) -> ScanResult:
        """Run a scanner using the appropriate backend.

        Backend selection:
          local  - use locally installed tools only, fail if not installed
          auto   - containers first (immutable), local fallback if no image
          docker - containers only, fail if unavailable
        """
        backend = self.config.execution.backend

        # Explicit local: user accepts version risk
        if backend == "local":
            if not scanner.is_available():
                raise RuntimeError(
                    f"Scanner '{scanner.name}' not installed locally. "
                    f"Install: {scanner.install_command()}"
                )
            logger.debug(
                "Backend 'local': running '%s' via local tool", scanner.name,
            )
            return scanner.scan(path, config)

        # auto or docker: prefer containers for immutable execution
        if backend in ("auto", "docker"):
            container_image = getattr(scanner, "container_image", "")

            if container_image and self._is_docker_available():
                logger.debug(
                    "Backend '%s': using container for '%s' (image=%s)",
                    backend,
                    scanner.name,
                    container_image,
                )
                try:
                    return self._run_in_container(scanner, path, config)
                except RuntimeError as exc:
                    if backend == "docker":
                        raise
                    # auto mode: container failed, try local fallback
                    logger.warning(
                        "Container execution failed for '%s': %s — "
                        "trying local fallback",
                        scanner.name,
                        exc,
                    )

            # docker backend requires containers — fail explicitly
            if backend == "docker":
                if not container_image:
                    raise RuntimeError(
                        f"Scanner '{scanner.name}' has no container image "
                        f"and backend is 'docker'."
                    )
                raise RuntimeError(
                    f"Docker not available. "
                    f"Install Docker: https://docs.docker.com/get-docker/"
                )

            # auto fallback: use local tool
            if scanner.is_available():
                logger.info(
                    "Falling back to local tool for '%s'",
                    scanner.name,
                )
                return scanner.scan(path, config)

            raise RuntimeError(
                f"Scanner '{scanner.name}' is not available. "
                f"Install: {scanner.install_command()}"
            )

        raise RuntimeError(
            f"Unknown execution backend '{backend}' for scanner '{scanner.name}'"
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _resolve_scanner_names(self, requested: list[str] | None) -> list[str]:
        """Determine which scanners to run."""
        if requested is not None:
            return requested

        return [
            name
            for name in self._scanners
            if self.config.get_scanner_config(name).enabled
        ]

    @staticmethod
    def _build_scanner_config_dict(scanner_config) -> dict:
        """Flatten a ScannerConfig into a plain dict for the scanner."""
        config_dict: dict = {}
        if scanner_config.config_file:
            config_dict["config_file"] = scanner_config.config_file
        if scanner_config.severity_threshold:
            config_dict["severity_threshold"] = scanner_config.severity_threshold.value
        if scanner_config.extra:
            config_dict.update(scanner_config.extra)
        return config_dict
