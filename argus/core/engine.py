"""Argus engine — orchestrates scanner execution and result aggregation."""

import logging
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from .config import ArgusConfig
from .models import ScanResult, ScanSummary
from .scanner import Scanner

logger = logging.getLogger("argus")


# Canonical extensions for SBOM formats — osv-scanner v2 detects format from file extension.
# Keys are the allowed sbom_format values; any other value triggers a warning.
SBOM_FORMAT_EXTENSIONS: dict[str, str] = {
    "spdx-json": ".spdx.json",
    "spdx-tv": ".spdx",
    "cyclonedx-json": ".cdx.json",
    "cyclonedx-xml": ".cdx.xml",
}


class ArgusEngine:
    """Orchestrates registered scanners and aggregates their results."""

    def __init__(self, config: ArgusConfig):
        self.config = config
        self._scanners: dict[str, Scanner] = {}
        self._allow_local_versions: bool = False
        self._no_cache: bool = False
        self._sbom_path: str | None = None
        self._sbom_format: str | None = None

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
        parallel: bool = True,
        allow_local_versions: bool = False,
        no_cache: bool = False,
        use_default_excludes: bool = True,
        sbom_path: str | None = None,
        sbom_format: str | None = None,
    ) -> ScanSummary:
        """Run scanners and return an aggregated ScanSummary.

        Args:
            scanner_names: specific scanners to run (None = all enabled)
            path: override scan path for all scanners
            fail_fast: abort immediately if any scanner fails
            timeout: per-scanner timeout in seconds (None = no limit)
            exclude: comma-separated CLI exclusion patterns
            parallel: run scanners concurrently (default True)
            allow_local_versions: skip version enforcement for local tools
            no_cache: disable DB cache volume mounts for containers
            use_default_excludes: include built-in defaults and ignore-file
                patterns (True by default). Set False when the caller wants
                their --exclude value to be the complete pattern set.
            sbom_path: path to a pre-built SBOM. When set, the engine
                restricts the run to scanners whose ``supports_sbom``
                attribute is True, auto-enables them regardless of
                argus.yml, and threads the SBOM path through
                ``config_dict['sbom_path']``.
        """
        from .exclusions import build_exclusion_set, log_exclusion_set

        self._allow_local_versions = allow_local_versions
        self._no_cache = no_cache
        self._use_default_excludes = use_default_excludes
        self._sbom_path = sbom_path
        self._sbom_format = sbom_format

        # Validate sbom_format if provided
        if sbom_format is not None and sbom_format not in SBOM_FORMAT_EXTENSIONS:
            logger.warning(
                "Unrecognized sbom_format '%s' — expected one of %s. "
                "Falling back to extension detection from sbom_path.",
                sbom_format,
                list(SBOM_FORMAT_EXTENSIONS.keys()),
            )

        if sbom_path is not None:
            names_to_run = self._resolve_sbom_scanner_names(scanner_names)
        else:
            names_to_run = self._resolve_scanner_names(scanner_names)
        logger.debug(
            "Resolved scanners to run: %s (from requested=%s, sbom=%s)",
            names_to_run,
            scanner_names,
            sbom_path,
        )

        # Build unified exclusion set from ignore files + config + CLI
        scan_root = path or "."
        exclusion_patterns = build_exclusion_set(
            scan_path=scan_root,
            cli_excludes=exclude,
            use_defaults=use_default_excludes,
        )
        log_exclusion_set(exclusion_patterns)

        # Prepare scanner jobs
        jobs = self._prepare_jobs(
            names_to_run, path, exclude, exclusion_patterns,
        )

        if not jobs:
            return ScanSummary(
                results=[],
                severity_threshold=self.config.reporting.severity_threshold,
            )

        # Run sequentially for single scanner or when parallel disabled
        if len(jobs) == 1 or not parallel:
            results = self._run_sequential(jobs, timeout, fail_fast)
        else:
            results = self._run_parallel(jobs, timeout, fail_fast)

        # TODO: Add total_duration_ms to ScanSummary for audit trail.
        # Requires a model change (new field on the ScanSummary dataclass).
        # Per-scanner duration_ms is already recorded in each ScanResult.metadata.
        return ScanSummary(
            results=results,
            severity_threshold=self.config.reporting.severity_threshold,
        )

    def _prepare_jobs(
        self,
        names_to_run: list[str],
        path: str | None,
        exclude: str,
        exclusion_patterns: list[str],
    ) -> list[tuple]:
        """Build (scanner, scan_path, config_dict, patterns) tuples."""
        from .exclusions import build_exclusion_set
        from .tool_config import resolve_config

        use_defaults = getattr(self, "_use_default_excludes", True)

        jobs = []
        resolutions = []
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

            # SBOM mode: inject the sbom_path into the scanner config so
            # each scanner's container_args / _build_command pick it up.
            # A dedicated ``/sbom/<basename>`` mount path avoids colliding
            # with arbitrary files a user's scan_path might already hold
            # under /workspace. The bind mount itself is added later in
            # ``_run_in_container`` when we build the docker command.
            if self._sbom_path:
                config_dict["sbom_path"] = self._sbom_path
                # Use format-canonical basename so scanners detect format from extension.
                # When sbom_format is provided and valid, use its canonical extension.
                # Otherwise, fall back to the file's extension(s) — using suffixes[-2:]
                # to preserve compound extensions like .spdx.json or .cdx.json.
                ext = SBOM_FORMAT_EXTENSIONS.get(self._sbom_format)
                if ext is None:
                    suffixes = Path(self._sbom_path).suffixes
                    ext = "".join(suffixes[-2:]) if len(suffixes) >= 2 else "".join(suffixes)
                config_dict["sbom_mount_path"] = f"/sbom/sbom{ext}"

            # Resolve the scanner's tool config file. Explicit `config_file:`
            # in argus.yml wins; otherwise we auto-discover against the scan
            # root so users who drop a `.bandit` / `.checkov.yaml` / etc. at
            # the project root get suppressions applied without manual wiring.
            resolution = resolve_config(
                name, scan_path, config_dict.get("config_file"),
            )
            if resolution.path:
                # Scanner container_args() prepends /workspace/ to whatever
                # path we pass, so store a scan-root-relative path when the
                # resolved file lives under scan_path. For absolute paths
                # outside scan_path (rare — user points at a shared config
                # elsewhere) we pass through unchanged; container wrappers
                # handle that case with an extra bind mount if needed.
                config_dict["config_file"] = _relativize_config_path(
                    resolution.path, scan_path,
                )
            resolutions.append(resolution)

            # Merge per-scanner excludes with global exclusion set
            scanner_exclude = config_dict.get("exclude", "")
            combined_patterns = build_exclusion_set(
                scan_path=scan_path,
                cli_excludes=exclude,
                config_excludes=scanner_exclude,
                use_defaults=use_defaults,
            ) if scanner_exclude else exclusion_patterns

            if combined_patterns:
                config_dict["exclude"] = ",".join(combined_patterns)

            jobs.append((scanner, scan_path, config_dict, combined_patterns))

        # Make tool-config resolution visible to callers (CLI verbose/dry-run).
        self._last_resolutions = resolutions
        from .tool_config import log_resolutions
        log_resolutions(resolutions)

        return jobs

    def _run_one_scanner(
        self,
        scanner,
        scan_path: str,
        config_dict: dict,
        exclusion_patterns: list[str],
        timeout: int | None,
    ) -> ScanResult:
        """Execute a single scanner with exclusion filtering."""
        result = self._run_scanner_with_timeout(
            scanner, scan_path, config_dict, timeout,
        )

        # Record tool version in metadata for audit trail
        if result.metadata.get("execution") == "container":
            from argus.containers import get_expected_version
            result.metadata.setdefault(
                "tool_version",
                get_expected_version(scanner.name) or "unknown",
            )
        else:
            version = self._get_tool_version(scanner)
            if version:
                result.metadata["tool_version"] = version

        # Skip exclusion filter in SBOM mode — findings reference SBOM path, not source
        if exclusion_patterns and result.findings and not config_dict.get("sbom_path"):
            from .exclusions import filter_findings
            filtered_findings, excluded_count = filter_findings(
                result.findings, exclusion_patterns,
            )
            if excluded_count:
                logger.info(
                    "Filtered %d finding(s) from excluded paths for '%s'",
                    excluded_count,
                    scanner.name,
                )
                result = ScanResult(
                    scanner=result.scanner,
                    findings=filtered_findings,
                    raw_report=result.raw_report,
                    sarif_report=result.sarif_report,
                    metadata=result.metadata,
                )

        return result

    def _run_sequential(
        self,
        jobs: list[tuple],
        timeout: int | None,
        fail_fast: bool,
    ) -> list[ScanResult]:
        """Run scanners one at a time."""
        results: list[ScanResult] = []

        for scanner, scan_path, config_dict, patterns in jobs:
            logger.info("Starting scanner: %s (path=%s)", scanner.name, scan_path)
            start = time.monotonic()

            try:
                result = self._run_one_scanner(
                    scanner, scan_path, config_dict, patterns, timeout,
                )
                elapsed = int((time.monotonic() - start) * 1000)
                result.metadata["duration_ms"] = elapsed
                logger.info(
                    "Scanner '%s' completed in %dms: %d finding(s)",
                    scanner.name, elapsed, result.total_count,
                )
                results.append(result)
            except Exception:
                elapsed = int((time.monotonic() - start) * 1000)
                logger.exception(
                    "Scanner '%s' failed after %dms", scanner.name, elapsed,
                )
                if fail_fast:
                    logger.error(
                        "Aborting scan — --fail-fast is set and '%s' failed",
                        scanner.name,
                    )
                    break

        return results

    def _run_parallel(
        self,
        jobs: list[tuple],
        timeout: int | None,
        fail_fast: bool,
    ) -> list[ScanResult]:
        """Run scanners concurrently using a thread pool."""
        import concurrent.futures

        # PERFORMANCE TODO: Consider pre-warming — pull all scanner images in parallel
        # before the scan phase. Currently images are pulled on-demand when each scanner
        # starts, which serializes the first-run pull latency.
        # Also investigate lazy pulls: start scanning tools that are already available
        # while others are still pulling.

        results: list[ScanResult] = []
        max_workers = min(len(jobs), 8)

        logger.info(
            "Running %d scanner(s) in parallel (max %d workers)",
            len(jobs), max_workers,
        )
        start_all = time.monotonic()

        def _timed_run(scanner, scan_path, config_dict, patterns):
            """Run a single scanner and attach timing metadata."""
            start = time.monotonic()
            result = self._run_one_scanner(
                scanner, scan_path, config_dict, patterns, timeout,
            )
            elapsed = int((time.monotonic() - start) * 1000)
            result.metadata["duration_ms"] = elapsed
            return result

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=max_workers,
        ) as pool:
            # Submit all jobs, preserving order
            future_to_name = {}
            for scanner, scan_path, config_dict, patterns in jobs:
                logger.info(
                    "Submitting scanner: %s (path=%s)", scanner.name, scan_path,
                )
                future = pool.submit(
                    _timed_run,
                    scanner, scan_path, config_dict, patterns,
                )
                future_to_name[future] = scanner.name

            # Collect results as they complete
            for future in concurrent.futures.as_completed(future_to_name):
                name = future_to_name[future]
                try:
                    result = future.result()
                    logger.info(
                        "Scanner '%s' finished in %dms: %d finding(s)",
                        name, result.metadata.get("duration_ms", -1),
                        result.total_count,
                    )
                    results.append(result)
                except Exception:
                    logger.exception("Scanner '%s' failed", name)
                    if fail_fast:
                        logger.error(
                            "Aborting scan — --fail-fast and '%s' failed",
                            name,
                        )
                        # Cancel pending futures
                        for f in future_to_name:
                            f.cancel()
                        break

        elapsed = int((time.monotonic() - start_all) * 1000)
        logger.info(
            "Parallel scan completed in %dms (%d scanner(s))",
            elapsed, len(results),
        )

        return results

    def get_available_scanners(self) -> list[str]:
        """Return names of registered scanners that are currently available."""
        return [
            name
            for name, scanner in self._scanners.items()
            if scanner.is_available()
        ]

    # ------------------------------------------------------------------
    # Container runtime support (Docker, Podman, nerdctl)
    # ------------------------------------------------------------------

    _container_runtime: str | None = None

    def _detect_runtime(self) -> str | None:
        """Detect the available container runtime.

        Checks in order:
        1. ARGUS_CONTAINER_RUNTIME env var (explicit override)
        2. docker
        3. podman
        4. nerdctl

        Docker, Podman, and nerdctl are CLI-compatible — same commands,
        same arguments. Argus works with any of them.
        """
        if self._container_runtime is not None:
            return self._container_runtime

        # Explicit override
        override = os.environ.get("ARGUS_CONTAINER_RUNTIME")
        if override and shutil.which(override):
            self._container_runtime = override
            logger.info("Using container runtime: %s (from ARGUS_CONTAINER_RUNTIME)", override)
            return override

        # Auto-detect
        for runtime in ("docker", "podman", "nerdctl"):
            if shutil.which(runtime):
                self._container_runtime = runtime
                if runtime != "docker":
                    logger.info("Using container runtime: %s", runtime)
                return runtime

        logger.debug("No container runtime found (docker, podman, nerdctl)")
        self._container_runtime = ""  # Cache negative result
        return None

    def _is_docker_available(self) -> bool:
        """Check if a container runtime is available."""
        return self._detect_runtime() is not None

    @property
    def _runtime(self) -> str:
        """Return the container runtime command name."""
        return self._detect_runtime() or "docker"

    def _get_image_digest(self, image: str) -> str:
        """Get the SHA256 digest of a Docker image.

        This is the immutable identifier — tags can be re-pushed,
        digests cannot. Critical for supply chain forensics.
        """
        try:
            result = subprocess.run(
                [self._runtime, "image", "inspect", image,
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
                [self._runtime, "image", "inspect", image,
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
        """Pull a container image based on pull policy.

        # PERFORMANCE TODO: Investigate Docker image layer caching across CI runs.
        # GitHub Actions cache action could pre-populate the Docker cache.
        # Also evaluate if pull_policy=if-not-present is effective when runners are ephemeral.
        """
        policy = self.config.execution.pull_policy
        logger.debug("Pull policy: %s for image: %s", policy, image)

        if policy == "never":
            logger.debug("Pull policy is 'never' — checking local images only")
            result = subprocess.run(
                [self._runtime, "image", "inspect", image],
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
                [self._runtime, "image", "inspect", image],
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
            [self._runtime, "pull", image],
            capture_output=True,
            text=True,
        )
        elapsed = int((time.monotonic() - start) * 1000)

        if result.returncode != 0:
            # Distinct from a hard "pull failed" — the retry below
            # almost always succeeds for upstreams that publish amd64-
            # only (clamav, etc.). Word it as a fallback so users
            # reading the log don't misread the line as a scan failure.
            logger.info(
                "%s: native pull unsuccessful (%dms) — auto-falling "
                "back to --platform linux/amd64 (common for upstreams "
                "without arm64 builds). stderr: %s",
                image,
                elapsed,
                result.stderr.strip()[:200],
            )
            start = time.monotonic()
            result = subprocess.run(
                [self._runtime, "pull", "--platform", "linux/amd64", image],
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
            # Make the host-side temp dir world-writable BEFORE the
            # container starts. Python's TemporaryDirectory creates
            # dirs with mode 0o700 (owner-only). When a scanner image
            # runs as a non-root user (e.g., bandit / opengrep / our
            # custom images all use ``USER argus`` uid 1000) and the
            # invoking host user has a different uid (commonly 501 on
            # macOS), the container's process can't write
            # ``/output/results.json`` and we get the silent "produced
            # no output files" failure mode.
            #
            # Mode 0o777 is safe here:
            #  - dir lives under ``tempfile.gettempdir()`` (host-only,
            #    not network-shared)
            #  - random name from ``mkdtemp`` (collision-resistant)
            #  - removed at the end of this with-block
            #  - holds only one scan's transient output (no secrets;
            #    findings travel through ``parse_results`` and end up
            #    in the user-specified output_dir, never here).
            os.chmod(output_dir, 0o777)

            docker_cmd = [
                self._runtime, "run", "--rm",
                "-v", f"{abs_path}:/workspace:ro",
                "-v", f"{output_dir}:/output",
            ]

            # SBOM mount: when the scan is operating on a pre-built SBOM,
            # bind-mount the file itself to the sibling ``/sbom/`` path.
            # Keeping it separate from ``/workspace/`` prevents filename
            # collisions with the user's project files.
            sbom_path = (config or {}).get("sbom_path")
            if sbom_path:
                abs_sbom = str(Path(sbom_path).resolve())
                mount_dest = (config or {}).get("sbom_mount_path") or (
                    f"/sbom/{Path(sbom_path).name}"
                )
                docker_cmd.extend(["-v", f"{abs_sbom}:{mount_dest}:ro"])

            # Mount host-side DB cache to persist vulnerability databases
            if not self._no_cache:
                from ..containers import get_cache_mount
                cache = get_cache_mount(scanner.name)
                if cache:
                    host_dir, container_dir = cache
                    docker_cmd.extend(["-v", f"{host_dir}:{container_dir}"])
                    logger.debug(
                        "DB cache mount: %s → %s", host_dir, container_dir,
                    )

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
                # Surface stderr + return code loudly when the scanner
                # produced nothing — this is the silent-failure mode
                # users hit when the underlying tool rejects the input
                # (e.g. Trivy on SPDX-2.1: "unknown scanning is not yet
                # supported"). A WARN-level summary means "something is
                # wrong" is visible without bumping to DEBUG logging.
                stderr_summary = proc.stderr.strip()
                if stderr_summary:
                    # Cap length so a megabyte of log output doesn't
                    # dominate the terminal; readers with DEBUG enabled
                    # still get the full dump via the earlier log line.
                    clipped = stderr_summary[:800]
                    if len(stderr_summary) > 800:
                        clipped += f" … ({len(stderr_summary) - 800} more bytes)"
                    logger.warning(
                        "Scanner '%s' produced no output files "
                        "(exit=%d). stderr: %s",
                        scanner.name,
                        proc.returncode,
                        clipped,
                    )
                else:
                    logger.warning(
                        "Scanner '%s' produced no output files and "
                        "no stdout (exit=%d).",
                        scanner.name,
                        proc.returncode,
                    )

            findings = []
            metadata_extra = {}
            # Track scanner execution failures distinctly from "ran and
            # found nothing". A scanner that produced no output files and
            # no stdout most likely failed to run — could not write to
            # /output (uid mismatch), crashed without flushing, or had
            # the wrong entrypoint chain. We mark these on the ScanResult
            # so the CLI / reporters can surface them, and so consumers
            # who want hard CI gates can opt into ``--fail-on-scanner-error``
            # without having to grep our log lines.
            if not result_files:
                metadata_extra["execution_failed"] = True
                stderr_clipped = proc.stderr.strip()[:400]
                if stderr_clipped:
                    metadata_extra["execution_failure_reason"] = (
                        f"no output files (exit={proc.returncode}). "
                        f"stderr: {stderr_clipped}"
                    )
                else:
                    metadata_extra["execution_failure_reason"] = (
                        f"no output files and no stdout (exit={proc.returncode})"
                    )
            if result_files and hasattr(scanner, "parse_results"):
                parsed = scanner.parse_results(result_files[0])
                # parse_results may return either a list of Findings,
                # a ``(list, int)`` tuple (legacy passed_count channel,
                # used by linters), or a ``(list, dict)`` tuple (extra
                # metadata merged into ScanResult.metadata — used by
                # Grype to flag "source.target=unknown" which means
                # "couldn't identify packages" rather than "nothing
                # vulnerable").
                if isinstance(parsed, tuple):
                    findings, extra = parsed
                    if isinstance(extra, int):
                        metadata_extra["passed_count"] = extra
                    elif isinstance(extra, dict):
                        metadata_extra.update(extra)
                        # Warn at the engine layer too so the signal is
                        # visible even when a reporter doesn't render
                        # per-scanner metadata.
                        if "warning" in extra:
                            logger.warning(
                                "Scanner '%s': %s",
                                scanner.name, extra["warning"],
                            )
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
        # PERFORMANCE TODO: Benchmark container vs local tool execution per scanner.
        # Docker overhead (image pull + container start) vs native tool startup.
        # Profile to identify if parsing or subprocess is the bottleneck.
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
            self._verify_tool_version(scanner)
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
                    f"No container runtime available. "
                    f"Install Docker, Podman, or nerdctl."
                )

            # auto fallback: use local tool
            if scanner.is_available():
                self._verify_tool_version(scanner)
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
    # Tool version enforcement
    # ------------------------------------------------------------------

    def _verify_tool_version(self, scanner) -> None:
        """Verify local tool version matches expected version.

        When ``_allow_local_versions`` is False (the default), raises
        RuntimeError on mismatch.  When True, logs a WARNING and proceeds.
        """
        from argus.containers import get_expected_version

        expected = get_expected_version(scanner.name)
        if not expected:
            return  # No expected version defined

        actual = None
        if hasattr(scanner, "tool_version"):
            actual = scanner.tool_version()

        if actual is None:
            return  # Can't determine version, allow

        if actual != expected:
            if self._allow_local_versions:
                logger.warning(
                    "Scanner '%s' version mismatch: installed %s, "
                    "expected %s (proceeding — --allow-local-versions set)",
                    scanner.name,
                    actual,
                    expected,
                )
                return

            raise RuntimeError(
                f"Scanner '{scanner.name}' version mismatch: "
                f"installed {actual}, expected {expected}. "
                f"Use --allow-local-versions to bypass."
            )

        logger.debug("Version verified: %s %s", scanner.name, actual)

    @staticmethod
    def _get_tool_version(scanner) -> str | None:
        """Return the tool version string if the scanner supports it."""
        if hasattr(scanner, "tool_version"):
            return scanner.tool_version()
        return None

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

    def _resolve_sbom_scanner_names(
        self, requested: list[str] | None
    ) -> list[str]:
        """Determine which scanners to run when an SBOM is supplied.

        SBOM mode has distinct semantics from filesystem mode:

        - Scanners must declare ``supports_sbom = True`` on the class.
        - When the caller names a scanner explicitly and it doesn't
          support SBOMs, we log a warning and drop it rather than fail
          the whole run — preserves pipeline momentum on a mixed config.
        - When no names are requested, we auto-enable every
          SBOM-capable scanner in the registry, ignoring argus.yml's
          ``enabled:`` flags. The user explicitly asked for full SBOM
          coverage by passing ``--sbom``.
        """
        sbom_capable = {
            name
            for name, scanner in self._scanners.items()
            if getattr(scanner, "supports_sbom", False)
        }
        if requested is None:
            return sorted(sbom_capable)

        resolved = []
        for name in requested:
            if name in sbom_capable:
                resolved.append(name)
            else:
                logger.warning(
                    "Scanner '%s' does not support SBOM input — skipping. "
                    "SBOM-capable scanners: %s",
                    name,
                    ", ".join(sorted(sbom_capable)) or "(none registered)",
                )
        return resolved

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


def _relativize_config_path(config_path: str, scan_path: str) -> str:
    """Return ``config_path`` as scan-root-relative when it lives under scan_path.

    Scanner container wrappers prepend ``/workspace/`` to whatever we return,
    so a relative value is what they want. If the config lives outside the
    scan root (user pointing at a shared config), we return the original
    path unchanged — the local-backend code path accepts absolute paths
    natively, and container wrappers that need this rare case can add a
    bind mount themselves.
    """
    from pathlib import Path
    try:
        cp = Path(config_path).resolve()
        sp = Path(scan_path).resolve()
        return str(cp.relative_to(sp))
    except (ValueError, OSError):
        return config_path
