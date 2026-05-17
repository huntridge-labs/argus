"""Argus engine — orchestrates scanner execution and result aggregation."""

import logging
import os
import platform
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from .config import ArgusConfig
from .models import ScanContext, ScanResult, ScanSummary
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


class ScannerPreconditionError(RuntimeError):
    """Raised when a scanner can't run because its inputs are missing or
    invalid — e.g. ``grype`` / ``trivy`` need an SBOM via ``--sbom``.

    The engine treats this distinctly from a runtime/container failure:
    no local fallback dance, no platform-mismatch retry, just surface the
    precondition to the user. Issue #168-I.
    """


def _classify_pull_error(stderr: str) -> tuple[str, bool]:
    """Classify a docker/podman ``pull`` failure for human-readable
    logging and retry policy.

    Returns ``(category, retryable)`` where ``retryable`` is True only
    when retrying with ``--platform linux/amd64`` has a realistic
    chance of fixing the failure. Issue #168-H.
    """
    s = stderr.lower()

    # Daemon-down: socket / connection-refused at the local runtime.
    daemon_markers = (
        "cannot connect to the docker daemon",
        "is the docker daemon running",
        "unix:///var/run/docker.sock",
        "no such file or directory: docker.sock",
        "docker api at unix:///",
    )
    if any(m in s for m in daemon_markers):
        return "docker-daemon-not-running", False

    # Auth — 403 / unauthorized / denied. Includes both registry-side
    # authorization failures and credentials missing locally.
    auth_markers = (
        "403 forbidden",
        "permission_denied",
        "401 unauthorized",
        "unauthorized:",
        "denied: requested access to the resource is denied",
        "no basic auth credentials",
    )
    if any(m in s for m in auth_markers):
        return "registry-auth-403", False

    # Rate-limit — docker hub etc.
    if "toomanyrequests" in s or "rate limit" in s:
        return "registry-rate-limited", False

    # Manifest / image not found at the requested ref. Could be a typo
    # or a missing tag. Not a platform issue; retrying with amd64 won't
    # help.
    not_found_markers = (
        "manifest unknown",
        "manifest for ",
        "not found:",
        "repository does not exist",
    )
    if any(m in s for m in not_found_markers) and "matching manifest" not in s:
        return "image-not-found", False

    # Platform mismatch — the upstream doesn't publish arm64. THIS is
    # the case where the --platform linux/amd64 retry is appropriate.
    platform_markers = (
        "no matching manifest for linux/arm",
        "no matching manifest for ",
        "cannot find amd64 manifest",
        "image platform",
    )
    if any(m in s for m in platform_markers):
        return "platform-mismatch", True

    # Network — connection refused / timeout reaching the registry.
    network_markers = (
        "i/o timeout",
        "dial tcp",
        "connection refused",
        "network is unreachable",
        "no route to host",
        "name resolution failed",
        "temporary failure in name resolution",
    )
    if any(m in s for m in network_markers):
        return "network", False

    # Unclassified — try the amd64 fallback as a last resort but
    # surface that we don't know what went wrong.
    return "unclassified", True


def _failure_result(
    scanner_name: str,
    exc: BaseException,
    duration_ms: int | None = None,
) -> ScanResult:
    """Build a ScanResult representing a scanner that raised during execution.

    Mirrors the ``execution_failed`` metadata that ``_run_in_container``
    produces for output-less docker runs, so the canonical results
    contract is uniform regardless of which path produced the failure.
    A user reviewing argus-results.json sees the scanner with its
    error reason; without this, scanners whose ``scan()`` raises (e.g.
    a missing local binary that subprocess.run can't find) silently
    disappear from the results — exactly the silent-failure pattern
    ADR-016 was written to prevent.
    """
    metadata: dict = {
        "execution_failed": True,
        "execution_failure_reason": f"{type(exc).__name__}: {exc}",
    }
    if duration_ms is not None:
        metadata["duration_ms"] = duration_ms
    return ScanResult(scanner=scanner_name, metadata=metadata)


class ArgusEngine:
    """Orchestrates registered scanners and aggregates their results."""

    def __init__(self, config: ArgusConfig):
        self.config = config
        self._scanners: dict[str, Scanner] = {}
        self._allow_local_versions: bool = False
        self._no_cache: bool = False
        self._sbom_path: str | None = None
        self._sbom_format: str | None = None
        self._raw_output_root: str | None = None
        # Image pre-warm orchestrator. Lazily constructed in ``run()``
        # when the engine has a job list and pull_policy is compatible.
        # Held as engine state (not a per-run local) so ``_run_in_container``
        # can consult it from a worker thread without arg-threading every
        # internal call site.
        self._prewarmer = None
        # Supply-chain verification results, one per container pull this
        # run. Consumed by ``report_tag_pinned_summary`` at end of
        # ``run()`` to emit a single WARNING listing tag-pinned third-
        # party images (rather than N warnings for N scanners).
        from argus.core.image_verify import VerifyResult  # local import
        self._verify_results: list[VerifyResult] = []

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
        raw_output_dir: str | None = None,
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
            raw_output_dir: when set, ``_run_in_container`` copies each
                scanner's raw output files (``results.json``,
                ``stdout.txt``, ``*.sarif``) into
                ``<raw_output_dir>/<scanner_name>/`` before the
                per-scanner tempdir is cleaned up. Mirrors the
                container-scan flow's ``raw/`` artifact preservation
                so users can drill into individual scanner output
                regardless of which scan flow produced it.
        """
        from .exclusions import build_exclusion_set, log_exclusion_set

        self._allow_local_versions = allow_local_versions
        self._no_cache = no_cache
        self._use_default_excludes = use_default_excludes
        self._sbom_path = sbom_path
        self._sbom_format = sbom_format
        self._raw_output_root = raw_output_dir

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
                scan_context=ScanContext.capture(),
            )

        # Pre-warm container images in the background while the engine
        # spins up. Best-effort: a failed warm just means the inline
        # ``_pull_image`` in ``_run_in_container`` does the work.
        # ``pull_policy=never`` skips pre-warm entirely (would be wasted
        # work — the engine refuses to pull anyway). The orchestrator
        # is a no-op when ``prewarm_images: false`` is set in config.
        self._start_prewarm(jobs)

        try:
            # Run sequentially for single scanner or when parallel disabled
            if len(jobs) == 1 or not parallel:
                results = self._run_sequential(jobs, timeout, fail_fast)
            else:
                results = self._run_parallel(jobs, timeout, fail_fast)
        finally:
            # Shut down the prewarmer regardless of how the run ends.
            # ``wait=False`` cancels pending pulls and lets in-flight
            # ones drain on their own (the subprocess holding the
            # network already has the bandwidth — no point racing it).
            self._shutdown_prewarm()

            # Supply-chain: one WARNING per run listing all third-party
            # tag-pinned images. Logged here (not per-scanner) so a
            # user with N scanners pointing at trivy doesn't see N
            # identical warnings.
            from argus.core.image_verify import report_tag_pinned_summary
            report_tag_pinned_summary(self._verify_results)

        # TODO: Add total_duration_ms to ScanSummary for audit trail.
        # Requires a model change (new field on the ScanSummary dataclass).
        # Per-scanner duration_ms is already recorded in each ScanResult.metadata.
        return ScanSummary(
            results=results,
            severity_threshold=self.config.reporting.severity_threshold,
            scan_context=ScanContext.capture(),
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
            except Exception as exc:
                elapsed = int((time.monotonic() - start) * 1000)
                logger.exception(
                    "Scanner '%s' failed after %dms", scanner.name, elapsed,
                )
                # Append a failure-row ScanResult so the user sees the
                # scanner in the canonical results — silently dropping
                # it makes a hard failure look identical to "ran clean
                # with zero findings". Mirrors the execution_failed
                # metadata that ``_run_in_container`` produces for
                # output-less docker runs.
                results.append(_failure_result(scanner.name, exc, elapsed))
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

        # Pre-warm + lazy pulls are wired in via ``_start_prewarm`` (called
        # from ``run()``) and ``_run_in_container`` (consults the prewarmer
        # before falling back to inline pull). Scanners whose images are
        # already cached — either because pre-warm finished or a prior
        # run populated the local store — start scanning immediately
        # instead of contending for registry bandwidth. See
        # ``argus/core/prewarm.py``.

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
                except Exception as exc:
                    logger.exception("Scanner '%s' failed", name)
                    # See _run_sequential for rationale — failure rows
                    # surface in canonical results instead of silently
                    # dropping the scanner.
                    results.append(_failure_result(name, exc))
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

    def _start_prewarm(self, jobs: list[tuple]) -> None:
        """Kick off background pulls for every distinct image in ``jobs``.

        No-op when:
        - ``execution.prewarm_images`` is False (user opt-out)
        - ``execution.pull_policy`` is "never" (would never pull anyway)
        - No container runtime is available (would fail every pull)
        - No scanner in the job list declares a container image (linters
          running locally, or backend=local)

        The orchestrator is best-effort: pre-warm pulls that fail are
        absorbed by the prewarmer, and ``_run_in_container`` falls back
        to inline ``_pull_image`` when ``wait_for`` reports a failed
        warm. This means a missing prewarmer (False, no runtime, etc.)
        and a failed prewarm produce identical user-visible behaviour:
        the existing inline pull path runs.
        """
        from .prewarm import ImagePrewarmer

        execution = self.config.execution
        if not getattr(execution, "prewarm_images", True):
            logger.debug("Pre-warm: disabled via execution.prewarm_images=false")
            return
        if execution.pull_policy == "never":
            logger.debug("Pre-warm: skipped (pull_policy=never)")
            return
        if not self._is_docker_available():
            logger.debug("Pre-warm: skipped (no container runtime)")
            return

        # Build the dedup'd image list using the same _resolve_image
        # path the scan-time code uses, so registry overrides are applied
        # consistently.
        images: list[str] = []
        seen: set[str] = set()
        for scanner, _scan_path, _config_dict, _patterns in jobs:
            image = self._resolve_image(scanner)
            if not image or image in seen:
                continue
            seen.add(image)
            images.append(image)

        if not images:
            logger.debug("Pre-warm: no container images in this run")
            return

        workers = getattr(execution, "prewarm_workers", 4)
        self._prewarmer = ImagePrewarmer(
            pull_fn=self._pull_image, max_workers=workers,
        )
        self._prewarmer.start(images)
        logger.debug(
            "Pre-warm: warming %d distinct image(s) with %d worker(s)",
            len(images), workers,
        )

    def _shutdown_prewarm(self) -> None:
        """Tear down the prewarmer. Idempotent and safe to call twice."""
        if self._prewarmer is None:
            return
        # ``wait=False`` cancels queued pulls; in-flight ones detach.
        # On a normal scan completion they're typically already done;
        # on KeyboardInterrupt this is what frees the threads.
        try:
            self._prewarmer.shutdown(wait=False)
        finally:
            self._prewarmer = None

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
            # Classify the failure so we only do the ``--platform
            # linux/amd64`` retry when the underlying error actually
            # looks like a platform mismatch. Issue #168-H: previously
            # every failure (daemon down, GHCR 403, network blocked)
            # surfaced as "auto-falling back to --platform linux/amd64
            # (common for upstreams without arm64 builds)" which was
            # misleading and produced wasted retry attempts on
            # permanently-failing pulls.
            stderr = result.stderr.strip()
            category, retryable = _classify_pull_error(stderr)
            if retryable:
                logger.info(
                    "%s: native pull failed (%dms, %s) — retrying with "
                    "--platform linux/amd64 (common for upstreams "
                    "without arm64 builds). stderr: %s",
                    image, elapsed, category, stderr[:200],
                )
                start = time.monotonic()
                result = subprocess.run(
                    [self._runtime, "pull", "--platform", "linux/amd64", image],
                    capture_output=True,
                    text=True,
                )
                elapsed = int((time.monotonic() - start) * 1000)
            else:
                logger.error(
                    "%s: pull failed (%dms, %s) — not retrying. "
                    "stderr: %s",
                    image, elapsed, category, stderr[:300],
                )
                return False

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

        # Consult the pre-warm orchestrator first. In parallel mode, this
        # is the lazy-pull path: scanners whose image is already cached
        # (because pre-warm finished, or a prior run populated the local
        # store) start immediately without contending for registry
        # bandwidth. ``NOT_WARMED`` means we never registered this
        # image (e.g. ``pull_policy=never``, prewarm disabled, or the
        # image was registered after start()) — fall through to inline
        # pull. ``False`` means pre-warm tried and failed — same fall-
        # through path so the inline pull's retry / amd64 fallback kicks
        # in.
        warmed = None
        if self._prewarmer is not None:
            from .prewarm import NOT_WARMED
            warmed = self._prewarmer.wait_for(image)
            if warmed is NOT_WARMED:
                warmed = None  # treat as "try inline pull"

        if warmed is not True:
            # Either pre-warm failed, was disabled, or didn't cover this
            # image — run the canonical inline pull. This is the same
            # path that existed before the prewarmer was added; the only
            # change here is we may skip it on a warm cache hit.
            if not self._pull_image(image):
                raise RuntimeError(f"Failed to pull container image: {image}")

        # Supply-chain verification (ADR-024 + roadmap item #3):
        #   - argus-owned images get cosign-verified against the
        #     publish workflow's identity; failure aborts the scanner;
        #   - third-party images with @sha256: digest pins are trusted
        #     by Docker's pull-time content-hash enforcement;
        #   - third-party tag-only pins log nothing here — the engine
        #     emits a single summary WARNING at end of ``run()``.
        # Default is verify_image_signatures=True (security-first); the
        # user can opt out wholesale via execution.verify_image_signatures.
        from argus.core.image_verify import verify_image, VerifyStatus
        verify_signatures = getattr(
            self.config.execution, "verify_image_signatures", True,
        )
        v = verify_image(image, verify_signatures=verify_signatures)
        self._verify_results.append(v)
        if v.is_fatal:
            logger.error(
                "Supply-chain verification FAILED for '%s' (%s): %s",
                image, v.status.value, v.message,
            )
            raise RuntimeError(
                f"Supply-chain verification failed for {image}: "
                f"{v.message}"
            )
        if v.status == VerifyStatus.VERIFIED_COSIGN:
            logger.info(
                "Supply-chain: %s — cosign verified (argus-owned)", image,
            )
        elif v.status == VerifyStatus.VERIFIED_DIGEST_PIN:
            logger.debug(
                "Supply-chain: %s — verified via digest pin", image,
            )
        elif v.status == VerifyStatus.SKIPPED_BY_CONFIG:
            logger.debug(
                "Supply-chain: %s — verification disabled by config", image,
            )

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
            #
            # Skip on Windows: NTFS doesn't honor POSIX bits, ``os.chmod``
            # only flips the read-only attribute, and Docker Desktop on
            # Windows handles uid mapping for bind mounts differently
            # (it doesn't suffer from the macOS uid-mismatch failure mode
            # this guard exists for). Calling ``chmod 0o777`` there is
            # at best a no-op and at worst confusing in stack traces.
            if platform.system() != "Windows":
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

            # Optional per-scanner env vars — e.g. credentials resolved
            # via ``argus.core.secrets.resolve_secret``. Scanners that
            # need to pass authentication or runtime parameters to the
            # tool implement ``container_env(config) -> dict[str, str]``.
            #
            # Passthrough strategy: ``docker run -e NAME`` (no value)
            # tells Docker to inherit the named env var from the *parent*
            # process. We put the resolved value into the subprocess's
            # own env via the ``subprocess_env`` dict below, so the value
            # never appears on the ``docker run`` command line — keeping
            # it out of ``ps``, ``docker inspect``, docker daemon audit
            # logs, and anywhere else argv strings get persisted. The
            # subprocess env is private to the python child and its
            # ``docker run`` grandchild; not visible to other local users
            # except those who can already read /proc/<pid>/environ for
            # this process (which is a strictly tighter access set than
            # ``ps``).
            subprocess_env: dict[str, str] | None = None
            if hasattr(scanner, "container_env"):
                extra_env = scanner.container_env(config or {}) or {}
                # Inherit the parent env so docker, PATH, HOME, etc. still
                # resolve normally; we only *add* the scanner's keys.
                subprocess_env = dict(os.environ)
                injected = 0
                for env_name, env_value in extra_env.items():
                    if env_value is None:
                        continue
                    subprocess_env[env_name] = env_value
                    docker_cmd.extend(["-e", env_name])
                    injected += 1
                if injected == 0:
                    # Nothing to inject — drop the override so subprocess
                    # uses the inherited env unmodified (matches behavior
                    # for scanners without a container_env method).
                    subprocess_env = None
                else:
                    logger.debug(
                        "Scanner '%s' injected %d env var(s) into container "
                        "(values passthrough via subprocess env, names only on argv)",
                        scanner.name, injected,
                    )

            # Optional per-scanner read-only bind mounts — e.g. ZAP
            # context files or ignore-rules files. Scanners return a
            # list of ``(host_path, container_path)`` tuples from
            # ``container_mounts(config)``. Host paths are resolved to
            # absolute paths; entries pointing at non-existent files
            # are skipped with a warning so a typo'd config doesn't
            # take down the whole scan.
            if hasattr(scanner, "container_mounts"):
                for mount in scanner.container_mounts(config or {}) or []:
                    host_path, container_path = mount
                    abs_host = str(Path(host_path).resolve())
                    if not Path(abs_host).exists():
                        logger.warning(
                            "Scanner '%s' requested mount of '%s' but the "
                            "path does not exist — skipping",
                            scanner.name, host_path,
                        )
                        continue
                    docker_cmd.extend(["-v", f"{abs_host}:{container_path}:ro"])
                    logger.debug(
                        "Scanner mount: %s → %s (ro)", abs_host, container_path,
                    )

            # Prefer the unified ``build_args(ScanPaths)`` shape (single
            # source of truth for both local and container CLI args).
            # Fall back to legacy ``container_args(config)`` for scanners
            # not yet migrated. Once every scanner declares
            # ``build_args``, the legacy branch and container_args
            # method go away.
            if hasattr(scanner, "build_args"):
                from argus.core.scanner_template import ScanPaths
                paths = ScanPaths(
                    workspace="/workspace",
                    output="/output/results.json",
                )
                container_args = scanner.build_args(paths, config or {})
                # ENTRYPOINT-based images supply the binary; drop argv[0].
                if getattr(scanner, "container_entrypoint", None):
                    container_args = container_args[1:]
            else:
                container_args = scanner.container_args(config)
            docker_cmd.extend([image] + container_args)

            logger.debug(
                "Docker command: docker run --rm -v ...:/workspace:ro "
                "-v ...:/output %s %s",
                image,
                " ".join(container_args),
            )

            start = time.monotonic()
            # Docker container output is always UTF-8. Without
            # ``encoding='utf-8'``, ``text=True`` falls back to the
            # platform default — cp1252 on Windows — which raises
            # ``UnicodeDecodeError`` on any non-ASCII byte the
            # scanner emits (CVE descriptions, file paths with
            # non-ASCII characters, etc.). ``errors='replace'`` is
            # a safe fallback over ``strict``: a security tool
            # showing ``�`` is better than crashing the whole
            # scan on output we'd otherwise be able to use.
            proc = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=subprocess_env,  # carries scanner-injected secrets
                                     # by NAME→value; None = inherit
                                     # the parent env unmodified
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

            # Persist raw scanner output (best-effort) before the
            # tempdir is wiped. Mirrors the container-scan flow's
            # ``raw/`` artifact preservation: every scanner gets its
            # own subdir under ``<raw_output_root>/<scanner.name>/``
            # so ``argus-results.json`` (the canonical artifact)
            # lives next to the per-scanner files (results.json,
            # *.sarif, stdout.txt) for forensics or manual triage.
            # Errors during copy are non-fatal — the scan succeeded,
            # the canonical JSON is still emitted upstream.
            if self._raw_output_root and result_files:
                try:
                    target_dir = Path(self._raw_output_root) / scanner.name
                    target_dir.mkdir(parents=True, exist_ok=True)
                    for src in result_files:
                        if src.exists() and src.stat().st_size > 0:
                            shutil.copy2(src, target_dir / src.name)
                except OSError as exc:
                    logger.warning(
                        "Failed to persist raw output for '%s' under %s: %s",
                        scanner.name, self._raw_output_root, exc,
                    )

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
                try:
                    parsed = scanner.parse_results(result_files[0])
                except Exception as exc:
                    # Scanner produced output but the parser couldn't
                    # interpret it (e.g. osv-scanner v2 rev'd its
                    # schema, truncated output, mixed text+JSON). This
                    # is a third state distinct from "execution failed"
                    # and "ran clean" — we surface it as
                    # ``parse_failed`` so the reporter can show "OSV
                    # produced 12KB of output we couldn't parse" rather
                    # than the misleading "no output produced". The
                    # parser bug doesn't crash the rest of the scan;
                    # other scanners' results are still useful.
                    head = ""
                    try:
                        head = result_files[0].read_text(
                            encoding="utf-8", errors="replace",
                        )[:200]
                    except OSError:
                        head = "<unreadable>"
                    metadata_extra["parse_failed"] = True
                    metadata_extra["parse_failure_reason"] = (
                        f"{type(exc).__name__}: {exc}. "
                        f"output head: {head!r}"
                    )
                    logger.warning(
                        "Scanner '%s' produced output but parse failed: %s",
                        scanner.name, exc,
                    )
                    findings = []
                else:
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

            # The engine's container path drives ``docker run`` from the
            # scanner's argv shape — either ``build_args(paths, config)``
            # (PR #117) or the legacy ``container_args(config)``. Scanners
            # without either method (linters with custom scan() flows
            # like HadolintLinter that walk the workspace and invoke
            # their tool per file) can't be driven that way; defer to
            # ``scanner.scan()`` and let it handle execution. ``auto``
            # mode falls through to the local path below; ``docker``
            # mode raises so the constraint is loud.
            container_capable = (
                hasattr(scanner, "build_args")
                or hasattr(scanner, "container_args")
            )

            if container_image and container_capable and self._is_docker_available():
                logger.debug(
                    "Backend '%s': using container for '%s' (image=%s)",
                    backend,
                    scanner.name,
                    container_image,
                )
                try:
                    return self._run_in_container(scanner, path, config)
                except ScannerPreconditionError as exc:
                    # The scanner's inputs are missing/invalid — no
                    # amount of fallback will help. Surface clearly and
                    # mark execution_failed so CI gating treats it as
                    # "didn't run" rather than "passed with 0 findings"
                    # (issue #168-I).
                    logger.error(
                        "Scanner '%s' precondition unmet: %s",
                        scanner.name, exc,
                    )
                    return _failure_result(scanner.name, exc)
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
            elif container_image and not container_capable:
                if backend == "docker":
                    raise RuntimeError(
                        f"Scanner '{scanner.name}' has a container_image "
                        f"but no build_args/container_args method, and "
                        f"backend is 'docker'. Implement build_args() or "
                        f"set backend to 'auto'/'local' to use the "
                        f"scanner's own scan() method."
                    )
                # auto: the scanner takes ownership of dispatch. It
                # likely has a custom flow (file-discovery linters that
                # walk the workspace and run their tool per-batch) and
                # handles local vs container internally — including the
                # docker-run fallback when the local binary is absent.
                # We hand off to scan() unconditionally rather than
                # falling through to the is_available() gate.
                logger.debug(
                    "Backend 'auto': scanner '%s' has no build_args/"
                    "container_args — handing off to scanner.scan()",
                    scanner.name,
                )
                return scanner.scan(path, config)

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
