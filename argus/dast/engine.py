"""Orchestrate the full DAST lifecycle for container images.

Inspects, starts, scans (with ZAP), and stops container targets.
Guarantees cleanup even on failures.
"""

import logging
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from argus.containers import get_image
from argus.core.models import Finding, Severity
from argus.scanners.zap import ZapScanner

from .inspect import inspect_image
from .runner import DastTarget, start_target, stop_target

logger = logging.getLogger("argus.dast")

_zap_parser = ZapScanner()
_ZAP_IMAGE = get_image("zap")

# Default ZAP scan timeout (10 minutes)
_ZAP_TIMEOUT = 600


@dataclass
class DastScanResult:
    """Results for one DAST target."""

    name: str
    image_ref: str
    target_url: str = ""
    port: int = 0
    findings: list[Finding] = field(default_factory=list)
    started: bool = True
    healthy: bool = True
    scan_error: str = ""

    @property
    def critical_count(self) -> int:
        return self._count_severity(Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return self._count_severity(Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return self._count_severity(Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return self._count_severity(Severity.LOW)

    @property
    def total_count(self) -> int:
        return len(self.findings)

    def _count_severity(self, severity: Severity) -> int:
        return sum(1 for f in self.findings if f.severity == severity)


@dataclass
class DastScanSummary:
    """Aggregated DAST results across all targets."""

    results: list[DastScanResult] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(r.critical_count for r in self.results)

    @property
    def high_count(self) -> int:
        return sum(r.high_count for r in self.results)

    @property
    def medium_count(self) -> int:
        return sum(r.medium_count for r in self.results)

    @property
    def low_count(self) -> int:
        return sum(r.low_count for r in self.results)

    @property
    def total_count(self) -> int:
        return sum(r.total_count for r in self.results)

    @property
    def target_count(self) -> int:
        return len(self.results)

    @property
    def healthy_count(self) -> int:
        return sum(1 for r in self.results if r.healthy)

    @property
    def scan_failures(self) -> int:
        return sum(1 for r in self.results if r.scan_error)


class DastEngine:
    """Orchestrates DAST scanning for one or more container images.

    Config dict matches the ``dast`` section of argus.yml::

        dast:
          targets:
            - image: myapp:latest
              port: 8080
              env:
                DATABASE_URL: sqlite:///test.db
          startup_timeout: 60
          scan_type: baseline
    """

    def __init__(self, config: dict):
        self.config = config
        self._startup_timeout = config.get("startup_timeout", 60)
        self._scan_type = config.get("scan_type", "baseline")

    def run(self) -> DastScanSummary:
        """Execute the full DAST lifecycle for configured targets.

        For each target:
        1. Inspect image for ports
        2. Start container on isolated network
        3. Wait for healthy
        4. Scan with ZAP
        5. Stop and cleanup (always, even on failure)
        """
        targets = self._resolve_targets()
        if not targets:
            logger.warning("No DAST targets configured")
            return DastScanSummary()

        logger.info("Scanning %d DAST target(s)", len(targets))
        results: list[DastScanResult] = []

        for i, target_config in enumerate(targets, 1):
            image_ref = target_config["image"]
            logger.info(
                "[%d/%d] Processing DAST target: %s",
                i, len(targets), image_ref,
            )

            result = self._process_target(target_config)
            results.append(result)

        summary = DastScanSummary(results=results)
        logger.info(
            "DAST scan complete: %d target(s), %d healthy, "
            "%d finding(s), %d failure(s)",
            summary.target_count,
            summary.healthy_count,
            summary.total_count,
            summary.scan_failures,
        )
        return summary

    def scan_image(
        self,
        image_ref: str,
        port: int | None = None,
        env: dict[str, str] | None = None,
        name: str = "",
    ) -> DastScanResult:
        """Scan a single image -- public API for CLI usage.

        Handles the full lifecycle: start, scan, stop.
        """
        target_config = {"image": image_ref}
        if port is not None:
            target_config["port"] = port
        if env:
            target_config["env"] = env
        if name:
            target_config["name"] = name

        return self._process_target(target_config)

    def _process_target(self, target_config: dict) -> DastScanResult:
        """Run the full lifecycle for a single target.

        Catches errors individually so one failing target does not
        block the rest. Always cleans up.
        """
        image_ref = target_config["image"]
        port = target_config.get("port")
        env = target_config.get("env")
        name = target_config.get("name", "")

        target: DastTarget | None = None

        try:
            target = start_target(
                image_ref=image_ref,
                name=name,
                port=port,
                env=env,
                startup_timeout=self._startup_timeout,
            )
        except RuntimeError as exc:
            logger.error("Failed to start target %s: %s", image_ref, exc)
            return DastScanResult(
                name=name or image_ref,
                image_ref=image_ref,
                started=False,
                healthy=False,
                scan_error=str(exc),
            )

        try:
            findings = self._run_zap_scan(target)
            return DastScanResult(
                name=target.name,
                image_ref=image_ref,
                target_url=target.url,
                port=target.port,
                findings=findings,
                started=True,
                healthy=target.healthy,
            )
        except Exception as exc:
            logger.error("ZAP scan failed for %s: %s", image_ref, exc)
            return DastScanResult(
                name=target.name,
                image_ref=image_ref,
                target_url=target.url,
                port=target.port,
                started=True,
                healthy=target.healthy,
                scan_error=str(exc),
            )
        finally:
            if target is not None:
                stop_target(target)

    def _run_zap_scan(self, target: DastTarget) -> list[Finding]:
        """Run ZAP against a running target container.

        Runs ZAP in a container on the same Docker network so it
        can reach the target by container name. Parses results
        using the existing :class:`ZapScanner` parser.
        """
        if shutil.which("docker") is None:
            raise RuntimeError("Docker is required to run ZAP scanner")

        container_name = f"argus-dast-{target.name}"
        # ZAP connects to the target via the Docker network by name
        # The container port is derived from the port mapping
        zap_target_url = f"http://{container_name}:{self._target_container_port(target)}/"

        with tempfile.TemporaryDirectory() as tmp_dir:
            output_path = Path(tmp_dir)
            results_file = output_path / "results.json"

            cmd = self._build_zap_command(
                target=target,
                zap_target_url=zap_target_url,
                output_dir=str(output_path),
            )

            logger.info("Running ZAP %s scan against %s", self._scan_type, zap_target_url)
            logger.debug("ZAP command: %s", " ".join(cmd))

            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=_ZAP_TIMEOUT,
                )
            except subprocess.TimeoutExpired:
                raise RuntimeError(
                    f"ZAP scan timed out after {_ZAP_TIMEOUT}s "
                    f"scanning {zap_target_url}"
                )

            if not results_file.exists():
                stderr_excerpt = result.stderr.strip()[:500]
                logger.error(
                    "ZAP produced no output (exit %d): %s",
                    result.returncode, stderr_excerpt,
                )
                raise RuntimeError(
                    f"ZAP scan failed (exit {result.returncode}): "
                    f"{stderr_excerpt or 'no output'}"
                )

            logger.info("Parsing ZAP results from %s", results_file)
            return _zap_parser.parse_results(results_file)

    def _build_zap_command(
        self,
        target: DastTarget,
        zap_target_url: str,
        output_dir: str,
    ) -> list[str]:
        """Build the ZAP Docker command."""
        scan_script = "zap-baseline.py"
        if self._scan_type == "full":
            scan_script = "zap-full-scan.py"

        return [
            "docker", "run", "--rm",
            "--network", target.network_name,
            "-v", f"{output_dir}:/zap/wrk",
            _ZAP_IMAGE,
            scan_script,
            "-t", zap_target_url,
            "-J", "results.json",
            "-I",  # Don't fail on warnings
        ]

    def _target_container_port(self, target: DastTarget) -> int:
        """Get the container-side port for the target.

        Re-inspects the image to find the exposed port. Falls back
        to the host port if inspection fails.
        """
        try:
            info = inspect_image(target.image_ref)
            if info.exposed_ports:
                return info.exposed_ports[0]
        except RuntimeError:
            pass

        return target.port

    def _resolve_targets(self) -> list[dict]:
        """Get target configurations from the config dict."""
        targets = self.config.get("targets", [])

        # Support shorthand: single image string
        if isinstance(targets, str):
            return [{"image": targets}]

        # Support list of image strings
        resolved: list[dict] = []
        for item in targets:
            if isinstance(item, str):
                resolved.append({"image": item})
            elif isinstance(item, dict):
                resolved.append(item)
            else:
                logger.warning("Skipping invalid target config: %s", item)

        return resolved
