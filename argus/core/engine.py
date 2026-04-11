"""Argus engine — orchestrates scanner execution and result aggregation."""

import logging
import shutil
import subprocess
import tempfile
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

    def run(
        self,
        scanner_names: list[str] | None = None,
        path: str | None = None,
    ) -> ScanSummary:
        """Run scanners and return an aggregated ScanSummary.

        If *scanner_names* is None, all registered scanners whose config
        has ``enabled=True`` are executed. If *path* is provided it
        overrides the per-scanner path from config.
        """
        names_to_run = self._resolve_scanner_names(scanner_names)
        results: list[ScanResult] = []

        for name in names_to_run:
            scanner = self._scanners.get(name)
            if scanner is None:
                logger.warning("Scanner '%s' is not registered — skipping", name)
                continue

            scanner_config = self.config.get_scanner_config(name)
            scan_path = path if path is not None else scanner_config.path
            config_dict = self._build_scanner_config_dict(scanner_config)

            try:
                result = self._run_scanner(scanner, scan_path, config_dict)
                results.append(result)
            except Exception:
                logger.exception("Scanner '%s' failed", name)

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
        return shutil.which("docker") is not None

    def _pull_image(self, image: str) -> bool:
        """Pull a container image based on pull policy."""
        policy = self.config.execution.pull_policy

        if policy == "never":
            result = subprocess.run(
                ["docker", "image", "inspect", image],
                capture_output=True,
            )
            return result.returncode == 0

        if policy == "if-not-present":
            result = subprocess.run(
                ["docker", "image", "inspect", image],
                capture_output=True,
            )
            if result.returncode == 0:
                return True

        # Pull the image (always, or if-not-present and not found)
        # Try native platform first, fall back to linux/amd64 for ARM Macs
        result = subprocess.run(
            ["docker", "pull", image],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            logger.info(
                "Native pull failed for %s, retrying with --platform linux/amd64",
                image,
            )
            result = subprocess.run(
                ["docker", "pull", "--platform", "linux/amd64", image],
                capture_output=True,
                text=True,
            )
        return result.returncode == 0

    def _resolve_image(self, scanner) -> str:
        """Resolve the full container image reference, applying registry override."""
        image = getattr(scanner, "container_image", "")
        if not image:
            return ""

        registry = self.config.execution.registry
        if registry:
            # Replace the registry prefix
            # e.g., "aquasec/trivy:0.58.0" -> "registry.internal/argus/trivy:0.58.0"
            parts = image.split("/", 1)
            if len(parts) == 2 and ("." in parts[0] or ":" in parts[0]):
                # Has explicit registry, replace it
                image = f"{registry}/{parts[1]}"
            else:
                # Docker Hub shorthand, prefix with registry
                image = f"{registry}/{image}"

        return image

    def _run_in_container(
        self, scanner, path: str, config: dict | None
    ) -> ScanResult:
        """Run a scanner in a Docker container."""
        image = self._resolve_image(scanner)

        if not self._pull_image(image):
            raise RuntimeError(f"Failed to pull container image: {image}")

        abs_path = str(Path(path).resolve())

        with tempfile.TemporaryDirectory() as output_dir:
            # Volume mount: scan path as /workspace (read-only), output dir as /output
            docker_cmd = [
                "docker", "run", "--rm",
                "-v", f"{abs_path}:/workspace:ro",
                "-v", f"{output_dir}:/output",
            ]

            # Override entrypoint if scanner specifies one
            entrypoint = getattr(scanner, "container_entrypoint", None)
            if entrypoint:
                docker_cmd.extend(["--entrypoint", entrypoint])

            # Add scanner-specific container args
            container_args = scanner.container_args(config)
            docker_cmd.extend([image] + container_args)

            proc = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
            )

            # Parse results from output directory
            output_path = Path(output_dir)
            result_files = (
                list(output_path.glob("*.json"))
                + list(output_path.glob("*.txt"))
                + list(output_path.glob("*.sarif"))
            )

            # If no output files but stdout has content, write it
            # (some scanners like clamscan output to stdout)
            if not result_files and proc.stdout.strip():
                stdout_file = output_path / "stdout.txt"
                stdout_file.write_text(proc.stdout)
                result_files = [stdout_file]

            findings = []
            if result_files and hasattr(scanner, "parse_results"):
                findings = scanner.parse_results(result_files[0])

            return ScanResult(
                scanner=scanner.name,
                findings=findings,
                metadata={"execution": "container", "image": image},
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
            return scanner.scan(path, config)

        # auto or docker: prefer containers for immutable execution
        if backend in ("auto", "docker"):
            container_image = getattr(scanner, "container_image", "")
            if container_image and self._is_docker_available():
                return self._run_in_container(scanner, path, config)

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

            # auto fallback: use local tool if no container image defined
            if scanner.is_available():
                logger.info(
                    "No container image for '%s', using local tool",
                    scanner.name,
                )
                return scanner.scan(path, config)

            raise RuntimeError(
                f"Scanner '{scanner.name}' has no container image "
                f"and is not installed locally. "
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
