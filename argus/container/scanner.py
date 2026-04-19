"""Scan container images with trivy and grype, deduplicate findings."""

import logging
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from argus.core.models import Finding, Severity
from argus.scanners.container import ContainerScanner

from .discovery import ContainerTarget

logger = logging.getLogger("argus.container")

# Shared parser instance — reuses ContainerScanner's parsing logic
_parser = ContainerScanner()


@dataclass
class ContainerScanResult:
    """Results for a single container image scan."""

    name: str
    image_ref: str
    digest: str = ""
    trivy_findings: list[Finding] = field(default_factory=list)
    grype_findings: list[Finding] = field(default_factory=list)
    combined_findings: list[Finding] = field(default_factory=list)
    build_success: bool = True
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
        return len(self.combined_findings)

    @property
    def unique_count(self) -> int:
        """Count of unique CVEs in combined findings."""
        cves = {f.cve for f in self.combined_findings if f.cve}
        non_cve_count = sum(
            1 for f in self.combined_findings if not f.cve
        )
        return len(cves) + non_cve_count

    def _count_severity(self, severity: Severity) -> int:
        return sum(
            1 for f in self.combined_findings if f.severity == severity
        )


@dataclass
class ContainerScanSummary:
    """Aggregated results across all container images."""

    results: list[ContainerScanResult] = field(default_factory=list)

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
    def unique_count(self) -> int:
        """Deduplicated CVE count across all images."""
        cves: set[str] = set()
        non_cve_count = 0
        for result in self.results:
            for finding in result.combined_findings:
                if finding.cve:
                    cves.add(finding.cve)
                else:
                    non_cve_count += 1
        return len(cves) + non_cve_count

    @property
    def container_count(self) -> int:
        return len(self.results)

    @property
    def build_failures(self) -> int:
        return sum(1 for r in self.results if not r.build_success)


def scan_image(
    target: ContainerTarget,
    scanners: tuple[str, ...] = ("trivy", "grype"),
    sbom: bool = True,
) -> ContainerScanResult:
    """Scan a single container image with trivy and/or grype.

    For remote images (not built from a Dockerfile), trivy and grype
    scan directly from the registry without pulling the full image.
    This uses minimal disk — only the vulnerability DB and scan output.

    For locally-built images, scanners reference the local Docker daemon.
    """
    trivy_findings: list[Finding] = []
    grype_findings: list[Finding] = []

    # Determine if the image is local (built by us) or remote
    is_local = target.dockerfile is not None

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)

        if "trivy" in scanners:
            trivy_findings = _run_trivy(
                target.image_ref, tmp_path, local=is_local,
            )

        if "grype" in scanners:
            grype_findings = _run_grype(
                target.image_ref, tmp_path, local=is_local,
            )

        if sbom and "syft" not in scanners:
            _run_syft(target.image_ref, tmp_path)

    combined = deduplicate_findings(trivy_findings, grype_findings)

    return ContainerScanResult(
        name=target.name,
        image_ref=target.image_ref,
        trivy_findings=trivy_findings,
        grype_findings=grype_findings,
        combined_findings=combined,
    )


def deduplicate_findings(
    trivy: list[Finding],
    grype: list[Finding],
) -> list[Finding]:
    """Merge and deduplicate findings from multiple scanners by CVE ID.

    Trivy findings take precedence when a CVE appears in both lists.
    Findings without CVE IDs are always included.
    """
    combined: list[Finding] = []
    seen_cves: set[str] = set()

    # Trivy findings first (they take precedence)
    for finding in trivy:
        if finding.cve:
            if finding.cve in seen_cves:
                continue
            seen_cves.add(finding.cve)
        combined.append(finding)

    # Grype findings, skipping duplicates
    for finding in grype:
        if finding.cve:
            if finding.cve in seen_cves:
                continue
            seen_cves.add(finding.cve)
        combined.append(finding)

    return combined


def _run_trivy(
    image_ref: str, tmp_path: Path, local: bool = False,
) -> list[Finding]:
    """Run trivy and parse results.

    Tries local binary first, falls back to Docker container image
    when trivy is not installed and a container runtime is available.
    When local=False, trivy scans directly from the registry without
    pulling the image — minimal disk usage.
    """
    import subprocess

    output_file = tmp_path / "trivy-results.json"
    use_container = False

    if shutil.which("trivy") is None:
        from argus import container_runtime
        from argus.containers import get_image

        image = get_image("trivy")
        if not image or not container_runtime.is_available():
            logger.warning("trivy not available (local or container) — skipping")
            return []
        if not container_runtime.pull_image(image):
            logger.error("Failed to pull trivy image: %s", image)
            return []
        use_container = True
        logger.info("Running trivy via container: %s", image)

    if use_container:
        from argus import container_runtime
        from argus.containers import get_image

        rt = container_runtime.runtime_cmd()
        image = get_image("trivy")
        cmd = [
            rt, "run", "--rm",
            "-v", f"{tmp_path}:/output",
            image,
            "image", "--format", "json",
            "--output", "/output/trivy-results.json",
        ]
        if not local:
            cmd.extend(["--image-src", "remote"])
        cmd.append(image_ref)
    else:
        cmd = [
            "trivy", "image",
            "--format", "json",
            "--output", str(output_file),
        ]
        if not local:
            cmd.extend(["--image-src", "remote"])
        cmd.append(image_ref)

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=600,
        )
    except subprocess.TimeoutExpired:
        logger.error("trivy timed out scanning %s", image_ref)
        return []
    except FileNotFoundError:
        logger.error("trivy binary not found")
        return []

    if not output_file.exists():
        logger.error(
            "trivy produced no output (exit %d): %s",
            result.returncode,
            result.stderr.strip()[:500],
        )
        return []

    try:
        return _parser.parse_trivy_results(output_file)
    except Exception:
        logger.exception("Failed to parse trivy results for %s", image_ref)
        return []


def _run_grype(
    image_ref: str, tmp_path: Path, local: bool = False,
) -> list[Finding]:
    """Run grype and parse results.

    Tries local binary first, falls back to Docker container image.
    Grype automatically fetches from registry when the image isn't
    in local Docker — no special flag needed.
    """
    import subprocess

    output_file = tmp_path / "grype-results.json"
    use_container = False

    if shutil.which("grype") is None:
        from argus import container_runtime
        from argus.containers import get_image

        image = get_image("grype")
        if not image or not container_runtime.is_available():
            logger.warning("grype not available (local or container) — skipping")
            return []
        if not container_runtime.pull_image(image):
            logger.error("Failed to pull grype image: %s", image)
            return []
        use_container = True
        logger.info("Running grype via container: %s", image)

    if use_container:
        from argus import container_runtime
        from argus.containers import get_image

        rt = container_runtime.runtime_cmd()
        image = get_image("grype")
        cmd = [
            rt, "run", "--rm",
            "-v", f"{tmp_path}:/output",
            image,
            image_ref,
            "-o", "json",
            "--file", "/output/grype-results.json",
        ]
    else:
        cmd = [
            "grype", image_ref,
            "-o", "json",
            "--file", str(output_file),
        ]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=600,
        )
    except subprocess.TimeoutExpired:
        logger.error("grype timed out scanning %s", image_ref)
        return []
    except FileNotFoundError:
        logger.error("grype binary not found")
        return []

    if not output_file.exists():
        logger.error(
            "grype produced no output (exit %d): %s",
            result.returncode,
            result.stderr.strip()[:500],
        )
        return []

    try:
        return _parser.parse_grype_results(output_file)
    except Exception:
        logger.exception("Failed to parse grype results for %s", image_ref)
        return []


def _run_syft(image_ref: str, tmp_path: Path) -> None:
    """Run syft to generate an SBOM (best-effort).

    Tries local binary first, falls back to Docker container image.
    """
    import subprocess

    output_file = tmp_path / "syft-sbom.json"

    if shutil.which("syft") is None:
        from argus import container_runtime
        from argus.containers import get_image

        image = get_image("syft")
        if not image or not container_runtime.is_available():
            logger.debug("syft not available (local or container) — skipping SBOM")
            return
        if not container_runtime.pull_image(image):
            logger.debug("Failed to pull syft image — skipping SBOM")
            return

        logger.info("Running syft via container: %s", image)
        rt = container_runtime.runtime_cmd()
        cmd = [
            rt, "run", "--rm",
            "-v", f"{tmp_path}:/output",
            image,
            image_ref,
            "-o", "cyclonedx-json",
            "--file", "/output/syft-sbom.json",
        ]
    else:
        cmd = [
            "syft", image_ref,
            "-o", "cyclonedx-json",
            "--file", str(output_file),
        ]

    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        logger.warning("syft timed out generating SBOM for %s", image_ref)
    except FileNotFoundError:
        logger.debug("syft binary not found")
