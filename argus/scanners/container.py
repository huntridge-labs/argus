"""Container scanner orchestrating Trivy, Grype, and Syft."""

import json
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from argus.containers import get_image
from argus.core.models import Finding, ScanResult, Severity

logger = logging.getLogger("argus")


class ContainerScanner:
    """Wraps Trivy, Grype, and Syft for container image scanning."""

    name = "container"
    description = "Container image vulnerability scanner — orchestrates Trivy, Grype, and Syft"
    category = "container"
    languages = ["docker"]
    # This scanner is an orchestrator, not a single-tool wrapper.  It runs
    # trivy, grype, and syft as separate sub-processes, each with its own
    # official container image (defined in containers.py).  Because of this
    # architecture the scanner cannot fall back to a single Docker image;
    # container_image is empty intentionally and Docker-fallback is handled
    # per sub-tool by the engine when local binaries are missing.
    container_image = ""

    def container_args(self, config: dict | None = None) -> list[str]:
        """Not applicable — this scanner orchestrates sub-tools directly.

        Each sub-tool (trivy, grype, syft) is invoked individually with its
        own container image and args, so a top-level container_args is unused.
        """
        return []

    def scan(self, path: str, config: dict | None = None) -> ScanResult:
        """Run enabled sub-scanners against a container image.

        The ``path`` argument is ignored; the image reference must be
        provided via ``config["image_ref"]``.
        """
        config = config or {}
        image_ref = config.get("image_ref")
        if not image_ref:
            return ScanResult(
                scanner=self.name,
                metadata={"error": "image_ref is required in config"},
            )

        enabled = self._enabled_scanners(config)
        all_findings: list[Finding] = []
        metadata: dict = {}
        seen_cves: set[str] = set()

        env = self._build_env(config)

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)

            if "trivy" in enabled:
                trivy_output = tmp_path / "trivy-results.json"
                trivy_findings, trivy_meta = self._run_sub_scanner(
                    tool="trivy",
                    local_cmd=["trivy", "image", "--format", "json",
                               "--output", str(trivy_output), image_ref],
                    container_args=["image", "--format", "json",
                                    "--output", "/output/results.json", image_ref],
                    output_file=trivy_output,
                    parse_fn=self.parse_trivy_results,
                    env=env,
                )
                self._merge_findings(trivy_findings, all_findings, seen_cves)
                metadata["trivy"] = trivy_meta

            if "grype" in enabled:
                grype_output = tmp_path / "grype-results.json"
                grype_findings, grype_meta = self._run_sub_scanner(
                    tool="grype",
                    local_cmd=["grype", image_ref, "-o", "json",
                               "--file", str(grype_output)],
                    container_args=[image_ref, "-o", "json",
                                    "--file", "/output/results.json"],
                    output_file=grype_output,
                    parse_fn=self.parse_grype_results,
                    env=env,
                )
                self._merge_findings(grype_findings, all_findings, seen_cves)
                metadata["grype"] = grype_meta

            if "syft" in enabled:
                syft_output = tmp_path / "syft-sbom.json"
                syft_meta = self._run_syft_with_fallback(
                    image_ref, syft_output, env,
                )
                metadata["syft"] = syft_meta

            if not metadata:
                metadata["error"] = (
                    "None of the enabled scanners "
                    "(trivy, grype, syft) could be executed — "
                    "install locally or ensure Docker is available"
                )

        return ScanResult(
            scanner=self.name,
            findings=all_findings,
            metadata=metadata,
        )

    def is_available(self) -> bool:
        """Check if at least one vulnerability scanner is available (local or Docker)."""
        if shutil.which("trivy") or shutil.which("grype"):
            return True
        # Check if Docker is available for container fallback
        from argus import container_runtime
        return container_runtime.is_available() and bool(get_image("trivy"))

    def install_command(self) -> str | None:
        """Return install hints for the container scanning tools."""
        return (
            "See https://aquasecurity.github.io/trivy, "
            "https://github.com/anchore/grype, "
            "https://github.com/anchore/syft"
        )

    def tool_version(self) -> str | None:
        """Return None — this is an orchestrator, not a single tool."""
        return None

    def parse_trivy_results(self, raw_output_path: Path) -> list[Finding]:
        """Parse Trivy container JSON output into findings."""
        data = json.loads(raw_output_path.read_text(encoding="utf-8", errors="replace"))
        findings: list[Finding] = []

        for target in data.get("Results", []):
            for vuln in target.get("Vulnerabilities", []):
                findings.append(self._parse_trivy_vuln(vuln))

        return findings

    def parse_grype_results(self, raw_output_path: Path) -> list[Finding]:
        """Parse Grype JSON output into findings."""
        data = json.loads(raw_output_path.read_text(encoding="utf-8", errors="replace"))
        findings: list[Finding] = []

        for match in data.get("matches", []):
            findings.append(self._parse_grype_match(match))

        return findings

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _enabled_scanners(self, config: dict) -> list[str]:
        """Return list of enabled sub-scanner names from config."""
        raw = config.get("scanners", "trivy,grype,syft")
        return [s.strip().lower() for s in raw.split(",") if s.strip()]

    def _build_env(self, config: dict) -> dict[str, str]:
        """Build environment dict with optional registry credentials."""
        env = dict(os.environ)
        username = config.get("registry_username")
        password = config.get("registry_password")

        if username:
            env["TRIVY_USERNAME"] = username
            env["GRYPE_REGISTRY_AUTH_USERNAME"] = username
            env["SYFT_REGISTRY_AUTH_USERNAME"] = username
        if password:
            env["TRIVY_PASSWORD"] = password
            env["GRYPE_REGISTRY_AUTH_PASSWORD"] = password
            env["SYFT_REGISTRY_AUTH_PASSWORD"] = password

        return env

    def _run_sub_scanner(
        self,
        tool: str,
        local_cmd: list[str],
        container_args: list[str],
        output_file: Path,
        parse_fn,
        env: dict[str, str],
    ) -> tuple[list[Finding], dict]:
        """Run a sub-scanner locally or via Docker fallback.

        Tries local binary first, falls back to container image if not
        installed and a container runtime is available.
        """
        if shutil.which(tool):
            logger.debug("Running %s locally", tool)
            result = subprocess.run(
                local_cmd, capture_output=True, text=True, env=env,
            )
            meta: dict = {"returncode": result.returncode, "execution": "local"}
        else:
            # Docker fallback
            from argus import container_runtime
            image = get_image(tool)
            if not image or not container_runtime.is_available():
                logger.warning(
                    "%s not installed and no container runtime available — skipping",
                    tool,
                )
                return [], {"error": f"{tool} not available (local or container)"}

            if not container_runtime.pull_image(image):
                return [], {"error": f"Failed to pull {image}"}

            logger.info("Running %s via container: %s", tool, image)
            rt = container_runtime.runtime_cmd()
            output_dir = str(output_file.parent)
            cmd = [
                rt, "run", "--rm",
                "-v", f"{output_dir}:/output",
                image,
            ] + container_args

            result = subprocess.run(
                cmd, capture_output=True, text=True, env=env,
            )
            meta = {"returncode": result.returncode, "execution": "container", "image": image}

            # Container writes to /output/results.json — copy to expected path
            container_output = output_file.parent / "results.json"
            if container_output.exists() and container_output != output_file:
                container_output.rename(output_file)

        if not output_file.exists():
            meta["error"] = result.stderr.strip() or "No output produced"
            return [], meta

        findings = parse_fn(output_file)
        return findings, meta

    def _run_syft_with_fallback(
        self,
        image_ref: str,
        output_file: Path,
        env: dict[str, str],
    ) -> dict:
        """Run Syft SBOM generation locally or via Docker fallback."""
        if shutil.which("syft"):
            cmd = [
                "syft", image_ref,
                "-o", "cyclonedx-json",
                "--file", str(output_file),
            ]
            result = subprocess.run(
                cmd, capture_output=True, text=True, env=env,
            )
            meta: dict = {"returncode": result.returncode, "execution": "local"}
        else:
            from argus import container_runtime
            image = get_image("syft")
            if not image or not container_runtime.is_available():
                return {"error": "syft not available (local or container)"}

            if not container_runtime.pull_image(image):
                return {"error": f"Failed to pull {image}"}

            logger.info("Running syft via container: %s", image)
            rt = container_runtime.runtime_cmd()
            output_dir = str(output_file.parent)
            cmd = [
                rt, "run", "--rm",
                "-v", f"{output_dir}:/output",
                image,
                image_ref,
                "-o", "cyclonedx-json",
                "--file", "/output/results.json",
            ]
            result = subprocess.run(
                cmd, capture_output=True, text=True, env=env,
            )
            meta = {"returncode": result.returncode, "execution": "container", "image": image}
            container_output = output_file.parent / "results.json"
            if container_output.exists() and container_output != output_file:
                container_output.rename(output_file)

        if output_file.exists():
            meta["sbom_path"] = str(output_file)
        else:
            meta["error"] = result.stderr.strip() or "No output produced"

        return meta

    def _merge_findings(
        self,
        new_findings: list[Finding],
        target: list[Finding],
        seen_cves: set[str],
    ) -> None:
        """Append findings to target, deduplicating by CVE ID."""
        for finding in new_findings:
            cve = finding.cve
            if cve and cve in seen_cves:
                continue
            if cve:
                seen_cves.add(cve)
            target.append(finding)

    def _parse_trivy_vuln(self, vuln: dict) -> Finding:
        """Convert a single Trivy vulnerability to a Finding."""
        severity = Severity.from_string(
            vuln.get("Severity", "UNKNOWN")
        )

        cwe = None
        cwe_ids = vuln.get("CweIDs") or []
        if cwe_ids:
            cwe = cwe_ids[0]

        vuln_id = vuln.get("VulnerabilityID", "UNKNOWN")
        pkg = vuln.get("PkgName", "")
        installed = vuln.get("InstalledVersion", "")
        fixed = vuln.get("FixedVersion", "")

        return Finding(
            id=vuln_id,
            severity=severity,
            title=vuln.get("Title", vuln_id),
            description=vuln.get("Description", ""),
            location=f"{pkg}@{installed}" if pkg else None,
            cwe=cwe,
            cve=vuln_id if vuln_id.startswith("CVE-") else None,
            scanner=self.name,
            metadata={
                "tool": "trivy",
                "package": pkg,
                "installed_version": installed,
                "fixed_version": fixed,
            },
        )

    def _parse_grype_match(self, match: dict) -> Finding:
        """Convert a single Grype match to a Finding."""
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})

        vuln_id = vuln.get("id", "UNKNOWN")
        severity = Severity.from_string(
            vuln.get("severity", "Unknown")
        )

        pkg_name = artifact.get("name", "")
        pkg_version = artifact.get("version", "")

        fix_versions = vuln.get("fix", {}).get("versions", [])
        fixed = ", ".join(fix_versions) if fix_versions else ""

        return Finding(
            id=vuln_id,
            severity=severity,
            title=vuln.get("description", vuln_id),
            description=vuln.get("description", ""),
            location=f"{pkg_name}@{pkg_version}" if pkg_name else None,
            cve=vuln_id if vuln_id.startswith("CVE-") else None,
            scanner=self.name,
            metadata={
                "tool": "grype",
                "package": pkg_name,
                "installed_version": pkg_version,
                "fixed_version": fixed,
            },
        )
