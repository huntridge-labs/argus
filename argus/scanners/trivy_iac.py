"""Trivy IaC (Infrastructure as Code) scanner."""

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from argus.containers import get_image
from argus.core.models import Finding, ScanResult, Severity
from argus.core.scanner_template import ScanPaths, workspace_file
from argus.core.version import parse_tool_version


class TrivyIacScanner:
    """Wraps Trivy to scan infrastructure-as-code for misconfigurations."""

    name = "trivy-iac"
    description = "Infrastructure-as-code scanner — Terraform, Kubernetes, Dockerfile misconfigurations"
    category = "iac"
    languages = ["terraform", "kubernetes", "dockerfile"]
    container_image = get_image("trivy")
    # The official Trivy image uses ENTRYPOINT ["trivy"]; engine strips
    # argv[0] for ENTRYPOINT-based images.
    container_entrypoint = "trivy"

    def scan(self, path: str, config: dict | None = None) -> ScanResult:
        """Run Trivy IaC scan against the given path and return results.

        Runs the JSON scan via the shared template and additionally
        produces a SARIF report (best-effort, non-blocking) to attach as
        ``sarif_report`` on the returned :class:`ScanResult`.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_output = Path(tmp_dir) / "trivy-iac-results.json"
            sarif_output = Path(tmp_dir) / "trivy-iac-results.sarif"

            json_paths = ScanPaths(workspace=path, output=str(json_output))
            json_result = subprocess.run(
                self.build_args(json_paths, config or {}),
                capture_output=True,
                text=True,
            )

            if json_result.returncode != 0 and not json_output.exists():
                return ScanResult(
                    scanner=self.name,
                    metadata={
                        "error": json_result.stderr.strip(),
                        "returncode": json_result.returncode,
                    },
                )

            # SARIF scan — best-effort, non-blocking. Same flags as the
            # JSON pass so the SARIF report honours the same config and
            # ignore file.
            sarif_paths = ScanPaths(workspace=path, output=str(sarif_output))
            subprocess.run(
                self._trivy_args(sarif_paths, config or {}, "sarif"),
                capture_output=True,
                text=True,
            )

            findings = self.parse_results(json_output) if json_output.exists() else []

            return ScanResult(
                scanner=self.name,
                findings=findings,
                raw_report=json_output if json_output.exists() else None,
                sarif_report=sarif_output if sarif_output.exists() else None,
            )

    def build_args(self, paths: ScanPaths, config: dict) -> list[str]:
        """Build the full argv (including the binary name).

        Engine drops argv[0] when the container image declares an
        ENTRYPOINT, so the same method works for both local and
        container execution.
        """
        return self._trivy_args(paths, config, "json")

    @staticmethod
    def _trivy_args(paths: ScanPaths, config: dict, output_format: str) -> list[str]:
        """``trivy config`` argv for one output format.

        ``config_file`` (``trivy.yaml``) and ``ignore_file``
        (``.trivyignore``) arrive scan-root-relative from the engine. Trivy
        only looks for them in its working directory, which is ``/`` in the
        official image, so both have to be passed explicitly.
        """
        args = [
            "trivy", "config",
            "--format", output_format,
            "--output", paths.output,
        ]
        config_file = config.get("config_file")
        if config_file:
            args.extend(["--config", workspace_file(paths.workspace, config_file)])
        ignore_file = config.get("ignore_file")
        if ignore_file:
            args.extend(["--ignorefile", workspace_file(paths.workspace, ignore_file)])
        args.append(paths.workspace)
        return args

    @staticmethod
    def rule_ids(finding: Finding) -> set[str]:
        """IDs a ``skip_check`` entry may use for this finding.

        Trivy 0.6x reported ``AVD-AWS-0017``; current releases report
        ``AWS-0017``. Docs and older ``.trivyignore`` files use either, so
        accept both spellings.
        """
        short = finding.id.removeprefix("AVD-")
        return {short, f"AVD-{short}"}

    def is_available(self) -> bool:
        """Check if Trivy is installed."""
        return shutil.which("trivy") is not None

    def install_command(self) -> str | None:
        """Return install command for Trivy."""
        return "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh"

    def tool_version(self) -> str | None:
        """Return the installed Trivy version, or None if not available."""
        if not self.is_available():
            return None
        return parse_tool_version(["trivy", "--version"], r"^Version: (\S+)")

    def parse_results(self, raw_output_path: Path) -> list[Finding]:
        """Parse Trivy IaC JSON output into findings."""
        data = json.loads(raw_output_path.read_text(encoding="utf-8", errors="replace"))
        results = data.get("Results", [])

        findings = []
        for target_result in results:
            target = target_result.get("Target", "")
            misconfigs = target_result.get("Misconfigurations", [])

            for misconfig in misconfigs:
                findings.append(self._parse_misconfiguration(target, misconfig))

        return findings

    def _parse_misconfiguration(self, target: str, misconfig: dict) -> Finding:
        """Convert a single Trivy misconfiguration into a Finding."""
        severity = Severity.from_string(misconfig.get("Severity", "UNKNOWN"))

        cause = misconfig.get("CauseMetadata", {})
        start_line = cause.get("StartLine")
        location = f"{target}:{start_line}" if start_line else target

        return Finding(
            id=misconfig.get("ID", "UNKNOWN"),
            severity=severity,
            title=misconfig.get("Title", ""),
            description=misconfig.get("Description", ""),
            location=location,
            scanner=self.name,
            metadata={
                "resolution": misconfig.get("Resolution", ""),
                "resource": cause.get("Resource", ""),
                "provider": cause.get("Provider", ""),
                "service": cause.get("Service", ""),
                "primary_url": misconfig.get("PrimaryURL", ""),
            },
        )
