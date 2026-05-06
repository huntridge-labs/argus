"""Terraform linter wrapping terraform fmt, validate, and tflint."""

import json
import shutil
import subprocess
from pathlib import Path

from argus.containers import get_image
from argus.core.models import Finding, ScanResult, Severity
from argus.core.version import parse_tool_version


class TerraformLinter:
    """Wraps terraform fmt/validate and tflint for Terraform linting.

    Falls back to the official ``hashicorp/terraform`` and
    ``ghcr.io/terraform-linters/tflint`` Docker images when the local
    binaries aren't installed — same shape as
    :class:`argus.linters.hadolint.HadolintLinter`. The workspace is
    bind-mounted read-write because ``terraform init -backend=false``
    needs to drop a ``.terraform/`` directory before ``terraform
    validate -json`` can read its plugin state.
    """

    name = "lint-terraform"
    description = "Terraform formatting and validation linter"
    category = "linter"
    languages = ["terraform"]
    container_image = get_image("terraform")

    def scan(self, path: str, config: dict | None = None) -> ScanResult:
        """Run terraform fmt check, validate, and optionally tflint."""
        config = config or {}
        all_findings: list[Finding] = []

        all_findings.extend(self._run_fmt_check(path))
        all_findings.extend(self._run_validate(path))

        if config.get("run_tflint", True):
            all_findings.extend(self._run_tflint(path, config))

        return ScanResult(scanner=self.name, findings=all_findings)

    def is_available(self) -> bool:
        """Check if terraform is installed locally.

        ``False`` when only Docker is available — the engine and
        ``scan()`` itself both fall back to the container image
        transparently in that case.
        """
        return shutil.which("terraform") is not None

    def install_command(self) -> str | None:
        return "Install from https://developer.hashicorp.com/terraform/install"

    def tool_version(self) -> str | None:
        if not self.is_available():
            return None
        return parse_tool_version(["terraform", "--version"], r"^Terraform v(\S+)")

    # ------------------------------------------------------------------
    # Subprocess execution helpers — local first, container fallback
    # ------------------------------------------------------------------

    def _run_terraform(self, args: list[str], path: str) -> subprocess.CompletedProcess:
        """Run ``terraform <args>`` locally if available, else via Docker."""
        if shutil.which("terraform"):
            return subprocess.run(
                ["terraform", *args],
                capture_output=True, text=True, cwd=path,
            )
        cmd = self._docker_command(get_image("terraform"), path, args)
        return subprocess.run(cmd, capture_output=True, text=True)

    def _run_tflint_subprocess(self, args: list[str], path: str) -> subprocess.CompletedProcess | None:
        """Run ``tflint <args>``, returning None when neither local nor docker is available."""
        if shutil.which("tflint"):
            return subprocess.run(
                ["tflint", *args],
                capture_output=True, text=True, cwd=path,
            )
        if shutil.which("docker"):
            cmd = self._docker_command(get_image("tflint"), path, args)
            return subprocess.run(cmd, capture_output=True, text=True)
        return None

    @staticmethod
    def _docker_command(image: str, workspace: str, args: list[str]) -> list[str]:
        """Build a ``docker run -v <workspace>:/workspace -w /workspace <image> <args>``.

        The mount is read-write so ``terraform init`` can write
        ``.terraform/`` plugin state. tflint also writes to a
        ``.tflint.d/`` subdir on init. The user's repo is already where
        terraform would write locally; mounting RW preserves that
        contract.
        """
        workspace_abs = str(Path(workspace).resolve())
        return [
            "docker", "run", "--rm",
            "-v", f"{workspace_abs}:/workspace",
            "-w", "/workspace",
            image,
            *args,
        ]

    # ------------------------------------------------------------------
    # Per-tool runners
    # ------------------------------------------------------------------

    def _run_fmt_check(self, path: str) -> list[Finding]:
        """Run ``terraform fmt -check`` to find formatting issues."""
        result = self._run_terraform(["fmt", "-check", "-recursive", "-diff"], path)

        if result.returncode == 0:
            return []

        findings = []
        for line in result.stdout.strip().splitlines():
            line = line.strip()
            if not line or line.startswith(("---", "+++", "@@", " ", "-", "+")):
                continue
            findings.append(Finding(
                id="terraform-fmt",
                severity=Severity.INFO,
                title=f"File needs formatting: {line}",
                description="Run 'terraform fmt' to fix formatting.",
                location=line,
                scanner=self.name,
            ))
        return findings

    def _run_validate(self, path: str) -> list[Finding]:
        """Run ``terraform validate`` (preceded by ``terraform init -backend=false``)."""
        # init writes plugin state into .terraform/ so validate can read it.
        self._run_terraform(["init", "-backend=false"], path)
        result = self._run_terraform(["validate", "-json"], path)

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []

        if data.get("valid", True):
            return []

        findings = []
        for diag in data.get("diagnostics", []):
            location = None
            diag_range = diag.get("range", {})
            filename = diag_range.get("filename", "")
            start = diag_range.get("start", {})
            if filename:
                line_num = start.get("line", 0)
                location = f"{filename}:{line_num}"

            findings.append(Finding(
                id="terraform-validate",
                severity=Severity.INFO,
                title=diag.get("summary", "Validation error"),
                description=diag.get("detail", ""),
                location=location,
                scanner=self.name,
                metadata={"severity": diag.get("severity", "")},
            ))
        return findings

    def _run_tflint(self, path: str, config: dict) -> list[Finding]:
        """Run tflint for additional linting rules.

        Skips silently when neither local tflint nor docker is
        available — terraform fmt/validate already produce findings,
        so a missing tflint isn't a hard error.
        """
        args = ["--format=json"]
        config_file = config.get("tflint_config")
        if config_file:
            args.append(f"--config={config_file}")

        result = self._run_tflint_subprocess(args, path)
        if result is None:
            return []

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []

        findings = []
        for issue in data.get("issues", []):
            location = None
            issue_range = issue.get("range", {})
            filename = issue_range.get("filename", "")
            start = issue_range.get("start", {})
            if filename:
                line_num = start.get("line", 0)
                location = f"{filename}:{line_num}"

            findings.append(Finding(
                id=issue.get("rule", {}).get("name", "tflint"),
                severity=Severity.INFO,
                title=issue.get("message", ""),
                description=issue.get("message", ""),
                location=location,
                scanner=self.name,
                metadata={
                    "rule_severity": issue.get("rule", {}).get("severity", ""),
                },
            ))
        return findings
