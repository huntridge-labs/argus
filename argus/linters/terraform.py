"""Terraform linter wrapping terraform fmt, validate, and tflint."""

import json
import shutil
import subprocess
from pathlib import Path

from argus.core.models import Finding, ScanResult, Severity


class TerraformLinter:
    """Wraps terraform fmt/validate and tflint for Terraform linting."""

    name = "lint-terraform"
    description = "Terraform formatting and validation linter"
    category = "linter"
    languages = ["terraform"]

    def scan(self, path: str, config: dict | None = None) -> ScanResult:
        """Run terraform fmt check, validate, and optionally tflint."""
        config = config or {}
        all_findings: list[Finding] = []

        fmt_findings = self._run_fmt_check(path)
        all_findings.extend(fmt_findings)

        validate_findings = self._run_validate(path)
        all_findings.extend(validate_findings)

        run_tflint = config.get("run_tflint", True)
        if run_tflint and shutil.which("tflint"):
            tflint_findings = self._run_tflint(path, config)
            all_findings.extend(tflint_findings)

        return ScanResult(scanner=self.name, findings=all_findings)

    def is_available(self) -> bool:
        """Check if terraform is installed."""
        return shutil.which("terraform") is not None

    def install_command(self) -> str | None:
        """Return install instructions for terraform."""
        return "Install from https://developer.hashicorp.com/terraform/install"

    def tool_version(self) -> str | None:
        """Return the installed Terraform version, or None if not available."""
        if not self.is_available():
            return None
        try:
            result = subprocess.run(
                ["terraform", "--version"],
                capture_output=True, text=True, timeout=5,
            )
            # Output: "Terraform vX.Y.Z\non ..."
            text = result.stdout.strip()
            if not text:
                return None
            first_line = text.splitlines()[0]
            parts = first_line.split()
            if len(parts) >= 2 and parts[0] == "Terraform":
                return parts[1].lstrip("v")
            return None
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            return None

    def _run_fmt_check(self, path: str) -> list[Finding]:
        """Run terraform fmt -check to find formatting issues."""
        result = subprocess.run(
            ["terraform", "fmt", "-check", "-recursive", "-diff"],
            capture_output=True,
            text=True,
            cwd=path,
        )

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
        """Run terraform validate to check configuration validity."""
        # terraform init is required before validate
        subprocess.run(
            ["terraform", "init", "-backend=false"],
            capture_output=True,
            text=True,
            cwd=path,
        )

        result = subprocess.run(
            ["terraform", "validate", "-json"],
            capture_output=True,
            text=True,
            cwd=path,
        )

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
        """Run tflint for additional linting rules."""
        cmd = ["tflint", "--format=json"]

        config_file = config.get("tflint_config")
        if config_file:
            cmd.append(f"--config={config_file}")

        result = subprocess.run(
            cmd, capture_output=True, text=True, cwd=path
        )

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
