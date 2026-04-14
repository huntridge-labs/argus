"""Dockerfile linter wrapping hadolint."""

import json
import shutil
import subprocess
from pathlib import Path

from argus.containers import get_image
from argus.core.models import Finding, ScanResult, Severity


class HadolintLinter:
    """Wraps hadolint to lint Dockerfiles for best-practice violations."""

    name = "lint-dockerfile"
    container_image = get_image("hadolint")

    def scan(self, path: str, config: dict | None = None) -> ScanResult:
        """Find Dockerfiles under path and lint each with hadolint."""
        config = config or {}
        target = Path(path)

        dockerfiles = self._find_dockerfiles(target)
        if not dockerfiles:
            return ScanResult(
                scanner=self.name,
                metadata={"info": "No Dockerfiles found"},
            )

        all_findings: list[Finding] = []
        for dockerfile in dockerfiles:
            findings = self._lint_file(dockerfile, config)
            all_findings.extend(findings)

        return ScanResult(scanner=self.name, findings=all_findings)

    def is_available(self) -> bool:
        """Check if hadolint is installed."""
        return shutil.which("hadolint") is not None

    def install_command(self) -> str | None:
        """Return install instructions for hadolint."""
        return "Install from https://github.com/hadolint/hadolint/releases"

    def _find_dockerfiles(self, target: Path) -> list[Path]:
        """Find all Dockerfile-like files under the target path."""
        if target.is_file():
            return [target]
        return sorted(target.rglob("Dockerfile*"))

    def _lint_file(
        self, dockerfile: Path, config: dict
    ) -> list[Finding]:
        """Run hadolint on a single Dockerfile and parse results."""
        cmd = self._build_command(dockerfile, config)

        result = subprocess.run(cmd, capture_output=True, text=True)

        if not result.stdout.strip():
            return []

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []

        return [self._parse_item(item, dockerfile) for item in data]

    def _build_command(
        self, dockerfile: Path, config: dict
    ) -> list[str]:
        """Build the hadolint CLI command."""
        cmd = ["hadolint", "--format", "json"]

        config_file = config.get("config_file")
        if config_file:
            cmd.extend(["--config", config_file])

        ignore_rules = config.get("ignore_rules", [])
        for rule in ignore_rules:
            cmd.extend(["--ignore", rule])

        cmd.append(str(dockerfile))
        return cmd

    def _parse_item(self, item: dict, dockerfile: Path) -> Finding:
        """Convert a single hadolint JSON result into a Finding."""
        rule_code = item.get("code", "UNKNOWN")
        line_num = item.get("line", 0)
        location = f"{dockerfile}:{line_num}"

        return Finding(
            id=rule_code,
            severity=Severity.INFO,
            title=item.get("message", ""),
            description=item.get("message", ""),
            location=location,
            scanner=self.name,
            metadata={
                "level": item.get("level", ""),
                "column": item.get("column", 0),
                "file": str(dockerfile),
            },
        )
