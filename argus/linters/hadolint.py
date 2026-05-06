"""Dockerfile linter wrapping hadolint."""

import json
import shutil
import subprocess
from pathlib import Path

from argus.containers import get_image
from argus.core.models import Finding, ScanResult, Severity
from argus.core.version import parse_tool_version


class HadolintLinter:
    """Wraps hadolint to lint Dockerfiles for best-practice violations."""

    name = "lint-dockerfile"
    description = "Dockerfile best practice linter"
    category = "linter"
    languages = ["dockerfile"]
    container_image = get_image("hadolint")

    def scan(self, path: str, config: dict | None = None) -> ScanResult:
        """Find Dockerfiles under *path* and lint them all in one hadolint invocation.

        Hadolint accepts multiple file paths on its CLI (``hadolint
        file1 file2 ...``) and emits a single JSON array spanning every
        file's findings. Doing one batched call beats spawning
        ``len(dockerfiles)`` subprocesses by N startup costs and keeps
        the per-finding ``file`` field intact in the parsed output.
        """
        config = config or {}
        target = Path(path)

        dockerfiles = self._find_dockerfiles(target)
        if not dockerfiles:
            return ScanResult(
                scanner=self.name,
                metadata={"info": "No Dockerfiles found"},
            )

        cmd = self._build_command(dockerfiles, config)
        result = subprocess.run(cmd, capture_output=True, text=True)

        # hadolint exits 0 when clean, non-zero when findings exist —
        # both are the happy path. Empty stdout means a real error
        # (binary missing, parse failure inside hadolint, etc.).
        if not result.stdout.strip():
            return ScanResult(
                scanner=self.name,
                metadata={
                    "execution_failed": True,
                    "execution_failure_reason": (
                        f"hadolint produced no output (exit={result.returncode}). "
                        f"stderr: {(result.stderr or '').strip()[:400]}"
                    ),
                },
            )

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            return ScanResult(
                scanner=self.name,
                metadata={
                    "execution_failed": True,
                    "execution_failure_reason": f"Invalid JSON from hadolint: {exc}",
                },
            )

        findings = [self._parse_item(item) for item in data]
        return ScanResult(scanner=self.name, findings=findings)

    def is_available(self) -> bool:
        """Check if hadolint is installed."""
        return shutil.which("hadolint") is not None

    def install_command(self) -> str | None:
        """Return install instructions for hadolint."""
        return "Install from https://github.com/hadolint/hadolint/releases"

    def tool_version(self) -> str | None:
        """Return the installed hadolint version, or None if not available."""
        if not self.is_available():
            return None
        return parse_tool_version(["hadolint", "--version"], r"Linter (\d+\.\d+\.\d+)")

    def _find_dockerfiles(self, target: Path) -> list[Path]:
        """Find all Dockerfile-like files under the target path."""
        if target.is_file():
            return [target]
        return sorted(target.rglob("Dockerfile*"))

    def _build_command(
        self, dockerfiles: list[Path], config: dict
    ) -> list[str]:
        """Build a single hadolint command covering every Dockerfile.

        Hadolint takes multiple file arguments and emits one combined
        JSON array — far cheaper than spawning a process per file.
        """
        cmd = ["hadolint", "--format", "json"]

        config_file = config.get("config_file")
        if config_file:
            cmd.extend(["--config", config_file])

        for rule in config.get("ignore_rules", []) or []:
            cmd.extend(["--ignore", rule])

        cmd.extend(str(p) for p in dockerfiles)
        return cmd

    def _parse_item(self, item: dict) -> Finding:
        """Convert a single hadolint JSON result into a Finding.

        Hadolint emits the source file as ``item["file"]`` when it ran
        against multiple paths — we use that directly instead of
        threading the path in via the caller.
        """
        rule_code = item.get("code", "UNKNOWN")
        line_num = item.get("line", 0)
        dockerfile = item.get("file", "")
        location = f"{dockerfile}:{line_num}" if dockerfile else None

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
                "file": dockerfile,
            },
        )
