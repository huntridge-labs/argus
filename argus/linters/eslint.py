"""JavaScript / TypeScript linter wrapping ESLint.

Replaces the legacy jshint integration. ESLint is the de-facto
JavaScript / TypeScript linter — actively maintained, has the broadest
plugin ecosystem, and ships an official multi-arch container at
``pipelinecomponents/eslint`` that keeps argus out of the business of
maintaining a Node container.

The linter is intentionally *config-driven*. ESLint only emits findings
when the project has an ``eslint.config.js``, ``eslint.config.mjs``, or
legacy ``.eslintrc*`` file at the workspace root — without one, the
tool exits with a "no configuration found" error. We treat that as a
clean no-op (info-level metadata) rather than a failure: a user
running ``argus scan`` against a repo that doesn't use ESLint
shouldn't see a hard error every time.
"""

import json
import shutil
import subprocess
from pathlib import Path

from argus.containers import get_image
from argus.core.linter_template import build_docker_command
from argus.core.models import Finding, ScanResult, Severity
from argus.core.version import parse_tool_version


# Files ESLint reads to discover its config. If none of these exist,
# scan() returns a clean "no eslint config" info row instead of running
# the tool — a project without an eslint config isn't an error.
_ESLINT_CONFIG_NAMES = (
    "eslint.config.js",
    "eslint.config.mjs",
    "eslint.config.cjs",
    "eslint.config.ts",
    ".eslintrc.js",
    ".eslintrc.cjs",
    ".eslintrc.json",
    ".eslintrc.yml",
    ".eslintrc.yaml",
)

# ESLint severity → argus Severity. ``2`` is error, ``1`` is warning;
# we promote both into the linter band but distinguish the two so a
# review can sort by severity later.
_ESLINT_SEVERITY = {
    2: Severity.LOW,    # error
    1: Severity.INFO,   # warning
}


class EslintLinter:
    """Wraps ESLint to lint JavaScript / TypeScript code."""

    name = "lint-javascript"
    description = "JavaScript / TypeScript linter (ESLint)"
    category = "linter"
    languages = ["javascript", "typescript"]
    container_image = get_image("eslint")

    def scan(self, path: str, config: dict | None = None) -> ScanResult:
        """Run ESLint against *path* and return findings.

        Falls back to the official ``pipelinecomponents/eslint``
        container when the local ``eslint`` binary isn't installed —
        same shape as ``HadolintLinter.scan``. Treats "no eslint
        config in the project" as a clean info row rather than a
        failure.
        """
        config = config or {}
        target = Path(path)

        if not self._has_eslint_config(target, config.get("config_file")):
            return ScanResult(
                scanner=self.name,
                metadata={
                    "info": (
                        "No ESLint config found at the workspace root "
                        "(eslint.config.js, .eslintrc*, etc.). Skipping; "
                        "see https://eslint.org/docs/latest/use/configure/"
                    ),
                },
            )

        if self.is_available():
            cmd = self._build_command(path, config)
        else:
            cmd = self._build_docker_command(target, config)
            if cmd is None:
                return ScanResult(
                    scanner=self.name,
                    metadata={
                        "execution_failed": True,
                        "execution_failure_reason": (
                            "eslint not installed and Docker not available. "
                            "Install eslint via 'npm install -g eslint' or "
                            "install Docker to use the container backend."
                        ),
                    },
                )

        result = subprocess.run(cmd, capture_output=True, text=True)

        # ESLint exits 0 on no findings, 1 on findings, 2 on tool error.
        # Empty stdout with a non-zero return code means a real error.
        if not result.stdout.strip():
            if result.returncode in (0, 1):
                return ScanResult(scanner=self.name, findings=[])
            return ScanResult(
                scanner=self.name,
                metadata={
                    "execution_failed": True,
                    "execution_failure_reason": (
                        f"ESLint produced no output (exit={result.returncode}). "
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
                    "execution_failure_reason": f"Invalid JSON from eslint: {exc}",
                },
            )

        findings: list[Finding] = []
        for entry in data:
            file_path = entry.get("filePath", "")
            for msg in entry.get("messages", []):
                findings.append(self._parse_message(msg, file_path))
        return ScanResult(scanner=self.name, findings=findings)

    def is_available(self) -> bool:
        return shutil.which("eslint") is not None

    def install_command(self) -> str | None:
        return "npm install -g eslint"

    def tool_version(self) -> str | None:
        if not self.is_available():
            return None
        return parse_tool_version(["eslint", "--version"], r"v?(\d+\.\d+\.\d+)")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _has_eslint_config(self, target: Path, explicit_config: str | None) -> bool:
        """Return True when the project has an ESLint configuration.

        An explicit ``config_file`` in argus.yml always wins. Otherwise
        check the workspace root for any of the standard ESLint config
        filenames, or a ``package.json`` with an ``eslintConfig``
        field.
        """
        if explicit_config:
            return True

        for name in _ESLINT_CONFIG_NAMES:
            if (target / name).is_file():
                return True

        package_json = target / "package.json"
        if package_json.is_file():
            try:
                data = json.loads(package_json.read_text(encoding="utf-8"))
                if isinstance(data, dict) and "eslintConfig" in data:
                    return True
            except (json.JSONDecodeError, OSError):
                pass

        return False

    def _build_command(self, path: str, config: dict) -> list[str]:
        """Build the local ESLint CLI command."""
        cmd = ["eslint", "--format", "json", "--no-error-on-unmatched-pattern"]
        if config.get("config_file"):
            cmd.extend(["--config", config["config_file"]])
        cmd.append(path)
        return cmd

    def _build_docker_command(
        self, target: Path, config: dict,
    ) -> list[str] | None:
        """Build a ``docker run pipelinecomponents/eslint`` command, or None when Docker is unavailable.

        The ``pipelinecomponents/eslint`` image ships with eslint on
        PATH and an ENTRYPOINT that passes its argv straight through,
        so the in-container args are ``eslint --format json
        --no-error-on-unmatched-pattern [--config ...] .``. The
        workspace mount + ``-w /workspace`` come from the shared
        ``build_docker_command`` helper.
        """
        if shutil.which("docker") is None:
            return None

        args = [
            "eslint",
            "--format", "json",
            "--no-error-on-unmatched-pattern",
        ]
        if config.get("config_file"):
            args.extend(["--config", f"/workspace/{config['config_file']}"])
        args.append(".")
        return build_docker_command(
            self.container_image, target, args, workdir="/workspace",
        )

    def _parse_message(self, msg: dict, file_path: str) -> Finding:
        """Convert a single ESLint message dict into a Finding."""
        line_num = msg.get("line", 0)
        location = f"{file_path}:{line_num}" if file_path else None
        rule = msg.get("ruleId") or "eslint"
        severity_int = msg.get("severity", 1)

        return Finding(
            id=rule,
            severity=_ESLINT_SEVERITY.get(severity_int, Severity.INFO),
            title=msg.get("message", ""),
            description=msg.get("message", ""),
            location=location,
            scanner=self.name,
            metadata={
                "rule": rule,
                "column": msg.get("column", 0),
                "node_type": msg.get("nodeType", ""),
                "file": file_path,
            },
        )
