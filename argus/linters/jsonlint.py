"""JSON linter using jsonlint (Node.js) or Python json.tool fallback."""

import json
import shutil
import subprocess
from pathlib import Path

from argus.core.models import Finding, ScanResult, Severity


class JsonlintLinter:
    """Validates JSON files for syntax errors.

    Uses jsonlint (Node.js) when available, falls back to
    Python's built-in json module for validation.
    """

    name = "lint-json"
    description = "JSON syntax validator"
    category = "linter"
    languages = ["json"]

    def scan(self, path: str, config: dict | None = None) -> ScanResult:
        """Find and validate all JSON files under the given path."""
        target = Path(path)
        json_files = (
            list(target.rglob("*.json"))
            if target.is_dir()
            else [target]
        )

        use_jsonlint = shutil.which("jsonlint") is not None
        findings = []

        for json_file in json_files:
            finding = (
                self._validate_with_jsonlint(json_file)
                if use_jsonlint
                else self._validate_with_python(json_file)
            )
            if finding:
                findings.append(finding)

        return ScanResult(
            scanner=self.name,
            findings=findings,
            metadata={"method": "jsonlint" if use_jsonlint else "python"},
        )

    def is_available(self) -> bool:
        """JSON validation is always available via Python stdlib."""
        return True

    def install_command(self) -> str | None:
        """Return install command for jsonlint (optional)."""
        return "npm install -g jsonlint"

    def tool_version(self) -> str | None:
        """Return None — JSON validation uses Python stdlib fallback."""
        return None

    def _validate_with_jsonlint(self, file_path: Path) -> Finding | None:
        """Validate a single JSON file with jsonlint."""
        result = subprocess.run(
            ["jsonlint", "-q", str(file_path)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            error_msg = result.stderr.strip() or result.stdout.strip()
            return Finding(
                id="json-syntax-error",
                severity=Severity.INFO,
                title=f"Invalid JSON: {file_path.name}",
                description=error_msg,
                location=str(file_path),
                scanner=self.name,
            )
        return None

    def _validate_with_python(self, file_path: Path) -> Finding | None:
        """Validate a single JSON file with Python's json module."""
        try:
            json.loads(file_path.read_text(encoding="utf-8"))
            return None
        except json.JSONDecodeError as exc:
            return Finding(
                id="json-syntax-error",
                severity=Severity.INFO,
                title=f"Invalid JSON: {file_path.name}",
                description=str(exc),
                location=f"{file_path}:{exc.lineno}",
                scanner=self.name,
            )
        except OSError as exc:
            return Finding(
                id="json-read-error",
                severity=Severity.INFO,
                title=f"Cannot read: {file_path.name}",
                description=str(exc),
                location=str(file_path),
                scanner=self.name,
            )
