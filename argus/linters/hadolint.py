"""Dockerfile linter wrapping hadolint.

Implemented on top of :class:`argus.core.linter_template.FileDiscoveryScanner`:
the base does workspace discovery (glob ``Dockerfile*``), local→
container dispatch, UTF-8 subprocess, and the
``execution_failed`` / ``parse_failed`` metadata shape. Hadolint
specifics live in three short methods: ``_build_local_args``,
``_build_container_args``, and ``_parse_results``.
"""

import json
import shutil
import subprocess
from pathlib import Path

from argus.containers import get_image
from argus.core.linter_template import FileDiscoveryScanner
from argus.core.models import Finding, Severity
from argus.core.version import parse_tool_version


class HadolintLinter(FileDiscoveryScanner):
    """Wraps hadolint to lint Dockerfiles for best-practice violations."""

    name = "lint-dockerfile"
    description = "Dockerfile best practice linter"
    category = "linter"
    languages = ["dockerfile"]
    container_image = get_image("hadolint")
    binary = "hadolint"
    file_glob = "Dockerfile*"

    # hadolint: 0 = clean, 1 = findings (happy path); we accept both.
    accept_returncodes = (0, 1)

    def is_available(self) -> bool:
        return shutil.which("hadolint") is not None

    def install_command(self) -> str | None:
        return "Install from https://github.com/hadolint/hadolint/releases"

    def tool_version(self) -> str | None:
        if not self.is_available():
            return None
        return parse_tool_version(["hadolint", "--version"], r"Linter (\d+\.\d+\.\d+)")

    def _build_local_args(
        self, files: list[Path], config: dict
    ) -> list[str]:
        cmd = ["hadolint", "--format", "json"]
        config_file = config.get("config_file")
        if config_file:
            cmd.extend(["--config", config_file])
        for rule in config.get("ignore_rules", []) or []:
            cmd.extend(["--ignore", rule])
        cmd.extend(str(p) for p in files)
        return cmd

    def _build_container_args(
        self, container_files: list[str], config: dict
    ) -> list[str]:
        # The hadolint/hadolint image has no ENTRYPOINT — its CMD is
        # ``["/bin/hadolint", "-"]`` so passing args at the end of
        # ``docker run`` replaces CMD entirely. Include the binary
        # name explicitly as the first arg.
        args = ["hadolint", "--format", "json"]
        config_file = config.get("config_file")
        if config_file:
            args.extend(["--config", f"/workspace/{config_file}"])
        for rule in config.get("ignore_rules", []) or []:
            args.extend(["--ignore", rule])
        args.extend(container_files)
        return args

    def _parse_results(
        self, stdout: str, completed: subprocess.CompletedProcess
    ) -> list[Finding]:
        if not stdout:
            return []
        data = json.loads(stdout)
        return [self._parse_item(item) for item in data]

    def _parse_item(self, item: dict) -> Finding:
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
