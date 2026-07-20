"""Grype standalone scanner — SBOM-input vulnerability scanning.

Used by ``argus scan --sbom`` to pass a pre-existing SBOM (CycloneDX,
SPDX, or Syft JSON) to Grype and collect vulnerability findings. Grype
also supports filesystem and image-based scanning upstream; for now
this module only wires the SBOM path because that's what the SBOM
feature needs. Filesystem/image modes remain covered by the
``container`` scanner's bundled Grype invocation.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from argus.containers import get_image
from argus.core.models import Finding, ScanResult, Severity

from argus.scanners._vuln_parsers import parse_grype_match


class GrypeScanner:
    """Run Grype against a CycloneDX/SPDX/Syft SBOM."""

    name = "grype"
    description = "Vulnerability scanner — consumes CycloneDX/SPDX/Syft SBOMs"
    category = "sca"
    languages = ["all"]
    container_image = get_image("grype")
    supports_sbom = True
    supports_vex = True

    def container_args(self, config: dict | None = None) -> list[str]:
        """Container args for ``anchore/grype``.

        Grype's image uses ``grype`` as entrypoint, so we return only the
        flags/positionals (no leading ``grype``). The engine mounts the
        SBOM into the container at ``sbom_mount_path`` (set by the engine;
        defaults to ``/workspace/<sbom_filename>``).
        """
        from argus.core.vex import vex_cli_flags

        config = config or {}
        sbom_path = config.get("sbom_path")
        if not sbom_path:
            from argus.core.engine import ScannerPreconditionError
            raise ScannerPreconditionError(
                "grype scanner requires sbom_path (run via `argus scan --sbom <path>`)"
            )
        mount = config.get("sbom_mount_path") or f"/workspace/{Path(sbom_path).name}"
        return [
            f"sbom:{mount}",
            "-o", "json",
            "--file", "/output/results.json",
            *vex_cli_flags(config, in_container=True),
        ]

    def container_mounts(self, config: dict | None = None) -> list[tuple[str, str]]:
        """Bind-mount any configured OpenVEX documents into the grype container.

        The engine adds ``-v`` / ``:ro`` around each ``(host, container)`` pair.
        """
        from argus.core.vex import vex_container_mounts

        return vex_container_mounts(config)

    def scan(self, path: str, config: dict | None = None) -> ScanResult:
        """Run grype against the SBOM given via ``config['sbom_path']``."""
        config = config or {}
        sbom_path = config.get("sbom_path")
        if not sbom_path:
            # Issue #168-I: raise ScannerPreconditionError instead of
            # returning a silently-passed result with only an ``error``
            # metadata key. The engine surfaces this distinctly and
            # marks the scanner ``execution_failed`` so CI gating treats
            # "couldn't run for lack of input" the same as "couldn't run
            # because it crashed" — both block the scan rather than
            # being recorded as a passed clean run.
            from argus.core.engine import ScannerPreconditionError
            raise ScannerPreconditionError(
                "grype scanner requires sbom_path (run via `argus scan --sbom <path>`)"
            )

        from argus.core.vex import vex_cli_flags

        with tempfile.TemporaryDirectory() as tmp_dir:
            output_file = Path(tmp_dir) / "grype-results.json"
            cmd = [
                "grype",
                f"sbom:{sbom_path}",
                "-o", "json",
                "--file", str(output_file),
                *vex_cli_flags(config, in_container=False),
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if not output_file.exists():
                return ScanResult(
                    scanner=self.name,
                    metadata={
                        "error": result.stderr.strip() or "grype produced no output",
                        "returncode": result.returncode,
                    },
                )
            findings = self.parse_results(output_file)
            return ScanResult(
                scanner=self.name,
                findings=findings,
                metadata={
                    "returncode": result.returncode,
                    "sbom_path": str(sbom_path),
                },
            )

    def is_available(self) -> bool:
        return shutil.which("grype") is not None

    def install_command(self) -> str | None:
        return (
            "curl -sSfL https://raw.githubusercontent.com/anchore/grype/"
            "main/install.sh | sh -s -- -b /usr/local/bin"
        )

    def tool_version(self) -> str | None:
        if not self.is_available():
            return None
        try:
            res = subprocess.run(
                ["grype", "version", "-o", "json"],
                capture_output=True, text=True, timeout=5,
            )
            data = json.loads(res.stdout)
            v = data.get("version")
            return v if isinstance(v, str) else None
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError, OSError):
            return None

    def parse_results(self, raw_output_path: Path) -> list[Finding]:
        """Parse Grype JSON output into Finding objects.

        When Grype can't identify the scan subject from the SBOM
        (e.g. SPDX tag-value without purl refs), it still emits a
        results file but with ``source.target = "unknown"`` and zero
        matches. That's a "couldn't identify anything" signal — NOT a
        "nothing vulnerable" signal — so we stash the fact on a module
        attribute the scan() method reads to annotate metadata. We
        can't add it here directly because ``parse_results`` only
        returns a list of Finding; engine.py:_run_in_container is where
        the metadata gets attached.
        """
        try:
            data = json.loads(Path(raw_output_path).read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, OSError):
            return []
        matches = data.get("matches") or []
        # Surface the "unknown source" signal via a module-level warning
        # plus the parse_results (list, extra) tuple convention the engine
        # understands. The extra dict is merged into result.metadata.
        target = data.get("source", {}).get("target", "")
        extra: dict = {}
        if isinstance(target, str) and target == "unknown" and not matches:
            extra["warning"] = (
                "Grype could not identify the scan subject "
                "(source.target=unknown). 0 findings does not mean "
                "clean — the SBOM likely lacks purl external refs."
            )
        findings = [parse_grype_match(m, scanner_name=self.name) for m in matches]
        return (findings, extra) if extra else findings
