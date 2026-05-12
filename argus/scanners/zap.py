"""OWASP ZAP DAST scanner.

Configuration keys read from ``scanners.zap.*`` in argus.yml (decided
in ADR-024):

  target_url            — URL of the running app to scan (required
                           unless ``app_image_ref`` brings up a sidecar)
  scan_type             — "baseline" (default) | "full" | "api"; ``api``
                           is also auto-selected when ``api_spec`` is set
  api_spec              — OpenAPI/Swagger spec URL or path for API scans
  rules_file            — path to a ZAP ``.tsv`` ignore-rules file
  cmd_options           — list[str] appended verbatim to the ZAP CLI
  max_duration_minutes  — int hard cap on scan duration
  registry_username     — literal OR registry_username_env for env-ref
  registry_password     — literal OR registry_password_env for env-ref
  auth.context_file     — path to a ZAP context XML (mounted)
  auth.username         — literal OR auth.username_env for env-ref
  auth.password         — literal OR auth.password_env for env-ref

Credentials NEVER appear as YAML literals when ``*_env`` is used;
``argus.core.secrets.resolve_secret`` reads from ``os.environ`` at
scan time. Web-app auth credentials are exported into the ZAP
container as ``ZAP_AUTH_USERNAME`` / ``ZAP_AUTH_PASSWORD`` which the
user's context file picks up via ZAP's native ``{%username%}`` /
``{%password%}`` placeholders.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from argus.containers import get_image
from argus.core.models import Finding, ScanResult, Severity
from argus.core.secrets import resolve_secret

logger = logging.getLogger("argus")

_RISKCODE_MAP = {
    "3": Severity.HIGH,
    "2": Severity.MEDIUM,
    "1": Severity.LOW,
    "0": Severity.INFO,
}

# Known paths inside the ZAP container where user-supplied files are
# expected. ZAP's standard scripts (``zap-baseline.py`` etc.) resolve
# relative paths against ``/zap/wrk``; we mount user files there.
_CONTAINER_RULES_PATH = "/zap/wrk/rules.tsv"
_CONTAINER_CONTEXT_PATH = "/zap/wrk/context.xml"


def _strip_html(text: str) -> str:
    """Remove HTML tags from a string."""
    return re.sub(r"<[^>]+>", "", text).strip()


def _resolve_scan_script(config: dict) -> str:
    """Pick the right ZAP script based on scan_type / api_spec."""
    if config.get("api_spec"):
        return "zap-api-scan.py"
    scan_type = str(config.get("scan_type", "baseline")).lower()
    if scan_type == "full":
        return "zap-full-scan.py"
    if scan_type == "api":
        return "zap-api-scan.py"
    return "zap-baseline.py"


def _build_zap_args(config: dict, output_path: str) -> list[str]:
    """Build the argv list for a ZAP scan inside the container.

    Output is always written to ``output_path`` (typically
    ``/output/results.json`` on the container side). All user-tunable
    knobs come from ``config``; ``cmd_options`` is appended last so it
    can override anything earlier in the argv.
    """
    script = _resolve_scan_script(config)
    cmd: list[str] = [script]

    if script == "zap-api-scan.py":
        spec = config.get("api_spec") or config.get("target_url")
        cmd.extend(["-t", spec, "-f", "openapi"])
    else:
        target = config.get("target_url", "http://localhost:3000")
        cmd.extend(["-t", target])

    cmd.extend(["-J", output_path, "-I"])

    rules_file = config.get("rules_file")
    if rules_file:
        cmd.extend(["-c", _CONTAINER_RULES_PATH])

    context_file = (config.get("auth") or {}).get("context_file")
    if context_file:
        cmd.extend(["-n", _CONTAINER_CONTEXT_PATH])

    max_minutes = config.get("max_duration_minutes")
    if max_minutes is not None:
        cmd.extend(["-T", str(max_minutes)])

    extra_opts = config.get("cmd_options") or []
    cmd.extend(str(o) for o in extra_opts)

    return cmd


class ZapScanner:
    """Wraps OWASP ZAP to perform dynamic application security testing."""

    name = "zap"
    description = "Dynamic application security testing — web application vulnerability scanning"
    category = "dast"
    languages = ["web"]
    container_image = get_image("zap")

    def container_args(self, config: dict | None = None) -> list[str]:
        """Return CLI args for running ZAP in a container."""
        config = config or {}
        return _build_zap_args(config, "/output/results.json")

    def container_env(self, config: dict | None = None) -> dict[str, str | None]:
        """Resolve credential fields and expose them to the ZAP container.

        Registry credentials are forwarded for any subsequent
        ``docker pull`` activity ZAP itself performs (none today, but
        the ZAP_REGISTRY_* env-var convention keeps future use
        straightforward). Web-app credentials follow ZAP's standard
        ``ZAP_AUTH_USERNAME`` / ``ZAP_AUTH_PASSWORD`` env vars that
        context files reference via ``{%username%}`` / ``{%password%}``
        placeholders.
        """
        config = config or {}
        env: dict[str, str | None] = {}

        reg_user = resolve_secret(config, "registry_username")
        reg_pass = resolve_secret(config, "registry_password")
        if reg_user:
            env["ZAP_REGISTRY_USERNAME"] = reg_user
        if reg_pass:
            env["ZAP_REGISTRY_PASSWORD"] = reg_pass

        auth_block = config.get("auth") or {}
        auth_user = resolve_secret(auth_block, "username")
        auth_pass = resolve_secret(auth_block, "password")
        if auth_user:
            env["ZAP_AUTH_USERNAME"] = auth_user
        if auth_pass:
            env["ZAP_AUTH_PASSWORD"] = auth_pass

        return env

    def container_mounts(
        self, config: dict | None = None,
    ) -> list[tuple[str, str]]:
        """Bind user-supplied rules and context files into the container."""
        config = config or {}
        mounts: list[tuple[str, str]] = []

        rules_file = config.get("rules_file")
        if rules_file:
            mounts.append((rules_file, _CONTAINER_RULES_PATH))

        context_file = (config.get("auth") or {}).get("context_file")
        if context_file:
            mounts.append((context_file, _CONTAINER_CONTEXT_PATH))

        return mounts

    def scan(self, path: str, config: dict | None = None) -> ScanResult:
        """Run ZAP against a target URL via the local ``zap-cli`` binary.

        This is the legacy local-binary path; the container path
        (driven by the engine via ``container_args`` / ``container_env``
        / ``container_mounts``) is the supported one for ZAP. The
        local path supports the basic ``target_url`` / ``spider`` flags
        only — features like ``api_spec``, ``rules_file``, and
        ``max_duration_minutes`` require the container backend.
        """
        config = config or {}
        target_url = config.get("target_url")

        if not target_url:
            return ScanResult(
                scanner=self.name,
                metadata={"error": "target_url is required in config"},
            )

        # Warn if the user has set container-only knobs on the local path.
        container_only_keys = (
            "api_spec", "rules_file", "cmd_options",
            "max_duration_minutes", "auth",
        )
        used_container_only = [k for k in container_only_keys if config.get(k)]
        if used_container_only:
            logger.warning(
                "ZAP local-binary backend ignores %s — these require "
                "the container backend",
                ", ".join(used_container_only),
            )

        with tempfile.TemporaryDirectory() as tmp_dir:
            output_file = Path(tmp_dir) / "zap-results.json"
            cmd = self._build_command(target_url, output_file, config)

            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                )
            except FileNotFoundError as exc:
                # zap-cli binary missing on the local backend — the
                # engine's container fallback handles this normally,
                # but if a caller invokes scan() directly we still
                # need to fail gracefully instead of raising.
                return ScanResult(
                    scanner=self.name,
                    metadata={
                        "error": (
                            f"zap-cli not installed: {exc}. "
                            "Use the container backend or run "
                            f"`{self.install_command()}`."
                        ),
                    },
                )

            if not output_file.exists():
                return ScanResult(
                    scanner=self.name,
                    metadata={
                        "error": (
                            result.stderr.strip()
                            or "No output file produced"
                        ),
                        "returncode": result.returncode,
                    },
                )

            findings = self.parse_results(output_file)
            return ScanResult(
                scanner=self.name,
                findings=findings,
                raw_report=output_file,
            )

    def is_available(self) -> bool:
        """Check if ZAP CLI is installed."""
        return shutil.which("zap-cli") is not None

    def install_command(self) -> str | None:
        """Return install command for ZAP CLI."""
        return "pip install python-owasp-zap-v2.4"

    def tool_version(self) -> str | None:
        """Return None — ZAP runs exclusively via Docker container."""
        return None

    def parse_results(self, raw_output_path: Path) -> list[Finding]:
        """Parse ZAP JSON output into findings."""
        data = json.loads(raw_output_path.read_text(encoding="utf-8", errors="replace"))
        findings: list[Finding] = []

        for site in data.get("site", []):
            alerts = site.get("alerts", [])
            for alert in alerts:
                finding = self._parse_alert(alert)
                findings.append(finding)

        return findings

    def _parse_alert(self, alert: dict) -> Finding:
        """Convert a single ZAP alert into a Finding."""
        riskcode = str(alert.get("riskcode", "0"))
        severity = _RISKCODE_MAP.get(riskcode, Severity.UNKNOWN)

        cweid = alert.get("cweid", "")
        cwe = f"CWE-{cweid}" if cweid and cweid != "0" else None

        location = self._extract_location(alert)
        raw_desc = alert.get("desc", "")
        description = _strip_html(raw_desc)

        return Finding(
            id=alert.get("pluginid", "UNKNOWN"),
            severity=severity,
            title=alert.get("name", ""),
            description=description,
            location=location,
            cwe=cwe,
            scanner=self.name,
            metadata={
                "riskdesc": alert.get("riskdesc", ""),
                "solution": _strip_html(alert.get("solution", "")),
                "instance_count": len(alert.get("instances", [])),
            },
        )

    def _extract_location(self, alert: dict) -> str | None:
        """Extract location from the first alert instance."""
        instances = alert.get("instances", [])
        if not instances:
            return None

        first = instances[0]
        uri = first.get("uri", "")
        method = first.get("method", "")

        if uri and method:
            return f"{method} {uri}"
        return uri or None

    def _build_command(
        self, target_url: str, output_file: Path, config: dict
    ) -> list[str]:
        """Build the legacy local ``zap-cli quick-scan`` command."""
        cmd = [
            "zap-cli",
            "quick-scan",
            "--self-contained",
            "--start-options",
            "-config api.disablekey=true",
            "-f", "json",
            "-o", str(output_file),
        ]

        spider = config.get("spider", False)
        if spider:
            cmd.append("--spider")

        cmd.append(target_url)
        return cmd
