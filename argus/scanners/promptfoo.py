"""promptfoo LLM-security scanner (red-team / eval).

promptfoo (https://github.com/promptfoo/promptfoo) is an OSS LLM
eval and red-team framework with 60+ plugins aligned to the OWASP
LLM Top 10 (prompt injection, jailbreaks, PII leakage, etc.). It
ships a Docker image and a JSON output mode, which fits the Argus
container-first execution model — the Node.js runtime stays inside
the promptfoo image and never touches Argus core.

This scanner is **opt-in** (not part of ``all``) and requires
network access plus provider API keys at scan time.

Configuration keys read from ``scanners.promptfoo.*`` in argus.yml:

  config_file           — path to the user's promptfoo config
                           (promptfooconfig.yaml); mounted into the
                           container and passed to ``promptfoo eval -c``
  cmd_options           — list[str] appended verbatim to the promptfoo CLI
  openai_api_key        — literal OR openai_api_key_env for env-ref
  anthropic_api_key     — literal OR anthropic_api_key_env for env-ref
  api_keys              — optional map of {ENV_NAME: <field>/<field>_env}
                           for any additional provider beyond the two
                           built-in shortcuts

Provider API keys NEVER appear as YAML literals when ``*_env`` is
used; ``argus.core.secrets.resolve_secret`` reads from ``os.environ``
at scan time and the value is exported as the provider's native env
var into the container. Adversarial prompts and model responses from
the results JSON are NOT echoed into ``Finding`` text fields — only
structural metadata (plugin id, assertion type, pass/fail) flows out.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path

from argus.containers import get_image
from argus.core.models import Finding, ScanResult, Severity
from argus.core.secrets import resolve_secret

logger = logging.getLogger("argus")

# Container-side path where the user's promptfoo config is mounted.
_CONTAINER_CONFIG_PATH = "/app/promptfooconfig.yaml"
_CONTAINER_OUTPUT_PATH = "/output/results.json"

# Red-team plugin ids whose successful attack is a high-severity
# security failure (the model was successfully manipulated). promptfoo
# namespaces red-team plugins; we match on substrings of the plugin id.
_HIGH_RISK_PLUGINS = (
    "prompt-injection",
    "jailbreak",
    "harmful",
    "pii",
    "rbac",
    "bola",
    "bfla",
    "ssrf",
    "sql-injection",
    "shell-injection",
    "debug-access",
    "excessive-agency",
)

# Map a promptfoo metric/assertion-type hint to a severity when no
# red-team plugin id is present (plain eval assertion failure).
_ASSERTION_SEVERITY = {
    "moderation": Severity.HIGH,
    "is-refusal": Severity.MEDIUM,
}


def _severity_for(plugin_id: str | None, assertion_type: str | None) -> Severity:
    """Map a failed promptfoo result to a Severity.

    Red-team plugin hits (prompt injection, jailbreak, PII, etc.) are
    HIGH — the model was successfully attacked. Other failed
    assertions default to MEDIUM unless the assertion type maps lower.
    """
    pid = (plugin_id or "").lower()
    if any(risk in pid for risk in _HIGH_RISK_PLUGINS):
        return Severity.HIGH
    atype = (assertion_type or "").lower()
    return _ASSERTION_SEVERITY.get(atype, Severity.MEDIUM)


def _build_promptfoo_args(config: dict, output_path: str) -> list[str]:
    """Build the argv for a promptfoo eval inside the container.

    ``cmd_options`` is appended last so it can override earlier flags.
    """
    cmd: list[str] = [
        "eval",
        "-c", _CONTAINER_CONFIG_PATH,
        "-o", output_path,
        "--no-progress-bar",
    ]
    extra_opts = config.get("cmd_options") or []
    cmd.extend(str(o) for o in extra_opts)
    return cmd


class PromptfooScanner:
    """Wraps promptfoo to perform LLM red-team / eval security testing."""

    name = "promptfoo"
    description = "LLM-security testing — red-team and eval against provider models"
    category = "llm-security"
    languages = ["llm"]
    container_image = get_image("promptfoo")

    def container_args(self, config: dict | None = None) -> list[str]:
        """Return CLI args for running promptfoo in a container."""
        config = config or {}
        return _build_promptfoo_args(config, _CONTAINER_OUTPUT_PATH)

    def container_env(self, config: dict | None = None) -> dict[str, str]:
        """Resolve provider API keys and expose them to the container.

        Keys are resolved via ``resolve_secret`` (env-var indirection
        preferred) and exported under the provider's native env-var
        name that promptfoo reads (``OPENAI_API_KEY``,
        ``ANTHROPIC_API_KEY``, …). Resolved values never reach the
        per-scanner config dict, the command args, or any Finding.
        """
        config = config or {}
        env: dict[str, str] = {}

        # Built-in shortcuts for the two most common providers.
        openai = resolve_secret(config, "openai_api_key")
        if openai:
            env["OPENAI_API_KEY"] = openai

        anthropic = resolve_secret(config, "anthropic_api_key")
        if anthropic:
            env["ANTHROPIC_API_KEY"] = anthropic

        # Generic map for any additional provider. Each entry maps the
        # provider's native env-var name (the key, e.g. MISTRAL_API_KEY)
        # to the *name* of the host env var holding the secret (the
        # value). The secret is read from os.environ at scan time — its
        # literal value never appears in argus.yml.
        api_keys = config.get("api_keys") or {}
        if isinstance(api_keys, dict):
            for provider_env_name, source_env_name in api_keys.items():
                value = resolve_secret(
                    {"key_env": source_env_name}, "key",
                )
                if value:
                    env[str(provider_env_name)] = value

        return env

    def container_mounts(
        self, config: dict | None = None,
    ) -> list[tuple[str, str]]:
        """Bind the user's promptfoo config file into the container."""
        config = config or {}
        config_file = config.get("config_file")
        if config_file:
            return [(config_file, _CONTAINER_CONFIG_PATH)]
        return []

    def scan(self, path: str, config: dict | None = None) -> ScanResult:
        """Run promptfoo via the local ``promptfoo`` binary.

        This is the legacy local-binary path; the container path
        (driven by the engine via ``container_args`` / ``container_env``
        / ``container_mounts``) is the supported one. Requires a
        ``config_file`` pointing at a promptfoo config.
        """
        config = config or {}
        config_file = config.get("config_file")

        if not config_file:
            return ScanResult(
                scanner=self.name,
                metadata={"error": "config_file is required in config"},
            )

        with tempfile.TemporaryDirectory() as tmp_dir:
            output_file = Path(tmp_dir) / "results.json"
            cmd = ["promptfoo"] + _build_promptfoo_args(config, str(output_file))

            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                )
            except FileNotFoundError as exc:
                return ScanResult(
                    scanner=self.name,
                    metadata={
                        "error": (
                            f"promptfoo not installed: {exc}. "
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
        """Check if the promptfoo CLI is installed locally."""
        return shutil.which("promptfoo") is not None

    def install_command(self) -> str | None:
        """Return install hint for promptfoo (container is preferred)."""
        return "npm install -g promptfoo"

    def tool_version(self) -> str | None:
        """Return None — promptfoo runs exclusively via Docker container."""
        return None

    def parse_results(self, raw_output_path: Path) -> list[Finding]:
        """Parse promptfoo JSON output into findings.

        promptfoo's ``--output results.json`` produces a top-level
        ``results.results`` list of per-test evaluation records. Only
        FAILED records become findings: a failed assertion is an eval
        miss, and a failed red-team probe is a successful attack.

        Secret-leak audit: the adversarial prompt and the model's
        response can contain user secrets or PII; they are deliberately
        omitted from every Finding field. Only structural identifiers
        (plugin id, assertion type, provider) are surfaced.
        """
        data = json.loads(
            raw_output_path.read_text(encoding="utf-8", errors="replace")
        )
        results_block = data.get("results", {})
        # promptfoo nests the per-test list under results.results; some
        # versions put it at the top level under "results".
        records = results_block.get("results", []) if isinstance(
            results_block, dict
        ) else results_block

        findings: list[Finding] = []
        for index, record in enumerate(records):
            if record.get("success", True):
                continue
            findings.append(self._parse_record(record, index))
        return findings

    def _parse_record(self, record: dict, index: int) -> Finding:
        """Convert a single failed promptfoo result into a Finding."""
        test_case = record.get("testCase", {}) or {}
        metadata = test_case.get("metadata", {}) or {}
        plugin_id = metadata.get("pluginId") or record.get("pluginId")

        grading = record.get("gradingResult", {}) or {}
        assertion = (record.get("assertion") or {})
        assertion_type = assertion.get("type") if isinstance(
            assertion, dict
        ) else None

        severity = _severity_for(plugin_id, assertion_type)

        provider = record.get("provider")
        if isinstance(provider, dict):
            provider = provider.get("id") or provider.get("label")

        if plugin_id:
            title = f"LLM red-team failure: {plugin_id}"
        else:
            title = "LLM eval assertion failed"

        # Reason text from promptfoo can echo the model response; keep
        # only the short structural reason, never the prompt/response.
        reason = grading.get("reason", "")
        description = (
            "promptfoo flagged a failing LLM security check. "
            "Review the promptfoo report for the adversarial prompt "
            "and model response (omitted here to avoid leaking secrets)."
        )

        return Finding(
            id=str(plugin_id or f"promptfoo-{index}"),
            severity=severity,
            title=title,
            description=description,
            scanner=self.name,
            metadata={
                "plugin_id": plugin_id,
                "assertion_type": assertion_type,
                "provider": provider,
                "pass": False,
                "grading_reason_present": bool(reason),
            },
        )
