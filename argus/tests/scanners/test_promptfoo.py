"""Tests for argus.scanners.promptfoo — PromptfooScanner."""

import json

from argus.core.models import Severity
from argus.core.redact import REDACTED_PLACEHOLDER
from argus.scanners.promptfoo import PromptfooScanner


class TestPromptfooParseResults:
    """Test PromptfooScanner.parse_results with fixture data."""

    def test_parse_redteam_results(self, fixtures_dir):
        scanner = PromptfooScanner()
        path = fixtures_dir / "promptfoo" / "results-redteam.json"
        findings = scanner.parse_results(path)

        # 3 failures, 1 success — only failures become findings.
        assert len(findings) == 3

    def test_severity_mapping(self, fixtures_dir):
        scanner = PromptfooScanner()
        path = fixtures_dir / "promptfoo" / "results-redteam.json"
        findings = scanner.parse_results(path)

        by_id = {f.id: f for f in findings}
        # Red-team plugin hits → HIGH.
        assert by_id["prompt-injection"].severity == Severity.HIGH
        assert by_id["pii:direct"].severity == Severity.HIGH
        # Plain eval assertion miss → MEDIUM.
        medium = [f for f in findings if f.severity == Severity.MEDIUM]
        assert len(medium) == 1

    def test_finding_fields(self, fixtures_dir):
        scanner = PromptfooScanner()
        path = fixtures_dir / "promptfoo" / "results-redteam.json"
        findings = scanner.parse_results(path)

        pi = [f for f in findings if f.id == "prompt-injection"][0]
        assert pi.scanner == "promptfoo"
        assert "prompt-injection" in pi.title
        assert pi.metadata["plugin_id"] == "prompt-injection"
        assert pi.metadata["provider"] == "openai:gpt-4o-mini"
        assert pi.metadata["pass"] is False

    def test_parse_zero_findings(self, fixtures_dir):
        scanner = PromptfooScanner()
        path = fixtures_dir / "promptfoo" / "results-zero-findings.json"
        findings = scanner.parse_results(path)
        assert len(findings) == 0

    def test_empty_results_block(self, tmp_path):
        scanner = PromptfooScanner()
        empty = tmp_path / "empty.json"
        empty.write_text(json.dumps({"results": {"results": []}}))
        assert scanner.parse_results(empty) == []


class TestPromptfooSecretHandling:
    """The scanner must never echo prompts, responses, or keys into findings."""

    def test_no_secret_literal_in_findings(self, fixtures_dir):
        scanner = PromptfooScanner()
        path = fixtures_dir / "promptfoo" / "results-redteam.json"
        findings = scanner.parse_results(path)

        # Secrets embedded in the fixture's prompts / responses /
        # grading reasons. None may survive into serialized findings.
        forbidden = [
            "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "FAKE-TEST-TOKEN-do-not-match",
            "hunter2",
            "123-45-6789",
            "jane@example.com",
        ]
        blob = json.dumps([f.to_dict() for f in findings])
        for secret in forbidden:
            assert secret not in blob, f"leaked: {secret}"

    def test_vendor_prefixed_secrets_redacted(self, fixtures_dir):
        # The backstop redactor in Finding.__post_init__ replaces any
        # vendor-prefix token that slipped through. We never put raw
        # prompt/response text into findings, so the placeholder should
        # not even be needed — but assert it's at least never a literal.
        scanner = PromptfooScanner()
        path = fixtures_dir / "promptfoo" / "results-redteam.json"
        findings = scanner.parse_results(path)
        blob = json.dumps([f.to_dict() for f in findings])
        # No raw ghp_/sk_live_ tokens anywhere.
        assert "ghp_" not in blob or REDACTED_PLACEHOLDER in blob


class TestPromptfooContainerArgs:
    """Container-arg construction from argus.yml passthrough config."""

    def test_entrypoint_overridden_to_promptfoo_binary(self):
        # Regression: the promptfoo image's default entrypoint
        # (docker-entrypoint.sh) execs "$@" verbatim, so passing the
        # ["eval", ...] args without overriding the entrypoint makes the
        # container try to exec the bare word "eval" (exit 127, scanner
        # never runs). The engine adds --entrypoint <container_entrypoint>,
        # so this must be the promptfoo binary for the args to run as
        # "promptfoo eval ...".
        scanner = PromptfooScanner()
        assert scanner.container_entrypoint == "promptfoo"
        assert scanner.container_args({})[0] == "eval"

    def test_default_args(self):
        args = PromptfooScanner().container_args({})
        assert args[0] == "eval"
        assert "-c" in args
        ci = args.index("-c")
        assert args[ci + 1] == "/app/promptfooconfig.yaml"
        assert "-o" in args
        oi = args.index("-o")
        assert args[oi + 1] == "/output/results.json"
        assert "--no-progress-bar" in args

    def test_cmd_options_appended_verbatim(self):
        args = PromptfooScanner().container_args({
            "cmd_options": ["--max-concurrency", "2"],
        })
        assert args[-2:] == ["--max-concurrency", "2"]

    def test_no_api_key_in_args(self, monkeypatch):
        # API keys must travel via env, never the command line.
        monkeypatch.setenv("OPENAI_KEY", "sk-secretvalue")
        args = PromptfooScanner().container_args({
            "openai_api_key_env": "OPENAI_KEY",
        })
        assert "sk-secretvalue" not in " ".join(args)


class TestPromptfooContainerEnv:
    """Provider API-key resolution via env-var indirection."""

    def test_no_keys_returns_empty(self):
        assert PromptfooScanner().container_env({}) == {}

    def test_openai_anthropic_via_env_refs(self, monkeypatch):
        monkeypatch.setenv("OAI", "sk-openai-token")
        monkeypatch.setenv("ANT", "sk-ant-token")
        env = PromptfooScanner().container_env({
            "openai_api_key_env": "OAI",
            "anthropic_api_key_env": "ANT",
        })
        assert env["OPENAI_API_KEY"] == "sk-openai-token"
        assert env["ANTHROPIC_API_KEY"] == "sk-ant-token"

    def test_unset_env_ref_not_injected(self, monkeypatch):
        monkeypatch.delenv("MISSING", raising=False)
        env = PromptfooScanner().container_env({
            "openai_api_key_env": "MISSING",
        })
        assert "OPENAI_API_KEY" not in env

    def test_generic_api_keys_map(self, monkeypatch):
        monkeypatch.setenv("MISTRAL_SRC", "mistral-secret")
        env = PromptfooScanner().container_env({
            "api_keys": {"MISTRAL_API_KEY": "MISTRAL_SRC"},
        })
        assert env["MISTRAL_API_KEY"] == "mistral-secret"


class TestPromptfooContainerMounts:
    def test_no_config_returns_empty(self):
        assert PromptfooScanner().container_mounts({}) == []

    def test_config_file_mount(self):
        mounts = PromptfooScanner().container_mounts({
            "config_file": "/host/promptfooconfig.yaml",
        })
        assert mounts == [
            ("/host/promptfooconfig.yaml", "/app/promptfooconfig.yaml"),
        ]


class TestPromptfooScannerMeta:
    def test_name_and_category(self):
        scanner = PromptfooScanner()
        assert scanner.name == "promptfoo"
        assert scanner.category == "llm-security"

    def test_install_command(self):
        assert PromptfooScanner().install_command() is not None

    def test_tool_version_is_none(self):
        assert PromptfooScanner().tool_version() is None

    def test_scan_requires_config_file(self, tmp_path):
        result = PromptfooScanner().scan(str(tmp_path), {})
        assert "config_file is required" in result.metadata["error"]
