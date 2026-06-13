"""Unit tests for argus.core.ai_triage (Phase 10 — AI assistant foundation).

Network-free: the prompt builders are pure, and the orchestrator runs
against a fake provider. ``provider_from_env`` is checked for the off/local
resolution without any real call.
"""

from __future__ import annotations

from argus.core.ai_triage import (
    DEFAULT_LOCAL_MODEL,
    explain_prompt,
    fix_prompt,
    provider_from_env,
    triage_explain,
    triage_fix,
)
from argus.core.models import Finding, Severity


def _finding(**kw):
    base = dict(id="CVE-2021-44228", severity=Severity.HIGH, title="Log4Shell RCE",
                cve="CVE-2021-44228", scanner="osv", location="pom.xml")
    base.update(kw)
    return Finding(**base)


class _FakeProvider:
    def __init__(self):
        self.prompts: list[str] = []

    def call(self, prompt: str) -> str:
        self.prompts.append(prompt)
        return "explanation text"


class TestPrompts:
    def test_explain_includes_key_fields(self):
        p = explain_prompt(_finding(), enrichment_summary="EPSS 97% · KEV")
        assert "osv" in p and "high" in p and "CVE-2021-44228" in p
        assert "pom.xml" in p and "Log4Shell RCE" in p
        assert "EPSS 97% · KEV" in p

    def test_explain_omits_absent_fields(self):
        p = explain_prompt(_finding(cve=None, location=None))
        assert "CVE:" not in p and "Location:" not in p

    def test_fix_prompt_asks_for_diff_and_review(self):
        p = fix_prompt(_finding())
        assert "unified diff" in p and "reviewed and tested" in p


class TestOrchestrator:
    def test_triage_explain_calls_provider(self):
        provider = _FakeProvider()
        out = triage_explain(_finding(), provider=provider, enrichment_summary="KEV")
        assert out == "explanation text"
        assert "KEV" in provider.prompts[0]

    def test_triage_fix_calls_provider(self):
        provider = _FakeProvider()
        triage_fix(_finding(), provider=provider)
        assert "unified diff" in provider.prompts[0]


class TestProviderFromEnv:
    def test_off_by_default(self):
        provider, label = provider_from_env({})
        assert provider is None and label == "off"

    def test_local_when_flag_set(self):
        provider, label = provider_from_env({"ARGUS_AI_LOCAL": "1"})
        assert provider is not None
        assert label == f"local:{DEFAULT_LOCAL_MODEL}"

    def test_local_via_ollama_host(self):
        provider, label = provider_from_env({"OLLAMA_HOST": "http://box:11434"})
        assert provider is not None and label.startswith("local:")

    def test_cloud_without_key_is_off(self):
        # Provider named but no key resolvable → off (no env key set).
        provider, label = provider_from_env({"ARGUS_AI_PROVIDER": "anthropic"})
        assert provider is None and label == "off"

    def test_cloud_with_key(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        provider, label = provider_from_env({"ARGUS_AI_PROVIDER": "anthropic"})
        assert provider is not None and label.startswith("anthropic:")
