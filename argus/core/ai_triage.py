"""AI-assisted triage — explain a finding / draft a fix (Phase 10 foundation).

Reuses the existing provider abstraction (``argus/scn/ai.py``:
``create_provider`` / ``resolve_api_key``, providers expose ``call(prompt)``)
— no new AI layer. **Local-first**: with ``ARGUS_AI_LOCAL=1`` (or
``OLLAMA_HOST``) it talks to a local OpenAI-compatible endpoint (Ollama) so
**no API key is required**; cloud providers are opt-in via the usual env
vars. With nothing configured, AI is simply *off* and the caller falls back
to the deterministic context it already has (Phase-6 enrichment, Phase-1 Fix).

UI-free: prompt builders + a thin orchestrator over a provider's ``call``.
The provider is injected, so tests never hit the network. **Model output is
untrusted** — an explanation is advisory, and any suggested fix must flow
through the Phase-1 diff-preview gate, never auto-applied.
"""

from __future__ import annotations

import os
from typing import Mapping, Protocol

from argus.core.models import Finding

# Local-first defaults: Ollama's OpenAI-compatible endpoint, no key required.
DEFAULT_LOCAL_BASE_URL = "http://localhost:11434/v1"
DEFAULT_LOCAL_MODEL = "llama3.1"
_DEFAULT_MAX_TOKENS = 1024
_CLOUD_MODELS = {"anthropic": "claude-3-5-haiku-latest", "openai": "gpt-4o-mini"}


class Provider(Protocol):
    def call(self, prompt: str) -> str: ...


def explain_prompt(finding: Finding, *, enrichment_summary: str = "") -> str:
    """Prompt asking the model to explain a finding in this repo's context."""
    lines = [
        "You are a security engineer triaging a scanner finding. Explain it "
        "concisely for a developer: what it is, why it matters here, and the "
        "most likely real-world impact. Be specific and practical; do not "
        "invent details that aren't given.",
        "",
        f"Scanner: {finding.scanner or 'unknown'}",
        f"Severity: {finding.severity.value}",
        f"ID: {finding.id}",
    ]
    if finding.cve:
        lines.append(f"CVE: {finding.cve}")
    if finding.location:
        lines.append(f"Location: {finding.location}")
    lines.append(f"Title: {finding.title}")
    if finding.description and finding.description != finding.title:
        lines.append(f"Description: {finding.description}")
    if enrichment_summary:
        lines.append(f"Exploit intelligence: {enrichment_summary}")
    return "\n".join(lines)


def fix_prompt(finding: Finding) -> str:
    """Prompt asking the model to propose a fix as a reviewable diff."""
    return (
        "Propose a minimal, safe fix for the security finding below, as a "
        "unified diff if you can infer the file, otherwise as concrete steps. "
        "Do not weaken other behaviour. The fix will be reviewed and tested "
        "before it is applied — never assume it is auto-applied.\n\n"
        f"Scanner: {finding.scanner or 'unknown'}\n"
        f"Severity: {finding.severity.value}\n"
        f"ID: {finding.id}\n"
        + (f"Location: {finding.location}\n" if finding.location else "")
        + f"Title: {finding.title}\n"
        + (f"Description: {finding.description}\n" if finding.description else "")
    )


def triage_explain(
    finding: Finding, *, provider: Provider, enrichment_summary: str = "",
) -> str:
    """Ask ``provider`` to explain ``finding``; returns the model's text."""
    return provider.call(explain_prompt(finding, enrichment_summary=enrichment_summary))


def triage_fix(finding: Finding, *, provider: Provider) -> str:
    """Ask ``provider`` to draft a fix for ``finding`` (advisory; review first)."""
    return provider.call(fix_prompt(finding))


def provider_from_env(env: Mapping[str, str] | None = None) -> tuple[object | None, str]:
    """Resolve a provider from the environment → ``(provider, label)``.

    Resolution order (local-first, key-optional):
      1. ``ARGUS_AI_PROVIDER=anthropic|openai`` *and* a resolvable API key →
         that cloud provider.
      2. ``ARGUS_AI_LOCAL=1`` or ``OLLAMA_HOST`` → a local OpenAI-compatible
         endpoint (Ollama), **no key required**.
      3. otherwise ``(None, "off")`` — AI is disabled, caller degrades.

    Construction only — never makes a network call here, so it's safe to call
    on every screen open.
    """
    e = os.environ if env is None else env
    name = (e.get("ARGUS_AI_PROVIDER") or "").strip().lower()

    if name in ("anthropic", "openai"):
        try:
            from argus.scn.ai import create_provider, resolve_api_key
            key = resolve_api_key(name)
            if key:
                model = e.get("ARGUS_AI_MODEL") or _CLOUD_MODELS[name]
                config = {"model": model, "max_tokens": _DEFAULT_MAX_TOKENS}
                if e.get("ARGUS_AI_BASE_URL"):
                    config["api_base_url"] = e["ARGUS_AI_BASE_URL"]
                return create_provider(name, key, config), f"{name}:{model}"
        except Exception:
            return None, "off"

    if e.get("ARGUS_AI_LOCAL") or e.get("OLLAMA_HOST"):
        try:
            from argus.scn.ai import create_provider
            base = e.get("ARGUS_AI_BASE_URL") or _ollama_base(e.get("OLLAMA_HOST"))
            model = e.get("ARGUS_AI_MODEL") or DEFAULT_LOCAL_MODEL
            config = {
                "model": model, "max_tokens": _DEFAULT_MAX_TOKENS, "api_base_url": base,
            }
            # Local endpoints don't need a real key; send a placeholder.
            return create_provider("openai", e.get("ARGUS_AI_KEY", "local"), config), f"local:{model}"
        except Exception:
            return None, "off"

    return None, "off"


def _ollama_base(host: str | None) -> str:
    if not host:
        return DEFAULT_LOCAL_BASE_URL
    host = host.rstrip("/")
    return host if host.endswith("/v1") else f"{host}/v1"
