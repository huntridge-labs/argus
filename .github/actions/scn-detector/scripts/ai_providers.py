#!/usr/bin/env python3
"""
FedRAMP SCN Detector - AI Provider Abstraction

Lightweight provider module supporting multiple AI backends:
- Anthropic (Claude models) — SDK or raw HTTP
- OpenAI (GPT models) — SDK or raw HTTP, also supports OpenAI-compatible APIs

Each provider tries its SDK first, falling back to raw HTTP requests.
"""

import json
import os
import sys
from typing import Dict, Optional

import requests

from defaults import DEFAULT_API_BASE_URLS


# --- Anthropic Provider ---

try:
    from anthropic import Anthropic
    HAS_ANTHROPIC_SDK = True
except ImportError:
    HAS_ANTHROPIC_SDK = False


try:
    from openai import OpenAI
    HAS_OPENAI_SDK = True
except ImportError:
    HAS_OPENAI_SDK = False


class AnthropicProvider:
    """Calls Anthropic Messages API (SDK or raw HTTP fallback)."""

    ENV_VAR = 'ANTHROPIC_API_KEY'

    def __init__(self, api_key: str, config: Dict):
        self.api_key = api_key
        self.config = config
        self.base_url = config.get('api_base_url') or DEFAULT_API_BASE_URLS['anthropic']

        # Initialize SDK client if available
        if HAS_ANTHROPIC_SDK:
            sdk_kwargs = {'api_key': api_key}
            if self.base_url != DEFAULT_API_BASE_URLS['anthropic']:
                sdk_kwargs['base_url'] = self.base_url
            self.client = Anthropic(**sdk_kwargs)
        else:
            self.client = None

    def call(self, prompt: str) -> str:
        """Send prompt to Anthropic API and return response text."""
        if self.client:
            return self._call_sdk(prompt)
        return self._call_http(prompt)

    def _call_sdk(self, prompt: str) -> str:
        """Call via Anthropic SDK."""
        model = self.config['model']  # Required - should be set by merge_config
        max_tokens = self.config['max_tokens']  # Required - should be set by merge_config

        message = self.client.messages.create(
            model=model,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}]
        )
        return message.content[0].text

    def _call_http(self, prompt: str) -> str:
        """Call via raw HTTP (fallback when SDK not installed)."""
        model = self.config['model']  # Required - should be set by merge_config
        max_tokens = self.config['max_tokens']  # Required - should be set by merge_config

        url = f'{self.base_url}/v1/messages'
        headers = {
            'x-api-key': self.api_key,
            'anthropic-version': '2023-06-01',
            'content-type': 'application/json'
        }
        data = {
            'model': model,
            'max_tokens': max_tokens,
            'messages': [{'role': 'user', 'content': prompt}]
        }

        response = requests.post(url, headers=headers, json=data, timeout=30)
        response.raise_for_status()

        result = response.json()
        return result['content'][0]['text']


class OpenAIProvider:
    """Calls OpenAI Chat Completions API (SDK or raw HTTP fallback).

    Also supports OpenAI-compatible APIs (Azure OpenAI, Ollama, vLLM)
    via the api_base_url config option.
    """

    ENV_VAR = 'OPENAI_API_KEY'

    def __init__(self, api_key: str, config: Dict):
        self.api_key = api_key
        self.config = config
        self.base_url = config.get('api_base_url') or DEFAULT_API_BASE_URLS['openai']

        # Initialize SDK client if available
        if HAS_OPENAI_SDK:
            self.client = OpenAI(api_key=api_key, base_url=self.base_url)
        else:
            self.client = None

    def call(self, prompt: str) -> str:
        """Send prompt to OpenAI API and return response text."""
        if self.client:
            return self._call_sdk(prompt)
        return self._call_http(prompt)

    def _call_sdk(self, prompt: str) -> str:
        """Call via OpenAI SDK."""
        model = self.config['model']  # Required - should be set by merge_config
        max_tokens = self.config['max_tokens']  # Required - should be set by merge_config

        response = self.client.chat.completions.create(
            model=model,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}]
        )
        return response.choices[0].message.content

    def _call_http(self, prompt: str) -> str:
        """Call via raw HTTP (fallback when SDK not installed)."""
        model = self.config['model']  # Required - should be set by merge_config
        max_tokens = self.config['max_tokens']  # Required - should be set by merge_config

        url = f'{self.base_url}/chat/completions'
        headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }
        data = {
            'model': model,
            'max_tokens': max_tokens,
            'messages': [{'role': 'user', 'content': prompt}]
        }

        response = requests.post(url, headers=headers, json=data, timeout=30)
        response.raise_for_status()

        result = response.json()
        return result['choices'][0]['message']['content']


# --- Provider Registry ---

PROVIDERS = {
    'anthropic': AnthropicProvider,
    'openai': OpenAIProvider,
}


def get_provider_class(provider_name: str):
    """Look up provider class by name. Returns None if unknown."""
    return PROVIDERS.get(provider_name)


def resolve_api_key(provider_name: str, explicit_key: Optional[str] = None) -> Optional[str]:
    """Resolve API key: explicit param → provider-specific env var."""
    if explicit_key:
        return explicit_key
    provider_cls = get_provider_class(provider_name)
    if provider_cls:
        return os.environ.get(provider_cls.ENV_VAR)
    return None


def create_provider(provider_name: str, api_key: str, config: Dict):
    """Create a provider instance by name.

    Args:
        provider_name: Provider identifier ("anthropic" or "openai")
        api_key: API key for the provider
        config: AI configuration dictionary

    Returns:
        Provider instance, or None if provider_name is unknown

    Raises:
        ValueError: If provider_name is not recognized
    """
    provider_cls = get_provider_class(provider_name)
    if not provider_cls:
        raise ValueError(
            f"Unknown AI provider: '{provider_name}'. "
            f"Supported providers: {', '.join(PROVIDERS.keys())}"
        )
    return provider_cls(api_key, config)
