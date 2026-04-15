#!/usr/bin/env python3
"""
FedRAMP SCN Detector - AI Provider Abstraction and Classification

Combines provider abstraction (Anthropic, OpenAI) with the AI classification
logic into a single module.

Each provider tries its SDK first, falling back to raw HTTP requests.
The AIClassifier uses a configurable provider to classify IaC changes.
"""

import json
import os
import sys
from typing import Dict, Optional

try:
    import requests
except ImportError:
    requests = None  # AI features unavailable without requests

from .defaults import DEFAULT_API_BASE_URLS, DEFAULT_AI_CONFIG, merge_config


# ---------------------------------------------------------------------------
# SDK availability detection (graceful ImportError handling)
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Provider helpers
# ---------------------------------------------------------------------------

def _validate_provider_config(config: Dict, provider_name: str) -> None:
    """Validate required config keys are present for a provider.

    Raises:
        ValueError: If 'model' or 'max_tokens' are missing from config.
    """
    missing = [k for k in ('model', 'max_tokens') if k not in config]
    if missing:
        raise ValueError(
            f"{provider_name} provider config missing required keys: {', '.join(missing)}. "
            f"Ensure your AI config includes 'model' and 'max_tokens'."
        )


# ---------------------------------------------------------------------------
# Anthropic Provider
# ---------------------------------------------------------------------------

class AnthropicProvider:
    """Calls Anthropic Messages API (SDK or raw HTTP fallback)."""

    ENV_VAR = 'ANTHROPIC_API_KEY'

    def __init__(self, api_key: str, config: Dict):
        _validate_provider_config(config, 'Anthropic')
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
        model = self.config['model']
        max_tokens = self.config['max_tokens']

        message = self.client.messages.create(
            model=model,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}]
        )
        return message.content[0].text

    def _call_http(self, prompt: str) -> str:
        """Call via raw HTTP (fallback when SDK not installed)."""
        model = self.config['model']
        max_tokens = self.config['max_tokens']

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


# ---------------------------------------------------------------------------
# OpenAI Provider
# ---------------------------------------------------------------------------

class OpenAIProvider:
    """Calls OpenAI Chat Completions API (SDK or raw HTTP fallback).

    Also supports OpenAI-compatible APIs (Azure OpenAI, Ollama, vLLM)
    via the api_base_url config option.
    """

    ENV_VAR = 'OPENAI_API_KEY'

    def __init__(self, api_key: str, config: Dict):
        _validate_provider_config(config, 'OpenAI')
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
        model = self.config['model']
        max_tokens = self.config['max_tokens']

        response = self.client.chat.completions.create(
            model=model,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}]
        )
        return response.choices[0].message.content

    def _call_http(self, prompt: str) -> str:
        """Call via raw HTTP (fallback when SDK not installed)."""
        model = self.config['model']
        max_tokens = self.config['max_tokens']

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


# ---------------------------------------------------------------------------
# Provider Registry
# ---------------------------------------------------------------------------

PROVIDERS = {
    'anthropic': AnthropicProvider,
    'openai': OpenAIProvider,
}


def get_provider_class(provider_name: str):
    """Look up provider class by name. Returns None if unknown."""
    return PROVIDERS.get(provider_name)


def resolve_api_key(provider_name: str, explicit_key: Optional[str] = None) -> Optional[str]:
    """Resolve API key: explicit param -> provider-specific env var."""
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
        Provider instance

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


# ---------------------------------------------------------------------------
# AI Classifier
# ---------------------------------------------------------------------------

class AIClassifier:
    """Classifies IaC changes using a configurable AI provider."""

    def __init__(self, ai_config: Optional[Dict] = None, api_key: Optional[str] = None):
        """
        Initialize AI classifier.

        Args:
            ai_config: AI configuration dictionary (provider, model, etc.)
            api_key: API key (or None to resolve from env var per provider)
        """
        self.ai_config = merge_config(ai_config or {}, DEFAULT_AI_CONFIG)
        provider_name = self.ai_config.get('provider', 'anthropic')
        self.api_key = resolve_api_key(provider_name, api_key)

        # Initialize provider if we have an API key
        self.provider = None
        if self.api_key:
            try:
                self.provider = create_provider(provider_name, self.api_key, self.ai_config)
            except ValueError as exc:
                print(f"Warning: {exc}", file=sys.stderr)

    def classify(self, change: Dict) -> Dict:
        """
        Classify change using the configured AI provider.

        Args:
            change: Change dictionary

        Returns:
            Dictionary with category, confidence, reasoning
        """
        if not self.api_key or not self.provider:
            return {
                'category': 'MANUAL_REVIEW',
                'confidence': 0.0,
                'reasoning': 'AI fallback not available (no API key or disabled)'
            }

        prompt = self._build_prompt(change)

        try:
            response = self.provider.call(prompt)
            result = json.loads(response)

            category = result.get('category', 'MANUAL_REVIEW').upper()
            confidence = float(result.get('confidence', 0.0))
            reasoning = result.get('reasoning', 'No reasoning provided')

            threshold = self.ai_config.get('confidence_threshold', 0.8)
            if confidence < threshold:
                return {
                    'category': 'MANUAL_REVIEW',
                    'confidence': confidence,
                    'reasoning': f"Low confidence ({confidence:.2f} < {threshold}): {reasoning}"
                }

            return {
                'category': category,
                'confidence': confidence,
                'reasoning': reasoning
            }

        except json.JSONDecodeError as e:
            print(f"Warning: AI returned invalid JSON: {e}", file=sys.stderr)
            return {
                'category': 'MANUAL_REVIEW',
                'confidence': 0.0,
                'reasoning': f'AI returned invalid JSON: {str(e)}'
            }
        except (requests.RequestException, ConnectionError, TimeoutError) as e:
            print(f"Warning: AI API request failed: {e}", file=sys.stderr)
            return {
                'category': 'MANUAL_REVIEW',
                'confidence': 0.0,
                'reasoning': f'AI API error: {str(e)}'
            }
        except (KeyError, ValueError, TypeError) as e:
            print(f"Warning: AI response format error: {e}", file=sys.stderr)
            return {
                'category': 'MANUAL_REVIEW',
                'confidence': 0.0,
                'reasoning': f'AI response parse error: {str(e)}'
            }

    def _build_prompt(self, change: Dict) -> str:
        """Build AI classification prompt using profile configuration."""
        resource_type = change.get('type', 'unknown')
        resource_name = change.get('name', 'unnamed')
        operation = change.get('operation', 'unknown')
        attributes = ', '.join(change.get('attributes_changed', []))

        max_diff_chars = self.ai_config.get('max_diff_chars', 1000)
        try:
            max_diff_chars = int(max_diff_chars)
            if max_diff_chars <= 0:
                max_diff_chars = 1000
        except (TypeError, ValueError):
            max_diff_chars = 1000
        diff_snippet = change.get('diff', '')[:max_diff_chars]

        # Get prompts from config (already merged with defaults in __init__)
        system_prompt = self.ai_config.get('system_prompt', '')
        user_prompt_template = self.ai_config.get('user_prompt_template', '')

        # Format user prompt with change details.
        # Use format_map with a safe dict so custom templates with unknown
        # placeholders pass through unchanged instead of crashing.
        format_values = {
            'resource_type': resource_type,
            'resource_name': resource_name,
            'operation': operation,
            'attributes': attributes,
            'diff_snippet': diff_snippet,
        }

        class _SafeDict(dict):
            """Returns the original placeholder for unrecognized keys."""
            def __missing__(self, key):
                return '{' + key + '}'

        user_prompt = user_prompt_template.format_map(_SafeDict(format_values))

        # Combine system and user prompts
        return f"{system_prompt}\n\n{user_prompt}"
