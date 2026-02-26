#!/usr/bin/env python3
"""
FedRAMP SCN Detector - AI Classification Module

Provides AI-based classification of IaC changes using configurable providers.
Supports Anthropic (Claude) and OpenAI (GPT) models via the ai_providers module.
This module is optional — the main classifier falls back to MANUAL_REVIEW
when AI is unavailable.
"""

import json
import sys
from typing import Dict, Optional

import requests

from ai_providers import create_provider, resolve_api_key


class AIClassifier:
    """Classifies IaC changes using a configurable AI provider."""

    def __init__(self, ai_config: Optional[Dict] = None, api_key: Optional[str] = None):
        """
        Initialize AI classifier.

        Args:
            ai_config: AI configuration dictionary (provider, model, prompts, etc.)
                       Must be supplied by the caller from the user's config — there
                       are no built-in AI defaults. Missing optional keys (e.g.
                       confidence_threshold, max_tokens) fall back to safe inline values.
            api_key: API key (or None to resolve from env var per provider)
        """
        self.ai_config = ai_config or {}
        provider_name = self.ai_config.get('provider', 'anthropic')
        self.api_key = resolve_api_key(provider_name, api_key)

        # Initialize provider if we have an API key
        self.provider = None
        if self.api_key:
            try:
                self.provider = create_provider(provider_name, self.api_key, self.ai_config)
            except ValueError as exc:
                print(f"⚠️  {exc}", file=sys.stderr)

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
            print(f"⚠️  AI returned invalid JSON: {e}", file=sys.stderr)
            return {
                'category': 'MANUAL_REVIEW',
                'confidence': 0.0,
                'reasoning': f'AI returned invalid JSON: {str(e)}'
            }
        except (requests.RequestException, ConnectionError, TimeoutError) as e:
            print(f"⚠️  AI API request failed: {e}", file=sys.stderr)
            return {
                'category': 'MANUAL_REVIEW',
                'confidence': 0.0,
                'reasoning': f'AI API error: {str(e)}'
            }
        except (KeyError, ValueError, TypeError) as e:
            print(f"⚠️  AI response format error: {e}", file=sys.stderr)
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
