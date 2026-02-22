#!/usr/bin/env python3
"""
FedRAMP SCN Detector - AI Classification Module

Provides AI-based classification of IaC changes using Claude Haiku.
This module is optional — the main classifier falls back to MANUAL_REVIEW
when AI is unavailable.
"""

import json
import os
import sys
from typing import Dict, Optional

import requests

# Try importing anthropic SDK (optional)
try:
    from anthropic import Anthropic
    HAS_ANTHROPIC_SDK = True
except ImportError:
    HAS_ANTHROPIC_SDK = False


class AIClassifier:
    """Classifies IaC changes using Claude Haiku."""

    DEFAULT_CONFIG = {
        'enabled': True,
        'model': 'claude-3-haiku-20240307',
        'confidence_threshold': 0.8,
        'max_tokens': 1024
    }

    def __init__(self, ai_config: Optional[Dict] = None, api_key: Optional[str] = None):
        """
        Initialize AI classifier.

        Args:
            ai_config: AI configuration dictionary
            api_key: Anthropic API key (or None to use env var)
        """
        self.ai_config = ai_config or self.DEFAULT_CONFIG
        self.api_key = api_key or os.environ.get('ANTHROPIC_API_KEY')

        # Initialize Anthropic client if SDK available
        if HAS_ANTHROPIC_SDK and self.api_key:
            self.anthropic_client = Anthropic(api_key=self.api_key)
        else:
            self.anthropic_client = None

    def classify(self, change: Dict) -> Dict:
        """
        Classify change using AI (Claude Haiku).

        Args:
            change: Change dictionary

        Returns:
            Dictionary with category, confidence, reasoning
        """
        if not self.api_key:
            return {
                'category': 'MANUAL_REVIEW',
                'confidence': 0.0,
                'reasoning': 'AI fallback not available (no API key or disabled)'
            }

        prompt = self._build_prompt(change)

        try:
            if HAS_ANTHROPIC_SDK and self.anthropic_client:
                response = self._call_sdk(prompt)
            else:
                response = self._call_api(prompt)

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

        except Exception as e:
            print(f"⚠️  AI classification failed: {e}", file=sys.stderr)
            return {
                'category': 'MANUAL_REVIEW',
                'confidence': 0.0,
                'reasoning': f'AI error: {str(e)}'
            }

    def _build_prompt(self, change: Dict) -> str:
        """Build AI classification prompt."""
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

        return f"""You are a FedRAMP compliance expert analyzing infrastructure changes.

FedRAMP Change Categories:
- ROUTINE: Regular maintenance, patching, minor capacity changes (no notification required)
- ADAPTIVE: Frequent improvements with minimal security plan changes (10 days after completion)
- TRANSFORMATIVE: Rare, significant changes altering risk profile (30 days initial + 10 days final notice)
- IMPACT: Changes to security boundary or FIPS level (requires new assessment)

Change Details:
- Resource Type: {resource_type}
- Resource Name: {resource_name}
- Operation: {operation}
- Attributes Changed: {attributes}
- Diff Preview:
{diff_snippet}

Classify this change. Respond ONLY with valid JSON in this exact format:
{{
  "category": "ROUTINE|ADAPTIVE|TRANSFORMATIVE|IMPACT",
  "confidence": 0.0-1.0,
  "reasoning": "Brief explanation (max 200 chars)"
}}"""

    def _call_sdk(self, prompt: str) -> str:
        """Call Anthropic API using SDK."""
        model = self.ai_config.get('model', 'claude-3-haiku-20240307')
        max_tokens = self.ai_config.get('max_tokens', 1024)

        message = self.anthropic_client.messages.create(
            model=model,
            max_tokens=max_tokens,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )

        return message.content[0].text

    def _call_api(self, prompt: str) -> str:
        """Call Anthropic API using requests (fallback)."""
        model = self.ai_config.get('model', 'claude-3-haiku-20240307')
        max_tokens = self.ai_config.get('max_tokens', 1024)

        url = 'https://api.anthropic.com/v1/messages'
        headers = {
            'x-api-key': self.api_key,
            'anthropic-version': '2023-06-01',
            'content-type': 'application/json'
        }
        data = {
            'model': model,
            'max_tokens': max_tokens,
            'messages': [
                {'role': 'user', 'content': prompt}
            ]
        }

        response = requests.post(url, headers=headers, json=data, timeout=30)
        response.raise_for_status()

        result = response.json()
        return result['content'][0]['text']
