#!/usr/bin/env python3
"""
Tests for AI classification module.
"""

import importlib.util
import json
import pytest
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

# Import module dynamically
REPO_ROOT = Path(__file__).resolve().parents[4]
SCRIPTS_DIR = REPO_ROOT / ".github" / "actions" / "scn-detector" / "scripts"

if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

spec = importlib.util.spec_from_file_location(
    "ai_classifier",
    SCRIPTS_DIR / "ai_classifier.py"
)
ai_classifier = importlib.util.module_from_spec(spec)
sys.modules["ai_classifier"] = ai_classifier
spec.loader.exec_module(ai_classifier)


pytestmark = pytest.mark.unit


class TestAIClassifierInit:
    """Test AIClassifier initialization."""

    @patch.dict('os.environ', {}, clear=True)
    def test_init_no_api_key(self):
        """Initializes without API key."""
        classifier = ai_classifier.AIClassifier(api_key=None)
        assert classifier.api_key is None
        assert classifier.provider is None

    def test_init_with_api_key(self):
        """Initializes with provided API key."""
        classifier = ai_classifier.AIClassifier(api_key='test-key')
        assert classifier.api_key == 'test-key'

    def test_init_no_config_empty_ai_config(self):
        """When no config provided, ai_config is empty — AI is opt-in, no defaults."""
        classifier = ai_classifier.AIClassifier(api_key='test-key')
        assert classifier.ai_config == {}

    def test_init_custom_config(self):
        """Uses provided config."""
        config = {'provider': 'openai', 'model': 'gpt-4o-mini', 'confidence_threshold': 0.9, 'max_tokens': 512}
        classifier = ai_classifier.AIClassifier(ai_config=config, api_key='test-key')
        assert classifier.ai_config['provider'] == 'openai'
        assert classifier.ai_config['model'] == 'gpt-4o-mini'
        assert classifier.ai_config['confidence_threshold'] == 0.9

    @patch.dict('os.environ', {'ANTHROPIC_API_KEY': 'env-key'})
    def test_init_api_key_from_env(self):
        """Falls back to env var for API key (anthropic provider)."""
        classifier = ai_classifier.AIClassifier()
        assert classifier.api_key == 'env-key'

    @patch.dict('os.environ', {'OPENAI_API_KEY': 'openai-env-key'})
    def test_init_openai_api_key_from_env(self):
        """Falls back to OPENAI_API_KEY for openai provider."""
        config = {'provider': 'openai', 'model': 'gpt-4o-mini', 'confidence_threshold': 0.8}
        classifier = ai_classifier.AIClassifier(ai_config=config)
        assert classifier.api_key == 'openai-env-key'

    def test_init_creates_provider_instance(self):
        """Provider instance is created when API key and valid config are available."""
        config = {
            'provider': 'anthropic',
            'model': 'claude-haiku-4-5-20251001',
            'max_tokens': 1024,
            'confidence_threshold': 0.8
        }
        classifier = ai_classifier.AIClassifier(ai_config=config, api_key='test-key')
        assert classifier.provider is not None

    def test_init_unknown_provider_no_crash(self):
        """Unknown provider doesn't crash, provider is None."""
        config = {'provider': 'gemini', 'model': 'test', 'confidence_threshold': 0.8}
        classifier = ai_classifier.AIClassifier(ai_config=config, api_key='key')
        assert classifier.provider is None


class TestAIClassifierClassify:
    """Test AIClassifier.classify method."""

    def test_classify_no_api_key(self):
        """Returns MANUAL_REVIEW when no API key."""
        classifier = ai_classifier.AIClassifier(api_key=None)
        change = {'type': 'test', 'name': 'test', 'operation': 'modify'}

        result = classifier.classify(change)

        assert result['category'] == 'MANUAL_REVIEW'
        assert result['confidence'] == 0.0
        assert 'not available' in result['reasoning']

    def test_classify_no_provider(self):
        """Returns MANUAL_REVIEW when provider is None."""
        classifier = ai_classifier.AIClassifier(api_key='test-key')
        classifier.provider = None

        result = classifier.classify({'type': 'test', 'name': 'test', 'operation': 'modify'})
        assert result['category'] == 'MANUAL_REVIEW'

    def test_classify_success(self):
        """Successful classification via provider."""
        classifier = ai_classifier.AIClassifier(api_key='test-key')
        mock_provider = MagicMock()
        mock_provider.call.return_value = json.dumps({
            'category': 'ADAPTIVE',
            'confidence': 0.92,
            'reasoning': 'Instance type change'
        })
        classifier.provider = mock_provider

        change = {
            'type': 'aws_instance',
            'name': 'web',
            'operation': 'modify',
            'attributes_changed': ['instance_type'],
            'diff': '- instance_type = "t2.micro"\n+ instance_type = "t3.small"'
        }

        result = classifier.classify(change)

        assert result['category'] == 'ADAPTIVE'
        assert result['confidence'] == 0.92
        mock_provider.call.assert_called_once()

    def test_classify_low_confidence(self):
        """Low confidence returns MANUAL_REVIEW."""
        classifier = ai_classifier.AIClassifier(api_key='test-key')
        mock_provider = MagicMock()
        mock_provider.call.return_value = json.dumps({
            'category': 'ADAPTIVE',
            'confidence': 0.5,
            'reasoning': 'Uncertain'
        })
        classifier.provider = mock_provider

        result = classifier.classify({'type': 'test', 'name': 'test', 'operation': 'modify'})

        assert result['category'] == 'MANUAL_REVIEW'
        assert result['confidence'] == 0.5
        assert 'Low confidence' in result['reasoning']

    def test_classify_provider_network_error_fallback(self):
        """Network errors fall back to MANUAL_REVIEW."""
        classifier = ai_classifier.AIClassifier(api_key='test-key')
        mock_provider = MagicMock()
        mock_provider.call.side_effect = ConnectionError("Connection timeout")
        classifier.provider = mock_provider

        result = classifier.classify({'type': 'test', 'name': 'test', 'operation': 'modify'})

        assert result['category'] == 'MANUAL_REVIEW'
        assert 'AI API error' in result['reasoning']

    def test_classify_provider_invalid_json_fallback(self):
        """Invalid JSON response falls back to MANUAL_REVIEW."""
        classifier = ai_classifier.AIClassifier(api_key='test-key')
        mock_provider = MagicMock()
        mock_provider.call.return_value = "not valid json {{"
        classifier.provider = mock_provider

        result = classifier.classify({'type': 'test', 'name': 'test', 'operation': 'modify'})

        assert result['category'] == 'MANUAL_REVIEW'
        assert 'invalid JSON' in result['reasoning']

    def test_classify_provider_malformed_response_fallback(self):
        """Malformed response data falls back to MANUAL_REVIEW."""
        import json as _json
        classifier = ai_classifier.AIClassifier(api_key='test-key')
        mock_provider = MagicMock()
        mock_provider.call.return_value = _json.dumps({
            'category': 'ADAPTIVE',
            'confidence': 'not-a-number',
            'reasoning': 'test'
        })
        classifier.provider = mock_provider

        result = classifier.classify({'type': 'test', 'name': 'test', 'operation': 'modify'})

        assert result['category'] == 'MANUAL_REVIEW'
        assert 'parse error' in result['reasoning']


class TestBuildPrompt:
    """Test AIClassifier._build_prompt method."""

    def test_prompt_contains_change_details(self):
        """Prompt includes resource type, name, operation from user-supplied config."""
        config = {
            'provider': 'anthropic',
            'model': 'test-model',
            'confidence_threshold': 0.8,
            'system_prompt': 'You are a FedRAMP compliance expert.',
            'user_prompt_template': (
                'Classify the change:\n'
                'Resource: {resource_type}.{resource_name}\n'
                'Operation: {operation}\n'
                'Attributes: {attributes}\n'
                'Diff: {diff_snippet}'
            )
        }
        classifier = ai_classifier.AIClassifier(ai_config=config, api_key='test-key')
        change = {
            'type': 'aws_instance',
            'name': 'web_server',
            'operation': 'modify',
            'attributes_changed': ['instance_type', 'tags'],
            'diff': '- t2.micro\n+ t3.small'
        }

        prompt = classifier._build_prompt(change)

        assert 'aws_instance' in prompt
        assert 'web_server' in prompt
        assert 'modify' in prompt
        assert 'instance_type' in prompt
        assert 'FedRAMP' in prompt

    def test_prompt_handles_missing_fields(self):
        """Prompt handles change with missing fields gracefully."""
        config = {
            'system_prompt': 'FedRAMP classifier.',
            'user_prompt_template': 'Resource: {resource_type}.{resource_name}, Op: {operation}'
        }
        classifier = ai_classifier.AIClassifier(ai_config=config, api_key='test-key')
        change = {}

        prompt = classifier._build_prompt(change)

        assert 'unknown' in prompt
        assert 'FedRAMP' in prompt

    def test_prompt_truncates_long_diff(self):
        """Diff truncated to max_diff_chars."""
        config = {'max_diff_chars': 50, 'model': 'test', 'confidence_threshold': 0.8, 'provider': 'anthropic'}
        classifier = ai_classifier.AIClassifier(ai_config=config, api_key='test-key')
        change = {
            'type': 'test',
            'name': 'test',
            'operation': 'modify',
            'attributes_changed': [],
            'diff': 'x' * 5000
        }

        prompt = classifier._build_prompt(change)

        # The full 5000-char diff should NOT appear in the prompt
        assert 'x' * 5000 not in prompt

    def test_prompt_invalid_max_diff_chars(self):
        """Invalid max_diff_chars falls back to 1000."""
        config = {'max_diff_chars': 'invalid', 'model': 'test', 'confidence_threshold': 0.8, 'provider': 'anthropic'}
        classifier = ai_classifier.AIClassifier(ai_config=config, api_key='test-key')
        change = {
            'type': 'test',
            'name': 'test',
            'operation': 'modify',
            'attributes_changed': [],
            'diff': 'y' * 2000
        }

        prompt = classifier._build_prompt(change)

        # Falls back to 1000 char truncation
        assert 'y' * 2000 not in prompt
