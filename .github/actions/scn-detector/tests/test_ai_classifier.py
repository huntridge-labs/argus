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
        assert classifier.anthropic_client is None

    def test_init_with_api_key(self):
        """Initializes with provided API key."""
        classifier = ai_classifier.AIClassifier(api_key='test-key')
        assert classifier.api_key == 'test-key'

    def test_init_default_config(self):
        """Uses default config when none provided."""
        classifier = ai_classifier.AIClassifier(api_key='test-key')
        assert classifier.ai_config['model'] == 'claude-3-haiku-20240307'
        assert classifier.ai_config['confidence_threshold'] == 0.8

    def test_init_custom_config(self):
        """Uses provided config."""
        config = {'model': 'custom-model', 'confidence_threshold': 0.9, 'max_tokens': 512}
        classifier = ai_classifier.AIClassifier(ai_config=config, api_key='test-key')
        assert classifier.ai_config['model'] == 'custom-model'
        assert classifier.ai_config['confidence_threshold'] == 0.9

    @patch.dict('os.environ', {'ANTHROPIC_API_KEY': 'env-key'})
    def test_init_api_key_from_env(self):
        """Falls back to env var for API key."""
        classifier = ai_classifier.AIClassifier()
        assert classifier.api_key == 'env-key'


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

    @patch('ai_classifier.HAS_ANTHROPIC_SDK', False)
    @patch('ai_classifier.requests.post')
    def test_classify_api_success(self, mock_post):
        """Successful classification via raw API."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'content': [{'text': json.dumps({
                'category': 'ADAPTIVE',
                'confidence': 0.92,
                'reasoning': 'Instance type change'
            })}]
        }
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        classifier = ai_classifier.AIClassifier(api_key='test-key')
        classifier.anthropic_client = None
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

    @patch('ai_classifier.HAS_ANTHROPIC_SDK', False)
    @patch('ai_classifier.requests.post')
    def test_classify_low_confidence(self, mock_post):
        """Low confidence returns MANUAL_REVIEW."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'content': [{'text': json.dumps({
                'category': 'ADAPTIVE',
                'confidence': 0.5,
                'reasoning': 'Uncertain'
            })}]
        }
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        classifier = ai_classifier.AIClassifier(api_key='test-key')
        classifier.anthropic_client = None
        change = {'type': 'test', 'name': 'test', 'operation': 'modify'}

        result = classifier.classify(change)

        assert result['category'] == 'MANUAL_REVIEW'
        assert result['confidence'] == 0.5
        assert 'Low confidence' in result['reasoning']

    @patch('ai_classifier.HAS_ANTHROPIC_SDK', False)
    @patch('ai_classifier.requests.post')
    def test_classify_api_error_fallback(self, mock_post):
        """API errors fall back to MANUAL_REVIEW."""
        mock_post.side_effect = Exception("Connection timeout")

        classifier = ai_classifier.AIClassifier(api_key='test-key')
        classifier.anthropic_client = None
        change = {'type': 'test', 'name': 'test', 'operation': 'modify'}

        result = classifier.classify(change)

        assert result['category'] == 'MANUAL_REVIEW'
        assert 'AI error' in result['reasoning']


class TestBuildPrompt:
    """Test AIClassifier._build_prompt method."""

    def test_prompt_contains_change_details(self):
        """Prompt includes resource type, name, operation."""
        classifier = ai_classifier.AIClassifier(api_key='test-key')
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
        classifier = ai_classifier.AIClassifier(api_key='test-key')
        change = {}

        prompt = classifier._build_prompt(change)

        assert 'unknown' in prompt
        assert 'FedRAMP' in prompt

    def test_prompt_truncates_long_diff(self):
        """Diff truncated to max_diff_chars."""
        config = {'max_diff_chars': 50, 'model': 'test', 'confidence_threshold': 0.8}
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
        config = {'max_diff_chars': 'invalid', 'model': 'test', 'confidence_threshold': 0.8}
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


class TestCallApi:
    """Test AIClassifier._call_api method."""

    @patch('ai_classifier.requests.post')
    def test_call_api_sends_correct_headers(self, mock_post):
        """API call includes correct headers."""
        mock_response = MagicMock()
        mock_response.json.return_value = {'content': [{'text': '{}'}]}
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        classifier = ai_classifier.AIClassifier(api_key='my-api-key')
        classifier._call_api("test prompt")

        call_kwargs = mock_post.call_args
        headers = call_kwargs.kwargs.get('headers') or call_kwargs[1].get('headers')
        assert headers['x-api-key'] == 'my-api-key'
        assert headers['anthropic-version'] == '2023-06-01'

    @patch('ai_classifier.requests.post')
    def test_call_api_timeout(self, mock_post):
        """API call uses 30s timeout."""
        mock_response = MagicMock()
        mock_response.json.return_value = {'content': [{'text': '{}'}]}
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        classifier = ai_classifier.AIClassifier(api_key='test-key')
        classifier._call_api("test prompt")

        call_kwargs = mock_post.call_args
        timeout = call_kwargs.kwargs.get('timeout') or call_kwargs[1].get('timeout')
        assert timeout == 30
