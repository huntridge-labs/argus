#!/usr/bin/env python3
"""
Tests for AI provider abstraction module.
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
    "ai_providers",
    SCRIPTS_DIR / "ai_providers.py"
)
ai_providers = importlib.util.module_from_spec(spec)
sys.modules["ai_providers"] = ai_providers
spec.loader.exec_module(ai_providers)

# Import defaults module
defaults_spec = importlib.util.spec_from_file_location(
    "defaults",
    SCRIPTS_DIR / "defaults.py"
)
defaults = importlib.util.module_from_spec(defaults_spec)
sys.modules["defaults"] = defaults
defaults_spec.loader.exec_module(defaults)


pytestmark = pytest.mark.unit


class TestAnthropicProvider:
    """Test AnthropicProvider class."""

    def test_env_var(self):
        """Correct env var for Anthropic."""
        assert ai_providers.AnthropicProvider.ENV_VAR == 'ANTHROPIC_API_KEY'

    def test_default_base_url(self):
        """Default base URL for Anthropic comes from defaults module."""
        provider = ai_providers.AnthropicProvider('test-key', {
            'model': 'claude-3-haiku-20240307',
            'max_tokens': 1024
        })
        assert provider.base_url == defaults.DEFAULT_API_BASE_URLS['anthropic']
        assert provider.base_url == 'https://api.anthropic.com'

    @patch('ai_providers.HAS_ANTHROPIC_SDK', False)
    def test_init_without_sdk(self):
        """Initializes without SDK (client is None)."""
        provider = ai_providers.AnthropicProvider('test-key', {'model': 'claude-3-haiku-20240307', 'max_tokens': 1024})
        assert provider.client is None
        assert provider.api_key == 'test-key'

    @patch('ai_providers.HAS_ANTHROPIC_SDK', False)
    @patch('ai_providers.requests.post')
    def test_http_call_success(self, mock_post):
        """Raw HTTP call returns response text."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'content': [{'text': '{"category": "ADAPTIVE"}'}]
        }
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        provider = ai_providers.AnthropicProvider('test-key', {
            'model': 'claude-3-haiku-20240307',
            'max_tokens': 1024
        })
        result = provider.call('test prompt')

        assert result == '{"category": "ADAPTIVE"}'
        mock_post.assert_called_once()

    @patch('ai_providers.HAS_ANTHROPIC_SDK', False)
    @patch('ai_providers.requests.post')
    def test_http_call_headers(self, mock_post):
        """HTTP call sends correct Anthropic headers."""
        mock_response = MagicMock()
        mock_response.json.return_value = {'content': [{'text': '{}'}]}
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        provider = ai_providers.AnthropicProvider('my-api-key', {'model': 'test-model', 'max_tokens': 1024})
        provider.call('prompt')

        call_kwargs = mock_post.call_args
        headers = call_kwargs.kwargs.get('headers') or call_kwargs[1].get('headers')
        assert headers['x-api-key'] == 'my-api-key'
        assert headers['anthropic-version'] == '2023-06-01'

    @patch('ai_providers.HAS_ANTHROPIC_SDK', False)
    @patch('ai_providers.requests.post')
    def test_http_call_timeout(self, mock_post):
        """HTTP call uses 30s timeout."""
        mock_response = MagicMock()
        mock_response.json.return_value = {'content': [{'text': '{}'}]}
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        provider = ai_providers.AnthropicProvider('key', {'model': 'test', 'max_tokens': 1024})
        provider.call('prompt')

        call_kwargs = mock_post.call_args
        timeout = call_kwargs.kwargs.get('timeout') or call_kwargs[1].get('timeout')
        assert timeout == 30

    @patch('ai_providers.HAS_ANTHROPIC_SDK', False)
    @patch('ai_providers.requests.post')
    def test_custom_base_url(self, mock_post):
        """Custom base URL is used in HTTP call."""
        mock_response = MagicMock()
        mock_response.json.return_value = {'content': [{'text': '{}'}]}
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        config = {
            'model': 'test',
            'max_tokens': 1024,
            'api_base_url': 'https://custom.api.com'
        }
        provider = ai_providers.AnthropicProvider('key', config)
        provider.call('prompt')

        call_args = mock_post.call_args
        url = call_args.args[0] if call_args.args else call_args.kwargs.get('url', '')
        assert url == 'https://custom.api.com/v1/messages'


class TestOpenAIProvider:
    """Test OpenAIProvider class."""

    def test_env_var(self):
        """Correct env var for OpenAI."""
        assert ai_providers.OpenAIProvider.ENV_VAR == 'OPENAI_API_KEY'

    def test_default_base_url(self):
        """Default base URL for OpenAI comes from defaults module."""
        provider = ai_providers.OpenAIProvider('test-key', {
            'model': 'gpt-4o-mini',
            'max_tokens': 1024
        })
        assert provider.base_url == defaults.DEFAULT_API_BASE_URLS['openai']
        assert provider.base_url == 'https://api.openai.com/v1'

    @patch('ai_providers.HAS_OPENAI_SDK', False)
    def test_init_without_sdk(self):
        """Initializes without SDK (client is None)."""
        provider = ai_providers.OpenAIProvider('test-key', {'model': 'gpt-4o-mini', 'max_tokens': 1024})
        assert provider.client is None
        assert provider.api_key == 'test-key'

    @patch('ai_providers.HAS_OPENAI_SDK', False)
    @patch('ai_providers.requests.post')
    def test_http_call_success(self, mock_post):
        """Raw HTTP call returns response text."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'choices': [{'message': {'content': '{"category": "ROUTINE"}'}}]
        }
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        provider = ai_providers.OpenAIProvider('test-key', {'model': 'gpt-4o-mini', 'max_tokens': 1024})
        result = provider.call('test prompt')

        assert result == '{"category": "ROUTINE"}'
        mock_post.assert_called_once()

    @patch('ai_providers.HAS_OPENAI_SDK', False)
    @patch('ai_providers.requests.post')
    def test_http_call_headers(self, mock_post):
        """HTTP call sends correct OpenAI headers."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'choices': [{'message': {'content': '{}'}}]
        }
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        provider = ai_providers.OpenAIProvider('my-openai-key', {'model': 'gpt-4o-mini', 'max_tokens': 1024})
        provider.call('prompt')

        call_kwargs = mock_post.call_args
        headers = call_kwargs.kwargs.get('headers') or call_kwargs[1].get('headers')
        assert headers['Authorization'] == 'Bearer my-openai-key'

    @patch('ai_providers.HAS_OPENAI_SDK', False)
    @patch('ai_providers.requests.post')
    def test_custom_base_url(self, mock_post):
        """Custom base URL for OpenAI-compatible APIs."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'choices': [{'message': {'content': '{}'}}]
        }
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        config = {
            'model': 'local-model',
            'max_tokens': 1024,
            'api_base_url': 'http://localhost:11434/v1'
        }
        provider = ai_providers.OpenAIProvider('key', config)
        provider.call('prompt')

        call_args = mock_post.call_args
        url = call_args.args[0] if call_args.args else call_args.kwargs.get('url', '')
        assert url == 'http://localhost:11434/v1/chat/completions'

    @patch('ai_providers.HAS_OPENAI_SDK', False)
    @patch('ai_providers.requests.post')
    def test_http_call_timeout(self, mock_post):
        """HTTP call uses 30s timeout."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'choices': [{'message': {'content': '{}'}}]
        }
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        provider = ai_providers.OpenAIProvider('key', {'model': 'test', 'max_tokens': 1024})
        provider.call('prompt')

        call_kwargs = mock_post.call_args
        timeout = call_kwargs.kwargs.get('timeout') or call_kwargs[1].get('timeout')
        assert timeout == 30


class TestProviderRegistry:
    """Test provider registry and factory functions."""

    def test_providers_dict_has_anthropic(self):
        """Registry contains anthropic."""
        assert 'anthropic' in ai_providers.PROVIDERS

    def test_providers_dict_has_openai(self):
        """Registry contains openai."""
        assert 'openai' in ai_providers.PROVIDERS

    def test_get_provider_class_anthropic(self):
        """get_provider_class returns AnthropicProvider."""
        cls = ai_providers.get_provider_class('anthropic')
        assert cls is ai_providers.AnthropicProvider

    def test_get_provider_class_openai(self):
        """get_provider_class returns OpenAIProvider."""
        cls = ai_providers.get_provider_class('openai')
        assert cls is ai_providers.OpenAIProvider

    def test_get_provider_class_unknown(self):
        """Unknown provider returns None."""
        assert ai_providers.get_provider_class('gemini') is None

    @patch('ai_providers.HAS_ANTHROPIC_SDK', False)
    def test_create_provider_anthropic(self):
        """Factory creates AnthropicProvider."""
        provider = ai_providers.create_provider('anthropic', 'key', {'model': 'test'})
        assert isinstance(provider, ai_providers.AnthropicProvider)

    @patch('ai_providers.HAS_OPENAI_SDK', False)
    def test_create_provider_openai(self):
        """Factory creates OpenAIProvider."""
        provider = ai_providers.create_provider('openai', 'key', {'model': 'test'})
        assert isinstance(provider, ai_providers.OpenAIProvider)

    def test_create_provider_unknown_raises(self):
        """Unknown provider raises ValueError."""
        with pytest.raises(ValueError, match="Unknown AI provider: 'gemini'"):
            ai_providers.create_provider('gemini', 'key', {})


class TestResolveApiKey:
    """Test API key resolution."""

    def test_explicit_key_takes_priority(self):
        """Explicit key overrides env var."""
        result = ai_providers.resolve_api_key('anthropic', 'explicit-key')
        assert result == 'explicit-key'

    @patch.dict('os.environ', {'ANTHROPIC_API_KEY': 'env-anthropic-key'})
    def test_anthropic_env_var(self):
        """Falls back to ANTHROPIC_API_KEY env var."""
        result = ai_providers.resolve_api_key('anthropic')
        assert result == 'env-anthropic-key'

    @patch.dict('os.environ', {'OPENAI_API_KEY': 'env-openai-key'})
    def test_openai_env_var(self):
        """Falls back to OPENAI_API_KEY env var."""
        result = ai_providers.resolve_api_key('openai')
        assert result == 'env-openai-key'

    @patch.dict('os.environ', {}, clear=True)
    def test_no_key_returns_none(self):
        """Returns None when no key available."""
        result = ai_providers.resolve_api_key('anthropic')
        assert result is None

    def test_unknown_provider_returns_none(self):
        """Unknown provider with no explicit key returns None."""
        result = ai_providers.resolve_api_key('unknown_provider')
        assert result is None
