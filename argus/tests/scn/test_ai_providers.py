#!/usr/bin/env python3
"""
Tests for AI provider abstraction module.
"""

import pytest
from unittest.mock import patch, MagicMock

from argus.scn.ai import (
    PROVIDERS,
    AnthropicProvider,
    OpenAIProvider,
    create_provider,
    get_provider_class,
    resolve_api_key,
)
from argus.scn.defaults import DEFAULT_API_BASE_URLS


pytestmark = pytest.mark.unit


class TestAnthropicProvider:
    """Test AnthropicProvider class."""

    def test_env_var(self):
        """Correct env var for Anthropic."""
        assert AnthropicProvider.ENV_VAR == 'ANTHROPIC_API_KEY'

    def test_default_base_url(self):
        """Default base URL for Anthropic comes from defaults module."""
        provider = AnthropicProvider('test-key', {
            'model': 'claude-3-haiku-20240307',
            'max_tokens': 1024
        })
        assert provider.base_url == DEFAULT_API_BASE_URLS['anthropic']
        assert provider.base_url == 'https://api.anthropic.com'

    @patch('argus.scn.ai.HAS_ANTHROPIC_SDK', False)
    def test_init_without_sdk(self):
        """Initializes without SDK (client is None)."""
        provider = AnthropicProvider('test-key', {'model': 'claude-3-haiku-20240307', 'max_tokens': 1024})
        assert provider.client is None
        assert provider.api_key == 'test-key'

    @patch('argus.scn.ai.HAS_ANTHROPIC_SDK', False)
    @patch('argus.scn.ai.requests.post')
    def test_http_call_success(self, mock_post):
        """Raw HTTP call returns response text."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'content': [{'text': '{"category": "ADAPTIVE"}'}]
        }
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        provider = AnthropicProvider('test-key', {
            'model': 'claude-3-haiku-20240307',
            'max_tokens': 1024
        })
        result = provider.call('test prompt')

        assert result == '{"category": "ADAPTIVE"}'
        mock_post.assert_called_once()

    @patch('argus.scn.ai.HAS_ANTHROPIC_SDK', False)
    @patch('argus.scn.ai.requests.post')
    def test_http_call_headers(self, mock_post):
        """HTTP call sends correct Anthropic headers."""
        mock_response = MagicMock()
        mock_response.json.return_value = {'content': [{'text': '{}'}]}
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        provider = AnthropicProvider('my-api-key', {'model': 'test-model', 'max_tokens': 1024})
        provider.call('prompt')

        call_kwargs = mock_post.call_args
        headers = call_kwargs.kwargs.get('headers') or call_kwargs[1].get('headers')
        assert headers['x-api-key'] == 'my-api-key'
        assert headers['anthropic-version'] == '2023-06-01'

    @patch('argus.scn.ai.HAS_ANTHROPIC_SDK', False)
    @patch('argus.scn.ai.requests.post')
    def test_http_call_timeout(self, mock_post):
        """HTTP call uses 30s timeout."""
        mock_response = MagicMock()
        mock_response.json.return_value = {'content': [{'text': '{}'}]}
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        provider = AnthropicProvider('key', {'model': 'test', 'max_tokens': 1024})
        provider.call('prompt')

        call_kwargs = mock_post.call_args
        timeout = call_kwargs.kwargs.get('timeout') or call_kwargs[1].get('timeout')
        assert timeout == 30

    @patch('argus.scn.ai.HAS_ANTHROPIC_SDK', False)
    @patch('argus.scn.ai.requests.post')
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
        provider = AnthropicProvider('key', config)
        provider.call('prompt')

        call_args = mock_post.call_args
        url = call_args.args[0] if call_args.args else call_args.kwargs.get('url', '')
        assert url == 'https://custom.api.com/v1/messages'


class TestOpenAIProvider:
    """Test OpenAIProvider class."""

    def test_env_var(self):
        """Correct env var for OpenAI."""
        assert OpenAIProvider.ENV_VAR == 'OPENAI_API_KEY'

    def test_default_base_url(self):
        """Default base URL for OpenAI comes from defaults module."""
        provider = OpenAIProvider('test-key', {
            'model': 'gpt-4o-mini',
            'max_tokens': 1024
        })
        assert provider.base_url == DEFAULT_API_BASE_URLS['openai']
        assert provider.base_url == 'https://api.openai.com/v1'

    @patch('argus.scn.ai.HAS_OPENAI_SDK', False)
    def test_init_without_sdk(self):
        """Initializes without SDK (client is None)."""
        provider = OpenAIProvider('test-key', {'model': 'gpt-4o-mini', 'max_tokens': 1024})
        assert provider.client is None
        assert provider.api_key == 'test-key'

    @patch('argus.scn.ai.HAS_OPENAI_SDK', False)
    @patch('argus.scn.ai.requests.post')
    def test_http_call_success(self, mock_post):
        """Raw HTTP call returns response text."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'choices': [{'message': {'content': '{"category": "ROUTINE"}'}}]
        }
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        provider = OpenAIProvider('test-key', {'model': 'gpt-4o-mini', 'max_tokens': 1024})
        result = provider.call('test prompt')

        assert result == '{"category": "ROUTINE"}'
        mock_post.assert_called_once()

    @patch('argus.scn.ai.HAS_OPENAI_SDK', False)
    @patch('argus.scn.ai.requests.post')
    def test_http_call_headers(self, mock_post):
        """HTTP call sends correct OpenAI headers."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'choices': [{'message': {'content': '{}'}}]
        }
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        provider = OpenAIProvider('my-openai-key', {'model': 'gpt-4o-mini', 'max_tokens': 1024})
        provider.call('prompt')

        call_kwargs = mock_post.call_args
        headers = call_kwargs.kwargs.get('headers') or call_kwargs[1].get('headers')
        assert headers['Authorization'] == 'Bearer my-openai-key'

    @patch('argus.scn.ai.HAS_OPENAI_SDK', False)
    @patch('argus.scn.ai.requests.post')
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
        provider = OpenAIProvider('key', config)
        provider.call('prompt')

        call_args = mock_post.call_args
        url = call_args.args[0] if call_args.args else call_args.kwargs.get('url', '')
        assert url == 'http://localhost:11434/v1/chat/completions'

    @patch('argus.scn.ai.HAS_OPENAI_SDK', False)
    @patch('argus.scn.ai.requests.post')
    def test_http_call_timeout(self, mock_post):
        """HTTP call uses 30s timeout."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'choices': [{'message': {'content': '{}'}}]
        }
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        provider = OpenAIProvider('key', {'model': 'test', 'max_tokens': 1024})
        provider.call('prompt')

        call_kwargs = mock_post.call_args
        timeout = call_kwargs.kwargs.get('timeout') or call_kwargs[1].get('timeout')
        assert timeout == 30


class TestProviderRegistry:
    """Test provider registry and factory functions."""

    def test_providers_dict_has_anthropic(self):
        """Registry contains anthropic."""
        assert 'anthropic' in PROVIDERS

    def test_providers_dict_has_openai(self):
        """Registry contains openai."""
        assert 'openai' in PROVIDERS

    def test_get_provider_class_anthropic(self):
        """get_provider_class returns AnthropicProvider."""
        cls = get_provider_class('anthropic')
        assert cls is AnthropicProvider

    def test_get_provider_class_openai(self):
        """get_provider_class returns OpenAIProvider."""
        cls = get_provider_class('openai')
        assert cls is OpenAIProvider

    def test_get_provider_class_unknown(self):
        """Unknown provider returns None."""
        assert get_provider_class('gemini') is None

    @patch('argus.scn.ai.HAS_ANTHROPIC_SDK', False)
    def test_create_provider_anthropic(self):
        """Factory creates AnthropicProvider."""
        provider = create_provider('anthropic', 'key', {'model': 'test', 'max_tokens': 1024})
        assert isinstance(provider, AnthropicProvider)

    @patch('argus.scn.ai.HAS_OPENAI_SDK', False)
    def test_create_provider_openai(self):
        """Factory creates OpenAIProvider."""
        provider = create_provider('openai', 'key', {'model': 'test', 'max_tokens': 1024})
        assert isinstance(provider, OpenAIProvider)

    @patch('argus.scn.ai.HAS_ANTHROPIC_SDK', False)
    def test_create_provider_missing_config_raises(self):
        """Provider with missing required config raises ValueError."""
        with pytest.raises(ValueError, match="missing required keys"):
            create_provider('anthropic', 'key', {'model': 'test'})

    def test_create_provider_unknown_raises(self):
        """Unknown provider raises ValueError."""
        with pytest.raises(ValueError, match="Unknown AI provider: 'gemini'"):
            create_provider('gemini', 'key', {})


class TestResolveApiKey:
    """Test API key resolution."""

    def test_explicit_key_takes_priority(self):
        """Explicit key overrides env var."""
        result = resolve_api_key('anthropic', 'explicit-key')
        assert result == 'explicit-key'

    @patch.dict('os.environ', {'ANTHROPIC_API_KEY': 'env-anthropic-key'})
    def test_anthropic_env_var(self):
        """Falls back to ANTHROPIC_API_KEY env var."""
        result = resolve_api_key('anthropic')
        assert result == 'env-anthropic-key'

    @patch.dict('os.environ', {'OPENAI_API_KEY': 'env-openai-key'})
    def test_openai_env_var(self):
        """Falls back to OPENAI_API_KEY env var."""
        result = resolve_api_key('openai')
        assert result == 'env-openai-key'

    @patch.dict('os.environ', {}, clear=True)
    def test_no_key_returns_none(self):
        """Returns None when no key available."""
        result = resolve_api_key('anthropic')
        assert result is None

    def test_unknown_provider_returns_none(self):
        """Unknown provider with no explicit key returns None."""
        result = resolve_api_key('unknown_provider')
        assert result is None
