#!/usr/bin/env python3
"""
Tests for defaults module - centralized configuration
"""

import importlib.util
import sys
from pathlib import Path

# Add scripts directory to path
REPO_ROOT = Path(__file__).resolve().parents[4]
SCRIPTS_DIR = REPO_ROOT / ".github" / "actions" / "scn-detector" / "scripts"

# Import defaults module dynamically
spec = importlib.util.spec_from_file_location(
    "defaults",
    SCRIPTS_DIR / "defaults.py"
)
defaults = importlib.util.module_from_spec(spec)
sys.modules["defaults"] = defaults
spec.loader.exec_module(defaults)


class TestDefaults:
    """Test centralized defaults configuration."""

    def test_default_ai_config_exists(self):
        """Test DEFAULT_AI_CONFIG is defined."""
        assert hasattr(defaults, 'DEFAULT_AI_CONFIG')
        assert isinstance(defaults.DEFAULT_AI_CONFIG, dict)

    def test_default_ai_config_structure(self):
        """Test DEFAULT_AI_CONFIG has required keys."""
        config = defaults.DEFAULT_AI_CONFIG

        assert 'provider' in config
        assert 'model' in config
        assert 'confidence_threshold' in config
        assert 'max_tokens' in config
        assert 'system_prompt' in config
        assert 'user_prompt_template' in config

    def test_default_rules_exist(self):
        """Test DEFAULT_RULES is defined."""
        assert hasattr(defaults, 'DEFAULT_RULES')
        assert isinstance(defaults.DEFAULT_RULES, dict)

    def test_default_rules_structure(self):
        """Test DEFAULT_RULES has all categories."""
        rules = defaults.DEFAULT_RULES

        assert 'routine' in rules
        assert 'adaptive' in rules
        assert 'transformative' in rules
        assert 'impact' in rules

        # Each category should have rules
        for category in ['routine', 'adaptive', 'transformative', 'impact']:
            assert isinstance(rules[category], list)
            assert len(rules[category]) > 0

    def test_merge_config_simple(self):
        """Test merge_config with simple override."""
        custom = {'model': 'claude-3-opus-20240229'}
        defaults_cfg = {'model': 'claude-3-haiku-20240307', 'max_tokens': 1024}

        result = defaults.merge_config(custom, defaults_cfg)

        assert result['model'] == 'claude-3-opus-20240229'  # Custom override
        assert result['max_tokens'] == 1024  # Default preserved

    def test_merge_config_nested(self):
        """Test merge_config with nested dictionaries."""
        custom = {
            'ai_fallback': {
                'model': 'custom-model',
                'new_key': 'new_value'
            }
        }
        defaults_cfg = {
            'ai_fallback': {
                'model': 'default-model',
                'max_tokens': 1024
            },
            'other_key': 'other_value'
        }

        result = defaults.merge_config(custom, defaults_cfg)

        # Nested merge should work
        assert result['ai_fallback']['model'] == 'custom-model'
        assert result['ai_fallback']['max_tokens'] == 1024
        assert result['ai_fallback']['new_key'] == 'new_value'
        assert result['other_key'] == 'other_value'

    def test_merge_config_empty_custom(self):
        """Test merge_config with empty custom config."""
        custom = {}
        defaults_cfg = {'key': 'value', 'nested': {'inner': 'data'}}

        result = defaults.merge_config(custom, defaults_cfg)

        assert result == defaults_cfg

    def test_merge_config_none_custom(self):
        """Test merge_config with None custom config."""
        custom = None
        defaults_cfg = {'key': 'value'}

        result = defaults.merge_config(custom, defaults_cfg)

        assert result == defaults_cfg

    def test_get_default_config(self):
        """Test get_default_config returns complete config."""
        config = defaults.get_default_config()

        # Should have all major sections
        assert 'version' in config
        assert 'name' in config
        assert 'rules' in config
        assert 'ai_fallback' in config
        assert 'notifications' in config

        # Rules should have all categories
        assert 'routine' in config['rules']
        assert 'adaptive' in config['rules']
        assert 'transformative' in config['rules']
        assert 'impact' in config['rules']

    def test_default_notifications_structure(self):
        """Test DEFAULT_NOTIFICATIONS has correct structure."""
        notifications = defaults.DEFAULT_NOTIFICATIONS

        assert 'adaptive' in notifications
        assert 'transformative' in notifications
        assert 'impact' in notifications

        # Check timeline values
        assert notifications['adaptive']['post_completion_days'] == 10
        assert notifications['transformative']['initial_notice_days'] == 30
        assert notifications['transformative']['final_notice_days'] == 10
        assert notifications['impact']['requires_new_assessment'] is True
