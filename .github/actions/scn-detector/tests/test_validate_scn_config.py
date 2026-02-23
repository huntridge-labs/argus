#!/usr/bin/env python3
"""
Tests for SCN config validation
"""

import importlib.util
import json
import os
import pytest
import sys
from pathlib import Path
from unittest.mock import patch

# Add scripts directory to path
REPO_ROOT = Path(__file__).resolve().parents[4]
SCRIPTS_DIR = REPO_ROOT / '.github' / 'actions' / 'scn-detector' / 'scripts'
PROFILES_DIR = REPO_ROOT / '.github' / 'actions' / 'scn-detector' / 'profiles'
SCHEMAS_DIR = REPO_ROOT / '.github' / 'actions' / 'scn-detector' / 'schemas'
FIXTURES_DIR = REPO_ROOT / 'tests' / 'fixtures' / 'scn-detector'

if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

# Import validate_scn_config module dynamically
spec = importlib.util.spec_from_file_location(
    'validate_scn_config',
    SCRIPTS_DIR / 'validate_scn_config.py'
)
validate_scn_config = importlib.util.module_from_spec(spec)
sys.modules['validate_scn_config'] = validate_scn_config
spec.loader.exec_module(validate_scn_config)

import yaml

# Mark all tests as unit tests
pytestmark = pytest.mark.unit


@pytest.fixture
def schema():
    """Load the SCN config schema."""
    schema_path = SCHEMAS_DIR / 'scn-config.schema.json'
    with open(schema_path, 'r') as f:
        return json.load(f)


@pytest.fixture
def minimal_valid_config():
    """Minimal valid SCN config."""
    return {
        'version': '1.0',
        'rules': {
            'routine': [
                {'pattern': 'tags.*', 'description': 'Tag changes'}
            ]
        }
    }


@pytest.fixture
def full_valid_config():
    """Full valid SCN config with all optional sections."""
    return {
        'version': '1.0',
        'name': 'Test Profile',
        'description': 'Full test configuration',
        'compliance_framework': 'FedRAMP 20X',
        'impact_level': 'Low',
        'rules': {
            'routine': [
                {'pattern': 'tags.*', 'description': 'Tag changes'}
            ],
            'adaptive': [
                {'resource': 'aws_instance.*.instance_type', 'operation': 'modify', 'description': 'Instance type changes'}
            ],
            'transformative': [
                {'resource': 'aws_rds_.*\\.engine', 'operation': 'modify', 'description': 'DB engine changes'}
            ],
            'impact': [
                {'attribute': '.*encryption.*', 'operation': 'delete|modify', 'description': 'Encryption changes'}
            ]
        },
        'ai_fallback': {
            'enabled': False,
            'provider': 'anthropic',
            'model': 'claude-3-haiku-20240307',
            'confidence_threshold': 0.8,
            'max_tokens': 1024,
            'max_diff_chars': 1000,
        },
        'notifications': {
            'adaptive': {
                'post_completion_days': 10,
                'description': 'Notify within 10 days'
            },
            'transformative': {
                'initial_notice_days': 30,
                'final_notice_days': 10,
                'post_completion_required': True,
                'description': '30+10 day notice'
            },
            'impact': {
                'requires_new_assessment': True,
                'description': 'Requires new assessment'
            }
        },
        'issue_templates': {
            'labels': {
                'prefix': 'scn',
                'categories': {
                    'routine': 'scn:routine',
                    'adaptive': 'scn:adaptive',
                    'transformative': 'scn:transformative',
                    'impact': 'scn:impact'
                }
            },
            'checklist': {
                'adaptive': ['Item 1', 'Item 2'],
                'transformative': ['Item A', 'Item B'],
                'impact': ['Step 1', 'Step 2']
            }
        }
    }


class TestValidateConfigStructure:
    """Test validate_config_structure function."""

    def test_valid_minimal_config(self, schema, minimal_valid_config):
        """Minimal config with version + one rule category passes."""
        validate_scn_config.validate_config_structure(minimal_valid_config, schema)

    def test_valid_full_config(self, schema, full_valid_config):
        """Full config with all optional sections passes."""
        validate_scn_config.validate_config_structure(full_valid_config, schema)

    def test_missing_version(self, schema):
        """Missing version raises error."""
        config = {'rules': {'routine': [{'pattern': 'x', 'description': 'x'}]}}
        with pytest.raises(ValueError, match='version: required field missing'):
            validate_scn_config.validate_config_structure(config, schema)

    def test_missing_rules(self, schema):
        """Missing rules raises error."""
        config = {'version': '1.0'}
        with pytest.raises(ValueError, match='rules: required field missing'):
            validate_scn_config.validate_config_structure(config, schema)

    def test_version_not_string(self, schema):
        """Non-string version raises error."""
        config = {
            'version': 1.0,
            'rules': {'routine': [{'pattern': 'x', 'description': 'x'}]}
        }
        with pytest.raises(ValueError, match='version: must be a string'):
            validate_scn_config.validate_config_structure(config, schema)

    def test_rules_not_dict(self, schema):
        """Non-dict rules raises error."""
        config = {'version': '1.0', 'rules': ['not', 'a', 'dict']}
        with pytest.raises(ValueError, match='rules: must be a mapping'):
            validate_scn_config.validate_config_structure(config, schema)

    def test_rules_empty(self, schema):
        """Empty rules dict raises error."""
        config = {'version': '1.0', 'rules': {}}
        with pytest.raises(ValueError, match='rules: must contain at least one category'):
            validate_scn_config.validate_config_structure(config, schema)

    def test_rules_unknown_category(self, schema):
        """Unknown category key raises error."""
        config = {
            'version': '1.0',
            'rules': {
                'critical': [{'pattern': 'x', 'description': 'x'}]
            }
        }
        with pytest.raises(ValueError, match='unknown category "critical"'):
            validate_scn_config.validate_config_structure(config, schema)

    def test_rules_category_not_list(self, schema):
        """Non-list category value raises error."""
        config = {
            'version': '1.0',
            'rules': {
                'routine': {'pattern': 'x', 'description': 'x'}
            }
        }
        with pytest.raises(ValueError, match='rules.routine: must be an array'):
            validate_scn_config.validate_config_structure(config, schema)

    def test_rules_category_empty_list(self, schema):
        """Empty category list raises error."""
        config = {'version': '1.0', 'rules': {'routine': []}}
        with pytest.raises(ValueError, match='rules.routine: must have at least 1 rule'):
            validate_scn_config.validate_config_structure(config, schema)

    def test_rules_rule_not_dict(self, schema):
        """Non-dict rule raises error."""
        config = {
            'version': '1.0',
            'rules': {'routine': ['not a dict']}
        }
        with pytest.raises(ValueError, match=r'rules\.routine\[0\]: must be an object'):
            validate_scn_config.validate_config_structure(config, schema)

    def test_rules_rule_missing_description(self, schema):
        """Rule without description raises error."""
        config = {
            'version': '1.0',
            'rules': {'routine': [{'pattern': 'tags.*'}]}
        }
        with pytest.raises(ValueError, match='description: required field missing'):
            validate_scn_config.validate_config_structure(config, schema)

    def test_rules_rule_no_matching_criterion(self, schema):
        """Rule with no pattern/resource/attribute raises error."""
        config = {
            'version': '1.0',
            'rules': {'routine': [{'description': 'Missing criterion', 'operation': 'modify'}]}
        }
        with pytest.raises(ValueError, match='at least one of pattern, resource, or attribute'):
            validate_scn_config.validate_config_structure(config, schema)

    def test_rules_rule_valid_pattern_only(self, schema):
        """Rule with only pattern + description passes."""
        config = {
            'version': '1.0',
            'rules': {'routine': [{'pattern': 'tags.*', 'description': 'Tag changes'}]}
        }
        validate_scn_config.validate_config_structure(config, schema)

    def test_rules_rule_valid_resource_only(self, schema):
        """Rule with only resource + description passes."""
        config = {
            'version': '1.0',
            'rules': {'adaptive': [{'resource': 'aws_instance.*', 'description': 'Instance changes'}]}
        }
        validate_scn_config.validate_config_structure(config, schema)

    def test_rules_rule_valid_attribute_only(self, schema):
        """Rule with only attribute + description passes."""
        config = {
            'version': '1.0',
            'rules': {'impact': [{'attribute': '.*encryption.*', 'description': 'Encryption changes'}]}
        }
        validate_scn_config.validate_config_structure(config, schema)

    def test_impact_level_valid_low(self, schema, minimal_valid_config):
        """impact_level Low passes."""
        minimal_valid_config['impact_level'] = 'Low'
        validate_scn_config.validate_config_structure(minimal_valid_config, schema)

    def test_impact_level_valid_moderate(self, schema, minimal_valid_config):
        """impact_level Moderate passes."""
        minimal_valid_config['impact_level'] = 'Moderate'
        validate_scn_config.validate_config_structure(minimal_valid_config, schema)

    def test_impact_level_valid_high(self, schema, minimal_valid_config):
        """impact_level High passes."""
        minimal_valid_config['impact_level'] = 'High'
        validate_scn_config.validate_config_structure(minimal_valid_config, schema)

    def test_impact_level_invalid_enum(self, schema, minimal_valid_config):
        """Invalid impact_level raises error."""
        minimal_valid_config['impact_level'] = 'Critical'
        with pytest.raises(ValueError, match='"Critical" is not valid'):
            validate_scn_config.validate_config_structure(minimal_valid_config, schema)

    def test_config_not_dict(self, schema):
        """Non-dict config raises error."""
        with pytest.raises(ValueError, match='must be a mapping'):
            validate_scn_config.validate_config_structure('not a dict', schema)

    def test_multiple_errors_collected(self, schema):
        """Multiple errors are collected and reported together."""
        config = {
            'version': 123,
            'rules': {
                'routine': [{'operation': 'modify'}]
            }
        }
        with pytest.raises(ValueError) as exc_info:
            validate_scn_config.validate_config_structure(config, schema)
        error_msg = str(exc_info.value)
        assert 'version: must be a string' in error_msg
        assert 'description: required field missing' in error_msg
        assert 'at least one of pattern, resource, or attribute' in error_msg


class TestValidateAiFallback:
    """Test ai_fallback section validation."""

    def test_valid_ai_fallback(self, schema, minimal_valid_config):
        """Valid ai_fallback section passes."""
        minimal_valid_config['ai_fallback'] = {
            'enabled': True,
            'provider': 'anthropic',
            'model': 'claude-3-haiku-20240307',
            'confidence_threshold': 0.85,
            'max_tokens': 1024,
            'max_diff_chars': 500,
        }
        validate_scn_config.validate_config_structure(minimal_valid_config, schema)

    def test_ai_fallback_not_dict(self, schema, minimal_valid_config):
        """Non-dict ai_fallback raises error."""
        minimal_valid_config['ai_fallback'] = 'not a dict'
        with pytest.raises(ValueError, match='ai_fallback: must be a mapping'):
            validate_scn_config.validate_config_structure(minimal_valid_config, schema)

    def test_ai_fallback_invalid_provider(self, schema, minimal_valid_config):
        """Invalid provider raises error."""
        minimal_valid_config['ai_fallback'] = {'provider': 'gemini'}
        with pytest.raises(ValueError, match='"gemini" is not valid'):
            validate_scn_config.validate_config_structure(minimal_valid_config, schema)

    def test_ai_fallback_confidence_too_high(self, schema, minimal_valid_config):
        """Confidence > 1.0 raises error."""
        minimal_valid_config['ai_fallback'] = {'confidence_threshold': 1.5}
        with pytest.raises(ValueError, match='must be between 0.0 and 1.0'):
            validate_scn_config.validate_config_structure(minimal_valid_config, schema)

    def test_ai_fallback_confidence_negative(self, schema, minimal_valid_config):
        """Negative confidence raises error."""
        minimal_valid_config['ai_fallback'] = {'confidence_threshold': -0.1}
        with pytest.raises(ValueError, match='must be between 0.0 and 1.0'):
            validate_scn_config.validate_config_structure(minimal_valid_config, schema)

    def test_ai_fallback_max_tokens_zero(self, schema, minimal_valid_config):
        """max_tokens of 0 raises error."""
        minimal_valid_config['ai_fallback'] = {'max_tokens': 0}
        with pytest.raises(ValueError, match='max_tokens: must be >= 1'):
            validate_scn_config.validate_config_structure(minimal_valid_config, schema)

    def test_ai_fallback_max_diff_chars_zero(self, schema, minimal_valid_config):
        """max_diff_chars of 0 raises error."""
        minimal_valid_config['ai_fallback'] = {'max_diff_chars': 0}
        with pytest.raises(ValueError, match='max_diff_chars: must be >= 1'):
            validate_scn_config.validate_config_structure(minimal_valid_config, schema)

    def test_ai_fallback_openai_provider(self, schema, minimal_valid_config):
        """OpenAI provider passes."""
        minimal_valid_config['ai_fallback'] = {
            'provider': 'openai',
            'model': 'gpt-4o-mini'
        }
        validate_scn_config.validate_config_structure(minimal_valid_config, schema)


class TestValidateNotifications:
    """Test notifications section validation."""

    def test_valid_notifications(self, schema, minimal_valid_config):
        """Valid notifications section passes."""
        minimal_valid_config['notifications'] = {
            'adaptive': {'post_completion_days': 10},
            'transformative': {'initial_notice_days': 30, 'final_notice_days': 10},
            'impact': {'requires_new_assessment': True}
        }
        validate_scn_config.validate_config_structure(minimal_valid_config, schema)

    def test_notifications_unknown_key(self, schema, minimal_valid_config):
        """Unknown notification category raises error."""
        minimal_valid_config['notifications'] = {'critical': {'days': 5}}
        with pytest.raises(ValueError, match='unknown key "critical"'):
            validate_scn_config.validate_config_structure(minimal_valid_config, schema)

    def test_notifications_not_dict(self, schema, minimal_valid_config):
        """Non-dict notifications raises error."""
        minimal_valid_config['notifications'] = 'not a dict'
        with pytest.raises(ValueError, match='notifications: must be a mapping'):
            validate_scn_config.validate_config_structure(minimal_valid_config, schema)


class TestValidateIssueTemplates:
    """Test issue_templates section validation."""

    def test_valid_issue_templates(self, schema, minimal_valid_config):
        """Valid issue_templates section passes."""
        minimal_valid_config['issue_templates'] = {
            'labels': {
                'prefix': 'scn',
                'categories': {'routine': 'scn:routine'}
            },
            'checklist': {
                'adaptive': ['Item 1', 'Item 2']
            }
        }
        validate_scn_config.validate_config_structure(minimal_valid_config, schema)

    def test_issue_templates_not_dict(self, schema, minimal_valid_config):
        """Non-dict issue_templates raises error."""
        minimal_valid_config['issue_templates'] = 'not a dict'
        with pytest.raises(ValueError, match='issue_templates: must be a mapping'):
            validate_scn_config.validate_config_structure(minimal_valid_config, schema)

    def test_issue_templates_checklist_not_strings(self, schema, minimal_valid_config):
        """Checklist with non-string items raises error."""
        minimal_valid_config['issue_templates'] = {
            'checklist': {'adaptive': [1, 2, 3]}
        }
        with pytest.raises(ValueError, match='all items must be strings'):
            validate_scn_config.validate_config_structure(minimal_valid_config, schema)


class TestValidateAiConfigStructure:
    """Test validate_ai_config_structure for standalone AI config files."""

    def test_valid_ai_config(self):
        """Valid standalone AI config passes."""
        config = {
            'enabled': True,
            'provider': 'anthropic',
            'model': 'claude-3-haiku-20240307',
            'confidence_threshold': 0.8,
            'max_tokens': 1024,
        }
        validate_scn_config.validate_ai_config_structure(config)

    def test_ai_config_invalid_provider(self):
        """Invalid provider in standalone config raises error."""
        config = {'provider': 'gemini'}
        with pytest.raises(ValueError, match='"gemini" is not valid'):
            validate_scn_config.validate_ai_config_structure(config)

    def test_ai_config_confidence_out_of_range(self):
        """Confidence > 1.0 in standalone config raises error."""
        config = {'confidence_threshold': 2.0}
        with pytest.raises(ValueError, match='must be between 0.0 and 1.0'):
            validate_scn_config.validate_ai_config_structure(config)

    def test_ai_config_not_dict(self):
        """Non-dict AI config raises error."""
        with pytest.raises(ValueError, match='must be a mapping'):
            validate_scn_config.validate_ai_config_structure('not a dict')


class TestMainFunction:
    """Test standalone main() execution."""

    def test_main_valid_config(self, tmp_path):
        """Valid config exits 0."""
        config_file = tmp_path / 'config.yml'
        config_file.write_text(
            'version: "1.0"\n'
            'rules:\n'
            '  routine:\n'
            '    - pattern: "tags.*"\n'
            '      description: "Tag changes"\n'
        )
        schema_path = SCHEMAS_DIR / 'scn-config.schema.json'

        with patch.dict(os.environ, {
            'CONFIG_FILE': str(config_file),
            'SCHEMA_FILE': str(schema_path),
            'AI_CONFIG_FILE': '',
        }):
            with pytest.raises(SystemExit) as exc_info:
                validate_scn_config.main()
            assert exc_info.value.code == 0

    def test_main_invalid_config(self, tmp_path):
        """Invalid config exits 1."""
        config_file = tmp_path / 'bad-config.yml'
        config_file.write_text('rules: []\n')
        schema_path = SCHEMAS_DIR / 'scn-config.schema.json'

        with patch.dict(os.environ, {
            'CONFIG_FILE': str(config_file),
            'SCHEMA_FILE': str(schema_path),
            'AI_CONFIG_FILE': '',
        }):
            with pytest.raises(SystemExit) as exc_info:
                validate_scn_config.main()
            assert exc_info.value.code == 1

    def test_main_missing_config_file_env(self):
        """Missing CONFIG_FILE env var exits 1."""
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(SystemExit) as exc_info:
                validate_scn_config.main()
            assert exc_info.value.code == 1

    def test_main_missing_schema_file_env(self, tmp_path):
        """Missing SCHEMA_FILE env var exits 1."""
        config_file = tmp_path / 'config.yml'
        config_file.write_text('version: "1.0"\nrules:\n  routine:\n    - pattern: "x"\n      description: "x"\n')

        with patch.dict(os.environ, {
            'CONFIG_FILE': str(config_file),
        }, clear=True):
            with pytest.raises(SystemExit) as exc_info:
                validate_scn_config.main()
            assert exc_info.value.code == 1

    def test_main_with_ai_config(self, tmp_path):
        """Valid config with AI config exits 0."""
        config_file = tmp_path / 'config.yml'
        config_file.write_text(
            'version: "1.0"\n'
            'rules:\n'
            '  routine:\n'
            '    - pattern: "tags.*"\n'
            '      description: "Tag changes"\n'
        )
        ai_config_file = tmp_path / 'ai-config.yml'
        ai_config_file.write_text(
            'provider: "anthropic"\n'
            'model: "claude-3-haiku-20240307"\n'
            'confidence_threshold: 0.8\n'
        )
        schema_path = SCHEMAS_DIR / 'scn-config.schema.json'

        with patch.dict(os.environ, {
            'CONFIG_FILE': str(config_file),
            'SCHEMA_FILE': str(schema_path),
            'AI_CONFIG_FILE': str(ai_config_file),
        }):
            with pytest.raises(SystemExit) as exc_info:
                validate_scn_config.main()
            assert exc_info.value.code == 0


class TestFixtureConfigs:
    """Test validation against existing fixture/profile configs."""

    def test_validate_fedramp_low_profile(self, schema):
        """Built-in FedRAMP Low profile passes validation."""
        profile_path = PROFILES_DIR / 'fedramp-low.yml'
        with open(profile_path, 'r') as f:
            config = yaml.safe_load(f)
        validate_scn_config.validate_config_structure(config, schema)

    def test_validate_minimal_fixture(self, schema):
        """Minimal fixture config passes validation."""
        fixture_path = FIXTURES_DIR / 'config' / 'scn-config-minimal.yml'
        with open(fixture_path, 'r') as f:
            config = yaml.safe_load(f)
        validate_scn_config.validate_config_structure(config, schema)

    def test_validate_openai_fixture(self, schema):
        """OpenAI fixture config passes validation."""
        fixture_path = FIXTURES_DIR / 'config' / 'scn-config-openai.yml'
        with open(fixture_path, 'r') as f:
            config = yaml.safe_load(f)
        validate_scn_config.validate_config_structure(config, schema)

    def test_invalid_no_version_fixture(self, schema):
        """No-version fixture fails validation."""
        fixture_path = FIXTURES_DIR / 'config' / 'scn-config-invalid-no-version.yml'
        with open(fixture_path, 'r') as f:
            config = yaml.safe_load(f)
        with pytest.raises(ValueError, match='version: required field missing'):
            validate_scn_config.validate_config_structure(config, schema)

    def test_invalid_bad_rules_fixture(self, schema):
        """Bad-rules fixture fails validation."""
        fixture_path = FIXTURES_DIR / 'config' / 'scn-config-invalid-bad-rules.yml'
        with open(fixture_path, 'r') as f:
            config = yaml.safe_load(f)
        with pytest.raises(ValueError) as exc_info:
            validate_scn_config.validate_config_structure(config, schema)
        error_msg = str(exc_info.value)
        # The second routine rule has no description and no criterion
        assert 'description: required field missing' in error_msg
        assert 'at least one of pattern, resource, or attribute' in error_msg

    def test_validate_custom_example(self, schema):
        """Custom example profile passes validation."""
        example_path = REPO_ROOT / 'examples' / 'configs' / 'scn-profile-custom.example.yml'
        with open(example_path, 'r') as f:
            config = yaml.safe_load(f)
        validate_scn_config.validate_config_structure(config, schema)
