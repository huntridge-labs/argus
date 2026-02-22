#!/usr/bin/env python3
"""
Tests for SCN classification engine
"""

import importlib.util
import json
import pytest
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add scripts directory to path
REPO_ROOT = Path(__file__).resolve().parents[4]
SCRIPTS_DIR = REPO_ROOT / ".github" / "actions" / "scn-detector" / "scripts"
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "scn-detector"

if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

# Import classify_changes module dynamically
spec = importlib.util.spec_from_file_location(
    "classify_changes",
    SCRIPTS_DIR / "classify_changes.py"
)
classify_changes = importlib.util.module_from_spec(spec)
sys.modules["classify_changes"] = classify_changes
spec.loader.exec_module(classify_changes)


# Mark all tests as unit tests
pytestmark = pytest.mark.unit


class TestChangeClassifier:
    """Test ChangeClassifier class."""

    @pytest.fixture
    def minimal_config(self):
        """Load minimal test config."""
        config_path = FIXTURES_DIR / "config" / "scn-config-minimal.yml"
        with open(config_path, 'r') as f:
            import yaml
            return yaml.safe_load(f)

    @pytest.fixture
    def classifier(self, minimal_config):
        """Create classifier instance with minimal config."""
        return classify_changes.ChangeClassifier(config=minimal_config)

    def test_initialization_default_rules(self):
        """Test classifier initializes with default rules."""
        classifier = classify_changes.ChangeClassifier()

        assert 'routine' in classifier.rules
        assert 'adaptive' in classifier.rules
        assert 'transformative' in classifier.rules
        assert 'impact' in classifier.rules

    def test_initialization_custom_config(self, minimal_config):
        """Test classifier initializes with custom config."""
        classifier = classify_changes.ChangeClassifier(config=minimal_config)

        assert classifier.config['version'] == '1.0'
        assert 'routine' in classifier.rules

    def test_match_rule_pattern(self, classifier):
        """Test rule matching with pattern."""
        change = {
            'type': 'aws_instance',
            'name': 'web_server',
            'operation': 'modify',
            'attributes_changed': ['tags'],
            'diff': 'tags = { Name = "test" }'
        }

        rule = {
            'pattern': r'tags\.*',
            'description': 'Tag changes'
        }

        assert classifier.match_rule(change, rule) is True

    def test_match_rule_resource_type(self, classifier):
        """Test rule matching with resource type."""
        change = {
            'type': 'aws_instance',
            'name': 'app_server',
            'operation': 'modify',
            'attributes_changed': ['instance_type'],
            'diff': ''
        }

        rule = {
            'resource': r'aws_instance\..*\.instance_type',
            'operation': 'modify',
            'description': 'Instance type changes'
        }

        # This should match because full resource is aws_instance.app_server
        assert classifier.match_rule(change, rule) is True

    def test_match_rule_attribute(self, classifier):
        """Test rule matching with attribute."""
        change = {
            'type': 'aws_s3_bucket',
            'name': 'data',
            'operation': 'modify',
            'attributes_changed': ['server_side_encryption'],
            'diff': '- encryption_enabled = true'
        }

        rule = {
            'attribute': r'.*encryption.*',
            'operation': 'modify',
            'description': 'Encryption changes'
        }

        assert classifier.match_rule(change, rule) is True

    def test_classify_with_rules_routine(self, classifier):
        """Test classification of routine change."""
        change = {
            'type': 'aws_instance',
            'name': 'web',
            'operation': 'modify',
            'attributes_changed': ['tags'],
            'diff': 'tags = { Name = "updated" }'
        }

        result = classifier.classify_with_rules(change)

        assert result is not None
        category, rule = result
        assert category == 'ROUTINE'

    def test_classify_with_rules_adaptive(self, classifier):
        """Test classification of adaptive change."""
        change = {
            'type': 'aws_instance',
            'name': 'app_server',
            'operation': 'modify',
            'attributes_changed': ['instance_type'],
            'diff': '- instance_type = "t2.micro"\n+ instance_type = "t3.small"'
        }

        result = classifier.classify_with_rules(change)

        assert result is not None
        category, rule = result
        assert category == 'ADAPTIVE'

    def test_classify_with_rules_transformative(self, classifier):
        """Test classification of transformative change."""
        change = {
            'type': 'aws_rds_cluster',
            'name': 'main',
            'operation': 'modify',
            'attributes_changed': ['engine'],
            'diff': '- engine = "postgres"\n+ engine = "aurora-postgresql"'
        }

        result = classifier.classify_with_rules(change)

        assert result is not None
        category, rule = result
        assert category == 'TRANSFORMATIVE'

    def test_classify_with_rules_impact(self, classifier):
        """Test classification of impact change."""
        change = {
            'type': 'aws_s3_bucket',
            'name': 'data',
            'operation': 'delete',
            'attributes_changed': ['server_side_encryption_configuration'],
            'diff': '- encryption { ... }'
        }

        result = classifier.classify_with_rules(change)

        assert result is not None
        category, rule = result
        assert category == 'IMPACT'

    def test_classify_with_rules_no_match(self, classifier):
        """Test classification when no rule matches."""
        change = {
            'type': 'unknown_resource',
            'name': 'test',
            'operation': 'create',
            'attributes_changed': [],
            'diff': ''
        }

        result = classifier.classify_with_rules(change)

        assert result is None

    def test_classify_with_ai_success(self, classifier):
        """Test AI classification success via mocked AIClassifier."""
        classifier.enable_ai = True
        classifier.api_key = 'test-api-key'

        # Mock the AI classifier
        mock_ai = MagicMock()
        mock_ai.classify.return_value = {
            'category': 'TRANSFORMATIVE',
            'confidence': 0.95,
            'reasoning': 'Test'
        }
        classifier._ai_classifier = mock_ai

        change = {
            'type': 'aws_rds_cluster',
            'name': 'main',
            'operation': 'modify',
            'attributes_changed': ['engine'],
            'diff': '- engine = "postgres"\n+ engine = "aurora"'
        }

        result = classifier.classify_with_ai(change)

        assert result['category'] == 'TRANSFORMATIVE'
        assert result['confidence'] == 0.95
        assert 'Test' in result['reasoning']

    def test_classify_with_ai_low_confidence(self, classifier):
        """Test AI classification with low confidence."""
        classifier.enable_ai = True
        classifier.api_key = 'test-api-key'

        # Mock the AI classifier returning low confidence
        mock_ai = MagicMock()
        mock_ai.classify.return_value = {
            'category': 'MANUAL_REVIEW',
            'confidence': 0.65,
            'reasoning': 'Low confidence (0.65 < 0.8): Uncertain'
        }
        classifier._ai_classifier = mock_ai

        change = {'type': 'test', 'name': 'test', 'operation': 'modify', 'attributes_changed': [], 'diff': ''}

        result = classifier.classify_with_ai(change)

        assert result['category'] == 'MANUAL_REVIEW'
        assert result['confidence'] == 0.65

    def test_classify_with_ai_no_api_key(self, classifier):
        """Test AI classification without API key."""
        classifier.enable_ai = True
        classifier.api_key = None

        change = {'type': 'test', 'name': 'test', 'operation': 'modify', 'attributes_changed': [], 'diff': ''}

        result = classifier.classify_with_ai(change)

        assert result['category'] == 'MANUAL_REVIEW'
        assert 'not available' in result['reasoning']

    def test_classify_change_rule_based_priority(self, classifier):
        """Test that rule-based classification takes priority over AI."""
        change = {
            'type': 'aws_instance',
            'name': 'web',
            'operation': 'modify',
            'attributes_changed': ['tags'],
            'diff': ''
        }

        result = classifier.classify_change(change)

        assert result['category'] == 'ROUTINE'
        assert result['method'] == 'rule-based'
        assert result['confidence'] == 1.0


class TestConfigLoading:
    """Test configuration loading."""

    def test_load_valid_config(self):
        """Test loading valid YAML config."""
        config_path = FIXTURES_DIR / "config" / "scn-config-minimal.yml"

        classifier = classify_changes.ChangeClassifier()
        config = classifier.load_config_from_file(str(config_path))

        assert config['version'] == '1.0'
        assert 'rules' in config

    def test_load_missing_config(self):
        """Test loading non-existent config."""
        classifier = classify_changes.ChangeClassifier()
        config = classifier.load_config_from_file('nonexistent.yml')

        assert config == {}


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_changes_classification(self):
        """Test classification with empty changes."""
        classifier = classify_changes.ChangeClassifier()

        changes_data = {
            'changes': [],
            'summary': {'total_files': 0}
        }

        result = classifier.classify_all_changes(changes_data)

        assert result['summary']['routine'] == 0
        assert result['summary']['adaptive'] == 0

    def test_malformed_change_data(self):
        """Test handling of malformed change data."""
        classifier = classify_changes.ChangeClassifier()

        change = {
            # Missing required fields
            'operation': 'modify'
        }

        result = classifier.classify_change(change)

        # Should not crash, returns classification
        assert 'category' in result


class TestProviderConfiguration:
    """Test multi-provider configuration."""

    def test_default_provider_is_anthropic(self):
        """Default AI config uses anthropic provider."""
        classifier = classify_changes.ChangeClassifier()
        assert classifier.ai_config.get('provider') == 'anthropic'

    @patch.dict('os.environ', {'ANTHROPIC_API_KEY': 'anthro-key'})
    def test_anthropic_api_key_resolved(self):
        """Anthropic API key resolved from env var."""
        classifier = classify_changes.ChangeClassifier()
        assert classifier.api_key == 'anthro-key'

    @patch.dict('os.environ', {'OPENAI_API_KEY': 'openai-key'}, clear=True)
    def test_openai_api_key_resolved(self):
        """OpenAI API key resolved when provider is openai."""
        config = {
            'ai_fallback': {
                'enabled': True,
                'provider': 'openai',
                'model': 'gpt-4o-mini',
                'confidence_threshold': 0.8
            }
        }
        classifier = classify_changes.ChangeClassifier(config=config)
        assert classifier.api_key == 'openai-key'

    def test_openai_config_from_fixture(self):
        """OpenAI config loaded from fixture file."""
        config_path = FIXTURES_DIR / "config" / "scn-config-openai.yml"
        if not config_path.exists():
            pytest.skip("OpenAI fixture not yet created")

        classifier = classify_changes.ChangeClassifier()
        config = classifier.load_config_from_file(str(config_path))

        assert config.get('ai_fallback', {}).get('provider') == 'openai'
        assert config.get('ai_fallback', {}).get('model') == 'gpt-4o-mini'
