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

    def test_no_default_ai_provider(self):
        """No default AI provider — ai_config is empty when no user config supplied."""
        classifier = classify_changes.ChangeClassifier()
        # AI is opt-in; no default provider is configured
        assert classifier.ai_config == {}
        assert classifier.ai_config.get('provider') is None

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


class TestMainFunction:
    """Tests for main() function and CLI argument handling."""

    def test_main_with_ai_config_file(self, tmp_path, monkeypatch):
        """Test main() with AI config file loading."""
        # Create test input with correct nested resources[] structure
        input_file = tmp_path / "input.json"
        input_file.write_text(json.dumps({
            'changes': [
                {
                    'file': 'test.tf',
                    'resources': [
                        {
                            'type': 'aws_instance',
                            'name': 'test',
                            'operation': 'modify',
                            'attributes_changed': ['tags'],
                            'diff': '+ tags = { Name = "test" }'
                        }
                    ]
                }
            ]
        }))

        # Create AI config file
        ai_config_file = tmp_path / "ai-config.yml"
        ai_config_file.write_text("""
provider: 'anthropic'
model: 'claude-3-haiku-20240307'
confidence_threshold: 0.85
max_tokens: 2048
""")

        # Create output file path
        output_file = tmp_path / "output.json"

        # Mock sys.argv
        monkeypatch.setattr('sys.argv', [
            'classify_changes.py',
            '--input', str(input_file),
            '--output', str(output_file),
            '--ai-config', str(ai_config_file)
        ])

        # Run main()
        result = classify_changes.main()

        # Should succeed
        assert result is None or result == 0
        assert output_file.exists()

        # Check output has classifications
        output_data = json.loads(output_file.read_text())
        assert 'classifications' in output_data
        assert 'summary' in output_data

    def test_main_with_missing_ai_config_file(self, tmp_path, monkeypatch, capsys):
        """Test main() with missing AI config file (should fail since user explicitly specified it)."""
        # Create test input file
        input_file = tmp_path / "input.json"
        input_file.write_text(json.dumps({'changes': []}))

        output_file = tmp_path / "output.json"

        # Reference non-existent AI config file
        ai_config_file = tmp_path / "nonexistent-ai-config.yml"

        # Mock sys.argv
        monkeypatch.setattr('sys.argv', [
            'classify_changes.py',
            '--input', str(input_file),
            '--output', str(output_file),
            '--ai-config', str(ai_config_file)
        ])

        # Run main() - should fail because user explicitly specified a file that doesn't exist
        result = classify_changes.main()
        assert result == 1

        # Check stderr for error message
        captured = capsys.readouterr()
        assert 'AI config file not found' in captured.err

    def test_main_with_invalid_ai_config_file(self, tmp_path, monkeypatch, capsys):
        """Test main() with invalid YAML in AI config file (should fail)."""
        # Create test input file
        input_file = tmp_path / "input.json"
        input_file.write_text(json.dumps({'changes': []}))

        output_file = tmp_path / "output.json"

        # Create invalid AI config file
        ai_config_file = tmp_path / "invalid-ai-config.yml"
        ai_config_file.write_text("{ invalid yaml content [[[")

        # Mock sys.argv
        monkeypatch.setattr('sys.argv', [
            'classify_changes.py',
            '--input', str(input_file),
            '--output', str(output_file),
            '--ai-config', str(ai_config_file)
        ])

        # Run main() - should fail because AI config has invalid YAML
        result = classify_changes.main()
        assert result == 1

        # Check stderr for error message
        captured = capsys.readouterr()
        assert 'Invalid YAML in AI config file' in captured.err

    def test_main_ai_config_merges_with_profile(self, tmp_path, monkeypatch):
        """Test that AI config file properly merges with profile ai_fallback."""
        # Create test input file
        input_file = tmp_path / "input.json"
        input_file.write_text(json.dumps({'changes': []}))

        # Create profile config with ai_fallback
        profile_config_file = tmp_path / "profile.yml"
        profile_config_file.write_text("""
version: "1.0"
rules:
  routine:
    - pattern: 'tags.*'
      description: 'Tag changes'
ai_fallback:
  provider: 'openai'
  model: 'gpt-4'
  confidence_threshold: 0.7
  max_tokens: 512
""")

        # Create AI config file that should override provider and model
        ai_config_file = tmp_path / "ai-config.yml"
        ai_config_file.write_text("""
provider: 'anthropic'
model: 'claude-3-haiku-20240307'
confidence_threshold: 0.9
""")

        output_file = tmp_path / "output.json"

        # Mock sys.argv
        monkeypatch.setattr('sys.argv', [
            'classify_changes.py',
            '--input', str(input_file),
            '--output', str(output_file),
            '--config', str(profile_config_file),
            '--ai-config', str(ai_config_file)
        ])

        # Run main()
        result = classify_changes.main()
        assert result is None or result == 0

        # Verify the output file reflects merged config
        output_data = json.loads(output_file.read_text())
        assert output_data['ai_enabled'] is False  # --enable-ai not passed

    def test_main_ai_config_without_profile(self, tmp_path, monkeypatch):
        """Test AI config file works without a profile config."""
        # Create test input file
        input_file = tmp_path / "input.json"
        input_file.write_text(json.dumps({'changes': []}))

        # Create AI config file
        ai_config_file = tmp_path / "ai-config.yml"
        ai_config_file.write_text("""
provider: 'anthropic'
model: 'claude-haiku-4-5-20251001'
""")

        output_file = tmp_path / "output.json"

        # Mock sys.argv (no --config, only --ai-config)
        monkeypatch.setattr('sys.argv', [
            'classify_changes.py',
            '--input', str(input_file),
            '--output', str(output_file),
            '--ai-config', str(ai_config_file)
        ])

        # Run main()
        result = classify_changes.main()
        assert result is None or result == 0
        assert output_file.exists()


class TestAiFallbackEnabled:
    """Tests for ai_fallback.enabled config field enabling AI without CLI flag."""

    def test_enabled_false_by_default_when_no_config(self):
        """Without any config, AI fallback is disabled."""
        classifier = classify_changes.ChangeClassifier()
        assert classifier.enable_ai is False

    def test_cli_flag_enables_ai(self):
        """--enable-ai CLI flag enables AI regardless of config."""
        classifier = classify_changes.ChangeClassifier(enable_ai=True)
        assert classifier.enable_ai is True

    def test_config_enabled_true_enables_ai(self):
        """ai_fallback.enabled: true in user config enables AI without CLI flag."""
        config = {'ai_fallback': {'enabled': True, 'provider': 'anthropic'}}
        classifier = classify_changes.ChangeClassifier(config=config, enable_ai=False)
        assert classifier.enable_ai is True

    def test_config_enabled_false_keeps_ai_disabled(self):
        """ai_fallback.enabled: false in config keeps AI disabled."""
        config = {'ai_fallback': {'enabled': False, 'provider': 'anthropic'}}
        classifier = classify_changes.ChangeClassifier(config=config, enable_ai=False)
        assert classifier.enable_ai is False

    def test_cli_flag_wins_over_config_disabled(self):
        """--enable-ai CLI flag enables AI even when config has enabled: false."""
        config = {'ai_fallback': {'enabled': False, 'provider': 'anthropic'}}
        classifier = classify_changes.ChangeClassifier(config=config, enable_ai=True)
        assert classifier.enable_ai is True

    def test_no_ai_config_in_defaults(self):
        """Default config must not contain ai_fallback (AI is opt-in only)."""
        from defaults import get_default_config
        default_cfg = get_default_config()
        assert 'ai_fallback' not in default_cfg, (
            "ai_fallback must not be in default config — "
            "AI must be explicitly opted in via user config or CLI."
        )
