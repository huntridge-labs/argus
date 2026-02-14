#!/usr/bin/env python3
"""
Unit tests for parse_zap_config.py
Tests config loading, validation, matrix generation for ZAP DAST scanning.
"""

import json
import pytest

pytestmark = pytest.mark.unit
import os
import sys
from pathlib import Path

import pytest

# Add parent directory to path to import the script
script_dir = Path(__file__).parent.parent / 'scripts'
sys.path.insert(0, str(script_dir))

from parse_zap_config import (
    load_config,
    validate_config_structure,
    generate_matrices,
    build_image_reference,
    expand_env_vars,
    expand_env_vars_in_object,
    normalize_ports,
    build_target_config,
    generate_scan_entry
)

# Paths for fixtures
REPO_ROOT = Path(__file__).parent.parent.parent.parent.parent
FIXTURES_DIR = REPO_ROOT / 'tests' / 'fixtures' / 'configs'
SCHEMA_PATH = REPO_ROOT / '.github' / 'schemas' / 'zap-config.schema.json'


class TestLoadConfig:
    """Tests for load_config function."""

    def test_load_valid_yaml_config(self):
        """Load valid YAML config file."""
        config_path = FIXTURES_DIR / 'zap-config.yml'
        config = load_config(str(config_path))

        assert config is not None
        assert isinstance(config, dict)
        assert 'scans' in config or 'scan_groups' in config

    def test_load_json_config(self, tmp_path):
        """Load JSON config file."""
        config_data = {
            'scans': [{'name': 'test', 'type': 'baseline', 'target_url': 'http://localhost'}]
        }
        json_file = tmp_path / 'config.json'
        json_file.write_text(json.dumps(config_data))

        config = load_config(str(json_file))
        assert config == config_data

    def test_unsupported_file_extension(self, tmp_path):
        """Error on unsupported file extension."""
        txt_file = tmp_path / 'config.txt'
        txt_file.write_text('invalid')

        with pytest.raises(ValueError, match="Unsupported config file type"):
            load_config(str(txt_file))


class TestExpandEnvVars:
    """Tests for environment variable expansion."""

    def test_expand_env_var_in_string(self, monkeypatch):
        """Expand ${VAR} syntax in string."""
        monkeypatch.setenv('API_TOKEN', 'secret123')
        result = expand_env_vars('Bearer ${API_TOKEN}')
        assert result == 'Bearer secret123'

    def test_expand_missing_env_var(self):
        """Keep original text for missing environment variable."""
        result = expand_env_vars('prefix-${MISSING_VAR}-suffix')
        assert result == 'prefix-${MISSING_VAR}-suffix'

    def test_preserve_secrets_mode(self, monkeypatch):
        """Preserve secrets mode returns var name."""
        monkeypatch.setenv('API_TOKEN', 'secret123')
        result = expand_env_vars('Bearer ${API_TOKEN}', preserve_secrets=True)
        assert result == 'Bearer API_TOKEN'

    def test_expand_env_vars_in_nested_object(self, monkeypatch):
        """Expand environment variables in nested objects."""
        monkeypatch.setenv('REGISTRY_HOST', 'ghcr.io')

        obj = {
            'target': {
                'image': '${REGISTRY_HOST}/zap:latest'
            }
        }

        result = expand_env_vars_in_object(obj)
        assert result['target']['image'] == 'ghcr.io/zap:latest'

    def test_skip_secret_fields_in_expansion(self, monkeypatch):
        """Don't expand secret field names."""
        monkeypatch.setenv('TOKEN', 'secret123')

        obj = {
            'auth': {
                'header_secret': '${TOKEN}'
            }
        }

        result = expand_env_vars_in_object(obj, skip_secret_fields=True)
        # Secret field value should not be expanded
        assert result['auth']['header_secret'] == '${TOKEN}'

    def test_expand_env_vars_in_array(self, monkeypatch):
        """Expand environment variables in arrays."""
        monkeypatch.setenv('SCAN_TYPE', 'baseline')
        obj = ['${SCAN_TYPE}', 'full']
        result = expand_env_vars_in_object(obj)
        assert result == ['baseline', 'full']


class TestValidateConfig:
    """Tests for validate_config_structure function."""

    def test_validate_valid_flat_config(self):
        """Valid flat config passes validation."""
        config = {
            'scans': [
                {
                    'name': 'test-scan',
                    'type': 'baseline',
                    'target_url': 'http://example.com'
                }
            ]
        }

        # Should not raise
        validate_config_structure(config, {})

    def test_validate_valid_grouped_config(self):
        """Valid grouped config passes validation."""
        config = {
            'scan_groups': [
                {
                    'name': 'group1',
                    'scans': [
                        {
                            'name': 'test-scan',
                            'type': 'baseline',
                            'target_url': 'http://example.com'
                        }
                    ]
                }
            ]
        }

        # Should not raise
        validate_config_structure(config, {})

    def test_validate_missing_scans_and_groups(self):
        """Error when neither scans nor scan_groups is present."""
        config = {}
        with pytest.raises(ValueError, match="must have either"):
            validate_config_structure(config, {})

    def test_validate_scans_not_array(self):
        """Error when scans is not an array."""
        config = {'scans': 'not-an-array'}
        with pytest.raises(ValueError, match="scans: must be an array"):
            validate_config_structure(config, {})

    def test_validate_missing_scan_name(self):
        """Error when scan name is missing."""
        config = {
            'scans': [
                {'type': 'baseline', 'target_url': 'http://example.com'}
            ]
        }
        with pytest.raises(ValueError, match="name: required field missing"):
            validate_config_structure(config, {})

    def test_validate_missing_scan_type(self):
        """Error when scan type is missing."""
        config = {
            'scans': [
                {'name': 'test-scan', 'target_url': 'http://example.com'}
            ]
        }
        with pytest.raises(ValueError, match="type: required field missing"):
            validate_config_structure(config, {})

    def test_validate_invalid_scan_type(self):
        """Error on invalid scan type."""
        config = {
            'scans': [
                {'name': 'test-scan', 'type': 'invalid', 'target_url': 'http://example.com'}
            ]
        }
        with pytest.raises(ValueError, match="must be one of"):
            validate_config_structure(config, {})

    def test_validate_grouped_config_missing_group_name(self):
        """Error when group name is missing."""
        config = {
            'scan_groups': [
                {
                    'scans': [
                        {'name': 'test', 'type': 'baseline', 'target_url': 'http://example.com'}
                    ]
                }
            ]
        }
        with pytest.raises(ValueError, match="name: required field missing"):
            validate_config_structure(config, {})

    def test_validate_grouped_config_missing_scans(self):
        """Error when group scans are missing."""
        config = {
            'scan_groups': [
                {'name': 'group1'}
            ]
        }
        with pytest.raises(ValueError, match="scans: required field missing"):
            validate_config_structure(config, {})

    def test_validate_duplicate_scan_names_flat(self):
        """Error on duplicate scan names in flat config."""
        config = {
            'scans': [
                {'name': 'test', 'type': 'baseline', 'target_url': 'http://example.com'},
                {'name': 'test', 'type': 'full', 'target_url': 'http://example.com'}
            ]
        }
        with pytest.raises(ValueError, match="Duplicate scan names found"):
            validate_config_structure(config, {})

    def test_validate_duplicate_scan_names_across_groups(self):
        """Error on duplicate scan names across groups."""
        config = {
            'scan_groups': [
                {
                    'name': 'group1',
                    'scans': [
                        {'name': 'test', 'type': 'baseline', 'target_url': 'http://example.com'}
                    ]
                },
                {
                    'name': 'group2',
                    'scans': [
                        {'name': 'test', 'type': 'full', 'target_url': 'http://example.com'}
                    ]
                }
            ]
        }
        with pytest.raises(ValueError, match="Duplicate scan names found"):
            validate_config_structure(config, {})


class TestBuildImageReference:
    """Tests for build_image_reference function."""

    def test_build_from_string(self):
        """String image reference returns as-is."""
        image = 'owasp/zap2docker-stable:latest'
        result = build_image_reference(image)
        assert result == image

    def test_build_from_structured_object(self):
        """Build image reference from structured object."""
        image = {
            'registry': 'docker.io',
            'repository': 'owasp',
            'name': 'zap2docker-stable',
            'tag': 'latest'
        }
        result = build_image_reference(image)

        assert 'zap2docker-stable' in result
        assert 'latest' in result
        assert 'docker.io' in result

    def test_build_with_digest(self):
        """Image reference includes digest when provided."""
        image = {
            'registry': 'docker.io',
            'repository': 'owasp',
            'name': 'zap2docker-stable',
            'tag': 'latest',
            'digest': 'sha256:1234567890abcdef'
        }
        result = build_image_reference(image)

        assert '@sha256:' in result
        assert '1234567890abcdef' in result

    def test_build_without_registry(self):
        """Image reference without registry."""
        image = {
            'repository': 'owasp',
            'name': 'zap2docker-stable',
            'tag': 'latest'
        }
        result = build_image_reference(image)

        assert 'owasp/zap2docker-stable:latest' in result




class TestNormalizePorts:
    """Tests for normalize_ports function."""

    def test_normalize_string_ports(self):
        """Parse comma-separated ports string."""
        result = normalize_ports('3000:3000,8080:8080')
        assert result == ['3000:3000', '8080:8080']

    def test_normalize_list_ports(self):
        """Handle list of ports."""
        result = normalize_ports(['3000:3000', '8080:8080'])
        assert result == ['3000:3000', '8080:8080']

    def test_default_ports(self):
        """Default to 8080:8080 when not specified."""
        result = normalize_ports(None)
        assert result == ['8080:8080']

    def test_normalize_single_port(self):
        """Handle single port string."""
        result = normalize_ports('3000:3000')
        assert result == ['3000:3000']

    def test_normalize_ports_with_whitespace(self):
        """Trim whitespace from ports."""
        result = normalize_ports('  3000:3000  ,  8080:8080  ')
        assert result == ['3000:3000', '8080:8080']


class TestBuildTargetConfig:
    """Tests for build_target_config function."""


    def test_build_target_config_with_custom_values(self):
        """Build target config with custom values."""
        target = {
            'mode': 'docker-run',
            'image': 'test-app:latest',
            'ports': '3000:3000',
            'healthcheck_url': 'http://localhost:3000/health'
        }
        result = build_target_config(target)

        assert result['mode'] == 'docker-run'
        assert 'test-app' in result['image']
        assert result['ports'] == '3000:3000'
        assert result['healthcheck_url'] == 'http://localhost:3000/health'

    def test_build_target_config_with_build_config(self):
        """Build target config with build settings."""
        target = {
            'build': {
                'context': '.',
                'dockerfile': 'Dockerfile',
                'tag': 'app:latest'
            }
        }
        result = build_target_config(target)

        assert result['build_context'] == '.'
        assert result['build_dockerfile'] == 'Dockerfile'
        assert result['build_tag'] == 'app:latest'


class TestGenerateScanEntry:
    """Tests for generate_scan_entry function."""

    def test_generate_scan_entry_basic(self):
        """Generate basic scan entry."""
        scan = {
            'name': 'test-scan',
            'type': 'baseline',
            'target_url': 'http://example.com'
        }
        defaults = {}
        target_config = build_target_config(None)
        root_config = {}

        entry = generate_scan_entry(scan, defaults, target_config, root_config)

        assert entry['name'] == 'test-scan'
        assert entry['scan_type'] == 'baseline'
        assert entry['target_url'] == 'http://example.com'

    def test_generate_scan_entry_with_defaults(self):
        """Generate scan entry with defaults applied."""
        scan = {
            'name': 'test-scan',
            'type': 'baseline'
        }
        defaults = {
            'target_url': 'http://default.com',
            'max_duration_minutes': 15,
            'fail_on_severity': 'high'
        }
        target_config = build_target_config(None)
        root_config = {}

        entry = generate_scan_entry(scan, defaults, target_config, root_config)

        assert entry['target_url'] == 'http://default.com'
        assert entry['max_duration_minutes'] == 15
        assert entry['fail_on_severity'] == 'high'

    def test_scan_overrides_defaults(self):
        """Scan-level values override defaults."""
        scan = {
            'name': 'test-scan',
            'type': 'baseline',
            'target_url': 'http://scan.com',
            'max_duration_minutes': 20
        }
        defaults = {
            'target_url': 'http://default.com',
            'max_duration_minutes': 15
        }
        target_config = build_target_config(None)
        root_config = {}

        entry = generate_scan_entry(scan, defaults, target_config, root_config)

        assert entry['target_url'] == 'http://scan.com'
        assert entry['max_duration_minutes'] == 20

    def test_generate_scan_entry_with_auth(self):
        """Generate scan entry with authentication."""
        scan = {
            'name': 'auth-scan',
            'type': 'baseline',
            'target_url': 'http://example.com',
            'auth': {
                'header_name': 'Authorization',
                'header_secret': 'API_TOKEN'
            }
        }
        defaults = {}
        target_config = build_target_config(None)
        root_config = {}

        entry = generate_scan_entry(scan, defaults, target_config, root_config)

        assert entry['auth_header_name'] == 'Authorization'
        assert entry['auth_header_secret'] == 'API_TOKEN'


class TestGenerateMatrices:
    """Tests for generate_matrices function."""

    def test_generate_matrices_flat_config(self):
        """Generate matrices from flat config."""
        config = {
            'scans': [
                {
                    'name': 'scan1',
                    'type': 'baseline',
                    'target_url': 'http://example.com'
                },
                {
                    'name': 'scan2',
                    'type': 'full',
                    'target_url': 'http://example.com'
                }
            ]
        }

        result = generate_matrices(config)

        assert 'groups' in result
        assert len(result['groups']) == 1
        assert result['groups'][0]['name'] == 'default'
        assert len(result['groups'][0]['matrix']['include']) == 2

    def test_generate_matrices_grouped_config(self):
        """Generate matrices from grouped config."""
        config = {
            'scan_groups': [
                {
                    'name': 'group1',
                    'scans': [
                        {
                            'name': 'scan1',
                            'type': 'baseline',
                            'target_url': 'http://example.com'
                        }
                    ]
                },
                {
                    'name': 'group2',
                    'scans': [
                        {
                            'name': 'scan2',
                            'type': 'full',
                            'target_url': 'http://example.com'
                        }
                    ]
                }
            ]
        }

        result = generate_matrices(config)

        assert len(result['groups']) == 2
        assert result['groups'][0]['name'] == 'group1'
        assert result['groups'][1]['name'] == 'group2'

    def test_generate_matrices_group_target_override(self):
        """Group target overrides root target."""
        config = {
            'target': {
                'mode': 'url',
                'image': 'root-image:latest'
            },
            'scan_groups': [
                {
                    'name': 'group1',
                    'target': {
                        'image': 'group-image:latest'
                    },
                    'scans': [
                        {
                            'name': 'scan1',
                            'type': 'baseline',
                            'target_url': 'http://example.com'
                        }
                    ]
                }
            ]
        }

        result = generate_matrices(config)

        group_target = result['groups'][0]['target']
        assert 'group-image' in group_target['image']

    def test_matrix_entries_have_required_fields(self):
        """Matrix entries contain all required fields."""
        config = {
            'scans': [
                {
                    'name': 'test-scan',
                    'type': 'baseline',
                    'target_url': 'http://example.com'
                }
            ]
        }

        result = generate_matrices(config)
        entry = result['groups'][0]['matrix']['include'][0]

        assert 'name' in entry
        assert 'scan_type' in entry
        assert 'target_url' in entry
        assert 'fail_on_severity' in entry
        assert 'mode' in entry




class TestFixtureConfigs:
    """Tests using fixture configuration files."""

    def test_load_and_validate_zap_config_fixture(self):
        """Load and validate the ZAP config fixture."""
        config = load_config(str(FIXTURES_DIR / 'zap-config.yml'))

        with open(SCHEMA_PATH, 'r') as f:
            schema = json.load(f)

        # Should not raise
        validate_config_structure(config, schema)

    def test_generate_matrices_from_zap_config_fixture(self):
        """Generate matrices from ZAP config fixture."""
        config = load_config(str(FIXTURES_DIR / 'zap-config.yml'))
        result = generate_matrices(config)

        assert len(result['groups']) >= 1

    def test_load_and_validate_invalid_zap_config_fixture(self):
        """Load invalid ZAP config fixture."""
        config = load_config(str(FIXTURES_DIR / 'invalid-zap-config.yml'))

        with open(SCHEMA_PATH, 'r') as f:
            schema = json.load(f)

        # Should raise validation error
        with pytest.raises(ValueError):
            validate_config_structure(config, schema)


class TestEdgeCases:
    """Tests for edge cases and special scenarios."""


    def test_post_pr_comment_priority(self):
        """post_pr_comment priority: scan > defaults > root > false."""
        # Test scan-level takes priority
        config = {
            'post_pr_comment': False,
            'defaults': {'post_pr_comment': False},
            'scans': [
                {
                    'name': 'test-scan',
                    'type': 'baseline',
                    'target_url': 'http://example.com',
                    'post_pr_comment': True
                }
            ]
        }

        result = generate_matrices(config)
        entry = result['groups'][0]['matrix']['include'][0]
        assert entry['post_pr_comment'] is True

    def test_auth_merge_scan_overrides_defaults(self):
        """Scan auth settings override defaults."""
        config = {
            'defaults': {
                'auth': {
                    'header_name': 'X-Default-Auth',
                    'header_secret': 'DEFAULT_SECRET'
                }
            },
            'scans': [
                {
                    'name': 'test-scan',
                    'type': 'baseline',
                    'target_url': 'http://example.com',
                    'auth': {
                        'header_name': 'Authorization'
                    }
                }
            ]
        }

        result = generate_matrices(config)
        entry = result['groups'][0]['matrix']['include'][0]

        # Scan auth should override default
        assert entry['auth_header_name'] == 'Authorization'
        # But default secret should be used if not overridden
        assert entry['auth_header_secret'] == 'DEFAULT_SECRET'

    def test_api_spec_in_matrix(self):
        """API scan includes api_spec field."""
        config = {
            'scans': [
                {
                    'name': 'api-scan',
                    'type': 'api',
                    'api_spec': 'openapi.yaml'
                }
            ]
        }

        result = generate_matrices(config)
        entry = result['groups'][0]['matrix']['include'][0]

        assert entry['api_spec'] == 'openapi.yaml'

    def test_healthcheck_url_cascade(self):
        """healthcheck_url cascades from target to entry."""
        config = {
            'target': {
                'healthcheck_url': 'http://localhost:3000/health'
            },
            'scans': [
                {
                    'name': 'test-scan',
                    'type': 'baseline',
                    'target_url': 'http://localhost:3000'
                }
            ]
        }

        result = generate_matrices(config)
        entry = result['groups'][0]['matrix']['include'][0]

        assert entry['healthcheck_url'] == 'http://localhost:3000/health'
