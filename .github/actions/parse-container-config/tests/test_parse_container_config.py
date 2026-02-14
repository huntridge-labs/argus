#!/usr/bin/env python3
"""
Unit tests for parse_container_config.py
Tests config loading, validation, matrix generation, and image reference building.
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

from parse_container_config import (
    load_config,
    validate_config_structure,
    generate_matrix,
    generate_scan_matrix,
    build_image_reference,
    expand_env_vars,
    expand_env_vars_in_object
)

# Paths for fixtures
REPO_ROOT = Path(__file__).parent.parent.parent.parent.parent
FIXTURES_DIR = REPO_ROOT / 'tests' / 'fixtures' / 'configs'
SCHEMA_PATH = REPO_ROOT / '.github' / 'schemas' / 'container-config.schema.json'


class TestLoadConfig:
    """Tests for load_config function."""

    def test_load_valid_yaml_config(self):
        """Load valid YAML config file."""
        config_path = FIXTURES_DIR / 'container-config.yml'
        config = load_config(str(config_path))

        assert config is not None
        assert isinstance(config, dict)
        assert 'containers' in config
        assert isinstance(config['containers'], list)


    def test_load_json_config(self, tmp_path):
        """Load JSON config file."""
        config_data = {'containers': [{'name': 'test', 'image': 'nginx:latest'}]}
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
        monkeypatch.setenv('TEST_VAR', 'test_value')
        result = expand_env_vars('prefix-${TEST_VAR}-suffix')
        assert result == 'prefix-test_value-suffix'

    def test_expand_missing_env_var(self):
        """Keep original text for missing environment variable."""
        result = expand_env_vars('prefix-${NONEXISTENT_VAR}-suffix')
        assert result == 'prefix-${NONEXISTENT_VAR}-suffix'


    def test_expand_env_vars_in_nested_object(self, monkeypatch):
        """Expand environment variables in nested objects."""
        monkeypatch.setenv('GITHUB_ACTOR', 'testuser')
        monkeypatch.setenv('REGISTRY_HOST', 'ghcr.io')

        obj = {
            'containers': [
                {
                    'name': 'app',
                    'image': '${REGISTRY_HOST}/test:latest',
                    'registry': {'username': '${GITHUB_ACTOR}'}
                }
            ]
        }

        result = expand_env_vars_in_object(obj)
        assert result['containers'][0]['image'] == 'ghcr.io/test:latest'
        assert result['containers'][0]['registry']['username'] == 'testuser'

    def test_expand_env_vars_in_array(self, monkeypatch):
        """Expand environment variables in arrays."""
        monkeypatch.setenv('SCANNER', 'trivy')
        obj = ['${SCANNER}', 'grype']
        result = expand_env_vars_in_object(obj)
        assert result == ['trivy', 'grype']


class TestValidateConfig:
    """Tests for validate_config_structure function."""

    def test_validate_valid_config(self):
        """Valid config passes validation."""
        with open(SCHEMA_PATH, 'r') as f:
            schema = json.load(f)

        config = {
            'containers': [
                {
                    'name': 'app',
                    'image': 'nginx:latest'
                }
            ]
        }

        # Should not raise
        validate_config_structure(config, schema)

    def test_validate_missing_containers_field(self):
        """Error when 'containers' field is missing."""
        config = {}
        with pytest.raises(ValueError, match="containers: required field missing"):
            validate_config_structure(config, {})

    def test_validate_containers_not_array(self):
        """Error when 'containers' is not an array."""
        config = {'containers': 'not-an-array'}
        with pytest.raises(ValueError, match="containers: must be an array"):
            validate_config_structure(config, {})

    def test_validate_empty_containers_array(self):
        """Error when 'containers' array is empty."""
        config = {'containers': []}
        with pytest.raises(ValueError, match="must have at least 1 item"):
            validate_config_structure(config, {})

    def test_validate_missing_name_field(self):
        """Error when container 'name' field is missing."""
        config = {
            'containers': [
                {'image': 'nginx:latest'}
            ]
        }
        with pytest.raises(ValueError, match="name: required field missing"):
            validate_config_structure(config, {})

    def test_validate_missing_image_field(self):
        """Error when container 'image' field is missing."""
        config = {
            'containers': [
                {'name': 'app'}
            ]
        }
        with pytest.raises(ValueError, match="image: required field missing"):
            validate_config_structure(config, {})

    def test_validate_invalid_name_format(self):
        """Error on invalid name format."""
        config = {
            'containers': [
                {'name': 'invalid name!', 'image': 'nginx:latest'}
            ]
        }
        with pytest.raises(ValueError, match="invalid format"):
            validate_config_structure(config, {})

    def test_validate_duplicate_container_names(self):
        """Error on duplicate container names."""
        config = {
            'containers': [
                {'name': 'app', 'image': 'nginx:latest'},
                {'name': 'app', 'image': 'nginx:latest'}
            ]
        }
        with pytest.raises(ValueError, match="Duplicate container names found: app"):
            validate_config_structure(config, {})

    def test_validate_invalid_scanner_name(self):
        """Error on invalid scanner name."""
        config = {
            'containers': [
                {
                    'name': 'app',
                    'image': 'nginx:latest',
                    'scanners': ['trivy', 'nonexistent']
                }
            ]
        }
        with pytest.raises(ValueError, match="'nonexistent' is not valid"):
            validate_config_structure(config, {})

    def test_validate_invalid_fail_on_severity(self):
        """Error on invalid fail_on_severity."""
        config = {
            'containers': [
                {
                    'name': 'app',
                    'image': 'nginx:latest',
                    'fail_on_severity': 'invalid'
                }
            ]
        }
        with pytest.raises(ValueError, match="'invalid' is not valid"):
            validate_config_structure(config, {})


class TestBuildImageReference:
    """Tests for build_image_reference function."""

    def test_build_from_string(self):
        """String image reference returns as-is."""
        image = 'nginx:alpine'
        result = build_image_reference(image)
        assert result == image

    def test_build_from_structured_object(self):
        """Build image reference from structured object."""
        image = {
            'repository': 'library',
            'name': 'nginx',
            'tag': 'alpine'
        }
        result = build_image_reference(image, 'docker.io')

        assert 'nginx' in result
        assert 'alpine' in result
        assert 'docker.io' in result
        assert 'library' in result

    def test_build_with_digest(self):
        """Image reference includes digest when provided."""
        image = {
            'repository': 'library',
            'name': 'nginx',
            'tag': 'alpine',
            'digest': 'sha256:1234567890abcdef'
        }
        result = build_image_reference(image, 'docker.io')

        assert '@sha256:' in result
        assert '1234567890abcdef' in result


    def test_custom_registry_host(self):
        """Custom registry host is used."""
        image = {
            'name': 'nginx',
            'tag': 'alpine'
        }
        result = build_image_reference(image, 'ghcr.io')

        assert 'ghcr.io' in result


    def test_image_without_repository(self):
        """Image reference without repository."""
        image = {
            'name': 'nginx',
            'tag': 'alpine'
        }
        result = build_image_reference(image, 'docker.io')

        # Should not have double slashes
        assert '//' not in result



class TestGenerateMatrix:
    """Tests for generate_matrix function."""

    def test_generate_matrix_from_valid_config(self):
        """Generate matrix from valid config."""
        config = {
            'containers': [
                {
                    'name': 'app',
                    'image': 'nginx:latest'
                }
            ]
        }

        matrix = generate_matrix(config)

        assert matrix is not None
        assert 'include' in matrix
        assert isinstance(matrix['include'], list)
        assert len(matrix['include']) > 0

    def test_matrix_entries_have_required_fields(self):
        """Matrix entries contain all required fields."""
        config = {
            'containers': [
                {
                    'name': 'app',
                    'image': 'nginx:latest'
                }
            ]
        }

        matrix = generate_matrix(config)
        entry = matrix['include'][0]

        assert 'name' in entry
        assert 'scanners' in entry
        assert 'image' in entry
        assert 'fail_on_severity' in entry
        assert 'allow_failure' in entry
        assert 'enable_code_security' in entry
        assert 'post_pr_comment' in entry
        assert 'registry_username' in entry
        assert 'registry_auth_secret' in entry

    def test_scanners_are_comma_separated_string(self):
        """Scanners are joined as comma-separated string."""
        config = {
            'containers': [
                {
                    'name': 'app',
                    'image': 'nginx:latest',
                    'scanners': ['trivy', 'grype']
                }
            ]
        }

        matrix = generate_matrix(config)
        entry = matrix['include'][0]

        assert isinstance(entry['scanners'], str)
        assert entry['scanners'] == 'trivy,grype'


    def test_default_scanner_is_trivy(self):
        """Default scanner is 'trivy' when not specified."""
        config = {
            'containers': [
                {'name': 'app', 'image': 'nginx:latest'}
            ]
        }

        matrix = generate_matrix(config)
        entry = matrix['include'][0]

        assert entry['scanners'] == 'trivy'




    def test_registry_configuration_in_matrix(self):
        """Registry configuration is included in matrix entry."""
        config = {
            'containers': [
                {
                    'name': 'app',
                    'image': {'repository': 'lib', 'name': 'nginx', 'tag': 'latest'},
                    'registry': {
                        'host': 'ghcr.io',
                        'username': 'user',
                        'auth_secret': 'TOKEN'
                    }
                }
            ]
        }

        matrix = generate_matrix(config)
        entry = matrix['include'][0]

        assert entry['registry_username'] == 'user'
        assert entry['registry_auth_secret'] == 'TOKEN'
        assert 'ghcr.io' in entry['image']


class TestGenerateScanMatrix:
    """Tests for generate_scan_matrix function."""

    def test_generate_scan_matrix_from_valid_config(self):
        """Generate scan matrix from valid config."""
        config = {
            'containers': [
                {
                    'name': 'app',
                    'image': 'nginx:latest',
                    'scanners': ['trivy', 'grype']
                }
            ]
        }

        matrix = generate_scan_matrix(config)

        assert matrix is not None
        assert 'include' in matrix
        assert isinstance(matrix['include'], list)

    def test_scan_matrix_creates_one_entry_per_scanner(self):
        """One matrix entry created for each scanner."""
        config = {
            'containers': [
                {
                    'name': 'app',
                    'image': 'nginx:latest',
                    'scanners': ['trivy', 'grype']
                }
            ]
        }

        matrix = generate_scan_matrix(config)

        # Should have 2 entries (one per scanner)
        assert len(matrix['include']) == 2

    def test_scan_matrix_multiple_containers_and_scanners(self):
        """Scan matrix for multiple containers with scanners."""
        config = {
            'containers': [
                {
                    'name': 'app1',
                    'image': 'nginx:latest',
                    'scanners': ['trivy', 'grype']
                },
                {
                    'name': 'app2',
                    'image': 'node:latest',
                    'scanners': ['trivy']
                }
            ]
        }

        matrix = generate_scan_matrix(config)

        # Should have 3 entries (2 scanners for app1, 1 for app2)
        assert len(matrix['include']) == 3

    def test_scan_matrix_entries_have_scanner_field(self):
        """Scan matrix entries have 'scanner' field."""
        config = {
            'containers': [
                {
                    'name': 'app',
                    'image': 'nginx:latest',
                    'scanners': ['trivy', 'grype']
                }
            ]
        }

        matrix = generate_scan_matrix(config)

        for entry in matrix['include']:
            assert 'scanner' in entry
            assert entry['scanner'] in ['trivy', 'grype']

    def test_scan_matrix_preserves_container_name(self):
        """Scan matrix entries preserve container name."""
        config = {
            'containers': [
                {
                    'name': 'my-app',
                    'image': 'nginx:latest',
                    'scanners': ['trivy', 'grype']
                }
            ]
        }

        matrix = generate_scan_matrix(config)

        for entry in matrix['include']:
            assert entry['name'] == 'my-app'


class TestFixtureConfigs:
    """Tests using fixture configuration files."""

    def test_load_and_validate_container_config_fixture(self):
        """Load and validate the container config fixture."""
        config = load_config(str(FIXTURES_DIR / 'container-config.yml'))

        with open(SCHEMA_PATH, 'r') as f:
            schema = json.load(f)

        # Should not raise
        validate_config_structure(config, schema)
        assert len(config['containers']) >= 1

    def test_generate_matrix_from_container_config_fixture(self):
        """Generate matrix from container config fixture."""
        config = load_config(str(FIXTURES_DIR / 'container-config.yml'))
        matrix = generate_matrix(config)

        assert len(matrix['include']) == len(config['containers'])

    def test_load_and_validate_invalid_container_config_fixture(self):
        """Load invalid container config fixture."""
        config = load_config(str(FIXTURES_DIR / 'invalid-container-config.yml'))

        with open(SCHEMA_PATH, 'r') as f:
            schema = json.load(f)

        # Should raise validation error
        with pytest.raises(ValueError):
            validate_config_structure(config, schema)


class TestEdgeCases:
    """Tests for edge cases and special scenarios."""



    def test_very_long_container_name(self):
        """Very long container name."""
        long_name = 'a' * 100
        config = {
            'containers': [
                {
                    'name': long_name,
                    'image': 'nginx:latest'
                }
            ]
        }

        # Schema might reject (max 50 chars), but our validation allows it
        # Just verify it processes
        validate_config_structure(config, {})

    def test_multiple_scanners_with_defaults(self):
        """Multiple scanners work correctly with matrix generation."""
        config = {
            'containers': [
                {
                    'name': 'app',
                    'image': 'nginx:latest',
                    'scanners': ['trivy', 'grype']
                }
            ]
        }

        # Sequential matrix should have 1 entry with comma-separated scanners
        matrix = generate_matrix(config)
        assert len(matrix['include']) == 1
        assert matrix['include'][0]['scanners'] == 'trivy,grype'

        # Scan matrix should have 2 entries (one per scanner)
        scan_matrix = generate_scan_matrix(config)
        assert len(scan_matrix['include']) == 2
