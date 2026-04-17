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
    expand_env_vars_in_object,
)
from sanitize_name import sanitize_container_name

# Paths for fixtures
REPO_ROOT = Path(__file__).parent.parent.parent.parent.parent
FIXTURES_DIR = REPO_ROOT / 'tests' / 'fixtures' / 'configs'
SCHEMA_PATH = REPO_ROOT / '.github' / 'actions' / 'parse-container-config' / 'schemas' / 'container-config.schema.json'


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


class TestSanitizeContainerName:
    """
    Tests for container name sanitization.
    Goal: Every container gets scanned regardless of input name.
    Output must match: ^[a-zA-Z0-9_][a-zA-Z0-9_-]{0,49}$
    """

    # (input, expected) - slugify transliterates unicode (ä→a) rather than stripping
    SANITIZE_TEST_CASES = [
        # Valid characters preserved
        ("myapp", "myapp"),                     # lowercase alphanumeric
        ("MyApp", "MyApp"),                     # uppercase preserved
        ("myApp123", "myApp123"),               # mixed case with numbers
        ("my-app", "my-app"),                   # hyphens preserved
        ("my_app", "my_app"),                   # underscores preserved
        ("app123", "app123"),                   # numbers preserved
        ("_app", "_app"),                       # leading underscore valid

        # Dot replacement
        ("my.app", "my-app"),                   # single dot to hyphen
        ("my.app.service", "my-app-service"),   # multiple dots to hyphens
        (".myapp", "myapp"),                    # leading dot stripped
        ("myapp.", "myapp"),                    # trailing dot stripped
        (".devcontainer", "devcontainer"),      # .devcontainer directory
        ("my.app.v2.0", "my-app-v2-0"),         # version-style dots

        # Special characters become hyphens then collapse
        ("my!app", "my-app"),                   # exclamation
        ("my@app", "my-app"),                   # at sign
        ("my#app", "my-app"),                   # hash
        ("my$app", "my-app"),                   # dollar
        ("my%app", "my-app"),                   # percent
        ("my^app", "my-app"),                   # caret
        ("my&app", "my-app"),                   # ampersand
        ("my*app", "my-app"),                   # asterisk
        ("my+app", "my-app"),                   # plus
        ("my=app", "my-app"),                   # equals
        ("my~app", "my-app"),                   # tilde
        ("my`app", "my-app"),                   # backtick
        ("my(app)", "my-app"),                  # parentheses
        ("my[app]", "my-app"),                  # brackets
        ("my{app}", "my-app"),                  # braces
        ("my<app>", "my-app"),                  # angle brackets
        ("my'app", "my-app"),                   # single quote
        ('my"app', "my-app"),                   # double quote
        ("my/app", "my-app"),                   # forward slash
        ("my\\app", "my-app"),                  # backslash
        ("my|app", "my-app"),                   # pipe
        ("my:app", "my-app"),                   # colon
        ("my;app", "my-app"),                   # semicolon
        ("my?app", "my-app"),                   # question mark
        ("my,app", "my-app"),                   # comma

        # Whitespace becomes hyphen
        ("my app", "my-app"),                   # space
        ("my\tapp", "my-app"),                  # tab
        ("my\napp", "my-app"),                  # newline
        ("my  app", "my-app"),                  # multiple spaces collapse

        # Unicode transliterated
        ("myäpp", "myapp"),                     # ä → a
        ("café", "cafe"),                       # é → e
        ("my🚀app", "myapp"),                   # emoji stripped
        ("naïve", "naive"),                     # ï → i

        # Edge cases with fallback
        ("", "container"),                      # empty string
        (None, "container"),                    # None input
        ("...", "container"),                   # only dots
        ("@#$%", "container"),                  # only special chars
        ("   ", "container"),                   # only spaces
        ("my..app", "my-app"),                  # consecutive dots collapse

        # Hyphen handling
        ("-app", "app"),                        # leading hyphen stripped
        ("app-", "app"),                        # trailing hyphen stripped
        ("---app", "app"),                      # multiple leading hyphens
        ("app---", "app"),                      # multiple trailing hyphens
        ("my.@app!service#1", "my-app-service-1"),  # mixed special chars

        # Length handling
        ("a" * 50, "a" * 50),                   # exactly 50 chars preserved
        ("a" * 60, "a" * 50),                   # over 50 chars truncated
        ("a" * 49 + "-bbb", "a" * 49),          # truncation strips trailing hyphen
    ]

    @pytest.mark.parametrize("input_name,expected", SANITIZE_TEST_CASES)
    def test_sanitize_cases(self, input_name, expected):
        """Parametrized sanitization tests."""
        assert sanitize_container_name(input_name) == expected

    def test_custom_fallback(self):
        """Custom fallback name can be specified."""
        assert sanitize_container_name("@#$", fallback="unknown") == "unknown"

    def test_all_outputs_match_validation_regex(self):
        """All sanitized outputs must match combined Docker + schema regex."""
        import re
        # Combined regex: first char alphanumeric/underscore (no hyphen), max 50 chars total
        pattern = re.compile(r'^[a-zA-Z0-9_][a-zA-Z0-9_-]{0,49}$')
        for input_name, _ in self.SANITIZE_TEST_CASES:
            result = sanitize_container_name(input_name)
            assert pattern.match(result), f"'{input_name}' -> '{result}' doesn't match regex"


class TestMatrixSanitization:
    """Tests that matrix generation applies sanitization correctly."""

    def test_generate_matrix_sanitizes_names(self):
        """Matrix generation sanitizes container names by default."""
        config = {
            'containers': [
                {'name': 'my.app', 'image': 'nginx:latest'}
            ]
        }
        matrix = generate_matrix(config)
        assert matrix['include'][0]['name'] == 'my-app'

    def test_generate_matrix_sanitization_can_be_disabled(self):
        """Matrix generation sanitization can be disabled."""
        config = {
            'containers': [
                {'name': 'my-app', 'image': 'nginx:latest'}
            ]
        }
        matrix = generate_matrix(config, sanitize_names=False)
        assert matrix['include'][0]['name'] == 'my-app'

    def test_generate_scan_matrix_sanitizes_names(self):
        """Scan matrix generation sanitizes container names by default."""
        config = {
            'containers': [
                {'name': 'my.app', 'image': 'nginx:latest', 'scanners': ['trivy']}
            ]
        }
        matrix = generate_scan_matrix(config)
        assert matrix['include'][0]['name'] == 'my-app'

    def test_generate_scan_matrix_sanitization_can_be_disabled(self):
        """Scan matrix generation sanitization can be disabled."""
        config = {
            'containers': [
                {'name': 'my-app', 'image': 'nginx:latest', 'scanners': ['trivy']}
            ]
        }
        matrix = generate_scan_matrix(config, sanitize_names=False)
        assert matrix['include'][0]['name'] == 'my-app'

    # Collision handling - names that sanitize to the same value get suffixes
    COLLISION_TEST_CASES = [
        # (container_names, expected_sanitized_names)
        (["my.app", "my@app"], ["my-app", "my-app-2"]),              # two collisions
        (["my.app", "my@app", "my#app"], ["my-app", "my-app-2", "my-app-3"]),  # three
        (["app", "app"], ["app", "app-2"]),                          # exact duplicates
        (["my.app", "other", "my@app"], ["my-app", "other", "my-app-2"]),  # non-adjacent
        (["a.b", "a@b", "a#b", "a$b"], ["a-b", "a-b-2", "a-b-3", "a-b-4"]),  # four collisions
        # 50-char names truncated to fit suffix
        (["a" * 50, "a" * 50, "a" * 50], ["a" * 50, "a" * 48 + "-2", "a" * 48 + "-3"]),
    ]

    @pytest.mark.parametrize("input_names,expected_names", COLLISION_TEST_CASES)
    def test_generate_matrix_handles_collisions(self, input_names, expected_names):
        """Matrix generation adds suffixes for sanitized name collisions."""
        config = {
            'containers': [
                {'name': name, 'image': f'{name}:latest'}
                for name in input_names
            ]
        }
        matrix = generate_matrix(config)
        actual_names = [entry['name'] for entry in matrix['include']]
        assert actual_names == expected_names

    @pytest.mark.parametrize("input_names,expected_names", COLLISION_TEST_CASES)
    def test_generate_scan_matrix_handles_collisions(self, input_names, expected_names):
        """Scan matrix generation adds suffixes for sanitized name collisions."""
        config = {
            'containers': [
                {'name': name, 'image': f'{name}:latest', 'scanners': ['trivy']}
                for name in input_names
            ]
        }
        matrix = generate_scan_matrix(config)
        actual_names = [entry['name'] for entry in matrix['include']]
        assert actual_names == expected_names


class TestSanitizeNamesCLI:
    """Tests for sanitize_names() function and CLI entrypoint."""

    # (input_list, kwargs, expected_output)
    SANITIZE_NAMES_CASES = [
        (["my.app", "my@app", "other"], {}, ["my-app", "my-app-2", "other"]),
        ([], {}, []),
        (["@#$", "..."], {"fallback": "unknown"}, ["unknown", "unknown-2"]),
    ]

    @pytest.mark.parametrize("input_list,kwargs,expected", SANITIZE_NAMES_CASES)
    def test_sanitize_names_function(self, input_list, kwargs, expected):
        """sanitize_names() handles lists with collision detection."""
        from sanitize_name import sanitize_names
        assert sanitize_names(input_list, **kwargs) == expected

    # (argv, expected_output)
    CLI_SUCCESS_CASES = [
        (['sanitize_name.py', 'my.app'], "my-app"),
        (['sanitize_name.py', '--list', 'my.app', 'my@app'], "my-app my-app-2"),
        (['sanitize_name.py', '--fallback', 'unknown', '@#$'], "unknown"),
    ]

    @pytest.mark.parametrize("argv,expected", CLI_SUCCESS_CASES)
    def test_cli_success(self, argv, expected, capsys, monkeypatch):
        """CLI produces correct output for valid inputs."""
        import sanitize_name
        monkeypatch.setattr('sys.argv', argv)
        sanitize_name.main()
        assert capsys.readouterr().out.strip() == expected

    # (argv) - all should exit with code 1
    CLI_ERROR_CASES = [
        (['sanitize_name.py'],),  # no args
        (['sanitize_name.py', '--list'],),  # --list with no names
    ]

    @pytest.mark.parametrize("argv", CLI_ERROR_CASES)
    def test_cli_errors(self, argv, monkeypatch):
        """CLI exits with code 1 for invalid inputs."""
        import sanitize_name
        monkeypatch.setattr('sys.argv', argv)
        with pytest.raises(SystemExit) as exc_info:
            sanitize_name.main()
        assert exc_info.value.code == 1
