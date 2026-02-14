#!/usr/bin/env python3
"""
Container Registry Config Parser (Composite Action Version)
Parses YAML, JSON config files and validates them.
Outputs matrix-compatible JSON for GitHub Actions

Environment variables:
    CONFIG_FILE  - Path to config file (required)
    SCHEMA_FILE  - Path to JSON schema (required)
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path

import yaml


def expand_env_vars(value: str) -> str:
    """
    Expand environment variables in a string.
    Supports ${VAR_NAME} syntax.
    """
    if not isinstance(value, str):
        return value

    def replace_var(match):
        var_name = match.group(1)
        return os.environ.get(var_name, match.group(0))

    return re.sub(r'\$\{([^}]+)\}', replace_var, value)


def expand_env_vars_in_object(obj):
    """
    Recursively expand environment variables in an object.
    """
    if isinstance(obj, str):
        return expand_env_vars(obj)
    elif isinstance(obj, list):
        return [expand_env_vars_in_object(item) for item in obj]
    elif isinstance(obj, dict):
        return {key: expand_env_vars_in_object(value) for key, value in obj.items()}
    else:
        return obj


def load_config(file_path: str) -> dict:
    """
    Load config file based on extension (YAML or JSON).
    """
    path = Path(file_path)
    ext = path.suffix.lower()

    with open(path, 'r', encoding='utf-8') as f:
        content = f.read()

    if ext in ('.yml', '.yaml'):
        return yaml.safe_load(content) or {}
    elif ext == '.json':
        return json.loads(content)
    else:
        raise ValueError(f"Unsupported config file type: {ext}. Use .yml, .yaml, or .json")


def validate_config_structure(config: dict, schema: dict) -> None:
    """
    Validate config structure against schema using simple dict checks.
    Avoids jsonschema dependency as per requirements.
    """
    # Check required top-level field
    if 'containers' not in config:
        raise ValueError("Config validation failed:\n  - containers: required field missing")

    containers = config['containers']

    # Check containers is an array
    if not isinstance(containers, list):
        raise ValueError("Config validation failed:\n  - containers: must be an array")

    # Check minimum items
    if len(containers) < 1:
        raise ValueError("Config validation failed:\n  - containers: must have at least 1 item")

    errors = []
    seen_names = {}

    for i, container in enumerate(containers):
        if not isinstance(container, dict):
            errors.append(f"containers[{i}]: must be an object")
            continue

        # Check required fields
        if 'name' not in container:
            errors.append(f"containers[{i}].name: required field missing")
        else:
            name = container['name']
            if not isinstance(name, str):
                errors.append(f"containers[{i}].name: must be a string")
            elif not re.match(r'^[a-zA-Z0-9_-]+$', name):
                errors.append(f"containers[{i}].name: invalid format (must match ^[a-zA-Z0-9_-]+$)")
            else:
                # Check for duplicate names
                if name in seen_names:
                    errors.append(f"containers: Duplicate container names found: {name}")
                else:
                    seen_names[name] = True

        if 'image' not in container:
            errors.append(f"containers[{i}].image: required field missing")
        else:
            image = container['image']
            if isinstance(image, dict):
                if 'name' not in image:
                    errors.append(f"containers[{i}].image.name: required field missing")

        # Validate optional scanners
        if 'scanners' in container:
            scanners = container['scanners']
            if isinstance(scanners, list):
                valid_scanners = {'trivy', 'grype', 'syft'}
                for scanner in scanners:
                    if scanner not in valid_scanners:
                        errors.append(f"containers[{i}].scanners: '{scanner}' is not valid")

        # Validate optional fail_on_severity
        if 'fail_on_severity' in container:
            severity = container['fail_on_severity']
            valid_severities = {'low', 'medium', 'high', 'critical', 'none'}
            if severity not in valid_severities:
                errors.append(f"containers[{i}].fail_on_severity: '{severity}' is not valid")

    if errors:
        raise ValueError("Config validation failed:\n  - " + "\n  - ".join(errors))


def build_image_reference(image, registry_host: str = 'docker.io') -> str:
    """
    Convert structured image format to string.
    Supports both simple string format and structured object format.
    """
    # If image is already a string, return as-is
    if isinstance(image, str):
        return image

    # If image is a structured object, build the reference
    if isinstance(image, dict):
        registry = registry_host or 'docker.io'
        repository = f"{image.get('repository', '')}/" if image.get('repository') else ''
        name = image.get('name', '')
        tag = image.get('tag', 'latest')
        digest = f"@{image.get('digest')}" if image.get('digest') else ''

        # Construct: registry/repository/name:tag@digest
        reference = f"{registry}/{repository}{name}:{tag}{digest}"

        # Clean up double slashes
        reference = re.sub(r'([^:])\/\/+', r'\1/', reference)

        return reference

    return image


def generate_matrix(config: dict) -> dict:
    """
    Generate matrix from validated config.
    Creates one matrix entry per container (scanners run sequentially).
    """
    matrix = {'include': []}

    for container in config['containers']:
        scanners = container.get('scanners', ['trivy'])
        image_ref = build_image_reference(
            container['image'],
            container.get('registry', {}).get('host')
        )

        entry = {
            'name': container['name'],
            'scanners': ','.join(scanners),
            'image': image_ref,
            'fail_on_severity': container.get('fail_on_severity', 'high'),
            'allow_failure': container.get('allow_failure', False),
            'enable_code_security': container.get('enable_code_security', False),
            'post_pr_comment': container.get('post_pr_comment', False),
            'registry_username': container.get('registry', {}).get('username', ''),
            'registry_auth_secret': container.get('registry', {}).get('auth_secret', '')
        }

        matrix['include'].append(entry)

    return matrix


def generate_scan_matrix(config: dict) -> dict:
    """
    Generate scan matrix from validated config.
    Creates one matrix entry per container+scanner combination (for parallel scanning).
    """
    matrix = {'include': []}

    for container in config['containers']:
        scanners = container.get('scanners', ['trivy'])
        image_ref = build_image_reference(
            container['image'],
            container.get('registry', {}).get('host')
        )

        # Create one entry per scanner for this container
        for scanner in scanners:
            entry = {
                'name': container['name'],
                'scanner': scanner,
                'image': image_ref,
                'fail_on_severity': container.get('fail_on_severity', 'high'),
                'allow_failure': container.get('allow_failure', False),
                'enable_code_security': container.get('enable_code_security', False),
                'registry_username': container.get('registry', {}).get('username', ''),
                'registry_auth_secret': container.get('registry', {}).get('auth_secret', '')
            }

            matrix['include'].append(entry)

    return matrix


def main():
    """Main execution."""
    config_file = os.environ.get('CONFIG_FILE')
    schema_file = os.environ.get('SCHEMA_FILE')

    if not config_file:
        print("Error: CONFIG_FILE environment variable is required", file=sys.stderr)
        sys.exit(1)

    if not schema_file:
        print("Error: SCHEMA_FILE environment variable is required", file=sys.stderr)
        sys.exit(1)

    try:
        print(f"📦 Loading config from: {config_file}")
        config = load_config(config_file)

        print("🔧 Expanding environment variables...")
        config = expand_env_vars_in_object(config)

        print(f"📋 Loading schema from: {schema_file}")
        with open(schema_file, 'r', encoding='utf-8') as f:
            schema = json.load(f)

        print("✓ Validating config against schema...")
        validate_config_structure(config, schema)
        print("✅ Config validation passed")

        print("🔄 Generating matrices...")

        # Sequential matrix (one entry per container)
        matrix = generate_matrix(config)
        print(f"✅ Generated {len(matrix['include'])} container entries (sequential)")

        # Parallel scan matrix (one entry per container+scanner)
        scan_matrix = generate_scan_matrix(config)
        print(f"✅ Generated {len(scan_matrix['include'])} scan entries (parallel)")

        # Output matrices for GitHub Actions
        matrix_json = json.dumps(matrix)
        scan_matrix_json = json.dumps(scan_matrix)

        # Log matrix entries for visibility
        print("\nSequential matrix (matrix):")
        for i, entry in enumerate(matrix['include']):
            print(f"  [{i + 1}] {entry['name']}: {entry['image']} (scanners: {entry['scanners']})")

        print("\nParallel matrix (scan_matrix):")
        for i, entry in enumerate(scan_matrix['include']):
            print(f"  [{i + 1}] {entry['name']} + {entry['scanner']}: {entry['image']}")

        # Set GitHub Actions output
        github_output = os.environ.get('GITHUB_OUTPUT')
        if github_output:
            with open(github_output, 'a', encoding='utf-8') as f:
                f.write(f"matrix={matrix_json}\n")
                f.write(f"scan_matrix={scan_matrix_json}\n")
            print("\n✅ Matrix outputs set for GitHub Actions")
        else:
            # Print matrix if not in GitHub Actions (for local testing)
            print("\nMatrix JSON:")
            print(matrix_json)
            print("\nScan Matrix JSON:")
            print(scan_matrix_json)

        sys.exit(0)

    except Exception as error:
        print(f"\n❌ Error: {error}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
