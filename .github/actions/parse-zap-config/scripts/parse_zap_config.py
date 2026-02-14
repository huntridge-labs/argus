#!/usr/bin/env python3
"""
ZAP DAST Config Parser
Parses YAML, JSON config files and validates them.
Outputs matrix-compatible JSON for GitHub Actions

Supports two config styles:
1. Flat: `scans` array with optional root `target`
2. Grouped: `scan_groups` array, each with their own `target` and `scans`
"""

import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


def expand_env_vars(value: str, preserve_secrets: bool = False) -> str:
    """
    Expand environment variables in a string.
    Supports ${VAR_NAME} syntax.
    """
    if not isinstance(value, str):
        return value

    def replace_var(match):
        var_name = match.group(1)
        if preserve_secrets:
            return var_name
        return os.environ.get(var_name, match.group(0))

    return re.sub(r'\$\{([^}]+)\}', replace_var, value)


def expand_env_vars_in_object(obj: Any, skip_secret_fields: bool = True) -> Any:
    """
    Recursively expand environment variables in an object.
    Skip auth_secret and header_secret fields (those are secret names, not values).
    """
    if isinstance(obj, str):
        return expand_env_vars(obj, False)
    elif isinstance(obj, list):
        return [expand_env_vars_in_object(item, skip_secret_fields) for item in obj]
    elif isinstance(obj, dict):
        result = {}
        for key, value in obj.items():
            # Don't expand secret field names - they're references, not values
            if skip_secret_fields and key in ('auth_secret', 'header_secret'):
                result[key] = value
            else:
                result[key] = expand_env_vars_in_object(value, skip_secret_fields)
        return result
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
    Validate config structure using simple dict checks.
    Avoids jsonschema dependency as per requirements.
    """
    errors = []

    # Check that config has either 'scans' or 'scan_groups'
    if 'scans' not in config and 'scan_groups' not in config:
        errors.append("Config must have either 'scans' or 'scan_groups'")

    # Validate flat config style (scans array)
    if 'scans' in config:
        scans = config['scans']
        if not isinstance(scans, list):
            errors.append("scans: must be an array")
        else:
            for i, scan in enumerate(scans):
                if not isinstance(scan, dict):
                    errors.append(f"scans[{i}]: must be an object")
                    continue

                if 'name' not in scan:
                    errors.append(f"scans[{i}].name: required field missing")
                elif not isinstance(scan['name'], str):
                    errors.append(f"scans[{i}].name: must be a string")

                if 'type' not in scan:
                    errors.append(f"scans[{i}].type: required field missing")
                elif scan['type'] not in ('baseline', 'full', 'api'):
                    errors.append(f"scans[{i}].type: must be one of (baseline, full, api)")

    # Validate grouped config style (scan_groups array)
    if 'scan_groups' in config:
        groups = config['scan_groups']
        if not isinstance(groups, list):
            errors.append("scan_groups: must be an array")
        else:
            for gi, group in enumerate(groups):
                if not isinstance(group, dict):
                    errors.append(f"scan_groups[{gi}]: must be an object")
                    continue

                if 'name' not in group:
                    errors.append(f"scan_groups[{gi}].name: required field missing")

                if 'scans' not in group:
                    errors.append(f"scan_groups[{gi}].scans: required field missing")
                else:
                    scans = group['scans']
                    if not isinstance(scans, list):
                        errors.append(f"scan_groups[{gi}].scans: must be an array")
                    else:
                        for si, scan in enumerate(scans):
                            if not isinstance(scan, dict):
                                errors.append(f"scan_groups[{gi}].scans[{si}]: must be an object")
                                continue

                            if 'name' not in scan:
                                errors.append(f"scan_groups[{gi}].scans[{si}].name: required field missing")

                            if 'type' not in scan:
                                errors.append(f"scan_groups[{gi}].scans[{si}].type: required field missing")
                            elif scan['type'] not in ('baseline', 'full', 'api'):
                                errors.append(
                                    f"scan_groups[{gi}].scans[{si}].type: must be one of (baseline, full, api)"
                                )

    # Check for duplicate scan names across all scans
    all_scan_names = []
    if 'scans' in config and isinstance(config['scans'], list):
        all_scan_names.extend([s.get('name') for s in config['scans'] if isinstance(s, dict)])

    if 'scan_groups' in config and isinstance(config['scan_groups'], list):
        for group in config['scan_groups']:
            if isinstance(group, dict) and 'scans' in group:
                all_scan_names.extend([s.get('name') for s in group['scans'] if isinstance(s, dict)])

    # Check for duplicates
    seen = {}
    duplicates = []
    for name in all_scan_names:
        if name in seen:
            if name not in duplicates:
                duplicates.append(name)
        else:
            seen[name] = True

    if duplicates:
        errors.append(f"scans: Duplicate scan names found: {', '.join(duplicates)}")

    if errors:
        raise ValueError("Config validation failed:\n  - " + "\n  - ".join(errors))


def build_image_reference(image: Any) -> str:
    """
    Build container image reference from structured format.
    """
    if isinstance(image, str):
        return image

    if isinstance(image, dict):
        registry = image.get('registry', '')
        repository = f"{image.get('repository', '')}/" if image.get('repository') else ''
        name = image.get('name', '')
        tag = image.get('tag', 'latest')
        digest = f"@{image.get('digest')}" if image.get('digest') else ''

        reference = ''
        if registry:
            reference = f"{registry}/{repository}{name}:{tag}{digest}"
        else:
            reference = f"{repository}{name}:{tag}{digest}"

        # Clean up double slashes
        reference = re.sub(r'([^:])\/\/+', r'\1/', reference)
        return reference

    return image


def normalize_ports(ports: Any) -> List[str]:
    """
    Convert ports to normalized array format.
    """
    if not ports:
        return ['8080:8080']

    if isinstance(ports, str):
        return [p.strip() for p in ports.split(',') if p.strip()]

    if isinstance(ports, list):
        return [str(p).strip() for p in ports if str(p).strip()]

    return ['8080:8080']


def build_target_config(target: Optional[Dict]) -> Dict[str, Any]:
    """
    Build target configuration object with defaults.
    """
    if target is None:
        target = {}

    return {
        'mode': target.get('mode', 'url'),
        'image': build_image_reference(target.get('image', '')),
        'ports': ','.join(normalize_ports(target.get('ports'))),
        'build_context': target.get('build', {}).get('context', '') if isinstance(target.get('build'), dict) else '',
        'build_dockerfile': target.get('build', {}).get('dockerfile', '') if isinstance(target.get('build'), dict) else '',
        'build_tag': target.get('build', {}).get('tag', '') if isinstance(target.get('build'), dict) else '',
        'compose_file': target.get('compose_file', 'docker-compose.yml'),
        'compose_build': target.get('compose_build', True) is not False,
        'registry_host': target.get('registry', {}).get('host', '') if isinstance(target.get('registry'), dict) else '',
        'registry_username': target.get('registry', {}).get('username', '') if isinstance(target.get('registry'), dict) else '',
        'registry_auth_secret': target.get('registry', {}).get('auth_secret', '') if isinstance(target.get('registry'), dict) else '',
        'healthcheck_url': target.get('healthcheck_url', '')
    }


def generate_scan_entry(
    scan: Dict,
    defaults: Dict,
    target_config: Dict,
    root_config: Dict
) -> Dict[str, Any]:
    """
    Generate scan entry with defaults applied.
    """
    # Merge auth from defaults and scan-specific (scan takes precedence)
    merged_auth = {**(defaults.get('auth', {})), **(scan.get('auth', {}))}

    # post_pr_comment priority: scan-level > defaults > root > false
    post_pr_comment = (
        scan.get('post_pr_comment')
        if 'post_pr_comment' in scan
        else (
            defaults.get('post_pr_comment')
            if 'post_pr_comment' in defaults
            else root_config.get('post_pr_comment', False)
        )
    )

    return {
        # Scan identification
        'name': scan['name'],
        'scan_type': scan['type'],

        # Scan-specific settings (with defaults fallback)
        'target_url': scan.get('target_url') or defaults.get('target_url', ''),
        'api_spec': scan.get('api_spec') or defaults.get('api_spec', ''),
        'healthcheck_url': scan.get('healthcheck_url') or defaults.get('healthcheck_url') or target_config['healthcheck_url'],
        'max_duration_minutes': scan.get('max_duration_minutes') or defaults.get('max_duration_minutes', 10),
        'rules_file': scan.get('rules_file') or defaults.get('rules_file', ''),
        'context_file': scan.get('context_file') or defaults.get('context_file', ''),
        'cmd_options': scan.get('cmd_options') or defaults.get('cmd_options', ''),

        # Failure handling
        'fail_on_severity': scan.get('fail_on_severity') or defaults.get('fail_on_severity', 'none'),
        'allow_failure': scan.get('allow_failure') if 'allow_failure' in scan else defaults.get('allow_failure', False),

        # PR comment preference (per-scan)
        'post_pr_comment': post_pr_comment,

        # Authentication
        'auth_header_name': merged_auth.get('header_name', ''),
        'auth_header_value': merged_auth.get('header_value', ''),
        'auth_header_secret': merged_auth.get('header_secret', ''),
        'auth_header_site': merged_auth.get('site', ''),

        # Target settings
        **target_config
    }


def generate_matrices(config: Dict) -> Dict[str, List]:
    """
    Generate matrices from validated config.
    Returns an object with group names as keys and matrices as values.
    """
    root_defaults = config.get('defaults', {})
    root_target = build_target_config(config.get('target'))

    # Flat config style: single matrix
    if 'scans' in config:
        matrix = {'include': []}
        for scan in config['scans']:
            matrix['include'].append(
                generate_scan_entry(scan, root_defaults, root_target, config)
            )

        return {
            'groups': [
                {
                    'name': 'default',
                    'description': 'ZAP Scans',
                    'matrix': matrix,
                    'target': root_target
                }
            ]
        }

    # Grouped config style: one matrix per group
    if 'scan_groups' in config:
        groups = []
        for group in config['scan_groups']:
            # Merge group target with root target (group takes precedence)
            group_target_data = {**config.get('target', {}), **(group.get('target', {}))}
            group_target = build_target_config(group_target_data)

            # Merge group defaults with root defaults (group takes precedence)
            group_defaults = {**root_defaults, **(group.get('defaults', {}))}

            matrix = {'include': []}
            for scan in group.get('scans', []):
                matrix['include'].append(
                    generate_scan_entry(scan, group_defaults, group_target, config)
                )

            groups.append({
                'name': group['name'],
                'description': group.get('description', group['name']),
                'matrix': matrix,
                'target': group_target
            })

        return {'groups': groups}

    raise ValueError('Config must have either "scans" or "scan_groups"')


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
        print(f"Loading config from: {config_file}")
        config = load_config(config_file)

        print("Expanding environment variables...")
        config = expand_env_vars_in_object(config)
        print("Environment variables expanded")

        print(f"Loading schema from: {schema_file}")
        with open(schema_file, 'r', encoding='utf-8') as f:
            schema = json.load(f)

        print("Validating config against schema...")
        validate_config_structure(config, schema)
        print("Config validation passed")

        print("Generating matrices...")
        result = generate_matrices(config)
        print(f"Generated {len(result['groups'])} group(s)")

        # Output for GitHub Actions
        groups_json = json.dumps([
            {
                'name': g['name'],
                'description': g['description'],
                'mode': g['target']['mode']
            }
            for g in result['groups']
        ])

        print("\nGroups JSON:")
        print(groups_json)

        for group in result['groups']:
            print(f"\nMatrix for {group['name']}:")
            print(json.dumps(group['matrix']))

        # Set GitHub Actions output
        github_output = os.environ.get('GITHUB_OUTPUT')
        if github_output:
            # Combine all groups into a single matrix for workflow consumption
            # Add group metadata to each scan entry
            combined_matrix = {'include': []}
            for group in result['groups']:
                for scan in group['matrix']['include']:
                    combined_matrix['include'].append({
                        **scan,
                        'group_name': group['name'],
                        'group_description': group['description']
                    })

            outputs = [
                f"matrix={json.dumps(combined_matrix)}",
                f"groups={groups_json}",
                f"group_count={len(result['groups'])}",
                f"has_scans={'true' if any(g['matrix']['include'] for g in result['groups']) else 'false'}",
                f"total_scan_count={sum(len(g['matrix']['include']) for g in result['groups'])}",
                f"post_pr_comment={'true' if any(s.get('post_pr_comment') for g in result['groups'] for s in g['matrix']['include']) else 'false'}",
                f"enable_code_security={'true' if config.get('enable_code_security') else 'false'}"
            ]

            # Output each group's matrix and target settings (for advanced use)
            for index, group in enumerate(result['groups']):
                outputs.append(f"group_{index}_matrix={json.dumps(group['matrix'])}")
                outputs.append(f"group_{index}_name={group['name']}")
                outputs.append(f"group_{index}_description={group['description']}")
                outputs.append(f"group_{index}_mode={group['target']['mode']}")
                outputs.append(f"group_{index}_image={group['target']['image']}")
                outputs.append(f"group_{index}_ports={group['target']['ports']}")
                outputs.append(f"group_{index}_scan_count={len(group['matrix']['include'])}")

            with open(github_output, 'a', encoding='utf-8') as f:
                for output in outputs:
                    f.write(f"{output}\n")

            print("\nOutputs set for GitHub Actions")

        # Print summary
        print("\n--- Configuration Summary ---")
        print(f"Config style: {'grouped' if 'scan_groups' in config else 'flat'}")
        print(f"Total groups: {len(result['groups'])}")
        for group in result['groups']:
            print(f"\n  Group: {group['name']}")
            print(f"    Mode: {group['target']['mode']}")
            if group['target']['image']:
                print(f"    Image: {group['target']['image']}")
            print(f"    Scans: {len(group['matrix']['include'])}")
            for scan in group['matrix']['include']:
                target = scan.get('api_spec', scan.get('target_url', ''))
                print(f"      - {scan['name']}: {scan['scan_type']} -> {target}")

        sys.exit(0)

    except Exception as error:
        print(f"\nError: {error}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
