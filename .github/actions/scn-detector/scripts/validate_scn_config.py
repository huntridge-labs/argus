#!/usr/bin/env python3
"""
SCN Config Validator

Validates SCN configuration files against expected structure.
Uses manual dict-based checks (no jsonschema dependency).

Importable as a module and runnable as a standalone script.

Environment variables (standalone mode):
    CONFIG_FILE     - Path to SCN config file (required)
    SCHEMA_FILE     - Path to JSON schema file (required)
    AI_CONFIG_FILE  - Path to standalone AI config file (optional)
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict, List

import yaml


VALID_CATEGORIES = {'routine', 'adaptive', 'transformative', 'impact'}
VALID_IMPACT_LEVELS = {'Low', 'Moderate', 'High'}
VALID_AI_PROVIDERS = {'anthropic', 'openai'}


def _validate_rules(rules, errors: List[str]) -> None:
    """Validate the rules section of the config."""
    if not isinstance(rules, dict):
        errors.append('rules: must be a mapping')
        return

    if not rules:
        errors.append('rules: must contain at least one category (routine, adaptive, transformative, impact)')
        return

    for key in rules:
        if key not in VALID_CATEGORIES:
            errors.append(f'rules: unknown category "{key}" (valid: {", ".join(sorted(VALID_CATEGORIES))})')

    for category in VALID_CATEGORIES:
        if category not in rules:
            continue

        category_rules = rules[category]
        if not isinstance(category_rules, list):
            errors.append(f'rules.{category}: must be an array')
            continue

        if len(category_rules) == 0:
            errors.append(f'rules.{category}: must have at least 1 rule')
            continue

        for i, rule in enumerate(category_rules):
            _validate_rule(rule, f'rules.{category}[{i}]', errors)


def _validate_rule(rule, path: str, errors: List[str]) -> None:
    """Validate a single classification rule."""
    if not isinstance(rule, dict):
        errors.append(f'{path}: must be an object')
        return

    if 'description' not in rule:
        errors.append(f'{path}.description: required field missing')
    elif not isinstance(rule['description'], str):
        errors.append(f'{path}.description: must be a string')

    has_criterion = any(key in rule for key in ('pattern', 'resource', 'attribute'))
    if not has_criterion:
        errors.append(f'{path}: must have at least one of pattern, resource, or attribute')

    for field in ('pattern', 'resource', 'attribute', 'operation'):
        if field in rule and not isinstance(rule[field], str):
            errors.append(f'{path}.{field}: must be a string')


def _validate_ai_fields(config: Dict, prefix: str, errors: List[str]) -> None:
    """Validate AI configuration fields (shared between profile ai_fallback and standalone AI config)."""
    if not isinstance(config, dict):
        errors.append(f'{prefix}: must be a mapping')
        return

    if 'enabled' in config and not isinstance(config['enabled'], bool):
        errors.append(f'{prefix}.enabled: must be a boolean')

    if 'provider' in config:
        if not isinstance(config['provider'], str):
            errors.append(f'{prefix}.provider: must be a string')
        elif config['provider'] not in VALID_AI_PROVIDERS:
            errors.append(
                f'{prefix}.provider: "{config["provider"]}" is not valid '
                f'(valid: {", ".join(sorted(VALID_AI_PROVIDERS))})'
            )

    if 'model' in config and not isinstance(config['model'], str):
        errors.append(f'{prefix}.model: must be a string')

    if 'confidence_threshold' in config:
        ct = config['confidence_threshold']
        if not isinstance(ct, (int, float)):
            errors.append(f'{prefix}.confidence_threshold: must be a number')
        elif ct < 0.0 or ct > 1.0:
            errors.append(f'{prefix}.confidence_threshold: must be between 0.0 and 1.0')

    if 'max_tokens' in config:
        mt = config['max_tokens']
        if not isinstance(mt, int):
            errors.append(f'{prefix}.max_tokens: must be an integer')
        elif mt < 1:
            errors.append(f'{prefix}.max_tokens: must be >= 1')

    if 'max_diff_chars' in config:
        mdc = config['max_diff_chars']
        if not isinstance(mdc, int):
            errors.append(f'{prefix}.max_diff_chars: must be an integer')
        elif mdc < 1:
            errors.append(f'{prefix}.max_diff_chars: must be >= 1')

    for field in ('api_base_url', 'system_prompt', 'user_prompt_template'):
        if field in config and not isinstance(config[field], str):
            errors.append(f'{prefix}.{field}: must be a string')


def _validate_notifications(notifications, errors: List[str]) -> None:
    """Validate the notifications section."""
    if not isinstance(notifications, dict):
        errors.append('notifications: must be a mapping')
        return

    valid_keys = {'adaptive', 'transformative', 'impact'}
    for key in notifications:
        if key not in valid_keys:
            errors.append(f'notifications: unknown key "{key}" (valid: {", ".join(sorted(valid_keys))})')

    if 'adaptive' in notifications:
        adaptive = notifications['adaptive']
        if isinstance(adaptive, dict):
            if 'post_completion_days' in adaptive and not isinstance(adaptive['post_completion_days'], int):
                errors.append('notifications.adaptive.post_completion_days: must be an integer')
            if 'description' in adaptive and not isinstance(adaptive['description'], str):
                errors.append('notifications.adaptive.description: must be a string')
        elif adaptive is not None:
            errors.append('notifications.adaptive: must be a mapping')

    if 'transformative' in notifications:
        transformative = notifications['transformative']
        if isinstance(transformative, dict):
            for field in ('initial_notice_days', 'final_notice_days'):
                if field in transformative and not isinstance(transformative[field], int):
                    errors.append(f'notifications.transformative.{field}: must be an integer')
            if 'post_completion_required' in transformative and not isinstance(transformative['post_completion_required'], bool):
                errors.append('notifications.transformative.post_completion_required: must be a boolean')
            if 'description' in transformative and not isinstance(transformative['description'], str):
                errors.append('notifications.transformative.description: must be a string')
        elif transformative is not None:
            errors.append('notifications.transformative: must be a mapping')

    if 'impact' in notifications:
        impact = notifications['impact']
        if isinstance(impact, dict):
            if 'requires_new_assessment' in impact and not isinstance(impact['requires_new_assessment'], bool):
                errors.append('notifications.impact.requires_new_assessment: must be a boolean')
            if 'description' in impact and not isinstance(impact['description'], str):
                errors.append('notifications.impact.description: must be a string')
        elif impact is not None:
            errors.append('notifications.impact: must be a mapping')


def _validate_issue_templates(templates, errors: List[str]) -> None:
    """Validate the issue_templates section."""
    if not isinstance(templates, dict):
        errors.append('issue_templates: must be a mapping')
        return

    if 'labels' in templates:
        labels = templates['labels']
        if isinstance(labels, dict):
            if 'prefix' in labels and not isinstance(labels['prefix'], str):
                errors.append('issue_templates.labels.prefix: must be a string')
            if 'categories' in labels:
                cats = labels['categories']
                if isinstance(cats, dict):
                    for key, val in cats.items():
                        if not isinstance(val, str):
                            errors.append(f'issue_templates.labels.categories.{key}: must be a string')
                else:
                    errors.append('issue_templates.labels.categories: must be a mapping')
        else:
            errors.append('issue_templates.labels: must be a mapping')

    if 'checklist' in templates:
        checklist = templates['checklist']
        if isinstance(checklist, dict):
            for key, val in checklist.items():
                if not isinstance(val, list):
                    errors.append(f'issue_templates.checklist.{key}: must be an array')
                elif not all(isinstance(item, str) for item in val):
                    errors.append(f'issue_templates.checklist.{key}: all items must be strings')
        else:
            errors.append('issue_templates.checklist: must be a mapping')


def validate_config_structure(config: dict, schema: dict) -> None:
    """
    Validate SCN config structure using dict-based checks.
    Avoids jsonschema dependency as per project requirements.

    Args:
        config: Parsed SCN configuration dictionary
        schema: JSON schema dict (used for reference, validation is manual)

    Raises:
        ValueError: If validation fails, with all errors collected
    """
    errors: List[str] = []

    if not isinstance(config, dict):
        raise ValueError('Config validation failed:\n  - config: must be a mapping')

    # Required fields
    if 'version' not in config:
        errors.append('version: required field missing')
    elif not isinstance(config['version'], str):
        errors.append('version: must be a string')

    if 'rules' not in config:
        errors.append('rules: required field missing')
    else:
        _validate_rules(config['rules'], errors)

    # Optional typed fields
    for field in ('name', 'description', 'compliance_framework'):
        if field in config and not isinstance(config[field], str):
            errors.append(f'{field}: must be a string')

    if 'impact_level' in config:
        if not isinstance(config['impact_level'], str):
            errors.append('impact_level: must be a string')
        elif config['impact_level'] not in VALID_IMPACT_LEVELS:
            errors.append(
                f'impact_level: "{config["impact_level"]}" is not valid '
                f'(valid: {", ".join(sorted(VALID_IMPACT_LEVELS))})'
            )

    # Optional sections
    if 'ai_fallback' in config:
        _validate_ai_fields(config['ai_fallback'], 'ai_fallback', errors)

    if 'notifications' in config:
        _validate_notifications(config['notifications'], errors)

    if 'issue_templates' in config:
        _validate_issue_templates(config['issue_templates'], errors)

    if errors:
        raise ValueError('Config validation failed:\n  - ' + '\n  - '.join(errors))


def validate_ai_config_structure(config: dict) -> None:
    """
    Validate a standalone AI configuration file.
    The standalone format has AI fields at the top level (no ai_fallback wrapper).

    Args:
        config: Parsed AI configuration dictionary

    Raises:
        ValueError: If validation fails, with all errors collected
    """
    errors: List[str] = []

    if not isinstance(config, dict):
        raise ValueError('AI config validation failed:\n  - config: must be a mapping')

    _validate_ai_fields(config, 'ai_config', errors)

    if errors:
        raise ValueError('AI config validation failed:\n  - ' + '\n  - '.join(errors))


def load_config(file_path: str) -> dict:
    """Load config file based on extension (YAML or JSON)."""
    path = Path(file_path)
    ext = path.suffix.lower()

    with open(path, 'r', encoding='utf-8') as f:
        content = f.read()

    if ext in ('.yml', '.yaml'):
        return yaml.safe_load(content) or {}
    elif ext == '.json':
        return json.loads(content)
    else:
        raise ValueError(f'Unsupported config file type: {ext}. Use .yml, .yaml, or .json')


def main():
    """Standalone execution for action.yml validation step."""
    config_file = os.environ.get('CONFIG_FILE')
    schema_file = os.environ.get('SCHEMA_FILE')
    ai_config_file = os.environ.get('AI_CONFIG_FILE', '')

    if not config_file:
        print('Error: CONFIG_FILE environment variable is required', file=sys.stderr)
        sys.exit(1)

    if not schema_file:
        print('Error: SCHEMA_FILE environment variable is required', file=sys.stderr)
        sys.exit(1)

    try:
        print(f'Loading config from: {config_file}')
        config = load_config(config_file)

        print(f'Loading schema from: {schema_file}')
        with open(schema_file, 'r', encoding='utf-8') as f:
            schema = json.load(f)

        print('Validating SCN config against schema...')
        validate_config_structure(config, schema)
        print('SCN configuration validation passed')

        if ai_config_file and os.path.isfile(ai_config_file):
            print(f'Loading AI config from: {ai_config_file}')
            ai_config = load_config(ai_config_file)

            print('Validating AI config...')
            validate_ai_config_structure(ai_config)
            print('AI configuration validation passed')

        sys.exit(0)

    except ValueError as error:
        print(f'\nError: {error}', file=sys.stderr)
        sys.exit(1)
    except Exception as error:
        print(f'\nError: {error}', file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
