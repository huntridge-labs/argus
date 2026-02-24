#!/usr/bin/env python3
"""
Default configuration values for SCN detector.
Single source of truth for all hardcoded defaults.
"""

from typing import Dict, Any


# Provider API Base URLs
DEFAULT_API_BASE_URLS = {
    'anthropic': 'https://api.anthropic.com',
    'openai': 'https://api.openai.com/v1'
}


# Default AI Configuration
DEFAULT_AI_CONFIG = {
    'provider': 'anthropic',
    'model': 'claude-3-haiku-20240307',
    'confidence_threshold': 0.8,
    'max_tokens': 1024,
    'max_diff_chars': 1000,
    'system_prompt': """You are a FedRAMP compliance expert analyzing infrastructure changes for Low impact systems.
You are performing this task because a rules-based classification could not confidently categorize the change.

Use the following guidelines to classify the change:

FedRAMP Change Categories:
- ROUTINE: Regular maintenance, patching, minor capacity changes (no notification required)
- ADAPTIVE: Frequent improvements with minimal security plan changes (10 days after completion)
- TRANSFORMATIVE: Rare, significant changes altering risk profile (30 days initial + 10 days final notice)
- IMPACT: Changes to security boundary or FIPS level (requires new assessment)""",
    'user_prompt_template': """Change Details:
- Resource Type: {resource_type}
- Resource Name: {resource_name}
- Operation: {operation}
- Attributes Changed: {attributes}
- Diff Preview:
{diff_snippet}

Classify this change. Respond ONLY with valid JSON in this exact format:
{{
  "category": "ROUTINE|ADAPTIVE|TRANSFORMATIVE|IMPACT",
  "confidence": 0.0-1.0,
  "reasoning": "Brief explanation (max 200 chars)"
}}"""
}

# Default Classification Rules (used if no config profile is provided)
DEFAULT_RULES = {
    'routine': [
        {'pattern': r'tags.*', 'description': 'Tag changes'},
        {'pattern': r'description', 'description': 'Description changes'},
    ],
    'adaptive': [
        {'resource': r'aws_ami\..*', 'operation': 'modify', 'description': 'AMI updates'},
        {'resource': r'aws_instance\..*\.instance_type', 'operation': 'modify', 'description': 'Instance type changes'},
    ],
    'transformative': [
        {'pattern': r'provider\..*\.region', 'operation': 'modify', 'description': 'Region changes'},
        {'resource': r'aws_rds_.*\.engine', 'operation': 'modify', 'description': 'Database engine changes'},
    ],
    'impact': [
        {'attribute': r'.*encryption.*', 'operation': 'delete|modify', 'description': 'Encryption changes'},
        {'resource': r'aws_security_group\..*', 'attribute': r'ingress', 'pattern': r'0\.0\.0\.0/0', 'description': 'Public security group'},
    ]
}

# Default Notification Configuration
DEFAULT_NOTIFICATIONS = {
    'adaptive': {
        'post_completion_days': 10,
        'description': "This change is classified as Adaptive. Argus recommends notifying your organization's security team within 10 days after completion to allow for any necessary documentation updates if required by your organization's policies."
    },
    'transformative': {
        'initial_notice_days': 30,
        'final_notice_days': 10,
        'post_completion_required': True,
        'description': "This change is classified as Transformative. Argus recommends providing an initial notice to your security team 30 days before implementation, a final notice 10 days before implementation, and post-completion notification if required."
    },
    'impact': {
        'requires_new_assessment': True,
        'description': "This change is classified as Impactful. Argus recommends that a new security assessment and authorization be conducted before implementation. Notify your compliance team immediately to initiate your organization's assessment process."
    }
}

# Default Profile Metadata
DEFAULT_PROFILE_METADATA = {
    'version': '1.0',
    'name': 'Default FedRAMP Profile',
    'description': 'Built-in FedRAMP-aligned classification rules',
    'compliance_framework': 'FedRAMP 20X',
    'impact_level': 'Low'
}


def merge_config(custom: Dict[str, Any], defaults: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deep merge custom configuration with defaults.

    Custom values override defaults. Nested dictionaries are merged recursively.
    Lists are replaced entirely (not merged).

    Args:
        custom: Custom configuration (from profile or user input)
        defaults: Default configuration values

    Returns:
        Merged configuration dictionary
    """
    if not custom:
        return defaults.copy()

    if not isinstance(custom, dict):
        return defaults.copy()

    result = defaults.copy()

    for key, value in custom.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            # Recursively merge nested dictionaries
            result[key] = merge_config(value, result[key])
        else:
            # Override with custom value (including lists)
            result[key] = value

    return result


def get_default_config() -> Dict[str, Any]:
    """
    Get complete default configuration.

    Returns:
        Dictionary with all default configuration values
    """
    return {
        **DEFAULT_PROFILE_METADATA,
        'rules': DEFAULT_RULES,
        'ai_fallback': DEFAULT_AI_CONFIG,
        'notifications': DEFAULT_NOTIFICATIONS
    }
