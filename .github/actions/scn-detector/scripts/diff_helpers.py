#!/usr/bin/env python3
"""
FedRAMP SCN Detector - Diff Parsing Helpers

Utility functions for extracting structured change data from git diffs.
Supports Terraform, Kubernetes, and CloudFormation formats.
"""

import re
from pathlib import Path
from typing import Dict, List


def determine_operation(diff_content: str, position: int) -> str:
    """
    Determine operation type (create/modify/delete) based on diff context.

    Args:
        diff_content: Git diff content
        position: Position in diff content

    Returns:
        Operation string: 'create', 'modify', or 'delete'
    """
    start = max(0, position - 500)
    end = min(len(diff_content), position + 500)
    context = diff_content[start:end]

    additions = context.count('\n+')
    deletions = context.count('\n-')

    if additions > deletions * 2:
        return 'create'
    elif deletions > additions * 2:
        return 'delete'
    else:
        return 'modify'


def extract_changed_attributes(diff_content: str, position: int) -> List[str]:
    """
    Extract list of changed attribute names from diff.

    Args:
        diff_content: Git diff content
        position: Position in diff content

    Returns:
        List of attribute names
    """
    attributes = set()

    start = max(0, position - 1000)
    end = min(len(diff_content), position + 1000)
    context = diff_content[start:end]

    tf_pattern = r'[+-]\s*([a-z_][a-z0-9_]*)\s*='
    yaml_pattern = r'[+-]\s*([a-z_][a-z0-9_-]*)\s*:'

    for pattern in [tf_pattern, yaml_pattern]:
        for match in re.finditer(pattern, context, re.IGNORECASE):
            attr_name = match.group(1)
            if attr_name not in ['diff', 'index', 'file']:
                attributes.add(attr_name)

    return sorted(list(attributes))


def extract_diff_snippet(diff_content: str, position: int, max_length: int = 300) -> str:
    """
    Extract a snippet of diff around position.

    Args:
        diff_content: Git diff content
        position: Position in diff content
        max_length: Maximum snippet length

    Returns:
        Diff snippet
    """
    start = max(0, position - max_length // 2)
    end = min(len(diff_content), position + max_length // 2)
    snippet = diff_content[start:end]

    lines = snippet.splitlines()
    if len(lines) > 10:
        lines = lines[:10]

    return '\n'.join(lines)


def _build_generic_resource(file_path: str, diff_content: str) -> Dict:
    """Build a generic resource entry when no specific pattern matched."""
    return {
        'type': 'unknown',
        'name': Path(file_path).stem,
        'operation': 'modify',
        'attributes_changed': extract_changed_attributes(diff_content, 0),
        'diff': diff_content[:500]
    }


def parse_terraform_diff(file_path: str, diff_content: str) -> Dict:
    """
    Parse Terraform diff to extract resource changes.

    Args:
        file_path: Path to Terraform file
        diff_content: Git diff content

    Returns:
        Dictionary with extracted changes
    """
    resources = []
    resource_pattern = r'resource\s+"([^"]+)"\s+"([^"]+)"'

    for match in re.finditer(resource_pattern, diff_content):
        resource_type = match.group(1)
        resource_name = match.group(2)

        resources.append({
            'type': resource_type,
            'name': resource_name,
            'operation': determine_operation(diff_content, match.start()),
            'attributes_changed': extract_changed_attributes(diff_content, match.start()),
            'diff': extract_diff_snippet(diff_content, match.start())
        })

    if not resources and diff_content:
        resources.append(_build_generic_resource(file_path, diff_content))

    return {'file': file_path, 'format': 'terraform', 'resources': resources}


def parse_kubernetes_diff(file_path: str, diff_content: str) -> Dict:
    """
    Parse Kubernetes diff to extract resource changes.

    Args:
        file_path: Path to Kubernetes manifest
        diff_content: Git diff content

    Returns:
        Dictionary with extracted changes
    """
    resources = []

    kind_pattern = r'kind:\s*([^\s\n]+)'
    name_pattern = r'name:\s*([^\s\n]+)'

    kind_matches = list(re.finditer(kind_pattern, diff_content))
    name_matches = list(re.finditer(name_pattern, diff_content))

    for kind_match in kind_matches:
        kind = kind_match.group(1)

        name = 'unnamed'
        for name_match in name_matches:
            if name_match.start() > kind_match.start():
                name = name_match.group(1)
                break

        resources.append({
            'type': kind,
            'name': name,
            'operation': determine_operation(diff_content, kind_match.start()),
            'attributes_changed': extract_changed_attributes(diff_content, kind_match.start()),
            'diff': extract_diff_snippet(diff_content, kind_match.start())
        })

    if not resources and diff_content:
        resources.append(_build_generic_resource(file_path, diff_content))

    return {'file': file_path, 'format': 'kubernetes', 'resources': resources}


def parse_cloudformation_diff(file_path: str, diff_content: str) -> Dict:
    """
    Parse CloudFormation diff to extract resource changes.

    Args:
        file_path: Path to CloudFormation template
        diff_content: Git diff content

    Returns:
        Dictionary with extracted changes
    """
    resources = []

    yaml_pattern = r'([A-Z][A-Za-z0-9]+):\s*\n\s*Type:\s*(AWS::[^\s\n]+)'
    json_pattern = r'"([^"]+)":\s*\{\s*"Type":\s*"(AWS::[^"]+)"'

    for match in re.finditer(yaml_pattern, diff_content):
        resource_name = match.group(1)
        resource_type = match.group(2)

        resources.append({
            'type': resource_type,
            'name': resource_name,
            'operation': determine_operation(diff_content, match.start()),
            'attributes_changed': extract_changed_attributes(diff_content, match.start()),
            'diff': extract_diff_snippet(diff_content, match.start())
        })

    # Try JSON pattern if no YAML matches
    if not resources:
        for match in re.finditer(json_pattern, diff_content):
            resource_name = match.group(1)
            resource_type = match.group(2)

            resources.append({
                'type': resource_type,
                'name': resource_name,
                'operation': determine_operation(diff_content, match.start()),
                'attributes_changed': extract_changed_attributes(diff_content, match.start()),
                'diff': extract_diff_snippet(diff_content, match.start())
            })

    if not resources and diff_content:
        resources.append(_build_generic_resource(file_path, diff_content))

    return {'file': file_path, 'format': 'cloudformation', 'resources': resources}
