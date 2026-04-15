#!/usr/bin/env python3
"""
FedRAMP SCN Detector - Diff Parsing and IaC Change Analysis

Combines diff parsing helpers and IaC change analysis into a single module.
Supports Terraform, Kubernetes, and CloudFormation formats.
"""

import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Diff parsing helpers
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# IaC Change Analyzer (ported from analyze_iac_changes.py)
# ---------------------------------------------------------------------------

class IaCChangeAnalyzer:
    """Analyzes git diffs for IaC changes."""

    # File patterns for IaC detection
    TERRAFORM_PATTERNS = [r'\.tf$', r'\.tfvars$']
    K8S_PATTERNS = [r'\.ya?ml$']
    CFN_PATTERNS = [r'\.json$', r'\.ya?ml$']

    # Kubernetes resource indicators
    K8S_INDICATORS = ['kind:', 'apiVersion:']

    # CloudFormation indicators
    CFN_INDICATORS = ['AWSTemplateFormatVersion:', 'Resources:']

    def __init__(self, base_ref: str, head_ref: str):
        """
        Initialize analyzer.

        Args:
            base_ref: Base git reference for comparison
            head_ref: Head git reference for comparison
        """
        self.base_ref = base_ref
        self.head_ref = head_ref

    def get_changed_files(self) -> List[str]:
        """Get list of changed files between refs."""
        try:
            result = subprocess.run(
                ['git', 'diff', '--name-only', self.base_ref, self.head_ref],
                capture_output=True,
                text=True,
                check=True
            )
            return [f.strip() for f in result.stdout.splitlines() if f.strip()]
        except subprocess.CalledProcessError as e:
            print(f"Error getting changed files: {e}", file=sys.stderr)
            print(f"  stderr: {e.stderr}", file=sys.stderr)
            return []

    def get_file_diff(self, file_path: str) -> Optional[str]:
        """Get diff content for a specific file."""
        try:
            result = subprocess.run(
                ['git', 'diff', self.base_ref, self.head_ref, '--', file_path],
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            print(f"Error getting diff for {file_path}: {e}", file=sys.stderr)
            return None

    def is_terraform_file(self, file_path: str) -> bool:
        """Check if file is Terraform."""
        return any(re.search(pattern, file_path) for pattern in self.TERRAFORM_PATTERNS)

    def is_kubernetes_file(self, file_path: str, content: str = None) -> bool:
        """Check if file is Kubernetes manifest."""
        if not any(re.search(pattern, file_path) for pattern in self.K8S_PATTERNS):
            return False
        if content:
            return any(indicator in content for indicator in self.K8S_INDICATORS)
        return True

    def is_cloudformation_file(self, file_path: str, content: str = None) -> bool:
        """Check if file is CloudFormation template."""
        if not any(re.search(pattern, file_path) for pattern in self.CFN_PATTERNS):
            return False
        if content:
            return any(indicator in content for indicator in self.CFN_INDICATORS)
        return True

    def determine_iac_format(self, file_path: str) -> Optional[str]:
        """
        Determine IaC format of file.

        Returns:
            Format string ('terraform', 'kubernetes', 'cloudformation') or None
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(1024)
        except (FileNotFoundError, PermissionError):
            content = None

        if self.is_terraform_file(file_path):
            return 'terraform'
        if self.is_kubernetes_file(file_path, content):
            return 'kubernetes'
        if self.is_cloudformation_file(file_path, content):
            return 'cloudformation'

        return None

    def analyze_changes(self) -> Dict:
        """Analyze all IaC changes between refs."""
        print(f"Analyzing IaC changes: {self.base_ref}...{self.head_ref}")

        changed_files = self.get_changed_files()
        print(f"Found {len(changed_files)} changed files")

        changes = []
        summary = {
            'total_files': 0,
            'terraform_files': 0,
            'kubernetes_files': 0,
            'cloudformation_files': 0
        }

        # Map formats to parsers
        parsers = {
            'terraform': parse_terraform_diff,
            'kubernetes': parse_kubernetes_diff,
            'cloudformation': parse_cloudformation_diff,
        }

        for file_path in changed_files:
            iac_format = self.determine_iac_format(file_path)
            if not iac_format:
                continue

            print(f"  {file_path} ({iac_format})")

            diff_content = self.get_file_diff(file_path)
            if not diff_content:
                continue

            parser = parsers.get(iac_format)
            if not parser:
                continue

            change_data = parser(file_path, diff_content)
            changes.append(change_data)
            summary[f'{iac_format}_files'] += 1
            summary['total_files'] += 1

        print(f"\nAnalysis Summary:")
        print(f"  Total IaC files: {summary['total_files']}")
        print(f"  Terraform: {summary['terraform_files']}")
        print(f"  Kubernetes: {summary['kubernetes_files']}")
        print(f"  CloudFormation: {summary['cloudformation_files']}")

        return {
            'changes': changes,
            'summary': summary,
            'base_ref': self.base_ref,
            'head_ref': self.head_ref
        }


# ---------------------------------------------------------------------------
# Public API for the diff module
# ---------------------------------------------------------------------------

def parse_diff(file_path: str, diff_content: str, iac_format: str) -> Dict:
    """
    Parse a diff based on IaC format.

    Args:
        file_path: Path to the IaC file
        diff_content: Git diff content
        iac_format: One of 'terraform', 'kubernetes', 'cloudformation'

    Returns:
        Dictionary with extracted changes

    Raises:
        ValueError: If iac_format is not recognized
    """
    parsers = {
        'terraform': parse_terraform_diff,
        'kubernetes': parse_kubernetes_diff,
        'cloudformation': parse_cloudformation_diff,
    }
    parser = parsers.get(iac_format)
    if not parser:
        raise ValueError(
            f"Unknown IaC format: '{iac_format}'. "
            f"Supported: {', '.join(parsers.keys())}"
        )
    return parser(file_path, diff_content)


def analyze_iac_changes(base_ref: str, head_ref: str) -> Dict:
    """
    Convenience wrapper around IaCChangeAnalyzer.

    Args:
        base_ref: Base git reference for comparison
        head_ref: Head git reference for comparison

    Returns:
        Dictionary with changes, summary, and ref info
    """
    analyzer = IaCChangeAnalyzer(base_ref, head_ref)
    return analyzer.analyze_changes()
