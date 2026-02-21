#!/usr/bin/env python3
"""
FedRAMP SCN Detector - IaC Change Analysis

Analyzes git diffs to identify and extract Infrastructure as Code changes from:
- Terraform (*.tf, *.tfvars)
- Kubernetes (*.yaml, *.yml with kind/apiVersion)
- CloudFormation (*.json, *.yaml with AWSTemplateFormatVersion)
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple


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
        """
        Get list of changed files between refs.

        Returns:
            List of changed file paths
        """
        try:
            result = subprocess.run(
                ['git', 'diff', '--name-only', self.base_ref, self.head_ref],
                capture_output=True,
                text=True,
                check=True
            )
            files = [f.strip() for f in result.stdout.splitlines() if f.strip()]
            return files
        except subprocess.CalledProcessError as e:
            # TODO: Improve error handling to provide more specific error messages
            # indicating whether the issue is with git availability, invalid refs,
            # or insufficient fetch depth. This would help users diagnose
            # "No IaC changes detected" issues more easily.
            print(f"Error getting changed files: {e}", file=sys.stderr)
            print(f"  stderr: {e.stderr}", file=sys.stderr)
            return []

    def get_file_diff(self, file_path: str) -> Optional[str]:
        """
        Get diff content for a specific file.

        Args:
            file_path: Path to file

        Returns:
            Diff content as string, or None if error
        """
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

        # If content provided, check for K8s indicators
        if content:
            return any(indicator in content for indicator in self.K8S_INDICATORS)

        return True

    def is_cloudformation_file(self, file_path: str, content: str = None) -> bool:
        """Check if file is CloudFormation template."""
        if not any(re.search(pattern, file_path) for pattern in self.CFN_PATTERNS):
            return False

        # If content provided, check for CFN indicators
        if content:
            return any(indicator in content for indicator in self.CFN_INDICATORS)

        return True

    def determine_iac_format(self, file_path: str) -> Optional[str]:
        """
        Determine IaC format of file.

        Args:
            file_path: Path to file

        Returns:
            Format string ('terraform', 'kubernetes', 'cloudformation', 'unknown') or None
        """
        # Get file content for format detection
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(1024)  # Read first 1KB for detection
        except (FileNotFoundError, PermissionError):
            # File might be deleted, check by extension only
            content = None

        # Check Terraform first (most specific)
        if self.is_terraform_file(file_path):
            return 'terraform'

        # Check Kubernetes (needs content inspection)
        if self.is_kubernetes_file(file_path, content):
            return 'kubernetes'

        # Check CloudFormation (needs content inspection)
        if self.is_cloudformation_file(file_path, content):
            return 'cloudformation'

        return None

    def parse_terraform_diff(self, file_path: str, diff_content: str) -> Dict:
        """
        Parse Terraform diff to extract resource changes.

        Args:
            file_path: Path to Terraform file
            diff_content: Git diff content

        Returns:
            Dictionary with extracted changes
        """
        resources = []

        # Pattern to match resource blocks: resource "type" "name"
        resource_pattern = r'resource\s+"([^"]+)"\s+"([^"]+)"'

        # Find all resource definitions in the diff
        for match in re.finditer(resource_pattern, diff_content):
            resource_type = match.group(1)
            resource_name = match.group(2)

            # Determine operation based on diff markers
            operation = self._determine_operation(diff_content, match.start())

            # Extract changed attributes
            attributes_changed = self._extract_changed_attributes(diff_content, match.start())

            # Extract diff snippet around this resource
            diff_snippet = self._extract_diff_snippet(diff_content, match.start())

            resources.append({
                'type': resource_type,
                'name': resource_name,
                'operation': operation,
                'attributes_changed': attributes_changed,
                'diff': diff_snippet
            })

        # If no resources found but file changed, mark as generic modification
        if not resources and diff_content:
            resources.append({
                'type': 'unknown',
                'name': Path(file_path).stem,
                'operation': 'modify',
                'attributes_changed': self._extract_changed_attributes(diff_content, 0),
                'diff': diff_content[:500]  # First 500 chars
            })

        return {
            'file': file_path,
            'format': 'terraform',
            'resources': resources
        }

    def parse_kubernetes_diff(self, file_path: str, diff_content: str) -> Dict:
        """
        Parse Kubernetes diff to extract resource changes.

        Args:
            file_path: Path to Kubernetes manifest
            diff_content: Git diff content

        Returns:
            Dictionary with extracted changes
        """
        resources = []

        # Pattern to match kind: and metadata.name:
        kind_pattern = r'kind:\s*([^\s\n]+)'
        name_pattern = r'name:\s*([^\s\n]+)'

        kind_matches = list(re.finditer(kind_pattern, diff_content))
        name_matches = list(re.finditer(name_pattern, diff_content))

        # Pair kinds with names (assume first name after kind is the resource name)
        for i, kind_match in enumerate(kind_matches):
            kind = kind_match.group(1)

            # Find nearest name after this kind
            name = 'unnamed'
            for name_match in name_matches:
                if name_match.start() > kind_match.start():
                    name = name_match.group(1)
                    break

            operation = self._determine_operation(diff_content, kind_match.start())
            attributes_changed = self._extract_changed_attributes(diff_content, kind_match.start())
            diff_snippet = self._extract_diff_snippet(diff_content, kind_match.start())

            resources.append({
                'type': kind,
                'name': name,
                'operation': operation,
                'attributes_changed': attributes_changed,
                'diff': diff_snippet
            })

        # If no resources found but file changed
        if not resources and diff_content:
            resources.append({
                'type': 'unknown',
                'name': Path(file_path).stem,
                'operation': 'modify',
                'attributes_changed': self._extract_changed_attributes(diff_content, 0),
                'diff': diff_content[:500]
            })

        return {
            'file': file_path,
            'format': 'kubernetes',
            'resources': resources
        }

    def parse_cloudformation_diff(self, file_path: str, diff_content: str) -> Dict:
        """
        Parse CloudFormation diff to extract resource changes.

        Args:
            file_path: Path to CloudFormation template
            diff_content: Git diff content

        Returns:
            Dictionary with extracted changes
        """
        resources = []

        # CloudFormation resources pattern (YAML): ResourceName:\n  Type: AWS::*
        # Or JSON: "ResourceName": { "Type": "AWS::*"
        yaml_pattern = r'([A-Z][A-Za-z0-9]+):\s*\n\s*Type:\s*(AWS::[^\s\n]+)'
        json_pattern = r'"([^"]+)":\s*\{\s*"Type":\s*"(AWS::[^"]+)"'

        # Try YAML pattern first
        for match in re.finditer(yaml_pattern, diff_content):
            resource_name = match.group(1)
            resource_type = match.group(2)

            operation = self._determine_operation(diff_content, match.start())
            attributes_changed = self._extract_changed_attributes(diff_content, match.start())
            diff_snippet = self._extract_diff_snippet(diff_content, match.start())

            resources.append({
                'type': resource_type,
                'name': resource_name,
                'operation': operation,
                'attributes_changed': attributes_changed,
                'diff': diff_snippet
            })

        # Try JSON pattern if no YAML matches
        if not resources:
            for match in re.finditer(json_pattern, diff_content):
                resource_name = match.group(1)
                resource_type = match.group(2)

                operation = self._determine_operation(diff_content, match.start())
                attributes_changed = self._extract_changed_attributes(diff_content, match.start())
                diff_snippet = self._extract_diff_snippet(diff_content, match.start())

                resources.append({
                    'type': resource_type,
                    'name': resource_name,
                    'operation': operation,
                    'attributes_changed': attributes_changed,
                    'diff': diff_snippet
                })

        # If no resources found but file changed
        if not resources and diff_content:
            resources.append({
                'type': 'unknown',
                'name': Path(file_path).stem,
                'operation': 'modify',
                'attributes_changed': self._extract_changed_attributes(diff_content, 0),
                'diff': diff_content[:500]
            })

        return {
            'file': file_path,
            'format': 'cloudformation',
            'resources': resources
        }

    def _determine_operation(self, diff_content: str, position: int) -> str:
        """
        Determine operation type (create/modify/delete) based on diff context.

        Args:
            diff_content: Git diff content
            position: Position in diff content

        Returns:
            Operation string: 'create', 'modify', or 'delete'
        """
        # Look at surrounding context (500 chars before and after)
        start = max(0, position - 500)
        end = min(len(diff_content), position + 500)
        context = diff_content[start:end]

        # Count additions (+) and deletions (-)
        additions = context.count('\n+')
        deletions = context.count('\n-')

        # If mostly additions, likely a create
        if additions > deletions * 2:
            return 'create'
        # If mostly deletions, likely a delete
        elif deletions > additions * 2:
            return 'delete'
        # Otherwise, modification
        else:
            return 'modify'

    def _extract_changed_attributes(self, diff_content: str, position: int) -> List[str]:
        """
        Extract list of changed attribute names from diff.

        Args:
            diff_content: Git diff content
            position: Position in diff content

        Returns:
            List of attribute names
        """
        attributes = set()

        # Look at surrounding context
        start = max(0, position - 1000)
        end = min(len(diff_content), position + 1000)
        context = diff_content[start:end]

        # Pattern for attribute changes: +/- followed by attribute name
        # Terraform: instance_type = "..."
        # K8s/CFN: key: value
        tf_pattern = r'[+-]\s*([a-z_][a-z0-9_]*)\s*='
        yaml_pattern = r'[+-]\s*([a-z_][a-z0-9_-]*)\s*:'

        for pattern in [tf_pattern, yaml_pattern]:
            for match in re.finditer(pattern, context, re.IGNORECASE):
                attr_name = match.group(1)
                # Skip common diff markers
                if attr_name not in ['diff', 'index', 'file']:
                    attributes.add(attr_name)

        return sorted(list(attributes))

    def _extract_diff_snippet(self, diff_content: str, position: int, max_length: int = 300) -> str:
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

        # Truncate to complete lines
        lines = snippet.splitlines()
        if len(lines) > 10:
            lines = lines[:10]
        snippet = '\n'.join(lines)

        return snippet

    def analyze_changes(self) -> Dict:
        """
        Analyze all IaC changes between refs.

        Returns:
            Dictionary with change analysis results
        """
        print(f"🔍 Analyzing IaC changes: {self.base_ref}...{self.head_ref}")

        changed_files = self.get_changed_files()
        print(f"📁 Found {len(changed_files)} changed files")

        changes = []
        summary = {
            'total_files': 0,
            'terraform_files': 0,
            'kubernetes_files': 0,
            'cloudformation_files': 0
        }

        for file_path in changed_files:
            iac_format = self.determine_iac_format(file_path)

            if not iac_format:
                continue  # Not an IaC file

            print(f"  ✓ {file_path} ({iac_format})")

            diff_content = self.get_file_diff(file_path)
            if not diff_content:
                continue

            # Parse based on format
            if iac_format == 'terraform':
                change_data = self.parse_terraform_diff(file_path, diff_content)
                summary['terraform_files'] += 1
            elif iac_format == 'kubernetes':
                change_data = self.parse_kubernetes_diff(file_path, diff_content)
                summary['kubernetes_files'] += 1
            elif iac_format == 'cloudformation':
                change_data = self.parse_cloudformation_diff(file_path, diff_content)
                summary['cloudformation_files'] += 1
            else:
                continue

            changes.append(change_data)
            summary['total_files'] += 1

        print(f"\n📊 Analysis Summary:")
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


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Analyze IaC changes for FedRAMP SCN classification'
    )
    parser.add_argument(
        '--base-ref',
        required=True,
        help='Base git reference for comparison'
    )
    parser.add_argument(
        '--head-ref',
        required=True,
        help='Head git reference for comparison'
    )
    parser.add_argument(
        '--output',
        required=True,
        help='Output JSON file path'
    )

    args = parser.parse_args()

    # Create analyzer and run analysis
    analyzer = IaCChangeAnalyzer(args.base_ref, args.head_ref)
    results = analyzer.analyze_changes()

    # Write output
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)

    print(f"\n✅ Analysis complete: {output_path}")

    # Exit with success
    return 0


if __name__ == '__main__':
    sys.exit(main())
