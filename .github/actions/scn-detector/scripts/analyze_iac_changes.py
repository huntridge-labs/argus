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
from typing import Dict, List, Optional

from diff_helpers import (
    parse_terraform_diff,
    parse_kubernetes_diff,
    parse_cloudformation_diff,
)


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

            print(f"  ✓ {file_path} ({iac_format})")

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
    parser.add_argument('--base-ref', required=True, help='Base git reference')
    parser.add_argument('--head-ref', required=True, help='Head git reference')
    parser.add_argument('--output', required=True, help='Output JSON file path')

    args = parser.parse_args()

    analyzer = IaCChangeAnalyzer(args.base_ref, args.head_ref)
    results = analyzer.analyze_changes()

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)

    print(f"\n✅ Analysis complete: {output_path}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
