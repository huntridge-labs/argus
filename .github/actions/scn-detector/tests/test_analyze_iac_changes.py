#!/usr/bin/env python3
"""
Tests for IaC change analysis.
"""

import importlib.util
import json
import pytest
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

# Import module dynamically
REPO_ROOT = Path(__file__).resolve().parents[4]
SCRIPTS_DIR = REPO_ROOT / ".github" / "actions" / "scn-detector" / "scripts"

# Add scripts dir to sys.path so sibling imports (from diff_helpers import ...) resolve
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

spec = importlib.util.spec_from_file_location(
    "analyze_iac_changes",
    SCRIPTS_DIR / "analyze_iac_changes.py"
)
analyze_iac_changes = importlib.util.module_from_spec(spec)
sys.modules["analyze_iac_changes"] = analyze_iac_changes
spec.loader.exec_module(analyze_iac_changes)


pytestmark = pytest.mark.unit


class TestIaCChangeAnalyzer:
    """Test IaCChangeAnalyzer class."""

    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance."""
        return analyze_iac_changes.IaCChangeAnalyzer('main', 'HEAD')

    def test_initialization(self, analyzer):
        """Test analyzer initializes with refs."""
        assert analyzer.base_ref == 'main'
        assert analyzer.head_ref == 'HEAD'

    def test_is_terraform_file(self, analyzer):
        """Test Terraform file detection."""
        assert analyzer.is_terraform_file('main.tf') is True
        assert analyzer.is_terraform_file('vars.tfvars') is True
        assert analyzer.is_terraform_file('README.md') is False
        assert analyzer.is_terraform_file('app.py') is False

    def test_is_kubernetes_file_by_extension(self, analyzer):
        """Test Kubernetes file detection by extension."""
        assert analyzer.is_kubernetes_file('deploy.yaml') is True
        assert analyzer.is_kubernetes_file('service.yml') is True
        assert analyzer.is_kubernetes_file('app.py') is False

    def test_is_kubernetes_file_with_content(self, analyzer):
        """Test Kubernetes file detection with content inspection."""
        k8s_content = "apiVersion: v1\nkind: Deployment\n"
        non_k8s = "name: my-app\nversion: 1.0\n"

        assert analyzer.is_kubernetes_file('deploy.yaml', k8s_content) is True
        assert analyzer.is_kubernetes_file('config.yaml', non_k8s) is False

    def test_is_cloudformation_file_with_content(self, analyzer):
        """Test CloudFormation file detection with content."""
        cfn_content = "AWSTemplateFormatVersion: '2010-09-09'\nResources:\n"
        non_cfn = "name: my-app\nversion: 1.0\n"

        assert analyzer.is_cloudformation_file('template.yaml', cfn_content) is True
        assert analyzer.is_cloudformation_file('config.yaml', non_cfn) is False

    def test_determine_iac_format_terraform(self, analyzer):
        """Test format detection for Terraform files."""
        assert analyzer.determine_iac_format('main.tf') == 'terraform'
        assert analyzer.determine_iac_format('terraform.tfvars') == 'terraform'

    @patch('analyze_iac_changes.subprocess.run')
    def test_get_changed_files_success(self, mock_run, analyzer):
        """Test getting changed files from git."""
        mock_run.return_value = MagicMock(
            stdout="main.tf\nservice.yaml\nREADME.md\n",
            returncode=0
        )

        files = analyzer.get_changed_files()

        assert len(files) == 3
        assert 'main.tf' in files
        assert 'service.yaml' in files

    @patch('analyze_iac_changes.subprocess.run')
    def test_get_changed_files_error(self, mock_run, analyzer):
        """Test handling of git diff error."""
        from subprocess import CalledProcessError
        mock_run.side_effect = CalledProcessError(1, 'git', stderr='fatal: bad ref')

        files = analyzer.get_changed_files()

        assert files == []

    @patch('analyze_iac_changes.subprocess.run')
    def test_get_file_diff_success(self, mock_run, analyzer):
        """Test getting file diff."""
        mock_run.return_value = MagicMock(
            stdout='diff --git a/main.tf b/main.tf\n+resource "aws_instance" "web" {}\n',
            returncode=0
        )

        diff = analyzer.get_file_diff('main.tf')

        assert diff is not None
        assert 'aws_instance' in diff

    @patch('analyze_iac_changes.subprocess.run')
    def test_get_file_diff_error(self, mock_run, analyzer):
        """Test handling of diff retrieval error."""
        from subprocess import CalledProcessError
        mock_run.side_effect = CalledProcessError(1, 'git', stderr='error')

        diff = analyzer.get_file_diff('missing.tf')

        assert diff is None
