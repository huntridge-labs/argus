#!/usr/bin/env python3
"""
Tests for diff parsing helper functions.
"""

import importlib.util
import pytest
import sys
from pathlib import Path

# Import module dynamically
REPO_ROOT = Path(__file__).resolve().parents[4]
SCRIPTS_DIR = REPO_ROOT / ".github" / "actions" / "scn-detector" / "scripts"

spec = importlib.util.spec_from_file_location(
    "diff_helpers",
    SCRIPTS_DIR / "diff_helpers.py"
)
diff_helpers = importlib.util.module_from_spec(spec)
sys.modules["diff_helpers"] = diff_helpers
spec.loader.exec_module(diff_helpers)


pytestmark = pytest.mark.unit


class TestDetermineOperation:
    """Test determine_operation function."""

    def test_mostly_additions_returns_create(self):
        """Many additions, few deletions -> create."""
        diff = "\n+line1\n+line2\n+line3\n+line4\n+line5\n-old"
        assert diff_helpers.determine_operation(diff, 0) == 'create'

    def test_mostly_deletions_returns_delete(self):
        """Many deletions, few additions -> delete."""
        diff = "\n-line1\n-line2\n-line3\n-line4\n-line5\n+new"
        assert diff_helpers.determine_operation(diff, 0) == 'delete'

    def test_balanced_changes_returns_modify(self):
        """Balanced additions/deletions -> modify."""
        diff = "\n+line1\n+line2\n-line3\n-line4"
        assert diff_helpers.determine_operation(diff, 0) == 'modify'

    def test_empty_diff_returns_modify(self):
        """Empty diff -> modify (default)."""
        assert diff_helpers.determine_operation("", 0) == 'modify'

    def test_position_offset(self):
        """Operation detection uses context around position."""
        diff = "prefix" * 200 + "\n+added\n+added\n+added\n+added\n+added"
        result = diff_helpers.determine_operation(diff, len(diff) - 10)
        assert result == 'create'


class TestExtractChangedAttributes:
    """Test extract_changed_attributes function."""

    def test_terraform_style_attributes(self):
        """Extract HCL-style attribute = value."""
        diff = "+  instance_type = \"t3.micro\"\n-  instance_type = \"t2.micro\""
        attrs = diff_helpers.extract_changed_attributes(diff, 0)
        assert 'instance_type' in attrs

    def test_yaml_style_attributes(self):
        """Extract YAML-style attribute: value."""
        diff = "+  replicas: 3\n-  replicas: 1"
        attrs = diff_helpers.extract_changed_attributes(diff, 0)
        assert 'replicas' in attrs

    def test_filters_noise_attributes(self):
        """Filters out known noise: diff, index, file."""
        diff = "+diff something\n+index abc123\n+file path"
        attrs = diff_helpers.extract_changed_attributes(diff, 0)
        assert 'diff' not in attrs
        assert 'index' not in attrs
        assert 'file' not in attrs

    def test_returns_sorted_unique(self):
        """Returns sorted unique attribute names."""
        diff = "+  name = \"a\"\n+  name = \"b\"\n+  tags = {}"
        attrs = diff_helpers.extract_changed_attributes(diff, 0)
        assert attrs == sorted(set(attrs))

    def test_empty_diff(self):
        """Empty diff returns empty list."""
        assert diff_helpers.extract_changed_attributes("", 0) == []


class TestExtractDiffSnippet:
    """Test extract_diff_snippet function."""

    def test_short_diff_returns_full(self):
        """Short diff within max_length returns entire content."""
        diff = "+line1\n+line2\n-line3"
        snippet = diff_helpers.extract_diff_snippet(diff, 0, max_length=300)
        assert "+line1" in snippet

    def test_long_diff_truncated(self):
        """Long diff truncated to max_length region."""
        diff = "\n".join(f"+line{i}" for i in range(100))
        snippet = diff_helpers.extract_diff_snippet(diff, 0, max_length=50)
        assert len(snippet) < len(diff)

    def test_truncates_to_max_10_lines(self):
        """Snippet limited to 10 lines."""
        diff = "\n".join(f"+line{i}" for i in range(20))
        snippet = diff_helpers.extract_diff_snippet(diff, 0, max_length=5000)
        assert snippet.count('\n') <= 9


class TestBuildGenericResource:
    """Test _build_generic_resource function."""

    def test_returns_unknown_type(self):
        """Generic resource has type 'unknown'."""
        result = diff_helpers._build_generic_resource("path/main.tf", "+content")
        assert result['type'] == 'unknown'

    def test_name_from_filename(self):
        """Name derived from file stem."""
        result = diff_helpers._build_generic_resource("infra/vpc.tf", "+content")
        assert result['name'] == 'vpc'

    def test_operation_is_modify(self):
        """Default operation is modify."""
        result = diff_helpers._build_generic_resource("main.tf", "+content")
        assert result['operation'] == 'modify'

    def test_diff_truncated_to_500(self):
        """Diff content capped at 500 characters."""
        long_diff = "x" * 1000
        result = diff_helpers._build_generic_resource("main.tf", long_diff)
        assert len(result['diff']) == 500


class TestParseTerraformDiff:
    """Test parse_terraform_diff function."""

    def test_extracts_resource_block(self):
        """Extracts terraform resource type and name."""
        diff = '+resource "aws_instance" "web" {\n+  ami = "ami-123"\n+}'
        result = diff_helpers.parse_terraform_diff("main.tf", diff)

        assert result['format'] == 'terraform'
        assert result['file'] == 'main.tf'
        assert len(result['resources']) == 1
        assert result['resources'][0]['type'] == 'aws_instance'
        assert result['resources'][0]['name'] == 'web'

    def test_multiple_resources(self):
        """Extracts multiple resource blocks."""
        diff = (
            '+resource "aws_instance" "web" {}\n'
            '+resource "aws_s3_bucket" "data" {}\n'
        )
        result = diff_helpers.parse_terraform_diff("main.tf", diff)
        assert len(result['resources']) == 2

    def test_fallback_to_generic_resource(self):
        """No resource pattern -> generic resource."""
        diff = "+variable = 42"
        result = diff_helpers.parse_terraform_diff("vars.tf", diff)
        assert len(result['resources']) == 1
        assert result['resources'][0]['type'] == 'unknown'

    def test_empty_diff(self):
        """Empty diff -> no resources."""
        result = diff_helpers.parse_terraform_diff("main.tf", "")
        assert result['resources'] == []


class TestParseKubernetesDiff:
    """Test parse_kubernetes_diff function."""

    def test_extracts_kind_and_name(self):
        """Extracts Kubernetes kind and metadata name."""
        diff = "kind: Deployment\nmetadata:\n  name: web-server\n"
        result = diff_helpers.parse_kubernetes_diff("deploy.yaml", diff)

        assert result['format'] == 'kubernetes'
        assert len(result['resources']) == 1
        assert result['resources'][0]['type'] == 'Deployment'
        assert result['resources'][0]['name'] == 'web-server'

    def test_unnamed_resource(self):
        """Kind without following name -> 'unnamed'."""
        diff = "kind: Service\n"
        result = diff_helpers.parse_kubernetes_diff("svc.yaml", diff)
        assert result['resources'][0]['name'] == 'unnamed'

    def test_multiple_documents(self):
        """Multiple kind entries -> multiple resources."""
        diff = "kind: Deployment\nname: app\n---\nkind: Service\nname: svc\n"
        result = diff_helpers.parse_kubernetes_diff("all.yaml", diff)
        assert len(result['resources']) == 2

    def test_fallback_to_generic(self):
        """No kind pattern -> generic resource."""
        diff = "+replicas: 3"
        result = diff_helpers.parse_kubernetes_diff("config.yaml", diff)
        assert result['resources'][0]['type'] == 'unknown'


class TestParseCloudFormationDiff:
    """Test parse_cloudformation_diff function."""

    def test_yaml_format(self):
        """Extracts resources from YAML CloudFormation."""
        diff = "WebServer:\n  Type: AWS::EC2::Instance\n"
        result = diff_helpers.parse_cloudformation_diff("template.yaml", diff)

        assert result['format'] == 'cloudformation'
        assert len(result['resources']) == 1
        assert result['resources'][0]['type'] == 'AWS::EC2::Instance'
        assert result['resources'][0]['name'] == 'WebServer'

    def test_json_format(self):
        """Extracts resources from JSON CloudFormation."""
        diff = '"WebServer": { "Type": "AWS::EC2::Instance" }'
        result = diff_helpers.parse_cloudformation_diff("template.json", diff)

        assert len(result['resources']) == 1
        assert result['resources'][0]['type'] == 'AWS::EC2::Instance'

    def test_fallback_to_generic(self):
        """No resource pattern -> generic resource."""
        diff = "+Description: My Stack"
        result = diff_helpers.parse_cloudformation_diff("template.yaml", diff)
        assert result['resources'][0]['type'] == 'unknown'

    def test_empty_diff(self):
        """Empty diff -> no resources."""
        result = diff_helpers.parse_cloudformation_diff("template.yaml", "")
        assert result['resources'] == []
