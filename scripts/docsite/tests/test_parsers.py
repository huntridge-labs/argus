"""Tests for docsite.parsers — workflow YAML parsing."""

from __future__ import annotations

from pathlib import Path

import pytest

from docsite.parsers import parse_workflow_full, parse_workflow_meta


class TestParseWorkflowFull:
    """Tests for parse_workflow_full()."""

    def test_extracts_name(self, sample_workflow: Path):
        result = parse_workflow_full(sample_workflow)
        assert result["name"] == "Security Scan"

    def test_extracts_header_comments(self, sample_workflow: Path):
        result = parse_workflow_full(sample_workflow)
        assert "Security Scan Workflow" in result["description"]
        assert "Runs all security scanners" in result["description"]

    def test_extracts_triggers(self, sample_workflow: Path):
        result = parse_workflow_full(sample_workflow)
        assert "push" in result["triggers"]
        assert "pull_request" in result["triggers"]
        assert "workflow_call" in result["triggers"]

    def test_extracts_inputs(self, sample_workflow: Path):
        result = parse_workflow_full(sample_workflow)
        assert "scanners" in result["inputs"]
        assert result["inputs"]["scanners"]["required"] is True

    def test_extracts_secrets(self, sample_workflow: Path):
        result = parse_workflow_full(sample_workflow)
        assert "GITHUB_TOKEN" in result["secrets"]

    def test_extracts_permissions(self, sample_workflow: Path):
        result = parse_workflow_full(sample_workflow)
        assert result["permissions"]["contents"] == "read"
        assert result["permissions"]["security-events"] == "write"

    def test_extracts_jobs(self, sample_workflow: Path):
        result = parse_workflow_full(sample_workflow)
        assert "bandit" in result["jobs"]
        assert "gitleaks" in result["jobs"]
        assert "summary" in result["jobs"]

    def test_extracts_job_needs(self, sample_workflow: Path):
        result = parse_workflow_full(sample_workflow)
        assert result["jobs"]["summary"]["needs"] == ["bandit", "gitleaks"]

    def test_extracts_used_actions(self, sample_workflow: Path):
        result = parse_workflow_full(sample_workflow)
        assert "scanner-bandit" in result["used_actions"]
        assert "scanner-gitleaks" in result["used_actions"]

    def test_extracts_job_actions_used(self, sample_workflow: Path):
        result = parse_workflow_full(sample_workflow)
        assert "scanner-bandit" in result["jobs"]["bandit"]["actions_used"]

    def test_handles_missing_file(self, tmp_path: Path):
        result = parse_workflow_full(tmp_path / "nonexistent.yml")
        assert result["name"] == "nonexistent"
        assert result["jobs"] == {}

    def test_handles_invalid_yaml(self, tmp_path: Path):
        bad = tmp_path / "bad.yml"
        bad.write_text(": : {{{\n")
        result = parse_workflow_full(bad)
        assert result["jobs"] == {}

    def test_handles_no_workflow_call(self, tmp_path: Path):
        wf = tmp_path / "simple.yml"
        wf.write_text("name: Simple\non:\n  push:\n    branches: [main]\njobs: {}\n")
        result = parse_workflow_full(wf)
        assert result["inputs"] == {}
        assert result["secrets"] == {}

    def test_handles_no_header_comments(self, tmp_path: Path):
        wf = tmp_path / "no-comments.yml"
        wf.write_text("name: No Comments\non:\n  push:\njobs: {}\n")
        result = parse_workflow_full(wf)
        assert result["description"] == ""


class TestParseWorkflowMeta:
    """Tests for parse_workflow_meta()."""

    def test_extracts_name(self, sample_workflow: Path):
        result = parse_workflow_meta(sample_workflow)
        assert result["name"] == "Security Scan"

    def test_fallback_to_stem(self, tmp_path: Path):
        wf = tmp_path / "my-workflow.yml"
        wf.write_text("")
        result = parse_workflow_meta(wf)
        assert result["name"] == "my-workflow"

    def test_handles_invalid_yaml(self, tmp_path: Path):
        wf = tmp_path / "bad.yml"
        wf.write_text(": : {{{\n")
        result = parse_workflow_meta(wf)
        assert result["name"] == "bad"
