"""Shared fixtures for docsite tests."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml


@pytest.fixture()
def tmp_repo(tmp_path: Path) -> Path:
    """Create a minimal fake Argus repo structure."""
    (tmp_path / ".github" / "actions" / "scanner-bandit").mkdir(parents=True)
    (tmp_path / ".github" / "actions" / "scanner-gitleaks").mkdir(parents=True)
    (tmp_path / ".github" / "actions" / "comment-pr").mkdir(parents=True)
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / "docs").mkdir()
    (tmp_path / "img").mkdir()
    (tmp_path / "version.yaml").write_text("0.5.0\n")
    (tmp_path / "README.md").write_text("# Argus\n\nTest readme.\n")

    # Minimal docsite.yml
    docsite_cfg = {
        "repo_url": "https://github.com/huntridge-labs/argus",
        "categories": {
            "sast": {"label": "SAST", "icon": "🔍"},
            "secrets": {"label": "Secrets Detection", "icon": "🔑"},
        },
        "excluded_actions": ["comment-pr"],
        "excluded_workflows": ["release"],
        "input_group_labels": {"codeql": "CodeQL"},
    }
    (tmp_path / "docsite.yml").write_text(
        yaml.dump(docsite_cfg, default_flow_style=False, allow_unicode=True),
    )

    # Per-action .docsite.yml files
    (tmp_path / ".github" / "actions" / "scanner-bandit" / ".docsite.yml").write_text(
        "category: sast\n",
    )
    (tmp_path / ".github" / "actions" / "scanner-bandit" / "action.yml").write_text(
        yaml.dump({
            "name": "Bandit Python Scanner",
            "description": "Run Bandit security linter on Python code.",
            "inputs": {
                "scan_path": {
                    "description": "Path to scan",
                    "required": False,
                    "default": ".",
                },
                "fail_on_severity": {
                    "description": "Fail on severity threshold",
                    "required": False,
                    "default": "none",
                },
            },
            "outputs": {
                "total_count": {"description": "Total findings", "value": "0"},
            },
            "runs": {"using": "composite", "steps": []},
        }),
    )
    (tmp_path / ".github" / "actions" / "scanner-bandit" / "README.md").write_text(
        "# Bandit Scanner\n\nScans Python code for vulnerabilities.\n",
    )

    (tmp_path / ".github" / "actions" / "scanner-gitleaks" / ".docsite.yml").write_text(
        "category: secrets\n",
    )
    (tmp_path / ".github" / "actions" / "scanner-gitleaks" / "action.yml").write_text(
        yaml.dump({
            "name": "Gitleaks Secrets Scanner",
            "description": "Detect secrets in git history.",
            "inputs": {},
            "outputs": {},
            "runs": {"using": "composite", "steps": []},
        }),
    )

    return tmp_path


@pytest.fixture()
def sample_workflow(tmp_repo: Path) -> Path:
    """Create a sample workflow YAML in the tmp repo."""
    wf_content = """\
# Security Scan Workflow
# Runs all security scanners
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:
  workflow_call:
    inputs:
      scanners:
        description: Scanners to run
        required: true
        type: string
    secrets:
      GITHUB_TOKEN:
        description: GitHub token
        required: true

permissions:
  contents: read
  security-events: write

jobs:
  bandit:
    name: Bandit Scanner
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: huntridge-labs/argus/.github/actions/scanner-bandit@0.5.0
        with:
          scan_path: src

  gitleaks:
    name: Gitleaks Scanner
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: huntridge-labs/argus/.github/actions/scanner-gitleaks@0.5.0

  summary:
    name: Security Summary
    needs: [bandit, gitleaks]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
    wf_path = tmp_repo / ".github" / "workflows" / "security-scan.yml"
    wf_path.write_text(wf_content)
    return wf_path
