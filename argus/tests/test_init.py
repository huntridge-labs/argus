"""Tests for argus init — project detection and config generation."""

import pytest

from argus.cli import build_parser
from argus.init import (
    detect_project,
    generate_config,
    run_init,
    _guess_iac_path,
)


class TestInitParser:
    """Test parsing of the 'init' subcommand."""

    def test_init_default_args(self):
        parser = build_parser()
        args = parser.parse_args(["init"])
        assert args.command == "init"
        assert args.force is False
        assert args.no_detect is False

    def test_init_force_flag(self):
        parser = build_parser()
        args = parser.parse_args(["init", "--force"])
        assert args.force is True

    def test_init_no_detect_flag(self):
        parser = build_parser()
        args = parser.parse_args(["init", "--no-detect"])
        assert args.no_detect is True


class TestDetectProject:
    """Test project detection from directory contents."""

    def test_detect_empty_dir(self, tmp_path):
        signals = detect_project(tmp_path)
        assert signals == {}

    def test_detect_python_files(self, tmp_path):
        (tmp_path / "app.py").write_text("print('hello')")
        signals = detect_project(tmp_path)
        assert "python" in signals
        assert "app.py" in signals["python"]

    def test_detect_node_project(self, tmp_path):
        (tmp_path / "package.json").write_text("{}")
        signals = detect_project(tmp_path)
        assert "node" in signals

    def test_detect_dependency_lockfiles(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("flask==2.0")
        signals = detect_project(tmp_path)
        assert "dependencies" in signals
        assert "requirements.txt" in signals["dependencies"]

    def test_detect_package_lock_as_dependency(self, tmp_path):
        (tmp_path / "package-lock.json").write_text("{}")
        signals = detect_project(tmp_path)
        assert "dependencies" in signals
        assert "node" in signals

    def test_detect_dockerfile(self, tmp_path):
        (tmp_path / "Dockerfile").write_text("FROM alpine")
        signals = detect_project(tmp_path)
        assert "container" in signals
        assert "Dockerfile" in signals["container"]

    def test_detect_docker_compose(self, tmp_path):
        (tmp_path / "docker-compose.yml").write_text("version: '3'")
        signals = detect_project(tmp_path)
        assert "container" in signals

    def test_detect_terraform(self, tmp_path):
        (tmp_path / "main.tf").write_text('resource "aws_instance" {}')
        signals = detect_project(tmp_path)
        assert "iac" in signals

    def test_detect_iac_directory(self, tmp_path):
        (tmp_path / "infrastructure").mkdir()
        (tmp_path / "infrastructure" / "main.tf").write_text("")
        signals = detect_project(tmp_path)
        assert "iac" in signals

    def test_detect_github_actions(self, tmp_path):
        workflows = tmp_path / ".github" / "workflows"
        workflows.mkdir(parents=True)
        (workflows / "ci.yml").write_text("on: push")
        signals = detect_project(tmp_path)
        assert "github-actions" in signals

    def test_detect_multiple_signals(self, tmp_path):
        (tmp_path / "app.py").write_text("print('hello')")
        (tmp_path / "requirements.txt").write_text("flask==2.0")
        (tmp_path / "Dockerfile").write_text("FROM python:3.11")
        signals = detect_project(tmp_path)
        assert "python" in signals
        assert "dependencies" in signals
        assert "container" in signals


class TestGenerateConfig:
    """Test argus.yml content generation."""

    def test_generate_empty_signals(self):
        content = generate_config({})
        assert "yaml-language-server" in content
        assert 'version: "1.0"' in content
        assert "gitleaks:" in content
        assert "opengrep:" in content
        assert "severity_threshold: high" in content

    def test_generate_enables_bandit_for_python(self):
        signals = {"python": ["app.py"]}
        content = generate_config(signals)
        assert "bandit:" in content
        assert "# Detected: Python files found" in content

    def test_generate_enables_osv_for_dependencies(self):
        signals = {"dependencies": ["requirements.txt"]}
        content = generate_config(signals)
        assert "osv:" in content
        assert "# Detected: dependency manifests found" in content

    def test_generate_enables_supply_chain_for_github_actions(self):
        signals = {"github-actions": [".github/workflows/ci.yml"]}
        content = generate_config(signals)
        assert "supply-chain:" in content
        assert "# Detected: GitHub Actions workflows" in content

    def test_generate_enables_iac_scanners(self):
        signals = {"iac": ["infrastructure/main.tf"]}
        content = generate_config(signals)
        assert "trivy-iac:" in content
        assert "checkov:" in content
        assert "# Detected: infrastructure-as-code files" in content

    def test_generate_enables_container_scanner(self):
        signals = {"container": ["Dockerfile"]}
        content = generate_config(signals)
        assert "container:" in content
        assert "# Detected: container files" in content

    def test_generate_comments_zap(self):
        content = generate_config({})
        assert "# zap:" in content
        assert "# Enable for web application DAST" in content

    def test_generate_comments_clamav(self):
        content = generate_config({})
        assert "# clamav:" in content
        assert "# Enable for malware scanning" in content

    def test_generate_has_schema_reference(self):
        content = generate_config({})
        assert "argus-config.schema.json" in content

    def test_generate_has_docs_link(self):
        content = generate_config({})
        assert "huntridge-labs.github.io/argus" in content

    def test_generate_has_reporting_section(self):
        content = generate_config({})
        assert "reporting:" in content
        assert "- terminal" in content
        assert "- sarif" in content
        assert "output_dir:" in content

    def test_generate_has_execution_section(self):
        content = generate_config({})
        assert "execution:" in content
        assert "backend: auto" in content
        assert "pull_policy: if-not-present" in content


class TestGuessIacPath:
    """Test IaC path guessing logic."""

    def test_guess_infrastructure_dir(self):
        signals = {"iac": ["infrastructure/main.tf"]}
        assert _guess_iac_path(signals) == "infrastructure"

    def test_guess_terraform_dir(self):
        signals = {"iac": ["terraform/main.tf"]}
        assert _guess_iac_path(signals) == "terraform"

    def test_guess_fallback_to_dot(self):
        signals = {"iac": ["main.tf"]}
        assert _guess_iac_path(signals) == "."

    def test_guess_no_iac_signals(self):
        assert _guess_iac_path({}) == "."


class TestRunInit:
    """Test the full init workflow."""

    def test_creates_argus_yml(self, tmp_path):
        result = run_init(target_dir=str(tmp_path))
        assert result == 0
        assert (tmp_path / "argus.yml").exists()

    def test_refuses_overwrite_without_force(self, tmp_path):
        (tmp_path / "argus.yml").write_text("existing config")
        result = run_init(target_dir=str(tmp_path))
        assert result == 2
        assert (tmp_path / "argus.yml").read_text() == "existing config"

    def test_overwrites_with_force(self, tmp_path):
        (tmp_path / "argus.yml").write_text("old config")
        result = run_init(force=True, target_dir=str(tmp_path))
        assert result == 0
        content = (tmp_path / "argus.yml").read_text()
        assert "old config" not in content
        assert 'version: "1.0"' in content

    def test_detect_false_skips_detection(self, tmp_path):
        (tmp_path / "app.py").write_text("print('hello')")
        result = run_init(detect=False, target_dir=str(tmp_path))
        assert result == 0
        content = (tmp_path / "argus.yml").read_text()
        # bandit should be commented out since detection was skipped
        assert "# bandit:" in content

    def test_detect_true_finds_python(self, tmp_path):
        (tmp_path / "app.py").write_text("print('hello')")
        result = run_init(detect=True, target_dir=str(tmp_path))
        assert result == 0
        content = (tmp_path / "argus.yml").read_text()
        assert "bandit:" in content
        assert "Detected: Python files found" in content

    def test_generates_config_only(self, tmp_path):
        """init generates argus.yml only — no CI workflow files."""
        result = run_init(target_dir=str(tmp_path))
        assert result == 0
        assert (tmp_path / "argus.yml").exists()
        assert not (tmp_path / ".github" / "workflows").exists()
