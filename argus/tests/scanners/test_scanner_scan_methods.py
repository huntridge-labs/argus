"""Tests for scanner scan() and _build_command() methods with mocked subprocess.

Covers the ~30 percent of each scanner that parse_results tests do not reach:
command construction, subprocess invocation, and error handling.
"""

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from argus.core.models import Severity
from argus.core.scanner_template import ScanPaths
from argus.scanners.bandit import BanditScanner
from argus.scanners.clamav import ClamavScanner
from argus.scanners.checkov import CheckovScanner
from argus.scanners.gitleaks import GitleaksScanner
from argus.scanners.opengrep import OpengrepScanner
from argus.scanners.osv import OsvScanner


def _make_paths(tmp_path, filename="results.json"):
    """Build a ScanPaths for unit-testing build_args."""
    out = tmp_path / filename
    return ScanPaths(workspace="src/", output=str(out))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_BANDIT_FIXTURE = {
    "errors": [],
    "results": [
        {
            "test_id": "B102",
            "test_name": "exec_used",
            "issue_severity": "HIGH",
            "issue_confidence": "HIGH",
            "issue_text": "Use of exec detected.",
            "issue_cwe": {"id": 78},
            "filename": "app.py",
            "line_number": 5,
            "code": "exec(x)",
            "more_info": "",
        }
    ],
}

_GITLEAKS_FIXTURE = [
    {
        "Description": "GitHub PAT",
        "StartLine": 3,
        "EndLine": 3,
        "Match": "ghp_abc",
        "Secret": "ghp_abc",
        "File": "config.py",
        "Commit": "aaa",
        "Author": "dev",
        "RuleID": "github-pat",
    }
]

_OSV_FIXTURE = {
    "results": [
        {
            "source": {"path": "requirements.txt"},
            "packages": [
                {
                    "package": {
                        "name": "requests",
                        "version": "2.25.0",
                        "ecosystem": "PyPI",
                    },
                    "vulnerabilities": [
                        {
                            "id": "GHSA-xxxx",
                            "summary": "HTTP request smuggling",
                            "aliases": ["CVE-2023-9999"],
                            "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-444"]},
                        }
                    ],
                }
            ],
        }
    ]
}

_CHECKOV_FIXTURE = {
    "results": {
        "passed_checks": [],
        "failed_checks": [
            {
                "check_id": "CKV_AWS_1",
                "check_name": "Ensure S3 bucket has versioning",
                "check_result": {"result": "FAILED"},
                "file_path": "/main.tf",
                "file_line_range": [10, 20],
                "resource": "aws_s3_bucket.data",
                "guideline": "https://docs.example.com",
                "severity": "HIGH",
            }
        ],
    }
}

_OPENGREP_FIXTURE = {
    "results": [
        {
            "check_id": "python.security.dangerous-exec",
            "path": "app.py",
            "start": {"line": 7, "col": 1},
            "end": {"line": 7, "col": 20},
            "extra": {
                "severity": "ERROR",
                "message": "Avoid dangerous code execution",
                "metadata": {"cwe": ["CWE-95"], "owasp": [], "category": "security"},
            },
        }
    ]
}

_CLAMAV_DETAIL_OUTPUT = (
    "/workspace/evil.exe: Win.Trojan.Test-123 FOUND\n"
    "/workspace/clean.txt: OK\n"
)

_CLAMAV_SUMMARY_OUTPUT = (
    "/workspace/evil.exe: Win.Trojan.Test-123 FOUND\n"
    "/workspace/clean.txt: OK\n"
    "\n"
    "----------- SCAN SUMMARY -----------\n"
    "Known viruses: 100\n"
    "Scanned files: 2\n"
    "Infected files: 1\n"
)


def _completed_process(stdout="", stderr="", returncode=0):
    """Build a CompletedProcess stub."""
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=stderr,
    )


def _write_fixture(path: Path, data):
    """Write JSON fixture data to a file, creating parent dirs."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))


# =====================================================================
# Bandit
# =====================================================================

class TestBanditBuildArgs:
    """Test BanditScanner.build_args construction."""

    def test_base_command(self, tmp_path):
        scanner = BanditScanner()
        paths = _make_paths(tmp_path)
        cmd = scanner.build_args(paths, {})

        assert cmd[0] == "bandit"
        assert "-r" in cmd
        assert paths.workspace in cmd
        assert "--exit-zero" in cmd

    def test_includes_config_file(self, tmp_path):
        scanner = BanditScanner()
        paths = _make_paths(tmp_path)
        cmd = scanner.build_args(paths, {"config_file": ".bandit.yml"})

        assert "-c" in cmd
        assert ".bandit.yml" in " ".join(cmd)

    def test_includes_exclude(self, tmp_path):
        scanner = BanditScanner()
        paths = _make_paths(tmp_path)
        cmd = scanner.build_args(paths, {"exclude": "tests/"})

        assert "--exclude" in cmd
        assert "tests/" in cmd


class TestBanditScan:
    """Test BanditScanner.scan() with mocked subprocess."""

    def test_successful_scan(self, monkeypatch, tmp_path):
        scanner = BanditScanner()

        def fake_run(cmd, **kwargs):
            output_idx = cmd.index("-o") + 1
            output_path = Path(cmd[output_idx])
            _write_fixture(output_path, _BANDIT_FIXTURE)
            return _completed_process()

        monkeypatch.setattr(subprocess, "run", fake_run)
        result = scanner.scan("src/")

        assert result.scanner == "bandit"
        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.HIGH

    def test_scan_failure(self, monkeypatch):
        scanner = BanditScanner()

        def fake_run(cmd, **kwargs):
            return _completed_process(
                returncode=2, stderr="bandit: error: no such file",
            )

        monkeypatch.setattr(subprocess, "run", fake_run)
        result = scanner.scan("nonexistent/")

        assert result.scanner == "bandit"
        assert result.metadata.get("execution_failed") is True


# =====================================================================
# ClamAV
# =====================================================================

class TestClamavScan:
    """Test ClamavScanner.scan() with mocked subprocess."""

    def test_successful_scan(self, monkeypatch):
        scanner = ClamavScanner()
        call_count = {"n": 0}

        def fake_run(cmd, **kwargs):
            call_count["n"] += 1
            if "--no-summary" in cmd:
                return _completed_process(stdout=_CLAMAV_DETAIL_OUTPUT)
            return _completed_process(stdout=_CLAMAV_SUMMARY_OUTPUT)

        monkeypatch.setattr(subprocess, "run", fake_run)
        result = scanner.scan("/workspace")

        assert result.scanner == "clamav"
        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.CRITICAL
        assert "infected_files" in result.metadata
        # ClamAV calls subprocess.run twice (detail + summary)
        assert call_count["n"] == 2


# =====================================================================
# Gitleaks
# =====================================================================

class TestGitleaksBuildArgs:
    """Test GitleaksScanner.build_args construction."""

    def test_base_command(self, tmp_path):
        scanner = GitleaksScanner()
        paths = _make_paths(tmp_path)
        cmd = scanner.build_args(paths, {})

        assert cmd[0] == "gitleaks"
        assert "detect" in cmd
        assert "--exit-code" in cmd

    def test_includes_config_file(self, tmp_path):
        scanner = GitleaksScanner()
        paths = _make_paths(tmp_path)
        cmd = scanner.build_args(paths, {"config_file": ".gitleaks.toml"})

        assert "--config" in cmd
        assert ".gitleaks.toml" in " ".join(cmd)


class TestGitleaksScan:
    """Test GitleaksScanner.scan() with mocked subprocess."""

    def test_successful_scan(self, monkeypatch):
        scanner = GitleaksScanner()

        def fake_run(cmd, **kwargs):
            output_idx = cmd.index("--report-path") + 1
            output_path = Path(cmd[output_idx])
            _write_fixture(output_path, _GITLEAKS_FIXTURE)
            return _completed_process()

        monkeypatch.setattr(subprocess, "run", fake_run)
        result = scanner.scan(".")

        assert result.scanner == "gitleaks"
        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.HIGH

    def test_scan_failure(self, monkeypatch):
        scanner = GitleaksScanner()

        def fake_run(cmd, **kwargs):
            return _completed_process(returncode=1, stderr="fatal error")

        monkeypatch.setattr(subprocess, "run", fake_run)
        result = scanner.scan(".")

        assert result.scanner == "gitleaks"
        assert result.metadata.get("execution_failed") is True


# =====================================================================
# OSV
# =====================================================================

class TestOsvBuildArgs:
    """Test OsvScanner.build_args construction."""

    def test_base_command(self, tmp_path):
        out = str(tmp_path / "out.json")
        paths = ScanPaths(workspace=".", output=out)
        cmd = OsvScanner().build_args(paths, {})

        assert cmd[0] == "osv-scanner"
        assert "scan" in cmd
        assert "--format" in cmd

    def test_includes_config_file(self, tmp_path):
        out = str(tmp_path / "out.json")
        paths = ScanPaths(workspace=".", output=out)
        cmd = OsvScanner().build_args(paths, {"config_file": "osv.toml"})

        assert "--config" in cmd
        assert "osv.toml" in " ".join(cmd)


class TestOsvScan:
    """Test OsvScanner.scan() with mocked subprocess."""

    def test_successful_scan(self, monkeypatch):
        scanner = OsvScanner()

        def fake_run(cmd, **kwargs):
            # build_args uses --output-file (osv-scanner v2 API)
            output_idx = cmd.index("--output-file") + 1
            output_path = Path(cmd[output_idx])
            _write_fixture(output_path, _OSV_FIXTURE)
            return _completed_process()

        monkeypatch.setattr(subprocess, "run", fake_run)
        result = scanner.scan(".")

        assert result.scanner == "osv"
        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.HIGH

    def test_scan_failure_no_output(self, monkeypatch):
        scanner = OsvScanner()

        def fake_run(cmd, **kwargs):
            return _completed_process(returncode=1, stderr="network error")

        monkeypatch.setattr(subprocess, "run", fake_run)
        result = scanner.scan(".")

        assert result.scanner == "osv"
        assert result.metadata.get("execution_failed") is True


# =====================================================================
# Checkov
# =====================================================================

class TestCheckovBuildArgs:
    """Test CheckovScanner.build_args construction."""

    def test_base_command(self, tmp_path):
        scanner = CheckovScanner()
        paths = _make_paths(tmp_path)
        cmd = scanner.build_args(paths, {})

        assert cmd[0] == "checkov"
        assert "-d" in cmd
        assert paths.workspace in cmd
        assert "--quiet" in cmd

    def test_includes_framework(self, tmp_path):
        scanner = CheckovScanner()
        paths = _make_paths(tmp_path)
        cmd = scanner.build_args(paths, {"framework": "terraform"})

        assert "--framework" in cmd
        assert "terraform" in cmd

    def test_includes_check_and_skip_check(self, tmp_path):
        scanner = CheckovScanner()
        paths = _make_paths(tmp_path)
        cmd = scanner.build_args(paths, {
            "check": "CKV_AWS_1",
            "skip_check": "CKV_AWS_2",
        })

        assert "--check" in cmd
        assert "CKV_AWS_1" in cmd
        assert "--skip-check" in cmd
        assert "CKV_AWS_2" in cmd


class TestCheckovScan:
    """Test CheckovScanner.scan() with mocked subprocess."""

    def test_successful_scan(self, monkeypatch):
        scanner = CheckovScanner()

        def fake_run(cmd, **kwargs):
            return _completed_process(
                stdout=json.dumps(_CHECKOV_FIXTURE),
            )

        monkeypatch.setattr(subprocess, "run", fake_run)
        result = scanner.scan(".")

        assert result.scanner == "checkov"
        assert len(result.findings) == 1
        assert result.findings[0].id == "CKV_AWS_1"
        assert result.metadata.get("passed_count") == 0

    def test_scan_failure(self, monkeypatch):
        scanner = CheckovScanner()

        def fake_run(cmd, **kwargs):
            return _completed_process(
                returncode=2, stdout="", stderr="checkov crashed",
            )

        monkeypatch.setattr(subprocess, "run", fake_run)
        result = scanner.scan(".")

        assert result.scanner == "checkov"
        assert result.metadata.get("execution_failed") is True

    def test_scan_no_output(self, monkeypatch):
        scanner = CheckovScanner()

        def fake_run(cmd, **kwargs):
            return _completed_process(stdout="", stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)
        result = scanner.scan(".")

        assert result.scanner == "checkov"
        assert result.metadata.get("execution_failed") is True


# =====================================================================
# OpenGrep
# =====================================================================

class TestOpengrepBuildArgs:
    """Test OpengrepScanner.build_args construction."""

    def test_base_command(self, tmp_path):
        scanner = OpengrepScanner()
        paths = _make_paths(tmp_path)
        cmd = scanner.build_args(paths, {})

        assert cmd[0] == "opengrep"
        assert "--json" in cmd
        assert paths.workspace in cmd

    def test_includes_config(self, tmp_path):
        scanner = OpengrepScanner()
        paths = _make_paths(tmp_path)
        cmd = scanner.build_args(paths, {"config": "p/python"})

        assert "--config" in cmd
        assert "p/python" in cmd


class TestOpengrepScan:
    """Test OpengrepScanner.scan() with mocked subprocess."""

    def test_successful_scan(self, monkeypatch):
        scanner = OpengrepScanner()

        def fake_run(cmd, **kwargs):
            output_idx = cmd.index("--output") + 1
            output_path = Path(cmd[output_idx])
            _write_fixture(output_path, _OPENGREP_FIXTURE)
            return _completed_process()

        monkeypatch.setattr(subprocess, "run", fake_run)
        result = scanner.scan("src/")

        assert result.scanner == "opengrep"
        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.HIGH

    def test_scan_failure_no_output(self, monkeypatch):
        scanner = OpengrepScanner()

        def fake_run(cmd, **kwargs):
            return _completed_process(returncode=1, stderr="opengrep error")

        monkeypatch.setattr(subprocess, "run", fake_run)
        result = scanner.scan(".")

        assert result.scanner == "opengrep"
        assert result.metadata.get("execution_failed") is True
