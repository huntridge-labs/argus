"""Tests for docsite.__main__ — CLI entry point."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest


class TestCLI:
    """Tests for the CLI entry point."""

    def test_validate_passes_valid_repo(self, tmp_repo: Path):
        result = subprocess.run(
            [sys.executable, "-m", "docsite", "--repo-root", str(tmp_repo), "--validate"],
            capture_output=True,
            text=True,
            cwd=str(Path(__file__).resolve().parent.parent.parent),
        )
        assert result.returncode == 0
        assert "valid" in result.stdout.lower()

    def test_validate_fails_invalid_repo(self, tmp_path: Path):
        (tmp_path / ".github").mkdir()
        result = subprocess.run(
            [sys.executable, "-m", "docsite", "--repo-root", str(tmp_path), "--validate"],
            capture_output=True,
            text=True,
            cwd=str(Path(__file__).resolve().parent.parent.parent),
        )
        assert result.returncode != 0

    def test_rejects_non_repo_dir(self, tmp_path: Path):
        result = subprocess.run(
            [sys.executable, "-m", "docsite", "--repo-root", str(tmp_path), "--validate"],
            capture_output=True,
            text=True,
            cwd=str(Path(__file__).resolve().parent.parent.parent),
        )
        assert result.returncode != 0
        assert ".github not found" in result.stdout

    def test_build_creates_output(self, tmp_repo: Path, tmp_path: Path):
        out = tmp_path / "cli-output"
        result = subprocess.run(
            [
                sys.executable, "-m", "docsite",
                "--repo-root", str(tmp_repo),
                "--output-dir", str(out),
            ],
            capture_output=True,
            text=True,
            cwd=str(Path(__file__).resolve().parent.parent.parent),
        )
        assert result.returncode == 0
        assert (out / "mkdocs.yml").exists()
        assert (out / "docs" / "index.md").exists()
