#!/usr/bin/env python3
"""Unit tests for generate_container_summary.py using pytest."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit


# Get the scripts directory
SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"
SUMMARY_SCRIPT = SCRIPTS_DIR / "generate_container_summary.py"
TRIVY_PARSER = SCRIPTS_DIR / "parse_trivy_results.py"
GRYPE_PARSER = SCRIPTS_DIR / "parse_grype_results.py"

# Get fixtures directory
FIXTURES_DIR = (
    Path(__file__).parent.parent.parent.parent.parent
    / "tests" / "fixtures" / "scanner-outputs"
)

# Fixture files (validated once at module load)
TRIVY_WITH_FINDINGS = FIXTURES_DIR / "trivy" / "results-with-findings.json"
TRIVY_ZERO_FINDINGS = FIXTURES_DIR / "trivy" / "results-zero-findings.json"
GRYPE_WITH_FINDINGS = FIXTURES_DIR / "grype" / "results-with-findings.json"
GRYPE_ZERO_FINDINGS = FIXTURES_DIR / "grype" / "results-zero-findings.json"


def run_summary_generator(
    combined: bool = False,
    cwd: Path = None,
) -> tuple:
    """Run the summary generator script.

    Returns (returncode, stdout, stderr, github_output, summary_md).
    github_output is a dict of key=value pairs from GITHUB_OUTPUT.
    summary_md is the content of scanner-summaries/container.md.
    """
    env = os.environ.copy()
    env["TRIVY_PARSER"] = str(TRIVY_PARSER)
    env["GRYPE_PARSER"] = str(GRYPE_PARSER)

    # Always capture GITHUB_OUTPUT
    work_dir = cwd or Path(".")
    github_output_file = work_dir / "github_output"
    env["GITHUB_OUTPUT"] = str(github_output_file)

    cmd = [sys.executable, str(SUMMARY_SCRIPT)]
    if combined:
        cmd.append("--combined")

    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=30, env=env,
        cwd=str(cwd) if cwd else None,
    )

    # Parse GITHUB_OUTPUT into a dict
    github_output = {}
    if github_output_file.exists():
        for line in github_output_file.read_text().splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                github_output[key.strip()] = value.strip()

    # Read summary markdown
    summary_file = work_dir / "scanner-summaries" / "container.md"
    summary_md = (
        summary_file.read_text() if summary_file.exists() else ""
    )

    return (
        result.returncode, result.stdout, result.stderr,
        github_output, summary_md,
    )


class TestGenerateContainerSummary:
    """Test suite for generate_container_summary.py."""

    # ====== Tests for no results scenario ======

    def test_no_results_found(self, tmp_path):
        """Test when no container scan results are found."""
        rc, stdout, _, gh_out, summary_md = run_summary_generator(
            cwd=tmp_path,
        )

        assert rc == 0
        assert "No container scan results found" in stdout

        # Summary should indicate skipped
        assert "Skipped" in summary_md

        # All output counts should be zero
        assert gh_out["total_vulns"] == "0"
        assert gh_out["critical"] == "0"
        assert gh_out["high"] == "0"
        assert gh_out["containers_scanned"] == "0"

    # ====== Tests for single container ======

    def test_single_container_with_zero_vulns(self, tmp_path):
        """Test a single container with no vulnerabilities."""
        container_dir = tmp_path / "container-scan-results-alpine"
        container_dir.mkdir(parents=True)

        assert TRIVY_ZERO_FINDINGS.exists(), \
            f"Missing fixture: {TRIVY_ZERO_FINDINGS}"
        assert GRYPE_ZERO_FINDINGS.exists(), \
            f"Missing fixture: {GRYPE_ZERO_FINDINGS}"

        (container_dir / "trivy-alpine-results.json").write_text(
            TRIVY_ZERO_FINDINGS.read_text(),
        )
        (container_dir / "grype-alpine-results.json").write_text(
            GRYPE_ZERO_FINDINGS.read_text(),
        )

        rc, stdout, _, gh_out, summary_md = run_summary_generator(
            cwd=tmp_path,
        )

        assert rc == 0
        assert "0 vulns" in stdout

        # All counts must be zero
        assert gh_out["total_vulns"] == "0"
        assert gh_out["critical"] == "0"
        assert gh_out["high"] == "0"
        assert gh_out["containers_scanned"] == "1"

        assert "Container Security" in summary_md

    def test_single_container_with_vulns(self, tmp_path):
        """Test a single container with vulnerabilities."""
        container_dir = tmp_path / "container-scan-results-vulnerable"
        container_dir.mkdir(parents=True)

        assert TRIVY_WITH_FINDINGS.exists(), \
            f"Missing fixture: {TRIVY_WITH_FINDINGS}"
        assert GRYPE_WITH_FINDINGS.exists(), \
            f"Missing fixture: {GRYPE_WITH_FINDINGS}"

        (container_dir / "trivy-vulnerable-results.json").write_text(
            TRIVY_WITH_FINDINGS.read_text(),
        )
        (container_dir / "grype-vulnerable-results.json").write_text(
            GRYPE_WITH_FINDINGS.read_text(),
        )

        rc, stdout, _, gh_out, summary_md = run_summary_generator(
            cwd=tmp_path,
        )

        assert rc == 0

        # Vuln counts must be non-zero
        # Fixtures have 1 crit, 1 high, 1 med, 1 low each
        assert int(gh_out["total_vulns"]) > 0
        assert int(gh_out["critical"]) > 0
        assert int(gh_out["high"]) > 0
        assert gh_out["containers_scanned"] == "1"

        # Stdout should report actual vuln counts
        assert "0 vulns" not in stdout

        # Summary should contain both scanners and detailed findings
        assert "Detailed Findings" in summary_md
        assert "Trivy" in summary_md
        assert "Grype" in summary_md

    # ====== Tests for multiple containers ======

    def test_multiple_containers(self, tmp_path):
        """Test processing multiple containers."""
        assert TRIVY_ZERO_FINDINGS.exists(), \
            f"Missing fixture: {TRIVY_ZERO_FINDINGS}"

        for name in ["app1", "app2", "app3"]:
            cdir = tmp_path / f"container-scan-results-{name}"
            cdir.mkdir(parents=True)
            (cdir / f"trivy-{name}-results.json").write_text(
                TRIVY_ZERO_FINDINGS.read_text(),
            )

        rc, _, _, gh_out, summary_md = run_summary_generator(
            cwd=tmp_path,
        )

        assert rc == 0
        assert gh_out["containers_scanned"] == "3"

        # Breakdown table should list each container
        assert "Container Breakdown" in summary_md
        assert "app1" in summary_md
        assert "app2" in summary_md
        assert "app3" in summary_md

    # ====== Tests for failure scenarios ======

    def test_container_with_failed_scan(self, tmp_path):
        """Test handling of container with failed scan."""
        container_dir = tmp_path / "container-scan-results-failed"
        container_dir.mkdir(parents=True)

        status = container_dir / "scan-status.json"
        status.write_text(json.dumps({
            "status": "failed",
            "error": "Image pull failed",
        }))

        rc, _, _, gh_out, summary_md = run_summary_generator(
            cwd=tmp_path,
        )

        assert rc == 0

        # Failed containers shouldn't count as scanned
        assert gh_out["containers_scanned"] == "0"
        assert gh_out["total_vulns"] == "0"

        # Summary should show the failure with error message
        assert "Build Failed" in summary_md
        assert "Image pull failed" in summary_md

    def test_single_scanner_trivy_only(self, tmp_path):
        """Test container with only Trivy results."""
        assert TRIVY_WITH_FINDINGS.exists(), \
            f"Missing fixture: {TRIVY_WITH_FINDINGS}"

        container_dir = tmp_path / "container-scan-results-app"
        container_dir.mkdir(parents=True)
        (container_dir / "trivy-app-results.json").write_text(
            TRIVY_WITH_FINDINGS.read_text(),
        )

        rc, stdout, _, gh_out, summary_md = run_summary_generator(
            cwd=tmp_path,
        )

        assert rc == 0
        assert gh_out["containers_scanned"] == "1"
        assert int(gh_out["total_vulns"]) > 0

        # Should show Trivy findings, no Grype section
        assert "Trivy" in summary_md
        assert "0 vulns" not in stdout

    def test_single_scanner_grype_only(self, tmp_path):
        """Test container with only Grype results."""
        assert GRYPE_WITH_FINDINGS.exists(), \
            f"Missing fixture: {GRYPE_WITH_FINDINGS}"

        container_dir = tmp_path / "container-scan-results-app"
        container_dir.mkdir(parents=True)
        (container_dir / "grype-app-results.json").write_text(
            GRYPE_WITH_FINDINGS.read_text(),
        )

        rc, stdout, _, gh_out, summary_md = run_summary_generator(
            cwd=tmp_path,
        )

        assert rc == 0
        assert gh_out["containers_scanned"] == "1"
        assert int(gh_out["total_vulns"]) > 0

        # Should show Grype findings
        assert "Grype" in summary_md
        assert "0 vulns" not in stdout

    # ====== Tests for GITHUB_STEP_SUMMARY ======

    def test_step_summary_written(self, tmp_path):
        """Test that GITHUB_STEP_SUMMARY file is written."""
        assert TRIVY_WITH_FINDINGS.exists(), \
            f"Missing fixture: {TRIVY_WITH_FINDINGS}"

        container_dir = tmp_path / "container-scan-results-test"
        container_dir.mkdir(parents=True)
        (container_dir / "trivy-test-results.json").write_text(
            TRIVY_WITH_FINDINGS.read_text(),
        )

        step_summary_path = tmp_path / "step_summary.md"
        os.environ["GITHUB_STEP_SUMMARY"] = str(step_summary_path)

        try:
            rc, _, _, gh_out, _ = run_summary_generator(
                cwd=tmp_path,
            )
            assert rc == 0
            assert int(gh_out["total_vulns"]) > 0

            # Step summary should also be written
            assert step_summary_path.exists()
            step_content = step_summary_path.read_text()
            assert "Container Security" in step_content
        finally:
            os.environ.pop("GITHUB_STEP_SUMMARY", None)

    # ====== Tests for --combined flag ======

    def test_combined_flag_flat_layout(self, tmp_path):
        """Test --combined with flat directory layout."""
        assert TRIVY_WITH_FINDINGS.exists(), \
            f"Missing fixture: {TRIVY_WITH_FINDINGS}"

        container_dir = tmp_path / "container-scan-results-app"
        container_dir.mkdir(parents=True)
        (container_dir / "trivy-app-results.json").write_text(
            TRIVY_WITH_FINDINGS.read_text(),
        )

        rc, stdout, _, gh_out, summary_md = run_summary_generator(
            combined=True, cwd=tmp_path,
        )

        assert rc == 0

        # Vulns must be found even with --combined flag
        assert int(gh_out["total_vulns"]) > 0
        assert gh_out["containers_scanned"] == "1"
        assert "0 vulns" not in stdout

        # Combined header
        assert "Parallel Scan" in summary_md

    def test_combined_nested_artifact_directories(self, tmp_path):
        """Test parallel scan with nested artifact directories.

        In parallel scan mode, download-artifact@v4 with
        merge-multiple: false creates nested directories:
          container-scan-results-app-grype-12345-app-grype/
            container-scan-results-app/
              grype-app-results.json
          container-scan-results-app-trivy-12345-app-trivy/
            container-scan-results-app/
              trivy-app-results.json
        """
        assert TRIVY_WITH_FINDINGS.exists(), \
            f"Missing fixture: {TRIVY_WITH_FINDINGS}"
        assert GRYPE_WITH_FINDINGS.exists(), \
            f"Missing fixture: {GRYPE_WITH_FINDINGS}"

        # Simulate nested CI artifact structure
        grype_inner = (
            tmp_path
            / "container-scan-results-app-grype-12345-app-grype"
            / "container-scan-results-app"
        )
        grype_inner.mkdir(parents=True)

        trivy_inner = (
            tmp_path
            / "container-scan-results-app-trivy-12345-app-trivy"
            / "container-scan-results-app"
        )
        trivy_inner.mkdir(parents=True)

        (trivy_inner / "trivy-app-results.json").write_text(
            TRIVY_WITH_FINDINGS.read_text(),
        )
        (grype_inner / "grype-app-results.json").write_text(
            GRYPE_WITH_FINDINGS.read_text(),
        )

        rc, stdout, _, gh_out, summary_md = run_summary_generator(
            combined=True, cwd=tmp_path,
        )

        assert rc == 0

        # Vulns must be non-zero — this is the bug that was missed
        assert int(gh_out["total_vulns"]) > 0
        assert int(gh_out["critical"]) > 0
        assert int(gh_out["high"]) > 0
        assert gh_out["containers_scanned"] == "1"
        assert "0 vulns" not in stdout

        # Both scanners should appear in summary
        assert "Parallel Scan" in summary_md
        assert "Trivy" in summary_md
        assert "Grype" in summary_md

    def test_combined_nested_multiple_containers(self, tmp_path):
        """Test nested artifacts with multiple containers."""
        assert TRIVY_WITH_FINDINGS.exists(), \
            f"Missing fixture: {TRIVY_WITH_FINDINGS}"
        assert GRYPE_ZERO_FINDINGS.exists(), \
            f"Missing fixture: {GRYPE_ZERO_FINDINGS}"

        # Container "alpha" with trivy findings
        alpha_trivy = (
            tmp_path
            / "container-scan-results-alpha-trivy-999-alpha-trivy"
            / "container-scan-results-alpha"
        )
        alpha_trivy.mkdir(parents=True)
        (alpha_trivy / "trivy-alpha-results.json").write_text(
            TRIVY_WITH_FINDINGS.read_text(),
        )

        # Container "beta" with grype zero findings
        beta_grype = (
            tmp_path
            / "container-scan-results-beta-grype-999-beta-grype"
            / "container-scan-results-beta"
        )
        beta_grype.mkdir(parents=True)
        (beta_grype / "grype-beta-results.json").write_text(
            GRYPE_ZERO_FINDINGS.read_text(),
        )

        rc, _, _, gh_out, summary_md = run_summary_generator(
            combined=True, cwd=tmp_path,
        )

        assert rc == 0
        assert gh_out["containers_scanned"] == "2"

        # Alpha has vulns, beta does not
        assert int(gh_out["total_vulns"]) > 0

        # Both containers should appear in breakdown
        assert "Container Breakdown" in summary_md
        assert "alpha" in summary_md
        assert "beta" in summary_md

    # ====== Tests for summary content validation ======

    def test_summary_contains_severity_table(self, tmp_path):
        """Test that summary contains severity count table."""
        assert TRIVY_WITH_FINDINGS.exists(), \
            f"Missing fixture: {TRIVY_WITH_FINDINGS}"

        container_dir = tmp_path / "container-scan-results-test"
        container_dir.mkdir(parents=True)
        (container_dir / "trivy-test-results.json").write_text(
            TRIVY_WITH_FINDINGS.read_text(),
        )

        rc, _, _, gh_out, summary_md = run_summary_generator(
            cwd=tmp_path,
        )

        assert rc == 0
        assert int(gh_out["total_vulns"]) > 0

        # Should contain the severity table headers
        assert "Critical" in summary_md
        assert "High" in summary_md
        assert "Medium" in summary_md
        assert "Low" in summary_md
        assert "|" in summary_md  # Markdown table

    def test_container_names_and_sbom_filter(self, tmp_path):
        """Test that SBOM-only dirs are ignored."""
        assert TRIVY_ZERO_FINDINGS.exists(), \
            f"Missing fixture: {TRIVY_ZERO_FINDINGS}"

        # SBOM-only directory (should be ignored by filename pattern)
        sbom_dir = tmp_path / "container-scan-results-sbom-only"
        sbom_dir.mkdir(parents=True)
        (sbom_dir / "sbom.json").write_text('{"format": "spdx"}')

        # Real container
        container_name = "my-awesome-app"
        cdir = tmp_path / f"container-scan-results-{container_name}"
        cdir.mkdir(parents=True)
        (cdir / f"trivy-{container_name}-results.json").write_text(
            TRIVY_ZERO_FINDINGS.read_text(),
        )

        rc, _, _, gh_out, summary_md = run_summary_generator(
            cwd=tmp_path,
        )

        assert rc == 0
        assert gh_out["containers_scanned"] == "1"
        assert container_name in summary_md

    def test_missing_parser_env_var(self, tmp_path):
        """Test error handling when parser env vars are missing."""
        orig_trivy = os.environ.pop("TRIVY_PARSER", None)
        orig_grype = os.environ.pop("GRYPE_PARSER", None)

        try:
            cmd = [sys.executable, str(SUMMARY_SCRIPT)]
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=10, cwd=str(tmp_path),
            )
            assert result.returncode != 0
        finally:
            if orig_trivy:
                os.environ["TRIVY_PARSER"] = orig_trivy
            if orig_grype:
                os.environ["GRYPE_PARSER"] = orig_grype

    def test_summary_file_encoding(self, tmp_path):
        """Test that summary file contains valid UTF-8 emojis."""
        assert TRIVY_WITH_FINDINGS.exists(), \
            f"Missing fixture: {TRIVY_WITH_FINDINGS}"

        container_dir = tmp_path / "container-scan-results-test"
        container_dir.mkdir(parents=True)
        (container_dir / "trivy-test-results.json").write_text(
            TRIVY_WITH_FINDINGS.read_text(),
        )

        rc, _, _, _, summary_md = run_summary_generator(cwd=tmp_path)

        assert rc == 0
        assert "🐳" in summary_md


class TestEdgeCases:
    """Edge case tests for container summary generation."""

    def test_no_container_directories(self, tmp_path):
        """Test when no scan result directories exist."""
        rc, _, _, gh_out, summary_md = run_summary_generator(
            cwd=tmp_path,
        )
        assert rc == 0
        assert gh_out["containers_scanned"] == "0"

    def test_empty_container_directory(self, tmp_path):
        """Test with empty container directory (no scan files)."""
        container_dir = tmp_path / "container-scan-results-empty"
        container_dir.mkdir(parents=True)

        rc, _, _, gh_out, _ = run_summary_generator(cwd=tmp_path)

        assert rc == 0
        # Empty dir has no result files, so nothing discovered
        assert gh_out["containers_scanned"] == "0"

    def test_malformed_json_in_results(self, tmp_path):
        """Test with malformed JSON in results."""
        container_dir = tmp_path / "container-scan-results-bad"
        container_dir.mkdir(parents=True)
        (container_dir / "trivy-bad-results.json").write_text(
            "{invalid json",
        )

        rc, _, _, gh_out, _ = run_summary_generator(cwd=tmp_path)

        assert rc == 0
        # Malformed JSON should be handled gracefully
        assert gh_out["containers_scanned"] == "1"

    def test_many_containers(self, tmp_path):
        """Test with 10 containers."""
        assert TRIVY_ZERO_FINDINGS.exists(), \
            f"Missing fixture: {TRIVY_ZERO_FINDINGS}"

        for i in range(10):
            name = f"app{i:03d}"
            cdir = tmp_path / f"container-scan-results-{name}"
            cdir.mkdir(parents=True)
            (cdir / f"trivy-{name}-results.json").write_text(
                TRIVY_ZERO_FINDINGS.read_text(),
            )

        rc, _, _, gh_out, summary_md = run_summary_generator(
            cwd=tmp_path,
        )

        assert rc == 0
        assert gh_out["containers_scanned"] == "10"
        assert "Container Breakdown" in summary_md
