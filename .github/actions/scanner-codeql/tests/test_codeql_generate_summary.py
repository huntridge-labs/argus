#!/usr/bin/env python3
"""
Unit tests for scanner-codeql/scripts/generate_summary.py
Tests markdown generation for CodeQL SAST scan results

Uses in-process imports instead of subprocess for fast execution.
"""

import argparse
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

pytestmark = pytest.mark.unit

# Paths
REPO_ROOT = Path(__file__).parent.parent.parent.parent.parent
SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"
GENERATOR_SCRIPT = SCRIPTS_DIR / "generate_summary.py"
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "scanner-outputs" / "codeql"

# Load module in-process via importlib
spec = importlib.util.spec_from_file_location(
    "codeql_generate_summary", GENERATOR_SCRIPT,
)
gen_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gen_mod)


def _run_in_process(
    workspace,
    output_file,
    is_pr_comment="false",
    language="python",
    critical="0",
    high="0",
    medium="0",
    low="0",
    total="0",
    repo_url="https://github.com/test/repo/blob/main",
    server_url="https://github.com",
    repository="test/repo",
    run_id="12345",
):
    """Run generate_codeql_summary in-process, returning a result-like object."""
    original_dir = os.getcwd()
    try:
        os.chdir(workspace)
        gen_mod.generate_codeql_summary(
            output_file,
            is_pr_comment,
            language,
            critical,
            high,
            medium,
            low,
            total,
            repo_url,
            server_url,
            repository,
            run_id,
        )
        return SimpleNamespace(returncode=0, stdout="", stderr="")
    except SystemExit as e:
        return SimpleNamespace(returncode=e.code or 1, stdout="", stderr="")
    except Exception as e:
        return SimpleNamespace(returncode=1, stdout="", stderr=str(e))
    finally:
        os.chdir(original_dir)


class TestCodeQLGenerateSummary:
    """Test cases for scanner-codeql generate_summary.py"""

    @pytest.fixture(autouse=True)
    def setup(self, tmp_path):
        """Set up test workspace for each test."""
        self.workspace = tmp_path
        self.codeql_reports = tmp_path / "codeql-reports"
        self.sarif_dir = self.codeql_reports / "sarif"
        self.sarif_dir.mkdir(parents=True)
        self.output_file = tmp_path / "summary.md"

    def run_generator(self, **kwargs):
        """Helper to run the generator in-process."""
        kwargs.setdefault("output_file", str(self.output_file))
        return _run_in_process(self.workspace, **kwargs)

    def test_script_and_fixtures_exist(self):
        """Verify generator script and fixtures exist."""
        assert GENERATOR_SCRIPT.exists(), f"Script not found: {GENERATOR_SCRIPT}"
        assert FIXTURES_DIR.exists(), f"Fixtures not found: {FIXTURES_DIR}"
        assert (FIXTURES_DIR / "results-with-findings.sarif").exists()
        assert (FIXTURES_DIR / "results-zero-findings.sarif").exists()

    def test_generates_summary_with_findings(self):
        """Test generating summary with findings (tests language, format, severity grouping)."""
        shutil.copy(
            FIXTURES_DIR / "results-with-findings.sarif",
            self.sarif_dir / "python.sarif",
        )

        result = self.run_generator(
            language="python",
            critical="0",
            high="2",
            medium="1",
            low="0",
            total="3",
            is_pr_comment="false",
        )

        assert result.returncode == 0, f"Script failed: {result.stderr}"
        assert self.output_file.exists(), "Output file not created"

        content = self.output_file.read_text()

        assert "CodeQL SAST" in content
        assert "python" in content.lower()
        assert "Findings Summary" in content
        assert "## 🔬 CodeQL SAST Scan (Python)" in content
        assert "Python" in content

    def test_generates_summary_zero_findings(self):
        """Test generating summary with zero findings."""
        shutil.copy(
            FIXTURES_DIR / "results-zero-findings.sarif",
            self.sarif_dir / "python.sarif",
        )

        result = self.run_generator(
            language="python",
            critical="0",
            high="0",
            medium="0",
            low="0",
            total="0",
        )

        assert result.returncode == 0
        assert self.output_file.exists()

        content = self.output_file.read_text()
        assert "No security findings" in content

    def test_pr_comment_format_collapsible(self):
        """Test PR comment format uses collapsible sections."""
        shutil.copy(
            FIXTURES_DIR / "results-with-findings.sarif",
            self.sarif_dir / "python.sarif",
        )

        result = self.run_generator(
            is_pr_comment="true",
            language="python",
            total="3",
        )

        assert result.returncode == 0
        content = self.output_file.read_text()

        assert "<details>" in content
        assert "<summary>" in content
        assert "</details>" in content

    def test_critical_severity_message(self):
        """Test CRITICAL severity priority message appears."""
        shutil.copy(
            FIXTURES_DIR / "results-with-findings.sarif",
            self.sarif_dir / "python.sarif",
        )

        result = self.run_generator(
            language="python",
            critical="2",
            total="2",
        )

        assert result.returncode == 0
        content = self.output_file.read_text()
        assert "CRITICAL" in content
        assert "2 critical-severity findings" in content

    def test_finding_details_section(self):
        """Test finding details section is present with findings."""
        shutil.copy(
            FIXTURES_DIR / "results-with-findings.sarif",
            self.sarif_dir / "python.sarif",
        )

        result = self.run_generator(
            language="python",
            high="2",
            medium="1",
            total="3",
        )

        assert result.returncode == 0
        content = self.output_file.read_text()

        assert "Finding Details" in content
        assert "Severity" in content
        assert "Rule" in content
        assert "Location" in content

    def test_artifact_link_present(self):
        """Test artifact link is present in output."""
        shutil.copy(
            FIXTURES_DIR / "results-with-findings.sarif",
            self.sarif_dir / "python.sarif",
        )

        result = self.run_generator(
            language="python",
            repository="test/repo",
            run_id="12345",
            total="3",
        )

        assert result.returncode == 0
        content = self.output_file.read_text()
        assert "https://github.com/test/repo/actions/runs/12345" in content

    def test_handles_no_sarif_directory(self):
        """Test handles missing SARIF directory gracefully."""
        shutil.rmtree(self.sarif_dir)

        result = self.run_generator(
            language="python",
            total="0",
        )

        assert result.returncode == 0
        assert self.output_file.exists()

        content = self.output_file.read_text()
        assert "CodeQL" in content

    def test_summary_table_format(self):
        """Test summary table has correct format."""
        shutil.copy(
            FIXTURES_DIR / "results-with-findings.sarif",
            self.sarif_dir / "python.sarif",
        )

        result = self.run_generator(
            language="python",
            critical="1",
            high="2",
            medium="3",
            low="4",
            total="10",
        )

        assert result.returncode == 0
        content = self.output_file.read_text()

        assert "| Critical | High | Medium | Low | Total |" in content
        assert "| **1** | **2** | **3** | **4** | **10** |" in content


class TestEdgeCases:
    """Edge case tests for CodeQL summary generation."""

    @pytest.fixture(autouse=True)
    def setup(self, tmp_path):
        """Set up test workspace for each test."""
        self.workspace = tmp_path
        self.codeql_reports = tmp_path / "codeql-reports"
        self.sarif_dir = self.codeql_reports / "sarif"
        self.sarif_dir.mkdir(parents=True)
        self.output_file = tmp_path / "summary.md"

    def run_generator(self, **kwargs):
        """Helper to run the generator in-process."""
        kwargs.setdefault("output_file", str(self.output_file))
        return _run_in_process(self.workspace, **kwargs)

    def test_malformed_sarif_file(self):
        """Test with malformed SARIF JSON file."""
        bad_sarif = self.sarif_dir / "broken.sarif"
        bad_sarif.write_text("{invalid json content")

        result = self.run_generator(language="python", total="0")
        assert result.returncode == 0
        assert self.output_file.exists()

    def test_sarif_with_no_runs(self):
        """Test SARIF file with empty runs array."""
        sarif_file = self.sarif_dir / "python.sarif"
        sarif_file.write_text(json.dumps({"runs": []}))

        result = self.run_generator(language="python", total="0")
        assert result.returncode == 0
        assert self.output_file.exists()

    def test_sarif_with_no_results(self):
        """Test SARIF run with no results field."""
        sarif_file = self.sarif_dir / "python.sarif"
        sarif_file.write_text(json.dumps({
            "runs": [{"tool": {"driver": {"name": "CodeQL"}}}]
        }))

        result = self.run_generator(language="python", total="0")
        assert result.returncode == 0
        assert self.output_file.exists()

    def test_all_critical_findings(self):
        """Test with all critical findings."""
        result = self.run_generator(
            language="python",
            critical="5",
            high="0",
            medium="0",
            low="0",
            total="5",
        )
        assert result.returncode == 0
        content = self.output_file.read_text()
        assert "CRITICAL" in content
        assert "5 critical-severity findings" in content

    def test_very_large_counts(self):
        """Test with very large vulnerability counts."""
        result = self.run_generator(
            language="python",
            critical="9999",
            high="9999",
            medium="9999",
            low="9999",
            total="39996",
        )
        assert result.returncode == 0
        content = self.output_file.read_text()
        assert "9999" in content

    def test_sarif_with_empty_locations(self):
        """Test SARIF result with empty locations array."""
        sarif_file = self.sarif_dir / "python.sarif"
        sarif_file.write_text(json.dumps({
            "runs": [{
                "tool": {"driver": {"name": "CodeQL"}},
                "results": [{
                    "level": "error",
                    "locations": []
                }]
            }]
        }))

        result = self.run_generator(language="python", critical="1", total="1")
        assert result.returncode == 0
        assert self.output_file.exists()

    def test_sarif_missing_level_field(self):
        """Test SARIF result missing level field."""
        sarif_file = self.sarif_dir / "python.sarif"
        sarif_file.write_text(json.dumps({
            "runs": [{
                "tool": {"driver": {"name": "CodeQL"}},
                "results": [{
                    "ruleId": "py/test",
                    "message": {"text": "Test finding"},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": "test.py"}}}]
                }]
            }]
        }))

        result = self.run_generator(language="python", total="1")
        assert result.returncode == 0
        assert self.output_file.exists()

    def test_pr_comment_with_zero_findings(self):
        """Test PR comment format with zero findings."""
        result = self.run_generator(
            is_pr_comment="true",
            language="python",
            total="0",
        )
        assert result.returncode == 0
        content = self.output_file.read_text()
        assert "<details>" in content
        assert "<summary>" in content


class TestEmptyCountArgs:
    """Regression tests for the `invalid int value: ''` summary crash.

    When an earlier step (Initialize CodeQL / Autobuild / Perform CodeQL
    Analysis) fails, `Parse results` is skipped and GitHub expands its outputs
    to the empty string.  `Generate scanner summary` is `if: always()`, so it
    still ran and invoked this script with `--critical ""`.

    These tests go through main()/argparse rather than calling
    generate_codeql_summary() directly -- the pre-existing zero-findings and
    no-SARIF tests pass literal "0" strings straight to the function, which is
    why the argparse-layer crash was invisible to them.
    """

    @pytest.fixture(autouse=True)
    def setup(self, tmp_path, monkeypatch):
        self.workspace = tmp_path
        (tmp_path / "codeql-reports" / "sarif").mkdir(parents=True)
        self.output_file = tmp_path / "summary.md"
        monkeypatch.chdir(tmp_path)

    def run_main(self, monkeypatch, argv_extra):
        """Invoke main() with a synthetic argv, returning the exit code."""
        argv = ["generate_summary.py", str(self.output_file)] + argv_extra
        monkeypatch.setattr(sys, "argv", argv)
        try:
            gen_mod.main()
        except SystemExit as e:
            return e.code if e.code is not None else 0
        return 0

    def test_all_count_flags_empty_does_not_crash(self, monkeypatch):
        """The exact consumer-facing failure: every count flag passed as ''."""
        code = self.run_main(
            monkeypatch,
            [
                "--is-pr-comment", "true",
                "--language", "python",
                "--critical", "",
                "--high", "",
                "--medium", "",
                "--low", "",
                "--total", "",
                "--repo-url", "https://github.com/test/repo/blob/main",
                "--server-url", "https://github.com",
                "--repository", "test/repo",
                "--run-id", "12345",
            ],
        )

        assert code == 0, "empty count flags must not abort the summary step"
        assert self.output_file.exists()
        assert "CodeQL" in self.output_file.read_text()

    @pytest.mark.parametrize("flag", ["--critical", "--high", "--medium", "--low", "--total"])
    def test_single_empty_count_flag_does_not_crash(self, monkeypatch, flag):
        """One flag empty and the rest populated -- each flag independently."""
        argv = ["--language", "python"]
        for f in ("--critical", "--high", "--medium", "--low", "--total"):
            argv += [f, "" if f == flag else "3"]

        assert self.run_main(monkeypatch, argv) == 0
        assert self.output_file.exists()

    def test_whitespace_count_flag_treated_as_zero(self, monkeypatch):
        """Whitespace-only values coerce to 0 rather than raising."""
        assert self.run_main(monkeypatch, ["--critical", "   ", "--total", " "]) == 0
        assert self.output_file.exists()

    def test_malformed_count_flag_still_rejected(self, monkeypatch):
        """Non-numeric junk must still be an error -- do not paper over parse bugs."""
        code = self.run_main(monkeypatch, ["--critical", "abc"])
        assert code == 2, "malformed counts should still fail argparse"

    def test_parse_count_helper(self):
        """Direct coverage of the coercion helper."""
        assert gen_mod.parse_count("") == 0
        assert gen_mod.parse_count("   ") == 0
        assert gen_mod.parse_count(None) == 0
        assert gen_mod.parse_count("7") == 7
        assert gen_mod.parse_count(" 7 ") == 7
        assert gen_mod.parse_count(7) == 7
        with pytest.raises(argparse.ArgumentTypeError):
            gen_mod.parse_count("abc")

    def test_empty_counts_with_failed_scan_status_are_not_reported_clean(self, monkeypatch):
        """Empty counts + a did-not-run scan must not render as 'no findings'."""
        code = self.run_main(
            monkeypatch,
            [
                "--language", "python",
                "--critical", "", "--high", "", "--medium", "",
                "--low", "", "--total", "",
                "--scan-status", "failed",
            ],
        )

        assert code == 0
        content = self.output_file.read_text()
        assert "did not complete" in content
        assert "No security findings detected" not in content

    def test_successful_zero_finding_scan_still_reports_clean(self, monkeypatch):
        """The happy path is unchanged: a real scan with 0 findings reads clean."""
        code = self.run_main(
            monkeypatch,
            [
                "--language", "python",
                "--critical", "0", "--high", "0", "--medium", "0",
                "--low", "0", "--total", "0",
                "--scan-status", "success",
            ],
        )

        assert code == 0
        content = self.output_file.read_text()
        assert "No security findings detected" in content
        assert "did not complete" not in content

    def test_scan_status_defaults_to_success(self, monkeypatch):
        """Omitting --scan-status keeps the pre-existing behaviour."""
        assert self.run_main(monkeypatch, ["--language", "python", "--total", "0"]) == 0
        assert "did not complete" not in self.output_file.read_text()


ACTION_YML = Path(__file__).parent.parent / "action.yml"


def _step_script(step_name):
    """Return a runnable bash body for a named step in action.yml.

    ``${{ ... }}`` expressions are neutralised so the script can be executed
    outside of GitHub Actions; every value the tests care about arrives via
    the step's ``env:`` block instead.
    """
    action = yaml.safe_load(ACTION_YML.read_text())
    for step in action["runs"]["steps"]:
        if step.get("name") == step_name:
            return re.sub(r"\$\{\{[^}]*\}\}", "EXPR", step["run"])
    raise AssertionError(f"step not found in action.yml: {step_name}")


class TestStepScriptHelper:
    """The action.yml step loader must fail loudly, not silently."""

    def test_unknown_step_name_raises(self):
        """A renamed step in action.yml must break these tests, not skip them."""
        with pytest.raises(AssertionError, match="step not found in action.yml"):
            _step_script("No Such Step")

    def test_expressions_are_neutralised(self):
        """`${{ ... }}` must not survive into the script handed to bash."""
        assert "${{" not in _step_script("Check severity threshold")


class TestParseResultsScanStatus:
    """`Parse results` must report whether the analysis actually ran."""

    def run_parse(self, workspace, analyze_outcome, organize_outcome, sarif=None):
        github_output = workspace / "github_output.txt"
        github_output.touch()

        if sarif is not None:
            sarif_dir = workspace / "codeql-reports" / "sarif"
            sarif_dir.mkdir(parents=True, exist_ok=True)
            (sarif_dir / "python.sarif").write_text(json.dumps(sarif))

        env = {
            **os.environ,
            "LANGUAGE": "python",
            "ANALYZE_OUTCOME": analyze_outcome,
            "ORGANIZE_OUTCOME": organize_outcome,
            "GITHUB_OUTPUT": str(github_output),
        }
        proc = subprocess.run(
            ["bash", "-c", _step_script("Parse results")],
            cwd=workspace, env=env, capture_output=True, text=True,
        )
        outputs = dict(
            line.split("=", 1)
            for line in github_output.read_text().splitlines()
            if "=" in line
        )
        return proc, outputs

    def test_step_is_always_run(self):
        """Without `if: always()` the step is skipped and its outputs go empty."""
        action = yaml.safe_load(ACTION_YML.read_text())
        step = next(
            s for s in action["runs"]["steps"] if s.get("id") == "parse-results"
        )
        assert step.get("if") == "always()"

    def test_scan_status_success_when_analysis_completed(self, tmp_path):
        _, outputs = self.run_parse(
            tmp_path, "success", "success",
            sarif={"runs": [{"tool": {"driver": {"rules": []}}, "results": []}]},
        )
        assert outputs["scan_status"] == "success"
        assert outputs["total_count"] == "0"

    def test_scan_status_failed_when_analyze_skipped(self, tmp_path):
        """Initialize CodeQL / Autobuild failed -> analyze never ran."""
        _, outputs = self.run_parse(tmp_path, "skipped", "skipped")
        assert outputs["scan_status"] == "failed"

    def test_scan_status_failed_when_analyze_failed(self, tmp_path):
        _, outputs = self.run_parse(tmp_path, "failure", "success")
        assert outputs["scan_status"] == "failed"

    def test_scan_status_failed_when_no_sarif_produced(self, tmp_path):
        """A 'successful' analysis that emitted no SARIF is not trustworthy."""
        _, outputs = self.run_parse(tmp_path, "success", "success", sarif=None)
        assert outputs["scan_status"] == "failed"

    def test_exits_cleanly_with_absent_sarif_directory(self, tmp_path):
        """`if: always()` is only safe if the step survives a missing SARIF dir."""
        proc, outputs = self.run_parse(tmp_path, "skipped", "skipped")
        assert proc.returncode == 0, proc.stderr
        assert outputs["critical_count"] == "0"
        assert outputs["total_count"] == "0"

    def test_exits_cleanly_with_empty_sarif_directory(self, tmp_path):
        (tmp_path / "codeql-reports" / "sarif").mkdir(parents=True)
        proc, outputs = self.run_parse(tmp_path, "success", "success")
        assert proc.returncode == 0, proc.stderr
        assert outputs["total_count"] == "0"


class TestSeverityGate:
    """`Check severity threshold` must not pass a scan that did not run."""

    def run_gate(self, threshold="high", scan_status="success",
                 critical="0", high="0", medium="0", low="0"):
        env = {
            **os.environ,
            "FAIL_ON_SEVERITY": threshold,
            "SCAN_STATUS": scan_status,
            "CRITICAL_COUNT": critical,
            "HIGH_COUNT": high,
            "MEDIUM_COUNT": medium,
            "LOW_COUNT": low,
        }
        return subprocess.run(
            ["bash", "-c", _step_script("Check severity threshold")],
            env=env, capture_output=True, text=True,
        )

    def test_gate_is_always_run(self):
        """A failed Initialize/Autobuild must not be able to skip the gate."""
        action = yaml.safe_load(ACTION_YML.read_text())
        step = next(
            s for s in action["runs"]["steps"]
            if s.get("name") == "Check severity threshold"
        )
        assert step["if"].startswith("always() &&")

    def test_passes_when_scan_ran_and_found_nothing(self):
        proc = self.run_gate(scan_status="success")
        assert proc.returncode == 0, proc.stdout + proc.stderr

    def test_fails_when_scan_did_not_run(self):
        """The false-green case: zero findings because nothing was scanned."""
        proc = self.run_gate(scan_status="failed")
        assert proc.returncode == 1
        assert "did not complete" in proc.stdout + proc.stderr

    def test_fails_when_scan_status_is_empty(self):
        """`Parse results` itself skipped -> its outputs expand to ''."""
        proc = self.run_gate(scan_status="")
        assert proc.returncode == 1
        assert "unknown" in proc.stdout + proc.stderr

    def test_empty_counts_cannot_produce_a_silent_pass(self):
        """Guard the exact shape that used to slip through the `&&` list."""
        proc = self.run_gate(
            scan_status="", critical="", high="", medium="", low="",
        )
        assert proc.returncode == 1

    def test_fails_on_findings_at_threshold(self):
        proc = self.run_gate(scan_status="success", high="1")
        assert proc.returncode == 1
        assert "at or above" in proc.stdout + proc.stderr

    def test_findings_below_threshold_pass(self):
        proc = self.run_gate(threshold="critical", scan_status="success", high="4")
        assert proc.returncode == 0, proc.stdout + proc.stderr


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
