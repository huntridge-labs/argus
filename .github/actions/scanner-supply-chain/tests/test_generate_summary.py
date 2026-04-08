"""Tests for supply chain scanner generate_summary.py."""

import importlib.util
import json
from pathlib import Path

import pytest

# Load module from file path
SCRIPT_DIR = Path(__file__).parent.parent / "scripts"
SUMMARY_SCRIPT = SCRIPT_DIR / "generate_summary.py"

spec = importlib.util.spec_from_file_location("generate_summary", SUMMARY_SCRIPT)
summary_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(summary_mod)


class TestIntOrZero:
    """Test _int_or_zero helper."""

    def test_valid_int(self):
        assert summary_mod._int_or_zero("5") == 5

    def test_zero(self):
        assert summary_mod._int_or_zero("0") == 0

    def test_empty_string(self):
        assert summary_mod._int_or_zero("") == 0

    def test_none(self):
        assert summary_mod._int_or_zero(None) == 0

    def test_whitespace(self):
        assert summary_mod._int_or_zero("  ") == 0

    def test_invalid(self):
        assert summary_mod._int_or_zero("abc") == 0


class TestLoadFindings:
    """Test findings file loading."""

    def test_valid_findings(self, tmp_path):
        findings = [{"rule": "test", "severity": "HIGH"}]
        f = tmp_path / "findings.json"
        f.write_text(json.dumps(findings))
        result = summary_mod._load_findings(str(f))
        assert len(result) == 1

    def test_empty_string(self):
        result = summary_mod._load_findings("")
        assert result == []

    def test_none(self):
        result = summary_mod._load_findings(None)
        assert result == []

    def test_nonexistent_file(self):
        result = summary_mod._load_findings("/nonexistent.json")
        assert result == []

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty.json"
        f.write_text("")
        result = summary_mod._load_findings(str(f))
        assert result == []

    def test_invalid_json_returns_none(self, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text("not json")
        result = summary_mod._load_findings(str(f))
        assert result is None

    def test_non_list_json_returns_none(self, tmp_path):
        f = tmp_path / "object.json"
        f.write_text('{"not": "a list"}')
        result = summary_mod._load_findings(str(f))
        assert result is None


class TestGenerateSummaryClean:
    """Test summary generation with no findings."""

    def test_clean_scan_pr_comment(self, tmp_path):
        output = tmp_path / "summary.md"
        summary_mod.generate_summary(
            str(output), "true", "", "0", "0", "0", "0",
            "https://github.com", "owner/repo", "123",
        )
        content = output.read_text()
        assert "<details>" in content
        assert "Supply Chain Security Scan" in content
        assert "No findings" in content
        assert "</details>" in content

    def test_clean_scan_step_summary(self, tmp_path):
        output = tmp_path / "summary.md"
        summary_mod.generate_summary(
            str(output), "false", "", "0", "0", "0", "0",
            "https://github.com", "owner/repo", "123",
        )
        content = output.read_text()
        assert "<details>" not in content
        assert "## " in content
        assert "No findings" in content

    def test_includes_report_link(self, tmp_path):
        output = tmp_path / "summary.md"
        summary_mod.generate_summary(
            str(output), "true", "", "0", "0", "0", "0",
            "https://github.com", "owner/repo", "456",
        )
        content = output.read_text()
        assert "https://github.com/owner/repo/actions/runs/456" in content


class TestGenerateSummaryWithFindings:
    """Test summary generation with findings."""

    @pytest.fixture
    def findings_file(self, tmp_path):
        findings = [
            {"rule": "template-injection", "severity": "HIGH", "confidence": "high",
             "description": "template injection via user-controlled input",
             "file": ".github/workflows/ci.yml", "line": 22, "source": "zizmor"},
            {"rule": "unpinned-uses", "severity": "MEDIUM", "confidence": "high",
             "description": "unpinned Action reference",
             "file": ".github/workflows/ci.yml", "line": 14, "source": "zizmor"},
            {"rule": "shellcheck", "severity": "MEDIUM", "confidence": "high",
             "description": "shellcheck reported issue",
             "file": ".github/workflows/ci.yml", "line": 18, "source": "actionlint"},
            {"rule": "ref-confusion", "severity": "LOW", "confidence": "low",
             "description": "symbolic ref used where commit SHA expected",
             "file": ".github/workflows/release.yml", "line": 30, "source": "zizmor"},
            {"rule": "github-env", "severity": "INFO", "confidence": "medium",
             "description": "GITHUB_ENV usage may allow injection",
             "file": ".github/workflows/ci.yml", "line": 45, "source": "zizmor"},
        ]
        f = tmp_path / "findings.json"
        f.write_text(json.dumps(findings))
        return str(f)

    def test_severity_table(self, tmp_path, findings_file):
        output = tmp_path / "summary.md"
        summary_mod.generate_summary(
            str(output), "true", findings_file, "1", "2", "1", "1",
            "https://github.com", "owner/repo", "123",
        )
        content = output.read_text()
        assert "| **1** | **2** | **1** | **1** | **5** |" in content

    def test_high_severity_warning(self, tmp_path, findings_file):
        output = tmp_path / "summary.md"
        summary_mod.generate_summary(
            str(output), "true", findings_file, "1", "2", "1", "1",
            "https://github.com", "owner/repo", "123",
        )
        content = output.read_text()
        assert "HIGH" in content
        assert "require immediate attention" in content

    def test_finding_details_present(self, tmp_path, findings_file):
        output = tmp_path / "summary.md"
        summary_mod.generate_summary(
            str(output), "true", findings_file, "1", "2", "1", "1",
            "https://github.com", "owner/repo", "123",
        )
        content = output.read_text()
        assert "Finding Details" in content
        assert "template-injection" in content
        assert "unpinned-uses" in content
        assert "zizmor" in content
        assert "actionlint" in content

    def test_severity_sections(self, tmp_path, findings_file):
        output = tmp_path / "summary.md"
        summary_mod.generate_summary(
            str(output), "true", findings_file, "1", "2", "1", "1",
            "https://github.com", "owner/repo", "123",
        )
        content = output.read_text()
        assert "HIGH Severity (1)" in content
        assert "MEDIUM Severity (2)" in content
        assert "LOW Severity (1)" in content
        assert "INFO Severity (1)" in content

    def test_high_section_open_by_default(self, tmp_path, findings_file):
        output = tmp_path / "summary.md"
        summary_mod.generate_summary(
            str(output), "true", findings_file, "1", "2", "1", "1",
            "https://github.com", "owner/repo", "123",
        )
        content = output.read_text()
        # HIGH section should be open
        high_idx = content.index("HIGH Severity")
        details_before = content[:high_idx].rfind("<details")
        assert "open" in content[details_before:high_idx]

    def test_status_findings_detected(self, tmp_path, findings_file):
        output = tmp_path / "summary.md"
        summary_mod.generate_summary(
            str(output), "true", findings_file, "1", "2", "1", "1",
            "https://github.com", "owner/repo", "123",
        )
        content = output.read_text()
        assert "Findings detected" in content

    def test_no_high_no_warning(self, tmp_path):
        findings = [
            {"rule": "test", "severity": "LOW", "file": "x.yml", "line": 1,
             "source": "zizmor", "description": "test", "confidence": "high"},
        ]
        f = tmp_path / "findings.json"
        f.write_text(json.dumps(findings))
        output = tmp_path / "summary.md"
        summary_mod.generate_summary(
            str(output), "true", str(f), "0", "0", "1", "0",
            "https://github.com", "owner/repo", "123",
        )
        content = output.read_text()
        assert "require immediate attention" not in content


class TestGenerateSummaryWithCorruptFindings:
    """Test summary generation when findings file is corrupted."""

    def test_corrupted_findings_shows_warning(self, tmp_path):
        bad_findings = tmp_path / "bad.json"
        bad_findings.write_text("not json")
        output = tmp_path / "summary.md"
        summary_mod.generate_summary(
            str(output), "true", str(bad_findings), "3", "2", "0", "0",
            "https://github.com", "owner/repo", "123",
        )
        content = output.read_text()
        assert "could not be loaded" in content
        assert "| **3** | **2** |" in content

    def test_step_summary_with_findings(self, tmp_path):
        findings = [
            {"rule": "test", "severity": "HIGH", "file": "x.yml", "line": 1,
             "source": "zizmor", "description": "test"},
        ]
        f = tmp_path / "findings.json"
        f.write_text(json.dumps(findings))
        output = tmp_path / "summary.md"
        summary_mod.generate_summary(
            str(output), "false", str(f), "1", "0", "0", "0",
            "https://github.com", "owner/repo", "123",
        )
        content = output.read_text()
        assert "## " in content
        assert "<details>" not in content or "Finding Details" in content
        assert "Findings detected" not in content  # Only in PR comment mode


class TestFindingTruncation:
    """Test truncation logic with many findings."""

    def test_truncation_shows_correct_remaining_count(self, tmp_path):
        # 60 HIGH findings — only 50 displayed, 10 remaining
        findings = [
            {"rule": f"rule-{i}", "severity": "HIGH", "file": "x.yml",
             "line": i, "source": "zizmor", "description": f"finding {i}"}
            for i in range(60)
        ]
        f = tmp_path / "findings.json"
        f.write_text(json.dumps(findings))
        output = tmp_path / "summary.md"
        summary_mod.generate_summary(
            str(output), "true", str(f), "60", "0", "0", "0",
            "https://github.com", "owner/repo", "123",
        )
        content = output.read_text()
        assert "... and 10 more findings" in content

    def test_no_truncation_when_under_limit(self, tmp_path):
        findings = [
            {"rule": f"rule-{i}", "severity": "HIGH", "file": "x.yml",
             "line": i, "source": "zizmor", "description": f"finding {i}"}
            for i in range(5)
        ]
        f = tmp_path / "findings.json"
        f.write_text(json.dumps(findings))
        output = tmp_path / "summary.md"
        summary_mod.generate_summary(
            str(output), "true", str(f), "5", "0", "0", "0",
            "https://github.com", "owner/repo", "123",
        )
        content = output.read_text()
        assert "more findings" not in content

    def test_multi_severity_truncation(self, tmp_path):
        # 40 HIGH + 40 MEDIUM = 80 total, 50+40=90 displayed? No: 40+40=80 < 50 per each
        # Both under per-severity limit, so all 80 displayed, 0 remaining
        findings = (
            [{"rule": f"h-{i}", "severity": "HIGH", "file": "x.yml",
              "line": i, "source": "zizmor", "description": f"high {i}"}
             for i in range(40)]
            + [{"rule": f"m-{i}", "severity": "MEDIUM", "file": "x.yml",
                "line": i, "source": "zizmor", "description": f"medium {i}"}
               for i in range(40)]
        )
        f = tmp_path / "findings.json"
        f.write_text(json.dumps(findings))
        output = tmp_path / "summary.md"
        summary_mod.generate_summary(
            str(output), "true", str(f), "40", "40", "0", "0",
            "https://github.com", "owner/repo", "123",
        )
        content = output.read_text()
        assert "more findings" not in content


class TestGenerateSummaryEdgeCases:
    """Test edge cases."""

    def test_empty_counts_treated_as_zero(self, tmp_path):
        output = tmp_path / "summary.md"
        summary_mod.generate_summary(
            str(output), "true", "", "", "", "", "",
            "https://github.com", "owner/repo", "123",
        )
        content = output.read_text()
        assert "No findings" in content

    def test_creates_parent_directories(self, tmp_path):
        output = tmp_path / "nested" / "dir" / "summary.md"
        summary_mod.generate_summary(
            str(output), "false", "", "0", "0", "0", "0",
            "https://github.com", "owner/repo", "123",
        )
        assert output.exists()

    def test_appends_to_existing_file(self, tmp_path):
        output = tmp_path / "summary.md"
        output.write_text("Existing content\n")
        summary_mod.generate_summary(
            str(output), "false", "", "0", "0", "0", "0",
            "https://github.com", "owner/repo", "123",
        )
        content = output.read_text()
        assert content.startswith("Existing content\n")
        assert "Supply Chain" in content

    def test_ghes_server_url(self, tmp_path):
        output = tmp_path / "summary.md"
        summary_mod.generate_summary(
            str(output), "true", "", "0", "0", "0", "0",
            "https://ghes.company.com", "org/repo", "789",
        )
        content = output.read_text()
        assert "https://ghes.company.com/org/repo/actions/runs/789" in content

    def test_large_counts(self, tmp_path):
        output = tmp_path / "summary.md"
        summary_mod.generate_summary(
            str(output), "true", "", "100", "200", "300", "50",
            "https://github.com", "owner/repo", "123",
        )
        content = output.read_text()
        assert "| **100** | **200** | **300** | **50** | **650** |" in content


class TestMainCLI:
    """Test CLI entry point."""

    def test_main_creates_output(self, tmp_path):
        output = tmp_path / "out.md"
        import sys
        old_argv = sys.argv
        sys.argv = [
            "generate_summary.py",
            "--output-file", str(output),
            "--is-pr-comment", "true",
            "--high", "1",
            "--medium", "2",
            "--low", "0",
            "--info", "0",
        ]
        try:
            summary_mod.main()
        finally:
            sys.argv = old_argv
        assert output.exists()
        content = output.read_text()
        assert "Supply Chain" in content
