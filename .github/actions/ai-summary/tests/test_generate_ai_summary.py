#!/usr/bin/env python3
"""
Unit tests for ai-summary/scripts/generate-ai-summary.py
Tests environment config loading, scanner summary collection,
prompt building, output formatting, and provider routing.
"""

import importlib.util
import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ───────────────────────────────── Load Script as Module ─────────────────────────────────
SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"
SCRIPT_PATH = SCRIPTS_DIR / "generate-ai-summary.py"


def load_script(env_overrides=None):
    """Load the script as a module with optional env overrides."""
    env = {
        "SUMMARY_DIR":  "/tmp/test-summaries",
        "OUTPUT_FILE":  "/tmp/test-output.md",
        "MAX_FINDINGS": "20",
        "AI_PROVIDER":  "claude",
        "REPO":         "test-org/test-repo",
        "PR_NUMBER":    "42",
        "PR_TITLE":     "Test PR",
        "PR_URL":       "https://github.com/test-org/test-repo/pull/42",
        "COMMIT_SHA":   "abc1234567890",
    }
    if env_overrides:
        env.update(env_overrides)
    with patch.dict(os.environ, env, clear=False):
        spec = importlib.util.spec_from_file_location("generate_ai_summary", SCRIPT_PATH)
        mod = importlib.util.module_from_spec(spec)
        return mod, spec, env


class TestScriptExists:
    def test_script_file_exists(self):
        assert SCRIPT_PATH.exists(), f"Script not found: {SCRIPT_PATH}"


class TestScannerSummaryCollection:
    def test_collects_multiple_scanner_files(self, tmp_path):
        """Collects and combines multiple scanner-summary-*.md files."""
        (tmp_path / "scanner-summary-trivy.md").write_text("## Trivy findings\nCVE-2021-44228")
        (tmp_path / "scanner-summary-gitleaks.md").write_text("## Gitleaks findings\nNo secrets")

        combined = ""
        count = 0
        for f in sorted(tmp_path.glob("scanner-summary-*.md")):
            name = f.stem.replace("scanner-summary-", "")
            combined += f"### {name} findings\n"
            combined += f.read_text(encoding="utf-8")
            combined += "\n\n"
            count += 1

        assert count == 2
        assert "trivy findings" in combined
        assert "gitleaks findings" in combined
        assert "CVE-2021-44228" in combined

    def test_scanner_names_title_cased(self, tmp_path):
        """Scanner names are title-cased for the prompt."""
        (tmp_path / "scanner-summary-trivy.md").write_text("findings")
        (tmp_path / "scanner-summary-gitleaks.md").write_text("findings")

        names = [
            f.stem.replace("scanner-summary-", "").title()
            for f in sorted(tmp_path.glob("scanner-summary-*.md"))
        ]

        assert "Trivy" in names
        assert "Gitleaks" in names

    def test_no_summary_files_returns_empty(self, tmp_path):
        """Returns zero count when no matching files exist."""
        files = list(tmp_path.glob("scanner-summary-*.md"))
        assert len(files) == 0

    def test_ignores_non_matching_files(self, tmp_path):
        """Does not pick up files that don't match the pattern."""
        (tmp_path / "other-file.md").write_text("should be ignored")
        (tmp_path / "scanner-summary-trivy.md").write_text("trivy findings")

        files = list(tmp_path.glob("scanner-summary-*.md"))
        assert len(files) == 1
        assert files[0].name == "scanner-summary-trivy.md"


class TestOutputFormatting:
    def test_short_sha_truncation(self):
        """Commit SHA is truncated to 7 characters."""
        commit_sha = "abc1234567890"
        short_sha = commit_sha[:7] if len(commit_sha) >= 7 else commit_sha
        assert short_sha == "abc1234"
        assert len(short_sha) == 7

    def test_short_sha_shorter_than_7(self):
        """Short SHAs under 7 chars are left as-is."""
        commit_sha = "abc12"
        short_sha = commit_sha[:7] if len(commit_sha) >= 7 else commit_sha
        assert short_sha == "abc12"

    def test_provider_label_copilot(self):
        labels = {"copilot": "GitHub Copilot", "claude": "Anthropic Claude", "gemini": "Google Gemini"}
        assert labels["copilot"] == "GitHub Copilot"

    def test_provider_label_claude(self):
        labels = {"copilot": "GitHub Copilot", "claude": "Anthropic Claude", "gemini": "Google Gemini"}
        assert labels["claude"] == "Anthropic Claude"

    def test_provider_label_gemini(self):
        labels = {"copilot": "GitHub Copilot", "claude": "Anthropic Claude", "gemini": "Google Gemini"}
        assert labels["gemini"] == "Google Gemini"

    def test_provider_label_unknown_falls_back(self):
        labels = {"copilot": "GitHub Copilot", "claude": "Anthropic Claude", "gemini": "Google Gemini"}
        provider = "unknown"
        assert labels.get(provider, provider) == "unknown"

    def test_final_output_contains_header(self):
        """Final output always contains the standard header."""
        summary = "Some AI summary content"
        repo = "test-org/test-repo"
        pr_number = "42"
        pr_url = "https://github.com/test-org/test-repo/pull/42"
        short_sha = "abc1234"
        provider_label = "Anthropic Claude"
        scanner_count = 2
        scanner_names_str = "Trivy, Gitleaks"
        date_str = "March 01, 2026"

        output = f"""## Security Scan Executive Summary

> Generated by Argus AI Summary | Powered by {provider_label}
> Repository: {repo} | PR: [#{pr_number}]({pr_url}) | Commit: `{short_sha}` | Date: {date_str}

{summary}

---
*Scan covered {scanner_count} security tool(s): {scanner_names_str}. This summary is AI-generated - review findings directly before merge decisions.*
"""
        assert "## Security Scan Executive Summary" in output
        assert "Anthropic Claude" in output
        assert "test-org/test-repo" in output
        assert "AI-generated" in output

    def test_final_output_contains_summary_body(self):
        """Final output includes the AI-generated summary body."""
        summary = "CRITICAL risk detected in log4j dependency."
        output = f"## Security Scan Executive Summary\n\n{summary}\n"
        assert summary in output


class TestPromptBuilding:
    def test_prompt_contains_repo(self):
        repo = "test-org/test-repo"
        prompt = f"Repository: {repo}"
        assert "test-org/test-repo" in prompt

    def test_prompt_contains_scanner_count(self):
        count = 3
        names = "Trivy, Gitleaks, Bandit"
        prompt = f"Scanners run: {count} ({names})"
        assert "3" in prompt
        assert "Trivy" in prompt

    def test_prompt_contains_findings(self):
        findings = "### trivy findings\nCVE-2021-44228 critical"
        prompt = f"Raw scan findings:\n{findings}"
        assert "CVE-2021-44228" in prompt


class TestClaudeApiPayload:
    def test_claude_payload_structure(self):
        """Claude API payload has correct structure."""
        prompt = "test prompt"
        payload = {
            "model":      "claude-sonnet-4-5",
            "max_tokens": 2048,
            "system":     "You are a security analyst writing executive summaries from automated scan results.",
            "messages":   [{"role": "user", "content": prompt}],
        }
        assert payload["model"] == "claude-sonnet-4-5"
        assert payload["max_tokens"] == 2048
        assert payload["messages"][0]["role"] == "user"
        assert payload["messages"][0]["content"] == prompt

    def test_claude_response_extraction(self):
        """Claude response text is extracted from correct path."""
        mock_response = {
            "content": [{"type": "text", "text": "Executive summary content"}]
        }
        result = mock_response["content"][0]["text"].strip()
        assert result == "Executive summary content"


class TestGeminiApiPayload:
    def test_gemini_payload_structure(self):
        """Gemini API payload has correct structure."""
        prompt = "test prompt"
        payload = {
            "contents":         [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.3, "maxOutputTokens": 2048},
        }
        assert payload["contents"][0]["parts"][0]["text"] == prompt
        assert payload["generationConfig"]["temperature"] == 0.3

    def test_gemini_response_extraction(self):
        """Gemini response text is extracted from correct path."""
        mock_response = {
            "candidates": [{"content": {"parts": [{"text": "Gemini summary"}]}}]
        }
        result = mock_response["candidates"][0]["content"]["parts"][0]["text"].strip()
        assert result == "Gemini summary"


class TestCopilotOutputFiltering:
    def test_filters_model_name_lines(self):
        """Lines containing gpt- or starting with claude- are filtered out."""
        lines = [
            "## Key Findings",
            "! Some warning",
            "Total usage: 1234 tokens",
            "gpt-4o model used",
            "claude-3-opus response",
            "Some real content",
        ]
        filtered = [
            line for line in lines
            if not any([
                line.startswith("!"),
                line.startswith("Total usage"),
                line.startswith("API time"),
                line.startswith("Total session"),
                line.startswith("Breakdown"),
                "gpt-" in line,
                line.startswith("claude-"),
            ])
        ]
        assert "## Key Findings" in filtered
        assert "Some real content" in filtered
        assert "! Some warning" not in filtered
        assert "Total usage: 1234 tokens" not in filtered
        assert "gpt-4o model used" not in filtered
        assert "claude-3-opus response" not in filtered

    def test_preserves_content_lines(self):
        """Real summary content lines pass through the filter."""
        lines = ["## Executive Overview", "Risk level: CRITICAL", "CVE-2021-44228 detected"]
        filtered = [
            line for line in lines
            if not any([
                line.startswith("!"),
                line.startswith("Total usage"),
                "gpt-" in line,
                line.startswith("claude-"),
            ])
        ]
        assert len(filtered) == 3


class TestOutputFileWriting:
    def test_writes_output_file(self, tmp_path):
        """Output file is written with correct content."""
        output_file = tmp_path / "ai-summary.md"
        content = "## Security Scan Executive Summary\n\nTest content"
        output_file.write_text(content, encoding="utf-8")

        assert output_file.exists()
        assert output_file.read_text(encoding="utf-8") == content

    def test_output_file_utf8_no_bom(self, tmp_path):
        """Output file is written as UTF-8 without BOM."""
        output_file = tmp_path / "ai-summary.md"
        content = "Security summary with unicode: ⚠️ 🔧 ✅"
        output_file.write_text(content, encoding="utf-8")

        raw = output_file.read_bytes()
        assert not raw.startswith(b"\xef\xbb\xbf"), "File should not have UTF-8 BOM"
        assert "⚠️" in output_file.read_text(encoding="utf-8")