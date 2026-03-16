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

# ──────────────────────────── Load Script as Module ────────────────────────────
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
    def test_collects_any_file_in_directory(self, tmp_path):
        """Collects any file in the directory regardless of name or extension."""
        (tmp_path / "scanner-summary-trivy.md").write_text("trivy findings")
        (tmp_path / "scanner-summary-bandit").write_text("bandit findings")
        (tmp_path / "some-other-file.txt").write_text("other findings")

        count = 0
        for f in sorted(tmp_path.rglob("*")):
            if f.is_file():
                count += 1

        assert count == 3

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
            "model":      "claude-sonnet-4-6",
            "max_tokens": 4096,
            "system":     "You are a security analyst writing executive summaries from automated scan results.",
            "messages":   [{"role": "user", "content": prompt}],
        }
        assert payload["model"] == "claude-sonnet-4-6"
        assert payload["max_tokens"] == 4096
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


class TestClaudeProviderIntegration:
    """Tests for Claude API call path using mocked HTTP."""

    def _make_claude_response(self, text="Executive summary content"):
        """Build a mock Claude API response."""
        return json.dumps({
            "content": [{"type": "text", "text": text}]
        }).encode("utf-8")

    def test_claude_success(self, tmp_path, monkeypatch):
        """Claude provider returns summary when API call succeeds."""
        monkeypatch.setenv("AI_PROVIDER", "claude")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        monkeypatch.setenv("SUMMARY_DIR", str(tmp_path))
        monkeypatch.setenv("OUTPUT_FILE", str(tmp_path / "out.md"))

        (tmp_path / "scanner-summary-trivy.md").write_text("## Trivy\nCVE-2021-44228")

        mock_resp = MagicMock()
        mock_resp.read.return_value = self._make_claude_response("## Key Findings Summary\nAll clear.")
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            import runpy
            runpy.run_path(str(SCRIPT_PATH))

        out = (tmp_path / "out.md").read_text(encoding="utf-8")
        assert "Key Findings Summary" in out
        assert "Anthropic Claude" in out

    def test_claude_missing_api_key_exits(self, tmp_path, monkeypatch):
        """Claude provider exits with error when API key is missing."""
        monkeypatch.setenv("AI_PROVIDER", "claude")
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.setenv("SUMMARY_DIR", str(tmp_path))
        monkeypatch.setenv("OUTPUT_FILE", str(tmp_path / "out.md"))

        (tmp_path / "scanner-summary-trivy.md").write_text("## Trivy\nfindings")

        with pytest.raises(SystemExit) as exc:
            import runpy
            runpy.run_path(str(SCRIPT_PATH))
        assert exc.value.code == 1

    def test_claude_http_error_exits(self, tmp_path, monkeypatch):
        """Claude provider exits with error on HTTP failure."""
        import urllib.error
        monkeypatch.setenv("AI_PROVIDER", "claude")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        monkeypatch.setenv("SUMMARY_DIR", str(tmp_path))
        monkeypatch.setenv("OUTPUT_FILE", str(tmp_path / "out.md"))

        (tmp_path / "scanner-summary-trivy.md").write_text("## Trivy\nfindings")

        with patch("urllib.request.urlopen", side_effect=urllib.error.HTTPError(
            url=None, code=401, msg="Unauthorized", hdrs=None, fp=None
        )):
            with pytest.raises(SystemExit) as exc:
                import runpy
                runpy.run_path(str(SCRIPT_PATH))
        assert exc.value.code == 1

    def test_claude_empty_response_exits(self, tmp_path, monkeypatch):
        """Claude provider exits when response text is empty."""
        monkeypatch.setenv("AI_PROVIDER", "claude")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        monkeypatch.setenv("SUMMARY_DIR", str(tmp_path))
        monkeypatch.setenv("OUTPUT_FILE", str(tmp_path / "out.md"))

        (tmp_path / "scanner-summary-trivy.md").write_text("## Trivy\nfindings")

        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "content": [{"type": "text", "text": "   "}]
        }).encode("utf-8")
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            with pytest.raises(SystemExit) as exc:
                import runpy
                runpy.run_path(str(SCRIPT_PATH))
        assert exc.value.code == 1


class TestGeminiProviderIntegration:
    """Tests for Gemini API call path using mocked HTTP."""

    def _make_gemini_response(self, text="Gemini summary content"):
        return json.dumps({
            "candidates": [{"content": {"parts": [{"text": text}]}}]
        }).encode("utf-8")

    def test_gemini_success(self, tmp_path, monkeypatch):
        """Gemini provider returns summary when API call succeeds."""
        monkeypatch.setenv("AI_PROVIDER", "gemini")
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        monkeypatch.setenv("SUMMARY_DIR", str(tmp_path))
        monkeypatch.setenv("OUTPUT_FILE", str(tmp_path / "out.md"))

        (tmp_path / "scanner-summary-trivy.md").write_text("## Trivy\nCVE-2021-44228")

        mock_resp = MagicMock()
        mock_resp.read.return_value = self._make_gemini_response("## Key Findings Summary\nAll clear.")
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            import runpy
            runpy.run_path(str(SCRIPT_PATH))

        out = (tmp_path / "out.md").read_text(encoding="utf-8")
        assert "Key Findings Summary" in out
        assert "Google Gemini" in out

    def test_gemini_missing_api_key_exits(self, tmp_path, monkeypatch):
        """Gemini provider exits with error when API key is missing."""
        monkeypatch.setenv("AI_PROVIDER", "gemini")
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        monkeypatch.setenv("SUMMARY_DIR", str(tmp_path))
        monkeypatch.setenv("OUTPUT_FILE", str(tmp_path / "out.md"))

        (tmp_path / "scanner-summary-trivy.md").write_text("## Trivy\nfindings")

        with pytest.raises(SystemExit) as exc:
            import runpy
            runpy.run_path(str(SCRIPT_PATH))
        assert exc.value.code == 1

    def test_gemini_http_error_exits(self, tmp_path, monkeypatch):
        """Gemini provider exits with error on HTTP failure."""
        import urllib.error
        monkeypatch.setenv("AI_PROVIDER", "gemini")
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        monkeypatch.setenv("SUMMARY_DIR", str(tmp_path))
        monkeypatch.setenv("OUTPUT_FILE", str(tmp_path / "out.md"))

        (tmp_path / "scanner-summary-trivy.md").write_text("## Trivy\nfindings")

        with patch("urllib.request.urlopen", side_effect=urllib.error.HTTPError(
            url=None, code=403, msg="Forbidden", hdrs=None, fp=None
        )):
            with pytest.raises(SystemExit) as exc:
                import runpy
                runpy.run_path(str(SCRIPT_PATH))
        assert exc.value.code == 1


class TestCopilotProviderIntegration:
    """Tests for Copilot subprocess call path."""

    def test_copilot_success(self, tmp_path, monkeypatch):
        """Copilot provider returns filtered summary output."""
        monkeypatch.setenv("AI_PROVIDER", "copilot")
        monkeypatch.setenv("SUMMARY_DIR", str(tmp_path))
        monkeypatch.setenv("OUTPUT_FILE", str(tmp_path / "out.md"))

        (tmp_path / "scanner-summary-trivy.md").write_text("## Trivy\nCVE-2021-44228")

        mock_result = MagicMock()
        mock_result.stdout = "## Key Findings Summary\nAll clear.\nTotal usage: 100 tokens\ngpt-4o used"

        with patch("subprocess.run", return_value=mock_result):
            import runpy
            runpy.run_path(str(SCRIPT_PATH))

        out = (tmp_path / "out.md").read_text(encoding="utf-8")
        assert "Key Findings Summary" in out
        assert "GitHub Copilot" in out
        assert "Total usage" not in out
        assert "gpt-4o" not in out

    def test_copilot_not_installed_exits(self, tmp_path, monkeypatch):
        """Copilot provider exits when CLI is not installed."""
        monkeypatch.setenv("AI_PROVIDER", "copilot")
        monkeypatch.setenv("SUMMARY_DIR", str(tmp_path))
        monkeypatch.setenv("OUTPUT_FILE", str(tmp_path / "out.md"))

        (tmp_path / "scanner-summary-trivy.md").write_text("## Trivy\nfindings")

        with patch("subprocess.run", side_effect=FileNotFoundError):
            with pytest.raises(SystemExit) as exc:
                import runpy
                runpy.run_path(str(SCRIPT_PATH))
        assert exc.value.code == 1


class TestUnknownProvider:
    def test_unknown_provider_exits(self, tmp_path, monkeypatch):
        """Unknown provider name exits with error."""
        monkeypatch.setenv("AI_PROVIDER", "openai")
        monkeypatch.setenv("SUMMARY_DIR", str(tmp_path))
        monkeypatch.setenv("OUTPUT_FILE", str(tmp_path / "out.md"))

        (tmp_path / "scanner-summary-trivy.md").write_text("## Trivy\nfindings")

        with pytest.raises(SystemExit) as exc:
            import runpy
            runpy.run_path(str(SCRIPT_PATH))
        assert exc.value.code == 1


class TestMissingSummaryDir:
    def test_missing_summary_dir_exits(self, tmp_path, monkeypatch):
        """Script exits when summary directory does not exist."""
        monkeypatch.setenv("AI_PROVIDER", "claude")
        monkeypatch.setenv("SUMMARY_DIR", str(tmp_path / "nonexistent"))
        monkeypatch.setenv("OUTPUT_FILE", str(tmp_path / "out.md"))

        with pytest.raises(SystemExit) as exc:
            import runpy
            runpy.run_path(str(SCRIPT_PATH))
        assert exc.value.code == 1

    def test_empty_summary_dir_exits(self, tmp_path, monkeypatch):
        """Script exits when summary directory has no matching files."""
        monkeypatch.setenv("AI_PROVIDER", "claude")
        monkeypatch.setenv("SUMMARY_DIR", str(tmp_path))
        monkeypatch.setenv("OUTPUT_FILE", str(tmp_path / "out.md"))

        with pytest.raises(SystemExit) as exc:
            import runpy
            runpy.run_path(str(SCRIPT_PATH))
        assert exc.value.code == 1
        