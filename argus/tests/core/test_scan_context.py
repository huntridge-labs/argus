"""Tests for ScanContext + ScanSummary scan-time metadata.

Covers the capture path (cwd + git rev-parse outputs), the
to_dict / from_dict round-trip, and the backwards-compatibility
contract: an older argus-results.json without ``scan_context`` loads
cleanly into a ScanSummary with ``scan_context=None`` so viewers can
fall back to their previous best-effort behavior.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from argus.core.models import ScanContext, ScanSummary, ScanResult


class TestScanContextRoundTrip:
    """to_dict / from_dict preserves every field."""

    def test_full_context_roundtrips(self):
        ctx = ScanContext(
            cwd="/workspace/argus",
            repo_root="/workspace/argus",
            commit_sha="abc123def4567890",
        )
        roundtripped = ScanContext.from_dict(ctx.to_dict())
        assert roundtripped == ctx

    def test_empty_context_roundtrips(self):
        ctx = ScanContext()
        roundtripped = ScanContext.from_dict(ctx.to_dict())
        assert roundtripped == ctx
        assert roundtripped.cwd == ""
        assert roundtripped.repo_root == ""
        assert roundtripped.commit_sha == ""

    def test_from_dict_with_none_returns_empty(self):
        ctx = ScanContext.from_dict(None)
        assert ctx == ScanContext()

    def test_from_dict_with_partial_data(self):
        ctx = ScanContext.from_dict({"cwd": "/x"})
        assert ctx.cwd == "/x"
        assert ctx.repo_root == ""
        assert ctx.commit_sha == ""


class TestScanContextCapture:
    """The capture path: cwd from os.getcwd, repo bits from git."""

    @patch("shutil.which", return_value="/usr/bin/git")
    @patch("subprocess.run")
    def test_captures_repo_root_and_sha(self, mock_run, _mock_which):
        # First call: rev-parse --show-toplevel
        # Second call: rev-parse HEAD
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="/repo/root\n"),
            MagicMock(returncode=0, stdout="deadbeef" * 5 + "\n"),
        ]
        ctx = ScanContext.capture(cwd="/repo/root/subdir")
        assert ctx.cwd == "/repo/root/subdir"
        assert ctx.repo_root == "/repo/root"
        assert ctx.commit_sha == "deadbeef" * 5

    @patch("shutil.which", return_value=None)
    def test_no_git_binary_returns_cwd_only(self, _mock_which):
        ctx = ScanContext.capture(cwd="/some/path")
        assert ctx.cwd == "/some/path"
        assert ctx.repo_root == ""
        assert ctx.commit_sha == ""

    @patch("shutil.which", return_value="/usr/bin/git")
    @patch("subprocess.run")
    def test_non_git_dir_returns_cwd_only(self, mock_run, _mock_which):
        # rev-parse returns non-zero outside a git working tree
        mock_run.return_value = MagicMock(
            returncode=128, stdout="", stderr="fatal: not a git repository",
        )
        ctx = ScanContext.capture(cwd="/tmp")
        assert ctx.cwd == "/tmp"
        assert ctx.repo_root == ""
        assert ctx.commit_sha == ""

    @patch("shutil.which", return_value="/usr/bin/git")
    @patch("subprocess.run", side_effect=OSError("permission denied"))
    def test_subprocess_oserror_never_raises(self, _mock_run, _mock_which):
        # Air-gapped runner / cgroup ban / weird filesystem — capture
        # must never propagate the error.
        ctx = ScanContext.capture(cwd="/x")
        assert ctx.cwd == "/x"
        assert ctx.repo_root == ""
        assert ctx.commit_sha == ""

    def test_default_cwd_is_os_getcwd(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        with patch("shutil.which", return_value=None):
            ctx = ScanContext.capture()
        assert ctx.cwd == str(tmp_path)


class TestScanSummaryRoundTrip:
    """ScanSummary preserves scan_context across to_dict / from_dict."""

    def test_with_scan_context(self):
        ctx = ScanContext(
            cwd="/workspace/argus",
            repo_root="/workspace/argus",
            commit_sha="abc123",
        )
        summary = ScanSummary(results=[], scan_context=ctx)
        out = summary.to_dict()
        assert "scan_context" in out
        assert out["scan_context"]["commit_sha"] == "abc123"

        rebuilt = ScanSummary.from_dict(out)
        assert rebuilt.scan_context == ctx

    def test_without_scan_context_omits_key(self):
        # Backwards-compat: when no context was captured, the field
        # shouldn't bloat the canonical JSON with a meaningless empty
        # mapping. Older consumers that didn't know about scan_context
        # see the same shape they used to.
        summary = ScanSummary(results=[])
        out = summary.to_dict()
        assert "scan_context" not in out

    def test_from_dict_legacy_payload(self):
        """A pre-scan_context argus-results.json must load cleanly."""
        legacy = {
            "results": [],
            "severity_threshold": None,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0,
            "total_count": 0,
            "passed": True,
        }
        summary = ScanSummary.from_dict(legacy)
        assert summary.scan_context is None

    def test_json_roundtrip_preserves_context(self):
        """End-to-end: dict → JSON → dict → ScanSummary."""
        ctx = ScanContext(
            cwd="/cwd",
            repo_root="/repo",
            commit_sha="deadbeef",
        )
        summary = ScanSummary(results=[], scan_context=ctx)
        text = json.dumps(summary.to_dict())
        rebuilt = ScanSummary.from_dict(json.loads(text))
        assert rebuilt.scan_context == ctx
