"""Tests for ``argus.viewers.terminal.mouse_actions`` — URL constructors
and file-open helpers exercised without spinning up Textual."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from argus.viewers.terminal.mouse_actions import (
    advisory_url_for_id,
    cve_url,
    find_repo_root,
    git_blob_url,
    open_file_local,
    open_in_browser,
    package_url,
    parse_file_line,
)


class TestCveUrl:
    """CVE URL routing across the four supported sources."""

    def test_nvd_default(self):
        assert cve_url("CVE-2024-12345") == (
            "https://nvd.nist.gov/vuln/detail/CVE-2024-12345"
        )

    def test_cve_org(self):
        assert cve_url("CVE-2024-12345", "cve_org") == (
            "https://www.cve.org/CVERecord?id=CVE-2024-12345"
        )

    def test_github_advisory(self):
        assert cve_url("CVE-2024-12345", "github") == (
            "https://github.com/advisories?query=CVE-2024-12345"
        )

    def test_mitre(self):
        assert cve_url("CVE-2024-12345", "mitre") == (
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-12345"
        )

    def test_unknown_source_falls_back_to_nvd(self):
        assert cve_url("CVE-2024-12345", "made-up") == (
            "https://nvd.nist.gov/vuln/detail/CVE-2024-12345"
        )

    def test_lowercase_id_canonicalized(self):
        """Scanners sometimes emit ``cve-2024-x``; we want NVD-shape URLs."""
        assert cve_url("cve-2024-12345") == (
            "https://nvd.nist.gov/vuln/detail/CVE-2024-12345"
        )

    def test_non_cve_returns_none(self):
        assert cve_url("GHSA-1234-5678-9abc") is None
        assert cve_url("BANDIT-B101") is None
        assert cve_url("") is None
        assert cve_url(None) is None  # type: ignore[arg-type]

    def test_malformed_cve_rejected(self):
        # Year part must be 4 digits, ID part must be 4+ digits
        assert cve_url("CVE-24-1234") is None
        assert cve_url("CVE-2024-12") is None


class TestAdvisoryUrlForId:
    """Routes any advisory ID to the right source."""

    def test_cve_uses_configured_source(self):
        assert advisory_url_for_id("CVE-2024-12345", "cve_org") == (
            "https://www.cve.org/CVERecord?id=CVE-2024-12345"
        )

    def test_ghsa_always_github(self):
        """GHSA IDs are GitHub-specific; cve_source doesn't apply."""
        assert advisory_url_for_id(
            "GHSA-1234-5678-9abc", "nvd",
        ) == "https://github.com/advisories/GHSA-1234-5678-9ABC"

    def test_unrecognized_returns_none(self):
        assert advisory_url_for_id("BANDIT-B101", "nvd") is None
        assert advisory_url_for_id("RUSTSEC-2024-001", "nvd") is None


class TestPackageUrl:
    """Best-effort registry URL for finding ``location`` strings."""

    def test_pypi_package(self):
        assert package_url("flask@3.0.0") == "https://pypi.org/project/flask/"

    def test_npm_scoped(self):
        assert package_url("@octokit/rest@21.0.0") == (
            "https://www.npmjs.com/package/@octokit/rest"
        )

    def test_npm_unscoped_routed_by_path_slash(self):
        """Path-shaped names route to npm even without ``@scope`` prefix."""
        # We don't have a clean disambiguator from PyPI here, but
        # ``some/dir@v`` shapes are vanishingly rare on PyPI.
        assert package_url("scope/pkg@1.0.0") == (
            "https://www.npmjs.com/package/scope/pkg"
        )

    def test_no_at_sign_returns_none(self):
        """Plain file path ≠ a package@version."""
        assert package_url("src/app.py:42") is None

    def test_empty_returns_none(self):
        assert package_url(None) is None
        assert package_url("") is None
        assert package_url("@") is None


class TestParseFileLine:
    """Parse scanner ``location`` strings into (path, line)."""

    def test_file_with_line(self):
        result = parse_file_line("src/app.py:42")
        assert result == (Path("src/app.py"), 42)

    def test_file_without_line(self):
        result = parse_file_line("src/app.py")
        assert result == (Path("src/app.py"), None)

    def test_file_with_line_and_column(self):
        """``file:line:column`` — keep line, drop column."""
        result = parse_file_line("src/app.py:42:13")
        assert result == (Path("src/app.py"), 42)

    def test_absolute_path(self):
        result = parse_file_line("/abs/path/to/file.py:99")
        assert result == (Path("/abs/path/to/file.py"), 99)

    def test_package_at_version_routed_elsewhere(self):
        """``flask@3.0.0`` is a package, not a file — return None."""
        assert parse_file_line("flask@3.0.0") is None
        assert parse_file_line("@octokit/rest@21.0.0") is None

    def test_empty_returns_none(self):
        assert parse_file_line(None) is None
        assert parse_file_line("") is None


class TestGitBlobUrl:
    """Construct GitHub / GitLab blob URLs from local git remote."""

    @patch("argus.viewers.terminal.mouse_actions.shutil.which", return_value="/usr/bin/git")
    @patch("argus.viewers.terminal.mouse_actions.subprocess.run")
    def test_github_ssh_remote(self, mock_run, _mock_which):
        mock_run.return_value = MagicMock(
            returncode=0, stdout="git@github.com:huntridge-labs/argus.git\n",
        )
        url = git_blob_url(
            Path("/repo"), Path("src/app.py"), 42, "abc123",
        )
        assert url == (
            "https://github.com/huntridge-labs/argus/blob/abc123/src/app.py#L42"
        )

    @patch("argus.viewers.terminal.mouse_actions.shutil.which", return_value="/usr/bin/git")
    @patch("argus.viewers.terminal.mouse_actions.subprocess.run")
    def test_github_https_remote(self, mock_run, _mock_which):
        mock_run.return_value = MagicMock(
            returncode=0, stdout="https://github.com/huntridge-labs/argus.git\n",
        )
        url = git_blob_url(Path("/repo"), Path("src/app.py"), 42, "main")
        assert url == (
            "https://github.com/huntridge-labs/argus/blob/main/src/app.py#L42"
        )

    @patch("argus.viewers.terminal.mouse_actions.shutil.which", return_value="/usr/bin/git")
    @patch("argus.viewers.terminal.mouse_actions.subprocess.run")
    def test_no_line_drops_anchor(self, mock_run, _mock_which):
        mock_run.return_value = MagicMock(
            returncode=0, stdout="git@github.com:o/r.git\n",
        )
        url = git_blob_url(Path("/repo"), Path("README.md"), None, "v1.0")
        assert url == "https://github.com/o/r/blob/v1.0/README.md"

    @patch("argus.viewers.terminal.mouse_actions.shutil.which", return_value="/usr/bin/git")
    @patch("argus.viewers.terminal.mouse_actions.subprocess.run")
    def test_gitlab_self_hosted(self, mock_run, _mock_which):
        mock_run.return_value = MagicMock(
            returncode=0, stdout="git@gitlab.internal:team/project.git\n",
        )
        url = git_blob_url(
            Path("/repo"), Path("svc/main.py"), 10, "feature/x",
        )
        assert url == (
            "https://gitlab.internal/team/project/blob/feature/x/svc/main.py#L10"
        )

    @patch("argus.viewers.terminal.mouse_actions.shutil.which", return_value="/usr/bin/git")
    @patch("argus.viewers.terminal.mouse_actions.subprocess.run")
    def test_no_remote_returns_none(self, mock_run, _mock_which):
        """Repo without origin remote produces None, not a broken URL."""
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="...")
        assert git_blob_url(Path("/repo"), Path("a.py"), 1, "main") is None

    @patch("argus.viewers.terminal.mouse_actions.shutil.which", return_value=None)
    def test_no_git_binary_returns_none(self, _mock_which):
        """Air-gapped scan host without git — graceful fail."""
        assert git_blob_url(Path("/repo"), Path("a.py"), 1, "main") is None

    @patch("argus.viewers.terminal.mouse_actions.shutil.which", return_value="/usr/bin/git")
    @patch("argus.viewers.terminal.mouse_actions.subprocess.run")
    def test_unrecognized_remote_returns_none(self, mock_run, _mock_which):
        """Local-only or non-http/ssh remote produces None."""
        mock_run.return_value = MagicMock(
            returncode=0, stdout="/local/path/to/bare/repo.git\n",
        )
        assert git_blob_url(Path("/r"), Path("a.py"), 1, "main") is None


class TestOpenInBrowser:
    """Smoke tests — webbrowser.open is the actual implementation."""

    @patch("argus.viewers.terminal.mouse_actions.webbrowser.open")
    def test_calls_webbrowser_open(self, mock_open):
        mock_open.return_value = True
        assert open_in_browser("https://example.com") is True
        mock_open.assert_called_once_with("https://example.com", new=2)

    def test_empty_url_returns_false(self):
        assert open_in_browser("") is False

    @patch("argus.viewers.terminal.mouse_actions.webbrowser.open")
    def test_exception_returns_false(self, mock_open):
        mock_open.side_effect = RuntimeError("display unavailable")
        assert open_in_browser("https://example.com") is False


class TestOpenFileLocal:
    """Editor-launch ergonomics."""

    @patch("argus.viewers.terminal.mouse_actions.subprocess.Popen")
    @patch("argus.viewers.terminal.mouse_actions.shutil.which")
    def test_vscode_with_line_uses_g_flag(self, mock_which, mock_popen, tmp_path):
        f = tmp_path / "app.py"
        f.write_text("print('hi')\n")
        mock_which.side_effect = lambda b: "/usr/local/bin/code" if b == "code" else None
        with patch.dict("os.environ", {"VISUAL": "code", "EDITOR": ""}):
            assert open_file_local(f, line=42) is True
        cmd = mock_popen.call_args.args[0]
        assert cmd == ["code", "-g", f"{f}:42"]

    @patch("argus.viewers.terminal.mouse_actions.subprocess.Popen")
    @patch("argus.viewers.terminal.mouse_actions.shutil.which")
    def test_vim_with_line_uses_plus_line(self, mock_which, mock_popen, tmp_path):
        f = tmp_path / "app.py"
        f.write_text("x = 1\n")
        mock_which.side_effect = lambda b: "/usr/bin/vim" if b == "vim" else None
        with patch.dict("os.environ", {"VISUAL": "", "EDITOR": "vim"}):
            assert open_file_local(f, line=10) is True
        cmd = mock_popen.call_args.args[0]
        assert cmd == ["vim", "+10", str(f)]

    @patch("argus.viewers.terminal.mouse_actions.subprocess.Popen")
    @patch("argus.viewers.terminal.mouse_actions.shutil.which")
    def test_explicit_editor_arg_wins_over_env(self, mock_which, mock_popen, tmp_path):
        f = tmp_path / "f.py"
        f.write_text("\n")
        mock_which.side_effect = lambda b: "/usr/bin/nano" if b == "nano" else None
        with patch.dict("os.environ", {"EDITOR": "vim"}):
            assert open_file_local(f, line=5, editor="nano") is True
        cmd = mock_popen.call_args.args[0]
        assert cmd[0] == "nano"  # config wins over env

    def test_nonexistent_file_returns_false(self, tmp_path):
        ghost = tmp_path / "does-not-exist.py"
        assert open_file_local(ghost, line=1) is False

    @patch("argus.viewers.terminal.mouse_actions.subprocess.Popen")
    @patch("argus.viewers.terminal.mouse_actions.shutil.which")
    def test_no_editor_falls_through_to_xdg_open(
        self, mock_which, mock_popen, tmp_path,
    ):
        f = tmp_path / "doc.pdf"
        f.write_text("\n")
        mock_which.side_effect = lambda b: "/usr/bin/xdg-open" if b == "xdg-open" else None
        with patch.dict("os.environ", {"VISUAL": "", "EDITOR": ""}, clear=False):
            assert open_file_local(f) is True
        cmd = mock_popen.call_args.args[0]
        assert cmd == ["xdg-open", str(f)]

    @patch("argus.viewers.terminal.mouse_actions.subprocess.Popen")
    @patch("argus.viewers.terminal.mouse_actions.shutil.which", return_value=None)
    def test_no_editor_no_opener_returns_false(
        self, _mock_which, _mock_popen, tmp_path,
    ):
        f = tmp_path / "x.py"
        f.write_text("\n")
        with patch.dict("os.environ", {"VISUAL": "", "EDITOR": ""}, clear=False):
            assert open_file_local(f, line=1) is False


class TestFindRepoRoot:
    """Walk up looking for ``.git``."""

    def test_finds_root_at_start(self, tmp_path):
        (tmp_path / ".git").mkdir()
        assert find_repo_root(tmp_path) == tmp_path

    def test_finds_root_above(self, tmp_path):
        (tmp_path / ".git").mkdir()
        nested = tmp_path / "a" / "b" / "c"
        nested.mkdir(parents=True)
        assert find_repo_root(nested) == tmp_path

    def test_no_git_returns_none(self, tmp_path):
        nested = tmp_path / "a"
        nested.mkdir()
        # walks all the way to filesystem root without finding .git
        # in this isolated tmp_path — but caller may have a real git
        # somewhere above tmp_path. Skip the assertion if a real .git
        # exists above us (CI runners often have one in $HOME).
        result = find_repo_root(nested)
        if result is not None:
            assert (result / ".git").exists()
        # Otherwise we got None as expected — both outcomes are valid
        # depending on the runner's filesystem layout.


class TestStripScanPrefix:
    """``strip_scan_prefix`` maps absolute container/CI paths back to
    repo-relative form using scan-time context."""

    def _ctx(self, *, cwd="", repo_root="", commit_sha=""):
        """Build a stand-in for ``argus.core.models.ScanContext`` so
        the test doesn't depend on the real dataclass — keeps the
        mouse_actions module decoupled from core."""
        class _StubContext:
            def __init__(self, cwd, repo_root, commit_sha):
                self.cwd = cwd
                self.repo_root = repo_root
                self.commit_sha = commit_sha
        return _StubContext(cwd, repo_root, commit_sha)

    def test_strips_repo_root_prefix(self):
        from argus.viewers.terminal.mouse_actions import strip_scan_prefix
        ctx = self._ctx(
            cwd="/workspace/argus",
            repo_root="/workspace/argus",
            commit_sha="abc",
        )
        result = strip_scan_prefix(
            Path("/workspace/argus/preflight/issue_reporter.py"), ctx,
        )
        assert result == Path("preflight/issue_reporter.py")

    def test_prefers_repo_root_over_cwd(self):
        """When cwd is a subdir of repo_root, prefer repo_root so
        the resulting path is anchored at the repo's top."""
        from argus.viewers.terminal.mouse_actions import strip_scan_prefix
        ctx = self._ctx(
            cwd="/workspace/argus/src",
            repo_root="/workspace/argus",
        )
        result = strip_scan_prefix(
            Path("/workspace/argus/src/main.py"), ctx,
        )
        assert result == Path("src/main.py")

    def test_falls_back_to_cwd_when_repo_root_missing(self):
        from argus.viewers.terminal.mouse_actions import strip_scan_prefix
        ctx = self._ctx(cwd="/workspace/argus")  # repo_root="" (non-git)
        result = strip_scan_prefix(
            Path("/workspace/argus/foo.py"), ctx,
        )
        assert result == Path("foo.py")

    def test_relative_path_returned_unchanged(self):
        from argus.viewers.terminal.mouse_actions import strip_scan_prefix
        ctx = self._ctx(repo_root="/workspace/argus")
        result = strip_scan_prefix(Path("src/foo.py"), ctx)
        assert result == Path("src/foo.py")

    def test_none_context_returns_unchanged(self):
        """Older argus-results.json without scan_context — fall
        through; let the viewer's existing best-effort handle it."""
        from argus.viewers.terminal.mouse_actions import strip_scan_prefix
        result = strip_scan_prefix(Path("/abs/path.py"), None)
        assert result == Path("/abs/path.py")

    def test_path_outside_prefix_returned_unchanged(self):
        """Absolute path that doesn't share the recorded prefix
        falls through — strip_scan_prefix doesn't invent mappings."""
        from argus.viewers.terminal.mouse_actions import strip_scan_prefix
        ctx = self._ctx(repo_root="/workspace/argus")
        result = strip_scan_prefix(
            Path("/usr/lib/python3.13/site-packages/foo.py"), ctx,
        )
        assert result == Path("/usr/lib/python3.13/site-packages/foo.py")

    def test_empty_prefixes_returned_unchanged(self):
        from argus.viewers.terminal.mouse_actions import strip_scan_prefix
        ctx = self._ctx()  # everything empty
        result = strip_scan_prefix(Path("/abs/path.py"), ctx)
        assert result == Path("/abs/path.py")
