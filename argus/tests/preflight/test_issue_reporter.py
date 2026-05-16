"""Tests for argus.preflight.issue_reporter."""

import json
from io import BytesIO
from unittest.mock import MagicMock, patch

import pytest

from argus.preflight.ci_provider import CIContext
from argus.preflight.issue_reporter import (
    GitHubIssueReporter,
    GitLabIssueReporter,
    get_issue_reporter,
    ISSUE_TITLE,
    ISSUE_LABEL,
)


def _mock_response(data, status=200):
    """Create a mock urllib response."""
    resp = MagicMock()
    resp.read.return_value = json.dumps(data).encode()
    resp.status = status
    resp.__enter__ = MagicMock(return_value=resp)
    resp.__exit__ = MagicMock(return_value=False)
    return resp


def _github_ctx(token="ghp_test"):
    return CIContext("github", token, "org/repo", "https://api.github.com", None)


def _gitlab_ctx(token="glcbt_test"):
    return CIContext("gitlab", token, "grp/proj", "https://gitlab.com/api/v4", "grp%2Fproj")


class TestGetIssueReporter:
    """Test factory function."""

    def test_github_returns_reporter(self):
        r = get_issue_reporter(_github_ctx())
        assert isinstance(r, GitHubIssueReporter)

    def test_gitlab_returns_reporter(self):
        r = get_issue_reporter(_gitlab_ctx())
        assert isinstance(r, GitLabIssueReporter)

    def test_unknown_returns_none(self):
        ctx = CIContext("unknown", None, None, None, None)
        assert get_issue_reporter(ctx) is None

    def test_github_no_token_returns_none(self):
        ctx = CIContext("github", None, "org/repo", "https://api.github.com", None)
        assert get_issue_reporter(ctx) is None

    def test_github_no_repo_returns_none(self):
        ctx = CIContext("github", "tok", None, "https://api.github.com", None)
        assert get_issue_reporter(ctx) is None

    def test_gitlab_no_token_returns_none(self):
        ctx = CIContext("gitlab", None, "grp/proj", "https://gitlab.com/api/v4", "grp%2Fproj")
        assert get_issue_reporter(ctx) is None

    def test_gitlab_no_project_returns_none(self):
        ctx = CIContext("gitlab", "tok", "grp/proj", "https://gitlab.com/api/v4", None)
        assert get_issue_reporter(ctx) is None


class TestGitHubIssueReporter:
    """Test GitHub API interactions."""

    @patch("urllib.request.urlopen")
    def test_find_issue_found(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response([
            {"number": 42, "html_url": "https://github.com/org/repo/issues/42"}
        ])
        r = GitHubIssueReporter(_github_ctx())
        result = r.find_issue()
        assert result == {"number": 42, "url": "https://github.com/org/repo/issues/42"}

    @patch("urllib.request.urlopen")
    def test_find_issue_not_found(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response([])
        r = GitHubIssueReporter(_github_ctx())
        assert r.find_issue() is None

    @patch("urllib.request.urlopen")
    def test_find_issue_api_error(self, mock_urlopen):
        import urllib.error
        mock_urlopen.side_effect = urllib.error.URLError("timeout")
        r = GitHubIssueReporter(_github_ctx())
        assert r.find_issue() is None

    @patch("urllib.request.urlopen")
    def test_create_issue(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response(
            {"number": 99, "html_url": "https://github.com/org/repo/issues/99"}
        )
        r = GitHubIssueReporter(_github_ctx())
        result = r.create_issue("## Test body")
        assert result == {"number": 99, "url": "https://github.com/org/repo/issues/99"}

    @patch("urllib.request.urlopen")
    def test_update_issue(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response({"number": 42})
        r = GitHubIssueReporter(_github_ctx())
        assert r.update_issue(42, "## Updated body") is True

    @patch("urllib.request.urlopen")
    def test_close_issue(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response({"number": 42, "state": "closed"})
        r = GitHubIssueReporter(_github_ctx())
        assert r.close_issue(42) is True

    @patch("urllib.request.urlopen")
    def test_create_issue_api_error(self, mock_urlopen):
        import urllib.error
        mock_urlopen.side_effect = urllib.error.URLError("forbidden")
        r = GitHubIssueReporter(_github_ctx())
        assert r.create_issue("body") is None

    @patch("urllib.request.urlopen")
    def test_request_sets_auth_header(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response([])
        r = GitHubIssueReporter(_github_ctx("my_token"))
        r.find_issue()
        req = mock_urlopen.call_args[0][0]
        assert req.get_header("Authorization") == "Bearer my_token"


class TestGitLabIssueReporter:
    """Test GitLab API interactions."""

    @patch("urllib.request.urlopen")
    def test_find_issue_found(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response([
            {"iid": 7, "web_url": "https://gitlab.com/grp/proj/-/issues/7"}
        ])
        r = GitLabIssueReporter(_gitlab_ctx())
        result = r.find_issue()
        assert result == {"number": 7, "url": "https://gitlab.com/grp/proj/-/issues/7"}

    @patch("urllib.request.urlopen")
    def test_find_issue_not_found(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response([])
        r = GitLabIssueReporter(_gitlab_ctx())
        assert r.find_issue() is None

    @patch("urllib.request.urlopen")
    def test_create_issue(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response(
            {"iid": 15, "web_url": "https://gitlab.com/grp/proj/-/issues/15"}
        )
        r = GitLabIssueReporter(_gitlab_ctx())
        result = r.create_issue("## Body")
        assert result == {"number": 15, "url": "https://gitlab.com/grp/proj/-/issues/15"}

    @patch("urllib.request.urlopen")
    def test_update_issue(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response({"iid": 7})
        r = GitLabIssueReporter(_gitlab_ctx())
        assert r.update_issue(7, "## Updated") is True

    @patch("urllib.request.urlopen")
    def test_close_issue(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response({"iid": 7, "state": "closed"})
        r = GitLabIssueReporter(_gitlab_ctx())
        assert r.close_issue(7) is True

    @patch("urllib.request.urlopen")
    def test_api_error_returns_none(self, mock_urlopen):
        import urllib.error
        mock_urlopen.side_effect = urllib.error.URLError("connection refused")
        r = GitLabIssueReporter(_gitlab_ctx())
        assert r.find_issue() is None
        assert r.create_issue("body") is None

    @patch("urllib.request.urlopen")
    def test_request_sets_job_token(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response([])
        r = GitLabIssueReporter(_gitlab_ctx("my_gl_token"))
        r.find_issue()
        req = mock_urlopen.call_args[0][0]
        assert req.get_header("Job-token") == "my_gl_token"
