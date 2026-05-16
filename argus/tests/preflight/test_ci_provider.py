"""Tests for argus.preflight.ci_provider."""

from argus.preflight.ci_provider import detect_ci_provider, CIContext


class TestDetectCIProvider:
    """Test CI provider detection from env vars."""

    def test_github_actions(self, monkeypatch):
        monkeypatch.setenv("GITHUB_ACTIONS", "true")
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_test123")
        monkeypatch.setenv("GITHUB_REPOSITORY", "huntridge-labs/argus")
        monkeypatch.setenv("GITHUB_SERVER_URL", "https://github.com")

        ctx = detect_ci_provider()
        assert ctx.provider == "github"
        assert ctx.api_token == "ghp_test123"
        assert ctx.repo_slug == "huntridge-labs/argus"
        assert ctx.api_base == "https://api.github.com"
        assert ctx.project_id is None

    def test_github_ghes(self, monkeypatch):
        """GHES uses {server}/api/v3 instead of api.github.com."""
        monkeypatch.setenv("GITHUB_ACTIONS", "true")
        monkeypatch.setenv("GITHUB_TOKEN", "tok")
        monkeypatch.setenv("GITHUB_REPOSITORY", "org/repo")
        monkeypatch.setenv("GITHUB_SERVER_URL", "https://github.mycompany.com")

        ctx = detect_ci_provider()
        assert ctx.provider == "github"
        assert ctx.api_base == "https://github.mycompany.com/api/v3"

    def test_github_no_token(self, monkeypatch):
        monkeypatch.setenv("GITHUB_ACTIONS", "true")
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        monkeypatch.setenv("GITHUB_REPOSITORY", "org/repo")

        ctx = detect_ci_provider()
        assert ctx.provider == "github"
        assert ctx.api_token is None

    def test_gitlab_ci(self, monkeypatch):
        monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
        monkeypatch.setenv("GITLAB_CI", "true")
        monkeypatch.setenv("CI_JOB_TOKEN", "glcbt-test")
        monkeypatch.setenv("CI_PROJECT_PATH", "group/subgroup/project")
        monkeypatch.setenv("CI_API_V4_URL", "https://gitlab.com/api/v4")

        ctx = detect_ci_provider()
        assert ctx.provider == "gitlab"
        assert ctx.api_token == "glcbt-test"
        assert ctx.repo_slug == "group/subgroup/project"
        assert ctx.api_base == "https://gitlab.com/api/v4"
        assert ctx.project_id == "group%2Fsubgroup%2Fproject"

    def test_gitlab_derives_api_url(self, monkeypatch):
        """Falls back to CI_SERVER_URL + /api/v4 when CI_API_V4_URL is unset."""
        monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
        monkeypatch.setenv("GITLAB_CI", "true")
        monkeypatch.setenv("CI_JOB_TOKEN", "tok")
        monkeypatch.setenv("CI_PROJECT_PATH", "grp/proj")
        monkeypatch.delenv("CI_API_V4_URL", raising=False)
        monkeypatch.setenv("CI_SERVER_URL", "https://gitlab.myorg.com")

        ctx = detect_ci_provider()
        assert ctx.api_base == "https://gitlab.myorg.com/api/v4"

    def test_unknown_provider(self, monkeypatch):
        monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
        monkeypatch.delenv("GITLAB_CI", raising=False)

        ctx = detect_ci_provider()
        assert ctx.provider == "unknown"
        assert ctx.api_token is None
        assert ctx.repo_slug is None
        assert ctx.api_base is None

    def test_github_takes_priority_over_gitlab(self, monkeypatch):
        """If both are set (shouldn't happen), GitHub wins."""
        monkeypatch.setenv("GITHUB_ACTIONS", "true")
        monkeypatch.setenv("GITLAB_CI", "true")
        monkeypatch.setenv("GITHUB_TOKEN", "gh_tok")
        monkeypatch.setenv("GITHUB_REPOSITORY", "org/repo")

        ctx = detect_ci_provider()
        assert ctx.provider == "github"
