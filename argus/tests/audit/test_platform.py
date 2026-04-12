"""Tests for argus.audit.platform -- CI platform detection."""

import os

import pytest

from argus.audit.platform import CIPlatform, detect_platform


@pytest.fixture(autouse=True)
def _clean_ci_env(monkeypatch):
    """Remove CI env vars so each test starts from a clean slate."""
    ci_vars = [
        "GITHUB_ACTIONS", "GITHUB_RUN_ID", "GITHUB_JOB",
        "GITHUB_SHA", "GITHUB_HEAD_REF", "GITHUB_REF_NAME",
        "GITHUB_REPOSITORY", "GITHUB_ACTOR", "GITHUB_SERVER_URL",
        "GITHUB_EVENT_NAME", "RUNNER_NAME",
        "GITLAB_CI", "CI_PIPELINE_ID", "CI_JOB_ID", "CI_JOB_NAME",
        "CI_JOB_URL", "CI_PIPELINE_URL", "CI_COMMIT_SHA",
        "CI_COMMIT_BRANCH", "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME",
        "CI_COMMIT_MESSAGE", "CI_PROJECT_PATH", "GITLAB_USER_LOGIN",
        "CI_RUNNER_DESCRIPTION", "CI_SERVER_URL", "CI_PIPELINE_SOURCE",
        "JENKINS_URL", "BUILD_NUMBER", "BUILD_ID", "JOB_NAME",
        "BUILD_URL", "GIT_COMMIT", "GIT_BRANCH", "BUILD_USER",
    ]
    for var in ci_vars:
        monkeypatch.delenv(var, raising=False)


class TestDetectPlatformLocal:
    """Detect local development environment."""

    def test_defaults_to_local(self):
        platform = detect_platform()
        assert platform.name == "local"

    def test_local_picks_up_user(self, monkeypatch):
        monkeypatch.setenv("USER", "testdev")
        platform = detect_platform()
        assert platform.actor == "testdev"


class TestDetectGitHub:
    """Detect GitHub Actions."""

    def test_detects_github(self, monkeypatch):
        monkeypatch.setenv("GITHUB_ACTIONS", "true")
        monkeypatch.setenv("GITHUB_RUN_ID", "12345")
        monkeypatch.setenv("GITHUB_JOB", "security-scan")
        monkeypatch.setenv("GITHUB_SHA", "abc123")
        monkeypatch.setenv("GITHUB_REPOSITORY", "org/repo")
        monkeypatch.setenv("GITHUB_ACTOR", "bot")
        monkeypatch.setenv("GITHUB_SERVER_URL", "https://github.com")
        monkeypatch.setenv("GITHUB_EVENT_NAME", "push")

        platform = detect_platform()
        assert platform.name == "github"
        assert platform.pipeline_id == "12345"
        assert platform.job_id == "security-scan"
        assert platform.commit_sha == "abc123"
        assert platform.repository == "org/repo"
        assert platform.actor == "bot"
        assert platform.event_name == "push"

    def test_github_job_url(self, monkeypatch):
        monkeypatch.setenv("GITHUB_ACTIONS", "true")
        monkeypatch.setenv("GITHUB_SERVER_URL", "https://ghes.internal")
        monkeypatch.setenv("GITHUB_REPOSITORY", "team/project")
        monkeypatch.setenv("GITHUB_RUN_ID", "999")

        platform = detect_platform()
        assert "ghes.internal" in platform.job_url
        assert "team/project" in platform.job_url
        assert "999" in platform.job_url

    def test_github_head_ref_preferred(self, monkeypatch):
        monkeypatch.setenv("GITHUB_ACTIONS", "true")
        monkeypatch.setenv("GITHUB_HEAD_REF", "feature/abc")
        monkeypatch.setenv("GITHUB_REF_NAME", "main")

        platform = detect_platform()
        assert platform.commit_branch == "feature/abc"

    def test_github_ref_name_fallback(self, monkeypatch):
        monkeypatch.setenv("GITHUB_ACTIONS", "true")
        monkeypatch.setenv("GITHUB_HEAD_REF", "")
        monkeypatch.setenv("GITHUB_REF_NAME", "main")

        platform = detect_platform()
        assert platform.commit_branch == "main"


class TestDetectGitLab:
    """Detect GitLab CI."""

    def test_detects_gitlab(self, monkeypatch):
        monkeypatch.setenv("GITLAB_CI", "true")
        monkeypatch.setenv("CI_PIPELINE_ID", "7777")
        monkeypatch.setenv("CI_JOB_ID", "8888")
        monkeypatch.setenv("CI_JOB_NAME", "sast")
        monkeypatch.setenv("CI_COMMIT_SHA", "def456")
        monkeypatch.setenv("CI_PROJECT_PATH", "group/project")
        monkeypatch.setenv("GITLAB_USER_LOGIN", "dev")
        monkeypatch.setenv("CI_SERVER_URL", "https://gitlab.internal")

        platform = detect_platform()
        assert platform.name == "gitlab"
        assert platform.pipeline_id == "7777"
        assert platform.job_id == "8888"
        assert platform.commit_sha == "def456"
        assert platform.repository == "group/project"
        assert platform.actor == "dev"

    def test_gitlab_branch_fallback(self, monkeypatch):
        monkeypatch.setenv("GITLAB_CI", "true")
        monkeypatch.setenv("CI_COMMIT_BRANCH", "")
        monkeypatch.setenv("CI_MERGE_REQUEST_SOURCE_BRANCH_NAME", "feat/mr")

        platform = detect_platform()
        assert platform.commit_branch == "feat/mr"


class TestDetectJenkins:
    """Detect Jenkins."""

    def test_detects_jenkins(self, monkeypatch):
        monkeypatch.setenv("JENKINS_URL", "https://jenkins.internal/")
        monkeypatch.setenv("BUILD_NUMBER", "42")
        monkeypatch.setenv("BUILD_ID", "42")
        monkeypatch.setenv("JOB_NAME", "pipeline/main")
        monkeypatch.setenv("GIT_COMMIT", "aaa111")
        monkeypatch.setenv("GIT_BRANCH", "origin/main")

        platform = detect_platform()
        assert platform.name == "jenkins"
        assert platform.pipeline_id == "42"
        assert platform.commit_sha == "aaa111"
        assert platform.commit_branch == "origin/main"
        assert platform.server_url == "https://jenkins.internal/"


class TestCIPlatformDataclass:
    """Verify the CIPlatform dataclass defaults."""

    def test_default_values(self):
        p = CIPlatform()
        assert p.name == "local"
        assert p.pipeline_id == ""
        assert p.actor == ""
