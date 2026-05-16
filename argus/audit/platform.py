"""CI/CD platform detection.

Auto-detects the CI environment (GitHub Actions, GitLab CI, Jenkins,
or local dev) by inspecting well-known environment variables.
"""

import os
from dataclasses import dataclass


@dataclass
class CIPlatform:
    """Detected CI/CD platform metadata."""

    name: str = "local"
    pipeline_id: str = ""
    job_id: str = ""
    job_name: str = ""
    job_url: str = ""
    pipeline_url: str = ""
    commit_sha: str = ""
    commit_branch: str = ""
    commit_message: str = ""
    repository: str = ""
    actor: str = ""
    runner: str = ""
    server_url: str = ""
    event_name: str = ""


def detect_platform() -> CIPlatform:
    """Auto-detect CI platform from environment variables."""
    if os.environ.get("GITHUB_ACTIONS") == "true":
        return _detect_github()
    if os.environ.get("GITLAB_CI") == "true":
        return _detect_gitlab()
    if os.environ.get("JENKINS_URL"):
        return _detect_jenkins()
    return CIPlatform(
        name="local",
        actor=os.environ.get("USER", "unknown"),
    )


def _detect_github() -> CIPlatform:
    """Extract metadata from GitHub Actions environment."""
    server = os.environ.get("GITHUB_SERVER_URL", "")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    run_url = f"{server}/{repo}/actions/runs/{run_id}" if server and repo else ""

    return CIPlatform(
        name="github",
        pipeline_id=run_id,
        job_id=os.environ.get("GITHUB_JOB", ""),
        job_name=os.environ.get("GITHUB_JOB", ""),
        job_url=run_url,
        pipeline_url=run_url,
        commit_sha=os.environ.get("GITHUB_SHA", ""),
        commit_branch=(
            os.environ.get("GITHUB_HEAD_REF", "")
            or os.environ.get("GITHUB_REF_NAME", "")
        ),
        repository=repo,
        actor=os.environ.get("GITHUB_ACTOR", ""),
        runner=os.environ.get("RUNNER_NAME", ""),
        server_url=server or "https://github.com",
        event_name=os.environ.get("GITHUB_EVENT_NAME", ""),
    )


def _detect_gitlab() -> CIPlatform:
    """Extract metadata from GitLab CI environment."""
    return CIPlatform(
        name="gitlab",
        pipeline_id=os.environ.get("CI_PIPELINE_ID", ""),
        job_id=os.environ.get("CI_JOB_ID", ""),
        job_name=os.environ.get("CI_JOB_NAME", ""),
        job_url=os.environ.get("CI_JOB_URL", ""),
        pipeline_url=os.environ.get("CI_PIPELINE_URL", ""),
        commit_sha=os.environ.get("CI_COMMIT_SHA", ""),
        commit_branch=(
            os.environ.get("CI_COMMIT_BRANCH", "")
            or os.environ.get("CI_MERGE_REQUEST_SOURCE_BRANCH_NAME", "")
        ),
        commit_message=os.environ.get("CI_COMMIT_MESSAGE", ""),
        repository=os.environ.get("CI_PROJECT_PATH", ""),
        actor=os.environ.get("GITLAB_USER_LOGIN", ""),
        runner=os.environ.get("CI_RUNNER_DESCRIPTION", ""),
        server_url=os.environ.get("CI_SERVER_URL", ""),
        event_name=os.environ.get("CI_PIPELINE_SOURCE", ""),
    )


def _detect_jenkins() -> CIPlatform:
    """Extract metadata from Jenkins environment."""
    return CIPlatform(
        name="jenkins",
        pipeline_id=os.environ.get("BUILD_NUMBER", ""),
        job_id=os.environ.get("BUILD_ID", ""),
        job_name=os.environ.get("JOB_NAME", ""),
        job_url=os.environ.get("BUILD_URL", ""),
        commit_sha=os.environ.get("GIT_COMMIT", ""),
        commit_branch=os.environ.get("GIT_BRANCH", ""),
        repository=os.environ.get("JOB_NAME", ""),
        actor=os.environ.get("BUILD_USER", ""),
        server_url=os.environ.get("JENKINS_URL", ""),
    )
