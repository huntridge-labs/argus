"""CI provider detection from environment variables.

Detects GitHub Actions and GitLab CI, extracting API credentials
and repository identifiers needed for issue management.
"""

import os
from dataclasses import dataclass


@dataclass
class CIContext:
    """Detected CI environment context."""

    provider: str           # "github", "gitlab", "unknown"
    api_token: str | None   # GITHUB_TOKEN or CI_JOB_TOKEN
    repo_slug: str | None   # e.g. "huntridge-labs/argus"
    api_base: str | None    # e.g. "https://api.github.com"
    project_id: str | None  # GitLab only: URL-encoded project path


def detect_ci_provider() -> CIContext:
    """Detect the current CI provider from environment variables.

    Checks for GitHub Actions and GitLab CI in that order.
    Returns a CIContext with provider="unknown" if neither is detected.
    """
    if os.environ.get("GITHUB_ACTIONS") == "true":
        return _detect_github()
    if os.environ.get("GITLAB_CI") == "true":
        return _detect_gitlab()
    return CIContext(
        provider="unknown",
        api_token=None,
        repo_slug=None,
        api_base=None,
        project_id=None,
    )


def _detect_github() -> CIContext:
    """Extract GitHub Actions context from environment."""
    server_url = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    # GHES uses {server}/api/v3; github.com uses api.github.com
    if "github.com" in server_url:
        api_base = "https://api.github.com"
    else:
        api_base = f"{server_url.rstrip('/')}/api/v3"

    return CIContext(
        provider="github",
        api_token=os.environ.get("GITHUB_TOKEN"),
        repo_slug=os.environ.get("GITHUB_REPOSITORY"),
        api_base=api_base,
        project_id=None,
    )


def _detect_gitlab() -> CIContext:
    """Extract GitLab CI context from environment."""
    from urllib.parse import quote

    api_base = os.environ.get("CI_API_V4_URL")
    if not api_base:
        server = os.environ.get("CI_SERVER_URL", "https://gitlab.com")
        api_base = f"{server.rstrip('/')}/api/v4"

    project_path = os.environ.get("CI_PROJECT_PATH", "")
    project_id = quote(project_path, safe="") if project_path else None

    return CIContext(
        provider="gitlab",
        api_token=os.environ.get("CI_JOB_TOKEN"),
        repo_slug=project_path or None,
        api_base=api_base,
        project_id=project_id,
    )
