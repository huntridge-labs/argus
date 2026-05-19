"""Living issue reporters for GitHub and GitLab.

Creates, updates, or closes a single "Argus Config Health" issue
so that config/tool problems surface as a persistent, auto-updating
issue rather than transient CI log output.

Uses stdlib ``urllib`` — no external HTTP library required.
"""

from __future__ import annotations

import json
import logging
import urllib.request
import urllib.error
from typing import Protocol

from .ci_provider import CIContext

logger = logging.getLogger("argus.preflight")

ISSUE_TITLE = "Argus Config Health"
ISSUE_LABEL = "argus-health"


class IssueReporter(Protocol):
    """Protocol for platform-specific issue management."""

    def find_issue(self) -> dict | None: ...
    def create_issue(self, body: str) -> dict | None: ...
    def update_issue(self, issue_id: int, body: str) -> bool: ...
    def close_issue(self, issue_id: int) -> bool: ...


class GitHubIssueReporter:
    """Manage a living issue on GitHub via the REST API."""

    def __init__(self, ctx: CIContext) -> None:
        self._token = ctx.api_token
        self._repo = ctx.repo_slug
        self._api = ctx.api_base

    def find_issue(self) -> dict | None:
        """Find an open issue with the argus-health label."""
        path = f"/repos/{self._repo}/issues"
        params = f"labels={ISSUE_LABEL}&state=open&per_page=1"
        data = self._get(f"{path}?{params}")
        if data and isinstance(data, list) and len(data) > 0:
            return {"number": data[0]["number"], "url": data[0]["html_url"]}
        return None

    def create_issue(self, body: str) -> dict | None:
        """Create a new issue with the argus-health label."""
        path = f"/repos/{self._repo}/issues"
        payload = {
            "title": ISSUE_TITLE,
            "body": body,
            "labels": [ISSUE_LABEL],
        }
        data = self._post(path, payload)
        if data:
            return {"number": data["number"], "url": data["html_url"]}
        return None

    def update_issue(self, issue_number: int, body: str) -> bool:
        """Update the body of an existing issue."""
        path = f"/repos/{self._repo}/issues/{issue_number}"
        return self._patch(path, {"body": body}) is not None

    def close_issue(self, issue_number: int) -> bool:
        """Close an issue with a resolution comment."""
        path = f"/repos/{self._repo}/issues/{issue_number}"
        return self._patch(path, {
            "state": "closed",
            "state_reason": "completed",
            "body": (
                "## Argus Config Health\n\n"
                "All checks pass. Auto-closed by `argus validate --report-issue`."
            ),
        }) is not None

    # -- HTTP helpers (stdlib urllib) --

    def _get(self, path: str) -> list | dict | None:
        return self._request("GET", path)

    def _post(self, path: str, payload: dict) -> dict | None:
        return self._request("POST", path, payload)

    def _patch(self, path: str, payload: dict) -> dict | None:
        return self._request("PATCH", path, payload)

    def _request(
        self, method: str, path: str, payload: dict | None = None
    ) -> list | dict | None:
        url = f"{self._api}{path}"
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self._token}",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        body = json.dumps(payload).encode() if payload else None
        if body:
            headers["Content-Type"] = "application/json"

        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            # B310: url is built from CIContext.api_base (CI-env, trusted)
            # plus an internal path literal; no file:// reachable.
            with urllib.request.urlopen(req, timeout=15) as resp:  # nosec B310
                return json.loads(resp.read().decode())
        except (urllib.error.URLError, json.JSONDecodeError, OSError) as exc:
            logger.warning("GitHub API %s %s failed: %s", method, path, exc)
            return None


class GitLabIssueReporter:
    """Manage a living issue on GitLab via the REST API."""

    def __init__(self, ctx: CIContext) -> None:
        self._token = ctx.api_token
        self._project_id = ctx.project_id  # URL-encoded project path
        self._api = ctx.api_base

    def find_issue(self) -> dict | None:
        """Find an open issue with the argus-health label."""
        path = f"/projects/{self._project_id}/issues"
        params = f"labels={ISSUE_LABEL}&state=opened&per_page=1"
        data = self._get(f"{path}?{params}")
        if data and isinstance(data, list) and len(data) > 0:
            return {"number": data[0]["iid"], "url": data[0]["web_url"]}
        return None

    def create_issue(self, body: str) -> dict | None:
        """Create a new issue with the argus-health label."""
        # GitLab may need the label created first — try anyway,
        # the API auto-creates labels in many configurations.
        path = f"/projects/{self._project_id}/issues"
        payload = {
            "title": ISSUE_TITLE,
            "description": body,
            "labels": ISSUE_LABEL,
        }
        data = self._post(path, payload)
        if data:
            return {"number": data["iid"], "url": data["web_url"]}
        return None

    def update_issue(self, issue_iid: int, body: str) -> bool:
        """Update the description of an existing issue."""
        path = f"/projects/{self._project_id}/issues/{issue_iid}"
        return self._put(path, {"description": body}) is not None

    def close_issue(self, issue_iid: int) -> bool:
        """Close an issue."""
        path = f"/projects/{self._project_id}/issues/{issue_iid}"
        return self._put(path, {
            "state_event": "close",
            "description": (
                "## Argus Config Health\n\n"
                "All checks pass. Auto-closed by `argus validate --report-issue`."
            ),
        }) is not None

    # -- HTTP helpers (stdlib urllib) --

    def _get(self, path: str) -> list | dict | None:
        return self._request("GET", path)

    def _post(self, path: str, payload: dict) -> dict | None:
        return self._request("POST", path, payload)

    def _put(self, path: str, payload: dict) -> dict | None:
        return self._request("PUT", path, payload)

    def _request(
        self, method: str, path: str, payload: dict | None = None
    ) -> list | dict | None:
        url = f"{self._api}{path}"
        headers = {
            "Content-Type": "application/json",
            "JOB-TOKEN": self._token,
        }
        body = json.dumps(payload).encode() if payload else None

        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            # B310: url is built from CIContext.api_base (CI-env, trusted)
            # plus an internal path literal; no file:// reachable.
            with urllib.request.urlopen(req, timeout=15) as resp:  # nosec B310
                return json.loads(resp.read().decode())
        except (urllib.error.URLError, json.JSONDecodeError, OSError) as exc:
            logger.warning("GitLab API %s %s failed: %s", method, path, exc)
            return None


def get_issue_reporter(ctx: CIContext) -> IssueReporter | None:
    """Return the appropriate issue reporter for the detected CI provider.

    Returns None (with a warning) if the provider is unknown or
    the required API token is missing.
    """
    if ctx.provider == "github":
        if not ctx.api_token:
            logger.warning(
                "GitHub Actions detected but GITHUB_TOKEN not set — "
                "cannot manage issues. Pass secrets.GITHUB_TOKEN to the job."
            )
            return None
        if not ctx.repo_slug:
            logger.warning("GITHUB_REPOSITORY not set — cannot manage issues.")
            return None
        return GitHubIssueReporter(ctx)

    if ctx.provider == "gitlab":
        if not ctx.api_token:
            logger.warning(
                "GitLab CI detected but CI_JOB_TOKEN not set — "
                "cannot manage issues."
            )
            return None
        if not ctx.project_id:
            logger.warning("CI_PROJECT_PATH not set — cannot manage issues.")
            return None
        return GitLabIssueReporter(ctx)

    logger.warning(
        "CI provider not detected (not GitHub Actions or GitLab CI) — "
        "skipping issue reporting."
    )
    return None
