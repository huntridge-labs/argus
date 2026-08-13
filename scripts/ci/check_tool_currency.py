#!/usr/bin/env python3
"""Report scanner pins that upstream has already moved past.

Two independent checks:

``consistency``
    The same tool is pinned in two places — ``OFFICIAL_IMAGES`` in
    ``argus/containers.py`` (the container-fallback path) and an
    ``ARG <TOOL>_VERSION`` in ``docker/Dockerfile.cli`` (baked into the CLI
    image). Renovate updates those through two different groups, so one can
    land without the other and a scan then gets a different tool version
    depending on which path it took. Offline and deterministic, so this one
    is a hard failure.

``currency``
    Compares each pin against the newest upstream release that is already
    older than ``--min-age-days``, i.e. one we are allowed to adopt under the
    supply-chain policy in ``.github/renovate.json``. Needs the network and
    depends on upstream release cadence, so by default it reports without
    failing — a tool releasing upstream is not a reason to redden ``main``.

Why this exists: ``osv-scanner`` sat 46 days behind and ``tflint`` 17 days
behind while Renovate's own dashboard listed both updates as available and
its ``container-images`` group merged three times in between. Whatever the
cause on Renovate's side, nothing in the repo noticed. This does.

Usage::

    python3 scripts/ci/check_tool_currency.py                  # both checks
    python3 scripts/ci/check_tool_currency.py --consistency-only
    python3 scripts/ci/check_tool_currency.py --fail-on-stale   # CI gate
    python3 scripts/ci/check_tool_currency.py --format=markdown # issue body

Exit codes:
  0 — nothing to report (or stale pins found without ``--fail-on-stale``)
  1 — a consistency mismatch, or staleness with ``--fail-on-stale``
  2 — upstream could not be queried (network); never a hard failure
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field

# Tools pinned in BOTH argus/containers.py and docker/Dockerfile.cli.
# image key in OFFICIAL_IMAGES -> ARG prefix in the Dockerfile.
DUAL_PINNED: dict[str, str] = {
    "trivy": "TRIVY",
    "grype": "GRYPE",
    "syft": "SYFT",
    "gitleaks": "GITLEAKS",
}

# image key -> GitHub "owner/repo" whose releases define "latest".
# Tools on a mutable tag (kics, gosec, shellcheck, eslint) are deliberately
# absent: their publishers ship no versioned tags, so there is no pin for us
# to compare and the digest is the only control. Our own huntridge-labs images
# are release-managed, not upstream-tracked.
UPSTREAM_REPOS: dict[str, str] = {
    "trivy": "aquasecurity/trivy",
    "grype": "anchore/grype",
    "syft": "anchore/syft",
    "gitleaks": "gitleaks/gitleaks",
    "checkov": "bridgecrewio/checkov",
    "osv-scanner": "google/osv-scanner",
    "zap": "zaproxy/zaproxy",
    "promptfoo": "promptfoo/promptfoo",
    "hadolint": "hadolint/hadolint",
    "tflint": "terraform-linters/tflint",
    "terraform": "hashicorp/terraform",
}

# The image path must exclude ':' so the tag, not the digest, lands in
# `version` — '[^"]+:' would greedily run past '@sha256' to the last colon and
# capture the digest hex as the version instead.
IMAGE_RE = re.compile(
    r'"(?P<key>[a-z0-9-]+)":\s*"'
    r'(?P<image>[^"@:]+):'
    r'(?P<version>[^"@]+)'
    r'(?:@sha256:(?P<digest>[a-f0-9]{64}))?"'
)
ARG_RE = re.compile(r"^ARG (?P<name>[A-Z0-9_]+)_VERSION=(?P<version>[\w.-]+)", re.M)

# Statuses worth a second attempt. GitHub answers a tripped secondary rate
# limit with 403 (occasionally 429) and load-sheds with 5xx — all transient.
# A 404 means the repo was renamed or deleted, so retrying only burns quota;
# that one surfaces on the first attempt so the rename gets fixed here.
RETRYABLE_STATUS: frozenset[int] = frozenset({403, 429, 500, 502, 503, 504})
FETCH_ATTEMPTS = 3
BACKOFF_BASE_SECONDS = 2.0
MAX_BACKOFF_SECONDS = 30.0


@dataclass
class Finding:
    kind: str
    tool: str
    detail: str


@dataclass
class Report:
    mismatches: list[Finding] = field(default_factory=list)
    stale: list[Finding] = field(default_factory=list)
    unknown: list[Finding] = field(default_factory=list)


def normalise(version: str) -> str:
    """Strip a leading ``v`` so ``v1.2.3`` and ``1.2.3`` compare equal."""
    return version[1:] if version.startswith("v") else version


def parse_images(source: str) -> dict[str, str]:
    """Map image key -> pinned version from a containers.py source string."""
    return {
        m.group("key"): m.group("version")
        for m in IMAGE_RE.finditer(source)
        if "/" in m.group("image")
    }


def parse_args_versions(dockerfile: str) -> dict[str, str]:
    """Map ARG prefix -> pinned version from a Dockerfile source string."""
    return {m.group("name"): m.group("version") for m in ARG_RE.finditer(dockerfile)}


def check_consistency(images: dict[str, str], args_versions: dict[str, str]) -> list[Finding]:
    """Flag tools whose two pins disagree."""
    out: list[Finding] = []
    for key, arg_prefix in DUAL_PINNED.items():
        image_version = images.get(key)
        arg_version = args_versions.get(arg_prefix)
        if image_version is None or arg_version is None:
            continue
        if normalise(image_version) != normalise(arg_version):
            out.append(
                Finding(
                    "mismatch",
                    key,
                    f"containers.py pins {image_version} but "
                    f"Dockerfile.cli pins ARG {arg_prefix}_VERSION={arg_version}",
                )
            )
    return out


def _retry_delay(error: Exception | None, attempt: int) -> float:
    """Seconds to wait before the next attempt.

    Honours ``Retry-After`` when GitHub sends it — on a secondary rate limit it
    tells us exactly how long to back off, and guessing shorter just trips the
    limit again. Falls back to exponential backoff, capped so a wedged upstream
    cannot stall the job.
    """
    headers = getattr(error, "headers", None)
    if headers is not None:
        retry_after = headers.get("Retry-After")
        if retry_after:
            try:
                return min(float(retry_after), MAX_BACKOFF_SECONDS)
            except (TypeError, ValueError):
                pass
    return min(BACKOFF_BASE_SECONDS**attempt, MAX_BACKOFF_SECONDS)


def fetch_releases(
    repo: str,
    *,
    attempts: int = FETCH_ATTEMPTS,
    sleep: Callable[[float], None] = time.sleep,
) -> list[dict]:
    """Return upstream releases, newest first. Raises on transport failure.

    Retries transient failures. A single 403 from a tripped secondary rate
    limit used to drop the tool straight into the "Not checked" bucket, and
    that bucket reads as "nothing to do" — the report filed for #382 listed
    checkov and trivy as unchecked while both endpoints were in fact healthy,
    so the run silently under-stated how many pins were behind. Retrying is
    what makes "not checked" mean the upstream is genuinely unreachable.
    """
    url = f"https://api.github.com/repos/{repo}/releases?per_page=30"
    # Resolved once: _gh_token() may shell out to `gh auth token`, which has no
    # business running per attempt.
    token = _gh_token()
    last_error: Exception | None = None
    for attempt in range(1, max(1, attempts) + 1):
        request = urllib.request.Request(
            url, headers={"Accept": "application/vnd.github+json", "User-Agent": "argus-ci"}
        )
        if token:
            request.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                return json.load(response)
        except urllib.error.HTTPError as exc:
            # HTTPError subclasses URLError subclasses OSError, so it must be
            # caught first for the status check to get a look at all.
            if exc.code not in RETRYABLE_STATUS:
                raise
            last_error = exc
        except (urllib.error.URLError, OSError, ValueError) as exc:
            # ValueError covers a truncated body failing json.load, which is
            # as transient as the socket error that caused it.
            last_error = exc
        if attempt < max(1, attempts):
            sleep(_retry_delay(last_error, attempt))
    raise last_error if last_error is not None else OSError(f"no attempt made for {repo}")


def _gh_token() -> str | None:
    """Best-effort token so CI runs are not rate-limited."""
    import os

    for name in ("GH_TOKEN", "GITHUB_TOKEN"):
        if os.environ.get(name):
            return os.environ[name]
    try:
        out = subprocess.run(
            ["gh", "auth", "token"], capture_output=True, text=True, timeout=10
        )
        return out.stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def newest_eligible(
    releases: list[dict], min_age_days: int, now: dt.datetime
) -> tuple[str, int] | None:
    """Newest non-prerelease already older than ``min_age_days``.

    Returns ``(tag, age_in_days)``. Releases inside the cooling window are
    skipped rather than reported, because adopting them would violate the
    supply-chain policy the age gate exists to enforce.
    """
    for release in releases:
        if release.get("draft") or release.get("prerelease"):
            continue
        published = release.get("published_at")
        if not published:
            continue
        age = (now - dt.datetime.fromisoformat(published.replace("Z", "+00:00"))).days
        if age >= min_age_days:
            return release["tag_name"], age
    return None


def check_currency(
    images: dict[str, str], min_age_days: int, now: dt.datetime
) -> tuple[list[Finding], list[Finding]]:
    stale: list[Finding] = []
    unknown: list[Finding] = []
    for key, repo in sorted(UPSTREAM_REPOS.items()):
        pinned = images.get(key)
        if pinned is None:
            continue
        try:
            releases = fetch_releases(repo)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            unknown.append(
                Finding(
                    "unknown",
                    key,
                    f"could not query {repo} after {FETCH_ATTEMPTS} attempt(s): {exc}",
                )
            )
            continue
        eligible = newest_eligible(releases, min_age_days, now)
        if eligible is None:
            continue
        tag, age = eligible
        if normalise(tag) != normalise(pinned):
            stale.append(
                Finding(
                    "stale",
                    key,
                    f"pinned {pinned}, {tag} available and {age}d old "
                    f"(>= {min_age_days}d gate) — {repo}",
                )
            )
    return stale, unknown


def render(report: Report, fmt: str, min_age_days: int) -> str:
    if fmt == "markdown":
        lines = ["## Scanner pin currency", ""]
        if report.mismatches:
            lines += ["### Inconsistent pins (blocking)", ""]
            lines += [f"- **{f.tool}** — {f.detail}" for f in report.mismatches] + [""]
        if report.stale:
            lines += [
                f"### Behind upstream (past the {min_age_days}-day gate)",
                "",
            ]
            lines += [f"- **{f.tool}** — {f.detail}" for f in report.stale] + [""]
        if report.unknown:
            lines += [
                "### Could not verify — currency UNKNOWN, not confirmed current",
                "",
                (
                    "These pins were not compared against upstream. Treat them "
                    "as unchecked, not as up to date."
                ),
                "",
            ]
            lines += [f"- {f.tool} — {f.detail}" for f in report.unknown] + [""]
        if not (report.mismatches or report.stale or report.unknown):
            lines += ["Every tracked pin is current. Nothing to do."]
        return "\n".join(lines)

    out = []
    for f in report.mismatches:
        out.append(f"MISMATCH  {f.tool}: {f.detail}")
    for f in report.stale:
        out.append(f"STALE     {f.tool}: {f.detail}")
    for f in report.unknown:
        out.append(f"UNKNOWN   {f.tool}: {f.detail}")
    if not out:
        out.append("All tracked pins current and consistent.")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--min-age-days", type=int, default=7)
    parser.add_argument("--fail-on-stale", action="store_true")
    parser.add_argument("--consistency-only", action="store_true")
    parser.add_argument("--format", choices=("text", "markdown"), default="text")
    parser.add_argument("--containers", default="argus/containers.py")
    parser.add_argument("--dockerfile", default="docker/Dockerfile.cli")
    args = parser.parse_args(argv)

    with open(args.containers) as fh:
        images = parse_images(fh.read())
    with open(args.dockerfile) as fh:
        args_versions = parse_args_versions(fh.read())

    report = Report(mismatches=check_consistency(images, args_versions))
    if not args.consistency_only:
        now = dt.datetime.now(dt.timezone.utc)
        report.stale, report.unknown = check_currency(images, args.min_age_days, now)

    print(render(report, args.format, args.min_age_days))

    if report.mismatches:
        return 1
    if report.stale and args.fail_on_stale:
        return 1
    if report.unknown and not report.stale:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
