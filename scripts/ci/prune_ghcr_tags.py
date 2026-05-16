"""Prune non-semver GHCR tags older than ``--keep-days`` days.

Kept regardless of age:
  - Semver tags: ``1.0.0``, ``1.0.0-rc.1``, ``1.0.0-beta.2``
  - The ``latest`` tag
  - Untagged digests (typically manifest-list children; deleting them
    would orphan the parent multi-arch manifest)

Deleted: anything else older than the cutoff. Examples in our usage:
``build-<sha>``, ``pr-<n>``, ``main-<sha>``, ``test-*``.

Uses the GitHub CLI for auth — caller exports ``GH_TOKEN`` with
``packages: write`` permission on the org. The ``GITHUB_TOKEN``
provided by Actions can delete org-owned package versions when the
workflow runs in the same org as the package.

Usage:

    python3 scripts/ci/prune_ghcr_tags.py \\
        --org huntridge-labs \\
        --keep-days 14 \\
        argus/scanner-bandit argus/cli
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import subprocess
import sys
from urllib.parse import quote

# Permissive semver matcher: ``MAJOR.MINOR.PATCH`` with an optional
# pre-release tail (``-rc.1``, ``-beta.2``, ``-alpha``, etc.). Build
# metadata after ``+`` is preserved.
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][a-zA-Z0-9.-]+)?$")
KEEP_ALWAYS = {"latest"}


def gh_json(args: list[str]) -> list[dict]:
    out = subprocess.check_output(
        ["gh", "api", "--paginate", *args], text=True
    )
    return json.loads(out)


def gh_delete(path: str) -> None:
    subprocess.check_call(["gh", "api", "--method", "DELETE", path])


def is_keeper(tags: list[str]) -> bool:
    """Return True when any tag on this version pins it as a semver release."""
    if not tags:
        # Untagged digests are often manifest-list children of a
        # multi-arch image — deleting them silently breaks the parent.
        return True
    return any(t in KEEP_ALWAYS or SEMVER_RE.match(t) for t in tags)


def prune(org: str, package: str, keep_days: int, dry_run: bool) -> int:
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=keep_days)
    pkg = quote(package, safe="")
    versions = gh_json([f"orgs/{org}/packages/container/{pkg}/versions"])

    deleted = 0
    for v in versions:
        tags = v.get("metadata", {}).get("container", {}).get("tags", [])
        created = dt.datetime.fromisoformat(
            v["created_at"].replace("Z", "+00:00")
        )
        if is_keeper(tags):
            continue
        if created >= cutoff:
            continue
        prefix = "[dry-run] " if dry_run else ""
        print(
            f"{prefix}delete {package} id={v['id']} "
            f"tags={tags or '<untagged>'} created={v['created_at']}"
        )
        if not dry_run:
            gh_delete(
                f"orgs/{org}/packages/container/{pkg}/versions/{v['id']}"
            )
        deleted += 1
    return deleted


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--org", required=True)
    parser.add_argument("--keep-days", type=int, default=14)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "packages",
        nargs="+",
        help="Package paths under the org (e.g. argus/cli)",
    )
    args = parser.parse_args()

    total = 0
    for package in args.packages:
        n = prune(args.org, package, args.keep_days, args.dry_run)
        verb = "would be deleted" if args.dry_run else "deleted"
        print(f"{package}: {n} version(s) {verb}")
        total += n
    print(f"TOTAL: {total}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
