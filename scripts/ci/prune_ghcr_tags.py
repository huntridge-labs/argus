"""Prune non-semver GHCR tags older than ``--keep-days`` days.

Kept regardless of age:
  - Semver tags: ``1.0.0``, ``1.0.0-rc.1``, ``1.0.0-beta.2``
  - The ``latest`` tag
  - Untagged digests (typically manifest-list children; deleting them
    would orphan the parent multi-arch manifest)
  - Cosign artifacts (``sha256-<subject>``, optionally suffixed ``.sig`` /
    ``.att`` / ``.sbom``) whose subject image is itself being kept — those
    are the signature and attestation for a live release, and deleting them
    breaks ``cosign verify`` for anyone pulling that tag

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

# Cosign publishes a signature/attestation as its own tag derived from the
# digest of the image it describes: ``sha256-<64 hex>`` with an optional
# ``.sig`` / ``.att`` / ``.sbom`` suffix. Such a tag is meaningless on its own
# and must outlive nothing — but it must outlive exactly as long as its
# subject image does.
COSIGN_TAG_RE = re.compile(
    r"^sha256-(?P<subject>[a-f0-9]{64})(?:\.(?:sig|att|sbom))?$"
)


def gh_json(args: list[str]) -> list[dict]:
    out = subprocess.check_output(
        ["gh", "api", "--paginate", *args], text=True
    )
    return json.loads(out)


def gh_delete(path: str) -> bool:
    """Delete a package version. Return False when it was already gone.

    Deleting a manifest-list parent cascades to versions GitHub considers
    dependent on it, so a version enumerated at the start of the run can
    vanish before we reach it. A 404 means the state we wanted is already
    true, which is success, not failure — the job used to abort the whole
    sweep on the first one. Any other error still raises.
    """
    proc = subprocess.run(
        ["gh", "api", "--method", "DELETE", path],
        capture_output=True,
        text=True,
    )
    if proc.returncode == 0:
        return True

    combined = f"{proc.stdout}\n{proc.stderr}"
    if "404" in combined or "not found" in combined.lower():
        print(f"  already gone (HTTP 404): {path}")
        return False

    raise RuntimeError(
        f"DELETE failed for {path}: {combined.strip()[:300]}"
    )


def cosign_subject(tags: list[str]) -> str | None:
    """Return the digest a cosign artifact describes, or None if not one."""
    for tag in tags:
        match = COSIGN_TAG_RE.match(tag)
        if match:
            return f"sha256:{match.group('subject')}"
    return None


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

    # Pass 1 — decide which image versions survive, so pass 2 can tell a
    # cosign artifact that still guards a live release from one whose subject
    # is on its way out.
    surviving_digests: set[str] = set()
    candidates: list[tuple[dict, list[str]]] = []
    for v in versions:
        tags = v.get("metadata", {}).get("container", {}).get("tags", [])
        created = dt.datetime.fromisoformat(
            v["created_at"].replace("Z", "+00:00")
        )
        if is_keeper(tags) or created >= cutoff:
            surviving_digests.add(v["name"])
            continue
        candidates.append((v, tags))

    # Pass 2 — delete, holding back signatures whose subject image survives.
    deleted = 0
    for v, tags in candidates:
        subject = cosign_subject(tags)
        if subject and subject in surviving_digests:
            print(
                f"keep {package} id={v['id']} tags={tags} "
                f"— cosign artifact for surviving image {subject[:19]}…"
            )
            surviving_digests.add(v["name"])
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
