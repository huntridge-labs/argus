#!/usr/bin/env python3
"""Validate that all pinned container image tags exist on their registries.

Catches stale or mistyped tags (e.g., missing v-prefix, yanked versions)
before they ship to users. Uses ``docker manifest inspect`` which resolves
manifests without pulling the full image.

Two kinds of non-zero exit from ``docker manifest inspect`` mean very
different things, and conflating them is how this check red-lined ``main``
for a reason no commit caused:

``manifest unknown`` / ``not found`` / ``unauthorized``
    The pin is genuinely wrong or the content is gone. Always a failure.

``toomanyrequests`` / timeouts / connection resets
    The registry is rate-limiting or unreachable. Says nothing about the
    pin. Anonymous Docker Hub pulls hit this routinely on shared runners.

By default both fail, so the release gate keeps verifying every manifest
before publishing. Pass ``--tolerate-registry-errors`` (PR CI does) to
report the unreachable ones without failing, while a genuinely bad pin
still fails.

Exit codes:
  0 — all images resolve (or only unreachable ones, when tolerated)
  1 — at least one pin is genuinely bad, or a registry was unreachable
      without ``--tolerate-registry-errors``
  2 — docker not available (skipped, not a failure)
"""

import argparse
import shutil
import subprocess
import sys
import time

# Substrings that mean "the registry did not answer", not "the pin is wrong".
TRANSIENT_MARKERS = (
    "toomanyrequests",
    "rate limit",
    "429 too many requests",
    "503 service unavailable",
    "502 bad gateway",
    "context deadline exceeded",
    "client.timeout exceeded",
    "net/http: request canceled",
    "i/o timeout",
    "tls handshake timeout",
    "temporary failure in name resolution",
    "no such host",
    "connection refused",
    "connection reset by peer",
    "eof",
)

RETRY_DELAY_SECONDS = 3


def is_transient(stderr: str) -> bool:
    lowered = stderr.lower()
    return any(marker in lowered for marker in TRANSIENT_MARKERS)


def inspect(image: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "manifest", "inspect", image],
        capture_output=True, text=True, timeout=30,
    )


def inspect_with_retry(image: str, attempts: int = 2) -> subprocess.CompletedProcess:
    """Inspect ``image``, retrying once on a transient registry error.

    A retry clears a momentary blip. It will not clear a sustained rate
    limit, which is why the caller still has to decide what a transient
    failure means.
    """
    result = inspect(image)
    for _ in range(attempts - 1):
        if result.returncode == 0 or not is_transient(result.stderr):
            return result
        time.sleep(RETRY_DELAY_SECONDS)
        result = inspect(image)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--tolerate-registry-errors",
        action="store_true",
        help="Report unreachable registries without failing. Use in PR CI; "
             "leave off for the release gate.",
    )
    args = parser.parse_args(argv)

    from argus.containers import OFFICIAL_IMAGES, CUSTOM_IMAGES

    if not shutil.which("docker"):
        print("docker not found — skipping image manifest check")
        return 2

    all_images = {**OFFICIAL_IMAGES, **CUSTOM_IMAGES}
    print(f"Checking {len(all_images)} container image manifest(s)...\n")

    bad_pins: list[tuple[str, str, str]] = []
    unreachable: list[tuple[str, str, str]] = []

    for name, image in sorted(all_images.items()):
        result = inspect_with_retry(image)
        if result.returncode == 0:
            print(f"  ✅ {name:<20} {image}")
            continue

        err = result.stderr.strip().split("\n")[0][:120]
        if is_transient(err):
            print(f"  ⚠️  {name:<20} {image}")
            print(f"     registry unreachable: {err}")
            unreachable.append((name, image, err))
        else:
            print(f"  ❌ {name:<20} {image}")
            print(f"     {err}")
            bad_pins.append((name, image, err))

    print()
    if bad_pins:
        print(f"{len(bad_pins)} image(s) failed manifest check:")
        for name, image, _ in bad_pins:
            print(f"  {name}: {image}")

    if unreachable:
        print(
            f"{len(unreachable)} image(s) could not be verified because the "
            "registry did not answer:"
        )
        for name, image, _ in unreachable:
            print(f"  {name}: {image}")
        if not args.tolerate_registry_errors:
            print(
                "\nTreating that as a failure. Re-run, or pass "
                "--tolerate-registry-errors if this is PR CI rather than a "
                "release gate."
            )

    if bad_pins:
        return 1
    if unreachable and not args.tolerate_registry_errors:
        return 1
    if unreachable:
        print("\nEvery pin that could be checked resolves.")
        return 0

    print("All images resolve.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
