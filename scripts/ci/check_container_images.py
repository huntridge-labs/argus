#!/usr/bin/env python3
"""Validate that all pinned container image tags exist on their registries.

Catches stale or mistyped tags (e.g., missing v-prefix, yanked versions)
before they ship to users. Uses ``docker manifest inspect`` which resolves
manifests without pulling the full image.

Exit codes:
  0 — all images resolve
  1 — one or more images failed
  2 — docker not available (skipped, not a failure)
"""

import shutil
import subprocess
import sys


def main() -> int:
    from argus.containers import OFFICIAL_IMAGES, CUSTOM_IMAGES

    if not shutil.which("docker"):
        print("docker not found — skipping image manifest check")
        return 2

    all_images = {**OFFICIAL_IMAGES, **CUSTOM_IMAGES}
    print(f"Checking {len(all_images)} container image manifest(s)...\n")

    failures = []
    for name, image in sorted(all_images.items()):
        result = subprocess.run(
            ["docker", "manifest", "inspect", image],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            print(f"  ✅ {name:<20} {image}")
        else:
            err = result.stderr.strip().split("\n")[0][:100]
            print(f"  ❌ {name:<20} {image}")
            print(f"     {err}")
            failures.append((name, image, err))

    print()
    if failures:
        print(f"{len(failures)} image(s) failed manifest check:")
        for name, image, err in failures:
            print(f"  {name}: {image}")
        return 1

    print("All images resolve.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
