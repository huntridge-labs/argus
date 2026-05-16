"""Inject container image digests into argus/containers.py.

Called by release-it's ``after:bump`` hook with the new version as
``argv[1]``. Reads image digests from ``ARGUS_DIGEST_<IMAGE>`` env
vars (set by the release workflow's ``build-containers`` job) and
rewrites each Argus-owned image line in ``argus/containers.py`` to
pin ``<version>@sha256:<digest>``.

Env var → image-name mapping (uppercase, ``_`` → ``-``):

    ARGUS_DIGEST_SCANNER_BANDIT       → scanner-bandit
    ARGUS_DIGEST_SCANNER_OPENGREP     → scanner-opengrep
    ARGUS_DIGEST_SCANNER_SUPPLY_CHAIN → scanner-supply-chain
    ARGUS_DIGEST_CLI                  → cli

Adding a new Argus-owned image: build/push it in ``release.yml``, emit
``ARGUS_DIGEST_<NAME>`` as a job output, expose it as an env var on the
``release`` job. No change required here.

If an image line has no matching env var, the line is left as-is and a
warning is printed — useful when running release-it locally to preview
a release that didn't go through the CI build pipeline.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

CONTAINERS_PY = Path("argus/containers.py")

# Matches ``ghcr.io/huntridge-labs/argus/<image>:<tag>[@sha256:<digest>]``.
# The optional digest group lets us update lines that previously had
# no SHA pin as well as lines that already do.
IMAGE_REF = re.compile(
    r"ghcr\.io/huntridge-labs/argus/(?P<image>[\w-]+):(?P<tag>[^\"@]+)"
    r"(?:@sha256:[a-f0-9]+)?"
)


def env_digests() -> dict[str, str]:
    """Return ``{image-name: "sha256:..."}`` from ``ARGUS_DIGEST_*`` env vars."""
    digests: dict[str, str] = {}
    for key, value in os.environ.items():
        if not key.startswith("ARGUS_DIGEST_"):
            continue
        digest = value.strip()
        if not digest:
            continue
        image = key.removeprefix("ARGUS_DIGEST_").lower().replace("_", "-")
        if not digest.startswith("sha256:"):
            digest = f"sha256:{digest}"
        digests[image] = digest
    return digests


def inject(version: str) -> int:
    if not CONTAINERS_PY.exists():
        print(f"ERROR: {CONTAINERS_PY} not found", file=sys.stderr)
        return 1

    digests = env_digests()
    if not digests:
        print(
            "WARN: no ARGUS_DIGEST_* env vars set; image digests left unchanged.",
            file=sys.stderr,
        )

    text = CONTAINERS_PY.read_text()
    missing: list[str] = []
    changed: list[str] = []

    def replace(match: re.Match[str]) -> str:
        image = match.group("image")
        digest = digests.get(image)
        if digest is None:
            missing.append(image)
            return match.group(0)
        new_ref = f"ghcr.io/huntridge-labs/argus/{image}:{version}@{digest}"
        if new_ref != match.group(0):
            changed.append(image)
        return new_ref

    new_text = IMAGE_REF.sub(replace, text)

    if missing:
        print(
            "WARN: digest env var missing for: "
            + ", ".join(sorted(set(missing))),
            file=sys.stderr,
        )

    if new_text != text:
        CONTAINERS_PY.write_text(new_text)
        unique = sorted(set(changed))
        print(
            f"Updated {CONTAINERS_PY} for {len(unique)} image(s): "
            f"{', '.join(unique)}"
        )
    else:
        print(f"No changes to {CONTAINERS_PY}")

    return 0


def main() -> int:
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <version>", file=sys.stderr)
        return 2
    return inject(sys.argv[1])


if __name__ == "__main__":
    sys.exit(main())
