"""End-to-end container-invocation smoke tests.

Every registered container scanner is run against a minimal fixture via
the real ``argus scan`` CLI with ``--fail-on-scanner-error``. That flag
makes argus exit non-zero when a scanner *cannot start* (bad entrypoint,
rejected flags, no output) — as opposed to "ran clean, found nothing".
So a malformed ``docker run`` argv fails here even though the scanner's
fixture-parsing unit tests pass.

This is the layer that catches container-side breakage. Two real bugs
that shipped green (gosec feeding a path list to ``-exclude`` → exit 2;
promptfoo's args hitting the image's ``exec "$@"`` entrypoint as the bare
word ``eval`` → exit 127) would both have failed here.

**Auto-coverage is the point.** The test is parametrized over
``SCANNER_REGISTRY`` and infers how to smoke-test each scanner from its
``category`` — a new directory-scanning scanner (SAST/IaC/secrets/…)
needs zero wiring here. Scanners that need a live target (DAST), a built
image (container), or external config (LLM) are listed in
``SMOKE_EXEMPT`` with a reason. ``test_every_container_scanner_is_covered``
fails if a scanner is neither inferable nor exempt — so the gap can't
silently reopen.

Marked ``slow`` and skipped without Docker. Locally (pre-push) the
registry cache makes image pulls free; in CI the dedicated job scopes to
changed scanners and caches images by digest.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from argus.scanners import SCANNER_REGISTRY

# Repo root (…/argus/tests/test_container_smoke.py → repo). Put on
# PYTHONPATH for the subprocess so `python -m argus` resolves even when
# we run it with cwd set elsewhere for config isolation.
_REPO_ROOT = str(Path(__file__).resolve().parents[2])


# Categories whose scanners take a filesystem path and can be smoke-tested
# by pointing them at a tiny fixture directory. Values match the actual
# ``category`` attributes in the registry (sast/iac/secrets/malware/linter/
# sca/supply-chain). Image-scanning sca tools (grype, trivy) are sca too
# but are listed in SMOKE_EXEMPT, which takes precedence.
_DIRECTORY_CATEGORIES = frozenset({
    "sast", "iac", "secrets", "malware", "linter", "sca", "supply-chain",
})

# Scanners that cannot be dir-smoke-tested here, each with the reason and
# where they ARE covered. Keeping this explicit (rather than silently
# skipping) is what lets test_every_container_scanner_is_covered enforce
# that every scanner is a conscious decision.
SMOKE_EXEMPT: dict[str, str] = {
    "zap": "DAST — needs a live HTTP target; covered by test_e2e_dast.py",
    "container": "needs a built image ref (--image/--discover); covered by test_e2e_container_scan.py",
    "trivy": "container-image sub-scanner; exercised via the 'container' scanner",
    "grype": "container-image sub-scanner; exercised via the 'container' scanner",
    # Pre-registered for the incoming promptfoo scanner (#208): it needs a
    # mounted promptfoo config + provider keys, so the generic directory
    # smoke can't drive it. A dedicated echo-provider smoke (no keys) is the
    # planned follow-up. Listing it here keeps the forcing-function green
    # the moment #208 rebases onto this harness.
    "promptfoo": "LLM eval — needs a promptfoo config + provider keys; echo-provider smoke is a follow-up",
}


def _is_container_scanner(name: str) -> bool:
    """A scanner participates in container smoke testing when it declares
    a pinned container image. Local-only linters (no image) are out of
    scope for *container* invocation checks."""
    inst = SCANNER_REGISTRY[name]()
    return bool(getattr(inst, "container_image", None))


def _container_scanner_names() -> list[str]:
    return sorted(n for n in SCANNER_REGISTRY if _is_container_scanner(n))


def _smoke_argv(name: str, fixture_dir: str) -> list[str] | None:
    """Build the `argus scan` argv for a scanner's smoke run, or None if
    the scanner is exempt / not inferable."""
    if name in SMOKE_EXEMPT:
        return None
    inst = SCANNER_REGISTRY[name]()
    category = getattr(inst, "category", None)
    if category in _DIRECTORY_CATEGORIES:
        return [
            sys.executable, "-m", "argus", "scan", name,
            "--path", fixture_dir,
            "--fail-on-scanner-error",
            "--severity-threshold", "none",
        ]
    return None


@pytest.fixture(scope="module")
def smoke_fixture(tmp_path_factory) -> str:
    """A tiny directory with one innocuous file per common language, so
    every directory scanner has something to chew on without tripping a
    real finding (we assert the scanner *ran*, not what it found)."""
    d = tmp_path_factory.mktemp("smoke")
    (d / "main.py").write_text("def add(a, b):\n    return a + b\n")
    (d / "main.go").write_text("package main\n\nfunc main() {}\n")
    (d / "main.tf").write_text('variable "x" {\n  default = 1\n}\n')
    (d / "Dockerfile").write_text("FROM alpine:3.19\nRUN echo hi\n")
    (d / "script.sh").write_text("#!/bin/bash\necho hello\n")
    (d / "data.yaml").write_text("key: value\n")
    # A lockfile so the dependency (sca) scanners have a manifest to read.
    (d / "requirements.txt").write_text("requests==2.32.0\n")
    # A workflow so the supply-chain scanner (zizmor + actionlint) has a
    # target. Empty-workflow handling is already covered by #185.
    wf = d / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(
        "name: ci\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - uses: actions/checkout@v4\n"
    )
    return str(d)


def _docker_available() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(
            ["docker", "info"], capture_output=True, timeout=10
        ).returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


requires_docker = pytest.mark.skipif(
    not _docker_available(), reason="Docker not available — container smoke skipped"
)


@pytest.mark.slow
@requires_docker
@pytest.mark.parametrize("scanner_name", _container_scanner_names())
def test_container_scanner_invocation_accepted(scanner_name, smoke_fixture):
    """The scanner's container actually runs against a fixture without a
    start-up failure. --fail-on-scanner-error turns 'couldn't start' into
    a non-zero exit, so this catches bad entrypoints / rejected flags."""
    argv = _smoke_argv(scanner_name, smoke_fixture)
    if argv is None:
        pytest.skip(f"{scanner_name}: {SMOKE_EXEMPT.get(scanner_name, 'not a directory scanner')}")

    # Run with cwd = the fixture dir so argus config auto-discovery can't
    # pick up the repo's own argus.yml / per-scanner config (pyproject.toml,
    # etc.). The smoke test validates the scanner's container invocation in
    # isolation, not whatever config happens to sit at the repo root.
    env = {**os.environ, "PYTHONPATH": _REPO_ROOT}
    proc = subprocess.run(
        argv, capture_output=True, text=True, timeout=300,
        cwd=smoke_fixture, env=env,
    )

    # Exit 0 = ran clean (findings suppressed by --fail-on-severity none).
    # Non-zero under --fail-on-scanner-error = the scanner could not run.
    assert proc.returncode == 0, (
        f"{scanner_name} container invocation was rejected "
        f"(exit={proc.returncode}). This usually means a bad entrypoint or "
        f"unaccepted flags.\nstderr tail:\n{proc.stderr[-1500:]}"
    )


@pytest.mark.parametrize("scanner_name", _container_scanner_names())
def test_container_image_is_digest_pinned(scanner_name):
    """Every container scanner's image must be pinned to an immutable
    ``@sha256:`` digest — not a floating tag. A bare tag lets the upstream
    publisher swap bytes under us (the clamav/eslint rot we hit) and
    breaks reproducibility + the content-addressable supply-chain gate.
    No Docker required."""
    image = SCANNER_REGISTRY[scanner_name]().container_image
    assert "@sha256:" in image, (
        f"{scanner_name} image is not digest-pinned: {image!r}. "
        f"Pin it as tag@sha256:... in argus/containers.py."
    )


@pytest.mark.parametrize("scanner_name", _container_scanner_names())
def test_arg_construction_does_not_crash(scanner_name):
    """Constructing the container argv must not raise and must yield a
    non-empty command. Catches scanners whose arg builder blows up on a
    minimal/empty config before any container ever runs. No Docker."""
    from argus.core.scanner_template import ScanPaths

    if scanner_name in SMOKE_EXEMPT:
        # Image-scanning sub-tools (trivy/grype) and external-target
        # scanners require a non-empty config (image ref / target URL),
        # so "empty config" isn't a valid input to assert against.
        pytest.skip(f"{scanner_name}: {SMOKE_EXEMPT[scanner_name]}")

    inst = SCANNER_REGISTRY[scanner_name]()
    if hasattr(inst, "build_args"):
        paths = ScanPaths(workspace="/workspace", output="/tmp/out.json")
        args = inst.build_args(paths, {})
    elif hasattr(inst, "container_args"):
        args = inst.container_args({})
    else:
        pytest.skip(f"{scanner_name}: no build_args/container_args (FileDiscovery linter)")
    assert isinstance(args, list) and args, (
        f"{scanner_name} produced an empty/invalid argv: {args!r}"
    )


def test_every_container_scanner_is_covered():
    """Forcing function: every container scanner must be either
    smoke-inferable (a known directory category) or explicitly exempt.
    A new scanner that's neither fails here — closing the gap that let
    the gosec/promptfoo invocation bugs ship. No Docker required."""
    uncovered = []
    for name in _container_scanner_names():
        inst = SCANNER_REGISTRY[name]()
        category = getattr(inst, "category", None)
        inferable = category in _DIRECTORY_CATEGORIES
        exempt = name in SMOKE_EXEMPT
        if not (inferable or exempt):
            uncovered.append((name, category))
    assert not uncovered, (
        "These container scanners have no smoke coverage. Add a directory "
        "category, or list them in SMOKE_EXEMPT with a reason:\n"
        + "\n".join(f"  - {n} (category={c!r})" for n, c in uncovered)
    )
