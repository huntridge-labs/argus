"""release.yml: a prerelease gets its own image tag but never :latest (ADR-500).

Runs the real ``run:`` scripts from the release job under bash, with a fake
``docker`` on PATH that records its arguments.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
RELEASE = ROOT / ".github" / "workflows" / "release.yml"
REGISTRY = "ghcr.io/huntridge-labs/argus"

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")


def _step(name_prefix: str) -> str:
    steps = yaml.safe_load(RELEASE.read_text(encoding="utf-8"))["jobs"]["release"]["steps"]
    for step in steps:
        if step.get("name", "").startswith(name_prefix):
            return step["run"]
    raise AssertionError(f"no release step named {name_prefix!r}")


def _run(script: str, env: dict[str, str], tmp_path: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", "-e", "-c", script],
        env={"PATH": os.environ["PATH"], **env},
        cwd=tmp_path, capture_output=True, text=True, check=True,
    )


def _captured_env(version_before: str, version_after: str, tmp_path: Path) -> dict[str, str]:
    """Run 'Capture released version' and return what it wrote to GITHUB_ENV."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    node = bin_dir / "node"
    node.write_text(f"#!/bin/sh\necho {version_after}\n")
    node.chmod(0o755)
    github_env = tmp_path / "github_env"
    github_env.write_text("")
    _run(_step("Capture released version"), {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "VERSION_BEFORE": version_before,
        "GITHUB_ENV": str(github_env),
    }, tmp_path)
    pairs = [line.split("=", 1) for line in github_env.read_text().splitlines() if "=" in line]
    return dict(pairs)


def _promoted_tags(captured: dict[str, str], tmp_path: Path) -> list[list[str]]:
    """Run the promote step with a fake docker; return each call's --tag values."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    log = tmp_path / "docker.log"
    docker = bin_dir / "docker"
    docker.write_text(f'#!/bin/sh\necho "$@" >> {log}\n')
    docker.chmod(0o755)
    _run(_step("Promote containers"), {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "IMAGE_NAMES": "cli scanner-bandit",
        "IMAGE_REGISTRY": REGISTRY,
        "BUILD_TAG": "build-abc123-1",
        **captured,
    }, tmp_path)
    calls = []
    for line in log.read_text().splitlines():
        args = line.split()
        calls.append([args[i + 1] for i, a in enumerate(args) if a == "--tag"])
    return calls


def test_final_release_moves_latest(tmp_path):
    captured = _captured_env("1.13.0", "1.14.0", tmp_path)
    assert captured["RELEASED"] == "true"
    assert captured["PRERELEASE"] == ""

    calls = _promoted_tags(captured, tmp_path)

    assert calls == [
        [f"{REGISTRY}/cli:1.14.0", f"{REGISTRY}/cli:latest"],
        [f"{REGISTRY}/scanner-bandit:1.14.0", f"{REGISTRY}/scanner-bandit:latest"],
    ]


@pytest.mark.parametrize("version", ["1.14.0-rc.0", "1.14.0-beta.2", "2.0.0-alpha.1"])
def test_prerelease_never_moves_latest(version, tmp_path):
    captured = _captured_env("1.13.0", version, tmp_path)
    assert captured["PRERELEASE"] == "true"

    calls = _promoted_tags(captured, tmp_path)

    assert calls == [[f"{REGISTRY}/cli:{version}"], [f"{REGISTRY}/scanner-bandit:{version}"]]
    assert not any(tag.endswith(":latest") for call in calls for tag in call)


def test_no_release_cut_sets_nothing_to_promote(tmp_path):
    captured = _captured_env("1.13.0", "1.13.0", tmp_path)
    assert captured == {"RELEASED": ""}
