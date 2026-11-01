"""Tests for ``scripts/ci/package_sbom.py`` and its wiring in release.yml.

The release job can't run from a PR, so these lock down what the wheel's
SBOM claims (ADR-528): it names the wheel by version and sha256, lists
only runtime dependencies, scopes extras-only packages as optional, and
gets signed and attached before PyPI publish.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import zipfile
from pathlib import Path

import pytest

from scripts.ci import package_sbom as ps
from tests.unit.test_image_sboms import release_steps, write_bundle

VERSION = "1.15.0"
WHEEL_NAME = f"argus_security-{VERSION}-py3-none-any.whl"
REQUIRES = [
    "PyYAML>=6.0.2",
    "flake8>=7.0",
    'requests>=2.33.0; extra == "ai"',
    'textual>=8.0; extra == "terminal"',
    'argus-security[ai,terminal]; extra == "all"',
]
EXTRAS = ["ai", "terminal", "all"]
BASE = ["pyyaml", "flake8", "pycodestyle"]
BY_EXTRA = {
    "ai": ["requests", "certifi"],
    "terminal": ["textual", "rich"],
    "all": ["requests", "certifi", "textual", "rich"],
}


def make_wheel(tmp_path: Path, requires=REQUIRES, extras=EXTRAS) -> Path:
    lines = ["Metadata-Version: 2.4", "Name: argus-security", f"Version: {VERSION}"]
    lines += [f"Provides-Extra: {e}" for e in extras]
    lines += [f"Requires-Dist: {r}" for r in requires]
    wheel = tmp_path / WHEEL_NAME
    with zipfile.ZipFile(wheel, "w") as zf:
        zf.writestr(f"argus_security-{VERSION}.dist-info/METADATA", "\n".join(lines) + "\n")
        zf.writestr("argus/__init__.py", f'__version__ = "{VERSION}"\n')
    return wheel


def uv_bom(names: list[str]) -> dict:
    """What ``uv export --format cyclonedx1.5`` prints, trimmed."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {"component": {
            "type": "library", "bom-ref": "argus-security-1", "name": "argus-security",
            "properties": [{"name": "uv:package:is_project_root", "value": "true"}],
        }},
        "components": [
            {"type": "library", "bom-ref": f"{n}-1@1.0", "name": n, "version": "1.0",
             "purl": f"pkg:pypi/{n}@1.0"}
            for n in names
        ],
    }


class FakeUv:
    """Answers ``uv export`` for the base install, one extra, or all extras."""

    def __init__(self, base=BASE, by_extra=BY_EXTRA, fail=False):
        self.base, self.by_extra, self.fail = base, by_extra, fail
        self.calls: list[list[str]] = []

    def __call__(self, cmd, **_):
        self.calls.append(cmd)
        if self.fail:
            return subprocess.CompletedProcess(cmd, 2, "", "lockfile needs to be updated")
        if "--all-extras" in cmd:
            names = self.base + sorted({n for ns in self.by_extra.values() for n in ns})
        elif "--extra" in cmd:
            names = self.base + self.by_extra[cmd[cmd.index("--extra") + 1]]
        else:
            names = list(self.base)
        return subprocess.CompletedProcess(cmd, 0, json.dumps(uv_bom(names)), "")


def generate(tmp_path, monkeypatch, uv=None, **wheel_kwargs):
    uv = uv or FakeUv()
    monkeypatch.setattr(ps.subprocess, "run", uv)
    env_file = tmp_path / "github_env"
    monkeypatch.setenv("GITHUB_ENV", str(env_file))
    wheel = make_wheel(tmp_path, **wheel_kwargs)
    out = tmp_path / "sboms"
    rc = ps.main(["generate", "--wheel", str(wheel), "--out-dir", str(out)])
    return rc, wheel, out / ps.sbom_name(VERSION), env_file, uv


def components(sbom_path: Path) -> dict:
    return {c["name"]: c for c in json.loads(sbom_path.read_text())["components"]}


class TestGenerate:
    def test_root_names_the_wheel_by_version_purl_and_sha256(self, tmp_path, monkeypatch):
        rc, wheel, sbom_path, _, _ = generate(tmp_path, monkeypatch)
        assert rc == 0
        root = json.loads(sbom_path.read_text())["metadata"]["component"]
        assert root["name"] == "argus-security"
        assert root["version"] == VERSION
        assert root["purl"] == f"pkg:pypi/argus-security@{VERSION}"
        assert root["hashes"] == [{"alg": "SHA-256",
                                   "content": hashlib.sha256(wheel.read_bytes()).hexdigest()}]

    def test_base_is_required_and_extras_are_optional_with_their_names(self, tmp_path, monkeypatch):
        _, _, sbom_path, _, _ = generate(tmp_path, monkeypatch)
        comps = components(sbom_path)
        for name in BASE:
            assert comps[name]["scope"] == "required"
            assert "properties" not in comps[name]
        assert comps["certifi"]["scope"] == "optional"
        assert comps["certifi"]["properties"] == [{"name": "argus:extras", "value": "ai,all"}]
        assert comps["textual"]["properties"] == [{"name": "argus:extras", "value": "all,terminal"}]

    def test_never_exports_the_dev_group(self, tmp_path, monkeypatch):
        _, _, _, _, uv = generate(tmp_path, monkeypatch)
        assert len(uv.calls) == 1 + len(EXTRAS) + 1
        for cmd in uv.calls:
            assert cmd[:2] == ["uv", "export"]
            assert {"--no-dev", "--frozen"} <= set(cmd)
            assert cmd[cmd.index("--format") + 1] == "cyclonedx1.5"

    def test_exports_paths_for_the_attest_step(self, tmp_path, monkeypatch):
        _, wheel, sbom_path, env_file, _ = generate(tmp_path, monkeypatch)
        assert env_file.read_text().splitlines() == [
            f"PACKAGE_SBOM_PATH={sbom_path.resolve()}",
            f"PACKAGE_WHEEL={wheel.resolve()}",
        ]

    def test_dependency_the_lock_does_not_export_fails(self, tmp_path, monkeypatch, capsys):
        rc, *_ = generate(tmp_path, monkeypatch, requires=[*REQUIRES, "packaging>=21"])
        assert rc == 1
        assert "wheel declares packaging" in capsys.readouterr().err

    def test_uv_export_failure_fails_the_run(self, tmp_path, monkeypatch, capsys):
        rc, *_ = generate(tmp_path, monkeypatch, uv=FakeUv(fail=True))
        assert rc == 1
        assert "lockfile needs to be updated" in capsys.readouterr().err

    def test_against_the_real_lock(self, tmp_path):
        """The checked-in uv.lock covers every runtime dependency in pyproject.toml."""
        if subprocess.run(["uv", "--version"], capture_output=True, check=False).returncode:
            pytest.skip("uv not installed")
        base = ps.component_names(ps.export([]))
        everything = ps.component_names(ps.export(["--all-extras"]))
        assert {"pyyaml", "flake8", "packaging"} <= base
        assert base < everything
        assert not {"pytest", "virtualenv", "filelock"} & everything


class TestCollect:
    def attest(self, tmp_path, monkeypatch, digest=None, predicate=None):
        _, wheel, sbom_path, _, _ = generate(tmp_path, monkeypatch)
        sbom = json.loads(sbom_path.read_text())
        digest = digest or "sha256:" + hashlib.sha256(wheel.read_bytes()).hexdigest()
        bundle = write_bundle(tmp_path / "bundle.json", WHEEL_NAME, digest, predicate or sbom)
        monkeypatch.setenv("ATTEST_STEPS", json.dumps(
            {ps.ATTEST_STEP_ID: {"outputs": {"bundle-path": str(bundle)}}}))
        return ps.main(["collect", "--wheel", str(wheel), "--sbom", str(sbom_path)]), sbom_path

    def test_copies_the_checked_bundle_next_to_the_sbom(self, tmp_path, monkeypatch):
        rc, sbom_path = self.attest(tmp_path, monkeypatch)
        assert rc == 0
        assert sbom_path.with_name(f"{sbom_path.name}.sigstore.json").is_file()

    def test_rejects_a_bundle_for_another_file(self, tmp_path, monkeypatch, capsys):
        rc, _ = self.attest(tmp_path, monkeypatch, digest="sha256:" + "0" * 64)
        assert rc == 1
        assert "bundle subject" in capsys.readouterr().err

    def test_rejects_a_bundle_signing_another_sbom(self, tmp_path, monkeypatch, capsys):
        rc, _ = self.attest(tmp_path, monkeypatch, predicate={"bomFormat": "CycloneDX"})
        assert rc == 1
        assert "signed predicate" in capsys.readouterr().err

    def test_missing_attest_step_fails(self, tmp_path, monkeypatch, capsys):
        _, wheel, sbom_path, _, _ = generate(tmp_path, monkeypatch)
        monkeypatch.setenv("ATTEST_STEPS", "{}")
        assert ps.main(["collect", "--wheel", str(wheel), "--sbom", str(sbom_path)]) == 1
        assert "no attest step 'attest-package'" in capsys.readouterr().err


class TestReleaseWorkflow:
    def test_package_sbom_is_signed_and_attached_before_pypi(self):
        steps = release_steps()
        names = [s.get("name") for s in steps]
        order = [
            "Build wheel",
            "Smoke test",
            "Generate package SBOM",
            "Attest SBOM (package)",
            "Attach package SBOM to the GitHub release",
            "Publish to PyPI",
            "Publish the GitHub release",
        ]
        positions = [names.index(n) for n in order]
        assert positions == sorted(positions)
        for name in order[2:5]:
            step = steps[names.index(name)]
            assert step["if"] == "env.RELEASED == 'true'"
            assert not step.get("continue-on-error")

    def test_attest_step_signs_the_wheel_with_the_sbom(self):
        attest = next(s for s in release_steps() if s.get("id") == ps.ATTEST_STEP_ID)
        assert attest["uses"].startswith("actions/attest@")
        assert attest["with"] == {
            "subject-path": "${{ env.PACKAGE_WHEEL }}",
            "sbom-path": "${{ env.PACKAGE_SBOM_PATH }}",
        }

    def test_attach_step_collects_then_uploads_both_files(self):
        attach = next(s for s in release_steps()
                      if s.get("name") == "Attach package SBOM to the GitHub release")
        assert attach["env"]["ATTEST_STEPS"] == "${{ toJSON(steps) }}"
        run = attach["run"]
        assert run.index("package_sbom collect") < run.index("gh release upload")
        assert '"${PACKAGE_SBOM_PATH}.sigstore.json"' in run

    def test_sbom_stays_out_of_dist(self):
        """pypa/gh-action-pypi-publish uploads everything in dist/."""
        gen = next(s for s in release_steps() if s.get("name") == "Generate package SBOM")
        assert '--out-dir "${SBOM_DIR}"' in gen["run"]
