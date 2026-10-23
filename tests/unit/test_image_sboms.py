"""Tests for ``scripts/ci/image_sboms.py`` and its wiring in release.yml.

The release job can't run from a PR, so these lock down the parts that
decide what gets signed (ADR-489): which digest each SBOM describes,
which digest each attestation names, and that every image in the build
loop has its attest steps.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from argus.containers import OFFICIAL_IMAGES
from scripts.ci import image_sboms as sb

REGISTRY = "ghcr.io/huntridge-labs/argus"
NAME = f"{REGISTRY}/cli"
AMD = "sha256:" + "a" * 64
ARM = "sha256:" + "b" * 64
SHA12 = "0123456789ab"
NOW = datetime(2026, 10, 23, 12, 0, tzinfo=UTC)
RELEASE_YML = Path(__file__).resolve().parents[2] / ".github/workflows/release.yml"


def raw_index(manifests=None) -> tuple[str, str]:
    """A buildx-style index (platforms + provenance manifests) and its digest."""
    manifests = manifests if manifests is not None else [
        {"digest": AMD, "platform": {"os": "linux", "architecture": "amd64"}},
        {"digest": ARM, "platform": {"os": "linux", "architecture": "arm64"}},
        {
            "digest": "sha256:" + "c" * 64,
            "platform": {"os": "unknown", "architecture": "unknown"},
            "annotations": {"vnd.docker.reference.type": "attestation-manifest"},
        },
    ]
    raw = json.dumps({"schemaVersion": 2, "manifests": manifests}, indent=2)
    return raw, "sha256:" + hashlib.sha256(raw.encode()).hexdigest()


def syft_sbom(name: str, digest: str) -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": "urn:uuid:1",
        "metadata": {"component": {"type": "container", "name": name, "version": digest}},
        "components": [{"type": "library", "name": "openssl", "version": "3.5.0"}],
    }


def completed(stdout: str = "", returncode: int = 0, stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


class FakeDocker:
    """Answers ``imagetools inspect --raw`` and ``docker run <syft>``."""

    def __init__(self, indexes: dict[str, str]):
        self.indexes = indexes
        self.calls: list[list[str]] = []

    def __call__(self, cmd):
        self.calls.append(cmd)
        if cmd[:4] == ["docker", "buildx", "imagetools", "inspect"]:
            ref = cmd[-1]
            if ref not in self.indexes:
                return completed(returncode=1, stderr="manifest unknown")
            return completed(self.indexes[ref])
        subject = next(a for a in cmd if a.startswith("registry:")).removeprefix("registry:")
        name, _, digest = subject.partition("@")
        return completed(json.dumps(syft_sbom(name, digest)))


class TestPlatformDigests:
    def test_maps_each_platform_and_skips_provenance_manifests(self):
        raw, digest = raw_index()
        assert sb.platform_digests(raw, digest) == {"linux/amd64": AMD, "linux/arm64": ARM}

    def test_rejects_bytes_that_are_not_the_pushed_index(self):
        raw, _ = raw_index()
        with pytest.raises(sb.SbomError, match="hash to"):
            sb.platform_digests(raw, "sha256:" + "0" * 64)

    def test_missing_platform_fails(self):
        raw, digest = raw_index([{"digest": AMD, "platform": {"os": "linux", "architecture": "amd64"}}])
        with pytest.raises(sb.SbomError, match="one linux/arm64 manifest, found 0"):
            sb.platform_digests(raw, digest)

    def test_duplicate_platform_fails(self):
        plat = {"os": "linux", "architecture": "amd64"}
        raw, digest = raw_index([
            {"digest": AMD, "platform": plat},
            {"digest": ARM, "platform": plat},
        ])
        with pytest.raises(sb.SbomError, match="found 2"):
            sb.platform_digests(raw, digest, platforms=("linux/amd64",))


class TestCheckSbom:
    def test_accepts_sbom_naming_the_manifest_digest(self):
        sb.check_sbom(syft_sbom(NAME, AMD), NAME, AMD)

    def test_rejects_sbom_that_records_another_digest(self):
        # What syft records when handed the index digest plus --platform.
        _, index_digest = raw_index()
        with pytest.raises(sb.SbomError, match="describes"):
            sb.check_sbom(syft_sbom(NAME, index_digest), NAME, AMD)

    def test_rejects_non_cyclonedx(self):
        with pytest.raises(sb.SbomError, match="not a CycloneDX"):
            sb.check_sbom({"spdxVersion": "SPDX-2.3"}, NAME, AMD)

    def test_rejects_empty_inventory(self):
        sbom = {**syft_sbom(NAME, AMD), "components": []}
        with pytest.raises(sb.SbomError, match="no components"):
            sb.check_sbom(sbom, NAME, AMD)


class TestSyft:
    def test_runs_the_digest_pinned_image_against_the_registry(self, monkeypatch):
        for name in sb.SYFT_AUTH_ENV:
            monkeypatch.delenv(name, raising=False)
        cmd = sb.syft_command(f"{NAME}@{AMD}", "linux/amd64")
        assert OFFICIAL_IMAGES["syft"] in cmd
        assert "@sha256:" in OFFICIAL_IMAGES["syft"]
        assert f"registry:{NAME}@{AMD}" in cmd
        assert cmd[cmd.index("--platform") + 1] == "linux/amd64"
        assert cmd[cmd.index("-o") + 1] == "cyclonedx-json"
        assert not any(a.startswith("SYFT_REGISTRY_AUTH") for a in cmd)

    def test_passes_registry_auth_by_name_only(self, monkeypatch):
        monkeypatch.setenv("SYFT_REGISTRY_AUTH_AUTHORITY", "ghcr.io")
        monkeypatch.setenv("SYFT_REGISTRY_AUTH_USERNAME", "bot")
        monkeypatch.setenv("SYFT_REGISTRY_AUTH_PASSWORD", "s3cret-value")
        cmd = sb.syft_command(f"{NAME}@{AMD}", "linux/amd64")
        for name in sb.SYFT_AUTH_ENV:
            assert ["-e", name] == cmd[cmd.index(name) - 1: cmd.index(name) + 1]
        assert not any("s3cret-value" in a for a in cmd)

    def test_scan_retries_once_then_returns_raw_output(self, monkeypatch):
        answers = iter([completed(returncode=1, stderr="503"), completed('{"bomFormat": "x"}')])
        monkeypatch.setattr(sb, "run", lambda cmd: next(answers))
        monkeypatch.setattr(sb.time, "sleep", lambda _s: None)
        assert sb.scan(f"{NAME}@{AMD}", "linux/amd64") == '{"bomFormat": "x"}'

    def test_scan_fails_after_last_attempt(self, monkeypatch):
        calls = []
        monkeypatch.setattr(sb, "run", lambda cmd: calls.append(cmd) or completed(returncode=1, stderr="DENIED"))
        monkeypatch.setattr(sb.time, "sleep", lambda _s: None)
        with pytest.raises(sb.SbomError, match="DENIED"):
            sb.scan(f"{NAME}@{AMD}", "linux/amd64")
        assert len(calls) == sb.SYFT_ATTEMPTS


class TestIndexBom:
    def test_lists_platform_manifests_under_the_index_digest(self):
        _, index_digest = raw_index()
        files = {"linux/amd64": "a.cdx.json", "linux/arm64": "b.cdx.json"}
        bom = sb.index_bom(NAME, index_digest, {"linux/amd64": AMD, "linux/arm64": ARM}, files, NOW)
        # actions/attest's CycloneDX detection needs these three fields.
        assert bom["bomFormat"] == "CycloneDX" and bom["serialNumber"] and bom["specVersion"]
        assert bom["metadata"]["component"]["version"] == index_digest
        assert [(c["bom-ref"], c["version"]) for c in bom["components"]] == [
            ("linux/amd64", AMD), ("linux/arm64", ARM),
        ]
        assert bom["dependencies"] == [{"ref": "index", "dependsOn": ["linux/amd64", "linux/arm64"]}]
        again = sb.index_bom(NAME, index_digest, {"linux/amd64": AMD, "linux/arm64": ARM}, files, NOW)
        assert again["serialNumber"] == bom["serialNumber"]


def generate(tmp_path, monkeypatch, images=("cli",)):
    raw, index_digest = raw_index()
    fake = FakeDocker({f"{REGISTRY}/{img}@{index_digest}": raw for img in images})
    monkeypatch.setattr(sb, "run", fake)
    github_env = tmp_path / "github_env"
    monkeypatch.setenv("GITHUB_ENV", str(github_env))
    out = tmp_path / "sboms"
    argv = ["generate", "--registry", REGISTRY, "--sha12", SHA12, "--out-dir", str(out)]
    for img in images:
        argv += ["--image", f"{img}@{index_digest}"]
    args = sb.build_parser().parse_args(argv)
    assert sb.cmd_generate(args, now=NOW) == 0
    return out, index_digest, github_env, fake


class TestGenerate:
    def test_writes_per_platform_and_index_sboms(self, tmp_path, monkeypatch):
        out, index_digest, github_env, _ = generate(tmp_path, monkeypatch)
        assert sorted(p.name for p in out.iterdir()) == [
            f"image-sboms-{SHA12}.json",
            f"sbom-cli-{SHA12}-index.cdx.json",
            f"sbom-cli-{SHA12}-linux-amd64.cdx.json",
            f"sbom-cli-{SHA12}-linux-arm64.cdx.json",
        ]
        amd = json.loads((out / f"sbom-cli-{SHA12}-linux-amd64.cdx.json").read_text())
        assert amd["metadata"]["component"]["version"] == AMD
        manifest = json.loads((out / f"image-sboms-{SHA12}.json").read_text())
        assert [(s["variant"], s["subject_digest"], s["step_id"]) for s in manifest["subjects"]] == [
            ("linux-amd64", AMD, "attest-cli-linux-amd64"),
            ("linux-arm64", ARM, "attest-cli-linux-arm64"),
            ("index", index_digest, "attest-cli-index"),
        ]
        env = github_env.read_text().splitlines()
        assert f"SBOM_CLI_LINUX_AMD64_DIGEST={AMD}" in env
        assert f"SBOM_CLI_INDEX_DIGEST={index_digest}" in env
        assert f"SBOM_CLI_LINUX_ARM64_PATH={(out / f'sbom-cli-{SHA12}-linux-arm64.cdx.json').resolve()}" in env

    def test_scans_platform_manifest_digests_never_the_index(self, tmp_path, monkeypatch):
        _, index_digest, _, fake = generate(tmp_path, monkeypatch)
        subjects = [a for cmd in fake.calls for a in cmd if a.startswith("registry:")]
        assert subjects == [f"registry:{NAME}@{AMD}", f"registry:{NAME}@{ARM}"]
        assert not any(index_digest in s for s in subjects)

    def test_unknown_index_fails_the_run(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr(sb, "run", FakeDocker({}))
        rc = sb.main(["generate", "--registry", REGISTRY, "--sha12", SHA12,
                      "--out-dir", str(tmp_path), "--image", f"cli@{AMD}"])
        assert rc == 1
        assert "::error::cannot inspect" in capsys.readouterr().err

    def test_rejects_malformed_image_argument(self):
        with pytest.raises(SystemExit):
            sb.build_parser().parse_args(["generate", "--registry", REGISTRY, "--sha12", SHA12,
                                          "--out-dir", "x", "--image", "cli:latest"])


def write_bundle(path: Path, name: str, digest: str, predicate: dict,
                 predicate_type: str = sb.CYCLONEDX_PREDICATE) -> Path:
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": name, "digest": {"sha256": digest.removeprefix("sha256:")}}],
        "predicateType": predicate_type,
        "predicate": predicate,
    }
    bundle = {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "dsseEnvelope": {
            "payloadType": sb.IN_TOTO_PAYLOAD,
            "payload": base64.b64encode(json.dumps(statement).encode()).decode(),
            "signatures": [{"sig": "x"}],
        },
    }
    path.write_text(json.dumps(bundle) + "\n")
    return path


def attest_all(out: Path, tmp_path: Path, tamper=None) -> dict:
    """Fake ``toJSON(steps)`` with one honest bundle per subject."""
    manifest = json.loads((out / f"image-sboms-{SHA12}.json").read_text())
    steps = {}
    for s in manifest["subjects"]:
        predicate = json.loads((out / s["sbom"]).read_text())
        digest = s["subject_digest"]
        kwargs = {}
        if tamper and tamper[0] == s["step_id"]:
            digest, predicate, kwargs = tamper[1](digest, predicate)
        bundle = write_bundle(tmp_path / f"{s['step_id']}.json", s["subject_name"], digest, predicate, **kwargs)
        steps[s["step_id"]] = {"outputs": {"bundle-path": str(bundle)}, "outcome": "success"}
    return steps


def collect(out: Path, steps: dict, monkeypatch) -> int:
    monkeypatch.setenv("ATTEST_STEPS", json.dumps(steps))
    return sb.main(["collect", "--sha12", SHA12, "--out-dir", str(out)])


class TestCollect:
    def test_copies_each_checked_bundle_next_to_its_sbom(self, tmp_path, monkeypatch):
        out, *_ = generate(tmp_path, monkeypatch)
        assert collect(out, attest_all(out, tmp_path), monkeypatch) == 0
        for variant in ("linux-amd64", "linux-arm64", "index"):
            assert (out / f"sbom-cli-{SHA12}-{variant}.cdx.json.sigstore.json").is_file()

    @pytest.mark.parametrize("step,tamper,message", [
        ("attest-cli-linux-amd64", lambda d, p: (ARM, p, {}), "bundle subject"),
        ("attest-cli-linux-arm64",
         lambda d, p: (d, json.loads(json.dumps(p).replace(ARM, AMD)), {}), "signed predicate"),
        ("attest-cli-index",
         lambda d, p: (d, p, {"predicate_type": "https://slsa.dev/provenance/v1"}), "predicate type"),
    ])
    def test_rejects_a_bundle_that_signs_something_else(self, tmp_path, monkeypatch, capsys,
                                                       step, tamper, message):
        out, *_ = generate(tmp_path, monkeypatch)
        assert collect(out, attest_all(out, tmp_path, tamper=(step, tamper)), monkeypatch) == 1
        assert message in capsys.readouterr().err

    def test_missing_attest_step_fails(self, tmp_path, monkeypatch, capsys):
        out, *_ = generate(tmp_path, monkeypatch)
        steps = attest_all(out, tmp_path)
        del steps["attest-cli-index"]
        assert collect(out, steps, monkeypatch) == 1
        assert "no attest step 'attest-cli-index'" in capsys.readouterr().err

    def test_rejects_multi_bundle_and_non_dsse_files(self, tmp_path):
        two = tmp_path / "two.json"
        two.write_text('{"a": 1}\n{"b": 2}\n')
        with pytest.raises(sb.SbomError, match="found 2"):
            sb.read_statement(two)
        plain = tmp_path / "plain.json"
        plain.write_text(json.dumps({"dsseEnvelope": {"payloadType": "text/plain"}}))
        with pytest.raises(sb.SbomError, match="not an in-toto"):
            sb.read_statement(plain)


# ── release.yml wiring ────────────────────────────────────────────────

def release_steps() -> list[dict]:
    workflow = yaml.safe_load(RELEASE_YML.read_text())
    return workflow["jobs"]["release"]["steps"]


def built_images() -> list[str]:
    build = next(s for s in release_steps() if s.get("name", "").startswith("Build and push containers"))
    return re.findall(r'^\s+"([\w-]+):docker/', build["run"], flags=re.M)


def step_index(steps: list[dict], predicate) -> int:
    return next(i for i, s in enumerate(steps) if predicate(s))


class TestReleaseWorkflow:
    def test_every_built_image_has_an_attest_step_per_variant(self):
        images = built_images()
        assert len(images) >= 5
        variants = [sb.variant_of(p) for p in sb.PLATFORMS] + [sb.INDEX_VARIANT]
        expected = {sb.step_id(img, v): (img, v) for img in images for v in variants}
        attest = {s["id"]: s for s in release_steps() if s.get("uses", "").startswith("actions/attest@")}
        assert set(attest) == set(expected)
        for sid, (img, variant) in expected.items():
            inputs = attest[sid]["with"]
            key = sb.env_key(img, variant)
            assert inputs == {
                "subject-name": f"${{{{ env.IMAGE_REGISTRY }}}}/{img}",
                "subject-digest": f"${{{{ env.SBOM_{key}_DIGEST }}}}",
                "sbom-path": f"${{{{ env.SBOM_{key}_PATH }}}}",
            }

    def test_attest_action_is_sha_pinned_v4(self):
        text = RELEASE_YML.read_text()
        refs = set(re.findall(r"uses: (actions/attest@\S+ # \S+)", text))
        assert len(refs) == 1
        assert re.fullmatch(r"actions/attest@[0-9a-f]{40} # v4\.\d+\.\d+", refs.pop())
        assert "attest-sbom" not in text

    def test_sbom_steps_run_before_release_it_and_cannot_be_skipped(self):
        steps = release_steps()
        build = step_index(steps, lambda s: s.get("name", "").startswith("Build and push"))
        generate_at = step_index(steps, lambda s: s.get("name") == "Generate image SBOMs")
        collect_at = step_index(steps, lambda s: s.get("name") == "Collect SBOM attestation bundles")
        upload_at = step_index(steps, lambda s: s.get("name") == "Upload image SBOMs")
        release_it = step_index(steps, lambda s: s.get("name", "").startswith("Release ("))
        attest_at = [i for i, s in enumerate(steps) if s.get("uses", "").startswith("actions/attest@")]
        assert build < generate_at < min(attest_at) and max(attest_at) < collect_at < upload_at < release_it
        for s in steps[generate_at:upload_at + 1]:
            assert "if" not in s and not s.get("continue-on-error")

    def test_collect_reads_attest_outputs_and_artifact_keeps_every_file(self):
        steps = release_steps()
        collect_step = next(s for s in steps if s.get("name") == "Collect SBOM attestation bundles")
        assert collect_step["env"]["ATTEST_STEPS"] == "${{ toJSON(steps) }}"
        upload = next(s for s in steps if s.get("name") == "Upload image SBOMs")["with"]
        assert upload["name"] == "image-sboms-${{ env.SBOM_SHA12 }}"
        assert upload["if-no-files-found"] == "error"

    def test_release_assets_and_permissions(self):
        workflow = yaml.safe_load(RELEASE_YML.read_text())
        job = workflow["jobs"]["release"]
        assert job["permissions"]["attestations"] == "write"
        assert job["permissions"]["id-token"] == "write"
        attach = next(s for s in job["steps"] if s.get("name") == "Attach SBOMs to the GitHub release")
        assert attach["if"] == "env.RELEASED == 'true'"
        assert 'gh release upload "${VERSION}" "${SBOM_DIR}"/*.json' in attach["run"]
        names = [s.get("name") for s in job["steps"]]
        assert names.index("Attach SBOMs to the GitHub release") < names.index("Publish to PyPI")
