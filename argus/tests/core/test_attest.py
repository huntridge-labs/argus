"""Tests for scan attestation signing (issue #241)."""

import json
import subprocess

from argus.core import attest
from argus.core.attest import (
    attest_scan,
    build_statement,
    build_subjects,
    pushed_image_refs,
)
from argus.core.models import (
    Finding,
    ScanContext,
    ScanResult,
    ScanSummary,
    Severity,
)

SHA_A = "sha256:" + "a" * 64
SHA_B = "sha256:" + "b" * 64


def _finding(image_ref, digest, cve="CVE-X"):
    return Finding(
        id=cve, severity=Severity.HIGH, title="v", scanner="container", cve=cve,
        metadata={"image_ref": image_ref, "image_digest": digest},
    )


def _summary(findings, commit="deadbeef" * 5):
    ctx = ScanContext(commit_sha=commit) if commit else None
    return ScanSummary(
        results=[ScanResult(scanner="container/app", findings=findings)],
        scan_context=ctx,
    )


class TestSubjects:
    def test_image_and_commit_subjects(self):
        s = _summary([_finding("ghcr.io/org/app:1.0", SHA_A)])
        subs = build_subjects(s)
        assert {"name": "ghcr.io/org/app", "digest": {"sha256": "a" * 64}} in subs
        assert {"name": "git-commit", "digest": {"gitCommit": "deadbeef" * 5}} in subs

    def test_dedup_and_skip_findings_without_digest(self):
        s = _summary([
            _finding("ghcr.io/org/app:1.0", SHA_A),
            _finding("ghcr.io/org/app:1.0", SHA_A),                 # dup
            Finding(id="x", severity=Severity.LOW, title="t",
                    scanner="container", metadata={}),               # no digest
        ], commit="")
        subs = build_subjects(s)
        assert len(subs) == 1  # one image, no commit

    def test_no_subjects_when_nothing_to_bind(self):
        s = _summary([Finding(id="x", severity=Severity.LOW, title="t",
                              scanner="bandit", metadata={})], commit="")
        assert build_subjects(s) == []


class TestPushedImageRefs:
    def test_registry_ref_included_local_excluded(self):
        s = _summary([
            _finding("ghcr.io/org/app:1.0", SHA_A),   # pushed (host)
            _finding("app:scan-abc", SHA_B),           # bare local — excluded
        ])
        assert pushed_image_refs(s) == ["ghcr.io/org/app@" + SHA_A]


class TestBuildStatement:
    def test_intoto_shape(self):
        stmt = build_statement({"@context": "openvex"}, [{"name": "x", "digest": {"sha256": "a"}}])
        assert stmt["_type"] == attest.INTOTO_STATEMENT_TYPE
        assert stmt["predicateType"] == attest.OPENVEX_PREDICATE_TYPE
        assert stmt["predicate"] == {"@context": "openvex"}
        assert stmt["subject"][0]["name"] == "x"


class TestAttestScan:
    def test_disabled_is_noop(self, tmp_path):
        assert attest_scan(_summary([_finding("ghcr.io/o/a:1", SHA_A)]),
                           tmp_path, enabled=False) == {"status": "disabled"}

    def test_skipped_when_nothing_to_bind(self, tmp_path):
        s = _summary([Finding(id="x", severity=Severity.LOW, title="t",
                              scanner="bandit", metadata={})], commit="")
        res = attest_scan(s, tmp_path, enabled=True)
        assert res["status"] == "skipped"

    def test_signs_both_modes_with_mock_runner(self, tmp_path):
        calls = []

        def runner(cmd):
            calls.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        s = _summary([
            _finding("ghcr.io/org/app:1.0", SHA_A),
            _finding("app:scan-abc", SHA_B),  # local — standalone only
        ])
        res = attest_scan(s, tmp_path, enabled=True, cosign_runner=runner)

        assert res["status"] == "signed"
        modes = {entry["mode"] for entry in res["signed"]}
        assert modes == {"standalone", "registry"}
        # Unsigned statement + predicate always written.
        stmt = json.loads((tmp_path / attest.STATEMENT_FILENAME).read_text())
        assert stmt["predicateType"] == attest.OPENVEX_PREDICATE_TYPE
        assert (tmp_path / attest.PREDICATE_FILENAME).is_file()
        # argv: keyless sign-blob (standalone) + attest (registry), no --key.
        verbs = [c[1] for c in calls]
        assert "sign-blob" in verbs and "attest" in verbs
        assert all("--key" not in c for c in calls)
        assert all("--yes" in c for c in calls)

    def test_cosign_absent_writes_unsigned_statement(self, tmp_path, monkeypatch):
        monkeypatch.setattr(attest.shutil, "which", lambda _c: None)
        res = attest_scan(_summary([_finding("ghcr.io/o/a:1", SHA_A)]),
                          tmp_path, enabled=True)
        assert res["status"] == "unsigned"
        assert "cosign not on PATH" in res["reason"]
        assert (tmp_path / attest.STATEMENT_FILENAME).is_file()

    def test_sign_failure_recorded(self, tmp_path):
        def runner(cmd):
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="boom")

        res = attest_scan(_summary([_finding("ghcr.io/o/a:1", SHA_A)]),
                          tmp_path, enabled=True, cosign_runner=runner)
        assert res["status"] == "sign_failed"
        assert res["failures"]
