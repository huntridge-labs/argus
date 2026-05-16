"""Tests for argus.audit.manifest -- audit trail generation."""

import json
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from argus.audit.manifest import (
    AuditManifest,
    ScanPhase,
    create_manifest,
    finalize_manifest,
)


class TestScanPhase:
    """Verify the ScanPhase dataclass."""

    def test_defaults(self):
        phase = ScanPhase(name="parse", started_at="2026-01-01T00:00:00+00:00")
        assert phase.status == "success"
        assert phase.error == ""
        assert phase.duration_ms == 0


class TestAuditManifest:
    """Verify the AuditManifest dataclass and save method."""

    def test_default_values(self):
        m = AuditManifest()
        assert m.argus_version == ""
        assert m.scan_id == ""
        assert m.findings_summary == {}
        assert m.artifacts == []

    def test_save_creates_file(self, tmp_path):
        m = AuditManifest(scan_id="test-123", argus_version="0.1.0")
        filepath = m.save(tmp_path)
        assert filepath.exists()
        assert filepath.name == "argus-audit.json"

        data = json.loads(filepath.read_text())
        assert data["scan_id"] == "test-123"
        assert data["argus_version"] == "0.1.0"

    def test_save_creates_directory(self, tmp_path):
        dest = tmp_path / "nested" / "output"
        m = AuditManifest(scan_id="nested-test")
        filepath = m.save(dest)
        assert filepath.exists()

    def test_save_produces_valid_json(self, tmp_path):
        m = AuditManifest(
            scan_id="json-test",
            scan_targets=["/app", "/lib"],
            findings_summary={"critical": 1, "high": 2},
        )
        filepath = m.save(tmp_path)
        data = json.loads(filepath.read_text())
        assert data["scan_targets"] == ["/app", "/lib"]
        assert data["findings_summary"]["critical"] == 1


class TestCreateManifest:
    """Verify create_manifest pre-fills provenance."""

    def test_generates_scan_id(self):
        m = create_manifest()
        assert m.scan_id != ""
        assert len(m.scan_id) == 36  # UUID format

    def test_fills_started_at(self):
        m = create_manifest()
        assert m.started_at != ""
        assert "T" in m.started_at  # ISO format

    def test_fills_python_version(self):
        m = create_manifest()
        assert m.python_version != ""

    def test_fills_os_info(self):
        m = create_manifest()
        assert m.os_info != ""

    def test_fills_hostname(self):
        m = create_manifest()
        assert m.hostname != ""

    def test_scan_targets_passed_through(self):
        m = create_manifest(scan_targets=["/src", "/lib"])
        assert m.scan_targets == ["/src", "/lib"]

    def test_config_hash_computed(self, tmp_path):
        config = tmp_path / "argus.yaml"
        config.write_text("scanners:\n  bandit:\n    enabled: true\n")

        m = create_manifest(config_path=str(config))
        assert m.config_hash != ""
        assert len(m.config_hash) == 64  # SHA-256 hex digest

    def test_config_hash_empty_when_no_file(self):
        m = create_manifest(config_path="/nonexistent/path.yaml")
        assert m.config_hash == ""

    def test_config_hash_empty_when_none(self):
        m = create_manifest(config_path=None)
        assert m.config_hash == ""

    def test_platform_detected(self, monkeypatch):
        # Ensure no CI vars are set so we get "local"
        for var in ["GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL"]:
            monkeypatch.delenv(var, raising=False)
        m = create_manifest()
        assert m.platform["name"] == "local"


class TestFinalizeManifest:
    """Verify finalize_manifest fills completion data."""

    def test_fills_completed_at(self, tmp_path):
        m = create_manifest()
        finalize_manifest(m, output_dir=tmp_path)
        assert m.completed_at != ""

    def test_computes_duration(self, tmp_path):
        m = create_manifest()
        finalize_manifest(m, output_dir=tmp_path)
        assert m.duration_ms >= 0

    def test_sets_exit_code(self, tmp_path):
        m = create_manifest()
        finalize_manifest(m, exit_code=1, output_dir=tmp_path)
        assert m.exit_code == 1

    def test_saves_manifest_file(self, tmp_path):
        m = create_manifest()
        filepath = finalize_manifest(m, output_dir=tmp_path)
        assert filepath.exists()
        assert filepath.name == "argus-audit.json"

    def test_inventories_artifacts(self, tmp_path):
        # Create some fake artifacts
        (tmp_path / "results.json").write_text('{"findings": []}')
        (tmp_path / "report.sarif").write_text('{}')

        m = create_manifest()
        finalize_manifest(m, output_dir=tmp_path)

        artifact_paths = [a["path"] for a in m.artifacts]
        assert "results.json" in artifact_paths
        assert "report.sarif" in artifact_paths

    def test_artifact_hashes_are_sha256(self, tmp_path):
        (tmp_path / "data.txt").write_text("hello world")

        m = create_manifest()
        finalize_manifest(m, output_dir=tmp_path)

        artifact = next(a for a in m.artifacts if a["path"] == "data.txt")
        assert len(artifact["sha256"]) == 64
        assert artifact["size_bytes"] > 0

    def test_summary_integration(self, tmp_path):
        """Verify findings summary is extracted from a ScanSummary-like object."""

        @dataclass
        class FakeResult:
            scanner: str = "bandit"

        @dataclass
        class FakeSummary:
            results: list = field(default_factory=lambda: [FakeResult()])
            critical_count: int = 1
            high_count: int = 2
            medium_count: int = 3
            low_count: int = 4
            total_count: int = 10

        m = create_manifest()
        finalize_manifest(m, summary=FakeSummary(), output_dir=tmp_path)

        assert m.scanners_executed == ["bandit"]
        assert m.findings_summary["critical"] == 1
        assert m.findings_summary["high"] == 2
        assert m.findings_summary["total"] == 10

    def test_no_summary_leaves_empty(self, tmp_path):
        m = create_manifest()
        finalize_manifest(m, summary=None, output_dir=tmp_path)
        assert m.findings_summary == {}
        assert m.scanners_executed == []


class TestManifestSecretLeakProtection:
    """End-to-end: planted secrets in manifest fields never reach disk.

    The manifest schema today doesn't include credential fields. This
    test guards against a future regression that adds one (a
    ``docker_cmd`` capture, an env dict, error messages from phases
    that quote the failing command) — the redaction pass at save()
    time catches it before the file lands.
    """

    def test_secret_in_phase_error_redacted(self, tmp_path):
        m = AuditManifest(scan_id="leak-test", argus_version="1.0.0")
        # Future regression: phase capture includes the failing
        # subprocess argv, which includes a credential.
        m.phases.append({
            "name": "container_pull",
            "status": "failure",
            "error": "docker login failed with token=ghp_secret_1234567890abcdef",
        })

        filepath = m.save(tmp_path)
        content = filepath.read_text()

        assert "ghp_secret_1234567890abcdef" not in content
        # Phase metadata that isn't a secret survives
        assert "container_pull" in content
        assert "failure" in content

    def test_secret_in_artifact_path_redacted(self, tmp_path):
        m = AuditManifest(scan_id="leak-test", argus_version="1.0.0")
        # Pathological: an artifact path that embedded a token
        # (e.g., a URL-shaped path with creds in it).
        m.artifacts.append({
            "name": "remote-fetch.log",
            "path": "https://user:AKIA1234567890ABCDEF@bucket.s3.amazonaws.com/x",
        })

        filepath = m.save(tmp_path)
        content = filepath.read_text()

        assert "AKIA1234567890ABCDEF" not in content

    def test_nested_dict_redacted(self, tmp_path):
        """Secret several levels deep — walker must recurse."""
        m = AuditManifest(scan_id="leak-test", argus_version="1.0.0")
        m.phases.append({
            "name": "auth",
            "env_snapshot": {
                "credentials": {
                    "registry": "Bearer eyJhbGc.realtoken.signature",
                    "non_secret": "/usr/bin",
                },
            },
        })

        filepath = m.save(tmp_path)
        content = filepath.read_text()

        assert "eyJhbGc.realtoken.signature" not in content
        # Non-secret nested value survives
        assert "/usr/bin" in content

    def test_input_dict_not_mutated_after_save(self, tmp_path):
        """Caller's manifest object stays unmodified after save()."""
        m = AuditManifest(scan_id="leak-test", argus_version="1.0.0")
        m.phases.append({
            "name": "p",
            "error": "token=ghp_aaaa1111bbbb2222cccc3333dddd4444",
        })
        original_error = m.phases[0]["error"]

        m.save(tmp_path)

        # In-memory view of the manifest unchanged — the redaction
        # only affects what hits disk.
        assert m.phases[0]["error"] == original_error

    def test_clean_manifest_writes_no_redaction_tokens(self, tmp_path):
        """A manifest with zero secret-shaped data has no false-positive
        ``<REDACTED>`` markers."""
        m = AuditManifest(scan_id="clean-test", argus_version="1.0.0")
        m.phases.append({"name": "init", "status": "success"})

        filepath = m.save(tmp_path)
        content = filepath.read_text()

        assert "<REDACTED>" not in content
