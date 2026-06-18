"""Security tests for the container plugin sandbox (argus.core.plugin_runtime).

The trust boundary is ``build_sandbox_argv`` (the hardened invocation) and
``validate_findings`` (untrusted-output handling). These run without Docker —
the runtime is never invoked; the runner is injected.
"""

from __future__ import annotations

import json
import subprocess

import pytest

from argus.core.models import Severity
from argus.core.plugin_runtime import (
    PLUGIN_SCHEMA,
    PluginError,
    PluginSpec,
    TrustTier,
    assert_runnable,
    build_sandbox_argv,
    plugin_provenance,
    run_plugin,
    validate_findings,
)

PINNED = "ghcr.io/acme/plugin@sha256:" + "a" * 64


def _spec(**kw):
    return PluginSpec(name="acme", image=PINNED, **kw)


def _envelope(findings):
    return json.dumps({"schema": PLUGIN_SCHEMA, "findings": findings})


class TestSandboxHardening:
    def test_all_lockdown_flags_present(self, tmp_path):
        argv = build_sandbox_argv(_spec(), str(tmp_path))
        joined = " ".join(argv)
        assert "--network none" in joined          # default-deny egress
        assert "--read-only" in argv
        assert ["--cap-drop", "ALL"] == argv[argv.index("--cap-drop"):argv.index("--cap-drop") + 2]
        assert "--security-opt" in argv and "no-new-privileges" in argv
        assert "--user" in argv and "65534:65534" in argv
        assert "--pids-limit" in argv and "--memory" in argv and "--cpus" in argv
        assert any(a.startswith("/tmp:rw,noexec,nosuid") for a in argv)
        assert f"{tmp_path.resolve()}:/scan:ro" in argv  # target read-only

    def test_no_escape_vectors(self, tmp_path):
        argv = build_sandbox_argv(_spec(), str(tmp_path))
        joined = " ".join(argv)
        assert "--privileged" not in argv
        assert "docker.sock" not in joined            # no socket mount → no host control
        assert not any(a == "-e" or a == "--env" for a in argv)  # no host env/secrets

    def test_digest_pin_required(self, tmp_path):
        with pytest.raises(PluginError, match="digest-pinned"):
            build_sandbox_argv(PluginSpec(name="x", image="ghcr.io/acme/plugin:latest"), str(tmp_path))

    def test_network_opt_in_changes_only_network_flag(self, tmp_path):
        argv = build_sandbox_argv(_spec(allow_network=True), str(tmp_path))
        assert "--network" in argv and "bridge" in argv
        assert "none" not in argv[argv.index("--network") + 1:argv.index("--network") + 2]

    def test_target_must_be_a_directory(self, tmp_path):
        f = tmp_path / "f"
        f.write_text("x")
        with pytest.raises(PluginError, match="not a directory"):
            build_sandbox_argv(_spec(), str(f))


class TestUntrustedOutput:
    def test_rejects_invalid_json(self):
        with pytest.raises(PluginError, match="invalid JSON"):
            validate_findings("{not json", plugin_name="acme")

    def test_rejects_wrong_schema(self):
        with pytest.raises(PluginError, match="schema"):
            validate_findings(json.dumps({"schema": "evil", "findings": []}), plugin_name="acme")

    def test_rejects_non_list_findings(self):
        with pytest.raises(PluginError, match="must be a list"):
            validate_findings(json.dumps({"schema": PLUGIN_SCHEMA, "findings": {}}), plugin_name="acme")

    def test_caps_finding_count(self):
        huge = _envelope([{"id": str(i)} for i in range(10_001)])
        with pytest.raises(PluginError, match="too many findings"):
            validate_findings(huge, plugin_name="acme")

    def test_unknown_severity_coerced_not_trusted(self):
        out = validate_findings(_envelope([{"severity": "ULTRA-MEGA"}]), plugin_name="acme")
        assert out[0].severity is Severity.UNKNOWN

    def test_absolute_and_traversal_locations_dropped(self):
        out = validate_findings(
            _envelope([
                {"location": "/etc/passwd"},
                {"location": "../../host/secret"},
                {"location": "src/app.py"},
            ]),
            plugin_name="acme",
        )
        assert out[0].location is None
        assert out[1].location is None
        assert out[2].location == "src/app.py"

    def test_control_chars_stripped(self):
        out = validate_findings(_envelope([{"title": "evil\x1b[2Jinjection\x00"}]), plugin_name="acme")
        assert "\x1b" not in out[0].title and "\x00" not in out[0].title

    def test_findings_tagged_untrusted(self):
        out = validate_findings(_envelope([{"id": "F1", "severity": "high"}]), plugin_name="acme")
        assert out[0].metadata["untrusted"] is True
        assert out[0].scanner == "plugin/acme"
        assert out[0].severity is Severity.HIGH


class TestProvenanceAndPolicy:
    def test_provenance_records_tier_and_digest(self):
        prov = plugin_provenance(_spec(version="1.2.3", trust_tier=TrustTier.VERIFIED, signature_verified=True))
        p = prov["plugin"]
        assert p["trust_tier"] == "verified"
        assert p["digest"] == "sha256:" + "a" * 64
        assert p["signature_verified"] is True
        assert p["network"] == "none"

    def test_unverified_requires_opt_in(self):
        with pytest.raises(PluginError, match="unverified"):
            assert_runnable(_spec(trust_tier=TrustTier.UNVERIFIED))
        assert_runnable(_spec(trust_tier=TrustTier.UNVERIFIED), opted_in=True)  # no raise

    def test_verified_runs_without_opt_in(self):
        assert_runnable(_spec(trust_tier=TrustTier.VERIFIED))  # no raise


class TestRunPlugin:
    def _runner(self, *, stdout="", returncode=0, raises=None):
        def fake(argv, **kw):
            if raises:
                raise raises
            return subprocess.CompletedProcess(argv, returncode, stdout=stdout, stderr="")
        return fake

    def test_happy_path_returns_validated_findings(self, tmp_path):
        runner = self._runner(stdout=_envelope([{"id": "F1", "severity": "medium", "title": "x"}]))
        res = run_plugin(_spec(trust_tier=TrustTier.VERIFIED), str(tmp_path), runtime="docker", runner=runner)
        assert res.metadata["status"] == "ran"
        assert res.metadata["plugin"]["trust_tier"] == "verified"
        assert len(res.findings) == 1 and res.findings[0].severity is Severity.MEDIUM

    def test_timeout_degrades_not_raises(self, tmp_path):
        runner = self._runner(raises=subprocess.TimeoutExpired(cmd="docker", timeout=1))
        res = run_plugin(_spec(trust_tier=TrustTier.VERIFIED), str(tmp_path), runtime="docker", runner=runner)
        assert res.metadata["status"] == "failed" and res.metadata["error"] == "timeout"
        assert res.findings == []

    def test_nonzero_exit_degrades(self, tmp_path):
        runner = self._runner(stdout="", returncode=2)
        res = run_plugin(_spec(trust_tier=TrustTier.FIRST_PARTY), str(tmp_path), runtime="docker", runner=runner)
        assert res.metadata["status"] == "failed" and "exit 2" in res.metadata["error"]

    def test_malformed_output_degrades(self, tmp_path):
        runner = self._runner(stdout="garbage")
        res = run_plugin(_spec(trust_tier=TrustTier.FIRST_PARTY), str(tmp_path), runtime="docker", runner=runner)
        assert res.metadata["status"] == "failed"

    def test_unverified_blocked_without_opt_in(self, tmp_path):
        runner = self._runner(stdout=_envelope([]))
        with pytest.raises(PluginError):
            run_plugin(_spec(), str(tmp_path), runtime="docker", runner=runner)  # default UNVERIFIED
