"""Tests for `argus validate --deep` — deep_checks, deep_hints, and the
cmd_validate wiring that uses them."""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from argus.cli import cmd_validate
from argus.preflight.deep_checks import (
    DeepCheckResult,
    check_paths,
    check_registry_reachability,
    manifest_probe,
)
from argus.preflight.deep_hints import compute_deep_hints


# ----- manifest_probe ------------------------------------------------------


class TestManifestProbe:
    def test_no_docker_binary(self):
        with patch("argus.preflight.deep_checks.shutil.which", return_value=None):
            success, detail = manifest_probe("any/image:tag")
        assert success is False
        assert detail == "no docker"

    def test_success(self):
        completed = MagicMock(returncode=0, stdout="...", stderr="")
        with patch("argus.preflight.deep_checks.shutil.which", return_value="/usr/bin/docker"), \
             patch("argus.preflight.deep_checks.subprocess.run", return_value=completed):
            success, detail = manifest_probe("alpine:3.19")
        assert success is True
        assert detail == "manifest resolved"

    def test_failure_returns_first_stderr_line(self):
        completed = MagicMock(
            returncode=1,
            stdout="",
            stderr="no such manifest: alpine:doesntexist\nsome stack trace garbage",
        )
        with patch("argus.preflight.deep_checks.shutil.which", return_value="/usr/bin/docker"), \
             patch("argus.preflight.deep_checks.subprocess.run", return_value=completed):
            success, detail = manifest_probe("alpine:doesntexist")
        assert success is False
        assert detail == "no such manifest: alpine:doesntexist"
        assert "stack trace garbage" not in detail

    def test_timeout(self):
        with patch("argus.preflight.deep_checks.shutil.which", return_value="/usr/bin/docker"), \
             patch(
                 "argus.preflight.deep_checks.subprocess.run",
                 side_effect=subprocess.TimeoutExpired(cmd="docker", timeout=30),
             ):
            success, detail = manifest_probe("alpine:3.19", timeout=30)
        assert success is False
        assert "timeout after 30s" == detail


# ----- check_registry_reachability -----------------------------------------


class TestCheckRegistryReachability:
    def test_empty_image_list(self):
        assert check_registry_reachability([]) == []

    def test_no_docker_short_circuits_with_one_explanation(self):
        with patch(
            "argus.preflight.deep_checks.manifest_probe",
            return_value=(False, "no docker"),
        ):
            results = check_registry_reachability(["a:1", "b:2", "c:3"])
        assert len(results) == 3
        # First result carries the install-Docker explanation, the
        # rest are quiet "(skipped — no Docker)" to avoid drowning the
        # user in identical lines.
        assert "install Docker" in results[0].message
        assert all(r.status == "skip" for r in results)
        for extra in results[1:]:
            assert "(skipped — no Docker)" == extra.message

    def test_registry_rewrite_applied_to_probed_ref(self):
        captured: list[str] = []

        def fake_probe(ref, timeout=30):
            captured.append(ref)
            return True, "manifest resolved"

        with patch("argus.preflight.deep_checks.manifest_probe", side_effect=fake_probe):
            results = check_registry_reachability(
                ["aquasec/trivy:0.70.0"],
                registry="my-mirror.corp",
            )
        assert len(results) == 1
        assert results[0].status == "ok"
        # The probed ref includes the registry rewrite, so the table
        # shows the operator what was actually checked.
        assert captured == ["my-mirror.corp/aquasec/trivy:0.70.0"]
        assert results[0].name == "my-mirror.corp/aquasec/trivy:0.70.0"

    def test_registry_map_rewrite_applied(self):
        captured: list[str] = []

        def fake_probe(ref, timeout=30):
            captured.append(ref)
            return True, "manifest resolved"

        with patch("argus.preflight.deep_checks.manifest_probe", side_effect=fake_probe):
            results = check_registry_reachability(
                ["aquasec/trivy:0.70.0", "ghcr.io/anchore/grype:v0.99.0"],
                registry_map={
                    "docker.io": "hub-mirror.corp",
                    "ghcr.io": "ghcr-mirror.corp",
                },
            )
        assert [r.status for r in results] == ["ok", "ok"]
        assert captured == [
            "hub-mirror.corp/aquasec/trivy:0.70.0",
            "ghcr-mirror.corp/anchore/grype:v0.99.0",
        ]

    def test_failure_reported_with_fail_status(self):
        with patch(
            "argus.preflight.deep_checks.manifest_probe",
            return_value=(False, "no such manifest"),
        ):
            results = check_registry_reachability(["bogus:image"])
        assert len(results) == 1
        assert results[0].status == "fail"
        assert results[0].severity == "error"
        assert results[0].message == "no such manifest"


# ----- check_paths ---------------------------------------------------------


class TestCheckPaths:
    def test_search_paths_existing_emits_ok(self, tmp_path):
        (tmp_path / "src").mkdir()
        (tmp_path / "infra").mkdir()
        results = check_paths(
            {"containers": {"search_paths": ["src", "infra"]}},
            base_dir=tmp_path,
        )
        assert len(results) == 2
        assert all(r.status == "ok" for r in results)

    def test_search_paths_missing_is_error(self, tmp_path):
        results = check_paths(
            {"containers": {"search_paths": ["nonexistent"]}},
            base_dir=tmp_path,
        )
        assert len(results) == 1
        assert results[0].status == "fail"
        assert results[0].severity == "error"

    def test_reporting_output_dir_missing_is_warn_not_error(self, tmp_path):
        # Argus creates output_dir at scan time, so missing is
        # informational only — never an error.
        results = check_paths(
            {"reporting": {"output_dir": "argus-results"}},
            base_dir=tmp_path,
        )
        assert len(results) == 1
        assert results[0].status == "warn"
        assert results[0].severity == "info"
        assert "will be created" in results[0].message

    def test_containers_output_dir_existing_emits_ok(self, tmp_path):
        (tmp_path / "out").mkdir()
        results = check_paths(
            {"containers": {"output_dir": "out"}},
            base_dir=tmp_path,
        )
        assert len(results) == 1
        assert results[0].status == "ok"
        assert results[0].name == "containers.output_dir=out"

    def test_per_scanner_exclude_glob_entries_are_skipped(self, tmp_path):
        # Glob patterns (e.g. ``**/*.lock``) are intentional patterns,
        # not paths — probing them as files would produce a confusing
        # warning every time.
        results = check_paths(
            {
                "scanners": {
                    "bandit": {"exclude": "**/*.lock,vendor/?,real-file.py"}
                }
            },
            base_dir=tmp_path,
        )
        # Only ``real-file.py`` (no glob chars) gets probed; it doesn't
        # exist in tmp_path so produces a warn row.
        assert len(results) == 1
        assert results[0].name == "scanners.bandit.exclude[real-file.py]"
        assert results[0].status == "warn"

    def test_per_scanner_exclude_existing_path_emits_no_row(self, tmp_path):
        # An exclusion that resolves to a real path is silently
        # accepted — only missing ones generate a warning, so a clean
        # config doesn't fill the output with noise.
        (tmp_path / "node_modules").mkdir()
        results = check_paths(
            {"scanners": {"bandit": {"exclude": "node_modules"}}},
            base_dir=tmp_path,
        )
        assert results == []


# ----- compute_deep_hints --------------------------------------------------


class TestComputeDeepHints:
    def test_empty_config_no_hints(self):
        assert compute_deep_hints({}) == []

    def test_minimal_scanners_only_no_hints(self):
        # A config that's just scanners + no live-checkable surface
        # should produce zero hints — that's the whole point of the
        # conditional nudge.
        assert compute_deep_hints({"scanners": {"bandit": {"enabled": True}}}) == []

    def test_registry_triggers_hint(self):
        hints = compute_deep_hints({"execution": {"registry": "mirror.corp"}})
        assert any("execution.registry set" in h for h in hints)
        assert any("mirror.corp" in h for h in hints)

    def test_registry_map_triggers_hint_with_count(self):
        hints = compute_deep_hints({
            "execution": {
                "registry_map": {"docker.io": "hub-mirror", "ghcr.io": "ghcr-mirror"}
            }
        })
        assert any("2 entries in execution.registry_map" in h for h in hints)

    def test_containers_images_triggers_hint(self):
        hints = compute_deep_hints({
            "containers": {"images": [{"image": "a:1"}, {"image": "b:2"}]}
        })
        assert any("2 container image(s)" in h for h in hints)

    def test_search_paths_and_output_dirs_trigger_hints(self):
        hints = compute_deep_hints({
            "containers": {
                "search_paths": ["./src", "./infra"],
                "output_dir": "./argus-results",
            },
            "reporting": {"output_dir": "./reports"},
        })
        assert any("2 entries in containers.search_paths" in h for h in hints)
        assert any("containers.output_dir './argus-results'" in h for h in hints)
        assert any("reporting.output_dir './reports'" in h for h in hints)


# ----- cmd_validate integration --------------------------------------------


@pytest.fixture
def valid_config(tmp_path):
    """A minimal but valid config that triggers no deep hints by default."""
    cfg = tmp_path / "argus.yml"
    cfg.write_text(
        "# yaml-language-server: $schema=https://example.invalid/schema.json\n"
        "scanners:\n"
        "  bandit:\n"
        "    enabled: true\n"
    )
    return cfg


@pytest.fixture
def config_with_deep_surface(tmp_path):
    """Config that should trigger every deep hint.

    All keys are valid per argus-config.schema.json — the schema-pass
    branch of cmd_validate is what gates the hint output, so the
    fixture must not generate fatal errors.
    """
    cfg = tmp_path / "argus.yml"
    cfg.write_text(
        "# yaml-language-server: $schema=https://example.invalid/schema.json\n"
        "scanners:\n"
        "  bandit:\n"
        "    enabled: true\n"
        "execution:\n"
        "  registry: mirror.corp\n"
        "  registry_map:\n"
        "    docker.io: hub-mirror.corp\n"
        "containers:\n"
        "  search_paths:\n"
        "    - ./src\n"
        "  output_dir: ./argus-results\n"
        "  images:\n"
        "    - image: alpine:3.19\n"
        "reporting:\n"
        "  output_dir: ./reports\n"
    )
    return cfg


class TestCmdValidateDeepHints:
    def test_no_hint_when_config_lacks_deep_surface(self, valid_config, capsys, monkeypatch):
        monkeypatch.chdir(valid_config.parent)
        args = argparse.Namespace(
            config=str(valid_config),
            check_tools=False,
            deep=False,
            schema=False,
            strict=False,
            report_issue=False,
        )
        rc = cmd_validate(args)
        out = capsys.readouterr().out
        assert rc == 0
        assert "Live checks available" not in out

    def test_hint_shown_when_deep_surface_present(
        self, config_with_deep_surface, capsys, monkeypatch
    ):
        monkeypatch.chdir(config_with_deep_surface.parent)
        args = argparse.Namespace(
            config=str(config_with_deep_surface),
            check_tools=False,
            deep=False,
            schema=False,
            strict=False,
            report_issue=False,
        )
        rc = cmd_validate(args)
        out = capsys.readouterr().out
        assert rc == 0
        assert "Live checks available (run with --deep):" in out
        # Should name at least the registry_map and containers entries.
        assert "execution.registry_map" in out
        assert "container image" in out

    def test_hint_suppressed_when_deep_already_requested(
        self, config_with_deep_surface, capsys, monkeypatch
    ):
        monkeypatch.chdir(config_with_deep_surface.parent)
        args = argparse.Namespace(
            config=str(config_with_deep_surface),
            check_tools=False,
            deep=True,
            schema=False,
            strict=False,
            report_issue=False,
        )
        # Mock the probe so the test doesn't hit the network or Docker.
        with patch(
            "argus.preflight.deep_checks.manifest_probe",
            return_value=(True, "manifest resolved"),
        ):
            cmd_validate(args)
        out = capsys.readouterr().out
        assert "Live checks available" not in out
        # But the registry section *is* printed under --deep.
        assert "Registry reachability:" in out


class TestCmdValidateDeepExitCode:
    def test_deep_failure_returns_error_exit(
        self, config_with_deep_surface, capsys, monkeypatch
    ):
        monkeypatch.chdir(config_with_deep_surface.parent)
        args = argparse.Namespace(
            config=str(config_with_deep_surface),
            check_tools=False,
            deep=True,
            schema=False,
            strict=False,
            report_issue=False,
        )
        with patch(
            "argus.preflight.deep_checks.manifest_probe",
            return_value=(False, "no such manifest"),
        ):
            rc = cmd_validate(args)
        out = capsys.readouterr().out
        assert rc != 0
        assert "deep-check failure" in out

    def test_deep_skip_when_no_docker_does_not_fail(
        self, config_with_deep_surface, capsys, monkeypatch
    ):
        # Docker not on PATH → skip rows, not failures. The user can
        # run --deep offline and still get the path-existence half.
        monkeypatch.chdir(config_with_deep_surface.parent)
        (config_with_deep_surface.parent / "src").mkdir()
        args = argparse.Namespace(
            config=str(config_with_deep_surface),
            check_tools=False,
            deep=True,
            schema=False,
            strict=False,
            report_issue=False,
        )
        with patch(
            "argus.preflight.deep_checks.manifest_probe",
            return_value=(False, "no docker"),
        ):
            rc = cmd_validate(args)
        out = capsys.readouterr().out
        assert rc == 0
        assert "Registry reachability:" in out
        assert "Paths:" in out
