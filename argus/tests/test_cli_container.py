"""Tests for CLI container/DAST routing, output helpers, and lifecycle detection."""

import argparse
import json
from pathlib import Path

import pytest

from argus.cli import (
    _is_container_lifecycle,
    _is_dast_lifecycle,
    _load_container_config,
    _print_container_terminal,
    _print_dast_terminal,
    _resolve_run_output_dir,
    _write_container_json,
    _write_dast_json,
    _write_dast_markdown,
    cmd_scan,
)


# ---------------------------------------------------------------------------
# Helpers to build Namespace objects that mimic parsed CLI args
# ---------------------------------------------------------------------------

def _base_scan_namespace(**overrides) -> argparse.Namespace:
    """Return a Namespace with all scan-related defaults."""
    defaults = {
        "command": "scan",
        "scanner": None,
        "path": ".",
        "config": None,
        "output_dir": None,
        "severity_threshold": None,
        "formats": None,
        "list": False,
        "verbose": False,
        "discover": None,
        "images": None,
        "scanners": None,
        "target": None,
        "port": None,
        "env_vars": None,
        "scan_type": "baseline",
        "startup_timeout": 60,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


# ---------------------------------------------------------------------------
# Minimal stub classes for container / DAST summaries
# ---------------------------------------------------------------------------

class _ContainerResult:
    def __init__(self, name="img", image_ref="img:latest", build_success=True,
                 total_count=3, critical_count=1, high_count=1, medium_count=1,
                 low_count=0, unique_count=2, combined_findings=None):
        self.name = name
        self.image_ref = image_ref
        self.build_success = build_success
        self.total_count = total_count
        self.critical_count = critical_count
        self.high_count = high_count
        self.medium_count = medium_count
        self.low_count = low_count
        self.unique_count = unique_count
        self.combined_findings = combined_findings or []


class _ContainerSummary:
    def __init__(self, results=None):
        self.results = results or [_ContainerResult()]

    @property
    def container_count(self):
        return len(self.results)

    @property
    def build_failures(self):
        return sum(1 for r in self.results if not r.build_success)

    @property
    def total_count(self):
        return sum(r.total_count for r in self.results)

    @property
    def unique_count(self):
        return sum(r.unique_count for r in self.results)


class _DastResult:
    def __init__(self, name="app", target_url="http://localhost:8080/",
                 healthy=True, scan_error="", findings=None):
        self.name = name
        self.target_url = target_url
        self.healthy = healthy
        self.scan_error = scan_error
        self.findings = findings or []

    @property
    def critical_count(self):
        return sum(1 for f in self.findings if getattr(f, 'severity', None)
                   and f.severity.value == 'critical')

    @property
    def high_count(self):
        return sum(1 for f in self.findings if getattr(f, 'severity', None)
                   and f.severity.value == 'high')

    @property
    def medium_count(self):
        return sum(1 for f in self.findings if getattr(f, 'severity', None)
                   and f.severity.value == 'medium')

    @property
    def low_count(self):
        return sum(1 for f in self.findings if getattr(f, 'severity', None)
                   and f.severity.value == 'low')

    @property
    def info_count(self):
        return sum(1 for f in self.findings if getattr(f, 'severity', None)
                   and f.severity.value == 'info')


class _DastSummary:
    def __init__(self, results=None):
        self.results = results or [_DastResult()]

    @property
    def target_count(self):
        return len(self.results)

    @property
    def healthy_count(self):
        return sum(1 for r in self.results if r.healthy)

    @property
    def total_count(self):
        return sum(len(r.findings) for r in self.results)

    @property
    def critical_count(self):
        return sum(r.critical_count for r in self.results)

    @property
    def high_count(self):
        return sum(r.high_count for r in self.results)

    @property
    def medium_count(self):
        return sum(r.medium_count for r in self.results)

    @property
    def low_count(self):
        return sum(r.low_count for r in self.results)

    @property
    def info_count(self):
        return sum(r.info_count for r in self.results)


# =====================================================================
# _is_container_lifecycle
# =====================================================================

class TestIsContainerLifecycle:
    """Test _is_container_lifecycle detection."""

    def test_returns_true_with_discover(self):
        args = _base_scan_namespace(discover=".")
        assert _is_container_lifecycle(args) is True

    def test_returns_true_with_image(self):
        args = _base_scan_namespace(images=["nginx:latest"])
        assert _is_container_lifecycle(args) is True

    def test_returns_false_without_lifecycle_flags(self):
        args = _base_scan_namespace()
        assert _is_container_lifecycle(args) is False


# =====================================================================
# _is_dast_lifecycle
# =====================================================================

class TestIsDastLifecycle:
    """Test _is_dast_lifecycle detection."""

    def test_returns_true_with_target(self):
        args = _base_scan_namespace(target="http://localhost:3000")
        assert _is_dast_lifecycle(args) is True

    def test_returns_true_with_image(self):
        args = _base_scan_namespace(images=["myapp:latest"])
        assert _is_dast_lifecycle(args) is True

    def test_returns_false_without_lifecycle_flags(self):
        args = _base_scan_namespace()
        assert _is_dast_lifecycle(args) is False


class TestResolveRunOutputDir:
    """``_resolve_run_output_dir`` — flat vs timestamped output layout.

    The flat layout is what lets the composite action find
    ``<output_dir>/container-scan.{json,md}`` and aggregate container
    results; the timestamped layout is the interactive-local default.
    """

    def test_no_timestamp_writes_flat(self, tmp_path):
        base = tmp_path / "reports"
        out = _resolve_run_output_dir(str(base), no_timestamp=True)
        # Output dir IS the base dir — no timestamped subdir, no symlink.
        assert out == str(base)
        assert base.is_dir()
        assert not (base / "latest").exists()
        assert list(base.iterdir()) == []

    def test_timestamped_by_default(self, tmp_path):
        base = tmp_path / "reports"
        out = _resolve_run_output_dir(str(base), no_timestamp=False)
        # Output dir is a timestamped subdirectory under base, and a
        # 'latest' pointer is created alongside it.
        assert out != str(base)
        assert Path(out).is_dir()
        assert Path(out).parent == base
        assert (base / "latest").exists()


# =====================================================================
# cmd_scan routing
# =====================================================================

class TestCmdScanRouting:
    """Test cmd_scan routes to the correct handler."""

    def test_routes_to_container_with_discover(self, monkeypatch):
        called = {}

        def fake_container_scan(args, **_kwargs):
            # The dispatcher now passes ``container_config=`` so the
            # downstream cmd doesn't have to re-load the YAML. Tolerate
            # the kwarg without inspecting it — this test only verifies
            # the routing decision, not the config plumbing.
            called["container"] = True
            return 0

        monkeypatch.setattr("argus.cli._cmd_container_scan", fake_container_scan)
        args = _base_scan_namespace(scanner="container", discover=".")
        result = cmd_scan(args)

        assert called.get("container") is True
        assert result == 0

    def test_routes_to_dast_with_target(self, monkeypatch):
        called = {}

        def fake_dast_scan(args):
            called["dast"] = True
            return 0

        monkeypatch.setattr("argus.cli._cmd_dast_scan", fake_dast_scan)
        args = _base_scan_namespace(scanner="zap", target="http://localhost:3000")
        result = cmd_scan(args)

        assert called.get("dast") is True
        assert result == 0

    def test_routes_to_source_scan_for_other_scanners(self, monkeypatch):
        called = {}

        def fake_source_scan(args):
            called["source"] = True
            return 0

        monkeypatch.setattr("argus.cli._cmd_source_scan", fake_source_scan)
        args = _base_scan_namespace(scanner="bandit")
        result = cmd_scan(args)

        assert called.get("source") is True
        assert result == 0


# =====================================================================
# _print_container_terminal
# =====================================================================

class TestPrintContainerTerminal:
    """Test _print_container_terminal produces expected stdout."""

    def test_produces_output(self, capsys):
        summary = _ContainerSummary()
        _print_container_terminal(summary)
        captured = capsys.readouterr()

        assert "Container Security Scan Results" in captured.out
        assert "Containers scanned:" in captured.out
        assert "Build failures:" in captured.out

    def test_shows_build_failed(self, capsys):
        results = [_ContainerResult(name="bad", build_success=False)]
        summary = _ContainerSummary(results=results)
        _print_container_terminal(summary)
        captured = capsys.readouterr()

        assert "BUILD FAILED" in captured.out


# =====================================================================
# _write_container_json
# =====================================================================

class TestWriteContainerJson:
    """Test _write_container_json creates valid JSON file."""

    def test_creates_json_file(self, tmp_path):
        summary = _ContainerSummary()
        output_dir = str(tmp_path / "out")
        _write_container_json(summary, output_dir)

        json_file = tmp_path / "out" / "container-scan.json"
        assert json_file.exists()

        data = json.loads(json_file.read_text())
        assert data["container_count"] == 1
        assert data["build_failures"] == 0
        assert len(data["results"]) == 1


# =====================================================================
# _print_dast_terminal
# =====================================================================

class TestPrintDastTerminal:
    """Test _print_dast_terminal produces expected stdout."""

    def test_produces_output(self, capsys):
        summary = _DastSummary()
        _print_dast_terminal(summary)
        captured = capsys.readouterr()

        assert "DAST Security Scan Results" in captured.out
        assert "Targets scanned: 1" in captured.out
        assert "Healthy targets: 1" in captured.out

    def test_shows_not_healthy(self, capsys):
        results = [_DastResult(name="sick", healthy=False)]
        summary = _DastSummary(results=results)
        _print_dast_terminal(summary)
        captured = capsys.readouterr()

        assert "NOT HEALTHY" in captured.out

    def test_shows_scan_error(self, capsys):
        results = [_DastResult(name="err", scan_error="timeout")]
        summary = _DastSummary(results=results)
        _print_dast_terminal(summary)
        captured = capsys.readouterr()

        assert "SCAN ERROR" in captured.out


# =====================================================================
# _write_dast_markdown
# =====================================================================

class TestWriteDastMarkdown:
    """Test _write_dast_markdown creates markdown file."""

    def test_creates_markdown_file(self, tmp_path):
        summary = _DastSummary()
        output_dir = str(tmp_path / "out")
        _write_dast_markdown(summary, output_dir)

        md_file = tmp_path / "out" / "dast-scan.md"
        assert md_file.exists()

        content = md_file.read_text()
        assert "# DAST Security Scan Results" in content
        assert "**Targets:** 1" in content

    def test_unhealthy_target_note(self, tmp_path):
        results = [_DastResult(name="down", healthy=False)]
        summary = _DastSummary(results=results)
        output_dir = str(tmp_path / "out")
        _write_dast_markdown(summary, output_dir)

        content = (tmp_path / "out" / "dast-scan.md").read_text()
        assert "Target not healthy" in content


# =====================================================================
# _write_dast_json
# =====================================================================

class TestWriteDastJson:
    """Test _write_dast_json creates valid JSON file."""

    def test_creates_json_file(self, tmp_path):
        summary = _DastSummary()
        output_dir = str(tmp_path / "out")
        _write_dast_json(summary, output_dir)

        json_file = tmp_path / "out" / "dast-scan.json"
        assert json_file.exists()

        data = json.loads(json_file.read_text())
        assert data["target_count"] == 1
        assert data["healthy_count"] == 1
        assert len(data["results"]) == 1


# =====================================================================
# _load_container_config: back-compat for legacy credential location (#180)
# =====================================================================
#
# Background: argus.example.yml has long documented registry credentials
# under ``scanners.container.registry_*`` because that's where the
# source-scan ``container`` scanner reads them. The container-scan
# subcommand (``argus scan container``), however, consumes the top-
# level ``containers:`` block. Without back-compat, the user-reported
# fix for #180 would silently stop authenticating until users migrate
# their YAML — a regression nobody asked for.
#
# These tests pin the promotion: if creds live only at the legacy
# location, they get copied to the canonical location; if they live at
# both, the canonical location wins.


class TestLoadContainerConfigPromotesLegacyCreds:
    """``_load_container_config`` lifts ``scanners.container.registry_*`` up to the top level."""

    def _write_config(self, tmp_path, body: str):
        cfg = tmp_path / "argus.yml"
        cfg.write_text(body)
        return argparse.Namespace(
            config=str(cfg),
            images=None,
            discover=None,
            scanners=None,
        )

    def test_legacy_env_form_promoted_to_top_level(self, tmp_path):
        args = self._write_config(tmp_path, """
scanners:
  container:
    registry_username_env: IRONBANK_USER
    registry_password_env: IRONBANK_CLI_SECRET
containers:
  images:
    - image: registry1.example.com/app@sha256:abcd
""")
        config = _load_container_config(args)
        # The runner-side resolver looks for these at the top of the
        # dict it receives; promotion is what makes the legacy YAML
        # shape actually authenticate.
        assert config["registry_username_env"] == "IRONBANK_USER"
        assert config["registry_password_env"] == "IRONBANK_CLI_SECRET"

    def test_canonical_location_wins_when_both_set(self, tmp_path):
        # The user is migrating: kept the legacy block for now but
        # also set the canonical fields. Canonical must win — that's
        # what makes the migration meaningful.
        args = self._write_config(tmp_path, """
scanners:
  container:
    registry_username_env: OLD_USER
    registry_password_env: OLD_TOKEN
containers:
  registry_username_env: NEW_USER
  registry_password_env: NEW_TOKEN
  images:
    - image: registry1.example.com/app@sha256:abcd
""")
        config = _load_container_config(args)
        assert config["registry_username_env"] == "NEW_USER"
        assert config["registry_password_env"] == "NEW_TOKEN"

    def test_no_legacy_creds_means_no_promotion(self, tmp_path):
        # Sanity: if the legacy block has no cred fields, the top-
        # level container config stays clean — no synthetic empty
        # cred keys appear (which would otherwise be a confusing
        # signal to debuggers asking "why is my username unset?").
        args = self._write_config(tmp_path, """
scanners:
  container:
    enabled: true
containers:
  images:
    - image: registry1.example.com/app@sha256:abcd
""")
        config = _load_container_config(args)
        assert "registry_username_env" not in config
        assert "registry_password_env" not in config
        assert "registry_username" not in config
        assert "registry_password" not in config

    def test_legacy_literal_forms_also_promoted(self, tmp_path):
        # Literal forms are deprecated in favor of *_env, but still
        # supported with a config-load-time warning elsewhere. The
        # promotion path mustn't drop them — that would silently
        # remove the user's only credential source.
        args = self._write_config(tmp_path, """
scanners:
  container:
    registry_username: alice
    registry_password: s3cret
containers:
  images:
    - image: registry1.example.com/app@sha256:abcd
""")
        config = _load_container_config(args)
        assert config["registry_username"] == "alice"
        assert config["registry_password"] == "s3cret"


# =====================================================================
# _load_container_config: plumbs execution.registry / registry_map (#186)
# =====================================================================
#
# The source-scan path routes scanner-image pulls through the engine's
# resolver, which reads ``execution.registry`` / ``execution.registry_map``
# off ArgusConfig. The container-scan path doesn't see ArgusConfig at
# all — it consumes the dict ``_load_container_config`` builds. Without
# explicit plumbing, the operator's mirror policy was silently ignored
# for every ``argus scan container`` invocation against a config with a
# mirror. The fix stashes both fields under synthetic underscore keys
# the same way ``_reporting_keep_raw`` is stashed.


class TestLoadContainerConfigPlumbsExecutionRegistry:
    """``execution.registry`` / ``registry_map`` reach the container config dict."""

    def _write_config(self, tmp_path, body: str):
        cfg = tmp_path / "argus.yml"
        cfg.write_text(body)
        return argparse.Namespace(
            config=str(cfg),
            images=None,
            discover=None,
            scanners=None,
        )

    def test_flat_registry_stashed_under_synthetic_key(self, tmp_path):
        args = self._write_config(tmp_path, """
execution:
  registry: harbor.internal.corp/argus
containers:
  images:
    - image: registry.example.com/app@sha256:abcd
""")
        config = _load_container_config(args)
        assert config["_execution_registry"] == "harbor.internal.corp/argus"

    def test_registry_map_stashed_under_synthetic_key(self, tmp_path):
        args = self._write_config(tmp_path, """
execution:
  registry_map:
    docker.io: harbor.internal.corp/dockerhub-cache
    ghcr.io:   harbor.internal.corp/ghcr-cache
containers:
  images:
    - image: registry.example.com/app@sha256:abcd
""")
        config = _load_container_config(args)
        assert config["_execution_registry_map"] == {
            "docker.io": "harbor.internal.corp/dockerhub-cache",
            "ghcr.io":   "harbor.internal.corp/ghcr-cache",
        }

    def test_no_execution_block_no_synthetic_keys(self, tmp_path):
        # Sanity: configs without an execution block stay clean — no
        # synthetic empty values, no surprise dict entries that could
        # confuse downstream lookups.
        args = self._write_config(tmp_path, """
containers:
  images:
    - image: registry.example.com/app@sha256:abcd
""")
        config = _load_container_config(args)
        assert "_execution_registry" not in config
        assert "_execution_registry_map" not in config

    def test_empty_registry_map_not_stashed(self, tmp_path):
        # An empty map (or one with only blank values) is functionally
        # the same as no map — don't stash it. Avoids triggering the
        # resolver's "map-is-set" branch on what is effectively a
        # default config.
        args = self._write_config(tmp_path, """
execution:
  registry_map: {}
containers:
  images:
    - image: registry.example.com/app@sha256:abcd
""")
        config = _load_container_config(args)
        assert "_execution_registry_map" not in config
