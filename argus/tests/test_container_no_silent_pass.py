"""Regression tests: a container scan that did not happen must never be green.

Both container dispatch sites are membership tests over a list of
sub-scanner names::

    if "trivy" in enabled: ...
    if "grype" in enabled: ...

An unrecognised name therefore matched no branch, ran nothing, produced
zero findings, and exited 0 — a passing security gate over an image that
nothing had looked at. A typo in a ``scanners:`` list ("tryvi") was
enough to trigger it.

The contract these tests pin down:

* an unknown sub-scanner name is rejected before any work starts;
* an empty selection is rejected for the same reason;
* a sub-scanner that *cannot run* (no binary, no container runtime,
  timeout) is recorded as a failure, not as "ran and found nothing";
* every one of the above exits non-zero.
"""

from __future__ import annotations

import argparse

import pytest

from argus.cli import EXIT_ERROR, _load_container_config
from argus.container import ContainerEngine, scan_image
from argus.container.discovery import ContainerTarget
from argus.container.scanner import _run_grype, _run_trivy
from argus.core.schema import _CONTAINER_SUB_SCANNERS
from argus.scanners.container import (
    SUB_SCANNERS,
    ContainerScanner,
    validate_sub_scanners,
)


# =====================================================================
# validate_sub_scanners — the single gate both entry points call
# =====================================================================

class TestValidateSubScanners:
    """The shared validator both dispatch sites route through."""

    def test_known_names_normalise(self):
        assert validate_sub_scanners(["Trivy", " GRYPE "]) == ["trivy", "grype"]

    def test_accepts_comma_separated_string(self):
        """Config files use both shapes; so does the CLI."""
        assert validate_sub_scanners("trivy,grype") == ["trivy", "grype"]

    def test_unknown_name_raises(self):
        with pytest.raises(ValueError) as excinfo:
            validate_sub_scanners(["bogusscanner"], source="--scanners")
        msg = str(excinfo.value)
        assert "bogusscanner" in msg
        # The message must name where to fix it and what is valid —
        # a bare "invalid" sends the user hunting.
        assert "--scanners" in msg
        assert "trivy" in msg

    def test_typo_in_a_valid_list_still_raises(self):
        """The reported case: one good name, one typo."""
        with pytest.raises(ValueError) as excinfo:
            validate_sub_scanners(["trivy", "tryvi"])
        assert "tryvi" in str(excinfo.value)

    def test_every_unknown_name_is_reported(self):
        with pytest.raises(ValueError) as excinfo:
            validate_sub_scanners(["foo", "bar"])
        msg = str(excinfo.value)
        assert "foo" in msg and "bar" in msg

    def test_empty_selection_raises(self):
        """"Run no sub-scanners" reproduces exactly the silent pass."""
        with pytest.raises(ValueError):
            validate_sub_scanners([])

    def test_whitespace_only_selection_raises(self):
        with pytest.raises(ValueError):
            validate_sub_scanners(["  ", ""])

    def test_schema_and_runtime_agree(self):
        """``test_schema_matches_runtime_sub_scanners``.

        ``argus.core.schema`` duplicates the valid-name set to keep
        ``argus.core`` free of a dependency on ``argus.scanners``. A
        drift between the two would mean one of them accepts a name that
        dispatches to nothing — the bug this module exists to prevent.
        """
        assert _CONTAINER_SUB_SCANNERS == set(SUB_SCANNERS)


# =====================================================================
# ContainerScanner.scan — the Scanner-protocol path (argus scan --config)
# =====================================================================

class TestScannerProtocolPathRejectsUnknownNames:
    """``argus scan`` with ``scanners.container.scanners`` in argus.yml."""

    def test_unknown_name_produces_a_failed_phase(self):
        result = ContainerScanner().scan(
            ".", {"image_ref": "alpine:3.18", "scanners": "bogusscanner"},
        )
        assert result.findings == []
        # A failed phase is what puts the scanner in the engine's "did
        # not run cleanly" bucket. Without it the engine reads zero
        # findings as a pass.
        assert len(result.phase_results) == 1
        phase = result.phase_results[0]
        assert phase.phase == "container-scanner-selection"
        assert phase.status == "failed"
        assert "bogusscanner" in phase.error
        assert result.metadata["execution_failed"] is True

    def test_valid_names_do_not_trip_the_gate(self, monkeypatch):
        """The happy path must stay unaffected by the new validation."""
        scanner = ContainerScanner()
        monkeypatch.setattr(
            scanner, "_run_sub_scanner",
            lambda **_kwargs: ([], {"returncode": 0, "execution": "local"}),
        )
        result = scanner.scan(
            ".", {"image_ref": "alpine:3.18", "scanners": "trivy"},
        )
        assert not result.phase_results
        assert "trivy" in result.metadata

    def test_a_name_with_no_dispatch_branch_is_an_execution_failure(
        self, monkeypatch,
    ):
        """Backstop for drift between ``SUB_SCANNERS`` and the dispatch.

        ``validate_sub_scanners`` only knows that a name is *on the list*;
        it cannot know whether ``scan()`` has a branch for it. If someone
        adds a name to ``SUB_SCANNERS`` and forgets the ``if "x" in
        enabled:`` branch, the selection validates, nothing runs, and we
        are back to the silent green pass. Simulated here by returning a
        name the dispatch does not handle.
        """
        scanner = ContainerScanner()
        monkeypatch.setattr(
            scanner, "_enabled_scanners", lambda _config: ["newscanner"],
        )
        result = scanner.scan(".", {"image_ref": "alpine:3.18"})

        assert result.findings == []
        assert result.metadata["execution_failed"] is True
        assert "newscanner" in result.metadata["error"]


# =====================================================================
# ContainerEngine — the argus scan container lifecycle path
# =====================================================================

class TestEngineRejectsUnknownNames:

    def test_scanners_property_raises_on_unknown_name(self):
        engine = ContainerEngine({"scanners": "bogusscanner"})
        with pytest.raises(ValueError) as excinfo:
            engine._scanners()
        assert "bogusscanner" in str(excinfo.value)
        assert "containers.scanners" in str(excinfo.value)

    def test_scanners_property_accepts_a_list(self):
        engine = ContainerEngine({"scanners": ["trivy", "exposure"]})
        assert engine._scanners() == ("trivy", "exposure")

    def test_default_selection_is_valid(self):
        """The built-in default must itself pass the gate."""
        assert ContainerEngine({})._scanners()


class TestScanImageBackstop:
    """Defence in depth behind the up-front validation."""

    def test_selection_matching_no_sub_scanner_is_recorded_as_a_failure(
        self, monkeypatch,
    ):
        monkeypatch.setattr(
            "argus.container.scanner.is_image_local", lambda _ref: True,
        )
        result = scan_image(
            ContainerTarget(name="app", image_ref="app:latest"),
            scanners=("bogusscanner",),
            sbom=False,
        )
        assert result.combined_findings == []
        # scanner_errors is what ContainerScanSummary.scan_failures counts,
        # and scan_failures is what makes the CLI exit non-zero.
        assert "selection" in result.scanner_errors
        assert "bogusscanner" in result.scanner_errors["selection"]

    def test_summary_counts_it_as_a_scan_failure(self, monkeypatch):
        from argus.container.scanner import ContainerScanSummary

        monkeypatch.setattr(
            "argus.container.scanner.is_image_local", lambda _ref: True,
        )
        result = scan_image(
            ContainerTarget(name="app", image_ref="app:latest"),
            scanners=("bogusscanner",),
            sbom=False,
        )
        assert ContainerScanSummary(results=[result]).scan_failures == 1


# =====================================================================
# "Cannot run" is not "ran and found nothing"
# =====================================================================

class TestUnrunnableScannerIsAFailure:
    """Exit-code contract for "nothing could be scanned"."""

    def _no_tools_at_all(self, monkeypatch):
        monkeypatch.setattr(
            "argus.container.scanner.shutil.which", lambda _name: None,
        )
        monkeypatch.setattr(
            "argus.container_runtime.is_available", lambda: False,
        )

    @pytest.mark.parametrize("runner", [_run_trivy, _run_grype])
    def test_unavailable_tool_raises_instead_of_returning_empty(
        self, runner, tmp_path, monkeypatch,
    ):
        """No local binary and no container runtime = the image was not scanned.

        Returning ``[]`` here rendered a clean PASS over an image nothing
        examined — the same failure mode as an unknown scanner name, just
        reached from the other direction.
        """
        self._no_tools_at_all(monkeypatch)
        with pytest.raises(RuntimeError) as excinfo:
            runner("alpine:3.18", tmp_path)
        assert "not available" in str(excinfo.value)

    @pytest.mark.parametrize(
        "tool,runner", [("trivy", _run_trivy), ("grype", _run_grype)],
    )
    def test_timeout_raises_instead_of_returning_empty(
        self, tool, runner, tmp_path, monkeypatch,
    ):
        import subprocess as _subprocess

        monkeypatch.setattr(
            "argus.container.scanner.shutil.which",
            lambda name: f"/usr/local/bin/{name}" if name == tool else None,
        )

        def _timeout(*_args, **_kwargs):
            raise _subprocess.TimeoutExpired(cmd=tool, timeout=600)

        monkeypatch.setattr("subprocess.run", _timeout)
        with pytest.raises(RuntimeError) as excinfo:
            runner("alpine:3.18", tmp_path)
        assert "timed out" in str(excinfo.value)

    @pytest.mark.parametrize(
        "tool,runner", [("trivy", _run_trivy), ("grype", _run_grype)],
    )
    def test_scanner_image_pull_failure_raises(
        self, tool, runner, tmp_path, monkeypatch,
    ):
        """The tool falls back to a container, but that image cannot be pulled.

        Distinct from "no runtime at all": a runtime exists, we just could
        not get the scanner image. Either way the target image went
        unexamined, so it must not read as a clean scan.
        """
        monkeypatch.setattr(
            "argus.container.scanner.shutil.which", lambda _name: None,
        )
        monkeypatch.setattr(
            "argus.container_runtime.is_available", lambda: True,
        )
        monkeypatch.setattr(
            "argus.container_runtime.pull_image",
            lambda *_a, **_kw: False,
        )
        with pytest.raises(RuntimeError) as excinfo:
            runner("alpine:3.18", tmp_path)
        assert "failed to pull" in str(excinfo.value)

    @pytest.mark.parametrize(
        "tool,runner", [("trivy", _run_trivy), ("grype", _run_grype)],
    )
    def test_binary_vanishing_mid_run_raises(
        self, tool, runner, tmp_path, monkeypatch,
    ):
        """shutil.which found the binary but exec failed.

        A race or a broken PATH entry. Previously returned [] and read as a
        clean scan.
        """
        monkeypatch.setattr(
            "argus.container.scanner.shutil.which",
            lambda name: f"/usr/local/bin/{name}" if name == tool else None,
        )

        def _missing(*_args, **_kwargs):
            raise FileNotFoundError(tool)

        monkeypatch.setattr("subprocess.run", _missing)
        with pytest.raises(RuntimeError) as excinfo:
            runner("alpine:3.18", tmp_path)
        assert "not found on PATH" in str(excinfo.value)

    @pytest.mark.parametrize(
        "tool,runner", [("trivy", _run_trivy), ("grype", _run_grype)],
    )
    def test_scanner_errors_reach_the_summary(
        self, tool, runner, tmp_path, monkeypatch,
    ):
        """The RuntimeError must land in scanner_errors, not escape."""
        monkeypatch.setattr(
            "argus.container.scanner.is_image_local", lambda _ref: True,
        )
        self._no_tools_at_all(monkeypatch)
        result = scan_image(
            ContainerTarget(name="app", image_ref="app:latest"),
            scanners=(tool,),
            sbom=False,
        )
        assert tool in result.scanner_errors


# =====================================================================
# CLI — the reported reproduction
# =====================================================================

def _container_args(**overrides) -> argparse.Namespace:
    defaults = {
        "config": None,
        "images": ["alpine:3.18"],
        "discover": None,
        "scanners": None,
        "platform": None,
        "vex": None,
        "list": False,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


class TestCliRejectsUnknownScanner:
    """``argus scan container --image <any> --scanners bogusscanner``."""

    def test_load_container_config_raises(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)  # no argus.yml to auto-detect
        with pytest.raises(ValueError) as excinfo:
            _load_container_config(_container_args(scanners="bogusscanner"))
        assert "bogusscanner" in str(excinfo.value)
        assert "--scanners" in str(excinfo.value)

    def test_dispatcher_exits_non_zero(self, monkeypatch, tmp_path, capsys):
        """The reported repro: exit 0 with nothing scanned. Now EXIT_ERROR."""
        from argus.cli import cmd_scan

        monkeypatch.chdir(tmp_path)
        args = _container_args(scanners="bogusscanner")
        args.scanner = "container"
        args.command = "scan"

        exit_code = cmd_scan(args)

        assert exit_code == EXIT_ERROR
        assert "bogusscanner" in capsys.readouterr().err

    def test_valid_scanner_list_passes_validation(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        config = _load_container_config(_container_args(scanners="trivy,grype"))
        assert config["scanners"] == ["trivy", "grype"]

    def test_config_file_scanners_are_validated_too(self, monkeypatch, tmp_path):
        """Not just the CLI flag — containers.scanners in argus.yml."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "argus.yml").write_text(
            "containers:\n"
            "  images:\n"
            "    - image: alpine:3.18\n"
            "  scanners: [tryvi]\n"
        )
        with pytest.raises(ValueError) as excinfo:
            _load_container_config(_container_args(images=None, config="argus.yml"))
        assert "tryvi" in str(excinfo.value)
        assert "containers.scanners" in str(excinfo.value)
