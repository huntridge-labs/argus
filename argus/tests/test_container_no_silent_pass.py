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
        """The built-in default must itself pass the gate.

        ``_scanners()`` returns None for an unset key — "the operator
        named nothing" — so the value under test is the constant that
        ``scan_image`` falls back to.
        """
        from argus.scanners.container import (
            DEFAULT_SUB_SCANNERS,
            validate_sub_scanners,
        )

        assert ContainerEngine({})._scanners() is None
        assert validate_sub_scanners(list(DEFAULT_SUB_SCANNERS))


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


# =====================================================================
# PR #427 review follow-ups — the two holes left in the backstop
# =====================================================================

class TestSyftIsADispatchedSubScanner:
    """``--scanners syft`` must actually run syft.

    ``syft`` is in ``SUB_SCANNERS`` and passes ``validate_sub_scanners``,
    but the dispatch read ``if sbom and "syft" not in scanners`` — it ran
    syft only for callers who had *not* asked for it, and skipped it for
    the one caller who had. The old backstop then counted syft as a match
    because it is in ``SUB_SCANNERS``, so nothing was recorded: zero
    findings, zero errors, exit 0 over an unscanned image.
    """

    def _local_image(self, monkeypatch):
        monkeypatch.setattr(
            "argus.container.scanner.is_image_local", lambda _ref: True,
        )

    def test_explicitly_requested_syft_runs(self, monkeypatch):
        calls: list[str] = []
        self._local_image(monkeypatch)
        monkeypatch.setattr(
            "argus.container.scanner._run_syft",
            lambda ref, path, **kw: (calls.append(ref) or True, None),
        )
        scan_image(
            ContainerTarget(name="app", image_ref="app:latest"),
            scanners=("syft",),
        )
        assert calls == ["app:latest"], "syft was selected but never invoked"

    def test_explicitly_requested_syft_satisfies_the_gate(self, monkeypatch):
        self._local_image(monkeypatch)
        monkeypatch.setattr(
            "argus.container.scanner._run_syft", lambda *a, **kw: (True, None),
        )
        result = scan_image(
            ContainerTarget(name="app", image_ref="app:latest"),
            scanners=("syft",),
        )
        assert "selection" not in result.scanner_errors

    def test_requested_syft_that_cannot_run_is_a_failure(self, monkeypatch):
        """An SBOM that could not be produced is not a pass."""
        self._local_image(monkeypatch)
        monkeypatch.setattr(
            "argus.container.scanner._run_syft",
            lambda *a, **kw: (False, "no local syft binary"),
        )
        result = scan_image(
            ContainerTarget(name="app", image_ref="app:latest"),
            scanners=("syft",),
        )
        assert "syft" in result.scanner_errors

    def test_implicit_sbom_still_runs_for_other_selections(self, monkeypatch):
        """``sbom=True`` keeps emitting an SBOM alongside a CVE scan."""
        calls: list[str] = []
        self._local_image(monkeypatch)
        monkeypatch.setattr(
            "argus.container.scanner._run_syft",
            lambda ref, path, **kw: (calls.append(ref) or True, None),
        )
        monkeypatch.setattr(
            "argus.container.scanner._run_trivy", lambda *a, **kw: [],
        )
        scan_image(
            ContainerTarget(name="app", image_ref="app:latest"),
            scanners=("trivy",),
        )
        assert calls == ["app:latest"]


class TestBackstopFiresOnTheDefaultPath:
    """``and not sbom`` made the backstop dead for every default caller.

    ``scan_image``'s signature is ``sbom: bool = True``, so ``not sbom``
    was False on every call that did not explicitly opt out — and both
    original tests passed ``sbom=False``. A direct API caller (the case
    ``ContainerEngine._scanners``' docstring names) got a clean result.
    """

    def test_bogus_selection_is_caught_with_sbom_left_at_its_default(
        self, monkeypatch,
    ):
        monkeypatch.setattr(
            "argus.container.scanner.is_image_local", lambda _ref: True,
        )
        monkeypatch.setattr(
            "argus.container.scanner._run_syft", lambda *a, **kw: (True, None),
        )
        result = scan_image(
            ContainerTarget(name="app", image_ref="app:latest"),
            scanners=("tryvi",),
        )
        assert "selection" in result.scanner_errors
        assert "tryvi" in result.scanner_errors["selection"]

    def test_an_implicit_sbom_does_not_satisfy_the_gate(self, monkeypatch):
        """An inventory is not a vulnerability scan."""
        from argus.container.scanner import ContainerScanSummary

        monkeypatch.setattr(
            "argus.container.scanner.is_image_local", lambda _ref: True,
        )
        monkeypatch.setattr(
            "argus.container.scanner._run_syft", lambda *a, **kw: (True, None),
        )
        result = scan_image(
            ContainerTarget(name="app", image_ref="app:latest"),
            scanners=("tryvi",),
        )
        assert ContainerScanSummary(results=[result]).scan_failures == 1


class TestEngineSurfacesTheSelectionMessage:
    """``run()`` must not let the broad ``except Exception`` eat it.

    ``_scanners()`` was called inside ``_scan_one_target``'s try block,
    whose ``except Exception`` rewrote the ValueError to a generic
    "Scan failed for <ref>" — discarding the bad token and the list of
    valid names, which is most of the message's value.
    """

    def test_run_raises_with_the_offending_token(self, monkeypatch):
        monkeypatch.setattr(
            "argus.container.engine.parse_container_config",
            lambda _cfg: [ContainerTarget(name="app", image_ref="app:latest")],
        )
        engine = ContainerEngine(
            {"images": [{"image": "app:latest"}], "scanners": "tryvi"},
        )
        with pytest.raises(ValueError) as excinfo:
            engine.run()
        msg = str(excinfo.value)
        assert "tryvi" in msg
        assert "containers.scanners" in msg
        assert "trivy" in msg  # the valid-names list survives

    def test_selection_is_validated_once_not_once_per_target(self):
        engine = ContainerEngine({"scanners": ["trivy"]})
        assert engine._scanners() is engine._scanners()


class TestSdkScannerUnrunnableIsNotAPass:
    """``if not metadata`` could never fire, so the SDK path passed green.

    Every dispatch branch writes its metadata key even on failure —
    ``_run_sub_scanner`` returns ``{"error": ...}`` rather than nothing —
    so on a host with no trivy, no grype and no container runtime the
    scanner returned zero findings, no ``execution_failed``, and the
    engine reported PASS.
    """

    def _no_tools(self, monkeypatch):
        monkeypatch.setattr(
            "argus.scanners.container.shutil.which", lambda _n: None,
        )
        monkeypatch.setattr(
            "argus.container_runtime.is_available", lambda: False,
        )

    def test_all_sub_scanners_failing_sets_execution_failed(self, monkeypatch):
        self._no_tools(monkeypatch)
        result = ContainerScanner().scan(
            ".", {"image_ref": "app:latest", "scanners": ["trivy", "grype"]},
        )
        assert result.metadata.get("execution_failed") is True
        assert "trivy" in result.metadata["error"]
        assert "grype" in result.metadata["error"]

    def test_unnamed_selection_with_nothing_runnable_still_fails(
        self, monkeypatch,
    ):
        """No ``scanners`` key at all, and nothing could run.

        The named-sub-scanner check cannot fire here — nobody named
        anything — so the "all of them failed" gate is what catches it.
        Both are needed; neither subsumes the other.
        """
        self._no_tools(monkeypatch)
        result = ContainerScanner().scan(".", {"image_ref": "app:latest"})
        assert result.metadata.get("execution_failed") is True

    def test_a_named_sub_scanner_that_skips_fails_the_scan(self, monkeypatch):
        """The parity case with argus/container/scanner.py (ADR-039).

        ``scanners: "trivy,exposure"`` on a host with no container
        runtime: trivy succeeds, exposure skips. ``all(...)`` is False,
        so the all-failed gate stays quiet — and the run used to be
        clean, which is the silent pass the orchestrator path was fixed
        for. Whichever container entry point you use, naming a
        sub-scanner that cannot run must fail the scan.
        """
        scanner = ContainerScanner()
        monkeypatch.setattr(
            scanner, "_run_sub_scanner",
            lambda **_kwargs: ([], {"returncode": 0, "execution": "local"}),
        )
        monkeypatch.setattr(
            scanner, "_scan_exposed_ports",
            lambda image_ref, cfg: ([], {"skipped": "no container runtime"}),
        )
        result = scanner.scan(
            ".", {"image_ref": "app:latest", "scanners": ["trivy", "exposure"]},
        )
        assert result.metadata.get("execution_failed") is True
        assert "exposure" in result.metadata["error"]

    def test_an_unnamed_sub_scanner_that_skips_does_not_fail_the_scan(
        self, monkeypatch,
    ):
        """The other half of ADR-039 — a default scan on a daemonless host."""
        scanner = ContainerScanner()
        monkeypatch.setattr(
            scanner, "_run_sub_scanner",
            lambda **_kwargs: ([], {"returncode": 0, "execution": "local"}),
        )
        for attr in ("_scan_exposed_ports", "_scan_services"):
            monkeypatch.setattr(
                scanner, attr,
                lambda image_ref, cfg: ([], {"skipped": "no container runtime"}),
                raising=False,
            )
        result = scanner.scan(".", {"image_ref": "app:latest"})
        assert result.metadata.get("execution_failed") is not True

    def test_a_succeeding_sub_scanner_keeps_the_scan_clean(self):
        from argus.scanners.container import _sub_scanner_failed

        assert _sub_scanner_failed({"error": "boom"}) is True
        assert _sub_scanner_failed({"skipped": "no runtime"}) is True
        assert _sub_scanner_failed({"returncode": 0}) is False


class TestRunSyftReportsWhetherItRan:
    """``_run_syft`` returning False is what turns a requested-but-absent
    syft into a recorded failure rather than a silent clean pass."""

    def test_no_binary_and_no_runtime_returns_false(self, tmp_path, monkeypatch):
        from argus.container.scanner import _run_syft

        monkeypatch.setattr(
            "argus.container.scanner.shutil.which", lambda _n: None,
        )
        monkeypatch.setattr("argus.container_runtime.is_available", lambda: False)
        produced, reason = _run_syft("app:1", tmp_path)
        assert produced is False
        assert reason

    def test_failed_image_pull_returns_false(self, tmp_path, monkeypatch):
        from argus.container.scanner import _run_syft

        monkeypatch.setattr(
            "argus.container.scanner.shutil.which", lambda _n: None,
        )
        monkeypatch.setattr("argus.container_runtime.is_available", lambda: True)
        monkeypatch.setattr(
            "argus.container_runtime.pull_image", lambda *a, **kw: False,
        )
        produced, reason = _run_syft("app:1", tmp_path)
        assert produced is False
        assert reason

    def test_missing_binary_at_exec_time_returns_false(self, tmp_path, monkeypatch):
        from argus.container.scanner import _run_syft

        monkeypatch.setattr(
            "argus.container.scanner.shutil.which", lambda _n: "/usr/bin/syft",
        )

        def boom(*a, **kw):
            raise FileNotFoundError("syft")

        monkeypatch.setattr("subprocess.run", boom)
        produced, reason = _run_syft("app:1", tmp_path)
        assert produced is False
        assert reason

    def test_timeout_returns_false(self, tmp_path, monkeypatch):
        import subprocess

        from argus.container.scanner import _run_syft

        monkeypatch.setattr(
            "argus.container.scanner.shutil.which", lambda _n: "/usr/bin/syft",
        )

        def slow(*a, **kw):
            raise subprocess.TimeoutExpired(cmd="syft", timeout=300)

        monkeypatch.setattr("subprocess.run", slow)
        produced, reason = _run_syft("app:1", tmp_path)
        assert produced is False
        assert reason

    def test_successful_invocation_returns_true(self, tmp_path, monkeypatch):
        """Clean exit *and* an SBOM on disk."""
        import subprocess

        from argus.container.scanner import _run_syft

        monkeypatch.setattr(
            "argus.container.scanner.shutil.which", lambda _n: "/usr/bin/syft",
        )

        def writes_sbom(*a, **kw):
            (tmp_path / "syft-sbom.json").write_text('{"components": []}')
            return subprocess.CompletedProcess([], 0, "", "")

        monkeypatch.setattr("subprocess.run", writes_sbom)
        produced, reason = _run_syft("app:1", tmp_path)
        assert produced is True
        assert reason is None

    def test_non_zero_exit_returns_false(self, tmp_path, monkeypatch):
        """Being invoked is not succeeding.

        An unpullable image or a registry auth failure exits non-zero with
        no SBOM; counting that as "ran" let `--scanners syft` exit 0 over
        an image syft never read.
        """
        import subprocess

        from argus.container.scanner import _run_syft

        monkeypatch.setattr(
            "argus.container.scanner.shutil.which", lambda _n: "/usr/bin/syft",
        )
        monkeypatch.setattr(
            "subprocess.run",
            lambda *a, **kw: subprocess.CompletedProcess(
                [], 1, "", "unauthorized: authentication required",
            ),
        )
        produced, reason = _run_syft("app:1", tmp_path)
        assert produced is False
        assert reason

    def test_clean_exit_without_an_sbom_returns_false(self, tmp_path, monkeypatch):
        import subprocess

        from argus.container.scanner import _run_syft

        monkeypatch.setattr(
            "argus.container.scanner.shutil.which", lambda _n: "/usr/bin/syft",
        )
        monkeypatch.setattr(
            "subprocess.run",
            lambda *a, **kw: subprocess.CompletedProcess([], 0, "", ""),
        )
        produced, reason = _run_syft("app:1", tmp_path)
        assert produced is False
        assert reason


class TestSubScannerFailedPredicate:
    """Non-dict metadata must not be mistaken for a failure."""

    def test_non_dict_metadata_is_not_a_failure(self):
        from argus.scanners.container import _sub_scanner_failed

        assert _sub_scanner_failed("a string") is False
        assert _sub_scanner_failed(None) is False


# =====================================================================
# The invariant, end to end: every way a scan can fail to happen
# =====================================================================

class TestNoSelectionCanProduceASilentPass:
    """Adversarial sweep over the ways a container scan does not run.

    The per-comment fixes each closed one path. This sweeps the whole
    space so a future sub-scanner cannot quietly reopen it: every entry
    must record a failure, and the clean case must stay clean.
    """

    def _no_tools(self, monkeypatch):
        monkeypatch.setattr(
            "argus.container.scanner.is_image_local", lambda _r: True,
        )
        monkeypatch.setattr(
            "argus.container.scanner.shutil.which", lambda _n: None,
        )
        monkeypatch.setattr("argus.container_runtime.is_available", lambda: False)

    @pytest.mark.parametrize("scanners", [
        ("tryvi",),
        (),
        ("trivy",),
        ("grype",),
        ("syft",),
        ("exposure",),
        ("services",),
        ("exposure", "services"),
        ("trivy", "grype", "syft", "exposure", "services"),
    ])
    def test_nothing_runnable_is_never_a_pass(self, scanners, monkeypatch):
        from argus.container.scanner import ContainerScanSummary

        self._no_tools(monkeypatch)
        result = scan_image(
            ContainerTarget(name="app", image_ref="app:1"), scanners=scanners,
        )
        assert result.combined_findings == []
        assert ContainerScanSummary(results=[result]).scan_failures == 1, (
            f"selection {scanners} reported a clean pass with nothing runnable"
        )

    def test_a_scan_that_did_run_stays_clean(self, monkeypatch):
        """Guard against over-correction: a real clean scan must exit 0."""
        from argus.container.scanner import ContainerScanSummary
        from argus.scanners.container import ContainerScanner

        monkeypatch.setattr(
            "argus.container.scanner.is_image_local", lambda _r: True,
        )
        monkeypatch.setattr(
            "argus.container.scanner._run_trivy", lambda *a, **k: [],
        )
        monkeypatch.setattr(
            "argus.container.scanner._run_grype", lambda *a, **k: [],
        )
        monkeypatch.setattr(
            "argus.container.scanner._run_syft", lambda *a, **k: (True, None),
        )
        monkeypatch.setattr(
            ContainerScanner, "_scan_exposed_ports",
            lambda self, r, c: ([], {"execution": "local-inspect"}),
        )
        monkeypatch.setattr(
            ContainerScanner, "_scan_services",
            lambda self, r, c: ([], {"execution": "local-extract"}),
        )
        result = scan_image(
            ContainerTarget(name="app", image_ref="app:1"),
            scanners=("trivy", "grype", "syft", "exposure", "services"),
        )
        assert result.scanner_errors == {}
        assert ContainerScanSummary(results=[result]).scan_failures == 0


class TestAttackSurfaceSubScannersReportSkips:
    """`exposure` / `services` signal "did not run" in metadata, not by raising.

    ``scan_image`` discarded that metadata, so
    ``--scanners exposure`` on a host with no runtime returned zero
    findings, zero errors and exit 0 — the image was never opened.
    """

    @pytest.mark.parametrize("name", ["exposure", "services"])
    def test_a_skipped_sub_scanner_is_recorded(self, name, monkeypatch):
        from argus.scanners.container import ContainerScanner

        monkeypatch.setattr(
            "argus.container.scanner.is_image_local", lambda _r: True,
        )
        attr = f"_scan_{'exposed_ports' if name == 'exposure' else 'services'}"
        monkeypatch.setattr(
            ContainerScanner, attr,
            lambda self, r, c: ([], {"skipped": "no container runtime available"}),
        )
        result = scan_image(
            ContainerTarget(name="app", image_ref="app:1"), scanners=(name,),
        )
        assert name in result.scanner_errors
        assert "runtime" in result.scanner_errors[name]


class TestServicesDistinguishesUnreadableFromEmpty:
    """`_extract_paths_from_image` returned {} for both "could not read the
    image" and "the image has no such paths".

    The realistic trigger is a runtime that is installed but not running:
    ``is_available()`` is True, the pull fails, and ``services_declared: 0``
    reads as a clean result for an image nothing ever opened.
    """

    def test_unreadable_image_is_an_error(self, monkeypatch):
        from argus.scanners.container import ContainerScanner

        monkeypatch.setattr("argus.container_runtime.is_available", lambda: True)
        monkeypatch.setattr(
            ContainerScanner, "_extract_paths_from_image",
            lambda self, *a, **k: None,
        )
        _findings, meta = ContainerScanner()._scan_services("app:1", {})
        assert "error" in meta

    def test_image_with_genuinely_no_services_is_clean(self, monkeypatch):
        from argus.scanners.container import ContainerScanner

        monkeypatch.setattr("argus.container_runtime.is_available", lambda: True)
        monkeypatch.setattr(
            ContainerScanner, "_extract_paths_from_image",
            lambda self, *a, **k: {},
        )
        _findings, meta = ContainerScanner()._scan_services("app:1", {})
        assert "error" not in meta and "skipped" not in meta
        assert meta["services_declared"] == 0

    def test_no_runtime_returns_none_not_empty(self, monkeypatch):
        from argus.scanners.container import ContainerScanner

        monkeypatch.setattr("argus.container_runtime.is_available", lambda: False)
        assert ContainerScanner()._extract_paths_from_image("app:1", ("/x",)) is None


class TestNoRuntimeHasOneReportingShape:
    """The same condition must not produce two different facts.

    ``exposure`` and ``services`` each check for a container runtime,
    and ``_extract_paths_from_image`` checks it again as its own first
    statement. The inner one returned ``None``, which the caller
    rewrote into ``{"error": ...}``, while the outer ones returned
    ``{"skipped": ...}`` — so which an operator saw depended on which
    check was reached first, and the two drifted independently.

    ADR-039 settles it: an absent runtime is a precondition that was
    never met, which is ``skipped``. ``error`` means "tried and
    failed". The distinction is load-bearing — ``skipped`` on an
    unnamed sub-scanner degrades the scan, ``error`` fails it — so a
    missing daemon reporting as ``error`` would fail every default
    container scan on a daemonless host all over again.
    """

    def _no_runtime(self, monkeypatch):
        monkeypatch.setattr(
            "argus.container_runtime.is_available", lambda: False,
        )
        monkeypatch.setattr(
            "argus.container_runtime.runtime_cmd", lambda: "docker",
        )

    def test_exposure_reports_skipped_not_error(self, monkeypatch):
        self._no_runtime(monkeypatch)
        _findings, meta = ContainerScanner()._scan_exposed_ports("app:1", {})
        assert "skipped" in meta
        assert "error" not in meta

    def test_services_reports_skipped_not_error(self, monkeypatch):
        self._no_runtime(monkeypatch)
        _findings, meta = ContainerScanner()._scan_services("app:1", {})
        assert "skipped" in meta
        assert "error" not in meta

    def test_both_name_the_same_remedy(self, monkeypatch):
        """One builder, so the advice cannot drift between the two."""
        self._no_runtime(monkeypatch)
        scanner = ContainerScanner()
        _f1, exposure = scanner._scan_exposed_ports("app:1", {})
        _f2, services = scanner._scan_services("app:1", {})
        for meta in (exposure, services):
            assert "install Docker, Podman, or nerdctl" in meta["skipped"]
        # Same condition, same prefix, different capability named.
        assert exposure["skipped"] != services["skipped"]
