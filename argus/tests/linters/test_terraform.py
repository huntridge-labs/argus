"""Tests for argus.linters.terraform.TerraformLinter.

Locks in the partial-failure shape introduced in issue #169: each phase
(``terraform-fmt``, ``terraform-validate``, ``tflint``) produces a
PhaseResult, and a phase whose underlying subprocess fails at the
runtime layer (image pull error, daemon down) is recorded with
``status="failed"`` so the engine folds the scanner into the "did not
run cleanly" bucket — instead of the pre-fix silent PASS with 0
findings.
"""

from __future__ import annotations

import subprocess
from unittest.mock import patch

from argus.linters.terraform import TerraformLinter, _detect_runtime_failure


def _completed(stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess(
        args=["terraform"], returncode=returncode, stdout=stdout, stderr=stderr,
    )


class TestTerraformPhaseResults:
    """The scan() contract surfaces per-phase outcomes."""

    def test_all_phases_clean_marks_all_ran(self):
        """When every phase exits cleanly, scan() returns a ScanResult
        whose phase_results all carry status='ran' and partial_failure
        is False."""
        # fmt clean: returncode 0
        # init clean: returncode 0
        # validate clean: {"valid": true} JSON
        # tflint clean: {"issues": []} JSON, returncode 0
        call_count = [0]

        def fake_terraform(args, path):
            call_count[0] += 1
            if "fmt" in args:
                return _completed()
            if "init" in args:
                return _completed()
            if "validate" in args:
                return _completed(stdout='{"valid": true}')
            return _completed()

        with patch.object(
            TerraformLinter, "_run_terraform", side_effect=fake_terraform,
        ), patch.object(
            TerraformLinter, "_run_tflint_subprocess",
            return_value=_completed(stdout='{"issues": []}'),
        ):
            result = TerraformLinter().scan("/some/path", {})

        assert result.partial_failure is False
        phase_names = [p.phase for p in result.phase_results]
        assert phase_names == ["terraform-fmt", "terraform-validate", "tflint"]
        assert all(p.status == "ran" for p in result.phase_results)
        assert result.findings == []

    def test_partial_failure_when_one_phase_fails(self):
        """Issue #169 acceptance: when one phase fails (e.g. the
        ``hashicorp/terraform`` container can't be pulled), the scanner
        still returns a ScanResult but ``partial_failure`` is True and
        the failing phase carries an error string. The engine and
        terminal reporter then bucket this scanner as
        "did not run cleanly" rather than silently passing."""
        # terraform-fmt fails with a pull-error-shaped stderr; tflint
        # runs cleanly so the scanner doesn't entirely collapse.
        def fake_terraform(args, path):
            if "fmt" in args:
                return _completed(
                    stdout="",
                    stderr=(
                        "Unable to find image 'hashicorp/terraform:1.9.8' "
                        "locally\nError response from daemon: failed to "
                        "pull image"
                    ),
                    returncode=125,
                )
            if "init" in args:
                return _completed(
                    stdout="",
                    stderr="failed to pull image",
                    returncode=125,
                )
            return _completed(stdout='{"valid": true}')

        with patch.object(
            TerraformLinter, "_run_terraform", side_effect=fake_terraform,
        ), patch.object(
            TerraformLinter, "_run_tflint_subprocess",
            return_value=_completed(stdout='{"issues": []}'),
        ):
            result = TerraformLinter().scan("/some/path", {})

        assert result.partial_failure is True
        # The failed phases are terraform-fmt and terraform-validate.
        failed_phases = {p.phase for p in result.failed_phases}
        assert "terraform-fmt" in failed_phases
        assert "terraform-validate" in failed_phases
        # Errors are populated and reference the runtime/pull issue.
        for phase in result.failed_phases:
            assert phase.error
            assert "pull" in phase.error.lower() or "image" in phase.error.lower()

    def test_tflint_skipped_when_no_runner_available(self):
        """Tflint is best-effort — when neither local tflint nor docker
        is available the phase records ``status="skipped"`` (not
        ``failed``), so it doesn't bubble up as a partial failure."""
        with patch.object(
            TerraformLinter, "_run_terraform",
            return_value=_completed(stdout='{"valid": true}'),
        ), patch.object(
            TerraformLinter, "_run_tflint_subprocess", return_value=None,
        ):
            result = TerraformLinter().scan("/some/path", {})

        tflint_phase = next(
            p for p in result.phase_results if p.phase == "tflint"
        )
        assert tflint_phase.status == "skipped"
        # ``skipped`` does NOT count as a partial failure.
        assert result.partial_failure is False

    def test_tflint_disabled_by_config_does_not_emit_phase(self):
        """When ``config['run_tflint']`` is False the phase isn't even
        attempted — it just doesn't appear in phase_results."""
        with patch.object(
            TerraformLinter, "_run_terraform",
            return_value=_completed(stdout='{"valid": true}'),
        ), patch.object(
            TerraformLinter, "_run_tflint_subprocess",
        ) as tflint_patch:
            result = TerraformLinter().scan("/some/path", {"run_tflint": False})

        assert tflint_patch.call_count == 0
        phase_names = [p.phase for p in result.phase_results]
        assert "tflint" not in phase_names


class TestDetectRuntimeFailure:
    """Edge cases for the runtime-vs-tool failure heuristic.

    The helper drives the per-phase status decision throughout the
    terraform linter — its branches need explicit coverage rather
    than relying on the higher-level scan() tests, which only exercise
    the pull-error path.
    """

    def test_none_input_returns_runner_unavailable(self):
        # ``_run_tflint_subprocess`` returns None when neither a local
        # tflint nor docker is on the PATH. Callers translate that
        # into a ``skipped`` phase rather than ``failed``.
        assert _detect_runtime_failure(None) is not None
        assert "command runner" in _detect_runtime_failure(None)

    def test_zero_exit_returns_none_even_with_stderr(self):
        # Tools commonly write progress / deprecation warnings to
        # stderr while still exiting 0. The helper must not flag those
        # as runtime failures.
        result = _completed(stdout='{"valid": true}', stderr="warning: stale plan", returncode=0)
        assert _detect_runtime_failure(result) is None

    def test_empty_stdout_nonzero_exit_flags_runtime_failure(self):
        # Empty stdout + non-zero exit + no known pull marker is the
        # generic "tool never produced output" shape — still a runtime
        # failure for our purposes (the tool would have printed
        # findings / diffs / JSON on a real run).
        result = _completed(stdout="", stderr="something exploded", returncode=2)
        err = _detect_runtime_failure(result)
        assert err is not None
        assert "command exited 2" in err

    def test_nonzero_exit_with_stdout_returns_none(self):
        # ``terraform fmt -check`` exits non-zero when files need
        # formatting, with diffs on stdout. That's "ran cleanly with
        # findings", NOT a runtime failure.
        result = _completed(stdout="--- a/main.tf\n+++ b/main.tf\n", returncode=3)
        assert _detect_runtime_failure(result) is None

    def test_pull_marker_in_stderr_overrides_stdout_presence(self):
        # Even with stdout present, a recognised pull/auth/daemon
        # marker in stderr counts as runtime failure — covers the
        # case where docker writes partial output before failing.
        result = _completed(
            stdout="partial output",
            stderr="Error response from daemon: failed to pull",
            returncode=1,
        )
        err = _detect_runtime_failure(result)
        assert err is not None
        assert "image pull/runtime failed" in err


class TestTerraformPhaseFindings:
    """Findings flowing out of individual phases.

    Each phase has a "ran cleanly with findings" path that's narrower
    than the partial-failure shape — covering it here keeps the
    aggregation logic in scan() honest.
    """

    def test_fmt_check_emits_findings_when_diffs_present(self):
        # terraform fmt -check exits non-zero with diff content on
        # stdout when files need reformatting. Phase status stays
        # "ran" but findings are populated, one per file.
        diff_output = (
            "main.tf\nvariables.tf\n"
            "--- old\n+++ new\n@@ -1,1 +1,2 @@\n"
            " resource\n+  tags = {}\n"
        )
        with patch.object(
            TerraformLinter, "_run_terraform",
            side_effect=[
                _completed(stdout=diff_output, returncode=3),  # fmt
                _completed(),  # init (clean)
                _completed(stdout='{"valid": true}'),  # validate
            ],
        ), patch.object(
            TerraformLinter, "_run_tflint_subprocess",
            return_value=_completed(stdout='{"issues": []}'),
        ):
            result = TerraformLinter().scan("/some/path", {})

        assert result.partial_failure is False
        fmt_phase = next(p for p in result.phase_results if p.phase == "terraform-fmt")
        assert fmt_phase.status == "ran"
        # main.tf + variables.tf rows survive the diff-marker filter.
        finding_locations = {f.location for f in fmt_phase.findings}
        assert "main.tf" in finding_locations
        assert "variables.tf" in finding_locations

    def test_validate_emits_findings_when_diagnostics_present(self):
        # validate -json returns ``{"valid": false, "diagnostics": [...]}``
        # when modules don't compile. Each diagnostic becomes a Finding
        # carrying file:line location and the diagnostic summary.
        validate_payload = (
            '{"valid": false, "diagnostics": ['
            '{"summary": "missing required argument", '
            '"detail": "var bucket_name is not set", '
            '"severity": "error", '
            '"range": {"filename": "main.tf", "start": {"line": 42}}}'
            "]}"
        )

        def fake_terraform(args, path):
            if "fmt" in args:
                return _completed()
            if "init" in args:
                return _completed()
            return _completed(stdout=validate_payload)

        with patch.object(
            TerraformLinter, "_run_terraform", side_effect=fake_terraform,
        ), patch.object(
            TerraformLinter, "_run_tflint_subprocess",
            return_value=_completed(stdout='{"issues": []}'),
        ):
            result = TerraformLinter().scan("/some/path", {})

        assert result.partial_failure is False
        validate_phase = next(
            p for p in result.phase_results if p.phase == "terraform-validate"
        )
        assert validate_phase.status == "ran"
        assert len(validate_phase.findings) == 1
        finding = validate_phase.findings[0]
        assert finding.location == "main.tf:42"
        assert "missing required argument" in finding.title

    def test_validate_unparsable_json_marks_phase_failed(self):
        # ``terraform validate -json`` exiting 0 but emitting garbage
        # (or banner text mixed with JSON) trips the JSONDecodeError
        # path. Phase records as failed with the parse reason — the
        # engine surfaces this in the "did not run cleanly" bucket.
        def fake_terraform(args, path):
            if "fmt" in args or "init" in args:
                return _completed()
            return _completed(stdout="not valid json", returncode=0)

        with patch.object(
            TerraformLinter, "_run_terraform", side_effect=fake_terraform,
        ), patch.object(
            TerraformLinter, "_run_tflint_subprocess",
            return_value=_completed(stdout='{"issues": []}'),
        ):
            result = TerraformLinter().scan("/some/path", {})

        assert result.partial_failure is True
        failed = {p.phase: p for p in result.failed_phases}
        assert "terraform-validate" in failed
        assert "unparsable output" in failed["terraform-validate"].error

    def test_tflint_emits_findings_when_issues_present(self):
        tflint_payload = (
            '{"issues": [{"rule": {"name": "terraform_required_providers", '
            '"severity": "warning"}, "message": "Missing providers block", '
            '"range": {"filename": "main.tf", "start": {"line": 7}}}]}'
        )
        with patch.object(
            TerraformLinter, "_run_terraform",
            return_value=_completed(stdout='{"valid": true}'),
        ), patch.object(
            TerraformLinter, "_run_tflint_subprocess",
            return_value=_completed(stdout=tflint_payload),
        ):
            result = TerraformLinter().scan("/some/path", {})

        tflint_phase = next(p for p in result.phase_results if p.phase == "tflint")
        assert tflint_phase.status == "ran"
        assert len(tflint_phase.findings) == 1
        finding = tflint_phase.findings[0]
        assert finding.id == "terraform_required_providers"
        assert finding.location == "main.tf:7"

    def test_tflint_runtime_failure_marks_phase_failed(self):
        # tflint's container failed to pull. The phase records as
        # failed, the scanner is partial_failure=True.
        with patch.object(
            TerraformLinter, "_run_terraform",
            return_value=_completed(stdout='{"valid": true}'),
        ), patch.object(
            TerraformLinter, "_run_tflint_subprocess",
            return_value=_completed(
                stdout="",
                stderr="Error response from daemon: failed to pull",
                returncode=125,
            ),
        ):
            result = TerraformLinter().scan("/some/path", {})

        tflint_phase = next(p for p in result.phase_results if p.phase == "tflint")
        assert tflint_phase.status == "failed"
        assert "image pull" in (tflint_phase.error or "").lower() \
            or "runtime" in (tflint_phase.error or "").lower()

    def test_tflint_unparsable_json_marks_phase_failed(self):
        with patch.object(
            TerraformLinter, "_run_terraform",
            return_value=_completed(stdout='{"valid": true}'),
        ), patch.object(
            TerraformLinter, "_run_tflint_subprocess",
            return_value=_completed(stdout="garbage", returncode=0),
        ):
            result = TerraformLinter().scan("/some/path", {})

        tflint_phase = next(p for p in result.phase_results if p.phase == "tflint")
        assert tflint_phase.status == "failed"
        assert "unparsable" in (tflint_phase.error or "").lower()
