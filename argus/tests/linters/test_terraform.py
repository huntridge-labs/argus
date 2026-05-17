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

from argus.linters.terraform import TerraformLinter


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
