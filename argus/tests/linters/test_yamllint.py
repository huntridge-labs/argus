"""Tests for argus.linters.yamllint.YamllintLinter.

Locks in the exit-code contract that previously allowed exit ≥ 2 to be
silently dropped: ``_parse_output("")`` returned ``[]`` and the caller
saw a clean ``ScanResult`` with zero findings, so a yamllint config
error rendered as ``Status: PASS``. The fix maps exit ≥ 2 + empty
findings to ``execution_failed`` so the terminal warning row, the
``--fail-on-scanner-error`` gate, and the engine's container-path
metadata all see the same shape.
"""

import subprocess
from unittest.mock import patch

from argus.core.models import Severity
from argus.linters.yamllint import YamllintLinter


def _completed(stdout: str = "", stderr: str = "", returncode: int = 0):
    return subprocess.CompletedProcess(
        args=["yamllint"], returncode=returncode, stdout=stdout, stderr=stderr,
    )


class TestYamllintScanExitCodes:
    """Per yamllint docs: 0=clean, 1=lint findings, 2+=runtime/config error."""

    def test_exit_zero_no_findings_is_clean_pass(self):
        linter = YamllintLinter()
        with patch("subprocess.run", return_value=_completed(returncode=0)):
            result = linter.scan(".")
        assert result.findings == []
        assert result.metadata.get("returncode") == 0
        # Exit 0 must NOT be treated as an execution failure.
        assert result.metadata.get("execution_failed") is not True

    def test_exit_one_with_findings_is_happy_path(self):
        # The "lint problems exist" exit code is the *expected* outcome
        # when violations are present — never an execution failure.
        sample = "config.yml:3:1: [error] syntax error (key-duplicates)"
        linter = YamllintLinter()
        with patch("subprocess.run", return_value=_completed(stdout=sample, returncode=1)):
            result = linter.scan(".")
        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.INFO
        assert result.metadata.get("returncode") == 1
        assert result.metadata.get("execution_failed") is not True

    def test_exit_one_with_findings_does_not_mark_failed_even_if_findings_only_partial(self):
        # Even when stdout has content that doesn't fully parse, exit
        # 1 still means yamllint *ran*. Don't blame the tool.
        linter = YamllintLinter()
        with patch(
            "subprocess.run",
            return_value=_completed(stdout="garbage that won't parse", returncode=1),
        ):
            result = linter.scan(".")
        # Parser may produce zero findings, but exit=1 still isn't a
        # runtime error — return code drives the decision, not parse
        # success.
        assert result.metadata.get("execution_failed") is not True

    def test_exit_two_empty_stdout_marks_execution_failed(self):
        """Regression: yamllint exit 2+ with empty stdout means the
        tool itself failed (bad config path, unreadable input,
        internal error). Previously we silently dropped this and
        printed Status: PASS. Now it surfaces via the same
        ``execution_failed`` metadata key the engine's container path
        emits, so reporters and ``--fail-on-scanner-error`` see it."""
        linter = YamllintLinter()
        stderr_msg = "configuration error: file not found"
        with patch(
            "subprocess.run",
            return_value=_completed(stdout="", stderr=stderr_msg, returncode=2),
        ):
            result = linter.scan(".")
        assert result.findings == []
        assert result.metadata.get("execution_failed") is True
        reason = result.metadata.get("execution_failure_reason", "")
        assert "yamllint exited 2" in reason
        # User-actionable: stderr is included so they don't have to
        # re-run with --verbose just to see why.
        assert stderr_msg in reason

    def test_high_exit_code_with_empty_stdout_marks_execution_failed(self):
        # Any exit ≥ 2 with no parsed findings is the same failure mode.
        linter = YamllintLinter()
        with patch(
            "subprocess.run",
            return_value=_completed(stdout="", stderr="boom", returncode=99),
        ):
            result = linter.scan(".")
        assert result.metadata.get("execution_failed") is True
        assert "exited 99" in result.metadata.get("execution_failure_reason", "")

    def test_returncode_always_recorded_in_metadata(self):
        # Returncode is captured even on the happy path so audit logs
        # and viewers can show it without re-running the tool.
        linter = YamllintLinter()
        with patch("subprocess.run", return_value=_completed(returncode=0)):
            result = linter.scan(".")
        assert "returncode" in result.metadata

    def test_permission_error_on_windows_falls_back_to_python_module(self, monkeypatch):
        """On Windows hosts with AppLocker / Software Restriction
        Policy blocking executables in user AppData paths,
        ``yamllint.exe`` raises PermissionError on direct launch but
        loading the same package via ``python -m yamllint`` works
        (the interpreter is whitelisted). The linter must detect
        that path and retry — without disturbing the Linux flow.

        The test pretends to be on Windows and asserts the second
        ``subprocess.run`` call is the ``python -m`` invocation."""
        from argus.linters import yamllint as ymod
        monkeypatch.setattr(ymod.sys, "platform", "win32")

        calls = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            if len(calls) == 1:
                # First call: direct yamllint invocation — simulate
                # AppLocker blocking it.
                raise PermissionError(13, "Access is denied", "yamllint.exe")
            # Second call: Windows fallback — succeeds.
            return _completed(stdout="path:1:1: [error] msg (rule)", returncode=1)

        with patch("subprocess.run", side_effect=fake_run):
            result = ymod.YamllintLinter().scan(".")

        # Both subprocess.run calls fired (direct + fallback).
        assert len(calls) == 2, f"expected 2 calls, got {len(calls)}: {calls}"
        # First was the direct binary invocation.
        assert calls[0][0] == "yamllint"
        # Second was 'python -m yamllint' with sys.executable as argv[0].
        assert calls[1][0] == ymod.sys.executable
        assert calls[1][1] == "-m"
        assert calls[1][2] == "yamllint"
        # Result-parsing logic is unchanged — the finding from the
        # fallback's stdout still made it through.
        assert len(result.findings) == 1
        assert result.metadata.get("execution_failed") is not True

    def test_permission_error_on_linux_does_not_fall_back(self, monkeypatch):
        """Cross-platform safety: Linux must NOT use the Windows
        fallback. AppLocker doesn't exist on Linux; a PermissionError
        there indicates a genuine permission bug (chmod, mount
        options) that the user needs to see, not a policy case the
        fallback compensates for. We re-raise and let the outer
        handler mark execution_failed with the actual reason."""
        from argus.linters import yamllint as ymod
        monkeypatch.setattr(ymod.sys, "platform", "linux")

        calls = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            raise PermissionError(13, "Permission denied", "yamllint")

        with patch("subprocess.run", side_effect=fake_run):
            result = ymod.YamllintLinter().scan(".")

        # Exactly ONE subprocess.run call — no fallback retry.
        # Linux happy-path / failure-path bytes are unchanged from
        # before this fix.
        assert len(calls) == 1
        # The PermissionError surfaces as execution_failed (caught by
        # the outer OSError handler in scan()), not as a stack trace.
        assert result.metadata.get("execution_failed") is True
        assert "PermissionError" in result.metadata.get(
            "execution_failure_reason", "",
        )

    def test_subprocess_uses_utf8_encoding(self, monkeypatch):
        """Bug 2 regression: container / CLI scanner output is UTF-8.
        Without explicit ``encoding='utf-8'`` the platform default
        (cp1252 on Windows) raises UnicodeDecodeError on non-ASCII
        bytes in YAML file paths or value content. We assert the
        subprocess.run call passes ``encoding='utf-8'`` and
        ``errors='replace'`` so Windows decodes container output
        the same way Linux does."""
        from argus.linters import yamllint as ymod

        captured: dict = {}

        def fake_run(cmd, **kwargs):
            captured.update(kwargs)
            return _completed(returncode=0)

        with patch("subprocess.run", side_effect=fake_run):
            ymod.YamllintLinter().scan(".")

        assert captured.get("encoding") == "utf-8"
        assert captured.get("errors") == "replace"

    def test_filenotfound_returns_execution_failed_not_raised(self):
        """If the yamllint binary disappears between is_available()
        and subprocess.run() (rare but possible: race in CI cleanup,
        manual uninstall mid-scan), scan() must not raise. Letting
        FileNotFoundError propagate triggers the engine's exception
        handler and renders a stack trace; a clean
        ``execution_failed`` ScanResult lets the reporter surface
        the actual reason."""
        linter = YamllintLinter()
        with patch(
            "subprocess.run",
            side_effect=FileNotFoundError(2, "no such file", "yamllint"),
        ):
            result = linter.scan(".")
        assert result.findings == []
        assert result.metadata.get("execution_failed") is True
        reason = result.metadata.get("execution_failure_reason", "")
        assert "yamllint" in reason
        assert "not found" in reason
