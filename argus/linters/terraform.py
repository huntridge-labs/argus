"""Terraform linter wrapping terraform fmt, validate, and tflint."""

import json
import shutil
import subprocess

from argus.containers import get_image
from argus.core.linter_template import build_docker_command
from argus.core.models import Finding, PhaseResult, ScanResult, Severity
from argus.core.version import parse_tool_version


# Patterns in stderr that mark a subprocess as having failed at the
# runtime layer (image pull, daemon contact, registry auth) rather than
# the tool layer. When one of these matches a non-zero exit with no
# stdout, the phase is recorded as ``status="failed"`` so the engine
# folds the scanner into the "did not run cleanly" bucket — issue #169.
_RUNTIME_FAILURE_MARKERS = (
    "failed to pull",
    "error response from daemon",
    "manifest unknown",
    "permission denied",
    "cannot connect to the docker daemon",
    "is the docker daemon running",
    "unix:///var/run/docker.sock",
    "403 forbidden",
    "401 unauthorized",
    "no matching manifest",
    "toomanyrequests",
    "dial tcp",
    "connection refused",
)


def _detect_runtime_failure(
    result: subprocess.CompletedProcess | None,
) -> str | None:
    """Inspect a subprocess result for runtime (vs. tool-layer) failure.

    Returns the error message when the subprocess looks like it never
    successfully ran the tool — None when the tool itself exited (even
    with findings). Examples that return non-None:

      - subprocess.run raised before launch (caller passes ``None``)
      - image pull error (stderr contains a pull/auth/network marker)
      - non-zero exit with completely empty stdout

    Heuristic, not bulletproof — tools that print diffs / JSON / counts
    on stdout when they have something to say all share the "empty
    stdout + non-zero exit = nothing ran" property.
    """
    if result is None:
        return "command runner unavailable (no local tool, no docker)"
    stdout = (result.stdout or "").strip()
    stderr = (result.stderr or "").strip()
    if result.returncode == 0:
        return None
    lower_err = stderr.lower()
    for marker in _RUNTIME_FAILURE_MARKERS:
        if marker in lower_err:
            return f"image pull/runtime failed: {stderr[:200]}"
    if not stdout:
        # Tool was supposed to print SOMETHING (diff, JSON, banner) on
        # success or expected failure. Empty stdout + non-zero exit is
        # the runtime-error shape.
        return f"command exited {result.returncode} with no output: {stderr[:200]}"
    return None


class TerraformLinter:
    """Wraps terraform fmt/validate and tflint for Terraform linting.

    Falls back to the official ``hashicorp/terraform`` and
    ``ghcr.io/terraform-linters/tflint`` Docker images when the local
    binaries aren't installed — same shape as
    :class:`argus.linters.hadolint.HadolintLinter`. The workspace is
    bind-mounted read-write because ``terraform init -backend=false``
    needs to drop a ``.terraform/`` directory before ``terraform
    validate -json`` can read its plugin state.

    Each phase (``terraform-fmt``, ``terraform-validate``, ``tflint``)
    produces a :class:`PhaseResult`. When one phase fails — typically
    because the underlying container image pull fails — the scanner
    still returns a ScanResult, but with the failed phase recorded so
    the engine and reporters bucket the run as "did not run cleanly"
    instead of the silent ``PASS`` it used to be (issue #169).
    """

    name = "lint-terraform"
    description = "Terraform formatting and validation linter"
    category = "linter"
    languages = ["terraform"]
    container_image = get_image("terraform")

    def scan(self, path: str, config: dict | None = None) -> ScanResult:
        """Run terraform fmt check, validate, and optionally tflint."""
        config = config or {}
        phases: list[PhaseResult] = []

        phases.append(self._run_fmt_check(path))
        phases.append(self._run_validate(path))

        if config.get("run_tflint", True):
            phases.append(self._run_tflint(path, config))

        all_findings: list[Finding] = [
            f for p in phases for f in p.findings
        ]
        return ScanResult(
            scanner=self.name,
            findings=all_findings,
            phase_results=phases,
        )

    def is_available(self) -> bool:
        """Check if terraform is installed locally.

        ``False`` when only Docker is available — the engine and
        ``scan()`` itself both fall back to the container image
        transparently in that case.
        """
        return shutil.which("terraform") is not None

    def install_command(self) -> str | None:
        return "Install from https://developer.hashicorp.com/terraform/install"

    def tool_version(self) -> str | None:
        if not self.is_available():
            return None
        return parse_tool_version(["terraform", "--version"], r"^Terraform v(\S+)")

    # ------------------------------------------------------------------
    # Subprocess execution helpers — local first, container fallback
    # ------------------------------------------------------------------

    def _run_terraform(self, args: list[str], path: str) -> subprocess.CompletedProcess:
        """Run ``terraform <args>`` locally if available, else via Docker."""
        if shutil.which("terraform"):
            return subprocess.run(
                ["terraform", *args],
                capture_output=True, text=True, cwd=path,
            )
        cmd = build_docker_command(
            get_image("terraform"), path, args,
            mount_rw=True, workdir="/workspace",
        )
        return subprocess.run(cmd, capture_output=True, text=True)

    def _run_tflint_subprocess(self, args: list[str], path: str) -> subprocess.CompletedProcess | None:
        """Run ``tflint <args>``, returning None when neither local nor docker is available.

        The mount is read-write because ``terraform init`` and
        ``tflint --init`` write plugin state under ``.terraform/`` and
        ``.tflint.d/`` respectively. The user's repo is already where
        terraform would write locally; RW preserves that contract.
        """
        if shutil.which("tflint"):
            return subprocess.run(
                ["tflint", *args],
                capture_output=True, text=True, cwd=path,
            )
        if shutil.which("docker"):
            cmd = build_docker_command(
                get_image("tflint"), path, args,
                mount_rw=True, workdir="/workspace",
            )
            return subprocess.run(cmd, capture_output=True, text=True)
        return None

    # ------------------------------------------------------------------
    # Per-tool runners
    # ------------------------------------------------------------------

    def _run_fmt_check(self, path: str) -> PhaseResult:
        """Run ``terraform fmt -check`` and return a phase result.

        ``terraform fmt -check`` exits 0 when all files are formatted,
        non-zero when some need formatting (with diffs on stdout) — both
        are "ran". Empty stdout + non-zero exit means the tool never ran
        (typically a container pull failure); the phase records as
        ``failed`` so the engine surfaces it (issue #169).
        """
        result = self._run_terraform(["fmt", "-check", "-recursive", "-diff"], path)

        err = _detect_runtime_failure(result)
        if err is not None:
            return PhaseResult(
                phase="terraform-fmt",
                status="failed",
                findings=[],
                error=err,
            )

        if result.returncode == 0:
            return PhaseResult(phase="terraform-fmt", status="ran", findings=[])

        findings = []
        for line in result.stdout.strip().splitlines():
            line = line.strip()
            if not line or line.startswith(("---", "+++", "@@", " ", "-", "+")):
                continue
            findings.append(Finding(
                id="terraform-fmt",
                severity=Severity.INFO,
                title=f"File needs formatting: {line}",
                description="Run 'terraform fmt' to fix formatting.",
                location=line,
                scanner=self.name,
            ))
        return PhaseResult(
            phase="terraform-fmt", status="ran", findings=findings,
        )

    def _run_validate(self, path: str) -> PhaseResult:
        """Run ``terraform validate`` (preceded by ``terraform init``).

        Both ``init`` and ``validate`` are wrapped in runtime-failure
        detection; if either fails because the container couldn't pull
        or the daemon is down, the phase records as ``failed`` rather
        than silently returning 0 findings.
        """
        # init writes plugin state into .terraform/ so validate can read it.
        init_result = self._run_terraform(["init", "-backend=false"], path)
        err = _detect_runtime_failure(init_result)
        if err is not None:
            return PhaseResult(
                phase="terraform-validate",
                status="failed",
                findings=[],
                error=f"terraform init failed: {err}",
            )

        result = self._run_terraform(["validate", "-json"], path)
        err = _detect_runtime_failure(result)
        if err is not None:
            return PhaseResult(
                phase="terraform-validate",
                status="failed",
                findings=[],
                error=err,
            )

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            return PhaseResult(
                phase="terraform-validate",
                status="failed",
                findings=[],
                error=(
                    f"terraform validate -json produced unparsable output "
                    f"(exit={result.returncode}): {exc}"
                ),
            )

        if data.get("valid", True):
            return PhaseResult(
                phase="terraform-validate", status="ran", findings=[],
            )

        findings = []
        for diag in data.get("diagnostics", []):
            location = None
            diag_range = diag.get("range", {})
            filename = diag_range.get("filename", "")
            start = diag_range.get("start", {})
            if filename:
                line_num = start.get("line", 0)
                location = f"{filename}:{line_num}"

            findings.append(Finding(
                id="terraform-validate",
                severity=Severity.INFO,
                title=diag.get("summary", "Validation error"),
                description=diag.get("detail", ""),
                location=location,
                scanner=self.name,
                metadata={"severity": diag.get("severity", "")},
            ))
        return PhaseResult(
            phase="terraform-validate", status="ran", findings=findings,
        )

    def _run_tflint(self, path: str, config: dict) -> PhaseResult:
        """Run tflint for additional linting rules.

        ``status="skipped"`` when neither local tflint nor docker is
        available — terraform fmt/validate already produce findings, so
        a missing tflint isn't a hard error. ``status="failed"`` when
        tflint launches but the container pull fails or its JSON output
        is unparsable; ``status="ran"`` on a clean execution.
        """
        args = ["--format=json"]
        config_file = config.get("tflint_config")
        if config_file:
            args.append(f"--config={config_file}")

        result = self._run_tflint_subprocess(args, path)
        if result is None:
            return PhaseResult(
                phase="tflint",
                status="skipped",
                findings=[],
                error="neither local tflint nor docker available",
            )

        err = _detect_runtime_failure(result)
        if err is not None:
            return PhaseResult(
                phase="tflint",
                status="failed",
                findings=[],
                error=err,
            )

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            return PhaseResult(
                phase="tflint",
                status="failed",
                findings=[],
                error=(
                    f"tflint produced unparsable JSON (exit="
                    f"{result.returncode}): {exc}"
                ),
            )

        findings = []
        for issue in data.get("issues", []):
            location = None
            issue_range = issue.get("range", {})
            filename = issue_range.get("filename", "")
            start = issue_range.get("start", {})
            if filename:
                line_num = start.get("line", 0)
                location = f"{filename}:{line_num}"

            findings.append(Finding(
                id=issue.get("rule", {}).get("name", "tflint"),
                severity=Severity.INFO,
                title=issue.get("message", ""),
                description=issue.get("message", ""),
                location=location,
                scanner=self.name,
                metadata={
                    "rule_severity": issue.get("rule", {}).get("severity", ""),
                },
            ))
        return PhaseResult(
            phase="tflint", status="ran", findings=findings,
        )
