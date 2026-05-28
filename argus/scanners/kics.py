"""KICS (Keeping Infrastructure as Code Secure) scanner.

KICS (Checkmarx, Apache-2.0) is a multi-format IaC scanner. It covers
formats the existing ``trivy-iac`` / ``checkov`` pair handles poorly or
not at all — Ansible, Bicep, Helm, CDK output, OpenAPI, Tekton, Buildah,
and several server-side template engines — alongside the usual
Terraform / Kubernetes / Dockerfile / CloudFormation surface (see
issue #188). The three IaC scanners are intentionally allowed to run
concurrently: they catch different things on the same target.

CLI shape::

    kics scan -p <path> --report-formats json -o <outdir>

KICS writes ``results.json`` into ``<outdir>`` (filename fixed by KICS,
not configurable per-format). The JSON has a top-level ``queries`` array;
each query is one rule and carries a ``files`` array of per-match
locations.
"""

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from argus.containers import get_image
from argus.core.models import Finding, ScanResult, Severity
from argus.core.redact import redact_secret
from argus.core.scanner_template import ScanPaths
from argus.core.version import parse_tool_version


# KICS per-match fields that echo raw source content. ``actual_value``
# and ``search_value`` quote the literal that triggered the match — for
# a secrets/credentials query (KICS ships Ansible "Passwords And Secrets"
# and Dockerfile/K8s secret queries) that literal IS the secret. We
# redact every per-match value field before it reaches a Finding rather
# than trying to enumerate which query IDs are secret-bearing: the
# location (``file_name:line``) plus the query name is enough triage
# signal, and the raw value carries no defensive benefit downstream.
_REDACTED_MATCH_FIELDS = ("actual_value", "expected_value", "search_value")

# KICS emits the fixed name ``results.json`` for ``--report-formats json``.
_KICS_RESULT_FILENAME = "results.json"


class KICSScanner:
    """Wraps KICS to scan infrastructure-as-code for misconfigurations."""

    name = "kics"
    description = (
        "Multi-format IaC scanner — Ansible, Bicep, Helm, Terraform, "
        "Kubernetes, Dockerfile, CloudFormation, OpenAPI and more"
    )
    category = "iac"
    languages = [
        "ansible",
        "bicep",
        "helm",
        "terraform",
        "kubernetes",
        "dockerfile",
        "cloudformation",
        "openapi",
    ]
    container_image = get_image("kics")
    # The official KICS image uses ENTRYPOINT ["kics"]; engine strips
    # argv[0] for ENTRYPOINT-based images.
    container_entrypoint = "kics"

    def scan(self, path: str, config: dict | None = None) -> ScanResult:
        """Run a KICS scan against *path* and return results.

        KICS exits non-zero when it finds issues (exit 40/50 = results
        at/above the configured severity). That's the happy path, not a
        failure — only a missing ``results.json`` is treated as an
        execution failure.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_file = Path(tmp_dir) / _KICS_RESULT_FILENAME
            paths = ScanPaths(
                workspace=path,
                output=str(output_file),
            )

            result = subprocess.run(
                self.build_args(paths, config or {}),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )

            if not output_file.exists():
                return ScanResult(
                    scanner=self.name,
                    metadata={
                        "execution_failed": True,
                        "execution_failure_reason": (
                            f"No output produced (exit={result.returncode}). "
                            f"stderr: {(result.stderr or '').strip()[:400]}"
                        ),
                    },
                )

            findings = self.parse_results(output_file)
            return ScanResult(
                scanner=self.name,
                findings=findings,
                raw_report=output_file,
            )

    def build_args(self, paths: ScanPaths, config: dict) -> list[str]:
        """Build the full argv (including the binary name).

        ``ScanPaths.output`` is a file path (``.../results.json``) in both
        execution environments — the engine's container path passes
        ``/output/results.json``, local ``scan()`` passes a tempdir file.
        KICS's ``-o`` takes the output *directory* and names the file
        ``results.json`` itself, so we pass the parent dir. Engine drops
        argv[0] for ENTRYPOINT-based images, so the same method serves
        local and container execution.
        """
        output_dir = os.path.dirname(paths.output) or "."
        args = [
            "kics", "scan",
            "-p", paths.workspace,
            "--report-formats", "json",
            "-o", output_dir,
            # Don't let a single unparsable file abort the whole scan,
            # and don't colorize the JSON path's stderr.
            "--no-progress",
            "--no-color",
        ]
        config_file = config.get("config_file")
        if config_file:
            # Local: caller passes the host path; container: prefix the
            # workspace mount since the file is mounted there.
            args.extend([
                "--config",
                config_file if "/" in config_file else f"{paths.workspace}/{config_file}",
            ])
        exclude = config.get("exclude")
        if exclude:
            args.extend(["--exclude-paths", exclude])
        return args

    def is_available(self) -> bool:
        """Check if KICS is installed."""
        return shutil.which("kics") is not None

    def install_command(self) -> str | None:
        """Return install command for KICS."""
        return "curl -sfL https://raw.githubusercontent.com/Checkmarx/kics/master/install.sh | bash"

    def tool_version(self) -> str | None:
        """Return the installed KICS version, or None if not available."""
        if not self.is_available():
            return None
        return parse_tool_version(["kics", "version"], r"(\d+\.\d+\.\d+)")

    def parse_results(self, raw_output_path: Path) -> list[Finding]:
        """Parse KICS JSON output into findings.

        One :class:`Finding` is emitted per (query, matched-file) pair so
        each finding points at a concrete ``file:line`` location, mirroring
        how ``trivy-iac`` emits one finding per misconfiguration site.
        """
        data = json.loads(
            raw_output_path.read_text(encoding="utf-8", errors="replace")
        )
        queries = data.get("queries", [])

        findings: list[Finding] = []
        for query in queries:
            for matched_file in query.get("files", []):
                findings.append(self._parse_match(query, matched_file))
        return findings

    def _parse_match(self, query: dict, matched_file: dict) -> Finding:
        """Convert a single (query, matched-file) pair into a Finding.

        Redaction commitment: KICS echoes the offending source snippet in
        ``actual_value`` / ``expected_value`` / ``search_value``. For a
        secrets-class query that snippet is the secret itself, so every
        per-match value field is replaced with the redaction placeholder
        before it reaches ``Finding.metadata``. The ``file:line`` location
        and query name remain as triage signal. ``Finding.__post_init__``
        runs a vendor-prefix second pass as defence-in-depth.
        """
        severity = Severity.from_string(query.get("severity", "UNKNOWN"))

        file_name = matched_file.get("file_name", "")
        line = matched_file.get("line")
        location = f"{file_name}:{line}" if file_name and line else (file_name or None)

        cwe_raw = query.get("cwe")
        cwe = f"CWE-{cwe_raw}" if cwe_raw else None

        redacted_match = {
            field: redact_secret(matched_file.get(field))
            for field in _REDACTED_MATCH_FIELDS
            if matched_file.get(field) is not None
        }

        return Finding(
            id=query.get("query_id", "UNKNOWN"),
            severity=severity,
            title=query.get("query_name", ""),
            description=query.get("description", ""),
            location=location,
            cwe=cwe,
            scanner=self.name,
            metadata={
                "platform": query.get("platform", ""),
                "category": query.get("category", ""),
                "query_url": query.get("query_url", ""),
                "issue_type": matched_file.get("issue_type", ""),
                "expected_value": redacted_match.get("expected_value", ""),
                "actual_value": redacted_match.get("actual_value", ""),
                "search_value": redacted_match.get("search_value", ""),
            },
        )
