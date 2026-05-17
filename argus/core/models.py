"""Core data models for Argus scan results."""

import functools
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional
from pathlib import Path


# Severity ordering: higher index = more severe
_SEVERITY_ORDER = {
    "unknown": 0,
    "info": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}

_SEVERITY_ALIASES = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
    "error": "high",
    "warning": "medium",
    "note": "low",
    "unknown": "unknown",
}


@functools.total_ordering
class Severity(Enum):
    """Security finding severity levels with comparison support."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"

    @classmethod
    def from_string(cls, value: str) -> "Severity":
        """Parse severity from various scanner formats.

        Handles: CRITICAL, Critical, critical, ERROR, WARNING,
        moderate, informational, note, etc.
        """
        normalized = _SEVERITY_ALIASES.get(value.lower().strip())
        if normalized is None:
            return cls.UNKNOWN
        return cls(normalized)

    @property
    def _order(self) -> int:
        return _SEVERITY_ORDER[self.value]

    def __lt__(self, other: "Severity") -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self._order < other._order


@dataclass(frozen=True)
class Finding:
    """A single security finding from a scanner.

    Defence-in-depth on secret leakage: the constructor runs every
    text field through ``argus.core.redact.redact_finding_text``
    so any high-confidence-prefix secret a scanner forgot to redact
    (a new GitHub PAT pattern, a Slack token in a description, a
    JWT in metadata) gets replaced before the Finding can flow to
    reporters / the MCP server / log files. See ADR-022 in
    ``.ai/decisions.yaml`` for the full layering rationale.
    """

    id: str
    severity: Severity
    title: str
    description: str = ""
    location: Optional[str] = None
    cwe: Optional[str] = None
    cve: Optional[str] = None
    scanner: str = ""
    metadata: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Frozen dataclass — fields can only be set via
        # ``object.__setattr__``. Run the second-pass redactor and
        # patch the text fields in place.
        from argus.core.redact import redact_finding_text
        title, description, metadata = redact_finding_text(
            self.title, self.description, self.metadata,
        )
        object.__setattr__(self, "title", title)
        object.__setattr__(self, "description", description)
        object.__setattr__(self, "metadata", metadata)

    def to_dict(self) -> dict:
        """Serialize to a plain dictionary."""
        result = asdict(self)
        result["severity"] = self.severity.value
        return result


@dataclass
class ScanResult:
    """Results from a single scanner run."""

    scanner: str
    findings: list[Finding] = field(default_factory=list)
    raw_report: Optional[Path] = None
    sarif_report: Optional[Path] = None
    metadata: dict = field(default_factory=dict)

    @property
    def critical_count(self) -> int:
        return self._count_severity(Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return self._count_severity(Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return self._count_severity(Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return self._count_severity(Severity.LOW)

    @property
    def info_count(self) -> int:
        return self._count_severity(Severity.INFO)

    @property
    def total_count(self) -> int:
        return len(self.findings)

    def _count_severity(self, severity: Severity) -> int:
        return sum(1 for f in self.findings if f.severity == severity)

    def to_dict(self) -> dict:
        """Serialize to a plain dictionary."""
        return {
            "scanner": self.scanner,
            "findings": [f.to_dict() for f in self.findings],
            "raw_report": str(self.raw_report) if self.raw_report else None,
            "sarif_report": str(self.sarif_report) if self.sarif_report else None,
            "metadata": self.metadata,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "info_count": self.info_count,
            "total_count": self.total_count,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ScanResult":
        """Reconstruct a ScanResult from a to_dict() output."""
        findings = [
            Finding(
                id=f.get("id", ""),
                severity=Severity.from_string(f.get("severity", "unknown")),
                title=f.get("title", ""),
                description=f.get("description", ""),
                location=f.get("location"),
                cwe=f.get("cwe"),
                cve=f.get("cve"),
                scanner=f.get("scanner", ""),
                metadata=f.get("metadata", {}),
            )
            for f in data.get("findings", [])
        ]
        return cls(
            scanner=data.get("scanner", ""),
            findings=findings,
            metadata=data.get("metadata", {}),
        )


@dataclass(frozen=True)
class ScanContext:
    """Where + when a scan was actually executed.

    Captured at scan-construction time and serialized into
    ``argus-results.json`` so downstream consumers (especially the
    viewers and the MCP layer) can map scanner-emitted paths back to
    repo-relative paths and construct accurate remote URLs.

    The three fields:

    cwd
        Absolute path of the directory the scan was launched from.
        On a developer laptop this is the project root; in a
        container CI job it's typically a mount point like
        ``/workspace/argus``. The viewer subtracts this prefix
        from absolute file:line locations before treating them as
        repo-relative.

    repo_root
        Absolute path returned by ``git rev-parse --show-toplevel``
        if the cwd is inside a git working tree, else empty.
        Usually identical to ``cwd``; differs when the scan was
        launched from a subdir (e.g. ``argus scan`` invoked from
        ``src/`` rather than the repo root). The viewer prefers
        ``repo_root`` over ``cwd`` for prefix-stripping when both
        are set.

    commit_sha
        Output of ``git rev-parse HEAD`` at scan time. Used by the
        viewer to construct remote blob URLs that point at the
        commit the scan actually saw — not whatever HEAD happens
        to be when the viewer runs. Empty when the cwd isn't a git
        working tree.

    All three fields are best-effort: any subprocess that fails
    leaves the field empty rather than raising. The capture path
    is wrapped in a try/except so a non-git cwd, an air-gapped
    runner, or a missing ``git`` binary never fails the scan.
    """

    cwd: str = ""
    repo_root: str = ""
    commit_sha: str = ""

    def to_dict(self) -> dict:
        return {
            "cwd": self.cwd,
            "repo_root": self.repo_root,
            "commit_sha": self.commit_sha,
        }

    @classmethod
    def from_dict(cls, data: dict | None) -> "ScanContext":
        if not isinstance(data, dict):
            return cls()
        return cls(
            cwd=str(data.get("cwd", "")),
            repo_root=str(data.get("repo_root", "")),
            commit_sha=str(data.get("commit_sha", "")),
        )

    @classmethod
    def capture(cls, cwd: str | None = None) -> "ScanContext":
        """Capture scan context from the given cwd (defaults to os.getcwd).

        Best-effort: errors during git introspection leave the
        corresponding field empty. Never raises.
        """
        import os
        import shutil
        import subprocess

        cwd_str = str(cwd) if cwd else os.getcwd()
        repo_root = ""
        commit_sha = ""

        if shutil.which("git"):
            try:
                result = subprocess.run(
                    ["git", "-C", cwd_str, "rev-parse", "--show-toplevel"],
                    capture_output=True, text=True, check=False, timeout=5,
                )
                if result.returncode == 0:
                    repo_root = result.stdout.strip()
            except (OSError, subprocess.SubprocessError):
                pass
            try:
                result = subprocess.run(
                    ["git", "-C", cwd_str, "rev-parse", "HEAD"],
                    capture_output=True, text=True, check=False, timeout=5,
                )
                if result.returncode == 0:
                    commit_sha = result.stdout.strip()
            except (OSError, subprocess.SubprocessError):
                pass

        return cls(cwd=cwd_str, repo_root=repo_root, commit_sha=commit_sha)


@dataclass
class ScanSummary:
    """Aggregated results across multiple scanner runs."""

    results: list[ScanResult] = field(default_factory=list)
    severity_threshold: Optional[Severity] = None
    # Scan-time context — where the scan ran + what commit it saw.
    # Populated by the engine at ScanSummary construction; None when
    # a ScanSummary is built outside the engine (e.g. tests, the diff
    # viewer reading two files into memory) so the viewer can fall
    # back to its existing heuristic resolution.
    scan_context: Optional[ScanContext] = None
    # True when the user passed --fail-on-scanner-error (or
    # ``reporting.fail_on_scanner_error: true`` in argus.yml). Set by
    # the CLI dispatcher before any reporter runs; lets reporters
    # suppress "pass --fail-on-scanner-error to fail the scan when
    # this happens" advice when the flag is already on (issue #168-D).
    fail_on_scanner_error_set: bool = False

    @property
    def critical_count(self) -> int:
        return sum(r.critical_count for r in self.results)

    @property
    def high_count(self) -> int:
        return sum(r.high_count for r in self.results)

    @property
    def medium_count(self) -> int:
        return sum(r.medium_count for r in self.results)

    @property
    def low_count(self) -> int:
        return sum(r.low_count for r in self.results)

    @property
    def info_count(self) -> int:
        return sum(r.info_count for r in self.results)

    @property
    def total_count(self) -> int:
        return sum(r.total_count for r in self.results)

    @property
    def passed(self) -> bool:
        """True if no findings meet or exceed the severity threshold."""
        if self.severity_threshold is None:
            return True
        return not any(
            f.severity >= self.severity_threshold
            for r in self.results
            for f in r.findings
        )

    def to_dict(self) -> dict:
        """Serialize to a plain dictionary."""
        out: dict = {
            "results": [r.to_dict() for r in self.results],
            "severity_threshold": (
                self.severity_threshold.value
                if self.severity_threshold
                else None
            ),
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "info_count": self.info_count,
            "total_count": self.total_count,
            "passed": self.passed,
        }
        if self.scan_context is not None:
            out["scan_context"] = self.scan_context.to_dict()
        return out

    @classmethod
    def from_dict(cls, data: dict) -> "ScanSummary":
        """Reconstruct a ScanSummary from a to_dict() output."""
        results = [
            ScanResult.from_dict(r) for r in data.get("results", [])
        ]
        threshold_str = data.get("severity_threshold")
        threshold = Severity.from_string(threshold_str) if threshold_str else None
        scan_context = None
        if "scan_context" in data:
            scan_context = ScanContext.from_dict(data.get("scan_context"))
        return cls(
            results=results,
            severity_threshold=threshold,
            scan_context=scan_context,
        )
