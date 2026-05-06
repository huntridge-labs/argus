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
    """A single security finding from a scanner."""

    id: str
    severity: Severity
    title: str
    description: str = ""
    location: Optional[str] = None
    cwe: Optional[str] = None
    cve: Optional[str] = None
    scanner: str = ""
    metadata: dict = field(default_factory=dict)

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


@dataclass
class ScanSummary:
    """Aggregated results across multiple scanner runs."""

    results: list[ScanResult] = field(default_factory=list)
    severity_threshold: Optional[Severity] = None

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
        return {
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
            "total_count": self.total_count,
            "passed": self.passed,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ScanSummary":
        """Reconstruct a ScanSummary from a to_dict() output."""
        results = [
            ScanResult.from_dict(r) for r in data.get("results", [])
        ]
        threshold_str = data.get("severity_threshold")
        threshold = Severity.from_string(threshold_str) if threshold_str else None
        return cls(results=results, severity_threshold=threshold)
