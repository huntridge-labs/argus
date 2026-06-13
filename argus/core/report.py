"""Formal vulnerability report model (Phase B4).

A *UI-free* view model for the authoritative, hand-it-to-a-government-body
security report that ``argus view browser`` renders to HTML and (with the
``[report]`` extra) to PDF. Everything here is pure data — no HTML, no Jinja,
no FastAPI — so the model is unit-testable without any viewer extra installed
and the same shape powers both the on-screen preview and the printed artifact.

What makes the report *authoritative* is the provenance block: the exact Argus
version that produced it, the commit SHA the scan saw, the scanner-toolchain
container images + digests + their cosign/digest verification status, and
whether a signed attestation sits alongside the scan. A reader can tie the
numbers in the report back to a specific, verifiable scan rather than trusting
a screenshot.

The findings/summary half reuses the same shared logic the dashboard and TUI
use (``argus.core.findings_view``), so the report's counts are identical to
what the interactive views show — one source of truth for "what does high
severity mean and which findings match".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from argus.core.findings_view import SEVERITY_ORDER, compute_summary
from argus.core.models import Finding, ScanSummary, Severity

# Attestation artifacts ``argus.core.attest`` writes next to a scan. Their
# presence lets the report state whether the scan is *tamper-evident* (signed)
# or merely *recorded* (unsigned in-toto statement) — a material distinction
# for a compliance reader.
_BUNDLE_FILENAME = "argus-attestation.bundle"
_STATEMENT_FILENAME = "argus-attestation.intoto.json"


@dataclass(frozen=True)
class SeverityGroup:
    """One severity bucket of findings, in report display order."""

    severity: Severity
    findings: list[Finding]

    @property
    def value(self) -> str:
        return self.severity.value

    @property
    def label(self) -> str:
        return self.severity.value.capitalize()

    @property
    def count(self) -> int:
        return len(self.findings)


@dataclass(frozen=True)
class ReportProvenance:
    """The "trust this artifact" block — who/what/when produced the scan.

    Every field is best-effort: a scan run outside a git tree has no commit
    SHA, an all-local-binary scan has no container toolchain, and a scan with
    signing disabled has no attestation. Absent fields render as "not
    recorded" rather than implying a guarantee that wasn't made.
    """

    argus_version: str
    generated_at: str                       # ISO-8601 UTC, second precision
    commit_sha: str = ""
    repo_root: str = ""
    scan_file: str = ""
    # Scanner-toolchain provenance (from ScanSummary.toolchain / issue #240).
    toolchain_images: list[dict] = field(default_factory=list)
    toolchain_all_verified: Optional[bool] = None
    toolchain_warnings: list[str] = field(default_factory=list)
    # Attestation status discovered alongside the scan file:
    # "signed" | "unsigned" | "none".
    attestation: str = "none"

    @property
    def commit_short(self) -> str:
        return self.commit_sha[:12] if self.commit_sha else ""


@dataclass(frozen=True)
class ReportModel:
    """Everything the formal report template needs, fully precomputed."""

    title: str
    provenance: ReportProvenance
    total: int
    by_severity: dict[str, int]
    severity_threshold: Optional[str]
    passed: bool
    per_product: list[dict]
    per_scanner: list[dict]
    quality_warnings: list[str]
    severity_groups: list[SeverityGroup]

    @property
    def finding_count(self) -> int:
        return sum(g.count for g in self.severity_groups)


def _detect_attestation(scan_file: Optional[Path]) -> str:
    """Classify any attestation sitting next to the scan results.

    ``signed`` when a cosign bundle is present, ``unsigned`` when only the
    in-toto statement is, ``none`` otherwise. Pure filesystem existence
    checks — never reads or verifies the contents (verification is cosign's
    job, not the report's).
    """
    if scan_file is None:
        return "none"
    directory = scan_file.parent
    if (directory / _BUNDLE_FILENAME).is_file():
        return "signed"
    if (directory / _STATEMENT_FILENAME).is_file():
        return "unsigned"
    return "none"


def _group_by_severity(findings: list[Finding]) -> list[SeverityGroup]:
    """Bucket findings into severity groups in report order (CRITICAL first).

    Within a group, findings are ordered severity-then-id (stable) so repeat
    renders of the same scan produce byte-identical output — important for an
    artifact that may be diffed or hashed downstream.
    """
    groups: list[SeverityGroup] = []
    for severity in SEVERITY_ORDER:
        members = [f for f in findings if f.severity == severity]
        if not members:
            continue
        members.sort(key=lambda f: (f.id or "", f.location or ""))
        groups.append(SeverityGroup(severity=severity, findings=members))
    return groups


def build_report(
    summary: ScanSummary,
    findings: list[Finding],
    *,
    scan_file: str | Path | None = None,
    argus_version: Optional[str] = None,
    generated_at: Optional[datetime] = None,
    title: str = "Security Assessment Report",
) -> ReportModel:
    """Assemble a :class:`ReportModel` from a loaded scan.

    ``findings`` is the already-flattened finding list (the caller flattens
    once and shares it with the dashboard/charts). ``argus_version`` and
    ``generated_at`` are injectable so tests get deterministic output; they
    default to the live package version and current UTC time.
    """
    if argus_version is None:
        from argus import __version__ as argus_version  # local import: avoid cycle

    stamp = (generated_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    resolved_file = Path(scan_file) if scan_file else None

    context = summary.scan_context
    toolchain = summary.toolchain or {}

    provenance = ReportProvenance(
        argus_version=argus_version,
        generated_at=stamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
        commit_sha=(context.commit_sha if context else ""),
        repo_root=(context.repo_root if context else ""),
        scan_file=str(resolved_file) if resolved_file else "",
        toolchain_images=list(toolchain.get("images", [])),
        toolchain_all_verified=toolchain.get("argus_images_all_verified"),
        toolchain_warnings=list(toolchain.get("warnings", [])),
        attestation=_detect_attestation(resolved_file),
    )

    agg = compute_summary(findings, top_n=3)

    return ReportModel(
        title=title,
        provenance=provenance,
        total=agg["total"],
        by_severity=agg["by_severity"],
        severity_threshold=(
            summary.severity_threshold.value if summary.severity_threshold else None
        ),
        passed=summary.passed,
        per_product=agg["per_product"],
        per_scanner=agg["per_scanner"],
        quality_warnings=agg["quality_warnings"],
        severity_groups=_group_by_severity(findings),
    )
