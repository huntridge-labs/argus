"""Scan one built container image with the Argus SDK and emit the
per-image PR-comment artifacts (markdown section + flat JSON counts) plus
a combined SARIF for the GitHub Security tab.

Why this exists
---------------
``build-containers.yml`` used to build its PR comment from an inline
heredoc that parsed **only** Trivy's JSON output and constructed a
``ContainerScanResult`` with ``combined_findings=trivy_findings`` and no
``grype_findings``. Because ``ContainerScanResult.grype_findings``
defaults to ``[]``, the container markdown reporter rendered
"✅ No vulnerabilities detected by Grype" for *every* image regardless of
what Grype actually found — a false negative — while the separate
``anchore/scan-action`` step still emitted its "failed minimum severity
level" annotation. The Trivy-only ``combined_findings`` also under-counted
the summary table by dropping every Grype-only CVE.

This script dogfoods the SDK's own :func:`argus.container.scan_image` —
the exact entrypoint ``ContainerEngine.run`` uses — so both Trivy and
Grype run and are deduplicated by CVE via
:func:`argus.container.deduplicate_findings`. The rendered section,
severity counts, and SARIF therefore all reflect the union of both
scanners.

Usage
-----
    python -m scripts.ci.render_container_summary \
        --image-name cli \
        --image-ref ghcr.io/huntridge-labs/argus/cli:<sha> \
        --out-dir scanner-summaries \
        --sarif-dir sarif-out
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from argus.container import ContainerTarget, scan_image
from argus.container.scanner import ContainerScanResult
from argus.reporters import get_reporter
from argus.reporters.container_markdown import ContainerMarkdownReporter

# Sub-scanners the PR comment reports on. Deliberately CVE-only
# (Trivy + Grype) to match the two subsections the container markdown
# reporter renders; the attack-surface sub-scanners (exposure, services)
# and SBOM generation aren't part of this image-vuln summary.
_SCANNERS: tuple[str, ...] = ("trivy", "grype")


def build_count_summary(result: ContainerScanResult) -> dict:
    """Build the flat per-image counts dict the combine step consumes.

    Keys mirror what ``build-containers.yml``'s combine step reads back
    (``name``, ``image_ref``, ``critical``/``high``/``medium``/``low``,
    ``build_success``); ``total``/``unique`` are included for parity with
    the SDK's own ``container-scan.json``. Counts derive from
    ``combined_findings``, so Grype-only CVEs are included — the exact
    gap this script closes.
    """
    return {
        "name": result.name,
        "image_ref": result.image_ref,
        "build_success": result.build_success,
        "critical": result.critical_count,
        "high": result.high_count,
        "medium": result.medium_count,
        "low": result.low_count,
        "total": result.total_count,
        "unique": result.unique_count,
    }


def write_pr_comment_artifacts(result: ContainerScanResult, out_dir: Path) -> None:
    """Write the per-image markdown section and flat JSON counts.

    The markdown section is produced by the SDK's own
    ``ContainerMarkdownReporter.report_single`` (bare ``<details>`` block,
    no outer wrapper) so the downstream combine step can concatenate it
    unchanged.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    ContainerMarkdownReporter().report_single(result, out_dir)
    (out_dir / f"{result.name}.json").write_text(
        json.dumps(build_count_summary(result), indent=2),
        encoding="utf-8",
    )


def write_sarif(result: ContainerScanResult, sarif_dir: Path) -> Path:
    """Write a combined (Trivy + Grype) SARIF for the GitHub Security tab.

    Wraps the deduplicated findings in a canonical ``ScanSummary`` and
    hands it to the standard SARIF reporter — the same shape the CLI's
    container-scan path emits. Uploading this (rather than a Trivy-only
    SARIF) means Grype-only CVEs also reach the Security tab.
    """
    from argus.core.models import ScanContext, ScanResult, ScanSummary

    sarif_dir.mkdir(parents=True, exist_ok=True)
    canonical = ScanSummary(
        results=[
            ScanResult(
                scanner=f"container/{result.name}",
                findings=list(result.combined_findings),
                metadata={"image_ref": result.image_ref},
            )
        ],
        scan_context=ScanContext.capture(),
    )
    return get_reporter("sarif").report(canonical, sarif_dir)


def run(
    image_name: str,
    image_ref: str,
    out_dir: Path,
    sarif_dir: Path | None = None,
) -> ContainerScanResult:
    """Scan ``image_ref`` via the SDK and write the CI artifacts.

    The image is already built and ``docker load``-ed into the local
    daemon by an earlier job, so the target carries no Dockerfile —
    ``scan_image`` detects it as a local image and scans it through the
    docker-daemon source.
    """
    target = ContainerTarget(name=image_name, image_ref=image_ref)
    result = scan_image(target, scanners=_SCANNERS, sbom=False)

    write_pr_comment_artifacts(result, out_dir)
    if sarif_dir is not None:
        write_sarif(result, sarif_dir)

    if result.scanner_errors:
        # Surface (don't swallow) sub-scanner failures — a Grype crash
        # must not masquerade as "0 findings" the way the old Trivy-only
        # path did. Non-zero exit lets the workflow decide how to gate.
        for tool, err in result.scanner_errors.items():
            print(f"::warning::{tool} sub-scanner error for {image_name}: {err}", file=sys.stderr)

    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Scan a built container image with the Argus SDK and "
        "render PR-comment + SARIF artifacts.",
    )
    parser.add_argument("--image-name", required=True, help="Short image name (matrix key).")
    parser.add_argument("--image-ref", required=True, help="Full image reference to scan.")
    parser.add_argument(
        "--out-dir",
        default="scanner-summaries",
        help="Directory for the per-image markdown section + JSON counts.",
    )
    parser.add_argument(
        "--sarif-dir",
        default=None,
        help="Directory for the combined SARIF (omit to skip SARIF output).",
    )
    args = parser.parse_args(argv)

    result = run(
        image_name=args.image_name,
        image_ref=args.image_ref,
        out_dir=Path(args.out_dir),
        sarif_dir=Path(args.sarif_dir) if args.sarif_dir else None,
    )

    # A sub-scanner failure means the summary is incomplete — exit
    # non-zero so the caller can gate rather than silently trusting a
    # partial result.
    return 1 if result.scanner_errors else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
