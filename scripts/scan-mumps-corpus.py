#!/usr/bin/env python3
"""Scan a MUMPS corpus and report findings for at-scale validation.

The MUMPS scanner's precision is validated against large real corpora (e.g.
the VistA Kernel, YottaDB projects) rather than only the in-repo fixtures —
a small sample hides false positives that only appear on real code. This
harness makes that validation repeatable: point it at a directory of ``.m``
files and it prints per-rule and per-severity counts plus a dump of every
security finding (id, location, taint sources) so each can be hand-adjudicated
true-positive / false-positive against the source.

Usage:
    python scripts/scan-mumps-corpus.py <corpus-dir> [--profile security-only]
    python scripts/scan-mumps-corpus.py <corpus-dir> --json > report.json

Requires the compiled grammar (scripts/build-mumps-grammar.sh) or run inside
the scanner-mumps container.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter

from argus.scanners.mumps.scanner import MumpsScanner

SECURITY_IDS = {"M001", "M002", "M003", "M004", "M005", "M006", "M007"}


def run(path: str, profile: str | None) -> dict:
    config: dict = {}
    if profile:
        config["profile"] = profile
    start = time.time()
    result = MumpsScanner().scan(path, config)
    elapsed = round(time.time() - start, 2)
    findings = list(result.findings)
    security = [
        {
            "id": f.id,
            "severity": getattr(f.severity, "value", str(f.severity)),
            "location": f.location,
            "taint_sources": f.metadata.get("taint_sources"),
        }
        for f in findings
        if f.id in SECURITY_IDS
    ]
    return {
        "path": path,
        "elapsed_sec": elapsed,
        "files_scanned": result.metadata.get("files_scanned"),
        "suppressed": result.metadata.get("suppressed"),
        "total": len(findings),
        "by_rule": dict(sorted(Counter(f.id for f in findings).items())),
        "by_severity": dict(
            Counter(getattr(f.severity, "value", str(f.severity)) for f in findings)
        ),
        "security": security,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", help="directory of MUMPS .m sources")
    parser.add_argument(
        "--profile",
        choices=["security-only", "lint-only", "strict", "default"],
        help="rule profile (default: all on-by-default rules)",
    )
    parser.add_argument("--json", action="store_true", help="emit raw JSON")
    args = parser.parse_args()
    report = run(args.corpus, args.profile if args.profile != "default" else None)
    if args.json:
        json.dump(report, sys.stdout, indent=1)
        print()
        return 0
    print(
        f"{report['path']}  files={report['files_scanned']}  "
        f"time={report['elapsed_sec']}s  total={report['total']}  "
        f"security={len(report['security'])}  suppressed={report['suppressed']}"
    )
    print("  by-rule:    ", report["by_rule"])
    print("  by-severity:", report["by_severity"])
    if report["security"]:
        print("  security findings (adjudicate TP/FP against source):")
        for finding in report["security"]:
            print(
                f"    {finding['id']} {finding['severity'].upper():8} "
                f"{finding['location']}  taint={finding['taint_sources']}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
