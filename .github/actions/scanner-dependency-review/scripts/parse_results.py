#!/usr/bin/env python3
"""Parse dependency-review-action outputs into severity counts."""

import argparse
import json
import sys
from pathlib import Path


SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "moderate": "MEDIUM",
    "medium": "MEDIUM",
    "low": "LOW",
}


def parse_vulnerable_changes(json_str):
    """Parse the vulnerable-changes JSON string into severity counts.

    Args:
        json_str: JSON string from dependency-review-action's vulnerable-changes output.

    Returns:
        dict with keys: critical, high, medium, low, total, vulnerabilities.
    """
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    vulns_out = []

    changes = _safe_parse_json(json_str)
    if not isinstance(changes, list):
        return _empty_counts()

    for change in changes:
        if not isinstance(change, dict):
            continue
        pkg_name = change.get("name", "unknown")
        pkg_version = change.get("version", "unknown")
        ecosystem = change.get("ecosystem", "unknown")
        manifest = change.get("manifest", "unknown")
        license_id = change.get("license", "")

        vulnerabilities = change.get("vulnerabilities")
        if not isinstance(vulnerabilities, list):
            continue

        for vuln in vulnerabilities:
            if not isinstance(vuln, dict):
                continue
            raw_severity = vuln.get("severity", "low")
            severity = SEVERITY_MAP.get(raw_severity.lower(), "LOW")
            if severity in counts:
                counts[severity] += 1

            vulns_out.append({
                "package": pkg_name,
                "version": pkg_version,
                "ecosystem": ecosystem,
                "manifest": manifest,
                "license": license_id,
                "severity": severity,
                "advisory_id": vuln.get("advisory_ghsa_id", ""),
                "advisory_summary": vuln.get("advisory_summary", ""),
                "advisory_url": vuln.get("advisory_url", ""),
            })

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    vulns_out.sort(key=lambda v: severity_order.get(v["severity"], 4))

    total = sum(counts.values())
    return {
        "critical": counts["CRITICAL"],
        "high": counts["HIGH"],
        "medium": counts["MEDIUM"],
        "low": counts["LOW"],
        "total": total,
        "vulnerabilities": vulns_out,
    }


def parse_license_changes(json_str):
    """Parse the invalid-license-changes JSON string.

    Returns:
        dict with keys: count, violations (list of dicts).
    """
    changes = _safe_parse_json(json_str)
    if not isinstance(changes, list):
        return {"count": 0, "violations": []}

    violations = []
    for change in changes:
        if not isinstance(change, dict):
            continue
        violations.append({
            "package": change.get("name", "unknown"),
            "version": change.get("version", "unknown"),
            "ecosystem": change.get("ecosystem", "unknown"),
            "manifest": change.get("manifest", "unknown"),
            "license": change.get("license", "unknown"),
        })

    return {"count": len(violations), "violations": violations}


def _safe_parse_json(json_str):
    """Safely parse a JSON string, returning None on failure."""
    if not json_str or json_str.strip() == "":
        return None
    try:
        return json.loads(json_str)
    except (json.JSONDecodeError, TypeError):
        return None


def _empty_counts():
    """Return empty counts dict."""
    return {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "total": 0,
        "vulnerabilities": [],
    }


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Parse dependency-review-action outputs",
    )
    parser.add_argument("command", choices=["counts", "licenses", "all"],
                        help="Command to execute")
    parser.add_argument("--vulnerable-changes", default="[]",
                        help="JSON string of vulnerable changes")
    parser.add_argument("--license-changes", default="[]",
                        help="JSON string of license violations")

    args = parser.parse_args()

    if args.command == "counts":
        result = parse_vulnerable_changes(args.vulnerable_changes)
        print(f"{result['critical']} {result['high']} {result['medium']} {result['low']}")
    elif args.command == "licenses":
        result = parse_license_changes(args.license_changes)
        print(json.dumps(result, indent=2))
    elif args.command == "all":
        vuln_result = parse_vulnerable_changes(args.vulnerable_changes)
        license_result = parse_license_changes(args.license_changes)
        combined = {
            "vulnerability_counts": {
                "critical": vuln_result["critical"],
                "high": vuln_result["high"],
                "medium": vuln_result["medium"],
                "low": vuln_result["low"],
                "total": vuln_result["total"],
            },
            "vulnerabilities": vuln_result["vulnerabilities"],
            "license_violations": license_result,
        }
        print(json.dumps(combined, indent=2))


if __name__ == "__main__":
    main()
