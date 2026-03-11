#!/usr/bin/env python3
"""Parse OSV-Scanner JSON results into severity counts."""

import argparse
import json
import sys
from pathlib import Path


SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "MODERATE": "MEDIUM",
    "LOW": "LOW",
}


def validate_file(file_path):
    """Check if file exists and is not empty."""
    path = Path(file_path)
    return path.exists() and path.stat().st_size > 0


def load_json(file_path):
    """Load and parse JSON file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def resolve_severity(vuln):
    """Extract severity string from an OSV vulnerability record.

    Priority order:
    1. database_specific.severity (top-level) — most reliable for GHSA
    2. affected[0].database_specific.severity
    3. First CVSS_V3 score mapped to severity bucket
    4. Fallback to LOW
    """
    db_sev = (vuln.get("database_specific") or {}).get("severity")
    if db_sev and db_sev.upper() in SEVERITY_MAP:
        return SEVERITY_MAP[db_sev.upper()]

    affected = vuln.get("affected")
    if isinstance(affected, list):
        for aff in affected:
            aff_db_sev = (aff.get("database_specific") or {}).get("severity")
            if aff_db_sev and aff_db_sev.upper() in SEVERITY_MAP:
                return SEVERITY_MAP[aff_db_sev.upper()]

    severity_list = vuln.get("severity")
    if isinstance(severity_list, list):
        for sev in severity_list:
            if sev.get("type") == "CVSS_V3":
                score = _cvss_score_from_vector(sev.get("score", ""))
                if score is not None:
                    return _score_to_severity(score)

    return "LOW"


def _cvss_score_from_vector(vector):
    """Extract numeric base score from a CVSS v3 vector string.

    Parses the last metric group to approximate the base score.
    Returns None if the vector cannot be parsed.
    """
    if not vector or not vector.startswith("CVSS:3"):
        return None

    try:
        parts = vector.split("/")
        # Base score is not in the vector — compute from metrics
        # Use a simple heuristic: count high-impact metrics
        impact_metrics = {"C": 0, "I": 0, "A": 0}
        for part in parts[1:]:
            if ":" in part:
                key, val = part.split(":", 1)
                if key in impact_metrics:
                    if val == "H":
                        impact_metrics[key] = 3
                    elif val == "L":
                        impact_metrics[key] = 1

        av = next((p.split(":")[1] for p in parts[1:] if p.startswith("AV:")), "N")
        ac = next((p.split(":")[1] for p in parts[1:] if p.startswith("AC:")), "L")
        pr = next((p.split(":")[1] for p in parts[1:] if p.startswith("PR:")), "N")

        score = sum(impact_metrics.values())
        if av == "N":
            score += 2
        if ac == "L":
            score += 1
        if pr == "N":
            score += 1

        return min(score, 10.0)
    except (ValueError, StopIteration):
        return None


def _score_to_severity(score):
    """Map a CVSS numeric score to a severity label."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def get_counts(file_path):
    """Get vulnerability counts by severity from OSV JSON.

    Returns dict with keys: critical, high, medium, low, total.
    Deduplicates using the vulnerability 'id' field.
    """
    if not validate_file(file_path):
        return {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}

    data = load_json(file_path)
    if not data:
        return {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}

    seen_ids = set()
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    results = data.get("results")
    if not isinstance(results, list):
        return {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}

    for result in results:
        packages = result.get("packages")
        if not isinstance(packages, list):
            continue
        for pkg in packages:
            vulns = pkg.get("vulnerabilities")
            if not isinstance(vulns, list):
                continue
            for vuln in vulns:
                vuln_id = vuln.get("id", "")
                if vuln_id in seen_ids:
                    continue
                seen_ids.add(vuln_id)

                severity = resolve_severity(vuln)
                if severity in counts:
                    counts[severity] += 1

    total = sum(counts.values())
    return {
        "critical": counts["CRITICAL"],
        "high": counts["HIGH"],
        "medium": counts["MEDIUM"],
        "low": counts["LOW"],
        "total": total,
    }


def get_vulnerabilities(file_path):
    """Get detailed vulnerability list for summary generation.

    Returns list of dicts with keys: id, package, version, ecosystem,
    source, severity, summary, fixed_version, aliases.
    """
    if not validate_file(file_path):
        return []

    data = load_json(file_path)
    if not data:
        return []

    seen_ids = set()
    vulns_out = []

    results = data.get("results")
    if not isinstance(results, list):
        return []

    for result in results:
        source_path = (result.get("source") or {}).get("path", "unknown")
        packages = result.get("packages")
        if not isinstance(packages, list):
            continue
        for pkg_entry in packages:
            pkg_info = pkg_entry.get("package") or {}
            pkg_name = pkg_info.get("name", "unknown")
            pkg_version = pkg_info.get("version", "unknown")
            pkg_ecosystem = pkg_info.get("ecosystem", "unknown")

            vulns = pkg_entry.get("vulnerabilities")
            if not isinstance(vulns, list):
                continue
            for vuln in vulns:
                vuln_id = vuln.get("id", "")
                if vuln_id in seen_ids:
                    continue
                seen_ids.add(vuln_id)

                severity = resolve_severity(vuln)
                summary = vuln.get("summary", "No description available")
                aliases = vuln.get("aliases", [])

                fixed_version = _extract_fixed_version(vuln, pkg_ecosystem, pkg_name)

                vulns_out.append({
                    "id": vuln_id,
                    "package": pkg_name,
                    "version": pkg_version,
                    "ecosystem": pkg_ecosystem,
                    "source": source_path,
                    "severity": severity,
                    "summary": summary,
                    "fixed_version": fixed_version,
                    "aliases": aliases if isinstance(aliases, list) else [],
                })

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    vulns_out.sort(key=lambda v: severity_order.get(v["severity"], 4))

    return vulns_out


def _extract_fixed_version(vuln, ecosystem, pkg_name):
    """Extract the fixed version from the affected ranges."""
    affected = vuln.get("affected")
    if not isinstance(affected, list):
        return "N/A"

    for aff in affected:
        aff_pkg = aff.get("package") or {}
        if aff_pkg.get("name") != pkg_name:
            continue
        ranges = aff.get("ranges")
        if not isinstance(ranges, list):
            continue
        for rng in ranges:
            events = rng.get("events")
            if not isinstance(events, list):
                continue
            for event in events:
                fixed = event.get("fixed")
                if fixed:
                    return fixed

    return "N/A"


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Parse OSV-Scanner JSON results",
    )
    parser.add_argument("command", choices=["counts", "vulnerabilities"],
                        help="Command to execute")
    parser.add_argument("json_file", help="Path to OSV JSON results file")

    args = parser.parse_args()

    if args.command == "counts":
        counts = get_counts(args.json_file)
        print(f"{counts['critical']} {counts['high']} {counts['medium']} {counts['low']}")
    elif args.command == "vulnerabilities":
        vulns = get_vulnerabilities(args.json_file)
        print(json.dumps(vulns, indent=2))


if __name__ == "__main__":
    main()
