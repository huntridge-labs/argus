#!/usr/bin/env python3
"""Parse Grype container scan JSON results."""

import argparse
import json
import os
import sys
from pathlib import Path


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


def get_counts(file_path):
    """Get vulnerability counts by severity: 'crit high med low'."""
    if not validate_file(file_path):
        return "0 0 0 0"

    data = load_json(file_path)
    if not data:
        return "0 0 0 0"

    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}

    matches = data.get("matches", [])
    if not isinstance(matches, list):
        return "0 0 0 0"

    for match in matches:
        vulnerability = match.get("vulnerability", {})
        severity = vulnerability.get("severity", "Low")
        if severity in counts:
            counts[severity] += 1

    return f"{counts['Critical']} {counts['High']} {counts['Medium']} {counts['Low']}"


def get_total(file_path):
    """Get total vulnerability count."""
    if not validate_file(file_path):
        return "0"

    data = load_json(file_path)
    if not data:
        return "0"

    matches = data.get("matches", [])
    if not isinstance(matches, list):
        return "0"
    return str(len(matches))


def get_unique(file_path):
    """Get unique CVE count."""
    if not validate_file(file_path):
        return "0"

    data = load_json(file_path)
    if not data:
        return "0"

    cves = set()
    matches = data.get("matches", [])
    if not isinstance(matches, list):
        return "0"

    for match in matches:
        vulnerability = match.get("vulnerability", {})
        cve_id = vulnerability.get("id")
        if cve_id:
            cves.add(cve_id)

    return str(len(cves))


def get_unique_by_severity(file_path):
    """Get unique CVE counts by severity: 'crit high med low'."""
    if not validate_file(file_path):
        return "0 0 0 0"

    data = load_json(file_path)
    if not data:
        return "0 0 0 0"

    unique_cves = {"Critical": set(), "High": set(), "Medium": set(), "Low": set()}

    matches = data.get("matches", [])
    if not isinstance(matches, list):
        return "0 0 0 0"

    for match in matches:
        vulnerability = match.get("vulnerability", {})
        cve_id = vulnerability.get("id")
        severity = vulnerability.get("severity", "Low")
        if cve_id and severity in unique_cves:
            unique_cves[severity].add(cve_id)

    return f"{len(unique_cves['Critical'])} {len(unique_cves['High'])} {len(unique_cves['Medium'])} {len(unique_cves['Low'])}"


def get_cves(file_path):
    """Get all CVE IDs (one per line, unique)."""
    if not validate_file(file_path):
        return ""

    data = load_json(file_path)
    if not data:
        return ""

    cves = set()
    matches = data.get("matches", [])
    if not isinstance(matches, list):
        return ""

    for match in matches:
        vulnerability = match.get("vulnerability", {})
        cve_id = vulnerability.get("id")
        if cve_id:
            cves.add(cve_id)

    return "\n".join(sorted(cves))


def get_cves_by_severity(file_path, severity):
    """Get CVE IDs for a specific severity."""
    if not validate_file(file_path):
        return ""

    data = load_json(file_path)
    if not data:
        return ""

    cves = set()
    matches = data.get("matches", [])
    if not isinstance(matches, list):
        return ""

    for match in matches:
        vulnerability = match.get("vulnerability", {})
        if vulnerability.get("severity") == severity:
            cve_id = vulnerability.get("id")
            if cve_id:
                cves.add(cve_id)

    return "\n".join(sorted(cves))


def severity_sort_key(match):
    """Return sort key for vulnerability by severity (Critical first)."""
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    vuln = match.get("vulnerability", {})
    severity = vuln.get("severity", "Low")
    return severity_order.get(severity, 4)


def get_severity_emoji(severity):
    """Return emoji for severity level."""
    emojis = {
        "Critical": "🚨 CRITICAL",
        "High": "⚠️ HIGH",
        "Medium": "🟡 MEDIUM",
        "Low": "🔵 LOW",
    }
    return emojis.get(severity, "❓ UNKNOWN")


def get_table(file_path, limit=50):
    """Generate markdown table of vulnerabilities."""
    if not validate_file(file_path):
        return "| No data | - | - | - | - |"

    data = load_json(file_path)
    if not data:
        return "| No data | - | - | - | - |"

    matches = data.get("matches", [])
    if not isinstance(matches, list):
        return "| No data | - | - | - | - |"

    # Sort by severity
    matches_sorted = sorted(matches, key=severity_sort_key)

    # Limit to specified number
    matches_sorted = matches_sorted[:limit]

    if not matches_sorted:
        return "| No data | - | - | - | - |"

    lines = []
    for match in matches_sorted:
        vulnerability = match.get("vulnerability", {})
        artifact = match.get("artifact", {})

        cve_id = vulnerability.get("id", "N/A")
        severity = vulnerability.get("severity", "Low")
        pkg_name = artifact.get("name", "N/A")
        pkg_version = artifact.get("version", "N/A")

        # Get fixed version from vulnerability.fix.versions[0]
        fix_data = vulnerability.get("fix", {})
        fix_versions = fix_data.get("versions", [])
        fixed_version = fix_versions[0] if fix_versions else "N/A"

        severity_str = get_severity_emoji(severity)
        line = f"| {cve_id} | {severity_str} | {pkg_name} | {pkg_version} | {fixed_version} |"
        lines.append(line)

    return "\n".join(lines)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Parse Grype container scan JSON results",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  counts              - Output "crit high med low" counts
  total               - Output total vulnerability count
  unique              - Output unique CVE count
  unique-by-severity  - Output unique CVEs by severity: "crit high med low"
  cves                - Output all CVE IDs (one per line)
  cves-by-severity    - Output CVE IDs for a specific severity (requires -s)
  table               - Output markdown table of vulnerabilities

Options:
  -s, --severity SEV  - Filter by severity (Critical, High, Medium, Low)
  -l, --limit N       - Limit output rows (default: 50 for table)
        """,
    )

    parser.add_argument("command", nargs="?", help="Command to execute")
    parser.add_argument("json_file", nargs="?", help="Path to Grype JSON results file")
    parser.add_argument(
        "-s",
        "--severity",
        help="Filter by severity (Critical, High, Medium, Low)",
    )
    parser.add_argument(
        "-l",
        "--limit",
        type=int,
        default=50,
        help="Limit output rows (default: 50 for table)",
    )

    args = parser.parse_args()

    if not args.command or args.command in ("-h", "--help", "help"):
        parser.print_help()
        sys.exit(0)

    if not args.json_file:
        print("Error: json_file is required", file=sys.stderr)
        sys.exit(1)

    if args.command == "counts":
        print(get_counts(args.json_file))
    elif args.command == "total":
        print(get_total(args.json_file))
    elif args.command == "unique":
        print(get_unique(args.json_file))
    elif args.command == "unique-by-severity":
        print(get_unique_by_severity(args.json_file))
    elif args.command == "cves":
        output = get_cves(args.json_file)
        if output:
            print(output)
    elif args.command == "cves-by-severity":
        if not args.severity:
            print("Error: -s/--severity required for cves-by-severity", file=sys.stderr)
            sys.exit(1)
        output = get_cves_by_severity(args.json_file, args.severity)
        if output:
            print(output)
    elif args.command == "table":
        print(get_table(args.json_file, args.limit))
    else:
        print(f"Error: Unknown command '{args.command}'", file=sys.stderr)
        print("Run with --help for usage", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
