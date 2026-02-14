#!/usr/bin/env python3
"""Parse Trivy container scan JSON results."""

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

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    results = data.get("Results", [])
    if not isinstance(results, list):
        return "0 0 0 0"

    for result in results:
        vulnerabilities = result.get("Vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            continue
        for vuln in vulnerabilities:
            severity = vuln.get("Severity", "LOW")
            if severity in counts:
                counts[severity] += 1

    return f"{counts['CRITICAL']} {counts['HIGH']} {counts['MEDIUM']} {counts['LOW']}"


def get_total(file_path):
    """Get total vulnerability count."""
    if not validate_file(file_path):
        return "0"

    data = load_json(file_path)
    if not data:
        return "0"

    total = 0
    results = data.get("Results", [])
    if not isinstance(results, list):
        return "0"

    for result in results:
        vulnerabilities = result.get("Vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            continue
        total += len(vulnerabilities)

    return str(total)


def get_unique(file_path):
    """Get unique CVE count."""
    if not validate_file(file_path):
        return "0"

    data = load_json(file_path)
    if not data:
        return "0"

    cves = set()
    results = data.get("Results", [])
    if not isinstance(results, list):
        return "0"

    for result in results:
        vulnerabilities = result.get("Vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            continue
        for vuln in vulnerabilities:
            cve_id = vuln.get("VulnerabilityID")
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

    unique_cves = {"CRITICAL": set(), "HIGH": set(), "MEDIUM": set(), "LOW": set()}

    results = data.get("Results", [])
    if not isinstance(results, list):
        return "0 0 0 0"

    for result in results:
        vulnerabilities = result.get("Vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            continue
        for vuln in vulnerabilities:
            cve_id = vuln.get("VulnerabilityID")
            severity = vuln.get("Severity", "LOW")
            if cve_id and severity in unique_cves:
                unique_cves[severity].add(cve_id)

    return f"{len(unique_cves['CRITICAL'])} {len(unique_cves['HIGH'])} {len(unique_cves['MEDIUM'])} {len(unique_cves['LOW'])}"


def get_cves(file_path):
    """Get all CVE IDs (one per line, unique)."""
    if not validate_file(file_path):
        return ""

    data = load_json(file_path)
    if not data:
        return ""

    cves = set()
    results = data.get("Results", [])
    if not isinstance(results, list):
        return ""

    for result in results:
        vulnerabilities = result.get("Vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            continue
        for vuln in vulnerabilities:
            cve_id = vuln.get("VulnerabilityID")
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
    results = data.get("Results", [])
    if not isinstance(results, list):
        return ""

    for result in results:
        vulnerabilities = result.get("Vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            continue
        for vuln in vulnerabilities:
            if vuln.get("Severity") == severity:
                cve_id = vuln.get("VulnerabilityID")
                if cve_id:
                    cves.add(cve_id)

    return "\n".join(sorted(cves))


def severity_sort_key(vuln):
    """Return sort key for vulnerability by severity (CRITICAL first)."""
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    return severity_order.get(vuln.get("Severity", "LOW"), 4)


def get_severity_emoji(severity):
    """Return emoji for severity level."""
    emojis = {
        "CRITICAL": "🚨 CRITICAL",
        "HIGH": "⚠️ HIGH",
        "MEDIUM": "🟡 MEDIUM",
        "LOW": "🔵 LOW",
    }
    return emojis.get(severity, "❓ UNKNOWN")


def get_table(file_path, limit=50):
    """Generate markdown table of vulnerabilities."""
    if not validate_file(file_path):
        return "| No data | - | - | - | - |"

    data = load_json(file_path)
    if not data:
        return "| No data | - | - | - | - |"

    vulnerabilities = []
    results = data.get("Results", [])
    if not isinstance(results, list):
        return "| No data | - | - | - | - |"

    for result in results:
        vulns = result.get("Vulnerabilities", [])
        if not isinstance(vulns, list):
            continue
        vulnerabilities.extend(vulns)

    # Sort by severity
    vulnerabilities.sort(key=severity_sort_key)

    # Limit to specified number
    vulnerabilities = vulnerabilities[:limit]

    if not vulnerabilities:
        return "| No data | - | - | - | - |"

    lines = []
    for vuln in vulnerabilities:
        cve_id = vuln.get("VulnerabilityID", "N/A")
        severity = vuln.get("Severity", "LOW")
        pkg_name = vuln.get("PkgName", "N/A")
        installed_version = vuln.get("InstalledVersion", "N/A")
        fixed_version = vuln.get("FixedVersion", "N/A")

        severity_str = get_severity_emoji(severity)
        line = f"| {cve_id} | {severity_str} | {pkg_name} | {installed_version} | {fixed_version} |"
        lines.append(line)

    return "\n".join(lines)


def get_digest(file_path):
    """Get image digest from metadata."""
    if not validate_file(file_path):
        return "unknown"

    data = load_json(file_path)
    if not data:
        return "unknown"

    metadata = data.get("Metadata", {})

    # Try RepoDigests first, then ImageID
    repo_digests = metadata.get("RepoDigests", [])
    if repo_digests:
        digest = repo_digests[0]
    else:
        digest = metadata.get("ImageID", "unknown")

    if not digest:
        digest = "unknown"

    # Clean up - extract just the digest part
    digest = digest.replace("\n", "").replace("\r", "").replace("|", "")[:100]

    if "@" in digest:
        digest = digest.split("@")[1]

    return digest


def get_image_ref(file_path):
    """Get image:tag reference from metadata."""
    if not validate_file(file_path):
        return "unknown"

    data = load_json(file_path)
    if not data:
        return "unknown"

    metadata = data.get("Metadata", {})

    # Try RepoTags first, then RepoDigests
    repo_tags = metadata.get("RepoTags", [])
    if repo_tags:
        image_ref = repo_tags[0]
    else:
        repo_digests = metadata.get("RepoDigests", [])
        if repo_digests:
            image_ref = repo_digests[0]
        else:
            image_ref = "unknown"

    if not image_ref:
        image_ref = "unknown"

    # Clean up - remove digest if present
    image_ref = image_ref.replace("\n", "").replace("\r", "")
    if "@" in image_ref:
        image_ref = image_ref.split("@")[0]

    return image_ref


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Parse Trivy container scan JSON results",
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
  digest              - Output image digest from metadata
  image               - Output image:tag reference from metadata

Options:
  -s, --severity SEV  - Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)
  -l, --limit N       - Limit output rows (default: 50 for table)
        """,
    )

    parser.add_argument("command", nargs="?", help="Command to execute")
    parser.add_argument("json_file", nargs="?", help="Path to Trivy JSON results file")
    parser.add_argument(
        "-s",
        "--severity",
        help="Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)",
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
    elif args.command == "digest":
        print(get_digest(args.json_file))
    elif args.command == "image":
        print(get_image_ref(args.json_file))
    else:
        print(f"Error: Unknown command '{args.command}'", file=sys.stderr)
        print("Run with --help for usage", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
