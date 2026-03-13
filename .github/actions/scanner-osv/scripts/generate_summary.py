#!/usr/bin/env python3
"""Generate markdown summary for OSV-Scanner dependency scan results."""

import argparse
import json
import sys
from pathlib import Path


SEVERITY_EMOJI = {
    "CRITICAL": "🚨",
    "HIGH": "⚠️",
    "MEDIUM": "🟡",
    "LOW": "🔵",
}


def _int_or_zero(value):
    """Convert string to int, defaulting to 0 for empty/invalid values."""
    if not value or value.strip() == "":
        return 0
    try:
        return int(value)
    except (ValueError, TypeError):
        return 0


def generate_osv_summary(
    output_file,
    is_pr_comment,
    results_file,
    critical,
    high,
    medium,
    low,
    github_server_url,
    github_repo,
    github_run_id,
):
    """Generate OSV-Scanner summary markdown."""
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    is_pr_comment = is_pr_comment == "true"

    critical = _int_or_zero(critical)
    high = _int_or_zero(high)
    medium = _int_or_zero(medium)
    low = _int_or_zero(low)
    total = critical + high + medium + low

    vulns = _load_vulnerabilities(results_file)

    with open(output_path, "a", encoding="utf-8") as f:
        if is_pr_comment:
            f.write("<details>\n")
            f.write("<summary>📦 OSV Dependency Scan</summary>\n")
        else:
            f.write("## 📦 OSV Dependency Scan Summary\n")
        f.write("\n")

        if total == 0:
            f.write("**Status:** ✅ No vulnerabilities found\n")
            f.write("\n")
            f.write("No known vulnerabilities detected in project dependencies.\n")
        else:
            if is_pr_comment:
                f.write("**Status:** ⚠️ Vulnerabilities found\n")
                f.write("\n")

            f.write("### 📊 Severity Summary\n")
            f.write("\n")
            f.write("| 🚨 Critical | ⚠️ High | 🟡 Medium | 🔵 Low | Total |\n")
            f.write("|-------------|---------|-----------|--------|-------|\n")
            f.write(f"| **{critical}** | **{high}** | **{medium}** | **{low}** | **{total}** |\n")
            f.write("\n")

            if critical > 0:
                f.write(f"🚨 **CRITICAL**: {critical} critical severity vulnerabilities require immediate attention\n")
                f.write("\n")
            elif high > 0:
                f.write(f"⚠️ **HIGH**: {high} high severity vulnerabilities should be addressed soon\n")
                f.write("\n")

            if vulns:
                f.write("<details>\n")
                f.write(f"<summary>🔍 Vulnerability Details ({total})</summary>\n")
                f.write("\n")

                _write_severity_grouped_vulns(f, vulns)

                if len(vulns) > 50:
                    f.write(f"*... and {len(vulns) - 50} more vulnerabilities. See full report in artifacts.*\n")
                    f.write("\n")

                f.write("</details>\n")
                f.write("\n")

        artifacts_url = f"{github_server_url}/{github_repo}/actions/runs/{github_run_id}"
        f.write(f"📋 [View full report]({artifacts_url})\n")

        if is_pr_comment:
            f.write("\n")
            f.write("</details>\n")

        f.write("\n")


def _write_severity_grouped_vulns(f, vulns):
    """Write vulnerabilities grouped by severity in collapsible sections."""
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        severity_vulns = [v for v in vulns if v.get("severity") == severity]
        if not severity_vulns:
            continue

        open_tag = " open" if severity == "CRITICAL" else ""
        emoji = SEVERITY_EMOJI.get(severity, "❓")

        f.write(f"<details{open_tag}>\n")
        f.write(f"<summary>{emoji} {severity} Severity ({len(severity_vulns)})</summary>\n")
        f.write("\n")
        f.write("| Package | Version | Fixed | ID | Summary |\n")
        f.write("|---------|---------|-------|----|---------|\n")

        for vuln in severity_vulns[:50]:
            fixed = vuln.get("fixed_version", "N/A")
            summary = vuln.get("summary", "")[:80]
            f.write(
                f"| {vuln['package']} "
                f"| {vuln['version']} "
                f"| {fixed} "
                f"| {vuln['id']} "
                f"| {summary} |\n"
            )

        f.write("\n")
        f.write("</details>\n")
        f.write("\n")


def _load_vulnerabilities(results_file):
    """Load vulnerability details from parse_results output or raw OSV JSON."""
    if not results_file or results_file.strip() == "":
        return []

    path = Path(results_file)
    if not path.exists() or path.stat().st_size == 0:
        return []

    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return []

    if isinstance(data, list):
        return data

    return []


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Generate OSV-Scanner summary markdown",
    )
    parser.add_argument("--output-file", required=True)
    parser.add_argument("--is-pr-comment", default="false")
    parser.add_argument("--results-file", default="")
    parser.add_argument("--critical", default="0")
    parser.add_argument("--high", default="0")
    parser.add_argument("--medium", default="0")
    parser.add_argument("--low", default="0")
    parser.add_argument("--github-server-url", default="https://github.com")
    parser.add_argument("--github-repo", default="")
    parser.add_argument("--github-run-id", default="0")

    args = parser.parse_args()

    generate_osv_summary(
        args.output_file,
        args.is_pr_comment,
        args.results_file,
        args.critical,
        args.high,
        args.medium,
        args.low,
        args.github_server_url,
        args.github_repo,
        args.github_run_id,
    )


if __name__ == "__main__":
    main()
