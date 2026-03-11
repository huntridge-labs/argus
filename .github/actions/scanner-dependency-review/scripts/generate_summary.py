#!/usr/bin/env python3
"""Generate markdown summary for dependency-review-action results."""

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


def generate_dependency_review_summary(
    output_file,
    is_pr_comment,
    skipped,
    critical,
    high,
    medium,
    low,
    license_violations,
    results_file,
    github_server_url,
    github_repo,
    github_run_id,
):
    """Generate dependency-review summary markdown."""
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    is_pr_comment = is_pr_comment == "true"
    skipped = skipped == "true"

    critical = _int_or_zero(critical)
    high = _int_or_zero(high)
    medium = _int_or_zero(medium)
    low = _int_or_zero(low)
    license_violations = _int_or_zero(license_violations)
    total = critical + high + medium + low

    vuln_details, license_details = _load_results(results_file)

    with open(output_path, "a", encoding="utf-8") as f:
        if is_pr_comment:
            f.write("<details>\n")
            f.write("<summary>🔗 Dependency Review</summary>\n")
        else:
            f.write("## 🔗 Dependency Review Summary\n")
        f.write("\n")

        if skipped:
            f.write("**Status:** ⏭️ Skipped (not a pull request event)\n")
            f.write("\n")
            f.write("Dependency Review requires a pull request context to compare dependency changes. ")
            f.write("Use `scanner-osv` for dependency scanning outside of PRs.\n")
        elif total == 0 and license_violations == 0:
            f.write("**Status:** ✅ No issues found\n")
            f.write("\n")
            f.write("No vulnerable or license-violating dependencies detected in this PR.\n")
        else:
            if is_pr_comment:
                f.write("**Status:** ⚠️ Issues found\n")
                f.write("\n")

            if total > 0:
                f.write("### 📊 Vulnerability Summary\n")
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

                if vuln_details:
                    f.write("### 🔍 Vulnerable Dependencies\n")
                    f.write("\n")
                    f.write("| Severity | Package | Version | Ecosystem | Advisory |\n")
                    f.write("|----------|---------|---------|-----------|----------|\n")
                    for vuln in vuln_details[:50]:
                        emoji = SEVERITY_EMOJI.get(vuln.get("severity", ""), "❓")
                        advisory_url = vuln.get("advisory_url", "")
                        advisory_id = vuln.get("advisory_id", "N/A")
                        link = f"[{advisory_id}]({advisory_url})" if advisory_url else advisory_id
                        f.write(
                            f"| {emoji} {vuln.get('severity', 'N/A')} "
                            f"| {vuln.get('package', 'N/A')} "
                            f"| {vuln.get('version', 'N/A')} "
                            f"| {vuln.get('ecosystem', 'N/A')} "
                            f"| {link} |\n"
                        )
                    f.write("\n")

            if license_violations > 0:
                f.write("### ⚖️ License Violations\n")
                f.write("\n")
                f.write(f"**{license_violations}** dependencies violate the license policy.\n")
                f.write("\n")

                if license_details:
                    f.write("| Package | Version | License | Ecosystem |\n")
                    f.write("|---------|---------|---------|----------|\n")
                    for lic in license_details[:20]:
                        f.write(
                            f"| {lic.get('package', 'N/A')} "
                            f"| {lic.get('version', 'N/A')} "
                            f"| {lic.get('license', 'N/A')} "
                            f"| {lic.get('ecosystem', 'N/A')} |\n"
                        )
                    f.write("\n")

        if not skipped:
            artifacts_url = f"{github_server_url}/{github_repo}/actions/runs/{github_run_id}"
            f.write(f"📋 [View full report]({artifacts_url})\n")

        if is_pr_comment:
            f.write("\n")
            f.write("</details>\n")

        f.write("\n")


def _load_results(results_file):
    """Load vulnerability and license details from results JSON."""
    if not results_file or results_file.strip() == "":
        return [], []

    path = Path(results_file)
    if not path.exists() or path.stat().st_size == 0:
        return [], []

    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return [], []

    if not isinstance(data, dict):
        return [], []

    vulns = data.get("vulnerabilities", [])
    license_info = data.get("license_violations", {})
    licenses = license_info.get("violations", []) if isinstance(license_info, dict) else []

    return vulns, licenses


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Generate dependency-review summary markdown",
    )
    parser.add_argument("--output-file", required=True)
    parser.add_argument("--is-pr-comment", default="false")
    parser.add_argument("--skipped", default="false")
    parser.add_argument("--critical", default="0")
    parser.add_argument("--high", default="0")
    parser.add_argument("--medium", default="0")
    parser.add_argument("--low", default="0")
    parser.add_argument("--license-violations", default="0")
    parser.add_argument("--results-file", default="")
    parser.add_argument("--github-server-url", default="https://github.com")
    parser.add_argument("--github-repo", default="")
    parser.add_argument("--github-run-id", default="0")

    args = parser.parse_args()

    generate_dependency_review_summary(
        args.output_file,
        args.is_pr_comment,
        args.skipped,
        args.critical,
        args.high,
        args.medium,
        args.low,
        args.license_violations,
        args.results_file,
        args.github_server_url,
        args.github_repo,
        args.github_run_id,
    )


if __name__ == "__main__":
    main()
