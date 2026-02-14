#!/usr/bin/env python3
"""Generate markdown summary for Checkov IaC security scan results."""

import argparse
import json
import sys
from pathlib import Path


def generate_checkov_summary(
    output_file,
    is_pr_comment,
    has_iac,
    iac_path,
    critical,
    high,
    medium,
    low,
    passed,
    total,
    repo_url,
    github_server_url,
    github_repo,
    github_run_id,
):
    """Generate Checkov summary markdown."""
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Convert string to boolean
    is_pr_comment = is_pr_comment == "true"
    has_iac = has_iac == "true"

    with open(output_path, "a", encoding="utf-8") as f:
        # Header
        if is_pr_comment:
            f.write("<details>\n")
            f.write("<summary>🏗️ Checkov IaC Security</summary>\n")
        else:
            f.write("## 🏗️ Checkov IaC Security Scan Summary\n")
        f.write("\n")

        if has_iac:
            json_file = Path("checkov-reports/checkov-results.json")

            if json_file.exists():
                if is_pr_comment:
                    f.write("**Status:** ✅ Completed\n")
                    f.write("\n")

                # Read JSON and get framework info
                try:
                    with open(json_file, "r", encoding="utf-8") as jf:
                        json_data = json.load(jf)
                    check_type = json_data.get("check_type", "unknown")
                except (json.JSONDecodeError, IOError):
                    check_type = "unknown"

                # Overall Summary Table
                f.write("### 📊 Check Summary\n")
                f.write("\n")
                f.write(
                    "| 🚨 Critical | ⚠️ High | 🟡 Medium | 🔵 Low | ❌ Failed | ✅ Passed |\n"
                )
                f.write("|-------------|---------|-----------|--------|-----------|----------|\n")
                f.write(f"| **{critical}** | **{high}** | **{medium}** | **{low}** | **{total}** | **{passed}** |\n")
                f.write("\n")

                f.write(f"**Framework:** {check_type}\n")
                f.write("\n")

                # Priority messages
                total_int = int(total)
                critical_int = int(critical)
                high_int = int(high)

                if total_int > 0:
                    if critical_int > 0:
                        f.write(
                            f"🚨 **CRITICAL**: {critical} critical severity issues require immediate attention\n"
                        )
                        f.write("\n")
                    elif high_int > 0:
                        f.write(
                            f"⚠️ **HIGH**: {high} high severity issues need attention\n"
                        )
                        f.write("\n")
                    else:
                        f.write(f"❌ **FAILED**: {total} IaC security checks failed\n")
                        f.write("\n")

                # Detailed findings with collapsible sections
                if total_int > 0:
                    f.write("<details>\n")
                    f.write(f"<summary>🔍 Failed Check Details ({total})</summary>\n")
                    f.write("\n")

                    # Check if severity field is populated
                    has_severity = False
                    if json_file.exists():
                        try:
                            with open(json_file, "r", encoding="utf-8") as jf:
                                json_data = json.load(jf)
                            failed_checks = json_data.get("results", {}).get(
                                "failed_checks", []
                            )
                            if (
                                failed_checks
                                and "severity" in failed_checks[0]
                                and failed_checks[0]["severity"]
                            ):
                                has_severity = True
                        except (json.JSONDecodeError, IOError, KeyError):
                            pass

                    if has_severity:
                        _write_severity_grouped_checks(f, json_file, repo_url, iac_path)
                    else:
                        _write_ungrouped_checks(f, json_file, repo_url, iac_path)

                    f.write("</details>\n")
                    f.write("\n")
                elif total_int == 0 and int(passed) > 0:
                    f.write(f"✅ **All {passed} security checks passed!**\n")
                    f.write("\n")

                f.write(
                    f"**📁 Artifacts:** [Checkov Results]({github_server_url}/{github_repo}/actions/runs/{github_run_id}#artifacts)\n"
                )
            else:
                if is_pr_comment:
                    f.write("**Status:** ⚠️ No results generated\n")
                else:
                    f.write("**Status:** ⚠️ No Checkov results available\n")
        else:
            if is_pr_comment:
                f.write("**Status:** ⏭️ Skipped (no IaC directory found)\n")
            else:
                f.write(
                    f"**Status:** ⏭️ Skipped - no IaC directory found at '{iac_path}'\n"
                )

        if is_pr_comment:
            f.write("\n")
            f.write("</details>\n")
        f.write("\n")


def _write_severity_grouped_checks(f, json_file, repo_url, iac_path):
    """Write failed checks grouped by severity."""
    try:
        with open(json_file, "r", encoding="utf-8") as jf:
            json_data = json.load(jf)
        failed_checks = json_data.get("results", {}).get("failed_checks", [])
    except (json.JSONDecodeError, IOError):
        return

    # Group by severity
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        severity_checks = [
            c for c in failed_checks if c.get("severity") == severity
        ]
        if severity_checks:
            open_tag = " open" if severity == "CRITICAL" else ""
            severity_emoji = {
                "CRITICAL": "🚨",
                "HIGH": "⚠️",
                "MEDIUM": "🟡",
                "LOW": "🔵",
            }.get(severity, "")

            f.write(f"<details{open_tag}>\n")
            f.write(
                f"<summary>{severity_emoji} {severity} Severity ({len(severity_checks)})</summary>\n"
            )
            f.write("\n")
            f.write("| Check ID | Check Name | Resource | Location |\n")
            f.write("|----------|------------|----------|----------|\n")

            for check in severity_checks:
                check_id = check.get("check_id", "N/A")
                check_name = (check.get("check_name", "N/A")[:50]).ljust(50)
                resource = (check.get("resource", "N/A")[:40]).ljust(40)
                file_path = check.get("file_path", "N/A")

                # Remove leading slash
                if file_path.startswith("/"):
                    file_path = file_path[1:]

                # Add iac_path prefix if provided
                if iac_path:
                    file_path = f"{iac_path}/{file_path}"

                # Get line range
                file_line_range = check.get("file_line_range", [1, 1])
                start_line = file_line_range[0] if file_line_range else 1
                end_line = file_line_range[1] if len(file_line_range) > 1 else 1

                location_link = f"[{file_path}#L{start_line}-L{end_line}]({repo_url}/{file_path}#L{start_line}-L{end_line})"

                f.write(f"| {check_id} | {check_name} | {resource} | {location_link} |\n")

            f.write("\n")
            f.write("</details>\n")
            f.write("\n")


def _write_ungrouped_checks(f, json_file, repo_url, iac_path):
    """Write failed checks without severity grouping."""
    try:
        with open(json_file, "r", encoding="utf-8") as jf:
            json_data = json.load(jf)
        failed_checks = json_data.get("results", {}).get("failed_checks", [])
    except (json.JSONDecodeError, IOError):
        return

    if failed_checks:
        f.write("<details open>\n")
        f.write(
            f"<summary>⚠️ Failed Checks ({len(failed_checks)}) - Severity info unavailable</summary>\n"
        )
        f.write("\n")

    f.write("| Check ID | Check Name | Resource | Location |\n")
    f.write("|----------|------------|----------|----------|\n")

    for check in failed_checks:
        check_id = check.get("check_id", "N/A")
        check_name = (check.get("check_name", "N/A")[:50]).ljust(50)
        resource = (check.get("resource", "N/A")[:40]).ljust(40)
        file_path = check.get("file_path", "N/A")

        # Remove leading slash
        if file_path.startswith("/"):
            file_path = file_path[1:]

        # Add iac_path prefix if provided
        if iac_path:
            file_path = f"{iac_path}/{file_path}"

        # Get line range
        file_line_range = check.get("file_line_range", [1, 1])
        start_line = file_line_range[0] if file_line_range else 1
        end_line = file_line_range[1] if len(file_line_range) > 1 else 1

        location_link = f"[{file_path}#L{start_line}-L{end_line}]({repo_url}/{file_path}#L{start_line}-L{end_line})"

        f.write(f"| {check_id} | {check_name} | {resource} | {location_link} |\n")

    f.write("\n")

    if failed_checks:
        f.write("</details>\n")
        f.write("\n")


def main():
    parser = argparse.ArgumentParser(
        description="Generate markdown summary for Checkov IaC security scan results"
    )
    parser.add_argument("output_file", help="Output markdown file path")
    parser.add_argument(
        "--is-pr-comment",
        default="false",
        help="Whether this is for a PR comment (default: false)",
    )
    parser.add_argument(
        "--has-iac", default="false", help="Whether IaC directory was found (default: false)"
    )
    parser.add_argument(
        "--iac-path", default="", help="Path to IaC directory (default: empty)"
    )
    parser.add_argument(
        "--critical", type=int, default=0, help="Number of critical issues (default: 0)"
    )
    parser.add_argument(
        "--high", type=int, default=0, help="Number of high issues (default: 0)"
    )
    parser.add_argument(
        "--medium", type=int, default=0, help="Number of medium issues (default: 0)"
    )
    parser.add_argument(
        "--low", type=int, default=0, help="Number of low issues (default: 0)"
    )
    parser.add_argument(
        "--passed", type=int, default=0, help="Number of passed checks (default: 0)"
    )
    parser.add_argument(
        "--total", type=int, default=0, help="Total number of failed checks (default: 0)"
    )
    parser.add_argument(
        "--repo-url", default="", help="Repository URL (default: empty)"
    )
    parser.add_argument(
        "--github-server-url",
        default="https://github.com",
        help="GitHub server URL (default: https://github.com)",
    )
    parser.add_argument(
        "--github-repo", default="", help="GitHub repository (default: empty)"
    )
    parser.add_argument(
        "--github-run-id", default="", help="GitHub run ID (default: empty)"
    )

    args = parser.parse_args()

    if not args.output_file:
        print("Error: output file is required", file=sys.stderr)
        sys.exit(1)

    generate_checkov_summary(
        args.output_file,
        args.is_pr_comment,
        args.has_iac,
        args.iac_path,
        str(args.critical),
        str(args.high),
        str(args.medium),
        str(args.low),
        str(args.passed),
        str(args.total),
        args.repo_url,
        args.github_server_url,
        args.github_repo,
        args.github_run_id,
    )


if __name__ == "__main__":
    main()
