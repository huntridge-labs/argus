#!/usr/bin/env python3
"""Generate markdown summary for OpenGrep SAST scan results."""

import argparse
import json
import sys
from pathlib import Path


def generate_opengrep_summary(
    output_file,
    is_pr_comment,
    error_count,
    warning_count,
    info_count,
    total,
    repo_url,
    github_server_url,
    github_repo,
    github_run_id,
):
    """Generate OpenGrep summary markdown."""
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Convert string to boolean
    is_pr_comment = is_pr_comment == "true"

    with open(output_path, "a", encoding="utf-8") as f:
        # Header
        if is_pr_comment:
            f.write("<details>\n")
            f.write("<summary>🔍 OpenGrep SAST</summary>\n")
        else:
            f.write("## OpenGrep SAST Scan\n")
        f.write("\n")

        # Check if we have results
        total_int = int(total)
        has_results = total_int > 0 or Path("opengrep-reports").exists()

        if has_results:
            if is_pr_comment:
                f.write("**Status:** Completed\n")
                f.write("\n")

            # Summary table
            f.write("### Findings Summary\n")
            f.write("\n")
            f.write("| Error | Warning | Info | Total |\n")
            f.write("|-------|---------|------|-------|\n")
            f.write(f"| **{error_count}** | **{warning_count}** | **{info_count}** | **{total}** |\n")
            f.write("\n")

            # Priority messages
            error_int = int(error_count)
            warning_int = int(warning_count)

            if error_int > 0:
                f.write(f"**ERROR**: {error_count} error-severity findings need immediate attention\n")
                f.write("\n")
            if warning_int > 0:
                f.write(f"**WARNING**: {warning_count} warning-severity findings should be reviewed\n")
                f.write("\n")

            if total_int == 0:
                f.write("No security findings detected.\n")
                f.write("\n")

            # Detailed findings (parse JSON if available)
            if Path("opengrep-reports/opengrep.json").exists() and total_int > 0:
                f.write("<details>\n")
                f.write("<summary>Finding Details</summary>\n")
                f.write("\n")

                try:
                    with open("opengrep-reports/opengrep.json", "r", encoding="utf-8") as jf:
                        json_data = json.load(jf)

                    results = json_data.get("results", [])
                    if results:
                        f.write("| Severity | Rule | Location | Message |\n")
                        f.write("|----------|------|----------|----------|\n")

                        # Show first 20 findings
                        for result in results[:20]:
                            severity = result.get("extra", {}).get("severity", "INFO")
                            file_path = result.get("path", "N/A")
                            start_line = result.get("start", {}).get("line", 1)
                            end_line = result.get("end", {}).get("line", start_line)

                            # Extract rule name from check_id
                            check_id = result.get("check_id", "N/A")
                            rule = check_id.split(".")[-1] if check_id != "N/A" else "N/A"

                            # Extract message
                            message = result.get("extra", {}).get("message", "N/A")
                            if not message:
                                message = result.get("extra", {}).get("metadata", {}).get("message", "N/A")
                            message = message.replace("\n", " ")[:60]

                            location_link = f"[{file_path}#L{start_line}]({repo_url}/{file_path}#L{start_line}-L{end_line})"

                            f.write(f"| {severity} | {rule} | {location_link} | {message} |\n")

                        f.write("\n")

                        # Check if truncated
                        if len(results) > 20:
                            f.write(f"_Showing 20 of {total} findings. See artifacts for complete list._\n")
                            f.write("\n")
                except (json.JSONDecodeError, IOError, KeyError):
                    pass

                f.write("</details>\n")
                f.write("\n")

            # Artifacts link
            f.write(f"**Artifacts:** [OpenGrep Reports]({github_server_url}/{github_repo}/actions/runs/{github_run_id}#artifacts)\n")
        else:
            if is_pr_comment:
                f.write("**Status:** Skipped or No Results\n")
            else:
                f.write("**Status:** No OpenGrep results available\n")

        if is_pr_comment:
            f.write("\n")
            f.write("</details>\n")
        f.write("\n")


def main():
    parser = argparse.ArgumentParser(
        description="Generate markdown summary for OpenGrep SAST scan results"
    )
    parser.add_argument("output_file", help="Output markdown file path")
    parser.add_argument(
        "--is-pr-comment",
        default="false",
        help="Whether this is for a PR comment (default: false)",
    )
    parser.add_argument(
        "--error-count", default="0", help="Number of error-severity findings (default: 0)"
    )
    parser.add_argument(
        "--warning-count",
        default="0",
        help="Number of warning-severity findings (default: 0)",
    )
    parser.add_argument(
        "--info-count", default="0", help="Number of info-severity findings (default: 0)"
    )
    parser.add_argument(
        "--total", default="0", help="Total number of findings (default: 0)"
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

    generate_opengrep_summary(
        args.output_file,
        args.is_pr_comment,
        args.error_count,
        args.warning_count,
        args.info_count,
        args.total,
        args.repo_url,
        args.github_server_url,
        args.github_repo,
        args.github_run_id,
    )


if __name__ == "__main__":
    main()
