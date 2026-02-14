#!/usr/bin/env python3
"""Generate markdown summary for CodeQL SAST scan results."""

import argparse
import json
import sys
from pathlib import Path


def capitalize_language(language):
    """Capitalize first letter of language name."""
    if not language:
        return language
    return language[0].upper() + language[1:]


def generate_codeql_summary(
    output_file,
    is_pr_comment,
    language,
    critical,
    high,
    medium,
    low,
    total,
    repo_url,
    server_url,
    repository,
    run_id,
):
    """Generate CodeQL summary markdown."""
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Convert string to boolean
    is_pr_comment = is_pr_comment == "true"

    lang_display = capitalize_language(language)

    with open(output_path, "a", encoding="utf-8") as f:
        # Header
        if is_pr_comment:
            f.write("<details>\n")
            f.write(f"<summary>🔬 CodeQL SAST ({lang_display})</summary>\n")
        else:
            f.write(f"## 🔬 CodeQL SAST Scan ({lang_display})\n")
        f.write("\n")

        # Check if we have results
        total_int = int(total)
        sarif_dir = Path("codeql-reports/sarif")
        has_results = total_int > 0 or sarif_dir.exists()

        if has_results:
            if is_pr_comment:
                f.write("**Status:** Completed\n")
                f.write("\n")

            # Summary table
            f.write("### Findings Summary\n")
            f.write("\n")
            f.write("| Critical | High | Medium | Low | Total |\n")
            f.write("|----------|------|--------|-----|-------|\n")
            f.write(f"| **{critical}** | **{high}** | **{medium}** | **{low}** | **{total}** |\n")
            f.write("\n")

            # Priority messages
            critical_int = int(critical)
            high_int = int(high)

            if critical_int > 0:
                f.write(
                    f"**CRITICAL**: {critical} critical-severity findings (CVSS >= 9.0) need immediate attention\n"
                )
                f.write("\n")
            if high_int > 0:
                f.write(
                    f"**HIGH**: {high} high-severity findings (CVSS >= 7.0) should be addressed promptly\n"
                )
                f.write("\n")

            if total_int == 0:
                f.write(f"No security findings detected for {lang_display}.\n")
                f.write("\n")

            # Detailed findings (parse SARIF files if available)
            if sarif_dir.exists() and total_int > 0:
                sarif_files = list(sarif_dir.glob("*.sarif"))
                if sarif_files:
                    f.write("<details>\n")
                    f.write("<summary>Finding Details</summary>\n")
                    f.write("\n")

                    for sarif_file in sarif_files:
                        try:
                            with open(sarif_file, "r", encoding="utf-8") as jf:
                                sarif_data = json.load(jf)

                            findings_written = 0
                            for run in sarif_data.get("runs", []):
                                rules = {
                                    r.get("id"): r
                                    for r in run.get("tool", {}).get("driver", {}).get("rules", [])
                                }
                                results = run.get("results", [])

                                # Build header if findings exist
                                if results and findings_written == 0:
                                    f.write(
                                        "| Severity | Rule | Location | Message |\n"
                                    )
                                    f.write(
                                        "|----------|------|----------|----------|\n"
                                    )

                                # Write first 20 findings
                                for result in results[:20]:
                                    rule_id = result.get("ruleId", "N/A")
                                    rule = rules.get(rule_id, {})
                                    severity = rule.get("properties", {}).get(
                                        "security-severity", 0
                                    )

                                    try:
                                        severity = float(severity)
                                    except (ValueError, TypeError):
                                        severity = 0

                                    # Map severity to level
                                    if severity >= 9.0:
                                        level = "Critical"
                                    elif severity >= 7.0:
                                        level = "High"
                                    elif severity >= 4.0:
                                        level = "Medium"
                                    elif severity > 0:
                                        level = "Low"
                                    else:
                                        level = "Info"

                                    # Extract file and line
                                    locations = result.get("locations", [])
                                    if locations:
                                        physical_loc = locations[0].get(
                                            "physicalLocation", {}
                                        )
                                        artifact_loc = physical_loc.get(
                                            "artifactLocation", {}
                                        )
                                        file_path = artifact_loc.get("uri", "N/A")
                                        region = physical_loc.get("region", {})
                                        line = region.get("startLine", 1)
                                    else:
                                        file_path = "N/A"
                                        line = 1

                                    # Extract message
                                    message = result.get("message", {}).get("text", "N/A")
                                    message = message.replace("\n", " ")[:50]

                                    location_link = f"[{file_path}#L{line}]({repo_url}/{file_path}#L{line})"

                                    f.write(
                                        f"| {level} | {rule_id} | {location_link} | {message} |\n"
                                    )
                                    findings_written += 1

                                # Check if truncated
                                if len(results) > 20:
                                    f.write(
                                        f"_Showing 20 of {len(results)} findings. See artifacts for complete list._\n"
                                    )
                                    f.write("\n")

                        except (json.JSONDecodeError, IOError, KeyError):
                            pass

                    f.write("</details>\n")
                    f.write("\n")

            # Artifacts link
            f.write(
                f"**Artifacts:** [CodeQL Reports ({lang_display})]({server_url}/{repository}/actions/runs/{run_id}#artifacts)\n"
            )
        else:
            if is_pr_comment:
                f.write("**Status:** Skipped or No Results\n")
            else:
                f.write(f"**Status:** No CodeQL results available for {lang_display}\n")

        if is_pr_comment:
            f.write("\n")
            f.write("</details>\n")
        f.write("\n")


def main():
    parser = argparse.ArgumentParser(
        description="Generate markdown summary for CodeQL SAST scan results"
    )
    parser.add_argument("output_file", help="Output markdown file path")
    parser.add_argument(
        "--is-pr-comment",
        default="false",
        help="Whether this is for a PR comment (default: false)",
    )
    parser.add_argument(
        "--language", default="", help="Language analyzed (default: empty)"
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
        "--total", type=int, default=0, help="Total number of findings (default: 0)"
    )
    parser.add_argument(
        "--repo-url", default="", help="Repository URL (default: empty)"
    )
    parser.add_argument(
        "--server-url", default="https://github.com",
        help="GitHub server URL (default: https://github.com)",
    )
    parser.add_argument(
        "--repository", default="", help="GitHub repository (default: empty)"
    )
    parser.add_argument(
        "--run-id", default="", help="GitHub run ID (default: empty)"
    )

    args = parser.parse_args()

    if not args.output_file:
        print("Error: output file is required", file=sys.stderr)
        sys.exit(1)

    generate_codeql_summary(
        args.output_file,
        args.is_pr_comment,
        args.language,
        str(args.critical),
        str(args.high),
        str(args.medium),
        str(args.low),
        str(args.total),
        args.repo_url,
        args.server_url,
        args.repository,
        args.run_id,
    )


if __name__ == "__main__":
    main()
