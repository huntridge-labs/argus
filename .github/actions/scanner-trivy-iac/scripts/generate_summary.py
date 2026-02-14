#!/usr/bin/env python3
"""Generate markdown summary for Trivy IaC security scan results."""

import argparse
import json
import sys
from pathlib import Path


def generate_trivy_iac_summary(
    output_file,
    is_pr_comment,
    has_iac,
    iac_path,
    repo_url,
    github_server_url,
    github_repo,
    github_run_id,
):
    """Generate Trivy IaC summary markdown."""
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Convert string to boolean
    is_pr_comment = is_pr_comment == "true"
    has_iac = has_iac == "true"

    with open(output_path, "a", encoding="utf-8") as f:
        # Header
        if is_pr_comment:
            f.write("<details>\n")
            f.write("<summary>🔍 Trivy IaC Scanner</summary>\n")
        else:
            f.write("## 🔍 Trivy IaC Scanner Summary\n")
        f.write("\n")

        if has_iac:
            json_file = Path(iac_path) / "security-reports" / "trivy-results.json"
            sarif_file = Path(iac_path) / "security-reports" / "trivy-results.sarif"

            if json_file.exists():
                if is_pr_comment:
                    f.write("**Status:** ✅ Completed\n")
                    f.write("\n")

                # Parse counts from JSON
                try:
                    with open(json_file, "r", encoding="utf-8") as jf:
                        json_data = json.load(jf)

                    # Count misconfigurations by severity
                    critical = 0
                    high = 0
                    medium = 0
                    low = 0

                    for result in json_data.get("Results", []):
                        for misc in result.get("Misconfigurations", []):
                            severity = misc.get("Severity", "")
                            if severity == "CRITICAL":
                                critical += 1
                            elif severity == "HIGH":
                                high += 1
                            elif severity == "MEDIUM":
                                medium += 1
                            elif severity == "LOW":
                                low += 1

                    total = critical + high + medium + low
                except (json.JSONDecodeError, IOError, KeyError):
                    critical = high = medium = low = total = 0

                # Summary table
                f.write("### 📊 Findings Summary\n")
                f.write("\n")
                f.write("| 🚨 Critical | ⚠️ High | 🟡 Medium | 🔵 Low | 📦 Total |\n")
                f.write("|-------------|---------|-----------|--------|----------|\n")
                f.write(f"| **{critical}** | **{high}** | **{medium}** | **{low}** | **{total}** |\n")
                f.write("\n")

                # Detailed findings with severity grouping
                if total > 0 and sarif_file.exists():
                    f.write("<details>\n")
                    f.write(f"<summary>🔍 Finding Details ({total})</summary>\n")
                    f.write("\n")

                    try:
                        with open(sarif_file, "r", encoding="utf-8") as sf:
                            sarif_data = json.load(sf)

                        # Process findings by severity
                        severity_labels = [
                            ("CRITICAL", "Critical", 9.0, 10.0),
                            ("HIGH", "High", 7.0, 9.0),
                            ("MEDIUM", "Medium", 4.0, 7.0),
                            ("LOW", "Low", 0, 4.0),
                        ]

                        for severity_key, severity_display, threshold_min, threshold_max in severity_labels:
                            findings_by_severity = []

                            for run in sarif_data.get("runs", []):
                                rules_dict = {}
                                for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
                                    rules_dict[rule.get("id")] = rule

                                for result in run.get("results", []):
                                    rule_id = result.get("ruleId", "N/A")
                                    rule = rules_dict.get(rule_id, {})
                                    sec_severity = float(
                                        rule.get("properties", {}).get("security-severity", 0)
                                    )

                                    if threshold_min <= sec_severity < threshold_max:
                                        findings_by_severity.append(result)

                            if findings_by_severity:
                                emoji = {
                                    "CRITICAL": "🚨",
                                    "HIGH": "⚠️",
                                    "MEDIUM": "🟡",
                                    "LOW": "🔵",
                                }.get(severity_key, "")

                                f.write("<details>\n")
                                f.write(f"<summary>{emoji} {severity_display} Severity ({len(findings_by_severity)})</summary>\n")
                                f.write("\n")
                                f.write("| Rule ID | Location | Message |\n")
                                f.write("|---------|----------|----------|\n")

                                for result in findings_by_severity:
                                    rule_id = result.get("ruleId", "N/A")
                                    locations = result.get("locations", [])
                                    if locations:
                                        physical_loc = locations[0].get("physicalLocation", {})
                                        artifact_loc = physical_loc.get("artifactLocation", {})
                                        file_path = artifact_loc.get("uri", "N/A")

                                        # Remove leading ./ or /
                                        if file_path.startswith("./"):
                                            file_path = file_path[2:]
                                        elif file_path.startswith("/"):
                                            file_path = file_path[1:]

                                        # Add iac_path prefix
                                        if iac_path and file_path != "N/A":
                                            file_path = f"{iac_path}/{file_path}"

                                        region = physical_loc.get("region", {})
                                        line = region.get("startLine", 1)
                                    else:
                                        file_path = "N/A"
                                        line = 1

                                    message = result.get("message", {}).get("text", "N/A")
                                    message = message.replace("\n", " ")[:100]

                                    location_link = f"[{file_path}#L{line}]({repo_url}/{file_path}#L{line})"

                                    f.write(f"| {rule_id} | {location_link} | {message} |\n")

                                f.write("\n")
                                f.write("</details>\n")
                                f.write("\n")
                    except (json.JSONDecodeError, IOError, KeyError):
                        pass

                    f.write("</details>\n")
                    f.write("\n")
                elif total == 0:
                    f.write("✅ **No misconfigurations detected!**\n")
                    f.write("\n")

                # Artifacts link
                if github_server_url and github_repo and github_run_id:
                    f.write(f"**📁 Artifacts:** [Trivy IaC Results]({github_server_url}/{github_repo}/actions/runs/{github_run_id}#artifacts)\n")
            else:
                if is_pr_comment:
                    f.write("**Status:** ⚠️ No results generated\n")
                else:
                    f.write("**Status:** ⚠️ No Trivy IaC results available\n")
        else:
            if is_pr_comment:
                f.write("**Status:** ⏭️ Skipped (no IaC directory found)\n")
            else:
                f.write("**Status:** ⏭️ No IaC directory found\n")

        if is_pr_comment:
            f.write("\n")
            f.write("</details>\n")
        f.write("\n")


def main():
    parser = argparse.ArgumentParser(
        description="Generate markdown summary for Trivy IaC security scan results"
    )
    parser.add_argument("output_file", help="Output markdown file path")
    parser.add_argument(
        "--is-pr-comment",
        default="false",
        help="Whether this is for a PR comment (default: false)",
    )
    parser.add_argument(
        "--has-iac",
        default="false",
        help="Whether IaC directory was found (default: false)",
    )
    parser.add_argument(
        "--iac-path", default="", help="Path to IaC directory (default: empty)"
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

    generate_trivy_iac_summary(
        args.output_file,
        args.is_pr_comment,
        args.has_iac,
        args.iac_path,
        args.repo_url,
        args.github_server_url,
        args.github_repo,
        args.github_run_id,
    )


if __name__ == "__main__":
    main()
