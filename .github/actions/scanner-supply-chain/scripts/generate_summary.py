#!/usr/bin/env python3
"""Generate markdown summary for supply chain security scan results."""

import argparse
import json
from pathlib import Path


SEVERITY_EMOJI = {
    "HIGH": "⚠️",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "INFO": "ℹ️",
}


def _int_or_zero(value):
    """Convert string to int, defaulting to 0 for empty/invalid values."""
    if not value or value.strip() == "":
        return 0
    try:
        return int(value)
    except (ValueError, TypeError):
        return 0


def generate_summary(
    output_file,
    is_pr_comment,
    results_file,
    high,
    medium,
    low,
    info,
    github_server_url,
    github_repo,
    github_run_id,
):
    """Generate supply chain scan summary markdown."""
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    is_pr_comment = is_pr_comment == "true"

    high = _int_or_zero(high)
    medium = _int_or_zero(medium)
    low = _int_or_zero(low)
    info = _int_or_zero(info)
    total = high + medium + low + info

    findings = _load_findings(results_file)

    with open(output_path, "a", encoding="utf-8") as f:
        if is_pr_comment:
            f.write("<details>\n")
            f.write("<summary>🔗 Supply Chain Security Scan</summary>\n")
        else:
            f.write("## 🔗 Supply Chain Security Scan Summary\n")
        f.write("\n")

        if total == 0:
            f.write("**Status:** ✅ No findings\n")
            f.write("\n")
            f.write("No supply chain security issues detected in workflow files.\n")
        else:
            if is_pr_comment:
                f.write("**Status:** ⚠️ Findings detected\n")
                f.write("\n")

            f.write("### 📊 Severity Summary\n")
            f.write("\n")
            f.write("| ⚠️ High | 🟡 Medium | 🔵 Low | ℹ️ Info | Total |\n")
            f.write("|---------|-----------|--------|---------|-------|\n")
            f.write(f"| **{high}** | **{medium}** | **{low}** | **{info}** | **{total}** |\n")
            f.write("\n")

            if high > 0:
                f.write(f"⚠️ **HIGH**: {high} high severity findings require immediate attention\n")
                f.write("\n")

            if findings is None:
                f.write("⚠️ *Finding details could not be loaded. Check action logs.*\n")
                f.write("\n")
            elif findings:
                _write_finding_details(f, findings, total)

        artifacts_url = f"{github_server_url}/{github_repo}/actions/runs/{github_run_id}"
        f.write(f"📋 [View full report]({artifacts_url})\n")

        if is_pr_comment:
            f.write("\n")
            f.write("</details>\n")

        f.write("\n")


def _write_finding_details(f, findings, total):
    """Write findings grouped by severity in collapsible sections."""
    max_per_severity = 50
    f.write("<details>\n")
    f.write(f"<summary>🔍 Finding Details ({total})</summary>\n")
    f.write("\n")

    written = 0
    for severity in ["HIGH", "MEDIUM", "LOW", "INFO"]:
        severity_findings = [fi for fi in findings if fi.get("severity") == severity]
        if not severity_findings:
            continue

        open_tag = " open" if severity == "HIGH" else ""
        emoji = SEVERITY_EMOJI.get(severity, "❓")

        f.write(f"<details{open_tag}>\n")
        f.write(f"<summary>{emoji} {severity} Severity ({len(severity_findings)})</summary>\n")
        f.write("\n")
        f.write("| Rule | File | Line | Source | Description |\n")
        f.write("|------|------|------|--------|-------------|\n")

        displayed = severity_findings[:max_per_severity]
        written += len(displayed)
        for finding in displayed:
            rule = finding.get("rule", "unknown")
            file_path = finding.get("file", "")
            line = finding.get("line", 0)
            source = finding.get("source", "")
            desc = finding.get("description", "")[:80]
            f.write(f"| {rule} | {file_path} | {line} | {source} | {desc} |\n")

        f.write("\n")
        f.write("</details>\n")
        f.write("\n")

    remaining = len(findings) - written
    if remaining > 0:
        f.write(f"*... and {remaining} more findings. See full report in artifacts.*\n")
        f.write("\n")

    f.write("</details>\n")
    f.write("\n")


def _load_findings(results_file):
    """Load finding details from parse_results output.

    Returns [] for missing/empty files. Returns None if file exists but is
    corrupted, so callers can warn about missing details.
    """
    if not results_file or results_file.strip() == "":
        return []

    path = Path(results_file)
    if not path.exists() or path.stat().st_size == 0:
        return []

    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return None

    if isinstance(data, list):
        return data

    return None


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Generate supply chain scan summary markdown",
    )
    parser.add_argument("--output-file", required=True)
    parser.add_argument("--is-pr-comment", default="false")
    parser.add_argument("--results-file", default="")
    parser.add_argument("--high", default="0")
    parser.add_argument("--medium", default="0")
    parser.add_argument("--low", default="0")
    parser.add_argument("--info", default="0")
    parser.add_argument("--github-server-url", default="https://github.com")
    parser.add_argument("--github-repo", default="")
    parser.add_argument("--github-run-id", default="0")

    args = parser.parse_args()

    generate_summary(
        args.output_file,
        args.is_pr_comment,
        args.results_file,
        args.high,
        args.medium,
        args.low,
        args.info,
        args.github_server_url,
        args.github_repo,
        args.github_run_id,
    )


if __name__ == "__main__":
    main()
