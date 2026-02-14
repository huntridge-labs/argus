#!/usr/bin/env python3
"""Generate container security summary from scan results."""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, Set, Tuple


def find_scan_results():
    """Find all scan result files recursively, regardless of directory nesting.

    Discovers trivy/grype results by searching for files matching the naming
    convention {scanner}-{container_name}-results.json. This handles any
    artifact directory layout:
      - Flat: container-scan-results-{name}/{scanner}-{name}-results.json
      - Nested: container-scan-results-{name}-{scanner}-{job-id}/
                  container-scan-results-{name}/{scanner}-{name}-results.json

    Returns dict mapping container names to their scan file paths:
      { "oris-kaci": {"trivy": Path, "grype": Path, "status": Path} }
    """
    containers = {}

    # Recursively find all scanner result JSON files
    for json_file in Path(".").rglob("*-results.json"):
        filename = json_file.name
        for scanner in ("trivy", "grype"):
            prefix = f"{scanner}-"
            suffix = "-results.json"
            if filename.startswith(prefix) and filename.endswith(suffix):
                container_name = filename[len(prefix):-len(suffix)]
                if container_name not in containers:
                    containers[container_name] = {
                        "trivy": None,
                        "grype": None,
                        "status": None,
                    }
                containers[container_name][scanner] = json_file

                # Check for scan-status.json in the same directory
                status = json_file.parent / "scan-status.json"
                if status.exists():
                    containers[container_name]["status"] = status

    # Also check for containers that only have a scan-status.json (build failures)
    for status_file in Path(".").rglob("scan-status.json"):
        # Derive container name from parent directory
        parent_name = status_file.parent.name
        if parent_name.startswith("container-scan-results-"):
            container_name = parent_name.replace("container-scan-results-", "")
            if container_name not in containers:
                containers[container_name] = {
                    "trivy": None,
                    "grype": None,
                    "status": status_file,
                }

    return containers


def run_parser(parser_path: str, command: str, json_file: Path, *args):
    """Run a parser script and return output."""
    if not json_file or not json_file.exists():
        return None

    cmd = [sys.executable, parser_path, command, str(json_file)]
    cmd.extend(args)

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return None


def parse_counts(output: str) -> Tuple[int, int, int, int]:
    """Parse 'crit high med low' output into tuple."""
    if not output:
        return (0, 0, 0, 0)
    parts = output.split()
    try:
        return (int(parts[0]), int(parts[1]), int(parts[2]), int(parts[3]))
    except (IndexError, ValueError):
        return (0, 0, 0, 0)


def combine_cves(*cve_lists: str) -> Set[str]:
    """Combine multiple CVE lists and deduplicate."""
    combined = set()
    for cve_list in cve_lists:
        if cve_list:
            for line in cve_list.split('\n'):
                line = line.strip()
                if line:
                    combined.add(line)
    return combined


def process_container(
    trivy_parser: str,
    grype_parser: str,
    container_name: str,
    scan_files: Dict,
) -> Tuple[dict, int]:
    """Process a single container and return data dict and failure count."""
    trivy_file = scan_files["trivy"]
    grype_file = scan_files["grype"]
    status_file = scan_files["status"]

    # Check for failure status
    if status_file:
        try:
            with open(status_file, 'r') as f:
                status = json.load(f)
                error_msg = status.get("error", "Scan failed")
                return {
                    "name": container_name,
                    "status": "failed",
                    "error": error_msg,
                }, 1
        except Exception:
            pass

    # Get Trivy data
    t_crit, t_high, t_med, t_low = 0, 0, 0, 0
    t_total, t_unique = 0, 0
    trivy_cves = ""
    trivy_crit_cves = ""
    trivy_high_cves = ""
    trivy_med_cves = ""
    trivy_low_cves = ""

    if trivy_file:
        counts = run_parser(trivy_parser, "counts", trivy_file)
        t_crit, t_high, t_med, t_low = parse_counts(counts)

        total = run_parser(trivy_parser, "total", trivy_file)
        t_total = int(total) if total else 0

        unique = run_parser(trivy_parser, "unique", trivy_file)
        t_unique = int(unique) if unique else 0

        trivy_cves = run_parser(trivy_parser, "cves", trivy_file) or ""
        trivy_crit_cves = run_parser(trivy_parser, "cves-by-severity", trivy_file, "-s", "CRITICAL") or ""
        trivy_high_cves = run_parser(trivy_parser, "cves-by-severity", trivy_file, "-s", "HIGH") or ""
        trivy_med_cves = run_parser(trivy_parser, "cves-by-severity", trivy_file, "-s", "MEDIUM") or ""
        trivy_low_cves = run_parser(trivy_parser, "cves-by-severity", trivy_file, "-s", "LOW") or ""

    # Get Grype data
    g_crit, g_high, g_med, g_low = 0, 0, 0, 0
    g_total, g_unique = 0, 0
    grype_cves = ""
    grype_crit_cves = ""
    grype_high_cves = ""
    grype_med_cves = ""
    grype_low_cves = ""

    if grype_file:
        counts = run_parser(grype_parser, "counts", grype_file)
        g_crit, g_high, g_med, g_low = parse_counts(counts)

        total = run_parser(grype_parser, "total", grype_file)
        g_total = int(total) if total else 0

        unique = run_parser(grype_parser, "unique", grype_file)
        g_unique = int(unique) if unique else 0

        grype_cves = run_parser(grype_parser, "cves", grype_file) or ""
        grype_crit_cves = run_parser(grype_parser, "cves-by-severity", grype_file, "-s", "Critical") or ""
        grype_high_cves = run_parser(grype_parser, "cves-by-severity", grype_file, "-s", "High") or ""
        grype_med_cves = run_parser(grype_parser, "cves-by-severity", grype_file, "-s", "Medium") or ""
        grype_low_cves = run_parser(grype_parser, "cves-by-severity", grype_file, "-s", "Low") or ""

    # Combine and deduplicate CVEs by severity
    combined_crit = combine_cves(trivy_crit_cves, grype_crit_cves)
    combined_high = combine_cves(trivy_high_cves, grype_high_cves)
    combined_med = combine_cves(trivy_med_cves, grype_med_cves)
    combined_low = combine_cves(trivy_low_cves, grype_low_cves)

    combined_total_cves = combine_cves(trivy_cves, grype_cves)

    crit = len(combined_crit)
    high = len(combined_high)
    med = len(combined_med)
    low = len(combined_low)
    total = crit + high + med + low
    combined_unique = len(combined_total_cves)

    # Get image metadata
    digest = "unknown"
    image_ref = "unknown"
    if trivy_file:
        digest = run_parser(trivy_parser, "digest", trivy_file) or "unknown"
        image_ref = run_parser(trivy_parser, "image", trivy_file) or "unknown"

    return {
        "name": container_name,
        "digest": digest,
        "image_ref": image_ref,
        "crit": crit,
        "high": high,
        "med": med,
        "low": low,
        "total": total,
        "combined_unique": combined_unique,
        "t_total": t_total,
        "t_unique": t_unique,
        "g_total": g_total,
        "g_unique": g_unique,
        "status": "success",
        "trivy_file": trivy_file,
        "grype_file": grype_file,
    }, 0


def generate_summary(
    trivy_parser: str,
    grype_parser: str,
    combined: bool = False,
) -> None:
    """Generate container security summary."""
    Path("scanner-summaries").mkdir(exist_ok=True)

    containers = find_scan_results()

    if not containers:
        # No scan results found
        print("⏭️ No container scan results found")
        with open("scanner-summaries/container.md", "w") as f:
            f.write("<details><summary>🐳 Container Security</summary>\n")
            f.write("\n**Status:** ⏭️ Skipped\n\n</details>\n")

        step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if step_summary:
            with open(step_summary, "a") as f:
                f.write("## 🐳 Container Security Scan Summary\n\n")
                f.write("**Status:** ⏭️ No containers found\n")

        github_output = os.environ.get("GITHUB_OUTPUT")
        if github_output:
            with open(github_output, "a") as f:
                f.write("total_vulns=0\n")
                f.write("critical=0\n")
                f.write("high=0\n")
                f.write("containers_scanned=0\n")

        return

    print("📊 Generating container security summary...")

    # Process each container
    scanned = 0
    failed = 0
    total_crit = 0
    total_high = 0
    total_med = 0
    total_low = 0
    all_cves = set()
    container_data = []

    for container_name, scan_files in sorted(containers.items()):
        print(f"  Processing: {container_name}")
        data, is_failed = process_container(trivy_parser, grype_parser, container_name, scan_files)

        container_data.append(data)
        if is_failed:
            failed += 1
        else:
            scanned += 1
            total_crit += data["crit"]
            total_high += data["high"]
            total_med += data["med"]
            total_low += data["low"]

            # Collect all CVEs
            if scan_files["trivy"]:
                cves = run_parser(trivy_parser, "cves", scan_files["trivy"])
                if cves:
                    for line in cves.split('\n'):
                        line = line.strip()
                        if line:
                            all_cves.add(line)

            if scan_files["grype"]:
                cves = run_parser(grype_parser, "cves", scan_files["grype"])
                if cves:
                    for line in cves.split('\n'):
                        line = line.strip()
                        if line:
                            all_cves.add(line)

            status = "✅" if data["status"] == "success" else "❌"
            print(f"    {status} {container_name}: {data['total']} vulns "
                  f"({data['crit']} crit, {data['high']} high, "
                  f"{data['med']} med, {data['low']} low)")

    total_vulns = total_crit + total_high + total_med + total_low
    unique_cves = len(all_cves)

    # Write outputs
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a") as f:
            f.write(f"total_vulns={unique_cves}\n")
            f.write(f"critical={total_crit}\n")
            f.write(f"high={total_high}\n")
            f.write(f"containers_scanned={scanned}\n")

    # Generate markdown summary
    output_files = ["scanner-summaries/container.md"]
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        output_files.append(step_summary)

    for output_file in output_files:
        with open(output_file, "a") as f:
            # Header
            if output_file.endswith("container.md"):
                if combined:
                    f.write("<details><summary>🐳 Container Security (Parallel Scan)</summary>\n")
                else:
                    f.write("<details><summary>🐳 Container Security</summary>\n")
                f.write("\n**Status:** ✅ Completed\n\n")
            else:
                if combined:
                    f.write("## 🐳 Container Security Scan Summary (Parallel)\n\n")
                else:
                    f.write("## 🐳 Container Security Scan Summary\n\n")

            # Summary table
            f.write("### 📊 Combined Findings Summary\n\n")
            f.write("| 🚨 Critical | ⚠️ High | 🟡 Medium | 🔵 Low | 📦 Total | 🔢 Unique |\n")
            f.write("|-------------|---------|-----------|---------|----------|----------|\n")
            f.write(f"| **{total_crit}** | **{total_high}** | **{total_med}** | **{total_low}** | **{total_vulns}** | **{unique_cves}** |\n\n")
            f.write(f"**Scanned:** {scanned} containers | **Build Failures:** {failed}\n\n")

            # Container breakdown (only for multiple containers)
            if scanned > 1 or failed > 0:
                f.write("### 📦 Container Breakdown\n\n")
                f.write("| Container | Image | 🚨 Crit | ⚠️ High | 🟡 Med | 🔵 Low | Total | Unique | Status |\n")
                f.write("|-----------|-------|---------|---------|--------|--------|-------|--------|--------|\n")

                for data in container_data:
                    if data["status"] == "failed":
                        f.write(f"| {data['name']} | - | - | - | - | - | - | - | ❌ {data.get('error', 'Failed')} |\n")
                    else:
                        f.write(f"| {data['name']} | `{data['image_ref']}` | {data['crit']} | {data['high']} | {data['med']} | {data['low']} | {data['total']} | {data['combined_unique']} | ✅ |\n")
                f.write("\n")

            # Detailed findings
            f.write("### 🔍 Detailed Findings by Container\n\n")

            for data in container_data:
                if data["status"] == "failed":
                    f.write(f"<details>\n")
                    f.write(f"<summary>❌ <strong>{data['name']}</strong> - Build Failed</summary>\n\n")
                    f.write(f"**Status:** {data.get('error', 'Build failed')}\n\n")
                    f.write("</details>\n\n")
                else:
                    # Determine emoji
                    if data["crit"] > 0:
                        emoji = "🚨"
                    elif data["high"] > 0:
                        emoji = "⚠️"
                    elif data["total"] > 0:
                        emoji = "🟡"
                    else:
                        emoji = "✅"

                    f.write(f"<details>\n")
                    f.write(f"<summary>{emoji} <strong>{data['name']}</strong> - {data['total']} vulnerabilities ({data['combined_unique']} unique)</summary>\n\n")
                    f.write(f"**Image:** `{data['image_ref']}`\n")
                    f.write(f"**Digest:** `@{data['digest']}`\n\n")
                    f.write("#### Combined (Deduplicated)\n\n")
                    f.write("| 🚨 Critical | ⚠️ High | 🟡 Medium | 🔵 Low | Total | Unique |\n")
                    f.write("|-------------|---------|-----------|---------|-------|--------|\n")
                    f.write(f"| {data['crit']} | {data['high']} | {data['med']} | {data['low']} | {data['total']} | {data['combined_unique']} |\n\n")

                    # Trivy section
                    if data["trivy_file"]:
                        f.write(f"<details open>\n")
                        f.write(f"<summary>🔷 Trivy Scanner ({data['t_total']} findings, {data['t_unique']} unique)</summary>\n\n")

                        if data["t_total"] == 0:
                            f.write("✅ No vulnerabilities detected by Trivy\n")
                        else:
                            f.write("| CVE | Severity | Package | Version | Fixed |\n")
                            f.write("|-----|----------|---------|---------|-------|\n")
                            table = run_parser(trivy_parser, "table", data["trivy_file"], "-l", "50")
                            if table:
                                f.write(f"{table}\n")
                            if data["t_total"] > 50:
                                f.write(f"\n_...and {data['t_total'] - 50} more_\n")

                        f.write("\n</details>\n\n")

                    # Grype section
                    if data["grype_file"]:
                        f.write(f"<details open>\n")
                        f.write(f"<summary>⚓ Grype Scanner ({data['g_total']} findings, {data['g_unique']} unique)</summary>\n\n")

                        if data["g_total"] == 0:
                            f.write("✅ No vulnerabilities detected by Grype\n")
                        else:
                            f.write("| CVE | Severity | Package | Version | Fixed |\n")
                            f.write("|-----|----------|---------|---------|-------|\n")
                            table = run_parser(grype_parser, "table", data["grype_file"], "-l", "50")
                            if table:
                                f.write(f"{table}\n")
                            if data["g_total"] > 50:
                                f.write(f"\n_...and {data['g_total'] - 50} more_\n")

                        f.write("\n</details>\n\n")

                    f.write("</details>\n\n")

        # Add artifact link (only for main summary)
        if output_file.endswith("container.md"):
            repo = os.environ.get("GITHUB_REPOSITORY")
            run_id = os.environ.get("GITHUB_RUN_ID")
            server_url = os.environ.get("GITHUB_SERVER_URL", "https://github.com")

            if repo and run_id:
                with open(output_file, "a") as f:
                    f.write(f"**📁 Artifacts:** [Container Scan Reports]({server_url}/{repo}/actions/runs/{run_id}#artifacts)\n")

            with open(output_file, "a") as f:
                f.write("\n</details>\n")

    print("✅ Reports generated")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Generate container security summary from scan results"
    )
    parser.add_argument(
        "--combined",
        action="store_true",
        help="Generate combined summary for parallel scans",
    )

    args = parser.parse_args()

    # Get parsers from environment
    trivy_parser = os.environ.get("TRIVY_PARSER")
    grype_parser = os.environ.get("GRYPE_PARSER")

    if not trivy_parser or not grype_parser:
        print("Error: TRIVY_PARSER and GRYPE_PARSER environment variables must be set", file=sys.stderr)
        sys.exit(1)

    generate_summary(trivy_parser, grype_parser, combined=args.combined)


if __name__ == "__main__":
    main()
