#!/usr/bin/env python3
"""Parse zizmor SARIF and actionlint JSON results into severity counts."""

import argparse
import json
import sys
from pathlib import Path


# SARIF level → our severity. Zizmor maps: high→error, medium→warning, low/info→note
SARIF_LEVEL_MAP = {
    "error": "HIGH",
    "warning": "MEDIUM",
    "note": "LOW",
    "none": "INFO",
}

# security-severity score thresholds (CVSS-style, used as tie-breaker)
SCORE_THRESHOLDS = [
    (7.0, "HIGH"),
    (4.0, "MEDIUM"),
    (0.1, "LOW"),
]


def validate_file(file_path):
    """Check if file exists and is not empty."""
    path = Path(file_path)
    return path.exists() and path.stat().st_size > 0


def load_json(file_path):
    """Load and parse JSON file.

    Returns None only for missing files. Exits non-zero on corrupted/unreadable
    files so that parse failures are never mistaken for clean scans.
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        return None
    except json.JSONDecodeError as e:
        print(
            f"::error::Failed to parse JSON from {file_path}: {e}",
            file=sys.stderr,
        )
        sys.exit(1)
    except OSError as e:
        print(
            f"::error::Cannot read {file_path}: {e}",
            file=sys.stderr,
        )
        sys.exit(1)


def _score_to_severity(score):
    """Map a security-severity score to a severity label."""
    for threshold, label in SCORE_THRESHOLDS:
        if score >= threshold:
            return label
    return "INFO"


def _build_rule_index(sarif_data):
    """Build a lookup of rule ID → rule metadata from SARIF tool.driver.rules."""
    rules = {}
    runs = sarif_data.get("runs")
    if not isinstance(runs, list) or not runs:
        return rules

    driver = (runs[0].get("tool") or {}).get("driver") or {}
    for rule in driver.get("rules") or []:
        rule_id = rule.get("id", "")
        if rule_id:
            rules[rule_id] = rule
    return rules


def _resolve_severity(result, rule_meta):
    """Determine severity from a SARIF result + its rule metadata.

    Priority:
    1. security-severity score on the rule properties (most precise)
    2. SARIF level on the result (error/warning/note)
    3. defaultConfiguration.level on the rule
    4. Fallback to LOW
    """
    props = (rule_meta.get("properties") or {}) if rule_meta else {}
    score_str = props.get("security-severity")
    if score_str is not None:
        try:
            return _score_to_severity(float(score_str))
        except (ValueError, TypeError):
            pass

    level = result.get("level")
    if level and level in SARIF_LEVEL_MAP:
        return SARIF_LEVEL_MAP[level]

    default_level = ((rule_meta or {}).get("defaultConfiguration") or {}).get("level")
    if default_level and default_level in SARIF_LEVEL_MAP:
        return SARIF_LEVEL_MAP[default_level]

    return "LOW"


def parse_zizmor_sarif(file_path):
    """Parse zizmor SARIF output into normalized findings.

    Returns [] for legitimately missing/empty files.
    Exits non-zero if file exists but contains malformed data.
    """
    if not validate_file(file_path):
        return []

    data = load_json(file_path)
    if not isinstance(data, dict):
        print(
            f"::error::Zizmor SARIF is not a JSON object: {file_path}",
            file=sys.stderr,
        )
        sys.exit(1)

    runs = data.get("runs")
    if not isinstance(runs, list) or not runs:
        return []

    rule_index = _build_rule_index(data)
    findings = []

    for result in runs[0].get("results") or []:
        if not isinstance(result, dict):
            continue

        rule_id = result.get("ruleId", "unknown")
        rule_meta = rule_index.get(rule_id)
        severity = _resolve_severity(result, rule_meta)

        message = (result.get("message") or {}).get("text", "")
        help_uri = (rule_meta or {}).get("helpUri", "")

        file_path_str = ""
        line = 0
        locations = result.get("locations") or []
        if locations:
            phys = (locations[0].get("physicalLocation") or {})
            artifact = phys.get("artifactLocation") or {}
            file_path_str = artifact.get("uri", "")
            region = phys.get("region") or {}
            line = region.get("startLine", 0)

        findings.append({
            "rule": rule_id,
            "severity": severity,
            "description": message,
            "url": help_uri,
            "file": file_path_str,
            "line": line,
            "source": "zizmor",
        })

    return findings


def parse_actionlint_findings(file_path):
    """Parse actionlint JSON output into normalized findings.

    Actionlint JSON format (via -format '{{json .}}') is an array of:
    - message: error message
    - filepath: path to workflow file
    - line: line number
    - column: column number
    - kind: error kind
    """
    if not validate_file(file_path):
        return []

    data = load_json(file_path)
    if not isinstance(data, list):
        print(
            f"::error::Actionlint output is not a JSON array: {file_path}",
            file=sys.stderr,
        )
        sys.exit(1)

    findings = []
    for item in data:
        if not isinstance(item, dict):
            continue

        findings.append({
            "rule": item.get("kind", "syntax"),
            "severity": "MEDIUM",
            "description": item.get("message", ""),
            "url": "",
            "file": item.get("filepath", ""),
            "line": item.get("line", 0),
            "source": "actionlint",
        })

    return findings


def get_all_findings(zizmor_file, actionlint_file=None):
    """Combine findings from zizmor SARIF and optionally actionlint."""
    findings = parse_zizmor_sarif(zizmor_file)

    if actionlint_file:
        findings.extend(parse_actionlint_findings(actionlint_file))

    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    findings.sort(key=lambda f: severity_order.get(f["severity"], 4))

    return findings


def get_counts(zizmor_file, actionlint_file=None):
    """Get finding counts by severity.

    Returns dict with keys: high, medium, low, info, total.
    """
    findings = get_all_findings(zizmor_file, actionlint_file)

    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for finding in findings:
        severity = finding["severity"]
        if severity in counts:
            counts[severity] += 1

    total = sum(counts.values())
    return {
        "high": counts["HIGH"],
        "medium": counts["MEDIUM"],
        "low": counts["LOW"],
        "info": counts["INFO"],
        "total": total,
    }


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Parse supply chain scan results",
    )
    parser.add_argument("command", choices=["counts", "findings"],
                        help="Command to execute")
    parser.add_argument("zizmor_file", help="Path to zizmor SARIF results file")
    parser.add_argument("--actionlint-file", default=None,
                        help="Path to actionlint JSON results file")

    args = parser.parse_args()

    if args.command == "counts":
        counts = get_counts(args.zizmor_file, args.actionlint_file)
        print(f"{counts['high']} {counts['medium']} {counts['low']} {counts['info']}")
    elif args.command == "findings":
        findings = get_all_findings(args.zizmor_file, args.actionlint_file)
        print(json.dumps(findings, indent=2))


if __name__ == "__main__":
    main()
