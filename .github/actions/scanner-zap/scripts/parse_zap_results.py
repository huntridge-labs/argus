#!/usr/bin/env python3
"""Parse ZAP (Zed Attack Proxy) scan JSON results.

Usage: parse_zap_results.py <command> <json_file> [options]

Commands:
  counts              - Output "crit high med low" counts (mapped from ZAP severities)
  counts-with-info    - Output "crit high med low info" counts (mapped from ZAP severities)
  total               - Output total alert count
  unique              - Output unique alert count (by pluginid)
  alerts              - Output all alert names (one per line)
  table               - Output markdown table of alerts
  details             - Output detailed nested collapsible sections (requires -s severity -l limit)
  compact-table       - Output compact table for severity (requires -s severity -l limit)
  target              - Output scan target URL

Options:
  -s, --severity SEV  - Filter by severity (Critical, High, Medium, Low)
  -l, --limit N       - Limit output rows (default: 50 for table)
  -h, --help          - Show this help message

Note: ZAP severities use 1:1 mapping:
  ZAP High (riskcode 3)          -> High
  ZAP Medium (riskcode 2)        -> Medium
  ZAP Low (riskcode 1)           -> Low
  ZAP Informational (riskcode 0) -> Informational
Note: ZAP has no "Critical" level. When fail_on_severity=critical, ZAP High is checked.
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path


def validate_file(file_path):
    """Check if file exists and is not empty."""
    path = Path(file_path)
    return path.exists() and path.stat().st_size > 0


def load_json(file_path):
    """Load JSON file safely."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return None


def get_alerts_from_json(data):
    """Extract all alerts from ZAP JSON structure."""
    alerts = []
    if not data:
        return alerts

    sites = data.get('site', [])
    for site in sites:
        site_alerts = site.get('alerts', [])
        alerts.extend(site_alerts)

    return alerts


def get_counts(file_path):
    """Get alert counts by severity: 'crit high med low'."""
    if not validate_file(file_path):
        return "0 0 0 0"

    data = load_json(file_path)
    if not data:
        return "0 0 0 0"

    alerts = get_alerts_from_json(data)

    # ZAP has no critical severity
    critical = 0
    high = sum(1 for a in alerts if a.get('riskcode') == '3')
    medium = sum(1 for a in alerts if a.get('riskcode') == '2')
    low = sum(1 for a in alerts if a.get('riskcode') == '1')

    return f"{critical} {high} {medium} {low}"


def get_counts_with_info(file_path):
    """Get alert counts including informational: 'crit high med low info'."""
    if not validate_file(file_path):
        return "0 0 0 0 0"

    data = load_json(file_path)
    if not data:
        return "0 0 0 0 0"

    alerts = get_alerts_from_json(data)

    # ZAP has no critical severity
    critical = 0
    high = sum(1 for a in alerts if a.get('riskcode') == '3')
    medium = sum(1 for a in alerts if a.get('riskcode') == '2')
    low = sum(1 for a in alerts if a.get('riskcode') == '1')
    info = sum(1 for a in alerts if a.get('riskcode') == '0')

    return f"{critical} {high} {medium} {low} {info}"


def get_total(file_path):
    """Get total alert count."""
    if not validate_file(file_path):
        return "0"

    data = load_json(file_path)
    if not data:
        return "0"

    alerts = get_alerts_from_json(data)
    return str(len(alerts))


def get_unique(file_path):
    """Get unique alert count by pluginid."""
    if not validate_file(file_path):
        return "0"

    data = load_json(file_path)
    if not data:
        return "0"

    alerts = get_alerts_from_json(data)
    unique_plugins = set(a.get('pluginid') for a in alerts if a.get('pluginid'))
    return str(len(unique_plugins))


def get_alerts(file_path, severity=None):
    """Get all alert names, optionally filtered by severity."""
    if not validate_file(file_path):
        return []

    data = load_json(file_path)
    if not data:
        return []

    alerts = get_alerts_from_json(data)

    if severity:
        riskcode = map_severity_to_riskcode(severity)
        if riskcode is None:
            return []
        alerts = [a for a in alerts if a.get('riskcode') == riskcode]

    # Return unique sorted alert names
    names = sorted(set(a.get('name', '') for a in alerts if a.get('name')))
    return names


def map_severity_to_riskcode(severity):
    """Map severity name to ZAP riskcode."""
    severity_lower = severity.lower()
    mapping = {
        'critical': '3',  # ZAP has no critical, use High
        'high': '3',
        'medium': '2',
        'low': '1',
        'informational': '0',
        'info': '0',
    }
    return mapping.get(severity_lower)


def get_target(file_path):
    """Get target URL from report."""
    if not validate_file(file_path):
        return "unknown"

    data = load_json(file_path)
    if not data:
        return "unknown"

    sites = data.get('site', [])
    if sites and len(sites) > 0:
        return sites[0].get('@name', 'unknown')

    return "unknown"


def generate_table(file_path, limit=50):
    """Generate markdown table of alerts."""
    if not validate_file(file_path):
        return ""

    data = load_json(file_path)
    if not data:
        return ""

    alerts = get_alerts_from_json(data)
    if not alerts:
        return ""

    # Process alerts
    processed = []
    for alert in alerts:
        processed.append({
            'name': alert.get('name', ''),
            'riskcode': int(alert.get('riskcode', '0')),
            'confidence': alert.get('confidence', ''),
            'count': alert.get('count', '1'),
            'pluginid': alert.get('pluginid', ''),
            'cweid': alert.get('cweid', ''),
            'first_url': alert.get('instances', [{}])[0].get('uri', 'N/A') if alert.get('instances') else 'N/A',
        })

    # Sort by riskcode descending
    processed.sort(key=lambda x: x['riskcode'], reverse=True)
    processed = processed[:limit]

    # Map severity emoji
    severity_map = {
        3: '⚠️ High',
        2: '🟡 Medium',
        1: '🔵 Low',
        0: 'ℹ️ Info',
    }

    confidence_map = {
        '3': 'High',
        '2': 'Medium',
        '1': 'Low',
    }

    lines = []
    for alert in processed:
        severity = severity_map.get(alert['riskcode'], '❓ Unknown')
        confidence = confidence_map.get(alert['confidence'], 'Unknown')
        line = f"| {alert['name']} | {severity} | {confidence} | {alert['count']} | {alert['cweid']} | {alert['first_url']} |"
        lines.append(line)

    return '\n'.join(lines)


def generate_details(file_path, severity, limit=50):
    """Generate detailed vulnerability information for a specific severity."""
    if not validate_file(file_path):
        return ""

    data = load_json(file_path)
    if not data:
        return ""

    riskcode = map_severity_to_riskcode(severity)
    if riskcode is None:
        return ""

    alerts = get_alerts_from_json(data)
    filtered = [a for a in alerts if a.get('riskcode') == riskcode]

    # Get unique alerts by pluginid
    seen = set()
    unique_alerts = []
    for alert in filtered:
        pluginid = alert.get('pluginid')
        if pluginid not in seen:
            seen.add(pluginid)
            unique_alerts.append(alert)

    unique_alerts = unique_alerts[:limit]

    lines = []
    for idx, alert in enumerate(unique_alerts, 1):
        name = alert.get('name', 'Unknown')
        description = alert.get('desc', 'No description available')
        # Remove HTML tags from description
        description = re.sub(r'<[^>]+>', '', description)
        solution = alert.get('solution', 'No solution provided')
        # Remove HTML tags from solution
        solution = re.sub(r'<[^>]+>', '', solution)
        reference = alert.get('reference', '')
        cweid = alert.get('cweid', '')
        instances = alert.get('instances', [])

        lines.append('<details>')
        cwe_part = f' (CWE-{cweid})' if cweid else ''
        lines.append(f'<summary>{idx}. {name}{cwe_part}</summary>')
        lines.append('')
        lines.append(f'**Description:** {description}')
        lines.append('')
        lines.append(f'**Solution:** {solution}')
        lines.append('')

        if instances:
            unique_uris = sorted(set(i.get('uri', '') for i in instances if i.get('uri')))[:5]
            lines.append(f'**Affected URLs:** {len(unique_uris)} location{"s" if len(unique_uris) > 1 else ""}')
            for uri in unique_uris:
                lines.append(f'- `{uri}`')
            lines.append('')

        if reference:
            # Remove HTML tags
            reference_clean = re.sub(r'<[^>]+>', '', reference)
            lines.append('<details>')
            lines.append('<summary>References</summary>')
            lines.append('')
            lines.append(reference_clean)
            lines.append('')
            lines.append('</details>')
            lines.append('')

        lines.append('</details>')
        lines.append('')

    return '\n'.join(lines)


def generate_compact_table(file_path, severity, limit=50):
    """Generate compact table for a specific severity."""
    if not validate_file(file_path):
        return ""

    data = load_json(file_path)
    if not data:
        return ""

    riskcode = map_severity_to_riskcode(severity)
    if riskcode is None:
        return ""

    alerts = get_alerts_from_json(data)
    filtered = [a for a in alerts if a.get('riskcode') == riskcode]

    # Get unique alerts by pluginid
    seen = set()
    unique_alerts = []
    for alert in filtered:
        pluginid = alert.get('pluginid')
        if pluginid not in seen:
            seen.add(pluginid)
            unique_alerts.append(alert)

    unique_alerts = unique_alerts[:limit]

    lines = ['| Alert | CWE | Locations | Quick Fix |']
    lines.append('|-------|-----|-----------|-----------|')

    for alert in unique_alerts:
        name = alert.get('name', '')
        cweid = alert.get('cweid', 'N/A')
        solution = alert.get('solution', 'No solution provided')
        # Remove HTML tags
        solution = re.sub(r'<[^>]+>', '', solution)
        # Get first sentence or up to 80 chars
        sentences = solution.split('. ')
        quick_fix = sentences[0] if sentences else solution
        if len(quick_fix) > 80:
            quick_fix = quick_fix[:77] + '...'

        instances = alert.get('instances', [])
        location_count = len(instances)

        line = f'| {name} | {cweid} | {location_count} | {quick_fix} |'
        lines.append(line)

    return '\n'.join(lines)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Parse ZAP JSON scan results',
        add_help=False  # We'll handle help manually
    )

    parser.add_argument('command', nargs='?', help='Command to execute')
    parser.add_argument('json_file', nargs='?', help='Path to ZAP JSON file')
    parser.add_argument('-s', '--severity', help='Filter by severity')
    parser.add_argument('-l', '--limit', type=int, default=50, help='Limit output rows')
    parser.add_argument('-h', '--help', action='store_true', help='Show help message')

    args = parser.parse_args()

    if args.help or not args.command:
        print(__doc__)
        sys.exit(0)

    if not args.json_file:
        print("Error: Missing required arguments", file=sys.stderr)
        sys.exit(1)

    # Execute command
    if args.command == 'counts':
        print(get_counts(args.json_file))
    elif args.command == 'counts-with-info':
        print(get_counts_with_info(args.json_file))
    elif args.command == 'total':
        print(get_total(args.json_file))
    elif args.command == 'unique':
        print(get_unique(args.json_file))
    elif args.command == 'alerts':
        for name in get_alerts(args.json_file, args.severity):
            print(name)
    elif args.command == 'table':
        output = generate_table(args.json_file, args.limit)
        if output:
            print(output)
    elif args.command == 'details':
        if not args.severity:
            print("Error: 'details' command requires -s/--severity option", file=sys.stderr)
            sys.exit(1)
        output = generate_details(args.json_file, args.severity, args.limit)
        if output:
            print(output)
    elif args.command == 'compact-table':
        if not args.severity:
            print("Error: 'compact-table' command requires -s/--severity option", file=sys.stderr)
            sys.exit(1)
        output = generate_compact_table(args.json_file, args.severity, args.limit)
        if output:
            print(output)
    elif args.command == 'target':
        print(get_target(args.json_file))
    else:
        print(f"Unknown command: {args.command}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
