#!/usr/bin/env python3
"""Generate CLI reference documentation from argus's argparse parser.

Introspects the parser tree and produces markdown. The CLI IS the
documentation source — no manual maintenance needed.

Usage:
    python -m scripts.ci.gen_cli_docs                          # stdout
    python -m scripts.ci.gen_cli_docs --output docs/cli.md     # file
    python -m scripts.ci.gen_cli_docs --format mkdocs          # for docsite
"""

import argparse
import datetime
import sys
from pathlib import Path

# Ensure argus is importable
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


def generate_cli_docs(output: str | None = None, fmt: str = "markdown") -> str:
    """Generate CLI documentation from the argparse parser tree."""
    from argus.cli import build_parser
    from argus import __version__

    parser = build_parser()
    lines: list[str] = []

    # Header
    lines.append(f"# Argus CLI Reference (v{__version__})")
    lines.append("")
    lines.append(f"> Auto-generated from argparse definitions on "
                 f"{datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d')}.")
    lines.append("> Do not edit manually — run `python -m scripts.ci.gen_cli_docs` to regenerate.")
    lines.append("")

    # Top-level description
    if parser.description:
        lines.append(parser.description)
        lines.append("")

    # Top-level usage
    lines.append("## Usage")
    lines.append("")
    lines.append("```")
    lines.append(f"argus [--version] [--help] <command> [options]")
    lines.append("```")
    lines.append("")

    # Top-level options
    top_options = [a for a in parser._actions
                   if a.option_strings and not isinstance(a, argparse._HelpAction)]
    if top_options:
        lines.append("## Global Options")
        lines.append("")
        lines.extend(_format_options_table(top_options))
        lines.append("")

    # Output and verbosity — explains how the four output-control
    # flags compose. Each flag's individual help text is also rendered
    # below in the per-command tables; this section gives readers the
    # mental model up front.
    lines.extend([
        "## Output and verbosity",
        "",
        "`argus scan` exposes four flags that compose orthogonally —"
        " `--quiet` controls log verbosity, `--no-spinner` controls UI"
        " rendering, and `--debug` (alias `--verbose`) is the explicit"
        " troubleshooting opt-in. The four most useful modes:",
        "",
        "| Invocation | When to use | What you see |",
        "|---|---|---|",
        "| `argus scan` | Default — interactive terminal | Phase-aware spinner that updates per image and per scan phase |",
        "| `argus scan --quiet` | Daily runs you don't want narrating | Spinner stays drawing, but per-phase chatter is suppressed; only WARNING/ERROR lines and the final summary print |",
        "| `argus scan --no-spinner` | CI logs, step-away monitoring | Persistent `[idx/total] name — phase (Ns)` lines on stderr instead of a self-overwriting spinner |",
        "| `argus scan --debug` (or `--verbose`) | Troubleshooting | Full firehose: subprocess output, vulnerability-DB updates, every engine log line |",
        "",
        "Compose flags for additional modes — `--quiet --no-spinner` is the fully-silent CI exit-code-only combination; `--debug --no-spinner` is identical to `--debug` since debug auto-disables the spinner.",
        "",
    ])

    # Commands
    lines.append("## Commands")
    lines.append("")

    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for cmd_name, sub_parser in action.choices.items():
                lines.extend(_format_subcommand(cmd_name, sub_parser))

    # Quick reference
    lines.append("## Quick Reference")
    lines.append("")
    lines.append("```bash")
    lines.append("# Source code scanning")
    lines.append("argus scan                                    # all enabled scanners")
    lines.append("argus scan bandit                             # specific scanner")
    lines.append("argus scan --list                             # list available scanners")
    lines.append("argus scan --config argus.yml --verbose       # with config and debug output")
    lines.append("")
    lines.append("# Container image scanning")
    lines.append("argus scan container --discover ./            # find and scan all Dockerfiles")
    lines.append("argus scan container --image nginx:latest     # scan specific image")
    lines.append("")
    lines.append("# DAST scanning")
    lines.append("argus scan zap --target http://localhost:3000 # scan running target")
    lines.append("argus scan zap --image myapp:latest           # auto-discover ports, scan")
    lines.append("")
    lines.append("# Reports")
    lines.append("argus report terminal --results-dir ./argus-results")
    lines.append("argus report sarif --results-dir ./argus-results")
    lines.append("```")
    lines.append("")

    # Exit codes
    lines.append("## Exit Codes")
    lines.append("")
    lines.append("| Code | Meaning |")
    lines.append("|------|---------|")
    lines.append("| `0`  | Scan passed — no findings above severity threshold |")
    lines.append("| `1`  | Findings detected above severity threshold |")
    lines.append("| `2`  | Error — scan could not complete |")
    lines.append("")

    content = "\n".join(lines)

    if output:
        Path(output).parent.mkdir(parents=True, exist_ok=True)
        Path(output).write_text(content, encoding="utf-8")
        print(f"CLI docs written to {output}")
    else:
        print(content)

    return content


def _format_subcommand(name: str, parser: argparse.ArgumentParser) -> list[str]:
    """Format a subcommand section."""
    lines: list[str] = []
    lines.append(f"### `argus {name}`")
    lines.append("")

    if parser.description:
        # Clean up raw description formatting
        desc = parser.description.strip()
        lines.append(desc)
        lines.append("")

    # Usage
    lines.append("```")
    lines.append(parser.format_usage().strip().replace("usage: ", ""))
    lines.append("```")
    lines.append("")

    # Positional arguments
    positionals = [a for a in parser._actions
                   if not a.option_strings
                   and not isinstance(a, (argparse._HelpAction, argparse._SubParsersAction))]
    if positionals:
        lines.append("**Arguments:**")
        lines.append("")
        for a in positionals:
            name_str = a.dest
            help_str = a.help or ""
            if a.choices:
                help_str += f" (choices: {', '.join(str(c) for c in a.choices)})"
            if a.default is not None and a.default != argparse.SUPPRESS:
                help_str += f" (default: {a.default})"
            lines.append(f"- `{name_str}` — {help_str}")
        lines.append("")

    # Group options by argument group
    for group in parser._action_groups:
        group_options = [a for a in group._group_actions
                         if a.option_strings
                         and not isinstance(a, argparse._HelpAction)]
        if not group_options:
            continue

        group_title = group.title or "Options"
        if group_title in ("positional arguments", "options"):
            group_title = "Options"

        lines.append(f"**{group_title.title()}:**")
        lines.append("")
        lines.extend(_format_options_table(group_options))
        lines.append("")

    return lines


def _format_options_table(options: list) -> list[str]:
    """Format a list of argparse actions as a markdown table."""
    lines: list[str] = []
    lines.append("| Flag | Description | Default |")
    lines.append("|------|-------------|---------|")

    for a in options:
        flags = ", ".join(f"`{f}`" for f in a.option_strings)
        help_text = (a.help or "").replace("|", "\\|")
        default = ""
        if a.default is not None and a.default != argparse.SUPPRESS and a.default is not False:
            default = f"`{a.default}`"
        if isinstance(a, argparse._StoreTrueAction):
            default = "`false`"
        if a.choices:
            help_text += f" ({', '.join(str(c) for c in a.choices)})"
        lines.append(f"| {flags} | {help_text} | {default} |")

    return lines


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Generate CLI reference docs")
    ap.add_argument("--output", "-o", help="Output file path (default: stdout)")
    ap.add_argument("--format", choices=["markdown", "mkdocs"], default="markdown")
    args = ap.parse_args()
    generate_cli_docs(output=args.output, fmt=args.format)
