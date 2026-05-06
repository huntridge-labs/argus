"""Shared helper for parsing scanner tool versions.

Every scanner module historically rolled its own ~17-line
``tool_version()`` that ran ``<tool> --version``, swallowed all
exceptions, and parsed the output with ad-hoc string slicing. The
parsers had drifted (some checked the first line, some the last; some
stripped a leading ``v``, some did not), the exception lists had drifted
(``except (TimeoutExpired, FileNotFoundError, Exception)`` — where
``Exception`` already covers the others), and the timeouts had drifted
(5s vs 10s for no clear reason).

``parse_tool_version`` collapses that boilerplate into a regex match:
each scanner declares its version-discovery command and a pattern, and
the helper returns the captured group or ``None`` when anything goes
wrong. Scanners whose output format doesn't fit a single regex (e.g.
Grype emits JSON via ``grype version -o json``) keep custom parsing —
the goal is a shared shape for the common case, not a forced
abstraction.
"""

import re
import subprocess


def parse_tool_version(
    cmd: list[str],
    pattern: str | re.Pattern,
    *,
    group: int = 1,
    timeout: float = 5.0,
) -> str | None:
    """Run *cmd* and extract a version string via *pattern*.

    Args:
        cmd: argv for the version subprocess (e.g. ``["bandit", "--version"]``).
        pattern: Compiled regex or pattern string. Compiled with
            ``re.MULTILINE`` so anchors like ``^`` match line starts in
            multi-line tool output. The captured group is returned.
        group: Match group index to return (default 1, the first capture).
        timeout: Seconds before giving up on the subprocess.

    Returns:
        The captured version string with surrounding whitespace stripped,
        or ``None`` when the subprocess fails (missing binary, timeout,
        nonzero exit) or the pattern doesn't match.
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None

    if isinstance(pattern, str):
        pattern = re.compile(pattern, re.MULTILINE)

    # Search stdout first (most tools), fall back to stderr (some
    # version banners land there — Java tools especially).
    for stream in (result.stdout or "", result.stderr or ""):
        match = pattern.search(stream)
        if match:
            return match.group(group).strip()
    return None
