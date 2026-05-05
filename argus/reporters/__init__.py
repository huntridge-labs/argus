"""Argus reporters — output scan results in various formats."""

from .terminal import TerminalReporter
from .markdown import MarkdownReporter
from .container_markdown import ContainerMarkdownReporter
from .sarif import SarifReporter
from .json_report import JsonReporter

REPORTER_REGISTRY = {
    'terminal': TerminalReporter,
    'markdown': MarkdownReporter,
    'container_markdown': ContainerMarkdownReporter,
    'sarif': SarifReporter,
    'json': JsonReporter,
}


def get_reporter(name: str):
    """Get a reporter instance by name."""
    cls = REPORTER_REGISTRY.get(name)
    if not cls:
        available = ', '.join(REPORTER_REGISTRY)
        raise ValueError(f"Unknown reporter: {name}. Available: {available}")
    return cls()


def available_reporters() -> list[str]:
    """Return list of registered reporter names."""
    return list(REPORTER_REGISTRY.keys())


# The single canonical scan artifact. ``argus-results.json`` is consumed
# by the audit manifest, both viewers (terminal + browser), the
# ``argus report`` subcommand, and any downstream tooling built on the
# SDK. Treating it as always-emitted decouples its existence from
# user-configured ``reporting.formats``: that list now means "which
# *additional* human-readable reports to emit alongside the canonical
# JSON," not "which artifacts exist at all." Eliminates the failure
# mode where a config like ``formats: [terminal, sarif]`` silently
# breaks ``argus view``.
CANONICAL_FORMAT = "json"


def ensure_canonical_json(formats: list[str]) -> list[str]:
    """Return the format list with the canonical JSON output guaranteed.

    Idempotent — if the user already lists ``json`` we don't add a
    duplicate (which would write the file twice). Order is preserved
    so the user's terminal/markdown/sarif reports still print in the
    sequence they configured; the canonical JSON is appended at the
    end so it's always the last reporter to run (its dict-dump output
    isn't influenced by side-effects of earlier reporters).
    """
    if CANONICAL_FORMAT in formats:
        return list(formats)
    return [*formats, CANONICAL_FORMAT]
