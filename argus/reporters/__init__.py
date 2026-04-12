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
