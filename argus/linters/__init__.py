"""Argus linter registry."""

from .hadolint import HadolintLinter
from .jshint import JshintLinter
from .jsonlint import JsonlintLinter
from .python_lint import PythonLinter
from .terraform import TerraformLinter
from .yamllint import YamllintLinter

__all__ = [
    "HadolintLinter",
    "JshintLinter",
    "JsonlintLinter",
    "PythonLinter",
    "TerraformLinter",
    "YamllintLinter",
    "LINTER_REGISTRY",
    "get_linter",
    "get_available_linters",
    "available_linter_names",
]

LINTER_REGISTRY = {
    "lint-yaml": YamllintLinter,
    "lint-json": JsonlintLinter,
    "lint-python": PythonLinter,
    "lint-javascript": JshintLinter,
    "lint-dockerfile": HadolintLinter,
    "lint-terraform": TerraformLinter,
}


def get_linter(name: str):
    """Instantiate and return a linter by registry name.

    Raises ValueError if the name is not registered.
    """
    cls = LINTER_REGISTRY.get(name)
    if not cls:
        raise ValueError(
            f"Unknown linter: {name}. "
            f"Available: {', '.join(LINTER_REGISTRY)}"
        )
    return cls()


def get_available_linters():
    """Return linter classes for all registered linters."""
    return list(LINTER_REGISTRY.values())


def available_linter_names() -> list[str]:
    """Return the names of all registered linters."""
    return list(LINTER_REGISTRY.keys())
