"""Argus scanner registry."""

from .bandit import BanditScanner
from .checkov import CheckovScanner
from .clamav import ClamavScanner
from .container import ContainerScanner
from .gitleaks import GitleaksScanner
from .gosec import GosecScanner
from .guarddog import GuardDogScanner
from .grype import GrypeScanner
from .kics import KICSScanner
from .mumps import MumpsScanner
from .opengrep import OpengrepScanner
from .osv import OsvScanner
from .promptfoo import PromptfooScanner
from .supply_chain import SupplyChainScanner
from .trivy import TrivyScanner
from .trivy_iac import TrivyIacScanner
from .zap import ZapScanner
from argus.linters import LINTER_REGISTRY

__all__ = [
    "BanditScanner",
    "CheckovScanner",
    "ClamavScanner",
    "ContainerScanner",
    "GitleaksScanner",
    "GosecScanner",
    "GrypeScanner",
    "KICSScanner",
    "MumpsScanner",
    "OpengrepScanner",
    "OsvScanner",
    "PromptfooScanner",
    "SupplyChainScanner",
    "TrivyScanner",
    "TrivyIacScanner",
    "ZapScanner",
    "SCANNER_REGISTRY",
    "get_scanner",
    "get_available_scanners",
    "available_scanner_names",
    "sbom_capable_scanner_names",
]

SCANNER_REGISTRY = {
    "bandit": BanditScanner,
    "gosec": GosecScanner,
    "clamav": ClamavScanner,
    "trivy": TrivyScanner,
    "trivy-iac": TrivyIacScanner,
    "grype": GrypeScanner,
    "gitleaks": GitleaksScanner,
    "guarddog": GuardDogScanner,
    "osv": OsvScanner,
    "checkov": CheckovScanner,
    "kics": KICSScanner,
    "mumps": MumpsScanner,
    "opengrep": OpengrepScanner,
    "supply-chain": SupplyChainScanner,
    "zap": ZapScanner,
    "container": ContainerScanner,
    "promptfoo": PromptfooScanner,
}

# Merge linter modules into the scanner registry so they can be
# invoked via `argus scan lint-yaml`, `argus scan lint-python`, etc.
SCANNER_REGISTRY.update(LINTER_REGISTRY)


def get_scanner(name: str):
    """Instantiate and return a scanner by registry name.

    Raises ValueError if the name is not registered.
    """
    cls = SCANNER_REGISTRY.get(name)
    if not cls:
        raise ValueError(
            f"Unknown scanner: {name}. "
            f"Available: {', '.join(SCANNER_REGISTRY)}"
        )
    return cls()


def get_available_scanners():
    """Return scanner classes for all registered scanners."""
    return list(SCANNER_REGISTRY.values())


def available_scanner_names() -> list[str]:
    """Return the names of all registered scanners."""
    return list(SCANNER_REGISTRY.keys())


def sbom_capable_scanner_names() -> list[str]:
    """Return the names of scanners that can scan a pre-built SBOM.

    Consumed by ``argus scan --sbom`` to auto-select the scanners whose
    class attribute ``supports_sbom`` is True. Linters are filtered out
    up front — they never operate on SBOMs by definition.
    """
    return [
        name
        for name, cls in SCANNER_REGISTRY.items()
        if getattr(cls, "supports_sbom", False)
    ]
