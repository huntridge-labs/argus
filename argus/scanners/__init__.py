"""Argus scanner registry."""

from .bandit import BanditScanner
from .checkov import CheckovScanner
from .clamav import ClamavScanner
from .container import ContainerScanner
from .gitleaks import GitleaksScanner
from .opengrep import OpengrepScanner
from .osv import OsvScanner
from .supply_chain import SupplyChainScanner
from .trivy_iac import TrivyIacScanner
from .zap import ZapScanner

__all__ = [
    "BanditScanner",
    "CheckovScanner",
    "ClamavScanner",
    "ContainerScanner",
    "GitleaksScanner",
    "OpengrepScanner",
    "OsvScanner",
    "SupplyChainScanner",
    "TrivyIacScanner",
    "ZapScanner",
    "SCANNER_REGISTRY",
    "get_scanner",
    "get_available_scanners",
    "available_scanner_names",
]

SCANNER_REGISTRY = {
    "bandit": BanditScanner,
    "clamav": ClamavScanner,
    "trivy-iac": TrivyIacScanner,
    "gitleaks": GitleaksScanner,
    "osv": OsvScanner,
    "checkov": CheckovScanner,
    "opengrep": OpengrepScanner,
    "supply-chain": SupplyChainScanner,
    "zap": ZapScanner,
    "container": ContainerScanner,
}


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
