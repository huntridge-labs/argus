"""Rule registry for the MUMPS scanner.

Rules are listed in ID order. ``MScanner`` iterates ``RULES`` to produce
findings; new rules added in follow-up commits land here.
"""

from .m001_xecute_injection import XECUTEInjectionRule
from .m002_indirection_injection import IndirectionInjectionRule
from .m004_hardcoded_credentials import HardcodedCredentialsRule
from .m101_duplicate_label import DuplicateLabelRule

RULES = [
    XECUTEInjectionRule(),
    IndirectionInjectionRule(),
    HardcodedCredentialsRule(),
    DuplicateLabelRule(),
]

__all__ = [
    "RULES",
    "XECUTEInjectionRule",
    "IndirectionInjectionRule",
    "HardcodedCredentialsRule",
    "DuplicateLabelRule",
]
