"""Rule registry for the MUMPS scanner.

Rules are listed in ID order. ``MScanner`` iterates ``RULES`` to produce
findings; new rules added in follow-up commits land here.
"""

from .m001_xecute_injection import XECUTEInjectionRule
from .m002_indirection_injection import IndirectionInjectionRule
from .m003_open_use_injection import OpenUseInjectionRule
from .m004_hardcoded_creds import HardcodedCredentialsRule
from .m005_tainted_dispatch import TaintedDispatchRule
from .m101_duplicate_label import DuplicateLabelRule
from .m102_unreachable_after_quit import UnreachableAfterQuitRule

RULES = [
    XECUTEInjectionRule(),
    IndirectionInjectionRule(),
    OpenUseInjectionRule(),
    HardcodedCredentialsRule(),
    TaintedDispatchRule(),
    DuplicateLabelRule(),
    UnreachableAfterQuitRule(),
]

__all__ = [
    "RULES",
    "XECUTEInjectionRule",
    "IndirectionInjectionRule",
    "OpenUseInjectionRule",
    "HardcodedCredentialsRule",
    "TaintedDispatchRule",
    "DuplicateLabelRule",
    "UnreachableAfterQuitRule",
]
