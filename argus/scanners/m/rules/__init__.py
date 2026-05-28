"""Rule registry for the MUMPS scanner.

Rules are listed in ID order. ``MScanner`` iterates ``RULES`` to produce
findings; new rules added in follow-up commits land here.
"""

from .m001_xecute_injection import XECUTEInjectionRule
from .m002_indirection_injection import IndirectionInjectionRule
from .m003_open_use_injection import OpenUseInjectionRule
from .m004_hardcoded_creds import HardcodedCredentialsRule
from .m005_tainted_dispatch import TaintedDispatchRule
from .m006_external_call_injection import ExternalCallInjectionRule
from .m101_duplicate_label import DuplicateLabelRule
from .m102_unreachable_after_quit import UnreachableAfterQuitRule
from .m201_unresolved_label import UnresolvedLabelRule
from .m202_routine_name_mismatch import RoutineNameMismatchRule
from .m203_implicit_declaration import ImplicitDeclarationRule
from .m204_unused_local import UnusedLocalRule
from .m205_label_fallthrough import LabelFallthroughRule
from .m206_kill_global_no_subscript import KillGlobalNoSubscriptRule

RULES = [
    XECUTEInjectionRule(),
    IndirectionInjectionRule(),
    OpenUseInjectionRule(),
    HardcodedCredentialsRule(),
    TaintedDispatchRule(),
    ExternalCallInjectionRule(),
    DuplicateLabelRule(),
    UnreachableAfterQuitRule(),
    UnresolvedLabelRule(),
    RoutineNameMismatchRule(),
    ImplicitDeclarationRule(),
    UnusedLocalRule(),
    LabelFallthroughRule(),
    KillGlobalNoSubscriptRule(),
]

__all__ = [
    "RULES",
    "XECUTEInjectionRule",
    "IndirectionInjectionRule",
    "OpenUseInjectionRule",
    "HardcodedCredentialsRule",
    "TaintedDispatchRule",
    "ExternalCallInjectionRule",
    "DuplicateLabelRule",
    "UnreachableAfterQuitRule",
    "UnresolvedLabelRule",
    "RoutineNameMismatchRule",
    "ImplicitDeclarationRule",
    "UnusedLocalRule",
    "LabelFallthroughRule",
    "KillGlobalNoSubscriptRule",
]
