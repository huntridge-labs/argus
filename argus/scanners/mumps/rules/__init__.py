"""Rule registry for the MUMPS scanner.

Rules are listed in ID order. ``MumpsScanner`` iterates ``RULES`` to produce
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
from .m207_bare_kill import BareKillRule
from .m208_bare_new import BareNewRule
from .m209_arg_count_mismatch import ArgCountMismatchRule
from .m210_duplicate_new import DuplicateNewRule
from .m211_scratch_global_no_job import ScratchGlobalNoJobRule
from .m212_infinite_for import InfiniteForRule
from .m213_quit_arg_in_for import QuitArgInForRule
from .m214_naked_global import NakedGlobalRule
from .m215_nonportable_zcommand import NonPortableZCommandRule
from .m216_nonportable_zfunction import NonPortableZFunctionRule
from .m217_nonportable_zsvn import NonPortableZSpecialVarRule
from .m218_exec_on_label_line import ExecOnLabelLineRule
from .m219_line_length import LineLengthRule

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
    BareKillRule(),
    BareNewRule(),
    ArgCountMismatchRule(),
    DuplicateNewRule(),
    ScratchGlobalNoJobRule(),
    InfiniteForRule(),
    QuitArgInForRule(),
    NakedGlobalRule(),
    NonPortableZCommandRule(),
    NonPortableZFunctionRule(),
    NonPortableZSpecialVarRule(),
    ExecOnLabelLineRule(),
    LineLengthRule(),
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
    "BareKillRule",
    "BareNewRule",
    "ArgCountMismatchRule",
    "DuplicateNewRule",
    "ScratchGlobalNoJobRule",
    "InfiniteForRule",
    "QuitArgInForRule",
    "NakedGlobalRule",
    "NonPortableZCommandRule",
    "NonPortableZFunctionRule",
    "NonPortableZSpecialVarRule",
    "ExecOnLabelLineRule",
    "LineLengthRule",
]
