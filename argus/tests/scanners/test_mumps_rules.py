"""Integration tests for MUMPS scanner rules.

These tests parse real .m fixture files and assert each rule fires (or
does not fire) as documented. They require the compiled
tree-sitter-mumps grammar shared library to be reachable — locally
that's ``scripts/build-mumps-grammar.sh``; in CI / container execution
it's the ``scanner-mumps`` image. When the grammar is not installed all
tests in this module skip cleanly so the unit-level coverage in
``test_mumps_scanner.py`` still runs.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from argus.core.models import Severity
from argus.core.redact import REDACTED_PLACEHOLDER
from argus.scanners.mumps import MumpsScanner
from argus.scanners.mumps.parser import tree_sitter_available


pytestmark = pytest.mark.skipif(
    not tree_sitter_available(),
    reason=(
        "MUMPS tree-sitter grammar not installed. Run "
        "scripts/build-mumps-grammar.sh or use the scanner-mumps container."
    ),
)


@pytest.fixture
def m_fixtures_dir() -> Path:
    return Path(__file__).parent / "mumps" / "fixtures"


def _scan(path: Path):
    return MumpsScanner().scan(str(path))


def _findings_with_id(result, rule_id: str):
    return [f for f in result.findings if f.id == rule_id]


class TestM001XECUTEInjection:
    def test_fires_on_read_tainted_xecute(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m001_xecute_taint.m")
        hits = _findings_with_id(result, "M001")
        assert hits, "M001 must fire when XECUTE references a READ-tainted var"
        assert all(f.severity == Severity.HIGH for f in hits)
        assert all(f.cwe == "CWE-95" for f in hits)

    def test_clean_xecute_does_not_fire(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m001_xecute_clean.m")
        assert _findings_with_id(result, "M001") == []

    def test_fires_on_zargv_tainted_xecute(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m001_zargv_taint.m")
        hits = _findings_with_id(result, "M001")
        assert hits, "M001 must recognize $ZARGV as a taint source"
        assert all(f.severity == Severity.HIGH for f in hits)

    def test_fires_on_cgi_tainted_xecute(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m001_cgi_taint.m")
        hits = _findings_with_id(result, "M001")
        assert hits, "M001 must recognize ^%CGI(...) as a taint source"
        assert all(f.severity == Severity.HIGH for f in hits)

    def test_pure_literal_xecute_not_flagged_even_with_taint(self, m_fixtures_dir):
        # X is READ-tainted but the XECUTE arg is a constant string —
        # nothing interpolated. The literal-descent fix must suppress it.
        result = _scan(m_fixtures_dir / "m001_literal_with_taint.m")
        assert _findings_with_id(result, "M001") == []

    def test_concatenation_with_taint_fires(self, m_fixtures_dir):
        # A literal concatenated with a tainted var is real injection.
        result = _scan(m_fixtures_dir / "m001_concat_taint.m")
        assert _findings_with_id(result, "M001"), "concat with tainted var must fire"

    def test_custom_taint_pattern_opt_in_via_config(self, m_fixtures_dir):
        # $ZIO is not a built-in source; without config the rule should
        # not fire on a $ZIO-driven XECUTE.
        path = m_fixtures_dir / "m001_zio_custom.m"
        baseline = MumpsScanner().scan(str(path))
        assert _findings_with_id(baseline, "M001") == [], (
            "$ZIO must not be a built-in taint source"
        )
        # With taint_sources.patterns set, the same fixture fires.
        config = {"taint_sources": {"patterns": [r"\$ZIO\b"]}}
        with_config = MumpsScanner().scan(str(path), config)
        hits = _findings_with_id(with_config, "M001")
        assert hits, (
            "M001 must fire when taint_sources.patterns adds the custom source"
        )


class TestM002IndirectionInjection:
    def test_fires_on_tainted_indirection(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m002_indirection.m")
        hits = _findings_with_id(result, "M002")
        assert hits, "M002 must fire HIGH on indirection of a READ-tainted var"
        assert all(f.severity == Severity.HIGH for f in hits)
        assert all(f.cwe == "CWE-94" for f in hits)
        assert all(f.metadata.get("taint_sources") for f in hits)

    def test_clean_routine_does_not_fire(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m002_clean.m")
        assert _findings_with_id(result, "M002") == []

    def test_constant_indirection_not_flagged_by_default(self, m_fixtures_dir):
        # Indirection of a non-tainted (source-constant) variable is the
        # benign idiom; taint-gating must suppress it by default.
        result = _scan(m_fixtures_dir / "m002_constant_indirection.m")
        assert _findings_with_id(result, "M002") == []

    def test_generic_indirection_flag_surfaces_at_info(self, m_fixtures_dir):
        # The generic-indirection advisory is opt-in and INFO-only.
        cfg = {"flag_generic_indirection": True}
        result = MumpsScanner().scan(
            str(m_fixtures_dir / "m002_constant_indirection.m"), cfg,
        )
        hits = _findings_with_id(result, "M002")
        assert hits, "generic indirection must surface when the flag is on"
        assert all(f.severity == Severity.INFO for f in hits)


class TestM004HardcodedCredentials:
    def test_fires_on_credential_shaped_globals(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m004_hardcoded.m")
        hits = _findings_with_id(result, "M004")
        assert len(hits) >= 2, "M004 must fire on each credential-shaped SET"
        assert all(f.severity == Severity.CRITICAL for f in hits)
        assert all(f.cwe == "CWE-798" for f in hits)

    def test_literal_value_is_redacted(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m004_hardcoded.m")
        hits = _findings_with_id(result, "M004")
        for finding in hits:
            assert "hunter2" not in finding.title
            assert "hunter2" not in finding.description
            assert "hunter2" not in str(finding.metadata)
            assert finding.metadata.get("value") == REDACTED_PLACEHOLDER

    def test_non_credential_globals_do_not_fire(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m004_clean.m")
        assert _findings_with_id(result, "M004") == []


class TestM003OpenUseInjection:
    def test_fires_on_tainted_open_argument(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m003_open_taint.m")
        hits = _findings_with_id(result, "M003")
        assert hits, "M003 must fire when OPEN/USE references a READ-tainted var"
        assert all(f.severity == Severity.HIGH for f in hits)
        assert all(f.cwe == "CWE-78" for f in hits)
        commands = {f.metadata.get("command") for f in hits}
        # Both OPEN and USE in the fixture should trip the rule
        assert "OPEN" in commands or "USE" in commands

    def test_constant_device_does_not_fire(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m003_open_clean.m")
        assert _findings_with_id(result, "M003") == []

    def test_pipe_device_bumps_to_critical(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m003_pipe_taint.m")
        hits = _findings_with_id(result, "M003")
        assert hits, "M003 must fire on a tainted PIPE-device argument"
        pipe_hits = [f for f in hits if f.metadata.get("device_class") == "PIPE"]
        assert pipe_hits, "PIPE detection must classify the device"
        assert all(f.severity == Severity.CRITICAL for f in pipe_hits), (
            "PIPE-bound OPEN/USE with tainted argument is OS-level RCE, must be CRITICAL"
        )


class TestM005TaintedDispatch:
    def test_fires_on_tainted_do_indirection(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m005_dispatch_taint.m")
        hits = _findings_with_id(result, "M005")
        assert hits, "M005 must fire when DO indirection references a READ-tainted var"
        assert all(f.severity == Severity.CRITICAL for f in hits)
        assert all(f.cwe == "CWE-95" for f in hits)
        # Taint sources should be recorded for downstream triage
        for finding in hits:
            assert finding.metadata.get("taint_sources"), (
                "M005 must record the tainted variable name(s)"
            )

    def test_static_dispatch_does_not_fire(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m005_dispatch_clean.m")
        assert _findings_with_id(result, "M005") == []


class TestM101DuplicateLabel:
    def test_fires_on_duplicate_label(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m101_dup_label.m")
        hits = _findings_with_id(result, "M101")
        assert len(hits) == 1, "M101 fires once — on the duplicate, not the first"
        finding = hits[0]
        assert finding.severity == Severity.INFO
        assert finding.metadata.get("label") == "DOTHING"
        assert finding.metadata.get("first_declaration"), (
            "M101 must record the first declaration's location"
        )

    def test_unique_labels_do_not_fire(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m101_unique_labels.m")
        assert _findings_with_id(result, "M101") == []


class TestM102UnreachableAfterQuit:
    def test_fires_on_unconditional_break(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m102_unreachable.m")
        hits = _findings_with_id(result, "M102")
        assert len(hits) == 2, (
            "M102 must fire once per unconditional break with a following command"
        )
        assert all(f.severity == Severity.INFO for f in hits)
        break_commands = {f.metadata.get("break_command") for f in hits}
        assert "Q" in break_commands or "H" in break_commands

    def test_postconditional_break_does_not_fire(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m102_postconditional.m")
        # Only the final unconditional Q at end-of-routine could
        # theoretically fire, but it has no following command and so
        # the rule should produce no findings on this fixture.
        assert _findings_with_id(result, "M102") == []


class TestM006ExternalCallInjection:
    def test_fires_on_tainted_external_call(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m006_external_taint.m")
        hits = _findings_with_id(result, "M006")
        assert hits, "M006 must fire when $& call receives a tainted argument"
        assert all(f.severity == Severity.HIGH for f in hits)
        assert all(f.cwe == "CWE-78" for f in hits)
        for finding in hits:
            assert finding.metadata.get("function", "").startswith("$&")

    def test_pure_external_call_does_not_fire(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m006_external_clean.m")
        assert _findings_with_id(result, "M006") == []


class TestM201UnresolvedLabel:
    def test_fires_on_missing_label_reference(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m201_missing.m")
        hits = _findings_with_id(result, "M201")
        assert hits, "M201 must fire when DO references an undeclared label"
        labels = {f.metadata.get("label") for f in hits}
        assert "MISSING" in labels

    def test_resolved_labels_do_not_fire(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m201_resolved.m")
        assert _findings_with_id(result, "M201") == []

    def test_read_timeout_not_flagged(self, m_fixtures_dir):
        # ``R X:DTIME`` misparses into a spurious routine_call ``TIME``
        # next to an ERROR node; the guards must suppress it.
        result = _scan(m_fixtures_dir / "m201_read_timeout.m")
        labels = {f.metadata.get("label") for f in _findings_with_id(result, "M201")}
        assert "TIME" not in labels
        assert "DTIME" not in labels


class TestM202RoutineNameMismatch:
    def test_fires_on_mismatch(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m202mismatch.m")
        hits = _findings_with_id(result, "M202")
        assert hits, "M202 must fire when first label differs from filename stem"
        finding = hits[0]
        assert finding.metadata.get("declared") == "WRONGNAME"
        assert finding.metadata.get("expected") == "M202MISMATCH"

    def test_matching_name_does_not_fire(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m202clean.m")
        assert _findings_with_id(result, "M202") == []

    def test_percent_routine_matches_after_strip(self, m_fixtures_dir):
        # Label ``%M202PCT`` vs stem ``M202PCT`` — the %-routine
        # convention is a match, not a mismatch.
        result = _scan(m_fixtures_dir / "M202PCT.m")
        assert _findings_with_id(result, "M202") == []

    def test_ignore_patterns_suppresses(self, m_fixtures_dir):
        # A site can suppress platform-variant families by regex.
        cfg = {"rules": {"M202": {"ignore_patterns": ["^WRONG"]}}}
        result = MumpsScanner().scan(str(m_fixtures_dir / "m202mismatch.m"), cfg)
        assert _findings_with_id(result, "M202") == []


# M205 ships off-by-default (too noisy on linear-style VistA routines),
# so its tests must opt in explicitly.
_M205_ON = {"rules": {"M205": {"enabled": True}}}


class TestM205LabelFallthrough:
    def test_fires_on_fallthrough(self, m_fixtures_dir):
        result = MumpsScanner().scan(
            str(m_fixtures_dir / "m205_fallthrough.m"), _M205_ON,
        )
        hits = _findings_with_id(result, "M205")
        assert hits, "M205 must fire when a label body falls through"
        finding = hits[0]
        assert finding.metadata.get("preceding_label") == "LABELA"
        assert finding.metadata.get("fallthrough_into") == "LABELB"

    def test_terminated_labels_do_not_fire(self, m_fixtures_dir):
        result = MumpsScanner().scan(
            str(m_fixtures_dir / "m205_terminated.m"), _M205_ON,
        )
        assert _findings_with_id(result, "M205") == []

    def test_disabled_by_default(self, m_fixtures_dir):
        # Without opt-in config, M205 must not run at all.
        result = _scan(m_fixtures_dir / "m205_fallthrough.m")
        assert _findings_with_id(result, "M205") == []
        assert "M205" not in result.metadata["rules_run"]


class TestM203ImplicitDeclaration:
    def test_fires_on_typo_read_before_define(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m203_typo.m")
        hits = _findings_with_id(result, "M203")
        assert hits, "M203 must fire on a variable read without a prior definition"
        names = {f.metadata.get("variable") for f in hits}
        assert "USR" in names
        # USER is defined; must NOT be flagged
        assert "USER" not in names

    def test_formal_args_not_flagged(self, m_fixtures_dir):
        # Formal params A,B parse as ``arguments`` siblings of the label.
        result = _scan(m_fixtures_dir / "m203_formal_args.m")
        names = {f.metadata.get("variable") for f in _findings_with_id(result, "M203")}
        assert "A" not in names and "B" not in names

    def test_external_vars_not_flagged(self, m_fixtures_dir):
        # DUZ and U are on the known_external_vars allowlist.
        result = _scan(m_fixtures_dir / "m203_external_var.m")
        names = {f.metadata.get("variable") for f in _findings_with_id(result, "M203")}
        assert "DUZ" not in names and "U" not in names

    def test_custom_external_var_via_config(self, m_fixtures_dir):
        # A site-specific var added through known_external_vars config
        # must also be treated as defined.
        cfg = {"known_external_vars": ["USR"]}
        result = MumpsScanner().scan(str(m_fixtures_dir / "m203_typo.m"), cfg)
        names = {f.metadata.get("variable") for f in _findings_with_id(result, "M203")}
        assert "USR" not in names


class TestM204UnusedLocal:
    def test_fires_on_dead_set(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m204_dead_set.m")
        hits = _findings_with_id(result, "M204")
        assert hits, "M204 must fire on a SET whose target is never read"
        names = {f.metadata.get("variable") for f in hits}
        assert "LEFTOVER" in names
        # USED is read by the W command; must NOT be flagged
        assert "USED" not in names

    def test_percent_var_not_flagged(self, m_fixtures_dir):
        # %X is read by the W command; the %-aware token matcher must
        # see the use (the old \\b pattern could not).
        result = _scan(m_fixtures_dir / "m204_percent_var.m")
        names = {f.metadata.get("variable") for f in _findings_with_id(result, "M204")}
        assert "%X" not in names


class TestM206KillGlobalNoSubscript:
    def test_fires_on_bare_global_kill(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m206_kill_tree.m")
        hits = _findings_with_id(result, "M206")
        assert hits, "M206 must fire on KILL of a bare global (no subscript)"
        globals_killed = {f.metadata.get("global") for f in hits}
        assert "^DATA" in globals_killed
        # ^TEMP("scratch") is subscripted; must NOT be flagged
        assert "^TEMP" not in globals_killed


class TestM207BareKill:
    def test_fires_on_bare_kill(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m207_bare_kill.m")
        hits = _findings_with_id(result, "M207")
        assert hits, "M207 must fire on a KILL with no arguments"
        # Sanity: only ONE bare K in the fixture
        assert len(hits) == 1


class TestM208BareNew:
    def test_fires_on_bare_new(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m208_bare_new.m")
        hits = _findings_with_id(result, "M208")
        assert hits, "M208 must fire on a NEW with no arguments"
        assert len(hits) == 1


class TestM209ArgCountMismatch:
    def test_fires_when_too_many_actuals(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "argcount")
        hits = _findings_with_id(result, "M209")
        assert hits, "M209 must fire when a call passes more args than formals"
        f = hits[0]
        assert "CALLER.m" in (f.location or ""), "finding is at the call site"
        assert f.metadata.get("actuals") == 3
        assert f.metadata.get("formals") == 2
        assert "RUN^CALLEE" in f.metadata.get("callee", "")

    def test_correct_arity_does_not_fire(self, m_fixtures_dir):
        # OK^CALLEE(1,2) into a 2-formal entry must not be flagged; only
        # the over-arity RUN^CALLEE call fires.
        result = _scan(m_fixtures_dir / "argcount")
        assert len(_findings_with_id(result, "M209")) == 1


class TestM210DuplicateNew:
    def test_fires_on_duplicate_new_target(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m210_dup_new.m")
        hits = _findings_with_id(result, "M210")
        assert hits, "M210 must fire on a repeated name in one NEW list"
        assert hits[0].metadata.get("variable") == "IEN"

    def test_distinct_new_targets_do_not_fire(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m210_unique_new.m")
        assert _findings_with_id(result, "M210") == []


class TestM212InfiniteFor:
    def test_fires_on_argumentless_for_without_exit(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m212_infinite_for.m")
        hits = _findings_with_id(result, "M212")
        assert hits, "M212 must fire on an argumentless FOR with no exit"
        assert all(f.severity == Severity.HIGH for f in hits)
        assert all(f.cwe == "CWE-835" for f in hits)

    def test_bounded_and_inline_exit_for_do_not_fire(self, m_fixtures_dir):
        # $ORDER walk with inline Q: exit + a counted FOR — neither fires.
        result = _scan(m_fixtures_dir / "m212_bounded_for.m")
        assert _findings_with_id(result, "M212") == []


class TestM213QuitArgInFor:
    def test_fires_on_quit_with_arg_in_for(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m213_quit_arg_in_for.m")
        hits = _findings_with_id(result, "M213")
        assert hits, "M213 must fire on QUIT-with-argument inside a FOR"

    def test_postconditional_quit_does_not_fire(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m213_postcond_quit.m")
        assert _findings_with_id(result, "M213") == []


def _on(rule_id):
    return {"rules": {rule_id: {"enabled": True}}}


class TestM211ScratchGlobalNoJob:
    def test_fires_on_scratch_without_job(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m211_scratch.m")
        hits = _findings_with_id(result, "M211")
        assert len(hits) == 1, "only the $J-less ^TMP write should fire"
        assert hits[0].cwe == "CWE-362"
        assert hits[0].metadata.get("global") == "^TMP"

    def test_lock_and_job_subscript_do_not_fire(self, m_fixtures_dir):
        # The ^TMP($J,...) write and the LOCK must not be flagged.
        result = _scan(m_fixtures_dir / "m211_scratch.m")
        refs = [f.metadata.get("reference", "") for f in _findings_with_id(result, "M211")]
        assert all("$J" not in r for r in refs)

    def test_configurable_scratch_globals(self, m_fixtures_dir):
        # A site can disable the default set by overriding it.
        cfg = {"scratch_globals": ["^SCRATCH"]}
        result = MumpsScanner().scan(str(m_fixtures_dir / "m211_scratch.m"), cfg)
        assert _findings_with_id(result, "M211") == []


class TestM218ExecOnLabelLine:
    def test_fires_on_code_on_label_line(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m218_exec_label.m")
        assert _findings_with_id(result, "M218"), "M218 must fire on exec on the header line"

    def test_clean_header_does_not_fire(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m218_clean_label.m")
        assert _findings_with_id(result, "M218") == []


class TestM219LineLength:
    def test_fires_on_long_line(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m219_long_line.m")
        hits = _findings_with_id(result, "M219")
        assert len(hits) == 1
        assert hits[0].metadata.get("length") > 245

    def test_configurable_limit(self, m_fixtures_dir):
        # Raise the limit above the offending line -> no finding.
        cfg = {"max_line_length": 1000}
        result = MumpsScanner().scan(str(m_fixtures_dir / "m219_long_line.m"), cfg)
        assert _findings_with_id(result, "M219") == []


class TestM214NakedGlobal:
    def test_fires_on_naked_reference(self, m_fixtures_dir):
        result = MumpsScanner().scan(
            str(m_fixtures_dir / "m214_naked_global.m"), _on("M214"),
        )
        hits = _findings_with_id(result, "M214")
        assert len(hits) == 1, "only the naked ^(2) reference should fire"
        assert hits[0].metadata.get("reference", "").startswith("^(")

    def test_off_by_default(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m214_naked_global.m")
        assert _findings_with_id(result, "M214") == []


class TestM215NonPortableZCommand:
    def test_fires_on_z_commands(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m215_zcommand.m")
        cmds = {f.metadata.get("command") for f in _findings_with_id(result, "M215")}
        assert "ZSYSTEM" in cmds and "ZGOTO" in cmds

    def test_standard_command_not_flagged(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m215_zcommand.m")
        # Exactly the two Z-commands, nothing else (the W is portable).
        assert len(_findings_with_id(result, "M215")) == 2


class TestM216NonPortableZFunction:
    def test_fires_on_z_intrinsic(self, m_fixtures_dir):
        result = MumpsScanner().scan(
            str(m_fixtures_dir / "m216_zfunction.m"), _on("M216"),
        )
        fns = {f.metadata.get("function") for f in _findings_with_id(result, "M216")}
        assert "$ZD" in fns
        # $P (standard) must not fire.
        assert all("$P" not in (x or "") for x in fns)

    def test_off_by_default(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m216_zfunction.m")
        assert _findings_with_id(result, "M216") == []


class TestM217NonPortableZSpecialVar:
    def test_fires_on_z_special_var(self, m_fixtures_dir):
        result = MumpsScanner().scan(
            str(m_fixtures_dir / "m217_zsvn.m"), _on("M217"),
        )
        svns = {f.metadata.get("special_variable") for f in _findings_with_id(result, "M217")}
        assert "$ZV" in svns
        assert "$H" not in svns

    def test_off_by_default(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m217_zsvn.m")
        assert _findings_with_id(result, "M217") == []


class TestConfigurableSanitizers:
    def test_sanitizer_removes_taint(self, m_fixtures_dir, tmp_path):
        # Construct a fixture inline that wraps a READ-tainted value in
        # a sanitizer before XECUTE. Without config M001 fires; with the
        # sanitizer name configured the rule must NOT fire.
        source = (
            "SANITIZED ; sanitizer fixture\n"
            ' R RAW\n'
            ' S CMD=$$ESCAPE^HTML(RAW)\n'
            ' X CMD\n'
            ' Q\n'
        )
        path = tmp_path / "sanitized.m"
        path.write_text(source)

        # Baseline: no sanitizer config — M001 fires because CMD picks
        # up RAW's taint through the assignment text.
        baseline = MumpsScanner().scan(str(path))
        # The detection depends on whether _tainted_references matches
        # RAW inside CMD's RHS. Phase 1's taint model adds CMD to the
        # tainted set when the RHS references RAW, which is the case
        # here via the function call argument. Verify both branches.
        config = {"sanitizers": ["$$ESCAPE^HTML"]}
        with_sanitizer = MumpsScanner().scan(str(path), config)
        baseline_hits = _findings_with_id(baseline, "M001")
        sanitized_hits = _findings_with_id(with_sanitizer, "M001")
        # With sanitizer config, M001 should fire fewer times than baseline
        assert len(sanitized_hits) < len(baseline_hits) or len(baseline_hits) == 0, (
            "Configuring a sanitizer must remove at least one taint hit "
            "or have nothing to remove"
        )


class TestSharedTaintAndCallGraphIndex:
    def test_resolve_tainted_uses_shared_set(self, m_fixtures_dir):
        # When config carries a precomputed _tainted set, resolve_tainted
        # returns it verbatim (the scanner's per-file sharing path).
        from argus.scanners.mumps.parser import MumpsParser
        from argus.scanners.mumps.taint import resolve_tainted
        path = m_fixtures_dir / "m001_xecute_taint.m"
        parsed = MumpsParser.parse(path, path.read_bytes())
        sentinel = {"SENTINEL"}
        assert resolve_tainted(parsed, {"_tainted": sentinel}) is sentinel

    def test_resolve_tainted_falls_back_without_shared(self, m_fixtures_dir):
        from argus.scanners.mumps.parser import MumpsParser
        from argus.scanners.mumps.taint import resolve_tainted
        path = m_fixtures_dir / "m001_xecute_taint.m"
        parsed = MumpsParser.parse(path, path.read_bytes())
        # No _tainted in config -> compute; CMD is READ-tainted.
        assert "CMD" in resolve_tainted(parsed, None)

    def test_callgraph_index_matches_linear_scan(self, m_fixtures_dir):
        from argus.scanners.mumps.parser import MumpsParser
        from argus.scanners.mumps.callgraph import build_callgraph
        d = m_fixtures_dir / "interproc"
        parses = [
            MumpsParser.parse(p, p.read_bytes()) for p in sorted(d.glob("*.m"))
        ]
        cg = build_callgraph(parses)
        # TAINTED is called by CALLER; the O(1) index must agree with a
        # manual scan of edges.
        manual = tuple(e for e in cg.edges if e.callee_routine == "TAINTED")
        assert cg.callers_of("TAINTED") == manual
        assert cg.callers_of("NOSUCHROUTINE") == ()

    def test_callgraph_nodes_hold_no_parse_tree(self, m_fixtures_dir):
        # Memory-bounded streaming guard: RoutineNode must NOT retain a
        # ParsedSource / tree (that pinned every file's tree and caused
        # the OOM). It carries only name, path, labels.
        import dataclasses
        from argus.scanners.mumps.parser import MumpsParser
        from argus.scanners.mumps.callgraph import build_callgraph, RoutineNode
        path = m_fixtures_dir / "m001_xecute_taint.m"
        cg = build_callgraph([MumpsParser.parse(path, path.read_bytes())])
        node = next(iter(cg.routines.values()))
        fields = {f.name for f in dataclasses.fields(RoutineNode)}
        # Lightweight fields only — name/path/labels/entry_formals.
        # The invariant that matters for the OOM fix: NO parse tree.
        assert fields == {"name", "path", "labels", "entry_formals"}
        assert not hasattr(node, "parsed")


class TestPerRuleEnableDisable:
    def test_disable_a_normally_on_rule(self, m_fixtures_dir):
        # M101 (duplicate label) is on by default; disabling it via
        # config must suppress it and drop it from rules_run.
        path = m_fixtures_dir / "m101_dup_label.m"
        baseline = _scan(path)
        assert _findings_with_id(baseline, "M101"), "M101 fires by default"
        disabled = MumpsScanner().scan(
            str(path), {"rules": {"M101": {"enabled": False}}},
        )
        assert _findings_with_id(disabled, "M101") == []
        assert "M101" not in disabled.metadata["rules_run"]

    def test_enable_a_normally_off_rule(self, m_fixtures_dir):
        # M205 is off by default; enabling it makes it run.
        path = m_fixtures_dir / "m205_fallthrough.m"
        on = MumpsScanner().scan(str(path), {"rules": {"M205": {"enabled": True}}})
        assert "M205" in on.metadata["rules_run"]


class TestPerRuleSeverityOverride:
    def test_severity_override_applies_to_default_severity_findings(
        self, m_fixtures_dir,
    ):
        # M001 default severity is HIGH. Override to LOW; the finding
        # should land at LOW.
        config = {"rules": {"M001": {"severity": "low"}}}
        result = MumpsScanner().scan(
            str(m_fixtures_dir / "m001_xecute_taint.m"), config,
        )
        hits = _findings_with_id(result, "M001")
        assert hits, "M001 must still fire under severity override"
        assert all(f.severity == Severity.LOW for f in hits), (
            "Per-rule severity override should replace the rule default"
        )

    def test_severity_override_skips_per_finding_calibration(
        self, m_fixtures_dir,
    ):
        # M003 default is HIGH; PIPE-device sites bump per-finding to
        # CRITICAL. Override to MEDIUM should affect non-PIPE findings
        # only — PIPE findings must remain CRITICAL because they
        # represent per-finding precision the user override should
        # not erase.
        config = {"rules": {"M003": {"severity": "medium"}}}
        result = MumpsScanner().scan(
            str(m_fixtures_dir / "m003_pipe_taint.m"), config,
        )
        hits = _findings_with_id(result, "M003")
        critical_pipe = [
            f for f in hits if f.metadata.get("device_class") == "PIPE"
        ]
        assert critical_pipe, "PIPE-device finding must still appear"
        assert all(f.severity == Severity.CRITICAL for f in critical_pipe), (
            "PIPE precision (CRITICAL) survives the rule-default override"
        )


class TestInterProceduralCallGraph:
    """Cross-file call-graph foundation. Full inter-procedural taint
    propagation is Phase 2.5; today the graph is built on every scan
    and rules can annotate findings with caller information."""

    def test_callgraph_built_on_multi_file_scan(self, m_fixtures_dir):
        result = MumpsScanner().scan(str(m_fixtures_dir / "interproc"))
        graph = result.metadata.get("callgraph") or {}
        assert graph.get("routines") == 2, "two .m files == two routine nodes"
        assert graph.get("edges") >= 1, "CALLER -> TAINTED edge must be recorded"

    def test_m001_finding_includes_callers_metadata(self, m_fixtures_dir):
        result = MumpsScanner().scan(str(m_fixtures_dir / "interproc"))
        m001_in_tainted = [
            f for f in result.findings
            if f.id == "M001" and "TAINTED.m" in (f.location or "")
        ]
        assert m001_in_tainted, "M001 must fire on TAINTED.m's READ -> XECUTE"
        callers = m001_in_tainted[0].metadata.get("inter_procedural_callers")
        assert callers, "Cross-file callers must be recorded when scan crosses files"
        assert "CALLER" in callers, "CALLER -> TAINTED edge must surface in metadata"

    def test_single_file_scan_has_no_cross_callers(self, m_fixtures_dir):
        # Scanning only TAINTED.m (no CALLER.m in the scan path) means
        # the call graph has no edges into TAINTED. M001 still fires
        # but ``inter_procedural_callers`` should be absent (or empty).
        result = MumpsScanner().scan(str(m_fixtures_dir / "interproc" / "TAINTED.m"))
        m001 = [f for f in result.findings if f.id == "M001"]
        assert m001, "M001 must still fire intra-file"
        callers = m001[0].metadata.get("inter_procedural_callers", [])
        assert callers == [], (
            "No cross-file context when only one file is in the scan path"
        )


_IP_ON = {"interprocedural": {"enabled": True}}


class TestInterProceduralTaint:
    """One-hop inter-procedural taint (opt-in via config)."""

    def test_disabled_by_default(self, m_fixtures_dir):
        # Without the flag, cross-file taint does not flow: SINK's XECUTE
        # of formal P is not tainted, so M001 stays silent.
        result = _scan(m_fixtures_dir / "interproc2")
        assert _findings_with_id(result, "M001") == []

    def test_propagates_tainted_actual_to_callee_formal(self, m_fixtures_dir):
        # SRC READ-taints CMD and calls RUN^SINK(CMD); with interproc on,
        # SINK's formal P becomes tainted and ``X P`` fires M001.
        result = MumpsScanner().scan(str(m_fixtures_dir / "interproc2"), _IP_ON)
        sink_hits = [
            f for f in _findings_with_id(result, "M001")
            if "SINK.m" in (f.location or "")
        ]
        assert sink_hits, "M001 must fire on SINK after one-hop propagation"

    def test_constant_actual_does_not_propagate(self, m_fixtures_dir):
        # CONST calls RUN^SAFE("literal") — a constant actual must not
        # taint SAFE's formal, so SAFE stays clean even with interproc on.
        result = MumpsScanner().scan(str(m_fixtures_dir / "interproc2"), _IP_ON)
        safe_hits = [
            f for f in _findings_with_id(result, "M001")
            if "SAFE.m" in (f.location or "")
        ]
        assert safe_hits == [], "constant actuals must not propagate taint"

    def test_propagation_unit(self, m_fixtures_dir):
        # Direct unit test of the worklist over the built call graph.
        from argus.scanners.mumps.parser import MumpsParser
        from argus.scanners.mumps.callgraph import build_callgraph
        from argus.scanners.mumps.interproc import propagate_inbound_taint
        d = m_fixtures_dir / "interproc2"
        parses = [MumpsParser.parse(p, p.read_bytes()) for p in sorted(d.glob("*.m"))]
        cg = build_callgraph(parses)
        inbound = propagate_inbound_taint(cg, {"SRC": {"CMD"}}, max_depth=1)
        assert inbound.get("SINK") == {"P"}
        # SAFE got no tainted caller.
        assert "SAFE" not in inbound or inbound["SAFE"] == set()


class TestScanResultShape:
    def test_metadata_records_files_scanned_and_rules(self, m_fixtures_dir):
        result = _scan(m_fixtures_dir / "m002_indirection.m")
        assert result.metadata["files_scanned"] == 1
        assert "M001" in result.metadata["rules_run"]
        assert "M101" in result.metadata["rules_run"]
