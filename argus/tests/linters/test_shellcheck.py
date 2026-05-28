"""Tests for argus.linters.shellcheck.ShellcheckLinter.

Covers the three behaviours called out in the issue #191 acceptance
criteria: parsing a captured shellcheck JSON fixture into findings,
file-discovery logic (extension + shebang detection), and empty-output
handling. Also locks in the local→container dispatch and the
``execution_failed`` / ``parse_failed`` metadata shapes inherited from
FileDiscoveryScanner.
"""

from __future__ import annotations

import json
import subprocess
from unittest.mock import patch

from argus.core.models import Severity
from argus.linters.shellcheck import (
    ShellcheckLinter,
    discover_shell_files,
    _has_shell_shebang,
)


# A captured-shape shellcheck ``-f json`` payload: one finding per
# upstream level so the parser is exercised across error/warning/info/
# style. Fields match shellcheck's real JSON output.
SAMPLE_SHELLCHECK_JSON = [
    {
        "file": "deploy.sh",
        "line": 3,
        "endLine": 3,
        "column": 6,
        "endColumn": 9,
        "level": "warning",
        "code": 2086,
        "message": "Double quote to prevent globbing and word splitting.",
    },
    {
        "file": "deploy.sh",
        "line": 7,
        "endLine": 7,
        "column": 1,
        "endColumn": 5,
        "level": "error",
        "code": 1009,
        "message": "The mentioned syntax error was in this simple command.",
    },
    {
        "file": "lib/util.bash",
        "line": 12,
        "endLine": 12,
        "column": 3,
        "endColumn": 3,
        "level": "style",
        "code": 2006,
        "message": "Use $(...) notation instead of legacy backticks.",
    },
]


def _completed(stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess(
        args=["shellcheck"], returncode=returncode, stdout=stdout, stderr=stderr,
    )


# ---------------------------------------------------------------- #
# Metadata + protocol surface                                      #
# ---------------------------------------------------------------- #


class TestShellcheckLinterMeta:

    def test_name(self):
        assert ShellcheckLinter().name == "lint-shell"

    def test_category(self):
        assert ShellcheckLinter().category == "linter"

    def test_languages(self):
        assert "shell" in ShellcheckLinter().languages

    def test_install_command_returns_string(self):
        assert isinstance(ShellcheckLinter().install_command(), str)

    def test_binary_attribute(self):
        assert ShellcheckLinter.binary == "shellcheck"

    def test_container_image_declared(self):
        assert ShellcheckLinter.container_image
        assert "shellcheck" in ShellcheckLinter.container_image.lower()

    def test_accept_returncodes_includes_findings_path(self):
        # shellcheck exits 1 when findings exist; that's the happy path.
        assert 1 in ShellcheckLinter.accept_returncodes

    def test_registered_in_linter_registry(self):
        from argus.linters import LINTER_REGISTRY

        assert LINTER_REGISTRY["lint-shell"] is ShellcheckLinter

    def test_registered_in_scanner_registry(self):
        # Linters auto-merge into the scanner registry.
        from argus.scanners import SCANNER_REGISTRY

        assert "lint-shell" in SCANNER_REGISTRY


# ---------------------------------------------------------------- #
# File discovery — shebang sniffing                                #
# ---------------------------------------------------------------- #


class TestShebangDetection:

    def test_plain_sh_shebang(self, tmp_path):
        f = tmp_path / "script"
        f.write_text("#!/bin/sh\necho hi\n")
        assert _has_shell_shebang(f) is True

    def test_bash_shebang(self, tmp_path):
        f = tmp_path / "script"
        f.write_text("#!/bin/bash\necho hi\n")
        assert _has_shell_shebang(f) is True

    def test_env_bash_shebang(self, tmp_path):
        f = tmp_path / "script"
        f.write_text("#!/usr/bin/env bash\necho hi\n")
        assert _has_shell_shebang(f) is True

    def test_env_zsh_shebang(self, tmp_path):
        f = tmp_path / "script"
        f.write_text("#!/usr/bin/env zsh\necho hi\n")
        assert _has_shell_shebang(f) is True

    def test_non_shell_shebang_rejected(self, tmp_path):
        f = tmp_path / "script"
        f.write_text("#!/usr/bin/env python3\nprint('hi')\n")
        assert _has_shell_shebang(f) is False

    def test_no_shebang_rejected(self, tmp_path):
        f = tmp_path / "notes"
        f.write_text("just some text\n")
        assert _has_shell_shebang(f) is False

    def test_empty_file_rejected(self, tmp_path):
        f = tmp_path / "empty"
        f.write_text("")
        assert _has_shell_shebang(f) is False

    def test_missing_file_returns_false(self, tmp_path):
        assert _has_shell_shebang(tmp_path / "does-not-exist") is False


# ---------------------------------------------------------------- #
# File discovery — extension + shebang union                       #
# ---------------------------------------------------------------- #


class TestDiscoverShellFiles:

    def test_discovers_by_extension(self, tmp_path):
        (tmp_path / "a.sh").write_text("echo a")
        (tmp_path / "b.bash").write_text("echo b")
        (tmp_path / "c.zsh").write_text("echo c")
        (tmp_path / "d.ksh").write_text("echo d")
        (tmp_path / "ignore.txt").write_text("not shell")

        found = {p.name for p in discover_shell_files(tmp_path)}
        assert found == {"a.sh", "b.bash", "c.zsh", "d.ksh"}

    def test_discovers_by_shebang_without_extension(self, tmp_path):
        (tmp_path / "configure").write_text("#!/bin/sh\necho hi\n")
        (tmp_path / "readme").write_text("plain text\n")

        found = {p.name for p in discover_shell_files(tmp_path)}
        assert found == {"configure"}

    def test_extension_and_shebang_union_no_duplicates(self, tmp_path):
        # A .sh file with a shebang must appear exactly once.
        (tmp_path / "with_ext.sh").write_text("#!/bin/bash\necho hi\n")
        (tmp_path / "no_ext").write_text("#!/bin/bash\necho hi\n")

        found = sorted(p.name for p in discover_shell_files(tmp_path))
        assert found == ["no_ext", "with_ext.sh"]

    def test_recurses_into_subdirs(self, tmp_path):
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "nested.sh").write_text("echo nested")
        found = {p.name for p in discover_shell_files(tmp_path)}
        assert "nested.sh" in found

    def test_python_file_excluded(self, tmp_path):
        (tmp_path / "app.py").write_text("#!/usr/bin/env python3\nprint('x')\n")
        assert discover_shell_files(tmp_path) == []

    def test_single_file_target_returned_directly(self, tmp_path):
        f = tmp_path / "anything.txt"
        f.write_text("whatever")
        assert discover_shell_files(f) == [f]


# ---------------------------------------------------------------- #
# scan() — parsing the sample fixture                              #
# ---------------------------------------------------------------- #


class TestShellcheckParsing:

    def test_parses_sample_fixture_into_findings(self, tmp_path):
        (tmp_path / "deploy.sh").write_text("#!/bin/sh\necho $x\n")

        def fake_which(b):
            return f"/usr/bin/{b}" if b == "shellcheck" else None

        def fake_run(cmd, **kwargs):
            return _completed(
                stdout=json.dumps(SAMPLE_SHELLCHECK_JSON), returncode=1,
            )

        with patch("argus.core.linter_template.shutil.which", side_effect=fake_which), \
             patch("argus.core.linter_template.subprocess.run", side_effect=fake_run):
            result = ShellcheckLinter().scan(str(tmp_path))

        assert len(result.findings) == 3
        # All findings normalised to INFO per the linter convention.
        assert all(f.severity == Severity.INFO for f in result.findings)
        # Code prefixing: numeric code → SCxxxx id.
        ids = {f.id for f in result.findings}
        assert ids == {"SC2086", "SC1009", "SC2006"}
        # Location is file:line.
        first = next(f for f in result.findings if f.id == "SC2086")
        assert first.location == "deploy.sh:3"
        # Upstream level preserved in metadata.
        assert first.metadata["level"] == "warning"
        assert first.metadata["column"] == 6
        # Findings (exit 1) is the happy path, not a failure.
        assert result.metadata.get("execution_failed") is not True

    def test_missing_code_falls_back_to_generic_id(self, tmp_path):
        (tmp_path / "x.sh").write_text("echo hi")

        def fake_which(b):
            return f"/usr/bin/{b}" if b == "shellcheck" else None

        def fake_run(cmd, **kwargs):
            return _completed(stdout=json.dumps([
                {"file": "x.sh", "line": 1, "level": "info", "message": "msg"}
            ]))

        with patch("argus.core.linter_template.shutil.which", side_effect=fake_which), \
             patch("argus.core.linter_template.subprocess.run", side_effect=fake_run):
            result = ShellcheckLinter().scan(str(tmp_path))

        assert result.findings[0].id == "shellcheck"


# ---------------------------------------------------------------- #
# scan() — discovery + dispatch + edge cases                       #
# ---------------------------------------------------------------- #


class TestShellcheckScan:

    def test_no_shell_files_returns_clean_info_row(self, tmp_path):
        (tmp_path / "readme.md").write_text("# docs")
        result = ShellcheckLinter().scan(str(tmp_path))
        assert result.findings == []
        assert "No shell scripts" in result.metadata.get("info", "")

    def test_local_invocation_uses_json_format(self, tmp_path):
        (tmp_path / "a.sh").write_text("echo hi")
        captured = {}

        def fake_which(b):
            return f"/usr/bin/{b}" if b == "shellcheck" else None

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            return _completed(stdout="[]")

        with patch("argus.core.linter_template.shutil.which", side_effect=fake_which), \
             patch("argus.core.linter_template.subprocess.run", side_effect=fake_run):
            result = ShellcheckLinter().scan(str(tmp_path))

        assert result.metadata["mode"] == "local"
        assert result.metadata["file_count"] == 1
        assert captured["cmd"][0] == "shellcheck"
        assert "-f" in captured["cmd"]
        assert "json" in captured["cmd"]

    def test_container_fallback_when_binary_missing(self, tmp_path):
        (tmp_path / "a.sh").write_text("echo hi")
        captured = {}

        def fake_which(b):
            return "/usr/bin/docker" if b == "docker" else None

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            return _completed(stdout="[]")

        with patch("argus.core.linter_template.shutil.which", side_effect=fake_which), \
             patch("argus.core.linter_template.subprocess.run", side_effect=fake_run):
            result = ShellcheckLinter().scan(str(tmp_path))

        assert result.metadata["mode"] == "container"
        assert captured["cmd"][0] == "docker"
        assert ShellcheckLinter.container_image in captured["cmd"]
        assert "shellcheck" in captured["cmd"]
        assert any(arg.startswith("/workspace/") for arg in captured["cmd"])

    def test_unavailable_when_neither_binary_nor_docker(self, tmp_path):
        (tmp_path / "a.sh").write_text("echo hi")
        with patch("argus.core.linter_template.shutil.which", return_value=None):
            result = ShellcheckLinter().scan(str(tmp_path))
        assert result.metadata["execution_failed"] is True
        assert "shellcheck" in result.metadata["execution_failure_reason"]

    def test_empty_output_with_zero_exit_returns_no_findings(self, tmp_path):
        (tmp_path / "a.sh").write_text("echo hi")

        def fake_which(b):
            return f"/usr/bin/{b}" if b == "shellcheck" else None

        def fake_run(cmd, **kwargs):
            return _completed(stdout="", returncode=0)

        with patch("argus.core.linter_template.shutil.which", side_effect=fake_which), \
             patch("argus.core.linter_template.subprocess.run", side_effect=fake_run):
            result = ShellcheckLinter().scan(str(tmp_path))

        assert result.findings == []
        assert result.metadata.get("execution_failed") is not True

    def test_empty_json_array_returns_no_findings(self, tmp_path):
        (tmp_path / "a.sh").write_text("echo hi")

        def fake_which(b):
            return f"/usr/bin/{b}" if b == "shellcheck" else None

        def fake_run(cmd, **kwargs):
            return _completed(stdout="[]", returncode=0)

        with patch("argus.core.linter_template.shutil.which", side_effect=fake_which), \
             patch("argus.core.linter_template.subprocess.run", side_effect=fake_run):
            result = ShellcheckLinter().scan(str(tmp_path))

        assert result.findings == []

    def test_malformed_json_marks_parse_failed(self, tmp_path):
        (tmp_path / "a.sh").write_text("echo hi")

        def fake_which(b):
            return f"/usr/bin/{b}" if b == "shellcheck" else None

        def fake_run(cmd, **kwargs):
            return _completed(stdout="not really json")

        with patch("argus.core.linter_template.shutil.which", side_effect=fake_which), \
             patch("argus.core.linter_template.subprocess.run", side_effect=fake_run):
            result = ShellcheckLinter().scan(str(tmp_path))

        assert result.metadata["parse_failed"] is True
        assert "JSONDecodeError" in result.metadata["parse_failure_reason"]

    def test_nonzero_exit_empty_stdout_marks_execution_failed(self, tmp_path):
        (tmp_path / "a.sh").write_text("echo hi")

        def fake_which(b):
            return f"/usr/bin/{b}" if b == "shellcheck" else None

        def fake_run(cmd, **kwargs):
            return _completed(stdout="", stderr="boom", returncode=2)

        with patch("argus.core.linter_template.shutil.which", side_effect=fake_which), \
             patch("argus.core.linter_template.subprocess.run", side_effect=fake_run):
            result = ShellcheckLinter().scan(str(tmp_path))

        assert result.metadata["execution_failed"] is True
        assert "boom" in result.metadata["execution_failure_reason"]

    def test_config_options_threaded_into_args(self, tmp_path):
        (tmp_path / "a.sh").write_text("echo hi")
        captured = {}

        def fake_which(b):
            return f"/usr/bin/{b}" if b == "shellcheck" else None

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            return _completed(stdout="[]")

        with patch("argus.core.linter_template.shutil.which", side_effect=fake_which), \
             patch("argus.core.linter_template.subprocess.run", side_effect=fake_run):
            ShellcheckLinter().scan(
                str(tmp_path),
                config={
                    "shell": "bash",
                    "severity": "warning",
                    "exclude_codes": ["SC2086", "SC1090"],
                },
            )

        cmd = captured["cmd"]
        assert "--shell" in cmd and cmd[cmd.index("--shell") + 1] == "bash"
        assert "--severity" in cmd and cmd[cmd.index("--severity") + 1] == "warning"
        assert cmd.count("--exclude") == 2
