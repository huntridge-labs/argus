"""Regression tests: a foreign-architecture image must be scannable.

Scanners read image layers; they never execute them. An arm64-only image
is therefore perfectly scannable from an amd64 runner — but every step
that touches the image (``docker pull``, ``docker image inspect``, trivy,
grype, syft) resolves a manifest against the *host's* architecture by
default, so the scan failed outright for anyone publishing multi-arch or
arm64-only images.

Two halves to the fix:

* ``containers.platform`` / ``--platform`` pins the variant explicitly and
  is threaded to every tool that accepts it;
* when it is not set, a failed pull reads the image's published platforms
  from the registry manifest and retries against one of them, instead of
  the old unconditional ``--platform linux/amd64`` retry that could only
  ever rescue amd64 images.
"""

from __future__ import annotations

import argparse

import pytest

from argus.cli import _load_container_config
from argus.container.scanner import _platform_args, _run_grype, _run_syft, _run_trivy
from argus.core.schema import _CONTAINERS_KEYS


def _completed(returncode: int = 0, stdout: str = "", stderr: str = ""):
    import subprocess
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=stderr,
    )


class TestPlatformArgs:
    """The shared flag builder."""

    def test_absent_when_unset(self):
        assert _platform_args({}) == []
        assert _platform_args(None) == []

    def test_absent_when_empty_string(self):
        """An unset workflow input arrives as '' — must not become a flag."""
        assert _platform_args({"platform": ""}) == []

    def test_present_when_set(self):
        assert _platform_args({"platform": "linux/arm64"}) == [
            "--platform", "linux/arm64",
        ]


class TestPlatformReachesEachTool:
    """trivy, grype and syft all accept --platform; all three must get it."""

    def _capture(self, monkeypatch, tool):
        """Force the local-binary branch and capture the argv."""
        captured: dict = {}

        monkeypatch.setattr(
            "argus.container.scanner.shutil.which",
            lambda name: f"/usr/local/bin/{name}" if name == tool else None,
        )

        def fake_run(cmd, **_kwargs):
            captured["cmd"] = cmd
            return _completed(returncode=0)

        monkeypatch.setattr("subprocess.run", fake_run)
        return captured

    def test_trivy_receives_platform(self, tmp_path, monkeypatch):
        captured = self._capture(monkeypatch, "trivy")
        monkeypatch.setattr(
            "argus.container.scanner._validate_scanner_output",
            lambda *_a, **_kw: None,
        )
        monkeypatch.setattr(
            "argus.container.scanner._parser.parse_trivy_results",
            lambda _f: [],
        )
        _run_trivy(
            "arm64v8/alpine:3.18", tmp_path, local=False,
            config={"platform": "linux/arm64"},
        )
        cmd = captured["cmd"]
        assert "--platform" in cmd
        assert cmd[cmd.index("--platform") + 1] == "linux/arm64"
        # The flag must precede the positional image ref.
        assert cmd.index("--platform") < cmd.index("arm64v8/alpine:3.18")

    def test_grype_receives_platform(self, tmp_path, monkeypatch):
        captured = self._capture(monkeypatch, "grype")
        monkeypatch.setattr(
            "argus.container.scanner._validate_scanner_output",
            lambda *_a, **_kw: None,
        )
        monkeypatch.setattr(
            "argus.container.scanner._parser.parse_grype_results",
            lambda _f: [],
        )
        _run_grype(
            "arm64v8/alpine:3.18", tmp_path, local=False,
            config={"platform": "linux/arm64"},
        )
        cmd = captured["cmd"]
        assert cmd[cmd.index("--platform") + 1] == "linux/arm64"
        # grype takes a scheme-prefixed target, which must stay last.
        assert cmd.index("--platform") < cmd.index("registry:arm64v8/alpine:3.18")

    def test_syft_receives_platform(self, tmp_path, monkeypatch):
        captured = self._capture(monkeypatch, "syft")
        _run_syft(
            "arm64v8/alpine:3.18", tmp_path, local=False,
            config={"platform": "linux/arm64"},
        )
        cmd = captured["cmd"]
        assert cmd[cmd.index("--platform") + 1] == "linux/arm64"

    @pytest.mark.parametrize("tool", ["trivy", "grype", "syft"])
    def test_no_platform_flag_when_unset(self, tool, tmp_path, monkeypatch):
        """Unset must mean "let the tool decide" — not a literal empty flag."""
        captured = self._capture(monkeypatch, tool)
        monkeypatch.setattr(
            "argus.container.scanner._validate_scanner_output",
            lambda *_a, **_kw: None,
        )
        monkeypatch.setattr(
            "argus.container.scanner._parser.parse_trivy_results", lambda _f: [],
        )
        monkeypatch.setattr(
            "argus.container.scanner._parser.parse_grype_results", lambda _f: [],
        )
        runner = {"trivy": _run_trivy, "grype": _run_grype, "syft": _run_syft}[tool]
        runner("alpine:3.18", tmp_path, local=False, config={})
        assert "--platform" not in captured["cmd"]


class TestExposureAndServicesHonorPlatform:
    """The two sub-scanners that need the image in the local daemon."""

    def test_exposure_passes_platform_to_pull(self, monkeypatch):
        from argus import container_runtime as rt_mod
        from argus.scanners.container import ContainerScanner

        seen: dict = {}

        monkeypatch.setattr(rt_mod, "is_available", lambda: True)
        monkeypatch.setattr(rt_mod, "runtime_cmd", lambda: "docker")

        def fake_pull(image, policy="if-not-present", platform=None):
            seen["platform"] = platform
            return False  # short-circuit before docker inspect

        monkeypatch.setattr(rt_mod, "pull_image", fake_pull)

        ContainerScanner()._scan_exposed_ports(
            "arm64v8/alpine:3.18", {"platform": "linux/arm64"},
        )
        assert seen["platform"] == "linux/arm64"

    def test_services_passes_platform_to_pull(self, monkeypatch):
        from argus import container_runtime as rt_mod
        from argus.scanners.container import ContainerScanner

        seen: dict = {}

        monkeypatch.setattr(rt_mod, "is_available", lambda: True)
        monkeypatch.setattr(rt_mod, "runtime_cmd", lambda: "docker")

        def fake_pull(image, policy="if-not-present", platform=None):
            seen["platform"] = platform
            return False

        monkeypatch.setattr(rt_mod, "pull_image", fake_pull)

        ContainerScanner()._scan_services(
            "arm64v8/alpine:3.18", {"platform": "linux/arm64"},
        )
        assert seen["platform"] == "linux/arm64"


class TestPlatformConfigPlumbing:

    def _args(self, **overrides):
        defaults = {
            "config": None,
            "images": ["arm64v8/alpine:3.18"],
            "discover": None,
            "scanners": None,
            "platform": None,
            "vex": None,
            "list": False,
        }
        defaults.update(overrides)
        return argparse.Namespace(**defaults)

    def test_cli_flag_lands_in_config(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        config = _load_container_config(self._args(platform="linux/arm64"))
        assert config["platform"] == "linux/arm64"

    def test_config_file_value_is_read(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "argus.yml").write_text(
            "containers:\n"
            "  images:\n"
            "    - image: arm64v8/alpine:3.18\n"
            "  platform: linux/arm64\n"
        )
        config = _load_container_config(self._args(images=None, config="argus.yml"))
        assert config["platform"] == "linux/arm64"

    def test_cli_flag_overrides_the_config_file(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "argus.yml").write_text(
            "containers:\n"
            "  images:\n"
            "    - image: app:1\n"
            "  platform: linux/amd64\n"
        )
        config = _load_container_config(
            self._args(images=None, config="argus.yml", platform="linux/arm64"),
        )
        assert config["platform"] == "linux/arm64"

    def test_schema_accepts_the_key(self):
        """Otherwise `argus validate` warns on a key we ourselves document."""
        assert "platform" in _CONTAINERS_KEYS


# =====================================================================
# PR #427 review follow-ups
# =====================================================================

class TestPlatformReachesTheSdkScannerPath:
    """``containers.platform`` must reach trivy/grype/syft on both paths.

    ``argus/scanners/container.py`` read it only for the ``exposure`` and
    ``services`` sub-scanners, so a single run mixed platform-pinned
    attack-surface results with host-resolved CVE results for different
    variants of the same image — while the config reference stated the
    value "is threaded to Trivy, Grype and Syft as their native
    ``--platform`` flag".
    """

    def _run_with_captured_argv(self, monkeypatch, scanners):
        from argus.scanners.container import ContainerScanner

        captured: list[list[str]] = []

        def fake_run(cmd, *a, **kw):
            captured.append(cmd)
            return _completed(returncode=0)

        monkeypatch.setattr(
            "argus.scanners.container.shutil.which", lambda name: f"/usr/bin/{name}",
        )
        monkeypatch.setattr(
            "argus.scanners.container.subprocess.run", fake_run,
        )
        ContainerScanner().scan(".", {
            "image_ref": "app:1",
            "platform": "linux/arm64",
            "scanners": scanners,
        })
        return captured

    @pytest.mark.parametrize("tool", ["trivy", "grype", "syft"])
    def test_each_tool_receives_the_flag(self, monkeypatch, tool):
        captured = self._run_with_captured_argv(monkeypatch, [tool])
        argv = next(c for c in captured if c and c[0] == tool)
        assert "--platform" in argv, f"{tool} argv: {argv}"
        assert argv[argv.index("--platform") + 1] == "linux/arm64"

    def test_no_flag_when_unset(self, monkeypatch):
        from argus.scanners.container import ContainerScanner

        captured: list[list[str]] = []
        monkeypatch.setattr(
            "argus.scanners.container.shutil.which", lambda name: f"/usr/bin/{name}",
        )
        monkeypatch.setattr(
            "argus.scanners.container.subprocess.run",
            lambda cmd, *a, **kw: captured.append(cmd) or _completed(0),
        )
        ContainerScanner().scan(
            ".", {"image_ref": "app:1", "scanners": ["trivy"]},
        )
        assert all("--platform" not in c for c in captured)


class TestSchemaValidatesPlatform:
    """The schema half of the pairing had two gaps."""

    def test_platform_must_be_os_slash_arch(self):
        from argus.core.schema import validate_config

        errors = validate_config({
            "containers": {"images": [{"image": "a:1"}], "platform": 123},
        })
        assert any("platform" in e.path for e in errors), (
            "platform: 123 validated clean and reached trivy as "
            "`--platform 123`"
        )

    @pytest.mark.parametrize(
        "value", ["linux/arm64", "linux/amd64", "linux/arm/v7", "windows/amd64"],
    )
    def test_valid_platform_strings_pass(self, value):
        from argus.core.schema import validate_config

        errors = validate_config({
            "containers": {"images": [{"image": "a:1"}], "platform": value},
        })
        assert not [e for e in errors if "platform" in e.path]

    @pytest.mark.parametrize("value", ["arm64", "linux/", "linux arm64", 123])
    def test_malformed_platform_strings_fail(self, value):
        from argus.core.schema import validate_config

        errors = validate_config({
            "containers": {"images": [{"image": "a:1"}], "platform": value},
        })
        assert [e for e in errors if "platform" in e.path]

    @pytest.mark.parametrize("value", ["", None])
    def test_empty_platform_means_unset_not_invalid(self, value):
        """The schema must not reject what the runtime happily ignores.

        ``_platform_args`` emits no flag for an empty value, and the
        container-scan.yml ``platform`` input defaults to ``''``, so
        ``platform: ""`` is a natural placeholder. Erroring on it would be
        the same schema/runtime drift as the sub-scanner case, just in the
        other direction.
        """
        from argus.core.schema import validate_config

        assert _platform_args({"platform": value}) == []
        errors = validate_config({
            "containers": {"images": [{"image": "a:1"}], "platform": value},
        })
        assert not [e for e in errors if "platform" in e.path]


class TestSchemaMatchesRuntimeNormalisation:
    """`argus validate` must not reject a config the scanner accepts.

    ``validate_sub_scanners`` lowercases and strips; the schema compared
    the raw value, so ``scanners: [Trivy]`` errored in validation and ran
    fine in the scan — drift in exactly the direction the paired test did
    not cover.
    """

    @pytest.mark.parametrize("value", ["Trivy", " GRYPE ", "SyFt"])
    def test_case_and_whitespace_are_normalised_like_the_runtime(self, value):
        from argus.core.schema import validate_config
        from argus.scanners.container import validate_sub_scanners

        assert validate_sub_scanners([value])  # the runtime accepts it
        errors = validate_config({
            "containers": {"images": [{"image": "a:1"}], "scanners": [value]},
        })
        assert not [e for e in errors if "scanners" in e.path], (
            f"schema rejected {value!r} but the scanner runs it"
        )

    def test_a_genuinely_unknown_name_still_fails(self):
        from argus.core.schema import validate_config

        errors = validate_config({
            "containers": {"images": [{"image": "a:1"}], "scanners": ["tryvi"]},
        })
        assert [e for e in errors if "scanners" in e.path]


class TestOnePlatformHelper:
    """Both container paths must share one implementation, not two copies.

    ``argus/container/scanner.py`` already imports ``SUB_SCANNERS`` from
    ``argus/scanners/container.py``, so the dependency runs one way and the
    helper can live in the lower module. Two copies kept in step by hand is
    the drift this PR is otherwise busy removing.
    """

    def test_both_modules_expose_the_same_function(self):
        from argus.container import scanner as upper
        from argus.scanners import container as lower

        assert upper._platform_args is lower._platform_args
