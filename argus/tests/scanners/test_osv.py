"""Tests for argus.scanners.osv — OsvScanner."""

import pytest

from argus.core.models import Severity
from argus.core.scanner_template import ScanPaths
from argus.scanners.osv import OsvScanner


_LOCAL = ScanPaths(workspace=".", output="/tmp/out.json")
_CONTAINER = ScanPaths(workspace="/workspace", output="/output/results.json")


class TestOsvParseResults:
    """Test OsvScanner.parse_results with fixture data."""

    def test_parse_results_with_findings(self, fixtures_dir):
        scanner = OsvScanner()
        path = fixtures_dir / "osv" / "results-with-findings.json"
        findings = scanner.parse_results(path)

        assert len(findings) == 4

        severities = [f.severity for f in findings]
        assert severities.count(Severity.CRITICAL) == 1
        assert severities.count(Severity.HIGH) == 1
        assert severities.count(Severity.MEDIUM) == 1
        assert severities.count(Severity.LOW) == 1

    def test_parse_results_zero_findings(self, fixtures_dir):
        scanner = OsvScanner()
        path = fixtures_dir / "osv" / "results-zero-findings.json"
        findings = scanner.parse_results(path)

        assert len(findings) == 0

    def test_finding_fields(self, fixtures_dir):
        scanner = OsvScanner()
        path = fixtures_dir / "osv" / "results-with-findings.json"
        findings = scanner.parse_results(path)

        # CRITICAL finding is lodash command injection
        crit = [f for f in findings if f.severity == Severity.CRITICAL][0]
        assert crit.id == "GHSA-jfh8-c2jp-5v3q"
        assert crit.cve == "CVE-2021-23337"
        assert crit.cwe == "CWE-77"
        assert crit.scanner == "osv"
        assert crit.metadata["package_name"] == "lodash"

        # LOW finding is pip
        low = [f for f in findings if f.severity == Severity.LOW][0]
        assert low.metadata["package_name"] == "pip"


class TestOsvScannerMeta:
    """Test OsvScanner metadata methods."""

    def test_name(self):
        assert OsvScanner().name == "osv"

    def test_install_command(self):
        cmd = OsvScanner().install_command()
        assert cmd is not None

    def test_supports_sbom(self):
        assert OsvScanner.supports_sbom is True

    def test_parse_results_succeeds_when_json_valid_regardless_of_exit_code(self, fixtures_dir):
        """Acceptance criterion: OSV exits 1 when vulnerabilities are
        found (it's the documented happy path). The engine parses
        ``results.json`` whenever the file exists — exit code is
        irrelevant. This test locks in that the parser successfully
        extracts findings from real OSV output that came out of an
        exit-1 run; if it ever stops doing so, the user sees
        '0 findings' on a vulnerable workspace."""
        scanner = OsvScanner()
        path = fixtures_dir / "osv" / "results-with-findings.json"
        findings = scanner.parse_results(path)
        # Fixture is captured from a real osv-scanner exit-1 run.
        # 4 findings means: 1 critical + 1 high + 1 medium + 1 low.
        assert len(findings) == 4
        assert all(f.scanner == "osv" for f in findings)

    def test_parse_results_zero_findings_returns_empty_list_no_exception(self, fixtures_dir):
        """OSV exits 0 with an empty ``results`` array when nothing's
        vulnerable. Parser returns [] cleanly — must NOT raise (a raise
        would be misclassified as parse_failed by the engine)."""
        scanner = OsvScanner()
        path = fixtures_dir / "osv" / "results-zero-findings.json"
        findings = scanner.parse_results(path)
        assert findings == []

    def test_parse_results_handles_non_ascii_utf8_bytes(self, tmp_path):
        """Bug 2 regression: OSV vulnerability summaries and file paths
        can contain non-ASCII characters (CVE titles in non-English
        locales, paths with unicode segments, contributor names with
        accents). The parser reads the file with explicit UTF-8 so
        Windows hosts (default cp1252) don't raise
        UnicodeDecodeError on bytes like 0x8f that decode fine in
        UTF-8 but not in cp1252."""
        import json
        scanner = OsvScanner()
        f = tmp_path / "results.json"
        # 'café' contains 0xc3 0xa9 in UTF-8 — both bytes are
        # invalid in cp1252's mapping (0xc3 is valid but 0xa9
        # decodes differently and the *combination* breaks). The
        # crash byte the user hit was 0x8f at position 18203 — same
        # category of failure mode.
        f.write_text(
            json.dumps({
                "results": [{
                    "source": {"path": "/src/café/Krürzungen.json"},
                    "packages": [{
                        "package": {
                            "name": "lodash",
                            "version": "4.17.20",
                            "ecosystem": "npm",
                        },
                        "vulnerabilities": [{
                            "id": "GHSA-xxxx",
                            "summary": "Précis: prototype pollution attack — café",
                            "aliases": ["CVE-2021-23337"],
                            "database_specific": {"severity": "HIGH"},
                        }],
                    }],
                }],
            }),
            encoding="utf-8",
        )
        findings = scanner.parse_results(f)
        assert len(findings) == 1
        # The non-ASCII content survived the round-trip — no
        # mojibake, no replacement chars (because the file was
        # genuinely UTF-8 and we read it as UTF-8).
        assert "Précis" in findings[0].title
        assert "café" in findings[0].location

    def test_parse_results_malformed_json_raises_for_engine_to_catch(self, tmp_path):
        """When the fixture is junk, parse_results must raise so the
        engine's parse-failed wrapper can mark
        ``parse_failed=True`` with a useful reason. Silently
        returning [] would hide schema-drift breakages and make every
        OSV run report '0 findings' indefinitely."""
        scanner = OsvScanner()
        bad = tmp_path / "results.json"
        bad.write_text("this is not json at all")
        with pytest.raises((ValueError, Exception)):
            scanner.parse_results(bad)

    def test_container_entrypoint_uses_absolute_path(self):
        """Regression: ``--entrypoint osv-scanner`` (bare) exited 127
        because the official ghcr.io/google/osv-scanner image declares
        ``ENTRYPOINT ["/osv-scanner"]`` (absolute) and Docker's
        ``--entrypoint`` does NOT consult the image's $PATH for bare
        names. We pin the absolute path so the engine's
        ``--entrypoint`` override resolves the binary the same way the
        image's own ENTRYPOINT does."""
        assert OsvScanner.container_entrypoint == "/osv-scanner"
        assert OsvScanner.container_entrypoint.startswith("/"), (
            "container_entrypoint must be absolute — Docker --entrypoint "
            "does not resolve bare names against the image $PATH"
        )


class TestOsvSbomMode:
    """SBOM mode (config['sbom_path'] set) → uses ``-L`` (osv-scanner v2)."""

    def test_local_uses_sbom_flag(self):
        args = OsvScanner().build_args(_LOCAL, {"sbom_path": "/shared/sbom.json"})
        assert "-L" in args
        assert "/shared/sbom.json" in args
        # SBOM mode never adds --recursive or the workspace path.
        assert "--recursive" not in args
        assert "." not in args

    def test_container_uses_sbom_flag_with_mount_path(self):
        args = OsvScanner().build_args(_CONTAINER, {
            "sbom_path": "/host/sbom.json",
            "sbom_mount_path": "/sbom/sbom.json",
        })
        assert "-L" in args
        assert "/sbom/sbom.json" in args
        assert "scan" in args
        assert "--format" in args

    def test_sbom_mode_ignores_lockfile_and_recursive(self):
        args = OsvScanner().build_args(_CONTAINER, {
            "sbom_path": "/host/sbom.json",
            "sbom_mount_path": "/sbom/sbom.json",
            "lockfile": "requirements.txt",
            "recursive": True,
        })
        assert "-L" in args
        assert "/sbom/sbom.json" in args
        assert "requirements.txt" not in " ".join(args)
        assert "--recursive" not in args

    def test_container_sbom_fallback_to_workspace_path(self):
        """No sbom_mount_path → fall back to ``<workspace>/<sbom_path>``."""
        args = OsvScanner().build_args(_CONTAINER, {
            "sbom_path": "my-sbom.spdx.json",
        })
        assert "-L" in args
        assert "/workspace/my-sbom.spdx.json" in args


class TestOsvSourceMode:
    """Non-SBOM mode — ``scan source`` with optional lockfile / recursive / config."""

    def test_config_file_passed_as_workspace_relative_config_flag(self):
        args = OsvScanner().build_args(_CONTAINER, {
            "config_file": "osv-scanner.toml",
        })
        assert "--config" in args
        assert "/workspace/osv-scanner.toml" in args
        assert "source" in args  # source mode

    def test_lockfile_disables_recursive(self):
        args = OsvScanner().build_args(_CONTAINER, {"lockfile": "requirements.txt"})
        assert "-L" in args
        assert "/workspace/requirements.txt" in args
        # When -L lockfile is set, the workspace path and --recursive are dropped.
        assert "--recursive" not in args

    def test_recursive_default_true(self):
        args = OsvScanner().build_args(_CONTAINER, {})
        assert "--recursive" in args
        assert "/workspace" in args
