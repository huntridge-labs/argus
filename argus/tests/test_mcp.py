"""Tests for the Argus MCP server (argus.mcp).

Covers all tools, resources, and prompts with mocked dependencies.
No real scanning, no Docker, no file I/O beyond tmp_path.
"""

import asyncio
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# MCP is an optional dependency — skip entire module when not installed
pytest.importorskip("mcp", reason="mcp package not installed (pip install argus-security[mcp])")

from argus.mcp import (  # noqa: E402
    argus_classify,
    argus_detect,
    argus_explain_finding,
    argus_init,
    argus_list_scanners,
    argus_scan,
    argus_scan_summary,
    argus_security_review,
    argus_validate,
    create_server,
    read_config,
    read_config_schema,
    read_latest_results,
    fix_findings,
    security_review,
    setup_scanning,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(coro):
    """Run an async coroutine synchronously."""
    return asyncio.run(coro)


def _make_mock_scanner_instance(
    name, *, available=True, description="", category="",
    languages=None, install_cmd=None, container_image="",
):
    """Create a mock scanner instance with the expected attributes."""
    instance = MagicMock()
    instance.name = name
    instance.is_available.return_value = available
    instance.install_command.return_value = install_cmd
    instance.description = description
    instance.category = category
    instance.languages = languages or []
    instance.container_image = container_image
    return instance


def _build_registry(count=16):
    """Build a fake SCANNER_REGISTRY with the given number of entries."""
    registry = {}
    for i in range(count):
        name = f"scanner-{i}"
        instance = _make_mock_scanner_instance(
            name,
            available=True,
            description=f"Scanner {i} description",
            category="sast" if i % 2 == 0 else "secrets",
            languages=["python"],
            install_cmd=f"pip install scanner-{i}",
            container_image=f"image:{i}",
        )
        cls = MagicMock(return_value=instance)
        registry[name] = cls
    return registry


# ---------------------------------------------------------------------------
# TestArgusListScanners
# ---------------------------------------------------------------------------


class TestArgusListScanners:
    """Tests for the argus_list_scanners tool."""

    def test_returns_all_scanners(self):
        registry = _build_registry(16)

        with patch("argus.scanners.SCANNER_REGISTRY", registry):
            with patch("argus.containers.get_image", return_value="mock-image"):
                result = _run(argus_list_scanners())

        data = json.loads(result)
        assert len(data) == 16

    def test_returns_all_expected_fields(self):
        registry = _build_registry(2)

        with patch("argus.scanners.SCANNER_REGISTRY", registry):
            with patch("argus.containers.get_image", return_value="mock-image"):
                result = _run(argus_list_scanners())

        data = json.loads(result)
        expected_fields = {
            "name", "available", "container_image",
            "description", "category", "languages", "install_command",
        }
        for scanner in data:
            assert expected_fields.issubset(scanner.keys()), (
                f"Missing fields: {expected_fields - scanner.keys()}"
            )

    def test_scanner_availability_reflected(self):
        """Scanners with is_available=False should report available=False."""
        instance = _make_mock_scanner_instance(
            "unavailable-scanner", available=False,
            description="desc", category="sast",
        )
        cls = MagicMock(return_value=instance)
        registry = {"unavailable-scanner": cls}

        with patch("argus.scanners.SCANNER_REGISTRY", registry):
            with patch("argus.containers.get_image", return_value=""):
                result = _run(argus_list_scanners())

        data = json.loads(result)
        assert len(data) == 1
        assert data[0]["available"] is False

    def test_container_image_from_get_image(self):
        """Container image should come from get_image, not the scanner attr."""
        instance = _make_mock_scanner_instance(
            "test-scanner", container_image="scanner-attr-image",
        )
        cls = MagicMock(return_value=instance)
        registry = {"test-scanner": cls}

        with patch("argus.scanners.SCANNER_REGISTRY", registry):
            with patch("argus.containers.get_image", return_value="registry-image:1.0"):
                result = _run(argus_list_scanners())

        data = json.loads(result)
        assert data[0]["container_image"] == "registry-image:1.0"

    def test_error_returns_json_error(self):
        """If iteration over SCANNER_REGISTRY fails, return a JSON error."""
        bad_registry = MagicMock()
        bad_registry.items.side_effect = RuntimeError("registry broken")

        with patch("argus.scanners.SCANNER_REGISTRY", bad_registry):
            result = _run(argus_list_scanners())

        data = json.loads(result)
        assert "error" in data


# ---------------------------------------------------------------------------
# TestArgusDetect
# ---------------------------------------------------------------------------


class TestArgusDetect:
    """Tests for the argus_detect tool."""

    def test_returns_detected_signals(self):
        mock_signals = {
            "python": ["app.py", "utils.py"],
            "github-actions": [".github/workflows/ci.yml"],
        }

        with patch("argus.init.detect_project", return_value=mock_signals):
            result = _run(argus_detect(path="/fake/path"))

        data = json.loads(result)
        assert data["python"] == ["app.py", "utils.py"]
        assert "github-actions" in data

    def test_empty_project_returns_empty_signals(self):
        with patch("argus.init.detect_project", return_value={}):
            result = _run(argus_detect(path="/empty"))

        data = json.loads(result)
        assert data == {}

    def test_error_returns_json_error(self):
        with patch("argus.init.detect_project", side_effect=OSError("cannot read")):
            result = _run(argus_detect(path="/bad"))

        data = json.loads(result)
        assert "error" in data
        assert "cannot read" in data["error"]


# ---------------------------------------------------------------------------
# TestArgusInit
# ---------------------------------------------------------------------------


class TestArgusInit:
    """Tests for the argus_init tool."""

    def test_returns_config_yaml_and_signals(self):
        mock_signals = {"python": ["main.py"]}
        mock_config = "version: '1.0'\nscanners:\n  bandit:\n    enabled: true\n"

        with patch("argus.init.detect_project", return_value=mock_signals):
            with patch("argus.init.generate_config", return_value=mock_config):
                result = _run(argus_init(path="/fake"))

        data = json.loads(result)
        assert "config_yaml" in data
        assert "signals" in data
        assert data["signals"]["python"] == ["main.py"]
        assert "version" in data["config_yaml"]

    def test_signals_override_merges(self):
        auto_signals = {"python": ["app.py"]}
        override = {"java": ["Main.java"]}

        captured_signals = {}

        def fake_generate(signals):
            captured_signals.update(signals)
            return "version: '1.0'\n"

        with patch("argus.init.detect_project", return_value=auto_signals):
            with patch("argus.init.generate_config", side_effect=fake_generate):
                result = _run(argus_init(path="/fake", signals_override=override))

        data = json.loads(result)
        assert "python" in data["signals"]
        assert "java" in data["signals"]

    def test_signals_override_none_uses_auto_only(self):
        auto_signals = {"python": ["app.py"]}

        with patch("argus.init.detect_project", return_value=auto_signals):
            with patch("argus.init.generate_config", return_value="config: true\n"):
                result = _run(argus_init(path="/fake", signals_override=None))

        data = json.loads(result)
        assert data["signals"] == {"python": ["app.py"]}

    def test_error_returns_json_error(self):
        with patch("argus.init.detect_project", side_effect=RuntimeError("fail")):
            result = _run(argus_init(path="/bad"))

        data = json.loads(result)
        assert "error" in data


# ---------------------------------------------------------------------------
# TestArgusValidate
# ---------------------------------------------------------------------------


class TestArgusValidate:
    """Tests for the argus_validate tool."""

    def test_valid_config(self, tmp_path, monkeypatch):
        config_content = (
            'version: "1.0"\n'
            "scanners:\n"
            "  bandit:\n"
            "    enabled: true\n"
            "reporting:\n"
            "  formats:\n"
            "    - terminal\n"
            "  severity_threshold: high\n"
        )
        config_file = tmp_path / "argus.yml"
        config_file.write_text(config_content)
        monkeypatch.chdir(tmp_path)

        result = _run(argus_validate())
        data = json.loads(result)

        assert data["valid"] is True
        assert data["errors"] == []
        assert "bandit" in data["scanners_enabled"]

    def test_missing_config_no_path(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)

        result = _run(argus_validate())
        data = json.loads(result)

        assert data["valid"] is False
        assert any("No argus.yml found" in e for e in data["errors"])

    def test_missing_config_explicit_path(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)

        result = _run(argus_validate(config_path="nonexistent.yml"))
        data = json.loads(result)

        assert data["valid"] is False
        assert any("not found" in e for e in data["errors"])

    def test_invalid_yaml_content(self, tmp_path, monkeypatch):
        config_file = tmp_path / "argus.yml"
        config_file.write_text("- just\n- a\n- list\n")
        monkeypatch.chdir(tmp_path)

        result = _run(argus_validate())
        data = json.loads(result)

        assert data["valid"] is False
        assert any("mapping" in e.lower() for e in data["errors"])

    def test_explicit_path_valid(self, tmp_path, monkeypatch):
        config_content = (
            'version: "1.0"\n'
            "scanners:\n"
            "  gitleaks:\n"
            "    enabled: true\n"
            "  osv:\n"
            "    enabled: false\n"
        )
        config_file = tmp_path / "custom-argus.yml"
        config_file.write_text(config_content)
        monkeypatch.chdir(tmp_path)

        result = _run(argus_validate(config_path="custom-argus.yml"))
        data = json.loads(result)

        assert data["valid"] is True
        assert "gitleaks" in data["scanners_enabled"]
        assert "osv" in data["scanners_disabled"]

    def test_disabled_scanners_detected(self, tmp_path, monkeypatch):
        config_content = (
            'version: "1.0"\n'
            "scanners:\n"
            "  bandit:\n"
            "    enabled: true\n"
            "  clamav:\n"
            "    enabled: false\n"
        )
        config_file = tmp_path / "argus.yml"
        config_file.write_text(config_content)
        monkeypatch.chdir(tmp_path)

        result = _run(argus_validate())
        data = json.loads(result)

        assert "bandit" in data["scanners_enabled"]
        assert "clamav" in data["scanners_disabled"]

    def test_reporting_formats_in_output(self, tmp_path, monkeypatch):
        config_content = (
            'version: "1.0"\n'
            "scanners:\n"
            "  bandit:\n"
            "    enabled: true\n"
            "reporting:\n"
            "  formats:\n"
            "    - terminal\n"
            "    - sarif\n"
        )
        config_file = tmp_path / "argus.yml"
        config_file.write_text(config_content)
        monkeypatch.chdir(tmp_path)

        result = _run(argus_validate())
        data = json.loads(result)

        assert data["formats"] == ["terminal", "sarif"]

    def test_backend_in_output(self, tmp_path, monkeypatch):
        config_content = (
            'version: "1.0"\n'
            "scanners:\n"
            "  bandit:\n"
            "    enabled: true\n"
            "execution:\n"
            "  backend: docker\n"
        )
        config_file = tmp_path / "argus.yml"
        config_file.write_text(config_content)
        monkeypatch.chdir(tmp_path)

        result = _run(argus_validate())
        data = json.loads(result)

        assert data["backend"] == "docker"


# ---------------------------------------------------------------------------
# TestArgusExplainFinding
# ---------------------------------------------------------------------------


class TestArgusExplainFinding:
    """Tests for the argus_explain_finding tool."""

    def test_bandit_finding(self):
        result = _run(argus_explain_finding(finding_id="B301", scanner="bandit"))
        data = json.loads(result)

        assert data["finding_id"] == "B301"
        assert data["source"] == "bandit"
        assert any("bandit.readthedocs.io" in r for r in data["references"])
        assert "guidance" in data

    def test_cwe_finding(self):
        result = _run(argus_explain_finding(finding_id="CWE-89"))
        data = json.loads(result)

        assert data["source"] == "cwe"
        assert any("cwe.mitre.org" in r for r in data["references"])
        assert "89" in data["guidance"]

    def test_cve_finding(self):
        result = _run(argus_explain_finding(finding_id="CVE-2024-1234"))
        data = json.loads(result)

        assert data["source"] == "cve"
        assert len(data["references"]) >= 2
        assert any("nvd.nist.gov" in r for r in data["references"])
        assert any("github.com/advisories" in r for r in data["references"])

    def test_cve_has_three_references(self):
        result = _run(argus_explain_finding(finding_id="CVE-2024-1234"))
        data = json.loads(result)

        assert len(data["references"]) == 3
        assert any("cvedetails.com" in r for r in data["references"])

    def test_checkov_finding(self):
        result = _run(argus_explain_finding(finding_id="CKV_AWS_1"))
        data = json.loads(result)

        assert data["source"] == "checkov"
        assert any("checkov.io" in r for r in data["references"])

    def test_trivy_avd_finding(self):
        result = _run(argus_explain_finding(finding_id="AVD-AWS-0001"))
        data = json.loads(result)

        assert data["source"] == "trivy"
        assert any("avd.aquasec.com" in r for r in data["references"])

    def test_opengrep_semgrep_finding(self):
        result = _run(argus_explain_finding(
            finding_id="python.lang.security.injection",
        ))
        data = json.loads(result)

        assert data["source"] == "opengrep/semgrep"
        assert any("semgrep.dev" in r for r in data["references"])

    def test_gitleaks_finding(self):
        result = _run(argus_explain_finding(
            finding_id="generic-api-key",
            scanner="gitleaks",
        ))
        data = json.loads(result)

        assert data["source"] == "gitleaks"
        assert any("gitleaks" in r for r in data["references"])
        assert "secret" in data["guidance"].lower()

    def test_gitleaks_finding_via_secrets_scanner(self):
        """The 'secrets' scanner alias should also trigger gitleaks source."""
        result = _run(argus_explain_finding(
            finding_id="aws-access-key",
            scanner="secrets",
        ))
        data = json.loads(result)

        assert data["source"] == "gitleaks"

    def test_unknown_finding(self):
        result = _run(argus_explain_finding(finding_id="UNKNOWN-RULE-42"))
        data = json.loads(result)

        assert data["source"] == "generic"
        assert "guidance" in data

    def test_location_produces_next_steps(self):
        result = _run(argus_explain_finding(
            finding_id="B301",
            scanner="bandit",
            location="app.py:42",
        ))
        data = json.loads(result)

        assert "next_steps" in data
        assert "app.py:42" in data["next_steps"]

    def test_no_location_no_next_steps(self):
        result = _run(argus_explain_finding(finding_id="B301"))
        data = json.loads(result)

        assert "next_steps" not in data

    def test_scanner_field_preserved(self):
        result = _run(argus_explain_finding(
            finding_id="B301", scanner="bandit", location="x.py:1",
        ))
        data = json.loads(result)

        assert data["scanner"] == "bandit"
        assert data["location"] == "x.py:1"

    def test_default_scanner_is_unknown(self):
        result = _run(argus_explain_finding(finding_id="B301"))
        data = json.loads(result)

        assert data["scanner"] == "unknown"


# ---------------------------------------------------------------------------
# TestArgusScan
# ---------------------------------------------------------------------------


class TestArgusScan:
    """Tests for the argus_scan tool."""

    def test_successful_scan_returns_results(self):
        mock_summary = MagicMock()
        mock_summary.to_dict.return_value = {
            "results": [],
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "total_count": 0,
            "passed": True,
            "severity_threshold": None,
        }

        mock_engine_instance = MagicMock()
        mock_engine_instance.run.return_value = mock_summary

        with patch("argus.core.ArgusConfig.load") as mock_load:
            mock_config = MagicMock()
            mock_config.reporting = MagicMock()
            mock_load.return_value = mock_config
            with patch("argus.core.ArgusEngine", return_value=mock_engine_instance):
                with patch(
                    "argus.scanners.get_available_scanners", return_value=[],
                ):
                    result = _run(argus_scan(scanners=["bandit"], path="."))

        data = json.loads(result)
        assert "results" in data
        assert data["passed"] is True

    def test_scan_passes_scanner_names_to_engine(self):
        mock_summary = MagicMock()
        mock_summary.to_dict.return_value = {"passed": True, "results": []}

        mock_engine = MagicMock()
        mock_engine.run.return_value = mock_summary

        with patch("argus.core.ArgusConfig.load") as mock_load:
            mock_load.return_value = MagicMock()
            with patch("argus.core.ArgusEngine", return_value=mock_engine):
                with patch(
                    "argus.scanners.get_available_scanners", return_value=[],
                ):
                    _run(argus_scan(
                        scanners=["bandit", "gitleaks"], path="/src",
                    ))

        mock_engine.run.assert_called_once_with(
            scanner_names=["bandit", "gitleaks"],
            path="/src",
        )

    def test_scan_with_severity_threshold(self):
        mock_summary = MagicMock()
        mock_summary.to_dict.return_value = {"passed": False, "results": []}

        mock_engine = MagicMock()
        mock_engine.run.return_value = mock_summary

        with patch("argus.core.ArgusConfig.load") as mock_load:
            mock_config = MagicMock()
            mock_config.reporting = MagicMock()
            mock_load.return_value = mock_config
            with patch("argus.core.ArgusEngine", return_value=mock_engine):
                with patch(
                    "argus.scanners.get_available_scanners", return_value=[],
                ):
                    result = _run(argus_scan(severity_threshold="high"))

        data = json.loads(result)
        assert "results" in data

    def test_scan_error_returns_structured_error(self):
        with patch(
            "argus.core.ArgusConfig.load",
            side_effect=FileNotFoundError("no config"),
        ):
            result = _run(argus_scan())

        data = json.loads(result)
        assert "error" in data
        assert "error_type" in data
        assert data["error_type"] == "FileNotFoundError"

    def test_scan_error_includes_partial_results_when_summary_exists(self):
        """When to_dict raises first, then succeeds in except block."""
        partial_data = {"results": [{"scanner": "bandit"}]}
        mock_summary = MagicMock()
        # First call (line 97) raises, second call (line 104) returns data
        mock_summary.to_dict.side_effect = [
            RuntimeError("serialize fail"),
            partial_data,
        ]

        mock_engine = MagicMock()
        mock_engine.run.return_value = mock_summary

        with patch("argus.core.ArgusConfig.load") as mock_load:
            mock_load.return_value = MagicMock()
            with patch("argus.core.ArgusEngine", return_value=mock_engine):
                with patch(
                    "argus.scanners.get_available_scanners", return_value=[],
                ):
                    result = _run(argus_scan())

        data = json.loads(result)
        assert "error" in data
        assert data["error_type"] == "RuntimeError"
        assert "partial_results" in data
        assert data["partial_results"]["results"][0]["scanner"] == "bandit"

    def test_scan_none_scanners_runs_all(self):
        mock_summary = MagicMock()
        mock_summary.to_dict.return_value = {"passed": True, "results": []}

        mock_engine = MagicMock()
        mock_engine.run.return_value = mock_summary

        with patch("argus.core.ArgusConfig.load") as mock_load:
            mock_load.return_value = MagicMock()
            with patch("argus.core.ArgusEngine", return_value=mock_engine):
                with patch(
                    "argus.scanners.get_available_scanners", return_value=[],
                ):
                    _run(argus_scan(scanners=None))

        mock_engine.run.assert_called_once_with(
            scanner_names=None,
            path=".",
        )


# ---------------------------------------------------------------------------
# TestArgusClassify
# ---------------------------------------------------------------------------


class TestArgusClassify:
    """Tests for the argus_classify tool."""

    def test_returns_classifications(self):
        mock_analysis = {"changes": [{"file": "main.tf", "type": "modified"}]}
        mock_result = {
            "classifications": [
                {"file": "main.tf", "category": "ROUTINE"},
            ],
            "summary": {
                "routine": 1,
                "adaptive": 0,
                "transformative": 0,
                "impact": 0,
                "manual_review": 0,
            },
        }

        mock_classifier = MagicMock()
        mock_classifier.classify_all_changes.return_value = mock_result

        with patch("argus.scn.analyze_iac_changes", return_value=mock_analysis):
            with patch(
                "argus.scn.ChangeClassifier", return_value=mock_classifier,
            ):
                result = _run(argus_classify(base_ref="main", head_ref="HEAD"))

        data = json.loads(result)
        assert "classifications" in data
        assert data["summary"]["routine"] == 1

    def test_category_counts_present(self):
        mock_analysis = {"changes": []}
        mock_result = {
            "classifications": [],
            "summary": {
                "routine": 0,
                "adaptive": 2,
                "transformative": 1,
                "impact": 0,
                "manual_review": 0,
            },
        }

        mock_classifier = MagicMock()
        mock_classifier.classify_all_changes.return_value = mock_result

        with patch("argus.scn.analyze_iac_changes", return_value=mock_analysis):
            with patch(
                "argus.scn.ChangeClassifier", return_value=mock_classifier,
            ):
                result = _run(argus_classify())

        data = json.loads(result)
        assert data["summary"]["adaptive"] == 2
        assert data["summary"]["transformative"] == 1

    def test_with_config_path(self, tmp_path):
        mock_analysis = {"changes": []}
        mock_classifier = MagicMock()
        mock_classifier.load_config_from_file.return_value = {"profile": "test"}
        mock_classifier.classify_all_changes.return_value = {
            "classifications": [],
            "summary": {"routine": 0},
        }

        config_file = tmp_path / "scn-profile.yml"
        config_file.write_text("profile: test\n")

        with patch("argus.scn.analyze_iac_changes", return_value=mock_analysis):
            with patch(
                "argus.scn.ChangeClassifier", return_value=mock_classifier,
            ):
                result = _run(argus_classify(
                    config_path=str(config_file),
                    enable_ai=False,
                ))

        data = json.loads(result)
        assert "classifications" in data

    def test_error_returns_structured_error(self):
        with patch(
            "argus.scn.analyze_iac_changes",
            side_effect=RuntimeError("no git"),
        ):
            result = _run(argus_classify())

        data = json.loads(result)
        assert "error" in data
        assert data["error_type"] == "RuntimeError"


# ---------------------------------------------------------------------------
# TestArgusScanSummary
# ---------------------------------------------------------------------------


class TestArgusScanSummary:
    """Tests for the argus_scan_summary tool."""

    def test_reads_and_summarizes_results(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)

        results_dir = tmp_path / "argus-results" / "latest"
        results_dir.mkdir(parents=True)

        results_data = {
            "passed": True,
            "severity_threshold": "high",
            "critical_count": 1,
            "high_count": 2,
            "medium_count": 3,
            "low_count": 4,
            "total_count": 10,
            "results": [
                {
                    "scanner": "bandit",
                    "total_count": 5,
                    "critical_count": 1,
                    "high_count": 2,
                    "findings": [
                        {
                            "id": "B301",
                            "severity": "critical",
                            "title": "Pickle usage",
                            "location": "app.py:10",
                            "scanner": "bandit",
                        },
                        {
                            "id": "B302",
                            "severity": "high",
                            "title": "Insecure marshal",
                            "location": "utils.py:5",
                            "scanner": "bandit",
                        },
                    ],
                },
                {
                    "scanner": "gitleaks",
                    "total_count": 5,
                    "critical_count": 0,
                    "high_count": 0,
                    "findings": [],
                },
            ],
        }

        results_file = results_dir / "argus-results.json"
        results_file.write_text(json.dumps(results_data))

        result = _run(argus_scan_summary())
        data = json.loads(result)

        assert data["passed"] is True
        assert data["counts"]["critical"] == 1
        assert data["counts"]["high"] == 2
        assert data["counts"]["total"] == 10
        assert len(data["scanners"]) == 2
        assert data["scanners"][0]["scanner"] == "bandit"
        assert len(data["top_findings"]) >= 1
        assert data["top_findings"][0]["severity"] == "critical"

    def test_source_path_included(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)

        results_dir = tmp_path / "argus-results" / "latest"
        results_dir.mkdir(parents=True)

        results_data = {
            "passed": True,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "total_count": 0,
            "results": [],
        }

        results_file = results_dir / "argus-results.json"
        results_file.write_text(json.dumps(results_data))

        result = _run(argus_scan_summary())
        data = json.loads(result)

        assert "source" in data
        assert "argus-results" in data["source"]

    def test_no_results_returns_error(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)

        result = _run(argus_scan_summary())
        data = json.loads(result)

        assert "error" in data
        assert "No scan results found" in data["error"]

    def test_fallback_to_root_results_file(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)

        results_dir = tmp_path / "argus-results"
        results_dir.mkdir()

        results_data = {
            "passed": True,
            "severity_threshold": None,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "total_count": 0,
            "results": [],
        }

        results_file = results_dir / "argus-results.json"
        results_file.write_text(json.dumps(results_data))

        result = _run(argus_scan_summary())
        data = json.loads(result)

        assert data["passed"] is True
        assert data["counts"]["total"] == 0

    def test_top_findings_limited_to_five(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)

        results_dir = tmp_path / "argus-results" / "latest"
        results_dir.mkdir(parents=True)

        findings = [
            {
                "id": f"VULN-{i}",
                "severity": "critical",
                "title": f"Vuln {i}",
                "location": f"file{i}.py:{i}",
                "scanner": "test",
            }
            for i in range(10)
        ]

        results_data = {
            "passed": False,
            "severity_threshold": "low",
            "critical_count": 10,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "total_count": 10,
            "results": [{
                "scanner": "test",
                "total_count": 10,
                "critical_count": 10,
                "high_count": 0,
                "findings": findings,
            }],
        }

        results_file = results_dir / "argus-results.json"
        results_file.write_text(json.dumps(results_data))

        result = _run(argus_scan_summary())
        data = json.loads(result)

        assert len(data["top_findings"]) == 5

    def test_critical_findings_sorted_first(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)

        results_dir = tmp_path / "argus-results" / "latest"
        results_dir.mkdir(parents=True)

        results_data = {
            "passed": False,
            "severity_threshold": "low",
            "critical_count": 1,
            "high_count": 1,
            "medium_count": 0,
            "low_count": 0,
            "total_count": 2,
            "results": [{
                "scanner": "test",
                "total_count": 2,
                "critical_count": 1,
                "high_count": 1,
                "findings": [
                    {
                        "id": "HIGH-1",
                        "severity": "high",
                        "title": "High vuln",
                        "location": "a.py:1",
                    },
                    {
                        "id": "CRIT-1",
                        "severity": "critical",
                        "title": "Critical vuln",
                        "location": "b.py:2",
                    },
                ],
            }],
        }

        results_file = results_dir / "argus-results.json"
        results_file.write_text(json.dumps(results_data))

        result = _run(argus_scan_summary())
        data = json.loads(result)

        assert data["top_findings"][0]["severity"] == "critical"
        assert data["top_findings"][1]["severity"] == "high"

    def test_medium_and_low_findings_excluded_from_top(
        self, tmp_path, monkeypatch,
    ):
        monkeypatch.chdir(tmp_path)

        results_dir = tmp_path / "argus-results" / "latest"
        results_dir.mkdir(parents=True)

        results_data = {
            "passed": True,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 1,
            "low_count": 1,
            "total_count": 2,
            "results": [{
                "scanner": "test",
                "total_count": 2,
                "critical_count": 0,
                "high_count": 0,
                "findings": [
                    {
                        "id": "MED-1",
                        "severity": "medium",
                        "title": "Medium finding",
                        "location": "a.py:1",
                    },
                    {
                        "id": "LOW-1",
                        "severity": "low",
                        "title": "Low finding",
                        "location": "b.py:2",
                    },
                ],
            }],
        }

        results_file = results_dir / "argus-results.json"
        results_file.write_text(json.dumps(results_data))

        result = _run(argus_scan_summary())
        data = json.loads(result)

        assert data["top_findings"] == []


# ---------------------------------------------------------------------------
# TestResources
# ---------------------------------------------------------------------------


class TestResources:
    """Tests for MCP resources."""

    def test_config_resource_reads_argus_yml(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)

        config_content = (
            'version: "1.0"\n'
            "scanners:\n"
            "  bandit:\n"
            "    enabled: true\n"
        )
        config_file = tmp_path / "argus.yml"
        config_file.write_text(config_content)

        result = _run(read_config())
        data = json.loads(result)

        assert data["version"] == "1.0"
        assert "bandit" in data["scanners"]

    def test_config_resource_reads_alternate_names(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)

        config_content = (
            'version: "1.0"\n'
            "scanners:\n"
            "  gitleaks:\n"
            "    enabled: true\n"
        )
        config_file = tmp_path / "argus.yaml"
        config_file.write_text(config_content)

        result = _run(read_config())
        data = json.loads(result)

        assert data["version"] == "1.0"
        assert "gitleaks" in data["scanners"]

    def test_config_resource_no_file_returns_auto_detected(
        self, tmp_path, monkeypatch,
    ):
        monkeypatch.chdir(tmp_path)

        mock_config = MagicMock()
        mock_config.version = "1.0"
        mock_config.scanners = {}
        mock_config.reporting = MagicMock()
        mock_config.reporting.formats = ["terminal"]
        mock_config.reporting.severity_threshold = None
        mock_config.reporting.output_dir = "./argus-results"
        mock_config.execution = MagicMock()
        mock_config.execution.backend = "auto"
        mock_config.execution.registry = ""
        mock_config.execution.pull_policy = "if-not-present"

        with patch("argus.core.ArgusConfig.load", return_value=mock_config):
            result = _run(read_config())

        data = json.loads(result)
        assert data["_source"] == "auto-detected (no argus.yml found)"
        assert data["version"] == "1.0"

    def test_config_schema_resource_with_file(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)

        schema = {
            "type": "object",
            "properties": {"version": {"type": "string"}},
        }
        schema_file = tmp_path / "argus-config.schema.json"
        schema_file.write_text(json.dumps(schema))

        result = _run(read_config_schema())
        data = json.loads(result)

        assert data["type"] == "object"
        assert "version" in data["properties"]

    def test_config_schema_resource_no_file(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)

        with patch("argus.mcp.__file__", str(tmp_path / "mcp.py")):
            result = _run(read_config_schema())

        data = json.loads(result)
        assert "error" in data
        assert "not found" in data["error"].lower()

    def test_results_latest_resource_reads_json(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)

        results_dir = tmp_path / "argus-results" / "latest"
        results_dir.mkdir(parents=True)

        results_data = {
            "results": [{"scanner": "bandit", "findings": []}],
            "passed": True,
        }
        results_file = results_dir / "argus-results.json"
        results_file.write_text(json.dumps(results_data))

        result = _run(read_latest_results())
        data = json.loads(result)

        assert data["passed"] is True
        assert len(data["results"]) == 1

    def test_results_latest_resource_no_results(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)

        result = _run(read_latest_results())
        data = json.loads(result)

        assert "error" in data
        assert "No scan results found" in data["error"]

    def test_results_latest_fallback_to_directory_glob(
        self, tmp_path, monkeypatch,
    ):
        monkeypatch.chdir(tmp_path)

        results_dir = tmp_path / "argus-results" / "latest"
        results_dir.mkdir(parents=True)

        custom_data = {"custom": True, "results": []}
        custom_file = results_dir / "custom-results.json"
        custom_file.write_text(json.dumps(custom_data))

        result = _run(read_latest_results())
        data = json.loads(result)

        assert data["custom"] is True


# ---------------------------------------------------------------------------
# TestPrompts
# ---------------------------------------------------------------------------


class TestPrompts:
    """Tests for MCP prompts."""

    def test_security_review_returns_nonempty(self):
        result = _run(security_review())
        assert isinstance(result, str)
        assert len(result) > 0
        # Prompt should steer the assistant toward at least one Argus tool —
        # argus_security_review is the canonical entry point but legacy
        # phrasing referencing argus_detect / argus_scan is also acceptable.
        assert any(
            tool in result
            for tool in (
                "argus_security_review",
                "argus_detect",
                "argus_scan",
                "argus_explain_finding",
            )
        )

    def test_fix_findings_returns_nonempty(self):
        result = _run(fix_findings())
        assert isinstance(result, str)
        assert len(result) > 0
        assert "argus_explain_finding" in result

    def test_setup_scanning_returns_nonempty(self):
        result = _run(setup_scanning())
        assert isinstance(result, str)
        assert len(result) > 0
        assert "argus_init" in result or "argus_detect" in result

    def test_security_review_mentions_findings(self):
        result = _run(security_review())
        assert "HIGH" in result or "CRITICAL" in result

    def test_fix_findings_mentions_results(self):
        result = _run(fix_findings())
        assert "results" in result.lower()

    def test_setup_scanning_mentions_validate(self):
        result = _run(setup_scanning())
        assert "argus_validate" in result


# ---------------------------------------------------------------------------
# TestCreateServer
# ---------------------------------------------------------------------------


class TestCreateServer:
    """Tests for the create_server factory."""

    def test_returns_fastmcp_instance(self):
        from mcp.server.fastmcp import FastMCP

        server = create_server()
        assert isinstance(server, FastMCP)

    def test_server_name_is_argus(self):
        server = create_server()
        assert server.name == "argus"

    def test_server_has_instructions(self):
        server = create_server()
        assert server.instructions is not None
        assert "argus" in server.instructions.lower()

    def test_server_is_singleton(self):
        """create_server returns the module-level mcp instance each time."""
        server1 = create_server()
        server2 = create_server()
        assert server1 is server2

    def test_instructions_advertise_security_review_entry_point(self):
        """The unified tool is the recommended path for natural-language
        queries. Server instructions must advertise it so clients route to
        it instead of stitching together argus_detect + argus_scan ad hoc.
        """
        server = create_server()
        assert "argus_security_review" in server.instructions
        assert "QUICK PATH" in server.instructions

    def test_instructions_warn_about_stale_cache(self):
        """Instructions must teach clients to check cache_age_seconds and
        re-scan when stale, so they don't answer posture questions from
        a 9-day-old snapshot.
        """
        server = create_server()
        assert "cache_age_seconds" in server.instructions


# ---------------------------------------------------------------------------
# TestArgusScanSummaryCacheFreshness
# ---------------------------------------------------------------------------


def _write_results(results_dir, payload, *, mtime_offset_seconds: int = 0):
    """Write a results JSON file and optionally backdate its mtime.

    A non-zero mtime_offset_seconds backs the file up that many seconds in
    the past — used to simulate stale cached scans without sleeping.
    """
    import os
    import time

    results_dir.mkdir(parents=True, exist_ok=True)
    results_file = results_dir / "argus-results.json"
    results_file.write_text(json.dumps(payload))
    if mtime_offset_seconds:
        target = time.time() - mtime_offset_seconds
        os.utime(results_file, (target, target))
    return results_file


class TestArgusScanSummaryCacheFreshness:
    """argus_scan_summary now reports cache_age_seconds + cached_at so
    the LLM can decide whether to trust the cached snapshot or re-scan.
    These tests pin that behavior — without the freshness signal, an
    assistant may answer posture questions from a 9-day-old cache (the
    real-world failure mode this guards against).
    """

    _BASE_PAYLOAD = {
        "passed": True,
        "severity_threshold": "high",
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "total_count": 0,
        "results": [],
    }

    def test_includes_cache_age_seconds_field(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        _write_results(tmp_path / "argus-results" / "latest", self._BASE_PAYLOAD)

        data = json.loads(_run(argus_scan_summary()))

        assert "cache_age_seconds" in data
        assert isinstance(data["cache_age_seconds"], int)
        assert data["cache_age_seconds"] >= 0
        # A just-written file should be within a few seconds of "now".
        assert data["cache_age_seconds"] < 10

    def test_includes_cached_at_iso_timestamp(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        _write_results(tmp_path / "argus-results" / "latest", self._BASE_PAYLOAD)

        data = json.loads(_run(argus_scan_summary()))

        assert "cached_at" in data
        # ISO-8601 with timezone — should parse cleanly via fromisoformat.
        from datetime import datetime
        parsed = datetime.fromisoformat(data["cached_at"])
        assert parsed.tzinfo is not None

    def test_fresh_results_omit_freshness_warning(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        _write_results(tmp_path / "argus-results" / "latest", self._BASE_PAYLOAD)

        data = json.loads(_run(argus_scan_summary()))

        assert "freshness_warning" not in data

    def test_stale_results_include_freshness_warning(self, tmp_path, monkeypatch):
        # Backdate the file by 48h — well past the 24h staleness threshold.
        monkeypatch.chdir(tmp_path)
        _write_results(
            tmp_path / "argus-results" / "latest",
            self._BASE_PAYLOAD,
            mtime_offset_seconds=48 * 3600,
        )

        data = json.loads(_run(argus_scan_summary()))

        assert data["cache_age_seconds"] >= 48 * 3600
        assert "freshness_warning" in data
        # The warning should name argus_scan or argus_security_review so
        # the client knows what to do — not a vague "results may be stale".
        assert (
            "argus_scan" in data["freshness_warning"]
            or "argus_security_review" in data["freshness_warning"]
        )


# ---------------------------------------------------------------------------
# TestReadLatestResultsCacheFreshness
# ---------------------------------------------------------------------------


class TestReadLatestResultsCacheFreshness:
    """The argus://results/latest resource now augments JSON-object
    payloads with _cache_age_seconds and _cached_at envelope fields.
    Underscore-prefixed because they're MCP-injected metadata, not part
    of the scan-results schema downstream consumers parse.
    """

    _BASE_PAYLOAD = {
        "passed": True,
        "severity_threshold": "high",
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "total_count": 0,
        "results": [],
    }

    def test_dict_payload_gets_cache_metadata(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        _write_results(tmp_path / "argus-results" / "latest", self._BASE_PAYLOAD)

        data = json.loads(_run(read_latest_results()))

        assert "_cache_age_seconds" in data
        assert "_cached_at" in data
        assert data["passed"] is True  # original fields preserved

    def test_stale_payload_includes_freshness_warning(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        _write_results(
            tmp_path / "argus-results" / "latest",
            self._BASE_PAYLOAD,
            mtime_offset_seconds=72 * 3600,
        )

        data = json.loads(_run(read_latest_results()))

        assert "_freshness_warning" in data
        assert data["_cache_age_seconds"] >= 72 * 3600


# ---------------------------------------------------------------------------
# TestArgusSecurityReview
# ---------------------------------------------------------------------------


class TestArgusSecurityReview:
    """argus_security_review is the canonical one-call entry point. It
    must return a stable JSON envelope so the same posture question
    produces the same response shape across sessions — that's the whole
    point of unifying the workflow into one tool.
    """

    _CACHED_PAYLOAD = {
        "passed": False,
        "severity_threshold": "high",
        "critical_count": 1,
        "high_count": 1,
        "medium_count": 0,
        "low_count": 0,
        "total_count": 2,
        "results": [
            {
                "scanner": "bandit",
                "total_count": 2,
                "critical_count": 1,
                "high_count": 1,
                "findings": [
                    {
                        "id": "B301",
                        "severity": "critical",
                        "title": "Pickle usage",
                        "location": "app.py:10",
                        "scanner": "bandit",
                    },
                    {
                        "id": "B302",
                        "severity": "high",
                        "title": "Insecure marshal",
                        "location": "utils.py:5",
                        "scanner": "bandit",
                    },
                ],
            },
        ],
    }

    def test_returns_stable_envelope_shape(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        _write_results(
            tmp_path / "argus-results" / "latest",
            self._CACHED_PAYLOAD,
        )

        with patch("argus.init.detect_project", return_value={"python": ["app.py"]}):
            data = json.loads(_run(argus_security_review()))

        # The envelope keys are the contract — every successful call
        # returns the same top-level shape regardless of cache state.
        for key in (
            "version",
            "cache_used",
            "cache_age_seconds",
            "cached_at",
            "is_stale",
            "signals",
            "summary",
            "next_steps",
        ):
            assert key in data, f"missing envelope key: {key}"
        assert data["version"] == "1"

    def test_uses_cache_when_fresh(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        _write_results(
            tmp_path / "argus-results" / "latest",
            self._CACHED_PAYLOAD,
        )

        with patch("argus.init.detect_project", return_value={"python": []}):
            data = json.loads(_run(argus_security_review()))

        assert data["cache_used"] is True
        assert data["is_stale"] is False
        # Summary should reflect the cached payload, not a fresh scan.
        assert data["summary"]["counts"]["critical"] == 1
        assert data["summary"]["counts"]["high"] == 1

    def test_summary_includes_top_findings(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        _write_results(
            tmp_path / "argus-results" / "latest",
            self._CACHED_PAYLOAD,
        )

        with patch("argus.init.detect_project", return_value={}):
            data = json.loads(_run(argus_security_review()))

        top = data["summary"]["top_findings"]
        assert len(top) == 2
        # critical sorts before high
        assert top[0]["severity"] == "critical"
        assert top[1]["severity"] == "high"

    def test_signals_passed_through_from_detect(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        _write_results(
            tmp_path / "argus-results" / "latest",
            self._CACHED_PAYLOAD,
        )

        signals = {"python": ["app.py"], "github-actions": [".github/workflows/ci.yml"]}
        with patch("argus.init.detect_project", return_value=signals):
            data = json.loads(_run(argus_security_review()))

        assert data["signals"] == signals

    def test_next_steps_recommend_explain_for_critical(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        _write_results(
            tmp_path / "argus-results" / "latest",
            self._CACHED_PAYLOAD,
        )

        with patch("argus.init.detect_project", return_value={}):
            data = json.loads(_run(argus_security_review()))

        joined = " ".join(data["next_steps"])
        assert "argus_explain_finding" in joined
        assert "critical" in joined.lower()

    def test_next_steps_clean_when_no_findings(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        clean_payload = dict(self._CACHED_PAYLOAD)
        clean_payload["critical_count"] = 0
        clean_payload["high_count"] = 0
        clean_payload["total_count"] = 0
        clean_payload["results"] = []
        _write_results(tmp_path / "argus-results" / "latest", clean_payload)

        with patch("argus.init.detect_project", return_value={}):
            data = json.loads(_run(argus_security_review()))

        assert data["next_steps"]
        joined = " ".join(data["next_steps"]).lower()
        assert "no critical or high" in joined

    def test_stale_cache_triggers_warning_and_rescan_hint(
        self, tmp_path, monkeypatch,
    ):
        monkeypatch.chdir(tmp_path)
        # Backdate cache 9 days — the exact failure mode the user reported.
        _write_results(
            tmp_path / "argus-results" / "latest",
            self._CACHED_PAYLOAD,
            mtime_offset_seconds=9 * 86400,
        )

        # Stale cache => the tool must run a fresh scan rather than reuse.
        # Mock the engine path so the test stays hermetic.
        mock_summary = MagicMock()
        mock_summary.to_dict.return_value = self._CACHED_PAYLOAD
        mock_engine_instance = MagicMock()
        mock_engine_instance.run.return_value = mock_summary

        with patch("argus.init.detect_project", return_value={}), \
             patch("argus.core.ArgusConfig.load", return_value=MagicMock()), \
             patch("argus.core.engine.ArgusEngine", return_value=mock_engine_instance), \
             patch("argus.scanners.get_available_scanners", return_value=[]):
            data = json.loads(_run(argus_security_review()))

        # When stale, we re-scanned, so cache_used is False.
        assert data["cache_used"] is False
        mock_engine_instance.run.assert_called_once()

    def test_force_fresh_scan_skips_cache(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        _write_results(
            tmp_path / "argus-results" / "latest",
            self._CACHED_PAYLOAD,
        )

        mock_summary = MagicMock()
        mock_summary.to_dict.return_value = self._CACHED_PAYLOAD
        mock_engine_instance = MagicMock()
        mock_engine_instance.run.return_value = mock_summary

        with patch("argus.init.detect_project", return_value={}), \
             patch("argus.core.ArgusConfig.load", return_value=MagicMock()), \
             patch("argus.core.engine.ArgusEngine", return_value=mock_engine_instance), \
             patch("argus.scanners.get_available_scanners", return_value=[]):
            data = json.loads(_run(argus_security_review(use_cached_if_fresh=False)))

        assert data["cache_used"] is False
        mock_engine_instance.run.assert_called_once()

    def test_error_returns_structured_error(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)

        with patch("argus.init.detect_project", side_effect=RuntimeError("boom")):
            data = json.loads(_run(argus_security_review()))

        assert "error" in data
        assert data["error_type"] == "RuntimeError"
