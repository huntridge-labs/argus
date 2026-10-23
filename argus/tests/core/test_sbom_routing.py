"""Tests for SBOM generator detection and matcher routing (#493)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from argus.core.sbom import detect_sbom
from argus.core.sbom_contents import Generator, read_generator
from argus.core.sbom_routing import choose_matchers, plan_sbom_scanners

FIXTURES = Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "sbom"
CAPABLE = ["grype", "osv", "trivy"]


def _write(tmp_path, name, content):
    path = tmp_path / name
    path.write_text(content if isinstance(content, str) else json.dumps(content))
    return detect_sbom(path)


class TestReadGenerator:
    @pytest.mark.parametrize("name,expected", [
        ("syft-amzn2023.cdx.json", Generator("syft", "1.54.1")),
        ("syft-amzn2023.spdx.json", Generator("syft", "1.54.1")),
        ("syft-amzn2023.syft.json", Generator("syft", "1.54.1")),
        ("trivy-amzn2023.cdx.json", Generator("trivy", "0.76.0")),
        ("trivy-amzn2023.spdx.json", Generator("trivy", "0.76.0")),
    ])
    def test_real_sboms(self, name, expected):
        assert read_generator(detect_sbom(FIXTURES / name)) == expected

    def test_cyclonedx_legacy_tools_list(self, tmp_path):
        info = _write(tmp_path, "bom.cdx.json", {
            "bomFormat": "CycloneDX", "specVersion": "1.4", "components": [],
            "metadata": {"tools": [{"vendor": "anchore", "name": "grype", "version": "0.120.1"}]},
        })
        assert read_generator(info) == Generator("grype", "0.120.1")

    def test_cyclonedx_unknown_tool_keeps_its_name(self, tmp_path):
        info = _write(tmp_path, "bom.cdx.json", {
            "bomFormat": "CycloneDX", "specVersion": "1.5", "components": [],
            "metadata": {"tools": {"components": [{"name": "cdxgen", "version": "10.2.1"}]}},
        })
        assert read_generator(info) == Generator("cdxgen", "10.2.1")

    def test_cyclonedx_without_tools(self, tmp_path):
        info = _write(tmp_path, "bom.cdx.json", {
            "bomFormat": "CycloneDX", "specVersion": "1.5", "components": [],
        })
        assert read_generator(info) is None

    def test_cyclonedx_xml(self, tmp_path):
        info = _write(tmp_path, "bom.xml", (
            '<?xml version="1.0"?>\n'
            '<bom xmlns="http://cyclonedx.org/schema/bom/1.5"><metadata><tools>'
            "<components><component type=\"application\"><author>anchore</author>"
            "<name>syft</name><version>1.54.1</version></component></components>"
            "</tools><component><name>alpine</name></component></metadata></bom>"
        ))
        assert read_generator(info) == Generator("syft", "1.54.1")

    def test_spdx_tag_value(self, tmp_path):
        info = _write(tmp_path, "bom.spdx", (
            "SPDXVersion: SPDX-2.3\n"
            "Creator: Organization: aquasecurity\n"
            "Creator: Tool: trivy-0.76.0\n"
        ))
        assert read_generator(info) == Generator("trivy", "0.76.0")

    def test_spdx_tool_without_version(self, tmp_path):
        info = _write(tmp_path, "bom.spdx.json", {
            "spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT",
            "creationInfo": {"creators": ["Tool: in-house-scanner"]},
        })
        assert read_generator(info) == Generator("in-house-scanner", "")

    def test_spdx_without_tool_creator(self, tmp_path):
        info = _write(tmp_path, "bom.spdx.json", {
            "spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT",
            "creationInfo": {"creators": ["Organization: ACME"]},
        })
        assert read_generator(info) is None


class TestChooseMatchers:
    @pytest.mark.parametrize("name", [
        "syft-amzn2023.cdx.json", "syft-amzn2023.spdx.json", "syft-amzn2023.syft.json",
    ])
    def test_syft_sboms_go_to_grype(self, name):
        choice = choose_matchers(detect_sbom(FIXTURES / name))
        assert choice.matchers == ("grype",)
        assert "syft 1.54.1" in choice.reason

    @pytest.mark.parametrize("name", ["trivy-amzn2023.cdx.json", "trivy-amzn2023.spdx.json"])
    def test_trivy_sboms_go_to_trivy(self, name):
        assert choose_matchers(detect_sbom(FIXTURES / name)).matchers == ("trivy",)

    def test_grype_sbom_goes_to_grype(self, tmp_path):
        info = _write(tmp_path, "bom.cdx.json", {
            "bomFormat": "CycloneDX", "specVersion": "1.4", "components": [],
            "metadata": {"tools": [{"name": "grype", "version": "0.120.1"}]},
        })
        assert choose_matchers(info).matchers == ("grype",)

    def test_unknown_generator_runs_both(self, tmp_path):
        info = _write(tmp_path, "bom.cdx.json", {
            "bomFormat": "CycloneDX", "specVersion": "1.5", "components": [],
            "metadata": {"tools": {"components": [{"name": "cdxgen", "version": "10"}]}},
        })
        choice = choose_matchers(info)
        assert choice.matchers == ("grype", "trivy")
        assert "cdxgen" in choice.reason

    def test_no_generator_runs_both(self, tmp_path):
        info = _write(tmp_path, "bom.cdx.json", {
            "bomFormat": "CycloneDX", "specVersion": "1.5", "components": [],
        })
        assert choose_matchers(info).matchers == ("grype", "trivy")

    def test_syft_json_never_goes_to_trivy(self, tmp_path):
        # trivy can't read the Syft JSON format at all, whoever wrote it.
        info = _write(tmp_path, "bom.json", {
            "artifacts": [], "descriptor": {"name": "syft", "version": "1.0.0"},
        })
        assert "trivy" not in choose_matchers(info).matchers


class TestPlanSbomScanners:
    def test_auto_plan_drops_the_other_matcher_and_keeps_osv(self):
        info = detect_sbom(FIXTURES / "syft-amzn2023.spdx.json")
        names, notes = plan_sbom_scanners(info, CAPABLE, requested=None)
        assert names == ["grype", "osv"]
        assert any("grype" in n and "trivy" in n for n in notes)

    def test_auto_plan_for_trivy_sbom(self):
        info = detect_sbom(FIXTURES / "trivy-amzn2023.cdx.json")
        names, _ = plan_sbom_scanners(info, CAPABLE, requested=None)
        assert names == ["osv", "trivy"]

    def test_auto_plan_falls_back_when_recommended_matcher_missing(self):
        info = detect_sbom(FIXTURES / "syft-amzn2023.spdx.json")
        names, notes = plan_sbom_scanners(info, ["osv", "trivy"], requested=None)
        assert names == ["osv", "trivy"]
        assert any("not available" in n for n in notes)

    def test_explicit_choice_runs_with_a_warning(self):
        info = detect_sbom(FIXTURES / "syft-amzn2023.spdx.json")
        names, notes = plan_sbom_scanners(info, CAPABLE, requested=["trivy"])
        assert names == ["trivy"]
        assert any("recommended matcher" in n and "grype" in n for n in notes)

    def test_explicit_recommended_choice_has_no_warning(self):
        info = detect_sbom(FIXTURES / "syft-amzn2023.spdx.json")
        names, notes = plan_sbom_scanners(info, CAPABLE, requested=["grype"])
        assert names == ["grype"]
        assert notes == []

    def test_explicit_non_matcher_choice_is_untouched(self):
        info = detect_sbom(FIXTURES / "syft-amzn2023.spdx.json")
        names, notes = plan_sbom_scanners(info, CAPABLE, requested=["osv"])
        assert names == ["osv"]
        assert notes == []

    def test_explicit_trivy_on_syft_json_warns_it_cannot_read_it(self):
        info = detect_sbom(FIXTURES / "syft-amzn2023.syft.json")
        names, notes = plan_sbom_scanners(info, CAPABLE, requested=["trivy"])
        assert names == ["trivy"]
        assert any("can't read Syft JSON" in n for n in notes)

    def test_explicit_choice_drops_non_capable_names(self):
        info = detect_sbom(FIXTURES / "syft-amzn2023.spdx.json")
        names, _ = plan_sbom_scanners(info, CAPABLE, requested=["bandit", "grype"])
        assert names == ["grype"]
