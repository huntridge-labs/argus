"""Tests for argus.core.sbom_inspect: what an SBOM describes (#494)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from argus.core.sbom import SbomDetectionError
from argus.core.sbom_inspect import format_terminal, inspect_sbom

FIXTURES = Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "sbom"


def _sbom(tmp_path, name, content):
    path = tmp_path / name
    path.write_text(content if isinstance(content, str) else json.dumps(content))
    return path


class TestRealSboms:
    def test_syft_spdx(self):
        report = inspect_sbom(FIXTURES / "syft-amzn2023.spdx.json").to_dict()
        assert report["format"] == "spdx-json"
        assert report["spec_version"] == "SPDX-2.3"
        assert report["generator"] == {"name": "syft", "version": "1.54.1"}
        assert report["subject"]["name"] == "amazonlinux"
        assert report["subject"]["version"] == "2023.1.20230705.0"
        assert report["subject"]["digest"].startswith("sha256:a2fe6341")
        assert report["os"] == {
            "name": "amzn", "version": "2023", "source": "purl", "distros": ["amzn-2023"],
        }
        assert report["packages"] == {"total": 4, "os": 3, "by_type": {"pypi": 1, "rpm": 3}}
        assert report["matcher"]["matchers"] == ["grype"]

    def test_syft_cyclonedx(self):
        report = inspect_sbom(FIXTURES / "syft-amzn2023.cdx.json").to_dict()
        assert report["spec_version"] == "1.7"
        assert report["subject"]["name"] == "amazonlinux"
        assert report["subject"]["type"] == "container"
        assert report["packages"]["os"] == 3

    def test_syft_json(self):
        report = inspect_sbom(FIXTURES / "syft-amzn2023.syft.json").to_dict()
        assert report["format"] == "syft-json"
        assert report["spec_version"] == "16.1.11"
        assert report["subject"]["name"] == "amazonlinux"
        assert report["subject"]["digest"].startswith("sha256:2a100347")
        assert report["os"]["name"] == "amzn"
        assert report["matcher"]["matchers"] == ["grype"]

    def test_trivy_cyclonedx(self):
        report = inspect_sbom(FIXTURES / "trivy-amzn2023.cdx.json").to_dict()
        assert report["generator"] == {"name": "trivy", "version": "0.76.0"}
        assert report["subject"]["name"] == "amazonlinux:2023.1.20230705.0"
        assert report["subject"]["digest"].startswith("sha256:2a100347")
        assert report["os"]["name"] == "amazon"
        assert report["os"]["version"] == "2023 (Amazon Linux)"
        assert report["matcher"]["matchers"] == ["trivy"]
        # The SBOM's own subject (pkg:oci) is not a package.
        assert "oci" not in report["packages"]["by_type"]

    def test_trivy_spdx_subject_from_describes(self):
        report = inspect_sbom(FIXTURES / "trivy-amzn2023.spdx.json").to_dict()
        assert report["subject"]["name"] == "amazonlinux:2023.1.20230705.0"
        assert "oci" not in report["packages"]["by_type"]


class TestOsFallbacks:
    def test_os_from_cyclonedx_operating_system_component(self, tmp_path):
        path = _sbom(tmp_path, "bom.cdx.json", {
            "bomFormat": "CycloneDX", "specVersion": "1.5",
            "components": [
                {"type": "operating-system", "name": "debian", "version": "12.5"},
                {"type": "library", "name": "bash", "purl": "pkg:deb/debian/bash@5.2.15"},
            ],
        })
        assert inspect_sbom(path).to_dict()["os"] == {
            "name": "debian", "version": "12.5", "source": "sbom-metadata", "distros": [],
        }

    def test_os_from_syft_distro_block(self, tmp_path):
        path = _sbom(tmp_path, "bom.json", {
            "artifacts": [], "descriptor": {"name": "syft", "version": "1.0.0"},
            "distro": {"id": "alpine", "versionID": "3.19.1"},
        })
        report = inspect_sbom(path).to_dict()
        assert report["os"]["name"] == "alpine"
        assert report["os"]["source"] == "sbom-metadata"

    def test_no_os(self, tmp_path):
        path = _sbom(tmp_path, "bom.cdx.json", {
            "bomFormat": "CycloneDX", "specVersion": "1.5",
            "components": [{"name": "requests", "purl": "pkg:pypi/requests@2.31.0"}],
        })
        report = inspect_sbom(path).to_dict()
        assert report["os"] is None
        assert report["packages"] == {"total": 1, "os": 0, "by_type": {"pypi": 1}}
        assert report["generator"] is None
        assert report["matcher"]["matchers"] == ["grype", "trivy"]


class TestOtherFormats:
    def test_spdx_tag_value(self, tmp_path):
        path = _sbom(tmp_path, "bom.spdx", (
            "SPDXVersion: SPDX-2.3\n"
            "DocumentName: my-app\n"
            "Creator: Tool: trivy-0.76.0\n"
            "PackageName: bash\n"
            "ExternalRef: PACKAGE-MANAGER purl pkg:deb/debian/bash@5.2.15?distro=debian-12\n"
        ))
        report = inspect_sbom(path).to_dict()
        assert report["spec_version"] == "SPDX-2.3"
        assert report["subject"]["name"] == "my-app"
        assert report["os"]["name"] == "debian"
        assert report["os"]["version"] == "12"

    def test_cyclonedx_xml(self, tmp_path):
        path = _sbom(tmp_path, "bom.xml", (
            '<?xml version="1.0"?>\n'
            '<bom xmlns="http://cyclonedx.org/schema/bom/1.5"><metadata>'
            "<component type=\"container\"><name>alpine</name><version>3.19</version></component>"
            "</metadata><components><component><name>musl</name>"
            "<purl>pkg:apk/alpine/musl@1.2.4-r2?distro=alpine-3.19.1</purl>"
            "</component></components></bom>"
        ))
        report = inspect_sbom(path).to_dict()
        assert report["spec_version"] == "1.5"
        assert report["subject"]["name"] == "alpine"
        assert report["os"]["name"] == "alpine"

    def test_not_an_sbom_raises(self, tmp_path):
        path = _sbom(tmp_path, "x.json", {"hello": "world"})
        with pytest.raises(SbomDetectionError):
            inspect_sbom(path)


class TestTerminalFormat:
    def test_lists_every_section(self):
        text = format_terminal(inspect_sbom(FIXTURES / "syft-amzn2023.spdx.json"))
        assert "Format:     SPDX JSON (SPDX-2.3)" in text
        assert "Generator:  syft 1.54.1" in text
        assert "Subject:    amazonlinux 2023.1.20230705.0" in text
        assert "OS:         amzn 2023 (from package purls)" in text
        assert "Packages:   4 (3 OS)" in text
        assert "rpm" in text and "pypi" in text
        assert "Matcher:    grype" in text

    def test_unknowns_are_spelled_out(self, tmp_path):
        path = _sbom(tmp_path, "bom.cdx.json", {
            "bomFormat": "CycloneDX", "specVersion": "1.5", "components": [],
        })
        text = format_terminal(inspect_sbom(path))
        assert "Generator:  not recorded" in text
        assert "OS:         none found" in text
