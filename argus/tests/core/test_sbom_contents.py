"""Tests for argus.core.sbom_contents: reading purls and OS packages from SBOMs."""

from __future__ import annotations

from pathlib import Path

import pytest

from argus.core.sbom import detect_sbom
from argus.core.sbom_contents import (
    os_packages,
    parse_purl,
    read_purls,
)

FIXTURES = Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "sbom"


class TestParsePurl:
    def test_parses_os_package_with_distro_qualifier(self):
        purl = parse_purl(
            "pkg:rpm/amzn/openssl-libs@1:3.0.8-1.amzn2023.0.3"
            "?arch=x86_64&distro=amzn-2023&upstream=openssl.src.rpm"
        )
        assert purl.type == "rpm"
        assert purl.namespace == "amzn"
        assert purl.name == "openssl-libs"
        assert purl.version == "1:3.0.8-1.amzn2023.0.3"
        assert purl.distro == "amzn-2023"
        assert purl.is_os_package is True

    def test_decodes_percent_encoded_qualifiers(self):
        purl = parse_purl(
            "pkg:rpm/amazon/curl@8.0.1?distro=amazon-2023%20%28Amazon%20Linux%29"
        )
        assert purl.distro == "amazon-2023 (Amazon Linux)"

    def test_language_package_is_not_an_os_package(self):
        purl = parse_purl("pkg:pypi/requests@2.31.0")
        assert purl.type == "pypi"
        assert purl.namespace == ""
        assert purl.name == "requests"
        assert purl.is_os_package is False

    def test_os_purl_type_without_distro_still_counts(self):
        # Some generators omit the distro qualifier. The package is still
        # an OS package; a matcher just has less to go on.
        assert parse_purl("pkg:deb/debian/libc6@2.36").is_os_package is True

    def test_scoped_npm_name_and_subpath(self):
        purl = parse_purl("pkg:npm/%40babel/core@7.22.0#lib/index.js")
        assert purl.namespace == "@babel"
        assert purl.name == "core"
        assert purl.version == "7.22.0"

    @pytest.mark.parametrize("value", ["", "not-a-purl", "pkg:", "pkg:/x@1", None, 42])
    def test_rejects_malformed_values(self, value):
        assert parse_purl(value) is None


class TestReadPurls:
    @pytest.mark.parametrize("name", [
        "syft-amzn2023.cdx.json",
        "syft-amzn2023.spdx.json",
        "syft-amzn2023.syft.json",
        "trivy-amzn2023.cdx.json",
        "trivy-amzn2023.spdx.json",
    ])
    def test_reads_every_package_purl(self, name):
        purls = read_purls(detect_sbom(FIXTURES / name))
        names = {parse_purl(p).name for p in purls if parse_purl(p)}
        assert {"curl-minimal", "openssl-libs"} <= names

    def test_skips_the_cyclonedx_subject_component(self):
        purls = read_purls(detect_sbom(FIXTURES / "trivy-amzn2023.cdx.json"))
        assert not any(p.startswith("pkg:oci/") for p in purls)

    def test_walks_nested_cyclonedx_components(self, tmp_path):
        sbom = tmp_path / "nested.cdx.json"
        sbom.write_text(
            '{"bomFormat": "CycloneDX", "specVersion": "1.5", "components": ['
            '{"name": "app", "purl": "pkg:npm/app@1.0.0", "components": ['
            '{"name": "zlib", "purl": "pkg:deb/debian/zlib1g@1.2.13?distro=debian-12"}'
            "]}]}"
        )
        assert read_purls(detect_sbom(sbom)) == [
            "pkg:npm/app@1.0.0",
            "pkg:deb/debian/zlib1g@1.2.13?distro=debian-12",
        ]

    def test_reads_cyclonedx_xml(self, tmp_path):
        sbom = tmp_path / "bom.xml"
        sbom.write_text(
            '<?xml version="1.0"?>\n'
            '<bom xmlns="http://cyclonedx.org/schema/bom/1.5">'
            "<metadata><component><purl>pkg:oci/app@sha256%3Aabc</purl>"
            "</component></metadata>"
            "<components><component><name>musl</name>"
            "<purl>pkg:apk/alpine/musl@1.2.4-r2?distro=alpine-3.19.1&amp;arch=x86_64</purl>"
            "</component></components></bom>"
        )
        assert read_purls(detect_sbom(sbom)) == [
            "pkg:apk/alpine/musl@1.2.4-r2?distro=alpine-3.19.1&arch=x86_64",
        ]

    def test_reads_spdx_tag_value(self, tmp_path):
        sbom = tmp_path / "bom.spdx"
        sbom.write_text(
            "SPDXVersion: SPDX-2.3\n"
            "PackageName: bash\n"
            "ExternalRef: PACKAGE-MANAGER purl pkg:deb/debian/bash@5.2.15?distro=debian-12\n"
            "PackageName: left-pad\n"
            "ExternalRef: PACKAGE_MANAGER purl pkg:npm/left-pad@1.3.0\n"
        )
        assert read_purls(detect_sbom(sbom)) == [
            "pkg:deb/debian/bash@5.2.15?distro=debian-12",
            "pkg:npm/left-pad@1.3.0",
        ]

    def test_unreadable_json_returns_empty(self, tmp_path):
        sbom = tmp_path / "bom.cdx.json"
        sbom.write_text('{"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}')
        info = detect_sbom(sbom)
        sbom.write_text("{ truncated")
        assert read_purls(info) == []


class TestOsPackages:
    def test_counts_os_packages_and_skips_language_packages(self):
        pkgs = os_packages(detect_sbom(FIXTURES / "syft-amzn2023.spdx.json"))
        assert {p.name for p in pkgs} == {"curl-minimal", "openssl-libs", "rpm"}
        assert all(p.type == "rpm" for p in pkgs)
        assert {p.distro for p in pkgs} == {"amzn-2023"}

    def test_sbom_without_os_packages(self, tmp_path):
        sbom = tmp_path / "app.cdx.json"
        sbom.write_text(
            '{"bomFormat": "CycloneDX", "specVersion": "1.5", "components": ['
            '{"name": "requests", "purl": "pkg:pypi/requests@2.31.0"}]}'
        )
        assert os_packages(detect_sbom(sbom)) == []
