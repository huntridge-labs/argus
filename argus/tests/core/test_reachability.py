"""Unit tests for argus.core.reachability (Phase 12 — import heuristic)."""

from __future__ import annotations

from argus.core.models import Finding, Severity
from argus.core.reachability import (
    REACHABILITY_IMPORTED,
    REACHABILITY_NOT_IMPORTED,
    REACHABILITY_UNKNOWN,
    ecosystem_of,
    is_imported,
    package_of,
    reachability_label,
    reachability_of,
)


def _dep_finding(package="requests", purl="pkg:pypi/requests@2.0", ecosystem=None):
    meta = {"package": package}
    if purl:
        meta["purl"] = purl
    if ecosystem:
        meta["ecosystem"] = ecosystem
    return Finding(id="CVE-1-1", severity=Severity.HIGH, title="t", cve="CVE-1-1", metadata=meta)


class TestEcosystemAndPackage:
    def test_ecosystem_from_purl(self):
        assert ecosystem_of(_dep_finding(purl="pkg:pypi/x@1")) == "python"
        assert ecosystem_of(_dep_finding(purl="pkg:npm/x@1")) == "javascript"

    def test_ecosystem_from_metadata(self):
        assert ecosystem_of(_dep_finding(purl=None, ecosystem="PyPI")) == "python"
        assert ecosystem_of(_dep_finding(purl=None, ecosystem="npm")) == "javascript"

    def test_unsupported_ecosystem_none(self):
        assert ecosystem_of(_dep_finding(purl="pkg:golang/x@1")) is None

    def test_package_of(self):
        assert package_of(_dep_finding(package="flask")) == "flask"
        assert package_of(Finding(id="x", severity=Severity.LOW, title="t")) == ""


class TestPythonImports:
    def test_detects_import(self, tmp_path):
        (tmp_path / "app.py").write_text("import requests\nrequests.get('x')\n")
        assert is_imported("requests", "python", root=tmp_path) == REACHABILITY_IMPORTED

    def test_detects_from_import(self, tmp_path):
        (tmp_path / "app.py").write_text("from flask import Flask\n")
        assert is_imported("flask", "python", root=tmp_path) == REACHABILITY_IMPORTED

    def test_hyphen_dist_name_maps_to_underscore(self, tmp_path):
        # Dist names whose import is the underscored form (e.g.
        # typing-extensions → typing_extensions) map cleanly.
        (tmp_path / "a.py").write_text("import typing_extensions\n")
        assert is_imported("typing-extensions", "python", root=tmp_path) == REACHABILITY_IMPORTED

    def test_not_imported(self, tmp_path):
        (tmp_path / "app.py").write_text("import os\n")
        assert is_imported("requests", "python", root=tmp_path) == REACHABILITY_NOT_IMPORTED

    def test_skips_vendor_dirs(self, tmp_path):
        (tmp_path / "app.py").write_text("import os\n")  # real source, no match
        vendored = tmp_path / "node_modules" / "x"
        vendored.mkdir(parents=True)
        (vendored / "dep.py").write_text("import requests\n")  # match only in vendored
        # the only match is in a skipped dir → not imported in real source
        assert is_imported("requests", "python", root=tmp_path) == REACHABILITY_NOT_IMPORTED

    def test_substring_not_falsely_matched(self, tmp_path):
        (tmp_path / "app.py").write_text("import requests_oauthlib\n")
        # "requests" should not match "requests_oauthlib" as a top import
        assert is_imported("requests", "python", root=tmp_path) == REACHABILITY_NOT_IMPORTED


class TestJsImports:
    def test_require(self, tmp_path):
        (tmp_path / "a.js").write_text("const lodash = require('lodash');\n")
        assert is_imported("lodash", "javascript", root=tmp_path) == REACHABILITY_IMPORTED

    def test_es_import(self, tmp_path):
        (tmp_path / "a.ts").write_text("import axios from 'axios';\n")
        assert is_imported("axios", "javascript", root=tmp_path) == REACHABILITY_IMPORTED

    def test_subpath_import(self, tmp_path):
        (tmp_path / "a.js").write_text("import x from 'lodash/merge';\n")
        assert is_imported("lodash", "javascript", root=tmp_path) == REACHABILITY_IMPORTED

    def test_not_imported(self, tmp_path):
        (tmp_path / "a.js").write_text("console.log('hi');\n")
        assert is_imported("lodash", "javascript", root=tmp_path) == REACHABILITY_NOT_IMPORTED


class TestUnknownAndLabels:
    def test_unsupported_ecosystem_unknown(self, tmp_path):
        assert is_imported("x", "golang", root=tmp_path) == REACHABILITY_UNKNOWN
        assert is_imported("x", None, root=tmp_path) == REACHABILITY_UNKNOWN

    def test_empty_package_unknown(self, tmp_path):
        assert is_imported("", "python", root=tmp_path) == REACHABILITY_UNKNOWN

    def test_reachability_of_non_dependency(self, tmp_path):
        f = Finding(id="x", severity=Severity.LOW, title="t")
        assert reachability_of(f, root=tmp_path) == REACHABILITY_UNKNOWN

    def test_reachability_of_dependency(self, tmp_path):
        (tmp_path / "app.py").write_text("import requests\n")
        assert reachability_of(_dep_finding(), root=tmp_path) == REACHABILITY_IMPORTED

    def test_labels(self):
        assert "imported" in reachability_label(REACHABILITY_IMPORTED)
        assert "likely unused" in reachability_label(REACHABILITY_NOT_IMPORTED)
        assert reachability_label("???") == "unknown"
