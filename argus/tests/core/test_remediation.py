"""Unit tests for argus.core.remediation — Tier-1 deterministic fixes.

UI-free: no Textual / no network. Pins the manifest-rewrite correctness
(operator/prefix preservation, name normalization, idempotence) and the
propose/apply contract, including the command fallback.
"""

from __future__ import annotations


from argus.core.models import Finding, Severity
from argus.core.remediation import (
    apply,
    bump_package_json_text,
    bump_requirements_text,
    ecosystem_from_purl,
    propose,
)


def _dep_finding(pkg, fixed, *, purl=None, installed="1.0.0", fid="CVE-X"):
    return Finding(
        id=fid, severity=Severity.HIGH, title="vuln", scanner="osv",
        metadata={
            "package": pkg, "installed_version": installed,
            "fixed_version": fixed, "purl": purl or f"pkg:pypi/{pkg}@{installed}",
        },
    )


class TestEcosystemFromPurl:
    def test_pypi(self):
        assert ecosystem_from_purl("pkg:pypi/django@3.2") == "pip"

    def test_npm_with_namespace(self):
        assert ecosystem_from_purl("pkg:npm/%40scope/pkg@1.0") == "npm"

    def test_unsupported_ecosystem(self):
        assert ecosystem_from_purl("pkg:golang/x/text@0.3") is None

    def test_missing_or_malformed(self):
        assert ecosystem_from_purl(None) is None
        assert ecosystem_from_purl("") is None
        assert ecosystem_from_purl("django@3.2") is None


class TestBumpRequirements:
    def test_pinned_equals(self):
        out = bump_requirements_text("flask==1.0.0\nrequests==2.0\n", "flask", "1.1.1")
        assert "flask==1.1.1" in out
        assert "requests==2.0" in out  # untouched

    def test_range_operator_preserved(self):
        out = bump_requirements_text("django>=3.0\n", "django", "3.2.18")
        assert out.strip() == "django>=3.2.18"

    def test_bare_name_gets_lower_bound(self):
        out = bump_requirements_text("urllib3\n", "urllib3", "2.0.7")
        assert out.strip() == "urllib3>=2.0.7"

    def test_name_normalization(self):
        # pip treats Django == django and _/-/.equivalent (PEP 503).
        out = bump_requirements_text("Jinja_2==3.0\n", "jinja-2", "3.1.4")
        assert "==3.1.4" in out

    def test_extras_preserved(self):
        out = bump_requirements_text("requests[security]==2.0\n", "requests", "2.32.3")
        assert "requests[security]==2.32.3" in out

    def test_inline_comment_preserved(self):
        out = bump_requirements_text("flask==1.0  # web\n", "flask", "1.1.1")
        assert "flask==1.1.1" in out
        assert "# web" in out

    def test_not_found_returns_none(self):
        assert bump_requirements_text("flask==1.0\n", "django", "3.2") is None

    def test_already_at_fixed_returns_none(self):
        assert bump_requirements_text("flask==1.1.1\n", "flask", "1.1.1") is None


class TestBumpPackageJson:
    def test_caret_prefix_preserved(self):
        text = '{\n  "dependencies": {\n    "lodash": "^4.17.0"\n  }\n}\n'
        out = bump_package_json_text(text, "lodash", "4.17.21")
        assert '"lodash": "^4.17.21"' in out

    def test_tilde_prefix_preserved(self):
        text = '{"dependencies": {"axios": "~0.21.0"}}'
        out = bump_package_json_text(text, "axios", "0.21.4")
        assert '"axios": "~0.21.4"' in out

    def test_dev_dependencies(self):
        text = '{"devDependencies": {"jest": "27.0.0"}}'
        out = bump_package_json_text(text, "jest", "27.5.1")
        assert '"jest": "27.5.1"' in out

    def test_not_found_returns_none(self):
        assert bump_package_json_text('{"dependencies": {"a": "1.0"}}', "b", "2.0") is None

    def test_already_at_fixed_returns_none(self):
        assert bump_package_json_text('{"dependencies": {"a": "^1.0"}}', "a", "1.0") is None

    def test_malformed_json_returns_none(self):
        assert bump_package_json_text("{not json", "a", "2.0") is None


class TestProposePip:
    def test_high_confidence_diff_when_manifest_matches(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("flask==1.0.0\n")
        rem = propose(_dep_finding("flask", "1.1.1"), repo_root=tmp_path)
        assert rem is not None
        assert rem.confidence == "high"
        assert rem.is_applicable
        assert rem.path == "requirements.txt"
        assert "flask==1.1.1" in rem.new_text
        assert "+flask==1.1.1" in rem.diff

    def test_command_fallback_when_no_manifest(self, tmp_path):
        rem = propose(_dep_finding("flask", "1.1.1"), repo_root=tmp_path)
        assert rem is not None
        assert rem.confidence == "medium"
        assert rem.command == ["pip", "install", "flask==1.1.1"]
        assert not rem.is_applicable

    def test_no_fixed_version_returns_none(self, tmp_path):
        assert propose(_dep_finding("flask", "—"), repo_root=tmp_path) is None
        assert propose(_dep_finding("flask", ""), repo_root=tmp_path) is None

    def test_no_package_returns_none(self, tmp_path):
        f = Finding(id="X", severity=Severity.HIGH, title="t", scanner="bandit", metadata={})
        assert propose(f, repo_root=tmp_path) is None


class TestProposeNpm:
    def test_high_confidence_package_json(self, tmp_path):
        (tmp_path / "package.json").write_text('{"dependencies": {"lodash": "^4.17.0"}}')
        f = _dep_finding("lodash", "4.17.21", purl="pkg:npm/lodash@4.17.0")
        rem = propose(f, repo_root=tmp_path)
        assert rem is not None and rem.confidence == "high"
        assert '"lodash": "^4.17.21"' in rem.new_text

    def test_command_fallback(self, tmp_path):
        f = _dep_finding("lodash", "4.17.21", purl="pkg:npm/lodash@4.17.0")
        rem = propose(f, repo_root=tmp_path)
        assert rem.command == ["npm", "install", "lodash@4.17.21"]


class TestApply:
    def test_writes_edit(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("flask==1.0.0\n")
        rem = propose(_dep_finding("flask", "1.1.1"), repo_root=tmp_path)
        result = apply(rem, repo_root=tmp_path)
        assert result.ok
        assert req.read_text() == "flask==1.1.1\n"

    def test_idempotent_when_already_applied(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("flask==1.0.0\n")
        rem = propose(_dep_finding("flask", "1.1.1"), repo_root=tmp_path)
        apply(rem, repo_root=tmp_path)
        again = apply(rem, repo_root=tmp_path)
        assert again.ok and "up to date" in again.message

    def test_command_only_not_applicable(self, tmp_path):
        rem = propose(_dep_finding("flask", "1.1.1"), repo_root=tmp_path)  # no manifest
        result = apply(rem, repo_root=tmp_path)
        assert not result.ok
        assert "pip install flask==1.1.1" in result.message
