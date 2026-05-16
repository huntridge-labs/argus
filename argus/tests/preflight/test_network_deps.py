"""Tests for argus.preflight.network_deps."""

from argus.preflight.network_deps import RUNTIME_NETWORK_DEPS, get_network_deps


class TestNetworkDeps:
    """Test runtime network dependency declarations."""

    def test_known_scanners_have_deps(self):
        for name in ("osv", "clamav", "trivy-iac", "container", "checkov"):
            deps = get_network_deps(name)
            assert len(deps) > 0, f"{name} should have network deps"

    def test_unknown_scanner_returns_empty(self):
        assert get_network_deps("bandit") == []
        assert get_network_deps("gitleaks") == []
        assert get_network_deps("nonexistent") == []

    def test_deps_are_strings(self):
        for name, deps in RUNTIME_NETWORK_DEPS.items():
            for dep in deps:
                assert isinstance(dep, str), f"{name} dep must be string"

    def test_osv_mentions_api(self):
        deps = get_network_deps("osv")
        assert any("api.osv.dev" in d for d in deps)

    def test_clamav_mentions_freshclam(self):
        deps = get_network_deps("clamav")
        assert any("freshclam" in d for d in deps)

    def test_trivy_mentions_db(self):
        deps = get_network_deps("trivy-iac")
        assert any("DB" in d or "db" in d for d in deps)
