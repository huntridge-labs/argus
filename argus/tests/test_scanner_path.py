"""Per-scanner ``path:`` in argus.yml applies unless ``--path`` is given (#458)."""

from __future__ import annotations

import pytest

from argus.cli import build_parser, main
from argus.core.config import ArgusConfig
from argus.core.engine import ArgusEngine, _rebase_location
from argus.core.models import Finding, ScanResult, Severity


class _RecordingScanner:
    container_image = ""

    def __init__(self, name, location):
        self.name = name
        self._location = location
        self.scanned_path = None

    def scan(self, path, config=None):
        self.scanned_path = path
        return ScanResult(scanner=self.name, findings=[
            Finding(id="R1", severity=Severity.HIGH, title="t", location=self._location),
        ])

    def is_available(self):
        return True

    def install_command(self):
        return None


def _run(tmp_path, monkeypatch, path=None, location="main.tf:1"):
    (tmp_path / "infra").mkdir()
    monkeypatch.chdir(tmp_path)
    engine = ArgusEngine(ArgusConfig.from_dict(
        {"scanners": {"trivy-iac": {"enabled": True, "path": "infra"}}},
    ))
    scanner = _RecordingScanner("trivy-iac", location)
    engine.register_scanner(scanner)
    summary = engine.run(path=path, parallel=False)
    return scanner, summary.results[0].findings[0].location


class TestScanPathPrecedence:
    def test_cli_path_defaults_to_none(self):
        assert build_parser().parse_args(["scan"]).path is None

    def test_scanner_path_applies_without_cli_path(self, tmp_path, monkeypatch):
        scanner, _ = _run(tmp_path, monkeypatch)
        assert scanner.scanned_path == "infra"

    def test_cli_path_overrides_scanner_path(self, tmp_path, monkeypatch):
        scanner, location = _run(tmp_path, monkeypatch, path=".")
        assert scanner.scanned_path == "."
        assert location == "main.tf:1"


class TestLocationRebase:
    def test_relative_location_gets_scanner_path(self, tmp_path, monkeypatch):
        _, location = _run(tmp_path, monkeypatch)
        assert location == "infra/main.tf:1"

    def test_container_workspace_location_gets_scanner_path(self, tmp_path, monkeypatch):
        _, location = _run(tmp_path, monkeypatch, location="/workspace/main.tf:4")
        assert location == "infra/main.tf:4"

    def test_rebase_leaves_rooted_locations_alone(self):
        for loc in ("infra/main.tf:1", "/abs/main.tf:1", "C:\\\\x\\\\main.tf:1",
                    "infra\\main.tf:1", "https://app/login", None, ""):
            assert _rebase_location(loc, "infra") == loc


class TestDryRunShowsScannerPaths:
    def test_lists_scanner_path(self, tmp_path, monkeypatch, capsys):
        (tmp_path / "infra").mkdir()
        (tmp_path / "argus.yml").write_text(
            'scanners:\n  trivy-iac:\n    enabled: true\n    path: "infra"\n',
        )
        monkeypatch.chdir(tmp_path)
        with pytest.raises(SystemExit):
            main(["scan", "trivy-iac", "--config", "argus.yml", "--dry-run"])
        assert "trivy-iac: infra (from argus.yml)" in capsys.readouterr().out


class TestManifestScanTargets:
    def _config(self):
        return ArgusConfig.from_dict({"scanners": {
            "trivy-iac": {"enabled": True, "path": "infra"},
            "bandit": {"enabled": True, "path": "src"},
            "checkov": {"enabled": False, "path": "ops"},
        }})

    def test_per_scanner_paths_without_cli_path(self):
        from argus.cli import _scan_targets

        args = build_parser().parse_args(["scan"])
        assert _scan_targets(args, self._config()) == ["infra", "src"]

    def test_cli_path_wins(self):
        from argus.cli import _scan_targets

        args = build_parser().parse_args(["scan", "--path", "app"])
        assert _scan_targets(args, self._config()) == ["app"]
