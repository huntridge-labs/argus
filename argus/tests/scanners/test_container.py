"""Tests for argus.scanners.container — ContainerScanner."""

import pytest

from argus.core.models import Finding, Severity
from argus.scanners.container import ContainerScanner


class TestContainerTrivyResults:
    """Test ContainerScanner.parse_trivy_results."""

    def test_parse_with_findings(self, fixtures_dir):
        scanner = ContainerScanner()
        path = fixtures_dir / "trivy" / "results-with-findings.json"
        findings = scanner.parse_trivy_results(path)

        assert len(findings) == 4

        severities = [f.severity for f in findings]
        assert severities.count(Severity.CRITICAL) == 1
        assert severities.count(Severity.HIGH) == 1
        assert severities.count(Severity.MEDIUM) == 1
        assert severities.count(Severity.LOW) == 1

    def test_parse_zero_findings(self, fixtures_dir):
        scanner = ContainerScanner()
        path = fixtures_dir / "trivy" / "results-zero-findings.json"
        findings = scanner.parse_trivy_results(path)

        assert len(findings) == 0

    def test_finding_fields(self, fixtures_dir):
        scanner = ContainerScanner()
        path = fixtures_dir / "trivy" / "results-with-findings.json"
        findings = scanner.parse_trivy_results(path)

        crit = [f for f in findings if f.severity == Severity.CRITICAL][0]
        assert crit.id == "CVE-2023-1234"
        assert crit.cve == "CVE-2023-1234"
        assert crit.cwe == "CWE-787"
        assert crit.scanner == "container"
        assert crit.metadata["tool"] == "trivy"
        assert crit.metadata["package"] == "libssl1.1"
        assert "libssl1.1@" in crit.location


class TestContainerGrypeResults:
    """Test ContainerScanner.parse_grype_results."""

    def test_parse_with_findings(self, fixtures_dir):
        scanner = ContainerScanner()
        path = fixtures_dir / "grype" / "results-with-findings.json"
        findings = scanner.parse_grype_results(path)

        assert len(findings) == 4

        severities = [f.severity for f in findings]
        assert severities.count(Severity.CRITICAL) == 1
        assert severities.count(Severity.HIGH) == 1
        assert severities.count(Severity.MEDIUM) == 1
        assert severities.count(Severity.LOW) == 1

    def test_parse_zero_findings(self, fixtures_dir):
        scanner = ContainerScanner()
        path = fixtures_dir / "grype" / "results-zero-findings.json"
        findings = scanner.parse_grype_results(path)

        assert len(findings) == 0

    def test_finding_fields(self, fixtures_dir):
        scanner = ContainerScanner()
        path = fixtures_dir / "grype" / "results-with-findings.json"
        findings = scanner.parse_grype_results(path)

        crit = [f for f in findings if f.severity == Severity.CRITICAL][0]
        assert crit.id == "CVE-2023-1234"
        assert crit.cve == "CVE-2023-1234"
        assert crit.scanner == "container"
        assert crit.metadata["tool"] == "grype"
        assert crit.metadata["package"] == "libssl1.1"


class TestContainerDeduplication:
    """Test ContainerScanner CVE deduplication logic."""

    def test_merge_deduplicates_by_cve(self):
        scanner = ContainerScanner()
        target: list[Finding] = []
        seen_cves: set[str] = set()

        findings_a = [
            Finding(
                id="CVE-2023-1234",
                severity=Severity.CRITICAL,
                title="vuln A",
                cve="CVE-2023-1234",
            ),
            Finding(
                id="CVE-2023-5678",
                severity=Severity.HIGH,
                title="vuln B",
                cve="CVE-2023-5678",
            ),
        ]
        findings_b = [
            Finding(
                id="CVE-2023-1234",
                severity=Severity.CRITICAL,
                title="vuln A from grype",
                cve="CVE-2023-1234",
            ),
            Finding(
                id="CVE-2023-9999",
                severity=Severity.LOW,
                title="vuln C",
                cve="CVE-2023-9999",
            ),
        ]

        scanner._merge_findings(findings_a, target, seen_cves)
        scanner._merge_findings(findings_b, target, seen_cves)

        assert len(target) == 3
        cve_ids = [f.cve for f in target]
        assert cve_ids.count("CVE-2023-1234") == 1

    def test_merge_keeps_findings_without_cve(self):
        scanner = ContainerScanner()
        target: list[Finding] = []
        seen_cves: set[str] = set()

        findings = [
            Finding(id="NO-CVE-1", severity=Severity.LOW, title="no cve 1"),
            Finding(id="NO-CVE-2", severity=Severity.LOW, title="no cve 2"),
        ]

        scanner._merge_findings(findings, target, seen_cves)
        assert len(target) == 2


class TestContainerScannerMeta:
    """Test ContainerScanner metadata methods."""

    def test_name(self):
        assert ContainerScanner().name == "container"

    def test_install_command(self):
        cmd = ContainerScanner().install_command()
        assert cmd is not None


class TestParsePortProto:
    """The PORT/PROTO parser shared by the runtime scan + schema validator."""

    def test_canonical_form(self):
        from argus.scanners.container import _parse_port_proto
        assert _parse_port_proto("22/tcp") == (22, "tcp")
        assert _parse_port_proto("161/udp") == (161, "udp")

    def test_bare_port_defaults_to_tcp(self):
        from argus.scanners.container import _parse_port_proto
        assert _parse_port_proto("8080") == (8080, "tcp")

    def test_case_and_whitespace_tolerated(self):
        from argus.scanners.container import _parse_port_proto
        assert _parse_port_proto(" 22 / TCP ") == (22, "tcp")
        assert _parse_port_proto("3306/TCP") == (3306, "tcp")

    @pytest.mark.parametrize("raw", [
        "",
        "abc",
        "abc/tcp",
        "22/foo",        # unknown protocol
        "0/tcp",         # out of range
        "65536/tcp",     # out of range
        "-1/tcp",        # negative
        None,            # non-string
        123,             # non-string
    ])
    def test_invalid_returns_none(self, raw):
        from argus.scanners.container import _parse_port_proto
        assert _parse_port_proto(raw) is None


class TestScanExposedPorts:
    """Runtime behavior of the ``exposure`` sub-scanner.

    Mocks the subprocess + container_runtime calls so tests don't
    require docker on PATH. Verifies port→Finding conversion,
    severity assignment, ignore-list suppression, and warn-override
    semantics.
    """

    def _mock_inspect(self, monkeypatch, exposed_ports: dict | None,
                     pull_ok: bool = True, inspect_rc: int = 0,
                     inspect_stdout: str | None = None):
        """Wire up the docker inspect mocks for one test."""
        import subprocess as _subprocess
        from argus import container_runtime as rt_mod
        from argus.scanners import container as container_mod

        monkeypatch.setattr(rt_mod, "is_available", lambda: True)
        monkeypatch.setattr(rt_mod, "runtime_cmd", lambda: "docker")
        monkeypatch.setattr(rt_mod, "pull_image",
                            lambda image, policy="if-not-present": pull_ok)

        if inspect_stdout is None:
            import json as _json
            payload = [{"Config": {"ExposedPorts": exposed_ports or {}}}]
            inspect_stdout = _json.dumps(payload)

        def fake_run(cmd, **kwargs):
            return _subprocess.CompletedProcess(
                args=cmd, returncode=inspect_rc,
                stdout=inspect_stdout, stderr="",
            )
        monkeypatch.setattr(container_mod.subprocess, "run", fake_run)

    def test_single_non_risky_port_emits_info(self, monkeypatch):
        self._mock_inspect(monkeypatch, {"8080/tcp": {}})
        scanner = ContainerScanner()

        findings, meta = scanner._scan_exposed_ports("myapp:latest", {})

        assert len(findings) == 1
        f = findings[0]
        assert f.id == "EXPOSE-8080-tcp"
        assert f.severity == Severity.INFO
        assert f.metadata["port"] == 8080
        assert f.metadata["protocol"] == "tcp"
        assert f.metadata["risky"] is False
        assert meta["ports_declared"] == 1
        assert meta["ports_reported"] == 1
        assert meta["ports_ignored"] == 0

    def test_risky_port_emits_medium_with_service_name(self, monkeypatch):
        self._mock_inspect(monkeypatch, {"22/tcp": {}})
        scanner = ContainerScanner()

        findings, meta = scanner._scan_exposed_ports("myapp:latest", {})

        assert len(findings) == 1
        f = findings[0]
        assert f.severity == Severity.MEDIUM
        assert "SSH" in f.title
        assert f.metadata["common_service"] == "SSH"
        assert f.metadata["risky"] is True

    def test_multiple_ports_sorted_and_classified(self, monkeypatch):
        self._mock_inspect(monkeypatch, {
            "443/tcp": {},
            "22/tcp": {},
            "8080/tcp": {},
            "6379/tcp": {},
        })
        scanner = ContainerScanner()

        findings, _meta = scanner._scan_exposed_ports("myapp:latest", {})

        assert len(findings) == 4
        # Sorted by raw port spec
        ids = [f.id for f in findings]
        assert ids == [
            "EXPOSE-22-tcp",     # 22/tcp sorts before 443/tcp alphabetically
            "EXPOSE-443-tcp",
            "EXPOSE-6379-tcp",
            "EXPOSE-8080-tcp",
        ]
        sev_map = {f.id: f.severity for f in findings}
        assert sev_map["EXPOSE-22-tcp"] == Severity.MEDIUM    # SSH
        assert sev_map["EXPOSE-443-tcp"] == Severity.INFO     # HTTPS — not on list
        assert sev_map["EXPOSE-6379-tcp"] == Severity.MEDIUM  # Redis
        assert sev_map["EXPOSE-8080-tcp"] == Severity.INFO    # ordinary app port

    def test_ignore_list_suppresses_findings(self, monkeypatch):
        self._mock_inspect(monkeypatch, {"22/tcp": {}, "8080/tcp": {}})
        scanner = ContainerScanner()

        findings, meta = scanner._scan_exposed_ports(
            "myapp:latest",
            {"expose_ignore_ports": ["22/tcp"]},
        )

        ids = [f.id for f in findings]
        assert "EXPOSE-22-tcp" not in ids
        assert "EXPOSE-8080-tcp" in ids
        assert meta["ports_ignored"] == 1

    def test_warn_override_replaces_default_list(self, monkeypatch):
        # Default WARN list includes 22/tcp. Operator override replaces it
        # entirely with [8080/tcp] — so 22/tcp becomes INFO and 8080/tcp
        # becomes MEDIUM.
        self._mock_inspect(monkeypatch, {"22/tcp": {}, "8080/tcp": {}})
        scanner = ContainerScanner()

        findings, _meta = scanner._scan_exposed_ports(
            "myapp:latest",
            {"expose_warn_ports": ["8080/tcp"]},
        )

        sev_map = {f.id: f.severity for f in findings}
        assert sev_map["EXPOSE-22-tcp"] == Severity.INFO
        assert sev_map["EXPOSE-8080-tcp"] == Severity.MEDIUM

    def test_empty_warn_override_demotes_everything_to_info(self, monkeypatch):
        # Pass an explicit empty list to suppress all WARN-severity findings.
        self._mock_inspect(monkeypatch, {"22/tcp": {}, "3306/tcp": {}})
        scanner = ContainerScanner()

        findings, _meta = scanner._scan_exposed_ports(
            "myapp:latest",
            {"expose_warn_ports": []},
        )

        for f in findings:
            assert f.severity == Severity.INFO

    def test_no_exposed_ports_returns_empty(self, monkeypatch):
        self._mock_inspect(monkeypatch, {})
        scanner = ContainerScanner()

        findings, meta = scanner._scan_exposed_ports("myapp:latest", {})

        assert findings == []
        assert meta["ports_declared"] == 0
        assert meta["ports_reported"] == 0

    def test_no_config_block_returns_empty(self, monkeypatch):
        # An image with no Config.ExposedPorts at all.
        import json as _json
        self._mock_inspect(
            monkeypatch, None,
            inspect_stdout=_json.dumps([{"Config": {}}]),
        )
        scanner = ContainerScanner()

        findings, _meta = scanner._scan_exposed_ports("myapp:latest", {})

        assert findings == []

    def test_inspect_returns_empty_array(self, monkeypatch):
        import json as _json
        self._mock_inspect(
            monkeypatch, None,
            inspect_stdout=_json.dumps([]),
        )
        scanner = ContainerScanner()

        findings, meta = scanner._scan_exposed_ports("myapp:latest", {})

        assert findings == []
        assert "no image entries" in meta["error"]

    def test_no_runtime_returns_skipped(self, monkeypatch):
        from argus import container_runtime as rt_mod

        monkeypatch.setattr(rt_mod, "is_available", lambda: False)
        scanner = ContainerScanner()

        findings, meta = scanner._scan_exposed_ports("myapp:latest", {})

        assert findings == []
        assert "skipped" in meta

    def test_pull_failure_returns_error(self, monkeypatch):
        self._mock_inspect(monkeypatch, None, pull_ok=False)
        scanner = ContainerScanner()

        findings, meta = scanner._scan_exposed_ports(
            "private.registry/missing:tag", {},
        )

        assert findings == []
        assert "private.registry/missing:tag" in meta["error"]

    def test_unparseable_port_logged_and_skipped(self, monkeypatch, caplog):
        # Pathological image manifest with a garbage port spec.
        self._mock_inspect(monkeypatch, {"not-a-port": {}, "8080/tcp": {}})
        scanner = ContainerScanner()

        import logging
        with caplog.at_level(logging.WARNING, logger="argus"):
            findings, _meta = scanner._scan_exposed_ports("myapp:latest", {})

        # Garbage entry skipped; valid one still produces a finding.
        assert len(findings) == 1
        assert findings[0].id == "EXPOSE-8080-tcp"
        assert any("unparsable" in r.message for r in caplog.records)


class TestExposureSchemaValidation:
    """Validator rules for expose_warn_ports / expose_ignore_ports."""

    def _errors(self, data):
        from argus.core.schema import validate_config
        return [e for e in validate_config(data) if e.level == "error"]

    def test_valid_lists_accepted(self):
        cfg = {"scanners": {"container": {
            "image_ref": "myapp:latest",
            "expose_warn_ports": ["22/tcp", "3306/tcp"],
            "expose_ignore_ports": ["8080/tcp", "443"],
        }}}
        assert self._errors(cfg) == []

    def test_non_list_value_errors(self):
        cfg = {"scanners": {"container": {
            "expose_warn_ports": "22/tcp",  # string, not list
        }}}
        errs = self._errors(cfg)
        assert any("expose_warn_ports" in e.path for e in errs)

    def test_malformed_entry_errors(self):
        cfg = {"scanners": {"container": {
            "expose_ignore_ports": ["abc/tcp", "70000/tcp"],
        }}}
        errs = self._errors(cfg)
        assert len(errs) == 2
        for e in errs:
            assert "expose_ignore_ports" in e.path

    def test_non_string_entry_errors(self):
        cfg = {"scanners": {"container": {
            "expose_warn_ports": [22, "8080/tcp"],
        }}}
        errs = self._errors(cfg)
        assert any("Entry must be a string" in e.message for e in errs)

    def test_exposure_in_scanners_sub_list_accepted(self):
        """``exposure`` is a valid sub-scanner name."""
        cfg = {"containers": {
            "images": [{"image": "nginx:latest"}],
            "scanners": ["trivy", "exposure"],
        }}
        assert self._errors(cfg) == []


class TestServiceNameFromPath:
    """``_service_name_from_path`` picks the right stem out of unit
    files and SysV init scripts, and rejects timer/socket/target/etc.
    """

    @pytest.mark.parametrize("path,expected", [
        ("/etc/systemd/system/sshd.service", "sshd"),
        ("/lib/systemd/system/postgresql.service", "postgresql"),
        ("/usr/lib/systemd/system/redis-server.service", "redis-server"),
        ("/etc/init.d/sshd", "sshd"),
        ("/etc/init.d/postgresql", "postgresql"),
    ])
    def test_service_recognized(self, path, expected):
        from argus.scanners.container import _service_name_from_path
        assert _service_name_from_path(path) == expected

    @pytest.mark.parametrize("path", [
        "/etc/systemd/system/foo.timer",
        "/etc/systemd/system/foo.socket",
        "/etc/systemd/system/foo.target",
        "/etc/systemd/system/foo.mount",
        "/etc/random/path/sshd.service.bak",
        "/etc/random/file.conf",
    ])
    def test_non_service_returns_none(self, path):
        from argus.scanners.container import _service_name_from_path
        # systemd non-service unit types and unrelated files are NOT
        # treated as service declarations. The .bak case in particular
        # guards against picking up backup unit files.
        assert _service_name_from_path(path) is None


class TestParseSystemdUnit:
    """``_parse_systemd_unit`` returns ``{section.key: value}`` dicts."""

    def test_extracts_common_fields(self):
        from argus.scanners.container import _parse_systemd_unit
        content = b"""[Unit]
Description=OpenSSH Daemon
After=network.target

[Service]
ExecStart=/usr/sbin/sshd -D
User=root
Restart=on-failure
"""
        parsed = _parse_systemd_unit(content)
        assert parsed["Unit.Description"] == "OpenSSH Daemon"
        assert parsed["Service.ExecStart"] == "/usr/sbin/sshd -D"
        assert parsed["Service.User"] == "root"

    def test_ignores_comments(self):
        from argus.scanners.container import _parse_systemd_unit
        content = b"""[Service]
# This is a comment
; This is also a comment
ExecStart=/bin/true
"""
        parsed = _parse_systemd_unit(content)
        assert parsed == {"Service.ExecStart": "/bin/true"}

    def test_duplicate_keys_last_wins(self):
        """systemd allows duplicate keys (e.g. multiple ExecStartPre=);
        we keep the last value, which is sufficient for the fields the
        sub-scanner inspects."""
        from argus.scanners.container import _parse_systemd_unit
        content = b"[Service]\nExecStart=/bin/first\nExecStart=/bin/second\n"
        parsed = _parse_systemd_unit(content)
        assert parsed["Service.ExecStart"] == "/bin/second"

    def test_binary_garbage_returns_empty(self):
        """A non-UTF-8 binary blob doesn't crash the parser."""
        from argus.scanners.container import _parse_systemd_unit
        # Random bytes with no = signs and no section headers
        content = bytes(range(256))
        parsed = _parse_systemd_unit(content)
        # No section headers + no parseable key=value lines → empty dict
        assert parsed == {}

    def test_lines_without_equals_skipped(self):
        from argus.scanners.container import _parse_systemd_unit
        content = b"""[Service]
ExecStart=/bin/true
this-line-has-no-equals
User=root
"""
        parsed = _parse_systemd_unit(content)
        assert parsed["Service.ExecStart"] == "/bin/true"
        assert parsed["Service.User"] == "root"

    def test_keys_before_first_section_ignored(self):
        from argus.scanners.container import _parse_systemd_unit
        content = b"OrphanKey=value\n[Service]\nExecStart=/bin/true\n"
        parsed = _parse_systemd_unit(content)
        # Pre-section orphan key is dropped; only the in-section one survives
        assert parsed == {"Service.ExecStart": "/bin/true"}


class TestScanServices:
    """Runtime behavior of the ``services`` sub-scanner.

    Mocks ``_extract_paths_from_image`` so tests don't require docker
    on PATH. The extraction helper is exercised separately in
    ``TestExtractPathsFromImage``.
    """

    def _scanner_with_files(self, monkeypatch, files: dict[str, bytes]):
        from argus import container_runtime as rt_mod
        monkeypatch.setattr(rt_mod, "is_available", lambda: True)
        scanner = ContainerScanner()
        monkeypatch.setattr(
            scanner, "_extract_paths_from_image",
            lambda image_ref, paths: files,
        )
        return scanner

    @staticmethod
    def _unit(description: str, exec_start: str = "/bin/true", user: str = "") -> bytes:
        lines = ["[Unit]", f"Description={description}", "", "[Service]",
                 f"ExecStart={exec_start}"]
        if user:
            lines.append(f"User={user}")
        return ("\n".join(lines) + "\n").encode()

    def test_single_non_risky_service_emits_info(self, monkeypatch):
        scanner = self._scanner_with_files(monkeypatch, {
            "/etc/systemd/system/myapp.service": self._unit("My App Worker"),
        })

        findings, meta = scanner._scan_services("myapp:latest", {})

        assert len(findings) == 1
        f = findings[0]
        assert f.id == "SVC-myapp"
        assert f.severity == Severity.INFO
        assert f.metadata["service"] == "myapp"
        assert f.metadata["risky"] is False
        assert "myapp.service" in f.metadata["source"]
        assert meta["services_declared"] == 1
        assert meta["services_reported"] == 1
        assert meta["services_ignored"] == 0

    def test_sshd_service_emits_medium(self, monkeypatch):
        scanner = self._scanner_with_files(monkeypatch, {
            "/lib/systemd/system/sshd.service": self._unit("OpenSSH Daemon",
                                                            "/usr/sbin/sshd -D",
                                                            "root"),
        })

        findings, _ = scanner._scan_services("myapp:latest", {})

        assert len(findings) == 1
        f = findings[0]
        assert f.id == "SVC-sshd"
        assert f.severity == Severity.MEDIUM
        assert f.metadata["risky"] is True
        assert f.metadata["default_port"] == "22/tcp"
        assert f.metadata["exec_start"] == "/usr/sbin/sshd -D"
        assert f.metadata["user"] == "root"

    def test_sysv_init_script_recognized(self, monkeypatch):
        """SysV init scripts in /etc/init.d/ are also discoverable.
        They don't have systemd unit syntax, so unit-field metadata is
        empty — but the service name + risky classification still work.
        """
        scanner = self._scanner_with_files(monkeypatch, {
            "/etc/init.d/postgresql": b"#!/bin/sh\n# trivial init script\n",
        })

        findings, _ = scanner._scan_services("myapp:latest", {})

        assert len(findings) == 1
        f = findings[0]
        assert f.id == "SVC-postgresql"
        assert f.severity == Severity.MEDIUM
        # No systemd unit fields to extract from a shell script
        assert f.metadata["exec_start"] == ""

    def test_timer_socket_target_files_skipped(self, monkeypatch):
        """Only ``.service`` unit files and ``/etc/init.d/*`` SysV scripts
        count as service declarations. Timer / socket / target / mount
        files are ignored."""
        scanner = self._scanner_with_files(monkeypatch, {
            "/etc/systemd/system/foo.timer": b"[Timer]\nOnUnitActiveSec=1min\n",
            "/etc/systemd/system/bar.socket": b"[Socket]\nListenStream=8080\n",
            "/etc/systemd/system/baz.target": b"[Unit]\nDescription=baz\n",
        })

        findings, meta = scanner._scan_services("myapp:latest", {})

        assert findings == []
        assert meta["services_reported"] == 0
        assert meta["services_declared"] == 0

    def test_multi_service_sort_and_classification(self, monkeypatch):
        """Multiple services produce sorted, correctly-classified findings."""
        scanner = self._scanner_with_files(monkeypatch, {
            "/etc/systemd/system/myapp.service": self._unit("My App"),
            "/etc/systemd/system/sshd.service": self._unit("OpenSSH"),
            "/lib/systemd/system/redis-server.service": self._unit("Redis"),
        })

        findings, meta = scanner._scan_services("myapp:latest", {})

        assert len(findings) == 3
        sev_map = {f.id: f.severity for f in findings}
        assert sev_map["SVC-myapp"] == Severity.INFO
        assert sev_map["SVC-sshd"] == Severity.MEDIUM
        assert sev_map["SVC-redis-server"] == Severity.MEDIUM
        assert meta["services_reported"] == 3

    def test_ignore_list_suppresses_findings(self, monkeypatch):
        scanner = self._scanner_with_files(monkeypatch, {
            "/etc/systemd/system/sshd.service": self._unit("OpenSSH"),
            "/etc/systemd/system/myapp.service": self._unit("My App"),
        })

        findings, meta = scanner._scan_services(
            "myapp:latest",
            {"services_ignore": ["sshd"]},
        )

        ids = [f.id for f in findings]
        assert "SVC-sshd" not in ids
        assert "SVC-myapp" in ids
        assert meta["services_ignored"] == 1

    def test_warn_override_replaces_default_list(self, monkeypatch):
        """Operator-provided warn list REPLACES the built-in defaults.
        sshd (default risky) becomes INFO; myapp (operator-flagged)
        becomes MEDIUM."""
        scanner = self._scanner_with_files(monkeypatch, {
            "/etc/systemd/system/sshd.service": self._unit("OpenSSH"),
            "/etc/systemd/system/myapp.service": self._unit("My App"),
        })

        findings, _ = scanner._scan_services(
            "myapp:latest",
            {"services_warn": ["myapp"]},
        )

        sev_map = {f.id: f.severity for f in findings}
        assert sev_map["SVC-sshd"] == Severity.INFO
        assert sev_map["SVC-myapp"] == Severity.MEDIUM

    def test_empty_warn_override_demotes_everything_to_info(self, monkeypatch):
        """Passing an explicit empty list demotes every service to INFO."""
        scanner = self._scanner_with_files(monkeypatch, {
            "/etc/systemd/system/sshd.service": self._unit("OpenSSH"),
            "/etc/systemd/system/postgresql.service": self._unit("Postgres"),
        })

        findings, _ = scanner._scan_services(
            "myapp:latest",
            {"services_warn": []},
        )

        for f in findings:
            assert f.severity == Severity.INFO

    def test_ignore_list_is_case_insensitive(self, monkeypatch):
        """Service-name matching ignores case — common pitfall otherwise
        (sshd vs SSHD vs SsHd)."""
        scanner = self._scanner_with_files(monkeypatch, {
            "/etc/systemd/system/sshd.service": self._unit("OpenSSH"),
        })

        findings, _ = scanner._scan_services(
            "myapp:latest",
            {"services_ignore": ["SSHD"]},
        )

        assert findings == []

    def test_no_files_returns_empty(self, monkeypatch):
        scanner = self._scanner_with_files(monkeypatch, {})
        findings, meta = scanner._scan_services("myapp:latest", {})
        assert findings == []
        assert meta["services_reported"] == 0

    def test_no_runtime_returns_skipped(self, monkeypatch):
        from argus import container_runtime as rt_mod
        monkeypatch.setattr(rt_mod, "is_available", lambda: False)
        scanner = ContainerScanner()

        findings, meta = scanner._scan_services("myapp:latest", {})

        assert findings == []
        assert "skipped" in meta


class TestExtractPathsFromImage:
    """Light coverage of the docker create / cp / rm flow.

    Verifies the happy path produces a path→bytes map and that the
    container is removed even when extraction fails partway through.
    """

    def test_happy_path_extracts_files(self, monkeypatch):
        import io
        import subprocess as _subprocess
        import tarfile

        from argus import container_runtime as rt_mod
        from argus.scanners import container as container_mod

        monkeypatch.setattr(rt_mod, "is_available", lambda: True)
        monkeypatch.setattr(rt_mod, "runtime_cmd", lambda: "docker")
        monkeypatch.setattr(rt_mod, "pull_image",
                            lambda image, policy="if-not-present": True)

        # Build a tar archive matching what ``docker cp <cid>:/etc/systemd/system -``
        # would emit: a top-level directory entry plus files inside it.
        tar_buf = io.BytesIO()
        with tarfile.open(fileobj=tar_buf, mode="w") as tf:
            data = b"[Unit]\nDescription=Test\n"
            info = tarfile.TarInfo(name="system/sshd.service")
            info.size = len(data)
            info.type = tarfile.REGTYPE
            tf.addfile(info, io.BytesIO(data))
        tar_bytes = tar_buf.getvalue()

        calls: list[list[str]] = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            if cmd[:2] == ["docker", "create"]:
                return _subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout="abc123\n", stderr="",
                )
            if cmd[:2] == ["docker", "cp"]:
                # Return tar bytes for /etc/systemd/system; empty for others.
                if cmd[2].endswith("/etc/systemd/system"):
                    return _subprocess.CompletedProcess(
                        args=cmd, returncode=0, stdout=tar_bytes, stderr=b"",
                    )
                return _subprocess.CompletedProcess(
                    args=cmd, returncode=1, stdout=b"", stderr=b"",
                )
            if cmd[:2] == ["docker", "rm"]:
                return _subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout="abc123\n", stderr="",
                )
            return _subprocess.CompletedProcess(
                args=cmd, returncode=1, stdout="", stderr="",
            )

        monkeypatch.setattr(container_mod.subprocess, "run", fake_run)

        scanner = ContainerScanner()
        result = scanner._extract_paths_from_image(
            "myapp:latest",
            ("/etc/systemd/system", "/etc/init.d"),
        )

        # Got the sshd.service we put in the tar; reconstructed full path.
        assert "/etc/systemd/system/sshd.service" in result
        assert result["/etc/systemd/system/sshd.service"] == b"[Unit]\nDescription=Test\n"
        # Missing path silently skipped (no /etc/init.d in result).
        assert all(not p.startswith("/etc/init.d") for p in result)
        # Container ALWAYS removed at the end, regardless of partial misses.
        assert any(cmd[:3] == ["docker", "rm", "-f"] for cmd in calls)

    def test_no_runtime_returns_empty(self, monkeypatch):
        from argus import container_runtime as rt_mod
        monkeypatch.setattr(rt_mod, "is_available", lambda: False)
        scanner = ContainerScanner()
        assert scanner._extract_paths_from_image("img", ("/x",)) == {}

    def test_create_failure_returns_empty(self, monkeypatch):
        import subprocess as _subprocess
        from argus import container_runtime as rt_mod
        from argus.scanners import container as container_mod

        monkeypatch.setattr(rt_mod, "is_available", lambda: True)
        monkeypatch.setattr(rt_mod, "runtime_cmd", lambda: "docker")
        monkeypatch.setattr(rt_mod, "pull_image",
                            lambda image, policy="if-not-present": True)

        def fake_run(cmd, **kwargs):
            return _subprocess.CompletedProcess(
                args=cmd, returncode=1, stdout="", stderr="no such image",
            )
        monkeypatch.setattr(container_mod.subprocess, "run", fake_run)

        scanner = ContainerScanner()
        result = scanner._extract_paths_from_image(
            "private/missing", ("/etc/systemd/system",),
        )
        assert result == {}


class TestServicesSchemaValidation:
    """Validator rules for services_warn / services_ignore."""

    def _errors(self, data):
        from argus.core.schema import validate_config
        return [e for e in validate_config(data) if e.level == "error"]

    def test_valid_lists_accepted(self):
        cfg = {"scanners": {"container": {
            "image_ref": "myapp:latest",
            "services_warn": ["sshd", "redis-server"],
            "services_ignore": ["myapp", "cron"],
        }}}
        assert self._errors(cfg) == []

    def test_non_list_value_errors(self):
        cfg = {"scanners": {"container": {
            "services_warn": "sshd",  # string, not list
        }}}
        errs = self._errors(cfg)
        assert any("services_warn" in e.path for e in errs)

    def test_non_string_entry_errors(self):
        cfg = {"scanners": {"container": {
            "services_warn": ["sshd", 42],
        }}}
        errs = self._errors(cfg)
        assert any("services_warn" in e.path and "string" in e.message
                   for e in errs)

    def test_empty_entry_errors(self):
        cfg = {"scanners": {"container": {
            "services_ignore": ["sshd", "  "],
        }}}
        errs = self._errors(cfg)
        assert any("non-empty" in e.message for e in errs)

    def test_services_in_sub_scanner_list_accepted(self):
        cfg = {"containers": {
            "images": [{"image": "myapp:latest"}],
            "scanners": ["trivy", "services"],
        }}
        assert self._errors(cfg) == []
