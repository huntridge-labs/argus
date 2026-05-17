"""Container scanner orchestrating Trivy, Grype, Syft, and exposed-port surface."""

import json
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from argus.containers import get_image
from argus.core.models import Finding, PhaseResult, ScanResult, Severity

logger = logging.getLogger("argus")


# ── Risky-default ports for the ``exposure`` sub-scanner ─────────────
#
# Services on this list are not vulnerabilities per se — the port being
# *declared* via Dockerfile EXPOSE is itself harmless. The risk is that
# these services historically ship with weak defaults (no-auth Redis,
# unauthenticated PostgreSQL trust mode, SMB anonymous binding, etc.)
# *and* are surprisingly often inherited by application images that
# never actually intend to expose them — e.g. a base image that
# EXPOSEs port 22 because openssh-server got pulled in as a transitive
# dependency. The WARN severity prompts a "did you mean to expose
# this?" review without falsely implying a known CVE.
#
# Keys are ``(port, protocol)`` tuples; values are the service name
# used in the finding title. Operators can override via
# ``scanners.container.expose_warn_ports`` in argus.yml or suppress
# any finding entirely via ``scanners.container.expose_ignore_ports``.
#
# Sources for each entry:
#   - 21/tcp, 23/tcp: cleartext protocols (FTP, Telnet) — categorically
#     unsafe on any public network; CIS Docker Benchmark §5.8.
#   - 22/tcp: SSH in a container is a recurring image-inheritance leak
#     (k8s.io/community#kubectl-exec-vs-ssh-in-pod discussion thread).
#   - 25/tcp, 110/tcp, 143/tcp: legacy mail protocols with cleartext
#     auth in default configs.
#   - 161/udp: SNMPv1/v2 default community strings (``public``); CVE-1999-0517.
#   - 389/tcp: LDAP cleartext bind; 636/tcp (LDAPS) is the encrypted
#     alternative and is not warned.
#   - 445/tcp: SMB; never appropriate from a containerized workload
#     without an explicit reason.
#   - 3306/tcp (MySQL), 5432/tcp (PostgreSQL), 6379/tcp (Redis),
#     9200/tcp (Elasticsearch), 11211/tcp (Memcached), 27017/tcp
#     (MongoDB): default no-auth configurations. The Shodan
#     "Unauthorized Database Access" reports cite these by name.
#   - 3389/tcp: RDP — same rationale as SSH plus auth-bypass CVE history.
#
# Adding a new entry requires citing a "why" in this docstring; rule
# is to keep operators from tuning the list blindly.
RISKY_PORTS: dict[tuple[int, str], str] = {
    (21, "tcp"): "FTP",
    (22, "tcp"): "SSH",
    (23, "tcp"): "Telnet",
    (25, "tcp"): "SMTP",
    (110, "tcp"): "POP3",
    (143, "tcp"): "IMAP",
    (161, "udp"): "SNMP",
    (389, "tcp"): "LDAP",
    (445, "tcp"): "SMB",
    (3306, "tcp"): "MySQL",
    (3389, "tcp"): "RDP",
    (5432, "tcp"): "PostgreSQL",
    (6379, "tcp"): "Redis",
    (9200, "tcp"): "Elasticsearch",
    (11211, "tcp"): "Memcached",
    (27017, "tcp"): "MongoDB",
}


def _parse_port_proto(raw: str) -> tuple[int, str] | None:
    """Parse a ``PORT/PROTO`` string into ``(port, protocol)``.

    Accepts ``"22/tcp"`` (canonical), ``"22"`` (defaults to tcp),
    ``" 22 / TCP "`` (whitespace + case tolerated). Returns ``None``
    if the input doesn't parse — callers log + skip.
    """
    if not isinstance(raw, str):
        return None
    cleaned = raw.strip().lower().replace(" ", "")
    if not cleaned:
        return None
    if "/" in cleaned:
        port_str, proto = cleaned.split("/", 1)
    else:
        port_str, proto = cleaned, "tcp"
    try:
        port = int(port_str)
    except ValueError:
        return None
    if port < 1 or port > 65535:
        return None
    if proto not in ("tcp", "udp", "sctp"):
        return None
    return (port, proto)


# ── Risky services for the ``services`` sub-scanner ─────────────────
#
# When an image declares one of these systemd / SysV services, the
# ``services`` sub-scanner emits a MEDIUM-severity finding instead of
# the default INFO. Same rationale as ``RISKY_PORTS`` but at the
# service-declaration layer: container images that ship a systemd
# unit for these services *intend* to launch them on boot — even
# when an empty ``Config.ExposedPorts`` would have suggested
# otherwise — and the default configurations historically ship
# without auth.
#
# Keys are bare service names (filename without ``.service``);
# values are ``(default_port, rationale)`` tuples. The rationale is
# the short blurb that lands in the finding's description. Operators
# can override via ``scanners.container.services_warn`` in
# argus.yml or suppress entirely via
# ``scanners.container.services_ignore``.
#
# Sources for each entry:
#   - sshd: SSH-in-container is a recurring image-inheritance leak
#     (k8s.io/community#kubectl-exec-vs-ssh-in-pod thread); CIS
#     Docker Benchmark §5.18 ("ensure SSH is not running within
#     containers").
#   - telnetd, vsftpd: cleartext protocols (CIS Docker Benchmark §5.8).
#   - postgresql / mysqld / mariadb / mongod / redis-server / redis /
#     memcached / elasticsearch: default no-auth configurations
#     (Shodan "Unauthorized Database Access" reports name each by
#     service binding 0.0.0.0).
#   - snmpd: SNMPv1/v2 default community strings — CVE-1999-0517.
#   - rpcbind / nfs-server: wide RPC / network filesystem surface
#     never appropriate from a typical app container.
#
# Adding a new entry requires citing a "why" in this docstring —
# same rule as RISKY_PORTS, keeps operators from tuning the list
# blindly.
RISKY_SERVICES: dict[str, tuple[str, str]] = {
    "sshd":            ("22/tcp",    "SSH service (image-inheritance leak risk; CIS §5.18)"),
    "telnetd":         ("23/tcp",    "Telnet — cleartext protocol"),
    "vsftpd":          ("21/tcp",    "FTP — cleartext protocol"),
    "postgresql":      ("5432/tcp",  "PostgreSQL — default trust-auth misconfigurations"),
    "mysqld":          ("3306/tcp",  "MySQL — default no-auth + 0.0.0.0 bind common"),
    "mariadb":         ("3306/tcp",  "MariaDB — same posture as MySQL"),
    "redis-server":    ("6379/tcp",  "Redis — default no-password; protected-mode bypass via 0.0.0.0"),
    "redis":           ("6379/tcp",  "Redis — default no-password"),
    "mongod":          ("27017/tcp", "MongoDB — default no-auth + 0.0.0.0 bind common"),
    "memcached":       ("11211/tcp", "Memcached — no auth; UDP amplification vector"),
    "elasticsearch":   ("9200/tcp",  "Elasticsearch — default no-auth on unconfigured installs"),
    "snmpd":           ("161/udp",   "SNMP — default community string 'public' (CVE-1999-0517)"),
    "rpcbind":         ("111/tcp",   "RPC portmapper — wide RPC surface"),
    "nfs-server":      ("2049/tcp",  "NFS server — wide network filesystem surface"),
}


# Standard locations the ``services`` sub-scanner extracts from a
# container image's filesystem to discover service declarations.
# Includes both systemd and SysV init paths; missing paths in any
# given image are silently skipped.
_SERVICE_PATHS: tuple[str, ...] = (
    "/etc/systemd/system",
    "/lib/systemd/system",
    "/usr/lib/systemd/system",
    "/etc/init.d",
)


def _service_name_from_path(file_path: str) -> str | None:
    """Extract the bare service name from a unit-file or init-script path.

    Returns the stem of the filename for systemd unit files
    (``sshd.service`` → ``sshd``) or the filename itself for SysV
    init scripts (``/etc/init.d/sshd`` → ``sshd``). Returns ``None``
    for files that aren't recognizable service declarations
    (``.timer``, ``.socket``, etc.).
    """
    name = Path(file_path).name
    # systemd unit files we recognize as service declarations.
    # .timer, .socket, .target, .mount, etc. are deliberately
    # ignored — they're either trigger metadata or system
    # primitives, not first-class service-on-boot declarations.
    if name.endswith(".service"):
        return name[: -len(".service")]
    # SysV init scripts live in /etc/init.d/ and have no suffix.
    if "/init.d/" in file_path:
        return name
    return None


def _parse_systemd_unit(content: bytes) -> dict[str, str]:
    """Parse a systemd ``.service`` unit file into a flat dict.

    Returns a dict of ``{section.key: value}`` (e.g.
    ``{"Unit.Description": "...", "Service.ExecStart": "...",
    "Service.User": "..."}``). Stdlib-only; no configparser since
    systemd unit files allow duplicate keys (e.g. multiple
    ``ExecStartPre=``) and use ``=`` without spaces around the
    separator. We keep the *last* value for each key — sufficient
    for the fields the sub-scanner inspects.

    Returns an empty dict when content is unparsable (binary
    blob, truncated read, etc.) — callers treat that as "skip,
    not a service file."
    """
    result: dict[str, str] = {}
    try:
        text = content.decode("utf-8", errors="replace")
    except Exception:
        return result
    section = ""
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if not section or not key:
            continue
        result[f"{section}.{key}"] = value
    return result


class ContainerScanner:
    """Wraps Trivy, Grype, and Syft for container image scanning."""

    name = "container"
    description = "Container image vulnerability scanner — orchestrates Trivy, Grype, and Syft"
    category = "container"
    languages = ["docker"]
    # This scanner is an orchestrator, not a single-tool wrapper.  It runs
    # trivy, grype, and syft as separate sub-processes, each with its own
    # official container image (defined in containers.py).  Because of this
    # architecture the scanner cannot fall back to a single Docker image;
    # container_image is empty intentionally and Docker-fallback is handled
    # per sub-tool by the engine when local binaries are missing.
    container_image = ""

    def container_args(self, config: dict | None = None) -> list[str]:
        """Not applicable — this scanner orchestrates sub-tools directly.

        Each sub-tool (trivy, grype, syft) is invoked individually with its
        own container image and args, so a top-level container_args is unused.
        """
        return []

    def scan(self, path: str, config: dict | None = None) -> ScanResult:
        """Run enabled sub-scanners against a container image.

        The ``path`` argument is ignored; the image reference must be
        provided via ``config["image_ref"]``.

        When invoked via the source-scan dispatcher (``argus scan``
        with ``scanners.container.enabled: true`` in argus.yml but no
        ``containers.images`` or ``containers.discover`` configured),
        no ``image_ref`` is supplied. The pre-fix path returned a
        ScanResult with just ``metadata={"error": ...}``, which the
        engine read as "ran with 0 findings" and reported PASS —
        silent gap, issue #170. Now the scanner returns a partial-
        failure ScanResult with a ``container-source-resolution``
        phase recording the failure, so the engine folds the scanner
        into the "did not run cleanly" bucket and
        ``--fail-on-scanner-error`` exits non-zero.

        The standalone ``argus scan container`` path doesn't go through
        here — its CLI dispatcher constructs ScanResult directly and
        already emits a usage message when no source is configured.
        """
        config = config or {}
        image_ref = config.get("image_ref")
        if not image_ref:
            error = (
                "container scanner enabled but no images or discover "
                "paths configured. Add containers.images: or "
                "containers.discover: to argus.yml, set --image / "
                "--discover on the CLI, or remove container: from the "
                "scanner list."
            )
            return ScanResult(
                scanner=self.name,
                metadata={"error": "image_ref is required in config"},
                phase_results=[
                    PhaseResult(
                        phase="container-source-resolution",
                        status="failed",
                        findings=[],
                        error=error,
                    )
                ],
            )

        enabled = self._enabled_scanners(config)
        all_findings: list[Finding] = []
        metadata: dict = {}
        seen_cves: set[str] = set()

        env = self._build_env(config)

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)

            if "trivy" in enabled:
                trivy_output = tmp_path / "trivy-results.json"
                trivy_findings, trivy_meta = self._run_sub_scanner(
                    tool="trivy",
                    local_cmd=["trivy", "image", "--format", "json",
                               "--output", str(trivy_output), image_ref],
                    container_args=["image", "--format", "json",
                                    "--output", "/output/results.json", image_ref],
                    output_file=trivy_output,
                    parse_fn=self.parse_trivy_results,
                    env=env,
                )
                self._merge_findings(trivy_findings, all_findings, seen_cves)
                metadata["trivy"] = trivy_meta

            if "grype" in enabled:
                grype_output = tmp_path / "grype-results.json"
                grype_findings, grype_meta = self._run_sub_scanner(
                    tool="grype",
                    local_cmd=["grype", image_ref, "-o", "json",
                               "--file", str(grype_output)],
                    container_args=[image_ref, "-o", "json",
                                    "--file", "/output/results.json"],
                    output_file=grype_output,
                    parse_fn=self.parse_grype_results,
                    env=env,
                )
                self._merge_findings(grype_findings, all_findings, seen_cves)
                metadata["grype"] = grype_meta

            if "syft" in enabled:
                syft_output = tmp_path / "syft-sbom.json"
                syft_meta = self._run_syft_with_fallback(
                    image_ref, syft_output, env,
                )
                metadata["syft"] = syft_meta

            if "exposure" in enabled:
                exposure_findings, exposure_meta = self._scan_exposed_ports(
                    image_ref, config,
                )
                all_findings.extend(exposure_findings)
                metadata["exposure"] = exposure_meta

            if "services" in enabled:
                services_findings, services_meta = self._scan_services(
                    image_ref, config,
                )
                all_findings.extend(services_findings)
                metadata["services"] = services_meta

            if not metadata:
                metadata["error"] = (
                    "None of the enabled scanners "
                    "(trivy, grype, syft) could be executed — "
                    "install locally or ensure Docker is available"
                )

        return ScanResult(
            scanner=self.name,
            findings=all_findings,
            metadata=metadata,
        )

    def is_available(self) -> bool:
        """Check if at least one vulnerability scanner is available (local or Docker)."""
        if shutil.which("trivy") or shutil.which("grype"):
            return True
        # Check if Docker is available for container fallback
        from argus import container_runtime
        return container_runtime.is_available() and bool(get_image("trivy"))

    def install_command(self) -> str | None:
        """Return install hints for the container scanning tools."""
        return (
            "See https://aquasecurity.github.io/trivy, "
            "https://github.com/anchore/grype, "
            "https://github.com/anchore/syft"
        )

    def tool_version(self) -> str | None:
        """Return None — this is an orchestrator, not a single tool."""
        return None

    def parse_trivy_results(self, raw_output_path: Path) -> list[Finding]:
        """Parse Trivy container JSON output into findings."""
        data = json.loads(raw_output_path.read_text(encoding="utf-8", errors="replace"))
        findings: list[Finding] = []

        for target in data.get("Results", []):
            for vuln in target.get("Vulnerabilities", []):
                findings.append(self._parse_trivy_vuln(vuln))

        return findings

    def parse_grype_results(self, raw_output_path: Path) -> list[Finding]:
        """Parse Grype JSON output into findings."""
        data = json.loads(raw_output_path.read_text(encoding="utf-8", errors="replace"))
        findings: list[Finding] = []

        for match in data.get("matches", []):
            findings.append(self._parse_grype_match(match))

        return findings

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _enabled_scanners(self, config: dict) -> list[str]:
        """Return list of enabled sub-scanner names from config.

        Default set covers vulnerability scanning (trivy, grype),
        SBOM generation (syft), and attack-surface visibility
        (exposure — declared Dockerfile EXPOSE ports). Disable any
        of them explicitly via the ``scanners`` config key.
        """
        raw = config.get("scanners", "trivy,grype,syft,exposure,services")
        return [s.strip().lower() for s in raw.split(",") if s.strip()]

    def _scan_exposed_ports(
        self, image_ref: str, config: dict,
    ) -> tuple[list[Finding], dict]:
        """Read ``Config.ExposedPorts`` from the image manifest.

        One ``Finding`` per declared port:
          - severity INFO for ordinary application ports;
          - severity WARN for ports on the built-in ``RISKY_PORTS``
            list (or the operator's override).
        Config knobs:
          ``scanners.container.expose_warn_ports``  – override the
              built-in WARN list. Replaces the default; pass an empty
              list to suppress all WARN-severity findings.
          ``scanners.container.expose_ignore_ports`` – suppress findings
              entirely for these ports (intended for ports the team
              has explicitly accepted, e.g. their app's known 8080/tcp).
        Both lists take ``"PORT/PROTO"`` strings.
        """
        from argus import container_runtime

        rt = container_runtime.runtime_cmd()
        if not container_runtime.is_available():
            return [], {
                "skipped": "no container runtime available — install Docker, "
                           "Podman, or nerdctl to enable exposed-port discovery",
            }

        # Ensure the image is present locally before inspecting.
        # ``if-not-present`` is a fast cache hit when trivy/grype/syft
        # already pulled the image in this scan run.
        if not container_runtime.pull_image(image_ref, policy="if-not-present"):
            return [], {
                "error": f"could not pull or locate image {image_ref} for inspection",
            }

        result = subprocess.run(
            [rt, "image", "inspect", image_ref],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            return [], {
                "error": (
                    f"docker inspect failed (rc={result.returncode}): "
                    f"{result.stderr.strip()[:300]}"
                ),
            }

        try:
            inspected = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            return [], {"error": f"could not parse docker inspect output: {exc}"}

        if not isinstance(inspected, list) or not inspected:
            return [], {"error": "docker inspect returned no image entries"}

        config_block = inspected[0].get("Config") or {}
        exposed = config_block.get("ExposedPorts") or {}

        # Resolve config-driven WARN-list override and ignore-list.
        warn_override = config.get("expose_warn_ports")
        if warn_override is not None:
            # Operator-provided list REPLACES the built-in defaults.
            warn_set = {
                pp for raw in warn_override
                if (pp := _parse_port_proto(raw)) is not None
            }
        else:
            warn_set = set(RISKY_PORTS.keys())

        ignore_set = {
            pp for raw in (config.get("expose_ignore_ports") or [])
            if (pp := _parse_port_proto(raw)) is not None
        }

        findings: list[Finding] = []
        ignored_count = 0
        for raw_port in sorted(exposed.keys()):
            parsed = _parse_port_proto(raw_port)
            if parsed is None:
                logger.warning(
                    "Skipping unparsable port reference '%s' in %s ExposedPorts",
                    raw_port, image_ref,
                )
                continue
            port, proto = parsed
            if (port, proto) in ignore_set:
                ignored_count += 1
                continue

            is_risky = (port, proto) in warn_set
            service = RISKY_PORTS.get((port, proto))
            severity = Severity.MEDIUM if is_risky else Severity.INFO
            title_service = f" ({service})" if service else ""
            description = (
                f"Image declares EXPOSE for port {port}/{proto}{title_service}. "
                + (
                    "This is on the risky-defaults watchlist — services on "
                    "this port have a history of weak default configurations. "
                    "Confirm the container actually intends to listen here "
                    "and that authentication/TLS is in front of it."
                    if is_risky else
                    "Declared exposed port — informational. No action required "
                    "unless the port is unexpected for this image."
                )
            )
            findings.append(
                Finding(
                    id=f"EXPOSE-{port}-{proto}",
                    severity=severity,
                    title=(
                        f"Port {port}/{proto}{title_service} declared exposed"
                    ),
                    description=description,
                    scanner=self.name,
                    metadata={
                        "port": port,
                        "protocol": proto,
                        "common_service": service or "",
                        "risky": is_risky,
                        "image_ref": image_ref,
                    },
                ),
            )

        return findings, {
            "execution": "local-inspect",
            "ports_declared": len(exposed),
            "ports_reported": len(findings),
            "ports_ignored": ignored_count,
        }

    def _extract_paths_from_image(
        self, image_ref: str, paths: tuple[str, ...] | list[str],
    ) -> dict[str, bytes]:
        """Pull files from a container image's filesystem without running it.

        Creates a stopped container from ``image_ref`` (no entrypoint
        execution; works on distroless / scratch images that don't
        even have a shell), then uses ``docker cp`` to stream each
        requested path out as a tar archive. Returns a flat mapping
        of in-container absolute path -> raw file bytes. Missing
        paths are silently skipped; the container is removed in a
        ``finally`` so partial extraction never leaves dangling
        container IDs.

        This is the read-side primitive shared by the ``services``
        sub-scanner and any future config-file walker (e.g.
        ``sshd_config`` parsing). Stdlib + container_runtime only.
        """
        from argus import container_runtime
        import io
        import tarfile

        rt = container_runtime.runtime_cmd()
        if not container_runtime.is_available():
            return {}

        # Ensure the image is locally present. The container scanner's
        # trivy/grype step normally pulls already; this is the safety
        # net when ``services`` runs as the only enabled sub-scanner.
        if not container_runtime.pull_image(image_ref, policy="if-not-present"):
            return {}

        create = subprocess.run(
            [rt, "create", image_ref],
            capture_output=True, text=True,
        )
        if create.returncode != 0 or not create.stdout.strip():
            return {}
        cid = create.stdout.strip()

        extracted: dict[str, bytes] = {}
        try:
            for path in paths:
                cp = subprocess.run(
                    [rt, "cp", f"{cid}:{path}", "-"],
                    capture_output=True,
                )
                if cp.returncode != 0 or not cp.stdout:
                    # Path doesn't exist in the image — common for any
                    # given image since we walk a superset of paths
                    # (SysV /etc/init.d won't be on a pure-systemd
                    # base, /lib/systemd vs /usr/lib/systemd varies by
                    # distro, etc.).
                    continue

                # docker cp -- emits a tar archive of the source.
                # When source is a directory ``/etc/systemd/system``,
                # tar member names look like ``system/sshd.service``
                # — relative to the source's parent. Reconstruct the
                # full in-container path by prepending the parent.
                parent = str(Path(path).parent).rstrip("/")
                try:
                    with tarfile.open(
                        fileobj=io.BytesIO(cp.stdout), mode="r:*",
                    ) as tf:
                        for member in tf.getmembers():
                            if not member.isfile():
                                continue
                            f = tf.extractfile(member)
                            if f is None:
                                continue
                            # Bound a single file's read so a hostile
                            # image (giant log dropped in /etc/init.d)
                            # can't blow up memory. 1 MiB is far above
                            # any real systemd unit or service config.
                            content = f.read(1024 * 1024)
                            full_path = (
                                f"{parent}/{member.name}" if parent != "/"
                                else f"/{member.name}"
                            )
                            extracted[full_path] = content
                except (tarfile.TarError, OSError) as exc:
                    logger.debug(
                        "services: failed to parse tar stream for %s: %s",
                        path, exc,
                    )
                    continue
        finally:
            subprocess.run(
                [rt, "rm", "-f", cid],
                capture_output=True,
            )

        return extracted

    def _scan_services(
        self, image_ref: str, config: dict,
    ) -> tuple[list[Finding], dict]:
        """Enumerate services the image would launch on boot.

        Walks systemd unit files (``/etc/systemd/system``,
        ``/lib/systemd/system``, ``/usr/lib/systemd/system``) and
        SysV init scripts (``/etc/init.d``) from the image's
        filesystem; emits one ``Finding`` per service with severity
        INFO by default and MEDIUM for services on the built-in
        ``RISKY_SERVICES`` watchlist (sshd, postgresql, redis, etc.).

        Same operational shape as ``_scan_exposed_ports`` — one
        offline filesystem extraction + parse; no container runtime
        execution; works on distroless / scratch / systemd-in-
        container images alike.

        Config knobs:
          ``scanners.container.services_warn``  -- list[str] of
              service names that should be elevated to MEDIUM,
              replacing the built-in ``RISKY_SERVICES`` set entirely.
              Pass an empty list to suppress all WARN-severity
              findings (every service becomes INFO).
          ``scanners.container.services_ignore`` -- list[str] of
              service names to suppress entirely (intended for
              services the team has explicitly accepted).
        """
        from argus import container_runtime

        if not container_runtime.is_available():
            return [], {
                "skipped": "no container runtime available — install Docker, "
                           "Podman, or nerdctl to enable service enumeration",
            }

        files = self._extract_paths_from_image(image_ref, _SERVICE_PATHS)
        if not files:
            return [], {
                "execution": "local-extract",
                "services_declared": 0,
                "services_reported": 0,
                "services_ignored": 0,
            }

        # Resolve config-driven WARN-list override and ignore-list.
        warn_override = config.get("services_warn")
        if warn_override is not None:
            warn_set = {str(s).strip().lower() for s in warn_override if s}
        else:
            warn_set = set(RISKY_SERVICES.keys())

        ignore_set = {
            str(s).strip().lower()
            for s in (config.get("services_ignore") or [])
            if s
        }

        findings: list[Finding] = []
        ignored_count = 0
        # Sort for deterministic order across runs (helpful for tests
        # and for diff-friendly markdown / SARIF output).
        for file_path in sorted(files.keys()):
            svc_name = _service_name_from_path(file_path)
            if not svc_name:
                continue
            svc_lower = svc_name.lower()

            if svc_lower in ignore_set:
                ignored_count += 1
                continue

            unit_fields: dict[str, str] = {}
            if file_path.endswith(".service"):
                unit_fields = _parse_systemd_unit(files[file_path])

            is_risky = svc_lower in warn_set
            risky_meta = RISKY_SERVICES.get(svc_lower)
            severity = Severity.MEDIUM if is_risky else Severity.INFO

            description = (
                unit_fields.get("Unit.Description", "").strip()
                or "Service declared by image filesystem"
            )
            if risky_meta:
                port, rationale = risky_meta
                description = (
                    f"{rationale} (default bind: {port}). "
                    f"Confirm the image actually intends to launch this "
                    f"service and that authentication / TLS is in front "
                    f"of it. Source: {file_path}"
                )
            else:
                description = (
                    f"{description}. Declared exposed service — "
                    f"informational. Source: {file_path}"
                )

            findings.append(
                Finding(
                    id=f"SVC-{svc_lower}",
                    severity=severity,
                    title=(
                        f"Service {svc_name} declared by image"
                        + (f" ({risky_meta[0]})" if risky_meta else "")
                    ),
                    description=description,
                    scanner=self.name,
                    metadata={
                        "service": svc_name,
                        "source": file_path,
                        "exec_start": unit_fields.get("Service.ExecStart", ""),
                        "user": unit_fields.get("Service.User", ""),
                        "default_port": risky_meta[0] if risky_meta else "",
                        "risky": is_risky,
                        "image_ref": image_ref,
                    },
                ),
            )

        return findings, {
            "execution": "local-extract",
            "services_declared": len([
                p for p in files if _service_name_from_path(p)
            ]),
            "services_reported": len(findings),
            "services_ignored": ignored_count,
        }

    def _build_env(self, config: dict) -> dict[str, str]:
        """Build environment dict with optional registry credentials.

        Credentials are resolved via ``argus.core.secrets.resolve_secret``,
        which accepts either form:

          registry_username:     "literal"            # back-compat, warned
                                                      # if vendor-shaped
          registry_username_env: ENV_VAR_NAME         # preferred

        The resolved values are exported to the env vars Trivy / Grype /
        Syft each natively read for registry authentication.
        """
        from argus.core.secrets import get_stdin_override, resolve_secret

        env = dict(os.environ)
        username = resolve_secret(config, "registry_username")
        password = resolve_secret(
            config, "registry_password",
            stdin_override=get_stdin_override("registry_password"),
        )

        if username:
            env["TRIVY_USERNAME"] = username
            env["GRYPE_REGISTRY_AUTH_USERNAME"] = username
            env["SYFT_REGISTRY_AUTH_USERNAME"] = username
        if password:
            env["TRIVY_PASSWORD"] = password
            env["GRYPE_REGISTRY_AUTH_PASSWORD"] = password
            env["SYFT_REGISTRY_AUTH_PASSWORD"] = password

        return env

    def _run_sub_scanner(
        self,
        tool: str,
        local_cmd: list[str],
        container_args: list[str],
        output_file: Path,
        parse_fn,
        env: dict[str, str],
    ) -> tuple[list[Finding], dict]:
        """Run a sub-scanner locally or via Docker fallback.

        Tries local binary first, falls back to container image if not
        installed and a container runtime is available.
        """
        if shutil.which(tool):
            logger.debug("Running %s locally", tool)
            result = subprocess.run(
                local_cmd, capture_output=True, text=True, env=env,
            )
            meta: dict = {"returncode": result.returncode, "execution": "local"}
        else:
            # Docker fallback
            from argus import container_runtime
            image = get_image(tool)
            if not image or not container_runtime.is_available():
                logger.warning(
                    "%s not installed and no container runtime available — skipping",
                    tool,
                )
                return [], {"error": f"{tool} not available (local or container)"}

            if not container_runtime.pull_image(image):
                return [], {"error": f"Failed to pull {image}"}

            logger.info("Running %s via container: %s", tool, image)
            rt = container_runtime.runtime_cmd()
            output_dir = str(output_file.parent)
            cmd = [
                rt, "run", "--rm",
                "-v", f"{output_dir}:/output",
                image,
            ] + container_args

            result = subprocess.run(
                cmd, capture_output=True, text=True, env=env,
            )
            meta = {"returncode": result.returncode, "execution": "container", "image": image}

            # Container writes to /output/results.json — copy to expected path
            container_output = output_file.parent / "results.json"
            if container_output.exists() and container_output != output_file:
                container_output.rename(output_file)

        if not output_file.exists():
            meta["error"] = result.stderr.strip() or "No output produced"
            return [], meta

        findings = parse_fn(output_file)
        return findings, meta

    def _run_syft_with_fallback(
        self,
        image_ref: str,
        output_file: Path,
        env: dict[str, str],
    ) -> dict:
        """Run Syft SBOM generation locally or via Docker fallback."""
        if shutil.which("syft"):
            cmd = [
                "syft", image_ref,
                "-o", "cyclonedx-json",
                "--file", str(output_file),
            ]
            result = subprocess.run(
                cmd, capture_output=True, text=True, env=env,
            )
            meta: dict = {"returncode": result.returncode, "execution": "local"}
        else:
            from argus import container_runtime
            image = get_image("syft")
            if not image or not container_runtime.is_available():
                return {"error": "syft not available (local or container)"}

            if not container_runtime.pull_image(image):
                return {"error": f"Failed to pull {image}"}

            logger.info("Running syft via container: %s", image)
            rt = container_runtime.runtime_cmd()
            output_dir = str(output_file.parent)
            cmd = [
                rt, "run", "--rm",
                "-v", f"{output_dir}:/output",
                image,
                image_ref,
                "-o", "cyclonedx-json",
                "--file", "/output/results.json",
            ]
            result = subprocess.run(
                cmd, capture_output=True, text=True, env=env,
            )
            meta = {"returncode": result.returncode, "execution": "container", "image": image}
            container_output = output_file.parent / "results.json"
            if container_output.exists() and container_output != output_file:
                container_output.rename(output_file)

        if output_file.exists():
            meta["sbom_path"] = str(output_file)
        else:
            meta["error"] = result.stderr.strip() or "No output produced"

        return meta

    def _merge_findings(
        self,
        new_findings: list[Finding],
        target: list[Finding],
        seen_cves: set[str],
    ) -> None:
        """Append findings to target, deduplicating by CVE ID."""
        for finding in new_findings:
            cve = finding.cve
            if cve and cve in seen_cves:
                continue
            if cve:
                seen_cves.add(cve)
            target.append(finding)

    def _parse_trivy_vuln(self, vuln: dict) -> Finding:
        """Convert a single Trivy vulnerability to a Finding."""
        severity = Severity.from_string(
            vuln.get("Severity", "UNKNOWN")
        )

        cwe = None
        cwe_ids = vuln.get("CweIDs") or []
        if cwe_ids:
            cwe = cwe_ids[0]

        vuln_id = vuln.get("VulnerabilityID", "UNKNOWN")
        pkg = vuln.get("PkgName", "")
        installed = vuln.get("InstalledVersion", "")
        fixed = vuln.get("FixedVersion", "")

        return Finding(
            id=vuln_id,
            severity=severity,
            title=vuln.get("Title", vuln_id),
            description=vuln.get("Description", ""),
            location=f"{pkg}@{installed}" if pkg else None,
            cwe=cwe,
            cve=vuln_id if vuln_id.startswith("CVE-") else None,
            scanner=self.name,
            metadata={
                "tool": "trivy",
                "package": pkg,
                "installed_version": installed,
                "fixed_version": fixed,
            },
        )

    def _parse_grype_match(self, match: dict) -> Finding:
        """Convert a single Grype match to a Finding."""
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})

        vuln_id = vuln.get("id", "UNKNOWN")
        severity = Severity.from_string(
            vuln.get("severity", "Unknown")
        )

        pkg_name = artifact.get("name", "")
        pkg_version = artifact.get("version", "")

        fix_versions = vuln.get("fix", {}).get("versions", [])
        fixed = ", ".join(fix_versions) if fix_versions else ""

        return Finding(
            id=vuln_id,
            severity=severity,
            title=vuln.get("description", vuln_id),
            description=vuln.get("description", ""),
            location=f"{pkg_name}@{pkg_version}" if pkg_name else None,
            cve=vuln_id if vuln_id.startswith("CVE-") else None,
            scanner=self.name,
            metadata={
                "tool": "grype",
                "package": pkg_name,
                "installed_version": pkg_version,
                "fixed_version": fixed,
            },
        )
