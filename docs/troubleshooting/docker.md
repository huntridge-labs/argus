# Docker troubleshooting

`argus scan` runs each scanner inside an immutable container by default. That
buys reproducibility — but it also means most scan failures bottom out in
something Docker did or did not do. This page is a single-stop reference for
the Docker-shaped pain points users hit most often: runtime detection, bind-mount
permissions, image pulls, network proxies, cache mounts, and the way the
engine reports execution / parse failures.

The runtime path is implemented in
[`argus/core/engine.py`](../../argus/core/engine.py) (`_detect_runtime`,
`_pull_image`, `_run_in_container`). When in doubt about what the engine is
doing, run with `--verbose` — every command, exit code, and stderr summary is
logged at DEBUG.

> **Backend selection**: this page assumes `execution.backend: auto` (the
> default) or `docker`. If you run with `backend: local`, the engine never
> launches a container — none of the symptoms below apply. See
> [Configuration Reference → execution](../config-reference.md#execution-backend)
> for the full backend semantics.

---

## Docker not installed / not on PATH / not running

**Problem.** The engine couldn't find a usable container runtime, or it found
one but the daemon isn't running. With `backend: auto` you'll see scanners
fall through to local execution (and fail with `not installed` if the local
binary is missing). With `backend: docker` the run aborts with
`Docker not available. No container runtime available.`.

**How to verify.**

```bash
docker info                  # daemon up?
docker run --rm hello-world  # full round-trip works?
argus scan --verbose         # check the "Using container runtime: ..." log line
```

**Fix.**

- Install Docker Desktop (macOS / Windows), Docker Engine (Linux), Podman, or
  nerdctl. The engine accepts any of them — see the next section.
- On Linux, ensure your user is in the `docker` group, or use `sudo`. After
  adding yourself to the group, log out and back in.
- On macOS / Windows, start Docker Desktop and wait for the whale icon to
  stop animating before scanning.
- Force the local code path while you debug Docker by editing `argus.yml`:

```yaml
execution:
  backend: local
```

This is fine for one-off triage but loses Argus's version pinning — the
engine will warn about scanner-version drift unless you also pass
`--allow-local-versions`.

---

## Wrong runtime selected (docker vs podman vs nerdctl)

**Problem.** You have multiple container CLIs on PATH and the engine picked
the wrong one — typically because Docker is installed but the daemon is down,
yet `docker` is still on PATH and gets selected over a working Podman.

**How the engine picks.** From `ArgusEngine._detect_runtime` in
[`argus/core/engine.py`](../../argus/core/engine.py):

1. `ARGUS_CONTAINER_RUNTIME` environment variable (explicit override, must
   resolve via `shutil.which`).
2. Auto-detect, in order: `docker`, `podman`, `nerdctl`. First match wins.

**How to verify.**

```bash
argus scan --verbose 2>&1 | grep -i "container runtime"
# Using container runtime: docker
```

**Fix — environment override (one shot).**

```bash
ARGUS_CONTAINER_RUNTIME=podman argus scan
```

**Fix — config file.** The runtime itself is auto-detected, but you can
disable Docker in your shell so Podman wins the fallback:

```bash
export ARGUS_CONTAINER_RUNTIME=podman
```

The auto-detector never tries combinations — it commits to the first runtime
it finds. If `docker` is on PATH but broken, set `ARGUS_CONTAINER_RUNTIME`
explicitly rather than uninstalling Docker.

---

## Permission denied writing to `/output` (uid mismatch)

**Problem.** A scanner runs but produces no output files. Verbose logs show
something like `Permission denied: /output/results.json` from the container,
followed by `Scanner 'X' produced no output files` from the engine. This is
the most common silent-failure mode on macOS.

**Root cause.** Argus mounts a host tempdir at `/output` for the scanner to
write into. Most Argus scanner images run as a non-root user (`USER argus`,
uid 1000); the invoking host user on macOS is commonly uid 501. Python's
`tempfile.TemporaryDirectory` creates the host dir with mode `0o700`, which
the container's uid 1000 process can't write into.

**Fix.** Already shipped — see commit `3e7dc78` and
`ArgusEngine._run_in_container` in [`argus/core/engine.py`](../../argus/core/engine.py)
(search for `os.chmod(output_dir, 0o777)`). On Linux and macOS the engine
chmods the host tempdir before launching the container. On Windows the
chmod is skipped because NTFS doesn't honor POSIX bits and Docker Desktop
maps uids differently — calling `chmod 0o777` there is at best a no-op.

**How to verify the fix is in effect.**

```bash
argus version            # should be the release containing 3e7dc78 (>= 0.7.x)
argus scan --verbose 2>&1 | grep -i "no output files"
```

If you still see permission-denied output after upgrading, check that
`$TMPDIR` (macOS / Linux) points at a directory where Docker Desktop's File
Sharing settings allow bind mounts. On macOS, that's typically `/private/tmp`,
`/tmp`, `/Users/...` — the defaults. If you've redirected `$TMPDIR` to a
custom path, add it to **Docker Desktop → Settings → Resources → File Sharing**.

For details on why `0o777` is safe in this specific context (host-only
tempdir, random name, removed at end of with-block, no secrets), read the
inline comment in `_run_in_container` directly.

---

## Container exits with code 127 (executable not found)

**Problem.** A scanner's container starts and immediately exits with
return code 127. No findings, no output files, no useful stderr. Most often
seen with `osv-scanner`.

**Root cause.** Docker's `--entrypoint` override does **not** consult the
image's `$PATH` when given a bare binary name. Some scanner images declare an
absolute entrypoint (e.g. `ghcr.io/google/osv-scanner` uses
`ENTRYPOINT ["/osv-scanner"]`) and require the absolute path on the override.
A bare `osv-scanner` resolves nowhere and exits 127.

**How to verify.** Inspect the image's actual entrypoint:

```bash
docker image inspect ghcr.io/google/osv-scanner \
  --format '{{json .Config.Entrypoint}}'
# ["/osv-scanner"]
```

**Fix.** This is fixed for OSV in PR #125 — the scanner class declares
`container_entrypoint = "/osv-scanner"` and the engine strips `argv[0]` for
ENTRYPOINT-based images. See
[`argus/scanners/osv.py`](../../argus/scanners/osv.py).

If you hit `exit 127` on a different scanner you're maintaining, follow the
same pattern: set `container_entrypoint` on the scanner class to the absolute
path read from `Config.Entrypoint`. The full failure pattern is documented
in [`.ai/errors.yaml`](../../.ai/errors.yaml) under
`category: scanner-execution` / `pattern: "exit 127|exec.*not found"`.

---

## Image pull failures: registry auth, rate limits, air-gapped GHES

**Problem.** A scanner aborts with `Failed to pull container image: <image>`
during the first phase of `_run_in_container`. The cause is one of: Docker
Hub rate limits (`toomanyrequests`), missing credentials for a private
registry, or an air-gapped environment where the registry is simply
unreachable.

**How to verify.**

```bash
argus scan --verbose 2>&1 | grep -i "Pulling container image\|Failed to pull"
docker pull <image>          # reproduce the pull outside argus
```

**Fix — Docker Hub rate limits.** Authenticate. Anonymous pulls cap at
100 / 6h per IP; authenticated pulls at 200 / 6h.

```bash
docker login docker.io -u <user>
```

**Fix — private registry.** For composite-action workflows, pass credentials
to the action:

```yaml
with:
  registry_username: ${{ secrets.REGISTRY_USER }}
  registry_password: ${{ secrets.REGISTRY_TOKEN }}
```

For SDK / CLI runs, log in to the registry on the host before invoking
`argus scan`:

```bash
echo "$REGISTRY_TOKEN" | docker login ghcr.io -u "$REGISTRY_USER" --password-stdin
argus scan
```

`.ai/errors.yaml → "registry.*authentication.*failed"` covers the registry
auth case end-to-end.

**Fix — target image fails to authenticate inside the sub-scanner container.**
Different failure mode from the scanner-image pull above: this is when Trivy,
Grype, or Syft (running inside their own container) can't reach the target
image's registry because credentials never made it into the sub-scanner's
process. Symptoms:

- Trivy: `FATAL Fatal error  run error: image scan error: scan error: unable
  to initialize a scan service` (terse, doesn't distinguish auth from other
  init failures).
- Grype: `failed to catalog: errors occurred attempting to resolve '<ref>':
  - docker: docker not available ... - podman: podman not available ...`
  (Grype tries local-daemon sources from inside the container; if no
  `registry:` prefix is supplied on the ref, the registry source isn't
  attempted and the auth env vars never get used).

Argus forwards resolved credentials as the sub-scanner's native env vars
(`TRIVY_USERNAME/PASSWORD`, `GRYPE_REGISTRY_AUTH_USERNAME/PASSWORD`,
`SYFT_REGISTRY_AUTH_USERNAME/PASSWORD`) via `-e` flags on `docker run` for
the container backend and via `env=` for the local-binary backend. Configure
them under `containers:` in argus.yml:

```yaml
containers:
  # Single-default shortcut — all images use the same creds.
  registry_username_env: REGISTRY_USER
  registry_password_env: REGISTRY_TOKEN
```

For multi-registry setups, use the `registry_auth` map (longest-prefix
matching):

```yaml
containers:
  registry_auth:
    registry.example.com:
      username_env: REGISTRY_DEFAULT_USER
      password_env: REGISTRY_DEFAULT_TOKEN
    registry.example.com/internal/restricted:
      username_env: REGISTRY_RESTRICTED_USER
      password_env: REGISTRY_RESTRICTED_TOKEN
```

If a `registry_auth` entry matches but the referenced env var is unset,
Argus logs a `WARNING` naming the missing variable and refuses to fall
back to a broader entry's creds (no silent privilege broadening). Run
with `--verbose` to see the redacted `docker run` invocation argus
constructs — confirms which env vars were forwarded.

**Fix — private image 401s when you authenticated with `docker login`
(e.g. AWS ECR).** If you don't pass `registry_username` / `registry_auth`
to Argus but instead authenticate the host the usual CI way:

```bash
aws ecr get-login-password --region us-east-1 \
  | docker login --username AWS --password-stdin <acct>.dkr.ecr.us-east-1.amazonaws.com
```

…those credentials live in the host `~/.docker/config.json`, which a
sub-scanner running on the Docker-fallback path (no trivy/grype binary on
the runner) cannot see — so the pull falls back to anonymous and the
registry returns `401 Unauthorized`. Argus bridges this automatically:
it stages a sanitized copy of the host Docker config (inline `auths`
only — `credsStore` / `credHelpers` are dropped because the helper
binary they name isn't present inside the scanner image) and mounts it
read-only into the sub-scanner container with `DOCKER_CONFIG` pointed at
the mount. No argus.yml change is required; a prior `docker login` is
enough. Two equivalent alternatives: install trivy + grype as local
binaries on the runner (local binaries read `~/.docker/config.json`
directly), or configure `registry_auth` so creds are forwarded as `-e`
env vars regardless of `docker login`.

Bisect before blaming argus: `docker pull <ref>` outside argus with the
same creds proves whether your account has access. If `docker pull`
fails too, the issue is creds or registry permissions, not the scan
plumbing.

**Fix — locally-built image scanned by reference resolves to Docker Hub.**
A different shape again: you built the image in one CI step (e.g.
`docker build -t hardening-test-opa:scan-<sha> .`) and scan it by ref in a
later step with `argus scan container --image hardening-test-opa:scan-<sha>`.
The image is never pushed anywhere, yet Grype tries to resolve it against
Docker Hub:

```
failed to catalog: errors occurred attempting to resolve 'hardening-test-opa:scan-<sha>':
  - oci-registry: ... GET https://index.docker.io/v2/library/hardening-test-opa/manifests/scan-<sha>: UNAUTHORIZED: authentication required
```

The scan then reports `0 findings` but exits non-zero
(`1 scanner failure(s) — results are incomplete`, exit 2). Root cause: the
target has no `dockerfile:` (Argus didn't build it), so it used to be
classified as *remote* and the runners fell through to the `registry:`
source — which defaults a bare name to `docker.io/library/<name>`.

Argus now also probes the local Docker daemon (`docker image inspect`) for
ref-only targets; if the image is already present, it scans via the
`docker:` daemon source instead. **No config change is needed** — just make
sure the image is built (present in the daemon) before the scan step runs.
This is the SDK/CLI counterpart to the daemon-vs-registry source selection,
and applies to Trivy (`--image-src remote` is dropped) and Syft as well.

One consequence worth knowing: if you pass a *fully-qualified registry ref*
(e.g. `ghcr.io/org/app:1.0`) that also happens to be cached locally, Argus
scans the **local copy**, not the current registry manifest — so a stale
local image would be scanned instead of what the registry serves today.
Argus logs an `INFO` line naming the image when this happens (`… found in
the local Docker daemon; scanning the local copy …`); run with `--verbose`
to see it. If you specifically want the registry version, remove the local
copy first (`docker rmi <ref>`) so the probe misses and the `registry:`
source is used.

**Fix — air-gapped GHES (mirror images).** Pre-pull every Argus scanner
image on a machine with internet, push them to your internal registry, and
point Argus at the mirror via `execution.registry`:

```yaml
execution:
  registry: registry.internal.corp/argus
  pull_policy: if-not-present
```

The mirror path is implemented in `_resolve_image` (same file). Argus
preserves the original `<repo>/<image>:<tag>` shape, just swaps the registry
host. See **GHES with private container registry** below for the full mirror
playbook.

**Fix — Harbor / Artifactory / ECR (per-upstream proxy caches).** The flat
`execution.registry` setting assumes one mirror that proxies *every* upstream
Argus uses. Proxy-cache projects on Harbor / Artifactory / ECR mirror a
**single** upstream registry per project — so a `dockerhub-cache` project
catches Argus's 9 Docker Hub images but can't serve the 7 GHCR ones (or
vice versa). Use `execution.registry_map` to point each upstream at its
corresponding mirror:

```yaml
execution:
  registry_map:
    docker.io: harbor.internal.corp/dockerhub-cache
    ghcr.io:   harbor.internal.corp/ghcr-cache
  pull_policy: if-not-present
```

Resolution rules:

- The upstream host is the first slash-segment when it contains a `.` /
  `:` (or equals `localhost`); otherwise the reference is treated as
  bare-name `docker.io`.
- The path under the mirror host preserves the upstream path verbatim
  (e.g. `ghcr.io/google/osv-scanner:tag` → `<ghcr-mirror>/google/osv-scanner:tag`),
  matching how Harbor proxy-caches lay out replicated content.
- A partial map leaves unmapped upstreams alone — they fall through to
  the legacy `execution.registry` setting (if set), then to the
  original reference unchanged.
- The `@sha256:` digest pin travels with the rewritten reference, so
  content-addressable pull verification still gates the bytes.

---

## Network proxies inside the container

**Problem.** The host can reach the internet through an HTTPS proxy, but
scanners that fetch databases at runtime (e.g. Trivy hitting its
vulnerability database, OSV-scanner hitting `osv.dev`) hang or time out
inside the container.

**Root cause.** `docker run` does not propagate `HTTP_PROXY` / `HTTPS_PROXY`
/ `NO_PROXY` from the host into the container automatically. Argus likewise
does not (by design — proxy semantics are environment-specific and
auto-injecting them is a footgun).

**How to verify.**

```bash
docker run --rm alpine sh -c 'env | grep -i proxy'
# (empty) → confirms host proxy isn't reaching the container
```

**Fix — Docker Desktop.** Configure proxies in **Docker Desktop → Settings →
Resources → Proxies**. Docker Desktop injects the variables into every
container automatically.

**Fix — Docker Engine on Linux.** Configure the proxy in the daemon and
restart it:

```bash
# /etc/systemd/system/docker.service.d/http-proxy.conf
[Service]
Environment="HTTP_PROXY=http://proxy.corp:3128"
Environment="HTTPS_PROXY=http://proxy.corp:3128"
Environment="NO_PROXY=localhost,127.0.0.1,.corp"

sudo systemctl daemon-reload && sudo systemctl restart docker
```

The systemd-level config affects `docker pull`. To inject proxies into the
*scanner process* itself, set them in the user environment that runs Argus:

```bash
export HTTPS_PROXY=http://proxy.corp:3128
export NO_PROXY=localhost,127.0.0.1,.corp
argus scan
```

Argus does not currently re-emit these as `-e HTTPS_PROXY=...` flags on
`docker run`. If your scanners need in-container proxy access, configure it
at the daemon level (Docker Desktop / systemd) so it applies image-wide.

---

## Pull-policy gotchas (`always` / `if-not-present` / `never`)

**Problem.** A CI run pulls a fresh scanner image every time and burns
minutes; or a dev's local cache goes stale and they get last week's CVE
database; or an air-gapped runner errors out trying to reach a registry it
can't see.

**How to verify.**

```bash
argus scan --verbose 2>&1 | grep -i "Pull policy\|Pulled\|skipping pull"
```

**Fix.** Three policies, configured under `execution.pull_policy` in
`argus.yml` (default: `if-not-present`). Implementation:
`ArgusEngine._pull_image` in [`argus/core/engine.py`](../../argus/core/engine.py).

| Policy           | Behavior                                                      | Use when                                                |
| ---------------- | ------------------------------------------------------------- | ------------------------------------------------------- |
| `always`         | Pull on every run, no local-cache check                       | Local dev where you want bleeding-edge CVE DBs          |
| `if-not-present` | Pull only if the image isn't cached locally (default)         | CI, day-to-day dev — best speed/freshness tradeoff      |
| `never`          | Never pull; fail if the image isn't already cached            | Air-gapped runners, bandwidth-constrained environments  |

Recommended pairings:

```yaml
# CI — predictable speed, ephemeral runners pull once per workflow
execution:
  pull_policy: if-not-present

# Air-gapped — registry is unreachable, all images pre-staged
execution:
  pull_policy: never
  registry: registry.internal.corp/argus

# Local dev — always grab the latest scanner DBs before a manual run
execution:
  pull_policy: always
```

GitHub Actions caches Docker images per-runner — `if-not-present` on an
ephemeral runner still pulls every job. To avoid that cost, pair Argus with
the `actions/cache` action keyed off `~/.docker` or use a self-hosted
runner with persistent disk.

---

## Cache mount permission issues for scanner DBs (Trivy, Grype)

**Problem.** Trivy and Grype each maintain a vulnerability database (~100MB
each) that's expensive to download every run. Argus mounts a host-side cache
into the container so the DB persists across scans — but if the host cache
directory is owned by the wrong uid or has restrictive permissions, the
scanner can't read or write it and falls back to "no DB available".

**How the cache works.** From `argus/containers.py::get_cache_mount`:

| Scanner | Container path        | Default host path                     |
| ------- | --------------------- | ------------------------------------- |
| Trivy   | `/root/.cache/trivy`  | `$TMPDIR/argus-cache/trivy`           |
| Grype   | `/root/.cache/grype`  | `$TMPDIR/argus-cache/grype`           |

The mount is added unconditionally unless you pass `--no-cache`.

**How to verify.**

```bash
argus scan --verbose 2>&1 | grep -i "DB cache mount"
ls -la "$TMPDIR/argus-cache/"
```

**Fix — wrong owner.** Wipe the cache and let Argus recreate it on next run:

```bash
rm -rf "$TMPDIR/argus-cache"
argus scan
```

**Fix — bypass cache entirely.** When the cache directory is wedged and you
just want a clean run:

```bash
argus scan --no-cache
```

`--no-cache` skips the `-v <host>:<container>` mount altogether — the scanner
downloads its DB into the ephemeral container layer and discards it on
exit. Slower per-run, but always-correct. Useful in CI where the runner is
ephemeral anyway and the cache provides no value.

---

## "All containers fail with no output produced"

**Problem.** Every scanner finishes with `produced no output files` warnings
and the dashboard shows zero findings — but you can't tell whether the code
is genuinely clean or the whole pipeline silently failed.

**How the engine handles this.** Three states, all visible in
`argus-results.json` under each scanner's `metadata`:

- `metadata['execution_failed'] = True` — the scanner couldn't run, or ran
  but produced no output. `metadata['execution_failure_reason']` carries a
  clipped stderr summary and the exit code.
- `metadata['parse_failed'] = True` — the scanner ran and wrote a file, but
  Argus couldn't parse it. See the next section.
- *Neither set* — the scanner ran clean.

The terminal reporter labels the run `Status: PASS (degraded — N did not
run, M unparsable)` whenever any result has `execution_failed` or
`parse_failed`, so the warning row above the status is consistent with the
verdict below it.

**How to verify.**

```bash
argus scan --verbose                       # full DEBUG firehose, every docker invocation logged
jq '.results[] | select(.metadata.execution_failed == true)' \
   ./argus-results/argus-results.json
```

`--verbose` is the right starting point for any "scan looks weird" report —
it logs every `docker run` command, exit code, stderr (capped at 800 bytes),
and the list of output files the scanner wrote.

**Fix — exit non-zero on scanner failures in CI.** The default exit code
reflects only severity-threshold compliance, which a zero-finding run always
satisfies. To turn execution / parse failures into a CI hard-fail, add
`--fail-on-scanner-error`:

```bash
argus scan --fail-on-scanner-error
```

Implementation: search for `fail_on_scanner_error` in
[`argus/cli.py`](../../argus/cli.py). The flag treats both `execution_failed`
and `parse_failed` as hard failures.

The `execution_failed` / `parse_failed` design is documented in
[`.ai/errors.yaml`](../../.ai/errors.yaml) under
`category: scanner-execution` (patterns "scanner produced no output|execution_failed"
and "0 findings.*known to be vulnerable|JSONDecodeError.*results.json").

---

## "Scanner produced output but parser failed"

**Problem.** A scanner exits cleanly and writes `results.json`, but Argus
warns `Scanner 'X' produced output but parse failed: ...` and the run shows
zero findings for that scanner. Most common cause: an upstream tool revved
its output schema (osv-scanner v1 → v2 is the canonical example), or the
scanner truncated output mid-write, or it interleaved text banners with
JSON.

**How the engine handles this.** PR #125 introduced a third state distinct
from "execution failed" and "ran clean":
`metadata['parse_failed'] = True` plus `metadata['parse_failure_reason']`
(the exception type and a 200-character clip of the output head). The
parser bug doesn't crash the rest of the scan — other scanners' results are
still useful — but the affected scanner is loudly surfaced.

Engine implementation: `try/except` around `scanner.parse_results` in
`_run_in_container` ([`argus/core/engine.py`](../../argus/core/engine.py)).
The same wrapping happens on the local-execution path in
`scanner_template.run_subprocess_scan`.

**How to verify.**

```bash
argus scan --verbose
jq '.results[] | select(.metadata.parse_failed == true)
                | {scanner, reason: .metadata.parse_failure_reason}' \
   ./argus-results/argus-results.json
```

Also inspect the raw scanner output that Argus preserved (assuming
`reporting.keep_raw: true`, the default):

```bash
ls ./argus-results/raw/<scanner-name>/
cat ./argus-results/raw/<scanner-name>/results.json | head -40
```

**Fix.** Most parse failures are upstream-schema drifts — either upgrade
Argus to a release that handles the new schema, or pin the scanner's tool
version via the container image (the default for `backend: auto`). If you
hit a schema you believe Argus should handle, file an issue with the raw
output snippet from the `raw/` directory.

`--fail-on-scanner-error` fires on `parse_failed` too, so a CI pipeline
that's strict about scan integrity stays strict.

---

## Windows: AppLocker / SRP blocking executables

**Problem.** On Windows, yamllint (or any pip-installed scanner script)
launches with `PermissionError: [WinError 5] Access is denied`. The same
pip install works fine on Linux/macOS.

**Root cause.** Windows AppLocker or Software Restriction Policy blocks
executable launches from user AppData paths — exactly where `pip --user`
and virtualenv install scripts. The Python interpreter itself is
whitelisted, so loading the same package via `python -m yamllint` works on
the same machine.

**How to verify.**

```cmd
where yamllint
yamllint --version
:: PermissionError: [WinError 5] Access is denied

python -m yamllint --version
:: 1.35.1   <- whitelisted via the interpreter
```

**Fix.** Already shipped — see commit `4760c1d` and
[`argus/linters/yamllint.py`](../../argus/linters/yamllint.py)
(`_run_with_windows_fallback`). On `sys.platform == 'win32'`, a
`PermissionError` / `OSError` triggers a retry with
`[sys.executable, '-m', 'yamllint'] + cmd[1:]`. `FileNotFoundError` still
propagates so "yamllint not installed" renders cleanly. Linux/macOS bypass
the fallback — there, a `PermissionError` is a real bug, not a policy case.

If you're packaging your own linter scanner and hit AppLocker, copy that
helper. The pattern is documented in
[`.ai/errors.yaml`](../../.ai/errors.yaml) under
`category: scanner-execution` / `pattern: PermissionError.*WinError 5`.

---

## Windows: UTF-8 encoding errors

**Problem.** Scans abort with `UnicodeDecodeError: 'charmap' codec can't
decode byte 0x8f` mid-run on Windows. Either the docker stdout/stderr
decode fails, or `Path.read_text()` against a scanner output file fails
when the file contains a non-ASCII byte (CVE descriptions, accented file
paths, scanner banners).

**Root cause.** Docker container output (and most CLI tool output) is
UTF-8. `subprocess.run(text=True)` and `Path.read_text()` fall back to
the platform default encoding when `encoding=` is omitted — that's
cp1252 on Windows.

**Fix.** Already shipped — see commit `4760c1d`. Every relevant call site
now passes `encoding='utf-8', errors='replace'`:

- `_run_in_container` subprocess (engine docker invocation)
- `scanner_template.run_subprocess_scan` (local execution path)
- All `argus/scanners/*.py` `parse_results` reads
- yamllint subprocess + Windows fallback

`errors='replace'` is preferred over `'strict'`: a security tool showing
`�` is better than crashing on otherwise-usable output. See
[`.ai/errors.yaml`](../../.ai/errors.yaml) under
`pattern: "UnicodeDecodeError.*charmap codec.*can't decode byte"` for the
full design rationale.

If you're upgrading from a pre-`4760c1d` release and you still see this
trace on Windows, you've found a missed call site — file an issue with
the scanner name and the line of the traceback in `argus/`.

---

## GHES with private container registry

**Problem.** Your runners can't reach `ghcr.io` / `docker.io`, so every
scan dies on `Failed to pull container image`. You have an internal mirror
registry, but Argus is pinned to upstream image references.

**Fix.** Two steps: mirror the images, then point Argus at the mirror.

**Step 1 — mirror the images.** From a machine with internet access, pull
every image Argus uses, retag, and push to your internal registry. The
canonical list is generated by `argus list --images` (or read from
[`argus/containers.py`](../../argus/containers.py)). For each image:

```bash
docker pull ghcr.io/aquasecurity/trivy:0.50.0
docker tag  ghcr.io/aquasecurity/trivy:0.50.0 \
            registry.internal.corp/argus/aquasecurity/trivy:0.50.0
docker push registry.internal.corp/argus/aquasecurity/trivy:0.50.0
```

Pin to `@sha256:...` digests for production mirrors so a re-pushed upstream
tag can't drift your scan results. Renovate / Dependabot can update digest
pins automatically.

**Step 2 — point Argus at the mirror.**

```yaml
execution:
  registry: registry.internal.corp/argus
  pull_policy: if-not-present
```

The `registry` knob is consumed by `_resolve_image` in
[`argus/core/engine.py`](../../argus/core/engine.py): Argus replaces the
upstream registry host with yours and preserves the rest of the image path
(`<repo>/<image>:<tag>`).

**Step 3 — authenticate (if the mirror is private).**

```bash
echo "$REGISTRY_TOKEN" | docker login registry.internal.corp \
  -u "$REGISTRY_USER" --password-stdin
argus scan
```

For composite actions, pass `registry_username` / `registry_password` as
inputs (see the
[Image pull failures](#image-pull-failures-registry-auth-rate-limits-air-gapped-ghes)
section above). Never put credentials in the config file —
`.ai/errors.yaml → "registry.*authentication.*failed"` covers the
secrets-handling story.

**Step 4 — pre-warm the cache on the runner (optional).** If your runners
are ephemeral and `pull_policy: if-not-present` still re-pulls per job,
either bake the images into the runner AMI / image, or pair Argus with a
caching action keyed off `~/.docker`.

---

## Quick reference

| Symptom                                         | Most likely cause                  | First command to run                              |
| ----------------------------------------------- | ---------------------------------- | ------------------------------------------------- |
| `No container runtime available`                | Docker not running / not on PATH   | `docker info`                                     |
| `Failed to pull container image`                | Auth, rate limit, or network       | `docker pull <image>`                             |
| `produced no output files (exit=N)`             | uid mismatch or scanner crash      | `argus scan --verbose`                            |
| `exit 127`                                      | Wrong entrypoint override          | `docker image inspect <image>`                    |
| `parse_failed` in metadata                      | Schema drift in scanner output     | `cat ./argus-results/raw/<scanner>/results.json`  |
| `PermissionError: [WinError 5]` (Windows)       | AppLocker on AppData binaries      | `python -m yamllint --version`                    |
| `UnicodeDecodeError: 'charmap' codec`           | cp1252 fallback on Windows         | Upgrade to a release that includes commit `4760c1d` |
| Scan looks clean but you don't trust it         | Silent execution / parse failures  | `argus scan --fail-on-scanner-error`              |

For anything not covered here, run `argus scan --verbose` and grep the log
for the scanner name. The full container-execution path lives in
[`argus/core/engine.py`](../../argus/core/engine.py) (`_run_in_container`,
`_pull_image`, `_detect_runtime`) — those three functions account for
nearly every Docker-shaped failure mode the engine knows how to produce.
