# Argus SDK Roadmap

The SDK migration is shipped. This page summarises what landed and tracks
the small set of follow-ups that survived the migration. Full design
rationale lives in [`docs/developer/portability-research.md`](portability-research.md)
and the ADR ledger at [`.ai/decisions.yaml`](../../.ai/decisions.yaml).

For a granular history of every PR / commit, use `git log` — the
in-roadmap progress log that lived here through migration was retired
once the work landed.

---

## Shipped

### Core SDK + CLI
- `argus/core/` — models, scanner protocol, config loader, engine (local + Docker dispatch).
- `argus/cli.py` — `argus scan / report / validate / init / list / mcp / cache / view / classify`.
- 200+ unit tests, 83 % SDK coverage; `pyyaml` is the only runtime dep for the bare install.

### Scanner & linter modules
- 11 scanners (`bandit`, `clamav`, `trivy_iac`, `gitleaks`, `osv`, `checkov`, `opengrep`,
  `supply_chain`, `zap`, `container`, `scn-detector`) and 6 linters all implementing the same
  `Scanner` protocol. Each has fixture-backed parser tests; container backends fall back to
  Docker automatically when the binary is missing.
- 4 built-in reporters (`terminal`, `markdown`, `sarif`, `json_report`); 3 added later
  (`github`, `gitlab`, `junit`); reporter plug-ins load via the
  `argus.reporters` entry-point group (ADR-023).
- `FileDiscoveryScanner` template for linters that need workspace-walk + per-file invocation
  (ADR-020); hadolint / eslint / terraform migrated.

### Docker execution backend
- Central image manifest (`argus/containers.py`), ARM64 fallback via `--platform linux/amd64`,
  pull-policy knob (`always | if-not-present | never`), registry override for air-gapped
  hosts, scanner DB cache mounts under `$TMPDIR/argus-cache` with `argus cache info|clean`,
  best-effort background image pre-warm (`argus/core/prewarm.py`).
- Cosign keyless-verify of Argus-owned images on pull; `@sha256:` digest pinning for every
  third-party image in the manifest; opt-out via `execution.verify_image_signatures: false`
  for air-gapped environments (ADR — see `docs/security.md` → *Container image provenance*).

### Composite-action thin wrappers
- 16 wrappers (10 scanners + 6 linters) refactored to call `argus scan` under the hood —
  ~300 lines → ~170 lines each, identical inputs/outputs/artifacts. Install pattern is
  `pip install "${{ github.action_path }}/../../.."` so the SDK version is pinned to the
  composite ref (no PyPI-release lag).
- 22 reusable workflows restored with identical input interfaces; 12 migrated internally to
  the SDK, 3 left as composite-action passthroughs (`scanner-codeql`, `scanner-dependency-review`,
  `scanner-syft`).
- Silent-failure gating shipped in PR #91 (ADR-016): `security-summary` / `linting-summary`
  composites render a per-scanner status table from a new `scan_statuses` JSON input, exit
  non-zero on any scanner failure by default, and unwrap the legacy `<details>` for one-click
  collapse.

### Distribution & multi-platform
- PyPI publishing via `release.yml` with trusted publishing (OIDC),
  TestPyPI dev versions on PRs (`publish-pypi.yml`), dynamic versioning, tool-version enforcement.
- GHCR container image publishing on release, cosign-signed by digest, multi-arch (amd64 + arm64),
  build-once-promote-everywhere pipeline so images and the wheel ship from the same commit.
- `argus init` with language / framework / linter detection; `--exclude` + parallel detection.
- CI preflight: `argus validate --strict --check-tools --report-issue`, living issue on
  GitHub/GitLab that auto-detects provider and auto-closes when healthy.
- CI examples for GitHub Actions, GitLab CI, Jenkins, Azure DevOps.

### Local viewing surfaces
- **`argus view terminal`** — Textual TUI for post-scan triage. Severity filters, free-text
  search, sort, export (CSV / JSON / Markdown / SARIF), executive dashboard, scan-over-scan
  diff, source-context preview, mouse-driven URL / editor / registry navigation. SVG
  screenshot pipeline regenerates docs in lockstep with the code.
- **`argus view browser`** — FastAPI + Jinja2 read-only web UI (Phases SA–SY). Executive
  dashboard, filterable findings table, picker, exports, scan diff, recent-runs dropdown,
  scan metadata panel, light/dark theme toggle, `/log` route with the run's `argus.log`.
- Shared per-finding renderer in `argus.core.findings_view` so the two viewers can't drift.

### Interactive architecture map (ADR-026)
- `.ai/architecture.yaml` is canonical; the JSON the docsite renders and the JSON
  `argus://architecture` returns are pure-function derivations from it plus runtime SDK
  introspection. Transformer is `scripts/docsite/architecture.py`; CI gate
  (`scripts/ci/check_architecture_sync.py`) blocks drift.
- Page lives inside the docs site at `/argus/architecture/` with Argus dark theme applied
  site-wide; Configure-mode multi-selects scanners and generates `argus.yml`, CLI, GitHub
  Actions, or MCP-client config from the selection.

### Agentic substrate
- MCP server (`argus/mcp.py`) with 8 tools, 3 resources, 3 prompts, stdio transport, 69 tests.
- Skill slimmed to a 66-line routing/strategy layer (MCP-first; falls back to CLI).

### Security hardening (post-1.0)
- DAST + container parity tracked under ADR-024 (ZAP config passthrough) and ADR-025 (OS-image
  scope split: services sub-scanner in, offline VM-image scanning out).
- Secret redaction at the parser plus a defence-in-depth second pass for vendor-prefix tokens
  in `Finding.__post_init__` (ADR-022); audit-trail walker masks secrets at write time before
  `argus.log` / `argus-audit.json` flush (`argus/audit/secrets.py`).
- `-e NAME` (name-only) docker env passthrough so credentials never appear on the docker
  command line / `docker inspect` / daemon audit log; `--registry-password-stdin` and
  `--zap-auth-password-stdin` CLI flags for ad-hoc local runs.
- Attack-surface visibility: `exposure` sub-scanner emits a `Finding` per declared `EXPOSE`
  port; `services` sub-scanner enumerates systemd/SysV unit files in the image filesystem.
  Both classify against a built-in `RISKY_PORTS` / `RISKY_SERVICES` watchlist with config
  overrides.

### Documentation & tooling
- `README.md` / `QUICK-START.md` / `AGENTS.md` / `CLAUDE.md` / `CONTRIBUTING.md` rewritten
  for the SDK-first reality; `docs/scanners.md`, `docs/failure-control.md`,
  `docs/config-reference.md`, `docs/migration/0.6.x-to-1.x.md`, `docs/security.md`,
  `docs/view-terminal.md`, `docs/view-browser.md`, `docs/container-scanning.md` all carry
  worked examples.
- `scripts/ci/check_version_refs.py` + `scripts/ci/check_cli_docs.py` +
  `scripts/ci/check_architecture_sync.py` enforce doc / version / registry / argparse
  freshness on every PR.
- Version-aware `GITHUB_BLOB` rewrite (`scripts/docsite/config.py` + `--ref` flag) so
  versioned doc URLs at `/argus/vX.Y.Z/` link to matching `/blob/vX.Y.Z/` blob URLs and
  PR-preview builds link to the PR's own SHA.
- Dependency maintenance: Dependabot for GitHub Actions / npm / pip / Docker; Renovate for
  Python `containers.py` image tags and Dockerfile / action.yml tool-version refs;
  `check_version_refs.py` as the cross-file consistency gate.

---

## Open follow-ups

These survived the migration. Some are small wiring tasks, others are deliberate deferrals
captured here so they don't get re-discovered as forgotten work.

### Real bugs / wiring

- **`argus scan container` ignores `--no-timestamp`.** Source scans honor it (`engine.py`);
  the container lifecycle path (`argus/container/engine.py`) writes into a timestamped subdir
  + `latest` symlink regardless. CLI help claims the flag works ("Write output directly to
  --output-dir without a timestamped subdirectory") so this is a doc-vs-behaviour mismatch.
  Fix: thread the flag through `ContainerEngine` so it skips the timestamp dir + symlink.
- **ZAP `healthcheck_url` not yet consumed.** Schema-allowlisted in `argus/core/schema.py`
  per ADR-024 but `argus/scanners/zap.py` doesn't poll the URL before scan. Engine should
  poll for a 2xx response (configurable timeout, default 60 s) and fail fast with a clear
  error if the SUT never becomes ready.

### TUI polish (deferred)

- **Column-resize / row-count improvements.** Textual's `DataTable` doesn't expose a
  column-resize hook in 8.x; needs a custom Splitter-style widget or an upstream feature
  request before this lands.
- **Shift+click row-range select, Cmd/Ctrl+click toggle.** Textual's `DataTable RowSelected`
  event surface in 8.x doesn't expose modifier state in the documented API; would need a
  spike against newer Textual or a custom `on_mouse_down` handler that also tracks the
  cursor row. Keyboard `space` / `a` / `A` still cover the multi-select workflow.
- **Inline ignore / suppression comment workflow.** Add a "Suppress finding" context-menu
  action that maps scanner → pragma syntax (`# nosec: B101` for bandit,
  `# nosemgrep: <rule>` for opengrep/semgrep, `# gitleaks:allow` for gitleaks,
  `// eslint-disable-next-line <rule>` for eslint, `# checkov:skip=CKV_X:<reason>` for
  checkov, etc.), prompts for an optional justification, inserts the pragma above the
  flagged line, refuses to write when the working tree shows the file as modified. Deferred
  because it touches user code and needs careful per-scanner handling.

### Verification

- **Composite-action backward-compatibility.** Verify identical outputs, artifacts, and
  SARIF across the SDK-migrated wrappers and the previous shape. Audited per-wrapper during
  the refactor; a full matrix re-run against a representative consumer repo is the only
  remaining step.
- **medsecops-golden-path silent-failure regression.** Verify the demo pipeline no longer
  reproduces the silent-failure scenarios that motivated PR #91 once the SDK lands on `main`.

### Build & dependency hygiene

Today the published wheel uses `>=` floor pins with CVE-conscious bottoms — the right
choice for a library, since `==` pins force resolver conflicts on consumers and offer
little protection that Dependabot's 7-day cooldown doesn't already give us. These two
items would add a *separate* deterministic build/test baseline for our own CI without
changing what end users see.

- **`requirements-frozen.txt` for CI.** Generate from a known-good install
  (`pip-compile` or `pip freeze --exclude-editable`), commit alongside the loose
  `requirements.txt`, use only in CI's lint / test jobs. Gives us a reproducible test
  matrix so a transitive dep silently breaking on a fresh `pip install` is caught here
  rather than by a user. Doesn't ship to PyPI; doesn't constrain consumers.
- **Adopt `uv` + `uv.lock` for the dev/CI workflow.** Hash-verified, deterministic dev
  environments with sub-second resolves. The published wheel still uses `>=` floors;
  `uv.lock` is internal-only, like a `Cargo.lock` for a library crate. Replaces the
  manual `requirements-frozen.txt` above with a more capable tool. Closes the
  "compromised fresh release slips into our build" attack class for our own CI by
  pinning hashes of every transitive dep. Out-of-scope until post-1.0.

### External distribution

- **Publish skill to [skills.sh](https://skills.sh/)** for discovery; the
  `.agents/skills/argus-scanner-selection/` file in the repo remains the canonical source.
- **MCP registry submissions.** Each is independent; ship as bandwidth allows. Submission
  process for each is documented in [`docs/mcp.md`](../mcp.md#discovery-and-registry-listings).
    - [`modelcontextprotocol/servers`](https://github.com/modelcontextprotocol/servers) —
      PR adding Argus to the **Community Servers** section.
    - [`punkpeye/awesome-mcp-servers`](https://github.com/punkpeye/awesome-mcp-servers) —
      PR adding Argus to the **Security** section.
    - [mcp.so](https://mcp.so/) — submit at https://mcp.so/submit.
    - [Smithery](https://smithery.ai/) — manual submission for PyPI-distributed servers.
    - [Glama](https://glama.ai/mcp/servers) — auto-discovers from public repos with the
      `mcp-server` GitHub topic; ensure the topic is set on `huntridge-labs/argus`.

### Portal integration product calls

The `argus-portal` web app is an adjacent surface for the same data. These are product
calls that need to land before the integration touches argus's surfaces.

- **Does the portal consume `argus-results.json` natively?** If yes, the TUI / browser
  viewer roles stay as "local-dev triage before pushing to portal." If no, we'd want a
  shared schema/loader library to avoid format drift.
- **"Send to portal" keybinding.** `P` from the TUI uploads the current results (or
  currently filtered subset) to a configured portal instance. Needs portal API (or upload
  endpoint) defined first.
- **"Open in portal" deep-links.** `argus-portal://scan/<id>` or HTTP URL. Works if scans
  have portal-assigned IDs.

### 0.6.x parity (deferred)

- **Web-app authentication V2 — argus-native form block.** A `scanners.zap.auth.form` block
  we'd translate into a ZAP context. Deferred until we have real consumer apps to validate
  against — abstracting the DOM is inherently leaky and we don't have signal yet that the
  context-file path (V1, shipped) is insufficient.
