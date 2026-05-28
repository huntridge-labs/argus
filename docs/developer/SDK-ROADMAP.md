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

---

## In-flight initiatives

### MUMPS / M language SAST (`argus scan m`)

Closes the OSS gap behind mHawk (IDEA Systems, commercial, the only purpose-built MUMPS
SAST). Target audience is federal / healthcare orgs running VistA on YottaDB or GT.M whose
procurement posture rules out closed-source SAST. Multi-phase capability build, not a
follow-up.

**Vendor reality check** (`mumps.cz`, captured 2026-05-28): mHawk ships **4 taint rules
+ 32 diagnostic rules = 36 total**, in Rust, with inter-procedural taint flow, YottaDB +
GT.M + InterSystems Caché/IRIS, compiled `.o` analysis, SARIF v2.1.0, LSP, and MCP
integration. Functional parity is a 12-month target, not 18-24. Re-verify quarterly.

**Foundation:** `janus-llm/tree-sitter-mumps` (Apache-2.0, MITRE Public Release 23-4084),
vendored at pinned SHA `345f3fb2`. Known grammar gaps worked around in the rule modules:
single-letter command keywords (`R`, `K`) are sometimes elided from the `keyword` child;
OPEN parameter lists (`:(COMMAND=...)`) parse as phantom sibling commands; IF condition
bodies surface ERROR nodes; the `pattern` operator (`?`) is a TODO stub. Where structural
queries are unreliable, the rules fall back to text-anchored matching against the
command's source line.

#### Phase 1 — Core taint coverage (shipped, PR #213)

**Architecture**
- `argus/scanners/m/` sub-package: parser wrapper (`parser.py`), Rule abstract base
  (`rule.py`), shared taint collector (`taint.py`), 14 rule modules in `rules/`, and
  `scanner.py` implementing the `Scanner` protocol.
- Intra-procedural taint engine with three built-in source classes plus user-extensible
  patterns. Document-order walk over the parse tree.
- SARIF v2.1.0 emission via the existing reporter — all 14 rule IDs declared in the
  driver block.
- Two installation paths: `pip install argus-security[m]` + `scripts/build-m-grammar.sh`
  for local execution, or the `scanner-m` container image (Alpine, multi-stage, grammar
  pre-compiled at image build time, 28.6 MB compressed). Container build is validated
  end-to-end locally; image publish lands as a Phase 2 item.
- Registered in `SCANNER_REGISTRY`; category `sast`. Auto-exposed via the Argus MCP
  server (`argus_list_scanners` / `argus_scan`).

**Security rules — covers the five MUMPS code-injection sinks plus credential leak**
- **M001** XECUTE injection (CWE-95, HIGH). Tainted variable in an XECUTE argument.
- **M002** indirection injection (CWE-94, HIGH). Indirection of a non-literal expression.
- **M003** OPEN / USE device injection (CWE-78, HIGH; **CRITICAL on PIPE devices**).
  PIPE detection via `"PIPE"` device-name literal or `COMMAND=` parameter marker bumps
  severity since PIPE arguments shell-execute at runtime.
- **M004** hard-coded credentials in globals (CWE-798, CRITICAL). `SET ^G(...)="literal"`
  with credential-shaped subscript. Literal value is redacted before reaching the Finding.
- **M005** tainted dynamic dispatch (CWE-95, CRITICAL). `DO @VAR` where VAR is tainted.
- **M006** tainted argument to external `$&` call (CWE-78, HIGH). Host-side helper
  invocation (`$&system`, `$&pipe`, custom callouts) with tainted argument.

**Diagnostic rules**
- **M101** duplicate label in routine.
- **M102** unreachable code after unconditional QUIT / HALT (postconditional excluded).
- **M201** DO / GOTO to a label not declared in this file (cross-routine refs skipped
  pending Phase 2's project-wide routine index).
- **M202** first label does not match filename stem (GT.M / YottaDB / Caché convention).
- **M203** local variable read before it was defined (typo on the definition site).
- **M204** local variable set but never read (def-use analysis with comment-stripped
  source-text fallback for XECUTE-consumed names).
- **M205** label body falls through into the following label without an unconditional
  `Q` / `H` / `G`.
- **M206** KILL of an entire global tree (`K ^G` with no subscript) — high real-world
  impact; production VistA outages have been traced to exactly this construct.

**Taint sources (built-in)**
- `READ` / `R` command arguments
- `$ZARGV` (YottaDB / GT.M process arguments)
- HTTP context globals `^%CGI`, `^%REQUEST`, `^%session`

**Config-driven taint extension**
- `scanners.m.taint_sources.patterns` in `argus.yml` accepts arbitrary regex strings
  that join the source set seen by every taint-aware rule. Lets users add site-specific
  intrinsics (`$ZIO`, custom HTTP globals, vendor input routines) without forking the
  scanner. Differentiator vs. mHawk's closed rule engine.

**Test coverage**
- 25 unit tests (`argus/tests/scanners/test_m_scanner.py`) cover the scanner protocol
  and rule registry without needing a compiled grammar.
- 31 integration tests (`argus/tests/scanners/test_m_rules.py`) parse real `.m`
  fixtures and assert per-rule behaviour. CI compiles `mumps.so` in the test-unit
  workflow's setup step so these run on every PR.
- Per-rule line coverage: 88-100%.

#### Phase 2 — Deepening (six-month horizon)

The single largest remaining gap is inter-procedural detection. Everything else is
incremental progress against mHawk's diagnostic surface or operational maturity.

- **Inter-procedural taint engine.** Largest technical lift in this whole roadmap.
  Pre-pass that loads every routine in the scan path; call-graph builder across `DO` /
  `GOTO` / `routine_call` / `^ROUTINE` references; per-routine taint summaries
  (`call ENTRY^X with argN tainted → state in X`); recursion / mutual-recursion handling
  via worklist iteration to fixpoint. Most real-world MUMPS injection bugs cross at
  least one routine boundary; closing this is the single biggest perception-of-parity
  win against mHawk.
- **Formal-argument scope tracking.** Entry-label parameter lists (`LABEL(ARG1,ARG2)`)
  become scope-aware definitions for M203 / M204 instead of the conservative
  "any-formal-anywhere-is-defined" heuristic Phase 1 ships. Unlocks precise def-use
  diagnostics inside routines that take parameters.
- **Container image publish + workflow wiring.** Image lands at
  `ghcr.io/huntridge-labs/argus/scanner-m:VERSION@sha256:...`; `CUSTOM_IMAGES` in
  `argus/containers.py` picks up the SHA-pinned tag; `argus.yml` `containers.images`
  adds the build entry so the build-containers workflow exercises it on every PR.
  Auto-covered by `container-smoke` once the image is published.
- **Diagnostic rule expansion** to roughly 20 (from 8 today, targeting the cheapest /
  highest-signal half of mHawk's claimed 32). Candidates: undeclared global reference,
  empty IF / ELSE body, bare KILL of all locals, NEW without later KILL pairing,
  JOB without ID capture, deprecated intrinsics, label-name collision with reserved
  word. Each is a 1-2 hour rule + fixture + test cycle.
- **Per-rule severity overrides via argus.yml.** `scanners.m.rules.M203.severity: low`
  lets operators tune the noise floor of the diagnostic surface against their codebase
  without disabling rules outright.
- **First false-positive triage pass.** Run against WorldVistA / RPMS / MailMan
  forks, capture FP patterns by rule, refine. mHawk's actual moat is years of this
  cycle — we have to start it.
- **Configurable per-rule sanitizers.** `scanners.m.sanitizers` accepts function /
  intrinsic names that remove taint when applied (`$$VALIDATE^LIBRARY`, etc.). Pairs
  with the existing config-driven taint sources to make the whole flow tunable.

#### Phase 3 — Full parity stretch (twelve-month horizon, MUMPS subject-matter expert engaged)

- **ObjectScript / Caché / IRIS dialect support.** Grammar fork or upstream contribution
  to MITRE for `Class Foo Extends Bar { Method ... }`, `..method()` dot-notation,
  `$ZF` / `$ZOBJ*` intrinsics, and the `.mac` / `.int` / `.cls` file extensions.
  Every Phase 1 rule re-validated against the new node types. Unlocks the InterSystems
  shops mHawk currently owns alone.
- **Compiled `.o` file analysis** for YottaDB object files. Useful for audit scenarios
  where source isn't available; format is sparsely documented so the analyzer is
  expected to be partial.
- **LSP server** for VS Code + NeoVim — Go to Definition (cross-routine, using the
  Phase 2 call graph), Find References, Completion, on-save diagnostics. Reuses the
  parser and rule infrastructure; pygls makes the server itself thin.
- **Diagnostic rule expansion** to 30+ (closing the rest of mHawk's claimed 32). The
  long tail is style / convention rules that need real-corpus calibration to ship
  without overwhelming users.
- **Sustained false-positive triage cycle** against WorldVistA / RPMS / MailMan / OSEHRA
  forks. Per-quarter pass: capture FP patterns, refine rules, document accepted-FP
  baselines. This is mHawk's actual moat (years of customer-base tuning); we close it
  by operating publicly with auditable rules and a tight feedback loop.
- **Performance hardening.** Profile against routine corpora measured in thousands of
  files; identify hot paths in the AST walks; selectively Cython-compile the taint
  collector and rule iteration if a measurable difference exists. Rust port is not
  on the table — interop cost outweighs the speed gain at this scale.
- **MCP-driven triage tools.** `argus_explain_finding` extended for MUMPS-specific
  context (cite the relevant Caché / GT.M / YottaDB documentation page); a dedicated
  `argus_m_routine_callgraph` MCP tool that surfaces the Phase 2 call graph for
  AI-assisted code review.

#### Known persistent gaps

- **VA-specific FileMan / HL7 / FHIR adapter patterns.** mHawk has years of customer-base
  tuning here. Closing this without sustained subject-matter expertise on the team is unrealistic.
- **Pattern operator (`?`) support** depends on upstreaming a grammar fix to MITRE.
  Sanitizer auto-inference remains config-driven until then.

#### Differentiators (not parity targets — durable axes where Argus wins)

- **OSS / Apache-2.0 license** with no procurement barrier for federal / healthcare orgs.
- **Native SARIF v2.1.0 with full Argus suite integration** — unified scanner output;
  shared `argus view` triage; shared MCP server at the suite level; aggregated
  security-summary across every scanner; no parallel toolchain for MUMPS vs every other
  language in the codebase.
- **Air-gappable container distribution** matching the rest of Argus's posture — the
  `scanner-m` image is self-contained (grammar pre-compiled at image build time, no
  network access required at scan time).
- **Auditable, YAML-configurable rules** — taint sources (shipped in Phase 1 via
  `scanners.m.taint_sources.patterns`), sanitizers (Phase 2), and per-rule severity
  (Phase 2) declared in `argus.yml`. No closed-source rule engine. Operators can tune
  the scanner against their codebase without forking or vendor escalation.
- **MCP integration baked into the suite, not bolted on.** Argus's MCP server auto-
  exposes every scanner including `m`; the AI assistant can drive scans, list rules,
  and (Phase 3) walk the call graph through the same protocol surface mHawk reserves
  for its dedicated MCP product.

---

### 0.6.x parity (deferred)

- **Web-app authentication V2 — argus-native form block.** A `scanners.zap.auth.form` block
  we'd translate into a ZAP context. Deferred until we have real consumer apps to validate
  against — abstracting the DOM is inherently leaky and we don't have signal yet that the
  context-file path (V1, shipped) is insufficient.
