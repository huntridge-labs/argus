# Argus Console Roadmap

The terminal viewer has outgrown its name. With a runs explorer and an
in-app scan runner already shipped (and a vulnerability-mitigation layer
designed), `argus view terminal` is becoming a place you *operate* Argus
from, not just read results in. This roadmap tracks the multi-phase build
that turns it into the **Argus Console** — a terminal-native control
centre for the whole scan → triage → fix → configure loop — and the
decision to make it what bare `argus` launches.

This is an epic, not a follow-up. Each phase ships as its own PR with its
own tests and docs; the phases are independently useful so the program can
pause between any two without leaving a half-built surface. Companion
material: the SDK roadmap at [`SDK-ROADMAP.md`](SDK-ROADMAP.md), the
configuration reference at [`../config-reference.md`](../config-reference.md),
the terminal-viewer guide at [`../view-terminal.md`](../view-terminal.md),
and the ADR ledger at [`../../.ai/decisions.yaml`](../../.ai/decisions.yaml).

---

## North star

`argus` (run interactively, no subcommand) opens a unified TUI: an ASCII
splash, then a home screen that launches Scan, Findings, Config, Init, and
focused Docs — each a screen in one app. A user can land in an empty repo,
detect + write a config, run a scan, triage findings, and apply fixes
without leaving the terminal or memorising a single flag. `argus view`
deep-links straight to the Findings screen for backward compatibility, and
every existing subcommand (`argus scan`, `argus init`, …) keeps working
exactly as today.

The model to beat is lazygit / k9s: *the tool, but a TUI* — feature-rich,
keyboard-first, mouse-friendly, and beautiful, without becoming a second
codebase or a maintenance sink.

## Architecture principles

- **One app, many screens.** A single Textual `App` (the Console) hosts
  Home, Scan, Findings, Config, Init, and Docs screens, each its own module
  under `argus/viewers/terminal/`. `argus view` mounts the Findings screen
  directly. No forked code paths to the same data.
- **Screens are thin frontends over the UI-free core.** All logic stays in
  `argus/core/` (`config`, `engine`, `findings_view`, `run_discovery`,
  the planned `remediation`) and the SDK. The Console never owns business
  logic, so the CLI, MCP server, and CI keep working headless and the test
  surface stays mostly pure-Python.
- **Reuse, don't reinvent.** The AI provider abstraction already exists
  (`argus/scn/ai.py`: `AnthropicProvider` / `OpenAIProvider`, env-var keys,
  SDK-or-HTTP, OpenAI-compatible base URL for local models) and is exposed
  via `argus classify --enable-ai` behind the `[ai]` extra. Mitigation's AI
  tier rides the same abstraction and opt-in pattern.
- **Mutations stay in the trusted shell.** Scan execution, config writes,
  and fixes run from the TUI (equivalent to the user typing the command).
  The browser viewer's read-only / 127.0.0.1 / no-auth boundary is *not*
  crossed by this epic — any browser-side execution is a separate,
  security-reviewed effort.

## Backward-compatibility contract (the load-bearing guardrail)

The bare-`argus` change is additive *only* if it never touches
non-interactive use:

- Bare `argus` launches the Console **only when `sys.stdout.isatty()`**.
  Piped / CI / non-interactive invocation keeps today's behaviour:
  `parser.print_help()` (`argus/cli.py`, the `args.command is None` branch).
  The codebase already gates interactivity this way (`_should_open_browser`,
  the `sys.stdin.isatty()` checks).
- Every subcommand is unchanged. `argus scan`, `argus init`, `argus view`,
  `argus mcp`, … behave identically; the Console is purely the new
  no-subcommand-in-a-TTY entry point.
- The default-behaviour change to bare `argus` warrants an **ADR** and a
  release-note callout, since a small number of users may rely on bare
  `argus` printing help.

---

## Phase 0 — Explorer & scan-runner foundations (shipped, PR #261)

The first bricks. Establishes the patterns the rest of the Console builds on.

**Shipped**
- Runs sidebar (`b`) + run switching, driven by the new UI-free
  `argus/core/run_discovery.py` (shared with the browser picker / recent-runs
  dropdown so the two viewers can't disagree on what a run is).
- In-app scan runner (`R`): prompt → stream `argus scan` in an overlay →
  reload the new run. Argv built by `argus/viewers/terminal/scan_runner.py`;
  re-invokes `sys.executable -m argus` so a venv'd viewer scans with that
  venv's tools.
- Cursor-anchored context menus (`mouse_actions.clamp_menu_offset`).
- Screenshot pipeline extended (`scripts/docsite/capture_view_terminal.py`)
  so the new states regenerate in lockstep with the code.

**Pattern established:** pure logic in textual-free modules (unit-tested in
CI without the `[terminal]` extra), Textual screens exercised via the
stubbed-textual loader, overlays that are diff-/review-first.

## Phase 1 — Vulnerability mitigation ("Fix") (Tier-1 dependency bumps shipped)

Let users resolve findings, not just read them.

**Shipped (PR 1 — deterministic dependency bumps, no AI)**
- UI-free `argus/core/remediation.py`: `Remediation` dataclass +
  `propose(finding, *, repo_root)` / `apply(...)` / `is_fixable(...)`.
  Computed on the fly from existing finding data — no `Finding` schema /
  `argus-results.json` / redaction change.
- Tier-1 **dependency bumps** for pip (`requirements*.txt`) and npm
  (`package.json`): locate the package, produce a unified diff bumping it to
  `metadata.fixed_version`, preserving the existing spec style (`==` stays
  pinned, `>=` keeps its operator, bare name → `>=`). PEP 503 name
  normalization for pip; caret/tilde preserved for npm. Falls back to the
  ecosystem upgrade *command* (shown, never auto-run) when no manifest line
  matches.
- **TUI:** `F` → Fix overlay (`FixScreen`) — diff-first preview, Apply
  (`a`/Enter) / Cancel; batch over the multi-select set; an `⚒ Apply fix`
  context-menu item on fixable rows. Apply writes the edit; the user re-runs
  the scan (`R`) to confirm.

**Remaining (later PRs)**
- More Tier-1 sources: **GitHub Actions SHA-pinning** (`scanner-supply-chain`
  findings → tag→SHA rewrite) and **opengrep rule autofix** (`fix:` keys).
- Surface **major-version bumps** as a distinct higher-risk class (currently
  the bump preserves the operator but doesn't flag a major jump).
- **Tier 2 — AI-assisted, opt-in (`[ai]` + `--enable-ai`):** SAST logic
  rewrites via the `scn/ai.py` providers (or a local model through the
  OpenAI-compatible base URL). Output is a unified diff, always reviewed,
  never auto-applied, always gated by the test pipeline.
- A persistent `⚒` table-column marker (today fixable rows are flagged in the
  context menu; a column needs the sort-indicator offsets reworked).

**Why this first:** Tier 1 is fully OSS and slots straight into the
"trust → green tests → auto-merge" end-state — a deterministic fix that
produces a passing run *is* the auto-merge story. It complements the
already-foundational Dependabot/Renovate flow as its interactive sibling.

## Phase 2 — Config editor screen (shipped, into PR #261)

Edit `argus.yml` by form, not by hand.

**Shipped**
- **Config screen** (`ConfigScreen` in `argus/viewers/terminal/console.py`)
  reachable from the home menu's *Configure* entry. Lists the editable
  settings as an `OptionList`; `enter` cycles a value, `s` validates + writes,
  `esc` discards. Opens the form when an `argus.yml` exists; with none, it
  nudges toward Initialize and falls back to `$EDITOR`/`$VISUAL` so a file can
  still be created by hand.
- **UI-free edit core** (`argus/viewers/terminal/config_editor.py`,
  textual-free → CI-covered): `editable_rows` parses the file into
  toggle/enum rows (scanner `enabled` flags + bounded section scalars —
  `severity_threshold`, `backend`, `pull_policy`, `cve_source`,
  `open_location`); `apply_row` cycles a row's value; `validate` re-parses and
  runs `argus/core/schema.py::validate_config`, blocking save on any
  `error`-level issue.
- **Surfaced focused docs:** each row carries a one-line `doc` string
  (`_DOCS`) rendered beside it, so "what does this do?" is on screen.
- **Safe write-back — decision resolved.** Rather than re-serialising the
  whole file (which clobbers comments/ordering), edits are *comment-preserving
  targeted line rewrites*: `set_value` walks the file indentation-aware to the
  exact `key: value` line and rewrites only its value, keeping key,
  indentation, and any trailing inline comment. The editable set is
  deliberately bounded to plain scalars so every edit is a single,
  unambiguous line — sidestepping the `ruamel.yaml` round-trip dependency
  entirely. Free-text fields (e.g. `output_dir`) stay editable via `$EDITOR`.

**Deferred to a follow-up**
- Free-text `Input` fields (paths, URLs, custom args) and scanner *addition*
  (the form edits settings that already exist in the file; adding a brand-new
  scanner block still goes through Init or `$EDITOR`). The docsite Configure
  logic (`scripts/docsite/architecture.py`) is the source of truth to reuse
  when that lands.

## Phase 3 — Init wizard screen (shipped, into PR #261)

Guided first-run, all in-app — the `argus init` subprocess hand-off is gone.

**Shipped**
- **`InitScreen`** (`argus/viewers/terminal/console.py`), reached from the
  home menu's *Initialize* entry: detect → show what was found + a
  tool-readiness line → list the proposed scanners as toggles → write
  `argus.yml`. `w` writes; `r` writes **and** hands off to the Phase-0 scan
  runner for the first scan; `esc` cancels. An existing `argus.yml` requires
  a confirming second keypress before it's overwritten (mirrors
  `argus init`'s `--force` guard) — never a silent clobber.
- **UI-free core** (`argus/viewers/terminal/init_wizard.py`, textual-free →
  CI-covered): `build_plan(root)` calls the *pure* `argus.init` functions
  (`detect_project`, `generate_config`, `_extract_enabled_scanners`,
  `_check_local_readiness`) and returns an `InitPlan` (detected categories,
  proposed scanners, the generated YAML, readiness). `write_config` enforces
  the overwrite guard. **No detection logic is reimplemented** — the wizard
  is strictly a frontend over `argus init`. The signal→label map was
  promoted to `argus.init.SIGNAL_LABELS` so the CLI summary and the wizard
  render identical names.
- Scanner toggles reuse the Phase-2 `config_editor` over the generated YAML,
  so toggling and the comment-preserving write share one implementation.

## Phase 4 — Console home, settings, and bare-`argus` entry (shipped: shell)

The launcher + customization centerpiece. The home, settings, theming, and
the bare-`argus` entry shipped here; the remaining item is folding the
findings viewer in as a true in-app screen (it's a hand-off today).

**Shipped**
- **Home screen** (`argus/viewers/terminal/console.py`, model in
  `console_model.py`): ASCII wordmark + tagline, a status line (config
  presence + latest run label / count / worst severity via
  `run_discovery`), and the launcher menu (Scan / View findings /
  Configure / Init / Settings / Docs / Quit). Banner fade honours the
  motion settings + `ARGUS_NO_ANIMATION`.
- **Settings** (full `Screen`, herdr-style): theme, accent colour,
  animations, reduced-motion, notifications — theme/accent preview live,
  persisted to `~/.config/argus/console.yml` (`console_config.py`, UI-free).
  A bespoke `argus-dark` theme is registered alongside the built-in Textual
  themes. (Full `Screen`, not `ModalScreen`: live re-theming while a modal
  is mounted hits a Textual 8.x NoneType-visual render bug.)
- **Bare-`argus` entry** (`cli._run_bare_argus`): opens the Console only
  when stdout *and* stdin are a TTY; piped / CI / no-`[terminal]` falls
  back to `--help` (the backward-compat contract). `argus view` still
  deep-links to findings.
- **Configure / Init** are both in-app screens now: Configure opens the
  Phase-2 form editor (falling back to `$EDITOR`/`$VISUAL` via `App.suspend`
  when no `argus.yml` exists yet), Init opens the Phase-3 wizard. The
  `argus init` subprocess hand-off has been removed.

**Remaining**
- Findings is still a hand-off (the console exits with a sentinel; the
  viewer runs, then the console reopens). The seamless single-app version
  folds the findings viewer in as a `FindingsScreen` mounted by both the
  Console and `argus view` — the "Console module layout" decision below.
  (Configure and Init are now in-app screens; only findings remains.)
- Deeper terminal-compat / accessibility (`NO_COLOR`, low-color, SSH/tmux
  fallbacks, screen-reader plain mode) beyond reduced-motion + the
  animation kill-switch.

---

# Part II — Modernization program (Phases 5–12)

Phases 0–4 made the Console *exist*. Part II makes it the best TUI in
security tooling — most security scanners are non-interactive (`trivy` has a
thin client/server mode; `grype` / `semgrep` / `snyk` / `osv-scanner` /
`gitleaks` print SARIF/JSON and exit), so "feature-rich interactive triage"
is itself the differentiator. Each phase is an independent PR, merged into
the integration branch as it goes green, exactly like Part I.

The guiding split is unchanged: **logic in UI-free `argus/core/` modules
(unit-tested in CI without the `[terminal]` extra), screens stay thin.**
Every network / AI feature is **opt-in and offline-degrading** so the
default `argus` experience needs no key, no daemon, and no egress.

## Phase 5 — Modern navigation essentials (table stakes)

The patterns every modern TUI (k9s, lazygit, atuin, yazi) has and the
Console doesn't yet. Small, cohesive, high polish-per-line.

**Build**
- **Command palette** — Textual's built-in `App.COMMANDS` + a custom
  `Provider`. Fuzzy "jump to any finding / scanner / action / screen" on
  `Ctrl+P`. Commands are generated from the registries we already have
  (scanners, reporters, menu items), so it's a thin projection.
- **Fuzzy filter everywhere** — a UI-free `argus/core/fuzzy.py` (subsequence
  match + score, no dependency) backing incremental filter inputs in the
  findings list, pickers, and the palette.
- **OSC 8 hyperlinks** — CVE/GHSA IDs and `file:line` locations render as
  real terminal hyperlinks (Rich supports them). UI-free helper builds the
  advisory URL (honours the existing `view.cve_source` setting) and the
  editor/remote URL (reuses `open_location`). Degrades to plain text.
- **OSC 52 clipboard** — yank the focused finding id / remediation command /
  SARIF snippet to the system clipboard, even over SSH. UI-free escape-seq
  encoder; one keybind.

**Effort/Risk** — low. No new runtime deps. The palette + links are the
visible wins; fuzzy + clipboard are quiet quality.

## Phase 6 — Live vulnerability intelligence (the headline)

Turn a finding from "a CVE id + severity" into "*should I care, right
now?*" — the single biggest differentiator, and free data no OSS scanner
TUI surfaces.

**Build**
- **`argus/core/enrichment.py`** (UI-free): given a CVE/GHSA id, fetch and
  merge:
  - **EPSS** — exploit-probability percentile (FIRST.org,
    `api.first.org/data/v1/epss`, no auth).
  - **CISA KEV** — known-exploited-in-the-wild flag (the published
    `known_exploited_vulnerabilities.json`, no auth).
  - **Advisory text / fixed versions** — OSV (`api.osv.dev/v1/query`, no
    auth) and optionally the GitHub Advisory GraphQL (token-gated).
- **On-disk cache** with TTL under `$XDG_CACHE_HOME/argus/` (KEV catalog
  daily; per-CVE EPSS/advisory for hours). Fully offline-degrading — no
  network ⇒ findings render exactly as today, just without the badges.
- **Risk re-ranking** — a pure scoring function combining
  `severity × EPSS × KEV (× reachability once Phase 12 lands)`. New
  "sort by risk" + a KEV 🔥 / EPSS% badge column in the findings viewer.
- **Privacy posture (ADR-worthy):** queries send only public CVE ids /
  package coords, never source or secrets; opt-in via config
  (`enrichment.enabled`) and a one-time first-run consent prompt; no
  telemetry. Honour `NO_NETWORK` / offline.

**Deps** — prefer stdlib `urllib`; add `httpx` only if we want async/timeout
ergonomics (pinned, in a `[enrich]` extra). **Effort/Risk** — moderate;
HTTP + cache are testable with mocked transports.

## Phase 7 — Triage at scale (bulk suppression + VEX)

lazygit's staged-action model applied to findings — the workflow security
teams do by hand in spreadsheets today.

**Build**
- Multi-select (already present) → bulk **suppress-with-reason** /
  **accept-risk** / **mark false-positive**, accumulating into a reviewable
  changeset before write (lazygit-style staging).
- **`argus/core/suppressions.py`** (UI-free): write back to the right
  artifact — `.trivyignore` / `.gitleaksignore` / inline comment
  suppressions — and emit/merge an **OpenVEX** document (the project already
  signs OpenVEX attestations — reuse that path) with status + justification
  + timestamp + author = an audit trail.
- A "suppressed" filter view so hidden findings remain reviewable, never
  silently dropped (honours the silent-failure rule).

**Effort/Risk** — moderate; the writeback formats are well-specified and the
VEX emitter is unit-testable.

## Phase 8 — Visual analytics (charts in the terminal)

**Build** — `textual-plotext` (pinned, `[terminal]` extra) on the dashboard:
a **severity-trend sparkline** over the last N runs ("are we getting more or
less secure?"), a **findings-by-scanner** bar, a **severity donut**. The
series math is a UI-free `argus/core/trends.py` over `run_discovery` history
(unit-tested); the chart widgets are thin. **Effort/Risk** — low/moderate;
one new `[terminal]` dependency.

## Phase 9 — Inline graphics (Kitty / iTerm2 / Sixel)

**Build** — `textual-image` renders real pixels on Kitty/Ghostty/iTerm2/
WezTerm (graphics protocol) with a Sixel path and a clean ASCII fallback
elsewhere (capability-detected). Concretely: a crisp logo on the splash, a
rendered **dependency graph** image for "why is this package here?", a
severity donut as an actual image, and a **QR code** linking to the full
report/attestation. **Effort/Risk** — moderate; gated entirely on
capability detection so non-graphics terminals are unaffected.

## Phase 10 — AI triage assistant (foundation, opt-in)

The roadmap's deferred Tier-2 — but as an interactive assistant, not just
batch fixes. **Reuses the existing provider abstraction** in
`argus/scn/ai.py` (`AnthropicProvider` / `OpenAIProvider`, env-var keys,
SDK-or-HTTP, OpenAI-compatible base URL) — no new AI layer.

**Build**
- A Findings-screen side panel: "explain this CVE in this repo's context",
  "is this reachable?", "draft a fix" — **streaming** tokens live.
- **No key required:** default to a local **Ollama** / OpenAI-compatible
  endpoint; cloud providers are opt-in via the same env-var pattern. Absent
  any provider, the panel shows deterministic context (Phase-6 enrichment +
  Phase-1 Fix) and says AI is off.
- UI-free `argus/core/ai_triage.py`: prompt builders + a streaming generator
  over the provider protocol, with provider/transport **mocked in tests**
  (exactly as the `scn` AI tests do). Treat model output as untrusted; any
  suggested fix flows through the Phase-1 diff-preview gate, never auto-applied.

**Effort/Risk** — high; ships as a tested foundation (provider wiring +
streaming panel + explain flow), with fix-suggestion polish iterative.

## Phase 11 — Console on the web (`textual serve`)

**Build** — one codebase, three surfaces: `argus console --web` runs the
*same* Console in a browser via `textual-serve`, yielding a shareable URL
for read-only triage. **Security-gated hard:** bind `127.0.0.1` by default,
require an auth token, and reuse the browser viewer's read-only boundary —
mutating actions (scan/fix/config/suppress) are disabled in web mode unless
explicitly, separately authorized. This is an ADR (it widens the
attack surface the browser-viewer ADR deliberately fenced off).
**Effort/Risk** — moderate to wire, high to get the security story right;
the gating is the feature.

## Phase 12 — Reachability-aware prioritization (research + first cut)

The holy grail of noise reduction: is the vulnerable code actually *called*?
The hardest item — honest staging:

- **First cut (buildable now):** a heuristic signal — does the vulnerable
  symbol / import appear anywhere in the scanned source? Cheap, imperfect,
  clearly labelled "present in source," and fed as one input to the Phase-6
  risk score.
- **Research (roadmap-only until proven):** true call-graph reachability via
  the SAST we already run (opengrep/semgrep dataflow), per-ecosystem. Scoped
  as its own investigation; not promised in this epic.

**Effort/Risk** — first cut: moderate. Real reachability: high / open
research — explicitly *not* claimed as shipped by this program.

---

## Build order & sequencing

Merge-train into `feat/tui-explorer-and-scan-runner`, highest
impact-vs-effort first: **5 → 6 → 7 → 8 → 9 → 10 → 11 → 12**. 5 (table
stakes) and 6 (the headline) front-load the visible wins; 6 unblocks the
risk score that 7 and 12 feed into. Charts (8) and graphics (9) are
independent visual upgrades. AI (10), web (11), and reachability (12) are
the deep/risky tail and ship as foundations.

---

## Cross-cutting concerns

- **Testing.** Pure core (`run_discovery`, `remediation`, config round-trip)
  unit-tested directly; screens via the stubbed-textual loader for CI
  coverage without the `[terminal]` extra; real-Textual `Pilot` smoke tests
  for interactive flows (skipped when textual is absent). AI providers mocked,
  exactly as the `scn` tests already do.
- **Terminal compatibility & accessibility.** The unglamorous third of the
  work: mouse capture, CJK/IME, low-color terminals, screen-reader-friendly
  plain mode, redraw-on-focus, SSH/tmux quirks. Budget for it per phase
  rather than bolting it on at the end.
- **Security.** Diff-/review-first for anything that touches user code or
  config; trusted-shell only (never the browser viewer); treat AI output as
  untrusted; honour the per-scanner secret-redaction guarantees when fixes
  echo finding content.
- **Docs in lockstep.** Extend the `capture_view_terminal.py` screenshot
  pipeline for each new screen so `view-terminal.md` (and a future
  `console.md`) never drift from the code.

## Open decisions (product calls before the relevant phase)

- **YAML write-back strategy** (Phase 2): ✅ decided — comment-preserving
  *targeted line rewrites* (`config_editor.set_value`) over the bounded set of
  toggle/enum scalars, not a `ruamel.yaml` round-trip or template
  regeneration. Preserves comments/ordering with no new dependency; the trade
  is that only settings already present in the file are form-editable.
- **Bare-`argus` default change** (Phase 4): ✅ decided — bare `argus`
  opens the Console, gated on stdout+stdin both being a TTY so headless /
  CI / piped use is untouched (no deprecation window needed). Still worth a
  formal ADR entry in `.ai/decisions.yaml`, and an opt-out env var
  (`ARGUS_NO_TUI`) could be added if a user wants help even interactively.
- **Local-model support depth** (Phase 1 Tier 2): how far to validate Ollama
  / OpenAI-compatible local endpoints so a cloud API key is never *required*.
- **Console module layout** (Phase 4): keep screens under
  `argus/viewers/terminal/` or promote to `argus/console/` once it's more than
  a viewer. Naming follows the bare-`argus` ADR.
