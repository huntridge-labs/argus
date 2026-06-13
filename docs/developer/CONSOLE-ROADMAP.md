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

## Phase 1 — Vulnerability mitigation ("Fix") (next)

Let users resolve findings, not just read them. Full design is the
mitigation plan; summary here.

**Architecture**
- New UI-free `argus/core/remediation.py`: `Remediation` dataclass +
  `propose(finding, *, repo_root)` / `apply(remediation, *, repo_root)`.
  Computed on the fly from existing finding data (no `Finding` schema /
  `argus-results.json` / redaction change).
- **Tier 1 — deterministic, OSS, no key:** dependency bumps (from
  `metadata.fixed_version`, populated in `argus/scanners/_vuln_parsers.py`),
  GitHub Actions SHA-pinning (`scanner-supply-chain` findings), opengrep
  rule autofix (`fix:` keys). Native manifest rewrite preferred over adding
  fixer-tool deps; major-version bumps surfaced as a distinct higher-risk
  class, never silent.
- **Tier 2 — AI-assisted, opt-in (`[ai]` + `--enable-ai`):** SAST logic
  rewrites via the `scn/ai.py` providers (or a local model through the
  OpenAI-compatible base URL). Output is a unified diff, always reviewed,
  never auto-applied, always gated by the test pipeline.
- **TUI:** `F` → Fix overlay (reuses the Phase-0 `RunScanScreen` pattern):
  show the proposed diff, Apply / Cancel, optionally chain into a re-scan to
  confirm the finding is gone. Batch-fix over the existing multi-select set.
  A `⚒` table marker flags fixable rows.

**Why first:** Tier 1 is fully OSS and slots straight into the
"trust → green tests → auto-merge" end-state — a deterministic fix that
produces a passing run *is* the auto-merge story. It also complements the
already-foundational Dependabot/Renovate flow as its interactive sibling.

## Phase 2 — Config editor screen (planned)

Edit `argus.yml` by form, not by hand.

**Architecture**
- A Config screen using Textual `Input` / `Select` / `Switch` / `RadioSet`,
  populated from and validated against the existing config schema
  (`argus/core/config.py` + `argus/core/schema.py`). Live validation; invalid
  states block save.
- **Surfaced focused docs:** render the relevant slice of
  [`config-reference.md`](../config-reference.md) per field so the answer to
  "what does this do?" is on screen.
- **Safe write-back:** form-generated YAML must not clobber a user's comments
  / ordering. Decide up front: a round-trip-preserving writer (`ruamel.yaml`)
  vs. regenerate-from-template. This is a prerequisite, not a detail.
- Scanner selection reuses the logic already behind the docsite Configure
  mode (`scripts/docsite/architecture.py`), keeping one source of truth for
  "which scanners, what config they emit."

## Phase 3 — Init wizard screen (planned)

Guided first-run. Wraps the existing detection (`argus init` —
language / framework / linter detection) in an interactive screen: detect →
review the proposed scanner set → tweak → write `argus.yml` → offer to run
the first scan (hand off to the Phase-0 runner). No new detection logic;
it's a frontend over `argus init`.

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
- **Configure / Init** reach the real CLI capabilities now: Configure opens
  `argus.yml` in `$EDITOR`/`$VISUAL` (via `App.suspend`), Init streams
  `argus init`. The form-based config editor (Phase 2) and init wizard
  (Phase 3) replace these interim flows.

**Remaining**
- Findings + Init are hand-offs (the console exits with a sentinel; the
  viewer / `argus init` run, then the console reopens). The seamless
  single-app version folds the findings viewer in as a `FindingsScreen`
  mounted by both the Console and `argus view` — the "Console module
  layout" decision below.
- Deeper terminal-compat / accessibility (`NO_COLOR`, low-color, SSH/tmux
  fallbacks, screen-reader plain mode) beyond reduced-motion + the
  animation kill-switch.

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

- **YAML write-back strategy** (Phase 2): `ruamel.yaml` round-trip vs.
  template regeneration. Affects whether we can preserve user comments.
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
