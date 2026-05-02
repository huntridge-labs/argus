# `argus view terminal` — interactive findings triage

After a scan produces `argus-results.json`, reading the raw file in an editor
or paging through the linear Markdown report is a poor way to triage.
`argus view terminal` is a full-screen terminal UI for *navigating* findings: filter by severity,
product, or scanner; search by CVE; drill into details; export the filtered
subset; see an executive summary — all with keyboard shortcuts.

Ships behind an optional extra so CI/server installs of argus stay
lightweight.

## Install

```bash
pip install 'argus-security[terminal]'
```

The extra pulls in [Textual](https://textual.textualize.io/) (~2 MB of Python
deps). Without it, running `argus view terminal` prints a friendly install hint and
exits cleanly — the extra is never required for `argus scan` or any other
subcommand.

## Launch

```bash
argus view terminal                          # loads ./argus-results/argus-results.json
argus view terminal ./run-2026-04-24         # specific results directory
argus view terminal ./custom-results.json    # direct file path
```

### One-flag scan → browse workflow

```bash
argus scan --interface=terminal              # scans, then opens the terminal viewer on the output
argus scan --sbom data/ --interface=terminal # batch-scan a directory of SBOMs, then browse
```

The `--interface=terminal` flag takes effect after the scan completes and the
manifest is finalized. If the `[terminal]` extra isn't installed, the scan
still succeeds; only the viewer launch is skipped with a note.

## Keyboard reference

Press `?` inside the TUI for the same reference, grouped by purpose.

| Key | Action |
|-----|--------|
| **Navigate** | |
| `j` / `k` or `↑` / `↓` | move selection |
| `tab` | jump between panes |
| **Search & filter** | |
| `/` | focus search (matches id, title, location, CVE, scanner) |
| `ESC` | exit search back to the findings list |
| `1` | show only CRITICAL findings |
| `2` | HIGH severity and above |
| `3` | MEDIUM severity and above |
| `4` | clear severity filter (all) |
| `p` | pick a product (SBOM source) to focus on — modal |
| `c` | pick a scanner to focus on — modal |
| **Sort** | |
| `s` | cycle: severity desc → asc → package → id (toast + header arrow) |
| **Export** | |
| `e` | export visible findings as CSV |
| `o` | open last export with your default app |
| `r` | reveal last export in file manager |
| **Other** | |
| `d` | executive dashboard overlay |
| `?` | help overlay |
| `Ctrl+P` | command palette (fuzzy-search every action) |
| `q` | quit |

JSON, Markdown, and SARIF exports are available via `Ctrl+P` → type
`Export: JSON` / `Export: Markdown` / `Export: SARIF`. The filename
convention is `argus-findings-YYYYMMDD-HHMMSS-<severity>.<ext>` so repeated
exports at different filters never clobber each other.

## Views

### Findings list (default)

Two-pane layout: table of findings on the left, detail of the currently
highlighted row on the right. The status bar lists every active filter
(severity, product, scanner, query) plus the current sort mode.

### Executive dashboard (`d`)

Modal overlay aimed at owners / managers / execs who want a one-screen
answer to "what's the state of our security posture?":

- Total findings with per-severity breakdown
- Quality warnings — SPDX-2.1 SBOMs Trivy can't read, SBOMs missing purl
  refs, Grype's "couldn't identify scan subject" warnings — surfaced loudly
  so an empty scan isn't misread as "we're clean"
- Per-product breakdown — every SBOM source with total + crit + high counts
  and the top-3 findings
- Per-scanner contribution counts

Dismiss with `ESC`, `q`, or `d` again.

### Help overlay (`?`)

Grouped keyboard reference with a one-line explanation of each binding.
Dismiss with `ESC`, `q`, or `?` again.

### Command palette (`Ctrl+P`)

Textual's built-in fuzzy-search launcher. Every `argus view terminal` action is
registered as a command — type "sort", "filter", "export", "dashboard",
"product", etc. to find them. Textual's own commands (Keys help, Theme
switcher, Screenshot-as-SVG) also appear.

The **Screenshot** command is genuinely useful: saves the current TUI view
as an SVG you can drop into a ticket or doc — better than cropping a
terminal screenshot manually.

## Export formats

All four writers take the currently filtered view. Pick via keyboard shortcut
(`e` for CSV) or the command palette for the others.

| Format | Best for | Produces |
|--------|----------|----------|
| **CSV** | Spreadsheet work, bulk ticket upload | `argus-findings-<stamp>-<scope>.csv` |
| **JSON** | Scripting, downstream automation | `argus-findings-<stamp>-<scope>.json` — list of `Finding.to_dict()` objects, identical shape to `argus-results.json` per-finding records |
| **Markdown** | Ticket bodies, PR descriptions | `argus-findings-<stamp>-<scope>.md` — table with severity icons, pipe-escaped cells |
| **SARIF** | Security dashboards, GitHub Code Security | `argus-findings-<stamp>-<scope>.sarif` — SARIF 2.1.0, per-scanner runs, severity→level mapping |

Exports write to the current working directory. `.gitignore` patterns
(`*.csv` and `argus-findings-*.{json,md,sarif}`) cover them in the argus
repo; add similar rules to downstream projects where you run `argus view terminal`.

## Platform notes

- **macOS**: `o` opens with the file's default app (Numbers for `.csv`,
  your Markdown viewer for `.md`); `r` reveals in Finder via `open -R`.
- **Windows**: `o` uses `cmd /c start`; `r` uses `explorer /select,<path>`
  (highlights the file in Explorer).
- **Linux**: `o` uses `xdg-open`; `r` opens the parent directory via
  `xdg-open` — there is no portable "select file" verb across file managers.

All opener invocations go through `subprocess.Popen` with an argv list, not a
shell string, so paths with spaces, quotes, or special characters are safe.

## Troubleshooting

**`argus: error: argument command: invalid choice: 'browse'`** — your `argus`
binary was installed before `browse` landed. Reinstall: `pip install -e
'.[browse]'` in a dev checkout, or `pip install --upgrade 'argus-security[terminal]'`.

**TUI shows "Could not find argus-results.json"** — you haven't run a scan in
the target directory yet, or the scan used a different `--output-dir`. Run
`argus scan --format json` first, or pass the results path explicitly.

**Command palette shows only Textual builtins** — your install is missing the
argus-specific command provider. Reinstall the branch or ensure you're
running the venv's `.venv/bin/argus` rather than a shim from a system
install.

**I want to open with a different app, not my system default** — `o` honors
your OS's file-type associations. Change those in Finder (macOS, "Get Info" →
"Open With"), via `xdg-mime` on Linux, or via File Explorer on Windows.

## Related

- [`argus scan`](cli-reference.md#argus-scan) — produces the
  `argus-results.json` that `argus view terminal` loads
- [`argus report`](cli-reference.md#argus-report) — regenerate terminal /
  markdown / JSON / SARIF output from an existing results directory without
  re-running scanners
- [SDK roadmap](developer/SDK-ROADMAP.md) — tracked follow-ups (multi-select,
  scan-over-scan diff, `argus summary` standalone command, `argus view browser` web
  view sharing the same `findings_view` module)
