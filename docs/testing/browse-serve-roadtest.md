# Argus — `browse` TUI + `serve` Web UI Roadtest Guide

Branch under test: **`feat/serve-webui`** ([PR #97](https://github.com/huntridge-labs/argus/pull/97))

`argus browse` is the terminal TUI; `argus serve` is the browser web UI. Both read the same `argus-results.json` produced by `argus scan`. You can test either without Docker if you already have scan results on disk.

Target time: ~15 min of clicking around.

---

## 1. One-time setup

### Option A — install from TestPyPI (fastest; no git clone)

```bash
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate

pip install --upgrade pip
pip install --index-url https://test.pypi.org/simple/ \
            --extra-index-url https://pypi.org/simple/ \
            'argus-security[browse,serve]==0.7.2.dev46'

argus version                  # sanity — should print 0.7.2.dev46
```

`--extra-index-url https://pypi.org/simple/` is required so dependencies resolve from real PyPI while `argus-security` itself comes from TestPyPI. The CI publishes a fresh `dev<N>` version on every push to `feat/serve-webui`; confirm the current number at https://test.pypi.org/project/argus-security/#history if `0.7.2.dev46` has been superseded.

### Option B — from source (for code review)

```bash
git clone https://github.com/huntridge-labs/argus.git
cd argus
git checkout feat/serve-webui

python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate

pip install --upgrade pip
pip install -r requirements.txt
pip install -e '.[browse,serve]'

argus version
```

If `argus: command not found` after install, see **Troubleshooting** at the bottom.

## 2. Get a scan to look at

Pick any one:

```bash
# Option A — scan this repo (quick, needs Docker)
argus scan --config argus.yml

# Option B — there's already one checked in
ls argus-results/     # has a timestamped dir + latest/ symlink

# Option C — scan your own project
cd /path/to/your/project && argus scan
```

---

## 3. Test `argus browse` (terminal TUI)

```bash
argus browse                    # looks at ./argus-results
argus browse /path/to/results   # or an explicit path
argus scan --interactive        # or the one-shot: scan → auto-launch browse
```

### Try each, in any order

| Key | What to verify |
|---|---|
| `j` `k` / `↑` `↓` | Move up/down the findings list |
| `/` → type → `Esc` | Search filters (by id/title/location/CVE/scanner); `Esc` exits back to the list |
| `1` `2` `3` `4` | Severity filter: Critical only / High+ / Medium+ / All |
| `p` | Product picker modal opens, selecting filters the view |
| `c` | Scanner picker modal, same deal |
| `s` | Sort cycles: severity desc → asc → package → id (toast + column arrow) |
| `e` | Export CSV — toast shows the path, file opens in editor on `o` |
| `Ctrl+P` → "Export: JSON" / "Markdown" / "SARIF" | Other export formats |
| `o` / `r` | Open last export with default app / reveal in Finder/Explorer |
| `d` | Dashboard overlay (totals, per-product, per-scanner, quality warnings) |
| `?` | Help overlay — every binding listed |
| `q` | Quit cleanly |

**Pass criteria:** No crashes. Every binding does something visible. Search + filters combine (AND semantics). Exports write a real file and open/reveal correctly.

---

## 4. Test `argus serve` (browser web UI)

```bash
argus serve argus-results --open       # default port 8080, auto-opens browser
# or: argus serve /some/results --port 8765 --open
```

Point a browser at `http://127.0.0.1:8080/` if `--open` didn't fire.

### Dashboard (`/`)

- [ ] Severity cards at the top — **click** any of them, should drill into `/findings` filtered to that severity
- [ ] "Scan metadata" disclosure — expand to see scanner versions, durations, container image digests
- [ ] Per-product / per-scanner rows — clickable, drill into filtered findings

### Findings (`/findings`)

- [ ] **Filter**: change the "Min severity" dropdown — table auto-refreshes, URL updates (bookmarkable)
- [ ] **Search**: type in the box — filters live across id/title/location/CVE/scanner
- [ ] **Sort**: click Severity / ID / Location / Scanner headers. Click twice to flip direction. Arrow marks the active column.
- [ ] **Detail**: click a finding's title → inline panel with scanner/CVE/CWE/package@version/fix/location/SBOM + description
- [ ] **Columns hide**: Package / Fix / Source SBOM should be absent when every visible row is empty for those fields (e.g., a bandit-only scan)
- [ ] **Export** disclosure (below filters):
  - [ ] **Download** CSV → browser saves `argus-findings-<timestamp>-<scope>.csv`; file opens in a spreadsheet
  - [ ] **Copy** CSV → toast says "CSV copied to clipboard" → paste into a ticket
  - [ ] Same for JSON / Markdown / SARIF

### Picker (`/picker`, "Switch scan" in the nav)

- [ ] Breadcrumb at top shows the **filesystem path**, not the URL path
- [ ] Click into a subfolder — navigates into it
- [ ] "Load scan" link next to a scan-ready folder — loads that scan
- [ ] **Check two** scan-ready rows → "Compare selected" button enables → click it → you land on `/diff` with a New/Fixed/Severity-changed/Still-open breakdown

### Scan diff (`/diff`)

- Needs two scans. If you have one in `argus-results/`, run `argus scan` again (maybe after a small code change) to generate a second.
- [ ] Before → After paths shown in the header
- [ ] Tally pills: `N new · N fixed · N severity changed · N still open`
- [ ] Each section lists the findings that moved into it
- [ ] "Still open" is collapsed by default

### Theme toggle (top-right, circle icon)

- [ ] Click → flips between dark and light
- [ ] Refresh the page — your choice persists
- [ ] Accent lime, eye logo, and severity badges all stay legible in both themes

### Recent-runs dropdown (nav, between "Findings" and "Switch scan")

- Only shows when `argus-results/` has 2+ scan-ready dirs — skip if you only have one.
- [ ] Clicking a row switches to that run; the current run is highlighted lime

### Security sanity checks

- [ ] `http://127.0.0.1:8080/?scan=/etc/passwd` → "Path is outside the scan root" error; no file contents leak
- [ ] Dev tools → Network → response headers on `/` include:
  - `Content-Security-Policy: default-src 'self'; style-src 'self'; script-src 'self'`
  - `X-Frame-Options: DENY`
  - `Referrer-Policy: no-referrer`
- [ ] Dev tools → Console should be empty (no errors, no warnings)

**Pass criteria:** every boxable item above checks, no console errors, no server crashes in the terminal running `argus serve`.

---

## 5. Report anything you find

Capture:
- The command you ran
- Browser + OS version
- Screenshot of the error or misbehavior
- A copy of `argus-results/latest/argus.log` if something crashed during scan

File issues at: https://github.com/huntridge-labs/argus/issues (mention "PR #97 roadtest" in the title).

---

## Troubleshooting

**`argus: command not found` after install** — your shell isn't pointing at the venv's `argus`. Fix:
```bash
which argus                                    # should be .venv/bin/argus
deactivate && source .venv/bin/activate        # re-activate
hash -r                                        # clear shell cache
```
If `which argus` still isn't the venv, pyenv shims or Homebrew may be intercepting. Call it explicitly: `.venv/bin/argus serve …`.

**`The local web UI needs the 'serve' extra`** — the venv doesn't have fastapi. Same root cause:
```bash
.venv/bin/pip install -e '.[serve]'
.venv/bin/argus serve ...
```

**`ImportError: Using SOCKS proxy, but the 'socksio' package is not installed`** — your shell has `ALL_PROXY`/`HTTPS_PROXY` set to `socks5://`. Fix:
```bash
.venv/bin/pip install 'httpx[socks]'
```

**`argus serve` starts but the browser doesn't open** — `--open` relies on your OS's default browser resolver. Just paste `http://127.0.0.1:8080` manually.

**Port already in use** — pass `--port N` to pick a different one.
