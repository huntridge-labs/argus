# Plugin contract — `argus.plugins.v1`

The **stable public surface** that third-party plugins (and Argus Enterprise)
build on. Anything documented here is contract: Argus commits not to break it
within a major version. It is enforced by conformance tests
(`argus/tests/test_plugin_contract.py`) that run on every PR — **a change that
breaks the contract fails CI before merge**, so "update Argus, break a plugin"
cannot slip through. See [ADR-032](../.ai/decisions.yaml).

## Stability policy

- **No breaking changes within a major version.** Adding a field, a `Severity`
  member, or a new entry-point group is backward-compatible. Removing or
  renaming a documented field/member/method is breaking → it requires a new
  contract version (`argus.plugins.v2`) and a **major version bump** of
  `argus-security`.
- Downstreams pin a **compatible range** (e.g. `argus-security>=1.4,<2.0`) and
  should add a load-time version guard that degrades gracefully on a mismatch
  rather than crashing (this is what Argus Enterprise does).

## The contract surface

### Data shapes (`argus.core.models`)

- **`Finding`** — fields: `id`, `severity` (a `Severity`), `title` (required);
  `description`, `location`, `cwe`, `cve`, `scanner`, `metadata` (optional, with
  defaults). `to_dict()` emits those keys with `severity` as its string value.
- **`ScanResult`** — fields include `scanner` and `findings`; `to_dict()` exposes
  both, with each finding serialized.
- **`Severity`** — members `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`, `UNKNOWN`
  (values are the lowercase names). `Severity.from_string(s)` coerces a string
  (case-insensitive, trimmed); unknown input → `UNKNOWN` (never raises).

### Scanner protocol (`argus.core.scanner.Scanner`)

A `runtime_checkable` Protocol. A conforming scanner provides the data members
`name: str` and `supports_sbom: bool`, and the methods `scan(path, config=None)
-> ScanResult`, `is_available() -> bool`, `install_command() -> str | None`,
`tool_version() -> str | None`.

### Reporter seam (`argus.reporters`)

- Entry-point group: **`argus.reporters`** (the constant
  `argus.reporters.ENTRY_POINT_GROUP`).
- A reporter is a class implementing **`report(summary, output_dir=None)`**.
- A third-party package registers one via
  `[project.entry-points."argus.reporters"]`; it is discovered and resolvable
  through `available_reporters()` / `get_reporter(name)`. External reporters
  **cannot shadow a built-in name** (the loader rejects that).

## Seams still being promoted into the contract

The interactive-extension seams — `argus.console_providers` and
`argus.viewers.browser_plugins` (plus the `app.state` helper surface) — and the
container plugin sandbox (`argus.core.plugin_runtime`, ADR-031) are part of the
plugin story but are **not yet on `main`** (they ride with the TUI/viewer work).
Their conformance tests join this suite when those seams land in a release; until
then, only the surface above is a stability guarantee.

## How this protects downstreams

1. **Versioned contract** (this doc) — defines "compatible".
2. **Conformance tests in core CI** — a contract break fails core CI pre-merge.
3. **Downstream range pin** — pip refuses to install an out-of-range core while
   the plugin is installed.
4. **Load-time version guard** — a forced mismatch degrades gracefully with an
   actionable "update the plugin" message instead of crashing.

Layers 1–2 live here in the OSS core; 3–4 live in each plugin (e.g. Argus
Enterprise's `compat` guard).
