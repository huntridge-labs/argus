# Argus Browser & Reporting Roadmap

The browser viewer (`argus view --interface=browser`) is the right surface
for an audience the terminal isn't built for: stakeholders who want to *see*
the security posture, and auditors who need an authoritative artifact. This
roadmap turns it from a read-only findings viewer into the **report-and-share
surface** — culminating in a formal, government-grade PDF vulnerability
report.

It's the deliberate alternative to a web Console (see
[`CONSOLE-ROADMAP.md`](CONSOLE-ROADMAP.md) Phase 11, *not pursued*): rather
than serving the operate-from TUI over a browser — clunky, and a security
surface — we invest in what the browser does that a terminal fundamentally
can't.

This is an epic, built the same way as the Console: each phase its own green
PR with tests + docs, merged into the integration branch
(`feat/tui-explorer-and-scan-runner`).

---

## Principles

- **The read-only boundary holds.** The browser viewer stays read-only,
  `127.0.0.1`, no repo mutation. Nothing here runs scans, writes config, or
  applies fixes — that's the terminal's trusted-shell job.
- **Reuse the shared UI-free cores.** Charts, risk, and reachability come
  from `argus/core/` modules built for the Console epic
  (`trends`, `enrichment`, `reachability`) — the browser is just another
  front-end over the same logic. No console code is imported.
- **Dependency-conscious, with one deliberate exception.** Everything is
  zero-new-runtime-dep (inline SVG, vanilla JS — the viewer's existing
  style) *except* the formal PDF, whose engine lives behind an opt-in
  `[report]` extra (see Phase B4). A supply-chain tool minimises its own
  surface; the one heavy dependency is isolated and justified.

## North star

A teammate runs `argus scan`, opens the browser viewer, and can: read the
findings with real charts; sort by real-world risk (EPSS/KEV) and see which
deps are actually imported; share a URL to an exact filtered slice; and
generate **one PDF** — counts, trends, charts, breakdowns, full findings,
and the cryptographic provenance of the scan — that they can hand to an
auditor or a government body as the authoritative record of "this is what we
scanned and what we found."

---

## Phase B1 — Real charts on the dashboard

The dashboard has no visualisations today. The browser is where charts
belong (the terminal only got Unicode bars out of necessity).

**Build** — inline **SVG** charts (hand-rolled, **no** `d3`/`plotly`/chart
library — matches the viewer's vanilla `argus.css` + JS): a severity donut,
a findings-over-runs trend line, and by-scanner / by-package bars. The data
comes from `argus.core.trends` (already unit-tested); a small UI-free
`svg`-string helper (testable) emits the markup, the Jinja template embeds
it. Degrades to the existing tables where data is absent.

## Phase B2 — Risk & reachability columns

**Build** — surface the Console epic's intelligence in the read-only viewer:
an **EPSS / KEV risk** badge + sortable risk column (`argus.core.enrichment`)
and an **"imported in source"** reachability indicator
(`argus.core.reachability`). Enrichment is a *server-side* fetch (public CVE
ids only, cached) — **opt-in** (a config/flag), honouring the same offline
posture as the terminal. Read-only: these annotate, never mutate.

## Phase B3 — URL-addressable views & dependency drilldown

**Build** — lean into the browser's superpower, the URL: bookmarkable,
shareable links for a filtered slice (`/findings?severity=high&scanner=osv`)
and a deep-link/anchor to a specific finding, so "here are the 3 criticals to
look at" is a pasteable link. Plus an interactive, collapsible
**dependency-tree / SBOM drilldown** ("why is this package here?") — HTML
does nesting + expand/collapse far better than a TUI.

## Phase B4 — Formal PDF vulnerability report (the centrepiece)

A comprehensive, **authoritative** PDF — the artifact you hand to an auditor
or government body to make formal policy decisions about scanned software.

**Build**
- A new report **route + template** assembling: a **cover page** (project,
  scan timestamp, argus version), an **executive summary** (counts +
  severity breakdown + trend), **charts** (reusing B1's SVG), per-severity /
  per-scanner / per-product **breakdowns**, the **full findings** tables
  (with CVE/CWE/location/package/fix), and a **provenance appendix**.
- **Provenance appendix — the authoritative facts**, pulled from what Argus
  already records: **argus version** (`core/version.py`), **scanner
  toolchain provenance** (`core/toolchain.py` — the `toolchain` block:
  per-scanner image digests + signature-verification status, #243), the
  **signed scan attestation** (`core/attest.py` — OpenVEX in-toto, subject =
  image digests + repo commit, #244), and **commit SHA / repo root**
  (`ScanSummary`). This is what makes the PDF *authoritative*, not just
  pretty.
- **Server-side one-click PDF** via **WeasyPrint** (HTML/CSS/SVG → PDF),
  behind an opt-in **`[report]` extra** — its native stack (pango/cairo)
  can't be a core dependency, so the feature errors with a clear
  `pip install 'argus-security[report]'` hint when absent (the same
  guarded-extra pattern the Console epic used). The report's HTML doubles as
  an on-screen view; the PDF is the frozen, signed-provenance record.
- **UI-free core** (`argus/core/report.py`, testable without WeasyPrint):
  assembles the report *model* (sections, provenance facts, chart data) from
  a `ScanSummary`; the HTML render + PDF conversion are the thin,
  dependency-bearing edges.

**Effort/Risk** — the largest phase; the provenance assembly + report model
are pure/tested, the WeasyPrint edge is guarded and smoke-tested.

## Phase B5 — Accessibility & responsive polish

**Build** — screen-reader semantics (ARIA on charts/tables), keyboard
navigation, and a responsive layout so the read-only report reads well on a
tablet / projector for the non-technical / exec audience the browser serves.

---

## Build order

Merge-train into `feat/tui-explorer-and-scan-runner`, value-first:
**B1 → B2 → B3 → B4 → B5**. B1's SVG charts are reused by B4's report, so
they come first; B4 (the formal report) is the centrepiece everything builds
toward; B5 polishes the surface once the content is there.

## Decisions

- **PDF engine = WeasyPrint, behind a `[report]` extra** (decided). Chosen
  for HTML/CSS/SVG fidelity so the report and the on-screen HTML share one
  template. Native-lib install is documented; the feature is opt-in, never a
  core dependency.
- **Charts = inline SVG, no chart library** (decided) — keeps the
  zero-new-dep posture for everything except the isolated PDF extra.
- **Enrichment in the browser is opt-in** (server-side egress of public CVE
  ids) — same posture as the terminal's `i` action.
