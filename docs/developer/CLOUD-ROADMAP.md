# Argus Cloud Roadmap

> **Status:** proposal / pre-implementation. This document scopes a hosted,
> multi-tenant scanning capability of **Argus Enterprise**. Nothing here ships
> yet. The design rationale and the licensing boundary are recorded in
> [`.ai/decisions.yaml`](../../.ai/decisions.yaml) **ADR-035**.

**Argus Cloud** is a **licensable capability of Argus Enterprise** — not a
separate tier. Argus Enterprise is the commercial layer over the AGPL core: a
menu of capabilities (the Console, the provenance report, and now Cloud) that
customers pick and choose from, with our contracting team setting the price per
engagement. Cloud is the capability you license when you want us to *host the
scanning* rather than run it yourself.

With the Cloud entitlement, a CISO points Argus at a GitHub org (or a
hand-picked set of repos) and gets the latest Argus hardening suite running on
every merge to the default branch — with **no workflows, no CI YAML, no runners
to babysit**. Results land in a dashboard built for the technical *and* the
non-technical, and (optionally) as a living issue on the repo's default branch.

It is the "we host it, you just watch the numbers go down" capability. The open
source SDK is "run it yourself"; Enterprise's local capabilities (Console,
report) are "run it yourself, but nicer locally"; Cloud is "don't run anything."

Because Cloud consumes **our** compute, the license isn't just an unlock — it
**parameterises** the engagement: which repos are in scope and how often they
may scan are contract terms the control plane enforces. We never run unbounded
scanning on our dime. See *Licensing & compute control* below — this is a hard
design constraint, not an afterthought.

---

## Why build it

We already have the hard part. The OSS SDK orchestrates 18+ scanners behind one
config, normalises every tool's output into a canonical `argus-results.json`
(`ScanSummary`), runs each scanner in a cosign-verified container, and renders a
findings dashboard from a FastAPI + Jinja2 browser viewer. Argus Cloud is
mostly **operationalising what exists** behind a control plane, a GitHub App,
and a billing boundary — not inventing new scanning.

The market it walks into is large and already paying:

| Incumbent | What it is | Where Argus Cloud wins |
|---|---|---|
| **GitHub Advanced Security** | CodeQL SAST + secret + dependency scanning, per *active committer* | Multi-tool (not just CodeQL), IaC + container + DAST + malware in one price, runs on GHES, no per-committer surprise billing |
| **GitLab Ultimate** | SAST/DAST/dependency/container in the Ultimate tier | Platform-independent (GitHub, GHES, later GitLab/Bitbucket), buy only the security layer, lower per-seat |
| **Docker Scout** | Container image CVE dashboard | Containers *and* source SAST/secrets/IaC under one roof and one dashboard |
| **Snyk / Aikido / etc.** | Multi-product security platforms | Single all-inclusive price, OSS engine you can self-host to exit, provenance-bound reports |

The pitch is **all-inclusive, one dashboard, lower cost per seat**, with a
credible "you can always run the OSS engine yourself" exit that the closed
incumbents can't match.

---

## Where it fits: a capability of Enterprise, not a tier

There are **two products**: OSS Argus (AGPL-3.0, free, self-host) and **Argus
Enterprise** (the commercial layer). Enterprise is not a monolith — it is a
menu of independently-licensable capabilities. Cloud is one of them.

| Argus Enterprise capability | What it adds | Where the work runs |
|---|---|---|
| **Console** | full-screen local home hub for the whole local workflow | your machine |
| **Report** | provenance-bound, board-ready HTML + PDF report | your machine |
| **Cloud** *(this doc)* | hosted scanning on merge + multi-tenant dashboard | **our infrastructure** |
| *(future capabilities)* | … | … |

A customer licenses **whatever subset they want** — Console only, report only,
Cloud only, or any combination. Our contracting team prices each engagement
(per-seat, per-product, or a blend — TBD); we simply offer the options and gate
each behind a license entitlement, exactly as the `report` capability is gated
today (ADR-034).

Cloud is distinguished from the local capabilities by *who runs the scan*:

| | OSS / local Enterprise capabilities | **Cloud capability** |
|---|---|---|
| Who runs the scan | you (CLI / your CI / local) | **we do — hosted workers** |
| Trigger | manual / your pipeline | **merge to default branch (automatic)** |
| Where results live | local `argus-results.json` / Console / PDF | **hosted dashboard + repo issue** |
| Cost driver | your compute | **our compute → license-controlled** |

Same engine, same `ScanSummary`, same findings renderer everywhere — Cloud is a
delivery model, not a fork. A customer can stop the Cloud subscription and run
the OSS SDK themselves at any time without losing their data model. That
portability is a feature, not a leak.

---

## The CISO journey (the "few steps" promise)

The entire onboarding must be doable by a security leader who never touches a
terminal:

1. **Sign in** with GitHub (OAuth) at `app.argus.security` (or self-hosted
   equivalent for GHES).
2. **Install the Argus GitHub App** on the target org. The app requests
   least-privilege scopes (see *Trust model* below).
3. **Choose coverage** — whole org, or a hand-picked repo list. Toggle which
   scanner categories are in scope (SAST / secrets / deps / IaC / container)
   with sensible all-on defaults.
4. **Pick a plan and pay** — per-seat subscription, seats = unique committers
   to covered repos in the billing period (with a clear, capped count, not a
   surprise overage like GHAS).
5. **Done.** The first scan kicks off immediately (baseline scan of each
   covered default branch); thereafter every merge to a default branch
   triggers a fresh scan with the latest pinned Argus suite.

No `argus.yml` to author, no workflow file to commit, no self-hosted runner.
Power users can still drop an `argus.yml` in the repo to override defaults —
Cloud reads it if present, falls back to managed defaults if not.

---

## Architecture

The service runs in **AWS**. The integration boundary is a **GitHub App** a
customer attaches to their org (or a chosen repo list); everything else is
ours. Three planes — *ingest/control*, *compute*, and *presentation* — plus a
Huntridge-owned *licensing & key* root.

```
   GitHub                          AWS (Argus Cloud VPC)
 ┌──────────┐   webhook    ┌──────────────────────────────────────────────────────────┐
 │  org /   │──(push, ────▶│  API Gateway / ALB → Ingest+API svc (ECS Fargate)         │
 │  repos   │  install)    │        │  verify license · check quota · enqueue          │
 │          │◀── issue ────│        ▼                                                   │
 │ living   │   check run  │     SQS scan queue ──▶ Worker fleet (Fargate, 1 task/job)  │
 │ issue +  │   (App token)│                          pull pinned Argus image (ECR)     │
 │ (future) │              │                          OIDC→short-lived install token    │
 │  PRs     │              │                          clone→`argus scan`→results        │
 └──────────┘              │        ┌─────────────────────────┘                          │
                           │        ▼                                                     │
                           │   Aurora PostgreSQL (tenants, runs, findings, ledger)        │
                           │   S3 (SARIF + raw artifacts, per-tenant prefix, KMS-enc)     │
                           │        ▲                         ▲                            │
   customer ───https──────▶│  Argus Portal (customer UI)   Admin console (Huntridge ops)  │
   (CISO/eng)              │   Cognito auth · tenant-scoped   cluster health · activity ·  │
                           │        ▲                         #customers/repos · Argus ver │
                           │        │                                                      │
                           │   Licensing & key root: KMS (signing key) + license issuer + │
                           │   Secrets Manager  ── Huntridge-owned, manages customer keys  │
                           └──────────────────────────────────────────────────────────────┘
```

### Components

- **GitHub App** — the integration boundary and the *initial offering*. One app,
  attached per org or to a chosen repo list, grants least-privilege access:
  `contents: read` (clone), `metadata: read`, `checks: write`, `issues: write`
  (the living issue), `pull_requests: read` (and, **only when the future
  agentic-PR capability is licensed**, `pull_requests: write` + `contents: write`
  on an opt-in basis). Webhooks: `push` (filtered to default branch),
  `installation`, `repository`. By default, no write access to code.

- **Ingest + API service** — **ECS Fargate** behind **API Gateway / ALB**.
  Multi-tenant, and the **license/quota enforcement point**. Owns:
  organisations, installations, repos & coverage selection, users & seats,
  license entitlements, billing, scan-job lifecycle, compute metering, and
  authz. Receives webhooks, resolves whether the event is a default-branch merge
  on a covered repo, **verifies the license, checks repo scope + cadence budget,
  and only then enqueues a job** onto SQS (see *The license token* and *quota-
  check flow*). It also runs the **cadence scheduler** — repos can be scanned on
  a defined schedule (e.g. nightly/weekly baseline), not only on merge, both
  bounded by the same quota.

- **Scan queue** — **Amazon SQS**. Durable, decouples ingest spikes (merge
  storms) from worker capacity; the budgeted, debounced job is what lands here.

- **Scan worker fleet** — **ephemeral, single-tenant Fargate tasks, one per
  job**. Each task pulls the pinned, cosign-verified Argus image from **ECR**,
  mints a **short-lived GitHub installation token scoped to the one repo**,
  shallow-clones the covered ref, runs the SDK engine (`argus scan`, managed
  defaults or the repo's `argus.yml`), emits canonical `argus-results.json`,
  pushes results to the API, and **self-destructs**. Source lives only on the
  task's ephemeral storage and dies with it. This is the existing Docker backend
  (`argus/containers.py`) running as a Fargate task instead of on a laptop.
  Autoscales on queue depth, capped by each tenant's `max_concurrent_workers`.

- **Argus version pipeline (we maintain "the latest")** — the service always
  scans with the current Argus suite. A release pipeline builds the
  cosign-signed worker image (engine + pinned scanner images) and publishes it to
  **ECR**; promoting a new Argus release re-points the worker task definition to
  the new digest. Customers never pin or upgrade anything — "latest, maintained
  by us" is the promise. The running Argus version is surfaced in both the Portal
  and the admin console.

- **Data stores** — **Aurora PostgreSQL** for tenant data and the queryable
  `ScanSummary` (runs, findings, severities, per-repo trends over time) plus the
  **runtime quota ledger**; **S3** (per-tenant key prefix, KMS-encrypted) for raw
  artifacts (SARIF, per-scanner output) under a retention policy. Row-/prefix-
  level tenant isolation from day one.

- **Licensing & key root (Huntridge-owned)** — the customer license is **issued
  by Huntridge and lives in AWS**, so Huntridge manages customer keys centrally.
  The license **signing key is an asymmetric key in AWS KMS** (cosign supports
  KMS signers, reusing our trust root); the private key never leaves KMS. A
  **license issuer** service (used by contracting tooling) mints
  `argus.license/v1` documents on a signed deal and stores issued licenses +
  per-customer metadata; **Secrets Manager** holds GitHub App credentials and
  other secrets. The Ingest service verifies licenses with the **public** key —
  offline, so self-hosted/air-gapped deployments verify with no callback while
  Huntridge retains sole control of issuance and revocation.

- **Argus Portal (customer dashboard)** — the customer-facing UI, the
  **separate Argus Portal project** we're already developing, not a one-off.
  Auth is **Amazon Cognito** (AWS-native, the most sustainable choice for an
  AWS service), and a single Cognito user pool fronts **three login methods** so
  customers sign in their chosen way:
  - **GitHub** — federated OIDC; natural since they're already attaching the
    GitHub App.
  - **Username / password** — the pool's native directory for teams that don't
    want to federate.
  - **Org SSO** — the customer's own IdP via **SAML or OIDC** (Okta, Entra ID,
    Google Workspace, etc.), configured per tenant so enterprise users land
    through their existing SSO.

  Whichever path, identities resolve to one user record mapped to exactly one
  tenant. Portal is strictly tenant-scoped: **only the customer's authorised
  users and Argus admins can see that customer's vulnerability data** — enforced
  at the query layer, not just the UI. It renders the two-lens dashboard (below)
  over the hosted `ScanSummary`, reusing the OSS browser viewer's `findings_view`
  + templates, and serves the board-ready PDF (the report capability, server-side).

- **Admin console (Huntridge ops)** — a separate, Argus-admin-only surface for
  **running the service**, and the home of the **performance & cost controls**.
  It is both observability *and* the live control plane for the fleet:
  - **Observe** — cluster/fleet health, current activity (jobs running, queue
    depth, recent scans), the live Argus version deployed, error/alert feed, and
    business telemetry: number of customers, covered repos, seats, and compute
    consumed vs. budget per account.
  - **Control (tunable, no redeploy)** — the **global concurrency ceiling**,
    priority-lane / fair-share weights, default cadence-jitter window, Spot-vs-
    on-demand capacity mix, AWS Budgets / anomaly alarm thresholds, and
    per-tenant overrides (raise/throttle a specific account, pause a noisy repo,
    kill a runaway scan). These knobs are read by the control plane at dispatch
    time, so an operator can retune cost-vs-latency in real time as load and
    metering data come in — the "tunable" global ceiling lives here.

  Backed by **CloudWatch** metrics/logs plus the control-plane DB; changes are
  audit-logged. This is what lets a small team operate a multi-tenant fleet and
  keep the bill bounded without shipping code.

- **Issue/check writer (the in-repo dashboard)** — uses the GitHub App token to
  post a check-run summary on the scanned commit and to maintain one **living
  "Argus security" issue** per repo on the default branch: current open findings
  grouped by severity, a trend line, and a deep link into the Portal. It *is* the
  in-repo dashboard for teams that live in GitHub. Auto-edited on each scan,
  auto-closed when clean — the OSS CI-preflight living-issue pattern repurposed
  for findings.

### Reuse vs. net-new

| Reused from OSS | Net-new for Cloud (AWS) |
|---|---|
| Scan engine (`argus/core/engine.py`) | GitHub App + webhook ingest (Fargate/API GW) |
| All scanner/linter modules | Multi-tenant control plane + cadence scheduler + authz |
| Docker backend, cosign verify, image pinning | Worker fleet as Fargate tasks + ECR image pipeline |
| `ScanSummary` / `argus-results.json` model | Aurora time-series store + S3 artifacts + quota ledger |
| `findings_view` + browser templates | **Argus Portal** (Cognito auth, tenant-scoped data) |
| Living-issue pattern (CI preflight) | Per-repo living *findings* issue + check runs |
| Report capability (server-side PDF) | License issuer + KMS key root + **admin console** |

The deliberate consequence: scanning logic has **one** home (the SDK). Cloud
must never fork it — it wraps the SDK in AWS plumbing, a license, and two UIs
(customer Portal + Huntridge admin).

---

## The dashboards: in-repo and in Portal

Customers get findings in **two places**, both reading the identical
`ScanSummary`:

- **In-repo dashboard** — the living "Argus security" issue on the default
  branch (above). Zero extra logins; for teams that live in GitHub it's the
  whole product.
- **Argus Portal** — the hosted, auth-protected dashboard for richer triage and
  cross-repo posture. The selling line "a dashboard for the technical and
  non-technical alike" is delivered here, as two coordinated lenses over the
  same data, not two products:

- **Executive lens (CISO / non-technical)** — org-wide posture at a glance:
  total open criticals/highs across all covered repos, trend over time
  (is the number going down?), worst-N repos, MTTR-style "how long has this
  critical been open," coverage (which repos are protected), and a one-click
  board-ready export (the provenance-bound PDF report from the Enterprise
  report add-on, served server-side here). No CVE jargon required to read it.

- **Engineer lens (technical)** — per-repo, per-finding triage: the existing
  filterable findings table, severity filters, scanner attribution, source
  context, SARIF/JSON export, scan-over-scan diff, and deep links to the exact
  file/line on GitHub. This is the OSS browser viewer, multi-tenant.

Both lenses are aggregation levels over the same pipeline. Portal access is
**tenant-scoped at the data layer**: a customer's users see only their org's
findings; Argus admins can see across tenants for support. No cross-tenant data
path exists in Portal queries.

---

## Trust & security model

This is a service that clones customer source code. The trust bar is the
product. Non-negotiables baked in from MVP:

- **Least-privilege GitHub App** — `contents: read` only; never code write.
  Short-lived installation tokens, minted per job, scoped to the single repo
  being scanned, expired immediately after.
- **Ephemeral, single-tenant workers** — one job per worker, no shared
  filesystem, source cloned to a tmpfs, worker destroyed after the run. Code is
  never written to durable storage; only findings + artifacts (SARIF, raw
  scanner output) are persisted.
- **Secret-safe findings** — Cloud inherits the SDK's secret redaction
  (`argus.core.redact` + the `Finding.__post_init__` pattern backstop). Matched
  secret literals are redacted before a finding is stored or rendered. A scan
  that *finds* a leaked key must not itself become a second copy of that key in
  our database. This gets an explicit ingest-time test.
- **Tenant isolation** — row-level isolation in the control plane; no cross-org
  data path in queries or the dashboard. Object storage keyed per tenant.
- **Provenance preserved** — every stored run is bound to the exact commit SHA
  and the cosign-verified scanner image digests that produced it (ADR-033/034
  provenance model), so the board-ready report stays attestable.
- **Data residency / self-host** — the default deployment is AWS multi-tenant;
  GHES and FedRAMP customers can run the same control plane + worker fleet
  single-tenant in their own AWS account (or on-prem), reusing the air-gapped
  registry override the SDK already supports and offline license verification.
  Vuln data is encrypted at rest (KMS) and tenant-scoped; only the customer's
  authorised users and Argus admins can read it. The OSS exit is always available.

---

## Licensing & pricing

Pricing is **not an engineering decision** — our contracting team sets it per
engagement. Engineering's job is to make the capability **licensable and
parameterised**, then offer the knobs. The model:

- **À la carte capabilities.** A customer licenses the Enterprise capabilities
  they want — Console, report, Cloud, or any mix. Each is gated by a license
  entitlement (same mechanism as the `report` entitlement today, ADR-034).
- **Per-seat *or* per-product, TBD.** Contracting decides the axis (and may
  blend them) per deal. The engine must support both: emit a live, auditable
  **seat count** (unique committers to covered repos) *and* track per-capability
  usage, so either basis can be invoiced.
- **All scanner categories included** within Cloud — no "pay more to unlock IaC
  scanning." The differentiation is scale/support/deployment, not which
  scanners run.
- **Positioned against** GitLab Ultimate / GHAS, justified by the OSS engine
  doing the heavy lifting and a single bundle — but the number is contracting's
  call.

The Cloud entitlement is special: it carries **embedded compute limits** (repo
scope + scan cadence) that the contract sets and the control plane enforces.
Licensing and compute control are the same mechanism — see below.

## Licensing & compute control (hard constraint)

> **We must not lose money on compute.** Cloud runs scanners on our
> infrastructure, so an unbounded license is an unbounded bill. Every Cloud
> entitlement is therefore **bounded by contract terms the control plane
> enforces server-side**. This is a gating requirement for the Cloud capability,
> not a Phase-3 nicety.

The license token for a Cloud entitlement encodes (and the control plane
enforces) at least:

- **Repo scope** — an explicit allowlist and/or a hard cap on covered repos.
  Selecting a repo beyond the licensed count is refused at onboarding, not
  silently billed. Org-wide coverage is a count ceiling, not "infinite."
- **Scan cadence** — how often a repo may trigger a hosted scan. A merge storm
  on a busy default branch must **not** fan out into one full multi-scanner run
  per merge. Enforced by:
  - **Debounce / coalescing** — collapse rapid merges into one scan per repo per
    window (e.g. one run per *N* minutes), scanning only the latest commit.
  - **Per-period run budget** — a contracted ceiling on runs per repo per
    day/month; beyond it, scans queue to the next window or require an explicit
    on-demand top-up. Always surfaced in the dashboard so it's never a surprise.
  - **Concurrency cap** — bounded simultaneous workers per tenant.
- **Scan scope / depth** — optional contract knobs: which scanner categories,
  size/time ceilings per run, and **change-scoped scanning** (re-run only the
  scanners whose inputs changed since the last scan) to keep the common case
  cheap.

Design implications that fall out of this:

- The control plane is the **enforcement point**, not the worker. Quota, scope,
  and cadence are checked *before* a job is enqueued; the worker only runs work
  that's already been authorised and budgeted.
- **Metering is first-class.** Every job records compute consumed (worker
  seconds, scanners run, image pulls) against the tenant's budget, so we can
  both enforce ceilings and reconcile cost-vs-price per account. This is the
  data contracting needs to price sustainably.
- The same enforcement powers **graceful degradation**: at the ceiling we
  queue/defer rather than fail, and prompt an upsell — never run unbudgeted
  compute, never hard-break the customer.

This makes the unit economics a *contract term* rather than a hope: a licensed
account can only ever cost us what its repo-count × cadence × scope ceilings
allow, and metering proves it.

---

## The license token

The license is the contract, made machine-readable. It is a **signed document**
(Ed25519 / cosign-style detached signature — the project already verifies cosign
signatures, so we reuse that trust root) that the control plane verifies
**offline**, with no phone-home. Two clean halves:

- **The license** — static, signed, immutable for its term. It states *what was
  bought*: which capabilities, and for Cloud, the **ceilings** (repo scope,
  cadence, scope/depth). Issued by Huntridge Labs contracting tooling when a deal
  is signed; re-issued on renewal or change order.
- **The runtime quota ledger** — mutable server-side state in the control plane.
  It tracks *what's been consumed* against those ceilings (runs this period,
  compute spent, seats seen). **Never** in the license — the license sets the
  limit, the ledger counts usage toward it.

A single license carries the customer's whole à la carte selection. Capabilities
are a list; only `cloud` carries a `quota` block (Console and report are plain
unlocks). Shape:

```jsonc
{
  "license": {
    "id": "lic_8f3c…",
    "schema": "argus.license/v1",
    "customer": { "org_id": "org_2a…", "name": "Acme Corp" },
    "issued_at": "2026-06-26T00:00:00Z",
    "not_before": "2026-07-01T00:00:00Z",
    "expires_at": "2027-07-01T00:00:00Z",
    "issuer": "huntridge-labs",

    // À la carte — the customer bought report + cloud, not console.
    "capabilities": [
      { "name": "report" },                       // plain unlock (local)
      {
        "name": "cloud",                            // the metered, hosted one
        "billing_basis": "per_seat",                // per_seat | per_product | blend
        "seat_cap": 250,                            // ceiling if per_seat
        "quota": {
          "repos": {
            "mode": "allowlist",                    // allowlist | count
            "allowlist": ["acme/api", "acme/web"],  // when mode=allowlist
            "max_repos": 25                          // hard cap (also bounds count mode)
          },
          "cadence": {
            "debounce_seconds": 600,                // coalesce merges within window
            "runs_per_repo_per_day": 24,
            "runs_per_repo_per_month": 400,
            "max_concurrent_workers": 4             // per tenant
          },
          "scope": {
            "scanner_categories": ["sast", "secrets", "deps", "iac", "container"],
            "change_scoped": true,                  // re-run only changed-input scanners
            "max_run_seconds": 1800,                // per-run wall-clock ceiling
            "max_repo_size_mb": 2048
          },
          "overage": {
            "policy": "defer",                      // defer | block | top_up
            "grace_runs": 5                          // soft buffer before policy bites
          }
        }
      }
    ]
  },
  // Signed by a Huntridge-held asymmetric key in AWS KMS (cosign KMS signer);
  // the private key never leaves KMS. Verified offline against the public key.
  "signature": { "alg": "ed25519", "key_id": "awskms:///argus-license-2026", "sig": "base64…" }
}
```

### Field reference (the Cloud `quota` block)

| Field | Enforces | Why it bounds cost |
|---|---|---|
| `repos.mode` / `allowlist` / `max_repos` | What may be covered | Caps the *breadth* of scanning; no surprise org-wide fan-out |
| `cadence.debounce_seconds` | Merge coalescing | A merge storm becomes one scan per window, not one per merge |
| `cadence.runs_per_repo_per_{day,month}` | Run budget | Hard ceiling on *frequency* — the core cost lever |
| `cadence.max_concurrent_workers` | Parallelism | Bounds peak spend and protects the fleet |
| `scope.scanner_categories` | Which scanners run | Fewer categories → cheaper runs |
| `scope.change_scoped` | Incremental scanning | The common merge re-runs only what changed |
| `scope.max_run_seconds` / `max_repo_size_mb` | Per-run ceilings | Caps the worst-case single run |
| `overage.policy` | Behaviour at the ceiling | `defer` queues, `block` refuses, `top_up` bills extra — never silent unbudgeted compute |

`billing_basis` + `seat_cap` are read by the metering/invoicing path, not the
quota gate — they decide *how we bill*, while `quota` decides *what we'll run*.

### Quota-check flow (control plane, per webhook)

Enforcement happens **before** a job is enqueued — the worker only ever runs
pre-authorised, pre-budgeted work:

```
push webhook
  │
  ├─ 1. verify license signature + not_before/expires_at        ─┐ reject → drop (license invalid/expired)
  ├─ 2. capability "cloud" present?                              ─┤ no    → drop (not licensed for Cloud)
  ├─ 3. event is a merge to the repo's DEFAULT branch?           ─┤ no    → drop (out of trigger scope)
  ├─ 4. repo ∈ allowlist / within max_repos?                     ─┤ no    → drop + surface "repo not covered"
  ├─ 5. debounce: a run for this repo within debounce_seconds?   ─┤ yes   → coalesce (replace pending w/ latest SHA)
  ├─ 6. ledger: runs_per_repo_per_{day,month} remaining?         ─┤ no    → apply overage.policy (defer | block | top_up)
  ├─ 7. ledger: tenant concurrency < max_concurrent_workers?     ─┤ no    → queue until a slot frees
  │
  └─ 8. ENQUEUE job (repo, SHA, scanner_categories, max_run_seconds, change_scoped)
         worker runs → on completion, METER (worker_seconds, scanners_run,
         image_pulls) and DECREMENT the period ledger; record run in results store
```

Every "drop"/"defer"/"queue" is reflected in the dashboard so the customer sees
*why* a scan didn't run and what the upsell is — never a silent gap. The ledger
counters reset on the period boundary; seat counts roll up continuously for the
billing path.

### Why this shape

- **Offline-verifiable, KMS-signed** — the signing key lives in AWS KMS under
  Huntridge control (issuance/revocation stay ours); the control plane verifies
  with the public key, so self-hosted / air-gapped (GHES, FedRAMP) deployments
  stay honest with no callback, and the signature stops tampering with the ceilings.
- **License ≠ ledger** is the critical split: the signed contract is immutable,
  consumption is mutable runtime state. Conflating them would mean re-signing on
  every scan.
- **One license, many capabilities** matches the à la carte model — Console-only,
  report-only, Cloud-only, or any mix, all in one signed document, all on the
  ADR-034 entitlement mechanism.
- **Numbers are contracting's, structure is engineering's** — the *fields* are
  fixed here; the *values* per plan are set per deal and informed by real
  metering from design partners.

---

## Scaling, availability & cost control

Many tenants × many repos × (merge events + scheduled baselines + on-demand) is
**spiky, highly-concurrent, bursty** load. Two goals pull against each other:
**high availability + high performance** (never drop a scan, keep the living
issue fresh) versus **never running a ridiculous cloud bill**. The per-tenant
license ceilings (above) are the *floor* — each account is bounded. This section
is the *fleet-level* machinery on top: scale to demand, stay multi-AZ, schedule
fairly, and cap *aggregate* spend with platform guardrails the per-tenant
license can't see.

### High availability
- **Multi-AZ by default.** The Ingest+API Fargate service runs across ≥2 AZs
  behind the ALB; SQS and S3 are regional managed services; **Aurora is multi-AZ**
  (writer + reader with automatic failover), or Aurora Serverless v2 for elastic
  capacity. No single-AZ point of failure.
- **Stateless compute.** API tasks and workers hold no durable state, so an AZ or
  task loss is absorbed by rescheduling. An in-flight scan whose worker dies is
  **redriven from SQS** (visibility timeout returns the message; a poison job
  lands in a **DLQ** after N attempts) — at-least-once execution, idempotent
  ingest keyed on `(repo, commit_sha, scan_config_hash)`.
- The latency-critical path (webhook → enqueue → issue update) must stay up even
  under worker saturation; ingest and issue-writing never block on scan capacity.

### Auto-scaling
- **Ingest + API** — target-tracking auto-scaling on request count / CPU.
- **Worker fleet** — scale on **SQS backlog**, the canonical pattern: a
  target-tracking policy on *backlog-per-running-task* adds tasks as the queue
  grows and **scales to zero when idle**, so we pay per task-second and nothing
  at rest. Runs on **Fargate**, with **Fargate Spot** as the default capacity
  (interruptible, redriven from SQS on reclaim) and on-demand Fargate as fallback.
- **Aurora Serverless v2** scales ACUs with load; read-heavy Portal/admin queries
  hit a reader endpoint.
- Concurrency is bounded at **two independent levels**: per-tenant
  (`max_concurrent_workers` from the license) and a **global platform ceiling**
  (below).

### Scheduling & fairness (the hard part)
Three demand sources contend for one shared worker pool, and naïve handling is
exactly how the bill explodes:

- **Smear scheduled scans.** Never fire every tenant's nightly baseline at
  00:00. Assign each repo a **deterministic jittered slot** across its cadence
  window (hash the repo id into the window) so scheduled load is a flat plateau,
  not a midnight spike. This alone removes the worst thundering herd.
- **Fairness across tenants.** One large customer must not starve everyone else.
  On top of per-tenant concurrency caps, dispatch is **fair-shared** — per-tenant
  queue shards (or weighted round-robin) over the global pool, so a tenant at its
  cap backs off while others proceed. No single tenant monopolises the fleet.
- **Priority lanes.** Merge-triggered scans are latency-sensitive (the in-repo
  issue should update quickly); scheduled and on-demand scans are not. **Merge
  scans dispatch ahead of scheduled/on-demand backlog** via separate priority
  lanes, so a scheduled-scan surge never delays the thing a developer is waiting
  on.

### On-demand scanning — offer it, but budgeted
**Recommendation: yes, offer "scan now" — but never as an unmetered button.**
Customers expect it and it's a differentiator, yet it's also the least
predictable cost driver. Made safe by treating it as just another governed job:

- it **debits the same per-period run budget** (or a small separate on-demand
  allowance with `top_up`), so it can't exceed what's licensed;
- it's **rate-limited** per repo (cooldown) and per user;
- it runs in the **low-priority lane** — it never preempts merge scans;
- it's subject to the **global concurrency ceiling** like everything else.

If an account is out of budget, "scan now" prompts a top-up instead of running
free. **Decision: on-demand ships at MVP** — because it's budget-debited, rate-
limited, and low-priority, it carries no more cost risk than a scheduled scan,
so there's no reason to hold it back.

### Platform cost guardrails (the circuit breaker)
Per-tenant ceilings bound each *account*; these bound the *aggregate*, so even if
every tenant maxes out at once we can't be surprised by the bill:

| Guardrail | What it does |
|---|---|
| **Global concurrency ceiling** | Hard cap on total simultaneous workers fleet-wide, independent of summed per-tenant allowances. At the cap, new jobs queue (merge first). The master cost valve. |
| **Fargate Spot + scale-to-zero** | Interruptible cheap capacity, redriven on reclaim; pay only per task-second, nothing idle. |
| **Cheap-by-default runs** | Change-scoped scanning, shallow clone, scanner-DB cache reuse (the SDK already mounts cache volumes), task right-sized to the scanner set. |
| **Spend observability** | Per-tenant cost attribution via resource tagging; AWS Budgets + Cost Anomaly Detection alarms feeding the admin console; the metering ledger reconciles compute-vs-price per account to catch a money-losing account early. |
| **Backpressure / graceful degradation** | If a budget alarm or the global ceiling trips, defer scheduled + on-demand work and keep merge scans flowing — never silently overspend, never hard-break the latency-critical path. State is visible in the admin console. |

Net: cost has **two independent floors of protection** — the per-tenant license
ceiling *and* the platform-global ceiling — plus Spot and scale-to-zero to make
the common case cheap. Performance comes from autoscaling on real backlog and
priority lanes; availability from multi-AZ, stateless compute, and SQS redrive.

---

## Phased delivery

### Phase 0 — Foundations (de-risk the boundary)
- GitHub App registration, OAuth sign-in, webhook receiver (API GW → Fargate)
  that correctly identifies default-branch merges on a covered repo.
- Core AWS scaffolding: VPC, Aurora PostgreSQL, S3 (per-tenant prefix), ECR with
  the cosign-signed Argus worker image, SQS.
- A single Fargate worker task: given a repo + token, shallow-clone, `argus scan`,
  produce `argus-results.json`, store it. No UI yet.
- KMS signing key + a minimal license issuer; the API verifies a license offline.
- Tenant data model (orgs, installations, repos, runs, findings) with row-level
  isolation. **Exit criteria:** a webhook drives an end-to-end Fargate scan, the
  result is queryable and tenant-isolated, and an invalid license is refused.

### Phase 1 — Private MVP
- Self-serve onboarding: attach app → pick org/repos → baseline scan.
- **License-enforced repo scope + scan cadence from day one** — repo allowlist/cap,
  debounce/coalescing, per-period run budget, concurrency cap, all enforced in
  the control plane *before* a job is enqueued. Compute control is not deferrable;
  an MVP that can run unbounded scans is not shippable.
- Cadence scheduler with **jittered slots** (scheduled baselines smeared across
  the window, not only on-merge), same quota.
- Per-job compute metering (worker seconds, scanners run) against the tenant budget.
- **Argus Portal** (engineer lens) with Cognito auth — GitHub + username/password
  login at MVP — tenant-scoped at the data layer.
- Living findings issue + check-run summary on the default branch (the in-repo dashboard).
- Worker fleet **autoscaling on SQS backlog** (scale-to-zero, Fargate Spot),
  capped per tenant *and* by a **global concurrency ceiling**; multi-AZ +
  SQS-redrive/DLQ from day one.
- Priority lanes (merge ahead of scheduled/on-demand) so a surge never delays a merge scan.
- **On-demand "scan now"** — budget-debited, rate-limited, low-priority (ships at MVP).
- **Minimal admin control surface** — the global concurrency ceiling and per-tenant
  throttle/pause/kill are tunable from day one (full admin console lands at GA),
  since the ceiling and on-demand are live at MVP and must be operable.
- Secret-redaction ingest tests; tenant-isolation tests.
- **Exit criteria:** a design-partner CISO onboards unaided and sees findings
  (in-repo + Portal) with no CI config; a merge storm cannot exceed the licensed
  run budget; and concurrent load across all tenants cannot exceed the global ceiling.

### Phase 2 — GA
- Billing wired to the license entitlements + metering; per-seat and
  per-product invoicing bases both supported (contracting picks per deal).
- Portal executive lens + board-ready PDF export (server-side, via the report capability).
- Trends across repos and over time; org-wide posture.
- **Admin console (Huntridge ops)** — fleet/cluster health, live activity, deployed
  Argus version, customers/repos/seats, compute-vs-budget per account.
- Per-tenant org SSO (SAML/OIDC federation in the Cognito pool), audit log,
  RBAC (customer admin / viewer; Argus admin).
- License lifecycle: renewal, change orders, revocation from the issuer.
- **Fair-share dispatch** (per-tenant queue shards / weighted) so no tenant
  starves others; cost-attribution tagging + AWS Budgets / anomaly alarms wired
  into the admin console.
- **Full admin console** — observability + the live performance/cost control
  surface (global ceiling, lane/fair-share weights, jitter window, Spot mix,
  alarm thresholds, per-tenant overrides), all tunable without redeploy and
  audit-logged.
- **Exit criteria:** a stranger can sign up, pay, and self-onboard; Huntridge can
  observe and retune the fleet from the admin console; one tenant's burst cannot
  starve another's merge scans.

### Phase 3 — Scale & breadth
- **Agentic patches & hardening suggestions via PR** — opt-in, gated behind a
  dedicated capability that escalates the App to `pull_requests: write` /
  `contents: write` only for consenting repos. Argus proposes fix PRs and
  hardening changes off the findings; the customer reviews and merges. This is
  the SDK's "does_not_solve: remediation" frontier, delivered as suggestion not
  silent change.
- Self-hosted / air-gapped single-tenant deployment for GHES + FedRAMP (same
  code; offline license verification already supports it).
- More VCS providers (GitLab, Bitbucket) behind the same control plane.
- PR-time scanning (not just default-branch) as an opt-in.

---

## Open questions / risks

Compute-cost-vs-price is **no longer an open risk** — it's handled by the
license-enforced repo scope + cadence + metering above. What remains open:

- **Exact ceiling defaults** — the *mechanism* (allowlist, debounce, run budget,
  concurrency cap) is fixed; the default numbers per plan are a contracting
  input informed by real metering data from design partners.
- **Seat vs. product as the invoicing basis** — engineering supports both; which
  one (or blend) ships first is a go-to-market call. The seat metric ("unique
  committer") must be countable from the GitHub App's data without surprising
  customers — pin the definition before any per-seat deal.
- **Change-scoped scanning fidelity** — re-running only the scanners whose inputs
  changed is the biggest cost lever; needs a reliable input-fingerprint per
  scanner so we don't silently skip a scanner that *should* have re-run.
- **Global concurrency ceiling default** — *resolved as a mechanism:* the valve
  exists from MVP and is **operator-tunable live from the admin console** (no
  redeploy). Its starting value remains a cost-vs-latency judgement to set against
  real fleet metering (too low and scheduled scans lag; too high and a bad day
  costs us) — but it's a dial, not a code constant. (On-demand-at-MVP and the
  admin-console-as-control-surface questions are now decided — see Phasing.)
- **Default-branch-only is the wedge, not the ceiling** — start there because
  it's the simplest promise and the cleanest dashboard story; PR-time is Phase
  3, not MVP, to avoid scope creep.
- **Where the engine runs in self-hosted mode** — the control plane is
  multi-tenant SaaS, but GHES/FedRAMP need single-tenant. Keep worker and
  control plane separable so the same code serves both. (Self-hosted shifts the
  compute to the customer, so the cadence ceilings become protective of *their*
  infra rather than ours — same mechanism, different beneficiary.)
- **Liability of cloning customer code** — legal + security review of the data
  handling, retention, and incident model before any non-design-partner
  customer. The trust model above is the engineering input to that review.
- **Pricing numbers** — contracting's decision; out of scope for this doc.

---

## What this does *not* change

- The OSS SDK stays AGPL-3.0 and fully self-hostable. Cloud is a delivery
  model, not a fork — all scanning logic remains in `argus/`.
- Cloud is a **capability of Argus Enterprise**, gated by the same license
  entitlement mechanism as the existing Console and report capabilities
  (ADR-034). It *consumes* the report capability server-side (for the
  board-ready PDF) rather than replacing it. The local capabilities are
  unaffected.
- Customers license **only what they want** — Cloud does not bundle in Console
  or report unless they're separately licensed.
- The "you can always run it yourself" exit is permanent and is part of the
  pitch.

See [`.ai/decisions.yaml`](../../.ai/decisions.yaml) **ADR-035** for the
recorded decision and the tier boundary.
