# Argus MCP Server

The Argus MCP server exposes Argus's security-scanning capabilities to AI assistants over the [Model Context Protocol](https://modelcontextprotocol.io/). Tools like Claude Desktop, Claude Code, Cursor, Continue, and Cline can run scans, validate configs, classify IaC changes, and explain findings — without leaving the chat.

The server speaks JSON-RPC over stdin/stdout (the standard MCP `stdio` transport). It's built on top of the same Argus SDK the CLI uses, so anything the CLI can do, an AI assistant can request.

---

## Quick start

You have two install paths. Pick based on whether you want Argus on your `$PATH` for direct CLI use too.

### Option A — `uvx` (zero-install, recommended for AI-tool-only users)

[`uvx`](https://docs.astral.sh/uv/guides/tools/) downloads the package on demand and runs the entry point. Nothing lands in your global Python.

```bash
uvx --from 'argus-security[mcp]' argus mcp
```

This is the right answer for people who don't otherwise use Argus from the terminal — you point your AI client at this command and that's the entire install. `uv` caches the package, so subsequent runs start in milliseconds.

### Option B — `pip install` (recommended if you also use the Argus CLI)

```bash
pip install 'argus-security[mcp]'
```

After this, `argus mcp` is on your `$PATH` and your AI client just needs to launch it. You also get the rest of the Argus CLI for free (`argus scan`, `argus view terminal`, `argus view browser`, etc.).

### Confirming it works

Run the server directly in a terminal:

```bash
argus mcp     # or: uvx --from 'argus-security[mcp]' argus mcp
```

You should see (on stderr):

```
argus MCP server starting on stdio transport — awaiting client messages...

  This is correct behavior. The server reads JSON-RPC messages from
  stdin and writes responses to stdout — that's how MCP clients
  (Claude Desktop, Cursor, Claude Code, etc.) talk to it.

  Configure your client to launch:  argus mcp
  Press Ctrl+C to exit.
```

`Ctrl+C` exits cleanly. The server is now ready to be wired into a client.

---

## Configure your AI client

Pick the section that matches your tool. Each example uses Option B (`pip install`); swap `"command": "argus"` for `"command": "uvx", "args": ["--from", "argus-security[mcp]", "argus", "mcp"]` if you went the `uvx` route.

### Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "argus": {
      "command": "argus",
      "args": ["mcp"]
    }
  }
}
```

Restart Claude Desktop. Argus's tools appear in the tool picker.

### Claude Code

Edit `.claude/settings.json` in your repo (or `~/.claude/settings.json` for global):

```json
{
  "mcpServers": {
    "argus": {
      "command": "argus",
      "args": ["mcp"]
    }
  }
}
```

Or use the CLI:

```bash
claude mcp add argus argus mcp
```

### Cursor

Open *Cursor Settings → MCP → Add new MCP server*, or edit `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "argus": {
      "command": "argus",
      "args": ["mcp"]
    }
  }
}
```

### Continue (VS Code)

Edit `~/.continue/config.json`:

```json
{
  "experimental": {
    "modelContextProtocolServers": [
      {
        "name": "argus",
        "transport": {
          "type": "stdio",
          "command": "argus",
          "args": ["mcp"]
        }
      }
    ]
  }
}
```

### Cline (VS Code)

Edit `~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json` (macOS path):

```json
{
  "mcpServers": {
    "argus": {
      "command": "argus",
      "args": ["mcp"]
    }
  }
}
```

### Generic stdio MCP client

Any client that supports the standard MCP stdio transport accepts the same shape:

```json
{
  "command": "argus",
  "args": ["mcp"]
}
```

---

## What the server provides

### Tools

| Tool | What it does |
|---|---|
| `argus_security_review` | **Recommended entry point** for natural-language posture queries ("is this repo secure?", "what should I fix?"). One call: detect → fresh-scan-or-cached-with-age → stable JSON envelope. |
| `argus_detect` | Inspect a project and report scanner-relevant signals (languages, package files, IaC, etc.) |
| `argus_init` | Generate a tailored `argus.yml` for the project |
| `argus_validate` | Check whether an existing `argus.yml` is valid |
| `argus_list_scanners` | List every scanner the SDK knows about, grouped by category |
| `argus_scan` | Run a scan (specify scanners or auto-detect) |
| `argus_scan_summary` | Quick check of the latest scan results without re-scanning. Returns `cache_age_seconds` so callers can decide whether to trust the snapshot. |
| `argus_explain_finding` | Get remediation guidance for a specific finding |
| `argus_classify` | Classify IaC changes between two git refs for compliance review |

**Cache freshness**: both `argus_scan_summary` and the `argus://results/latest` resource report `cache_age_seconds` and `cached_at`. Results older than 24 hours are flagged with a `freshness_warning` field. Treat stale results as a cue to re-run `argus_scan` rather than answering posture questions from a 9-day-old snapshot.

### Resources

The MCP client can read these directly without invoking a tool:

| URI | Contents |
|---|---|
| `argus://config` | The current `argus.yml` (rendered as JSON) |
| `argus://results/latest` | The most recent scan results from `argus-results/` |
| `argus://config/schema` | The full JSON schema for `argus.yml` |

### Prompts

| Prompt | Use when... |
|---|---|
| `security_review` | You want a comprehensive review: detect → scan → explain critical/high findings → summarize posture |
| `fix_findings` | You want the AI to apply fixes for the latest scan's findings |
| `setup_scanning` | You're onboarding a new project — detect → init → validate → baseline scan |

---

## Secrets handling

Argus's commitment: a secret value detected by a scanner **never** leaves the parser. The MCP server returns scan results to AI clients, which means anything carried in those results travels through your assistant's API call to a third-party LLM provider — exactly where you don't want a credential. We block the leak at the source instead of trying to scrub it downstream.

**How it works:**

- Each scanner that detects credential-shaped content audits its own output and replaces secret-bearing fields with the literal `<redacted>` placeholder before the `Finding` is constructed.
- The scrubbed `Finding` is what every consumer sees: terminal output, JSON / Markdown / SARIF exports, the MCP tool responses, and the AI assistant's context window. There's no path that reaches a raw secret.
- A small fixed-string placeholder is used deliberately. Length-preserving masks (`ghp_***...12`) leak entropy and the first-prefix sniff (`ghp_` etc.) duplicates information already in `rule_id`. Position-bearing fields (`file:line:col`, scanner-emitted `fingerprint`) are kept because they're enough for a developer to find the right line and rotate the credential.

**What gets redacted:**

| Scanner | Redacted | Kept |
|---|---|---|
| **gitleaks** | `Match`, `Secret`, `Author` (PII), `Email` (PII), `Date`, `Message` | `RuleID`, `Commit` (SHA, public), `Fingerprint`, `match_length` (integer for diagnostics), line/col |
| **bandit** B105 / B106 / B107 (hardcoded-credential checks) | `issue_text` literal value (regex-stripped between quotes), `code` excerpt (replaced wholesale with `<redacted>`) | `test_name`, `more_info` URL, location, CWE, severity |
| **bandit** other tests | nothing — code excerpts are valuable triage signal | everything bandit emits |

**Adding a new scanner — audit checklist:**

When you wire up a new scanner module under `argus/scanners/`, run through this before merging:

1. Does the raw output contain matched literals from source code?
2. If yes: which JSON / output fields carry that content? Document them in the parser's docstring.
3. Drop or `redact_secret(...)` those fields before building the `Finding`. Helpers: `argus.core.redact.redact_secret(value)` returns the placeholder; `redact_secret_in_message(msg, value)` substring-replaces the literal in human-readable strings.
4. Add a test that loads a representative fixture and asserts the original literal does not appear anywhere in the `Finding.to_dict()` JSON dump (see `argus/tests/scanners/test_gitleaks.py` `TestGitleaksRedaction` for the pattern).
5. Note the redaction policy in the scanner's module docstring so future maintainers don't accidentally re-add the leak.

**Defense-in-depth pattern-pass safety net:** ✅ shipped. `Finding.__post_init__` now runs every text field (`title`, `description`, every string value in `metadata`) through `argus.core.redact.redact_high_risk_patterns` before the constructor returns. Patterns are conservative and vendor-prefixed only — GitHub PATs (`gh[opusr]_<36>`), AWS access keys (`AKIA…`/`ASIA…`), Slack tokens (`xox[abprs]-…`), GitLab PATs (`glpat-…`), npm publish tokens, Google API keys (`AIza…`), Stripe live keys (`sk_live_…`), JWTs (`eyJ.…eyJ.….…`), and PEM private-key headers. Generic high-entropy heuristics are deliberately excluded (false-positive rate on legitimate finding bodies is too high). Rationale + boundary rule: [`.ai/decisions.yaml` ADR-022](../.ai/decisions.yaml). The per-scanner first pass remains the primary defense; this catches new scanners that get added without the audit.

---

## Discovery and registry listings

The Argus MCP server is distributed as part of the [`argus-security` PyPI package](https://pypi.org/project/argus-security/). Listings in community MCP server catalogs make it easier for AI-tool users to find it without needing to read the Argus repo first.

### Where Argus is listed

| Registry | Listed | Submission flow |
|---|---|---|
| [`modelcontextprotocol/servers`](https://github.com/modelcontextprotocol/servers) | _pending — open a PR adding Argus to the **Community Servers** section of `README.md`_ | Pull request to the official Anthropic-maintained list |
| [`punkpeye/awesome-mcp-servers`](https://github.com/punkpeye/awesome-mcp-servers) | _pending — open a PR adding Argus to the **Security** section_ | Pull request to the community awesome-list |
| [mcp.so](https://mcp.so/) | _pending_ | [Submit form](https://mcp.so/submit) |
| [Smithery](https://smithery.ai/) | _pending_ | [Submit at smithery.ai](https://smithery.ai/) (auto-detects npm packages; manual submission for PyPI servers) |
| [Glama](https://glama.ai/mcp/servers) | _pending_ | Auto-discovers servers from public GitHub repos with the `mcp-server` topic + `MCP` mention in README |

_Update this table when each submission lands. The `_pending_` rows are tracked in [`docs/developer/SDK-ROADMAP.md`](developer/SDK-ROADMAP.md#mcp-registry-submissions)._

### How to submit Argus to a new registry

1. Confirm the package metadata is current — `pyproject.toml` description, classifiers, `Repository`/`Documentation` URLs.
2. Confirm the README's **MCP Server** section accurately describes what the server does.
3. Most catalogs want:
   - Server name: `argus`
   - Install command: `pip install 'argus-security[mcp]'` or `uvx --from 'argus-security[mcp]' argus mcp`
   - Launch command: `argus mcp`
   - Tools list: see *What the server provides → Tools* above
   - Categories/tags: `security`, `vulnerability-scanning`, `sast`, `iac`, `sca`, `secrets`, `dast`
   - Author: Huntridge Labs
   - License: Apache-2.0
4. File the PR / form. Reference [PR #97](https://github.com/huntridge-labs/argus/pull/97) and earlier MCP work for the canonical implementation history.

---

## Troubleshooting

**"command not found: argus"** — your shell isn't pointing at the venv that has Argus. Either re-activate (`deactivate && source .venv/bin/activate && hash -r`), call `.venv/bin/argus` explicitly, or switch to the `uvx` path which doesn't depend on `$PATH`.

**The terminal goes silent when I run `argus mcp` directly** — that's expected behavior; the server is awaiting JSON-RPC messages on stdin from a client. Argus 0.7.2+ logs a banner to stderr explaining this. Press `Ctrl+C` to exit.

**Client says "spawn argus ENOENT"** — the client can't find the `argus` binary. Either give the absolute path (`/full/path/to/.venv/bin/argus`) or switch to the `uvx` invocation.

**`ImportError: Using SOCKS proxy, but the 'socksio' package is not installed`** — your shell has `ALL_PROXY` or `HTTPS_PROXY` set to `socks5://`. Install the SOCKS extras: `pip install 'httpx[socks]'`. The `[ai]` extra already pins this since 0.7.2, so `pip install 'argus-security[ai]'` covers it too.

**Stale tool definitions in the client** — most clients cache MCP tool schemas. Restart the client (or use its "reload MCP servers" command) after upgrading Argus or changing your config.

**The MCP server starts but tools aren't appearing in the client** — confirm the server is actually being launched. Most clients log subprocess stderr; you should see the `argus MCP server starting...` banner. If you don't, the client either isn't running the command at all (typically a config-path issue) or is running it with a different working directory than expected.

---

## See also

- [`docs/cli-reference.md`](cli-reference.md) — full CLI reference including `argus mcp` subcommand options
- [`README.md` → MCP Server section](../README.md#mcp-server-ai-integration) — the elevator-pitch summary
- [Model Context Protocol specification](https://modelcontextprotocol.io/) — the underlying protocol
- [`argus/mcp.py`](../argus/mcp.py) — the server implementation
