# hello-plugin — a reference Argus plugin

A minimal plugin that demonstrates the `argus.plugin.v1` contract: it scans the
target for TODO/FIXME markers and reports them as findings. Use it as a template.

See [`docs/plugin-sandbox.md`](../../../docs/plugin-sandbox.md) for the full
contract, threat model, and sandbox guarantees.

## The contract

A plugin is a container image that:

1. Reads the scan target, mounted **read-only at `/scan`** (the workdir).
2. Writes a single JSON document to **stdout**:

   ```json
   {
     "schema": "argus.plugin.v1",
     "findings": [
       {"id": "...", "severity": "high|medium|low|info",
        "title": "...", "description": "...",
        "location": "relative/path.py:42", "cwe": "CWE-89", "cve": "CVE-..."}
     ]
   }
   ```

Only `severity` and one of `id`/`title` are meaningful minimums; unknown
severities are coerced to `unknown`, and `location` must be **relative** (absolute
paths and `..` are dropped by Argus as untrusted).

## How Argus runs it (you don't have to)

Argus executes the image in a locked-down sandbox — no network, read-only root
filesystem, all capabilities dropped, non-root, resource-limited, with the target
mounted read-only. Your plugin therefore must not need network, writable disk
(a `tmpfs` is available at `/tmp`), or root.

## Build & try locally

```bash
docker build -t hello-plugin:dev examples/plugins/hello-plugin
# Simulate the sandbox invocation Argus would use:
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --user 65534:65534 \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m -v "$PWD:/scan:ro" \
  hello-plugin:dev
```

In production, pin the image by digest and have Huntridge sign/verify it — see
the trust tiers in the threat model.
