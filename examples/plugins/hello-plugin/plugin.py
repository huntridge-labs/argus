#!/usr/bin/env python3
"""Reference Argus plugin — emits an ``argus.plugin.v1`` document on stdout.

Trivial demonstration of the plugin contract: walk the read-only scan target at
``/scan`` and report TODO/FIXME/XXX markers as INFO findings. Real plugins do
something useful; this shows the I/O contract and that a plugin needs no host
access beyond ``/scan`` (read-only) and stdout.

Runs under the Argus plugin sandbox: no network, read-only root filesystem,
non-root (nobody), all capabilities dropped. See docs/plugin-sandbox.md.
"""

import json
import os
import re

SCAN_ROOT = "/scan"
_MARKER = re.compile(r"\b(TODO|FIXME|XXX)\b")


def main() -> None:
    findings = []
    for root, _dirs, files in os.walk(SCAN_ROOT):
        for name in files:
            path = os.path.join(root, name)
            try:
                with open(path, encoding="utf-8", errors="ignore") as handle:
                    for lineno, line in enumerate(handle, start=1):
                        if _MARKER.search(line):
                            rel = os.path.relpath(path, SCAN_ROOT)
                            findings.append(
                                {
                                    "id": f"hello-{rel}-{lineno}",
                                    "severity": "info",
                                    "title": "TODO/FIXME marker",
                                    "description": line.strip()[:200],
                                    "location": f"{rel}:{lineno}",
                                }
                            )
            except OSError:
                continue
    print(json.dumps({"schema": "argus.plugin.v1", "findings": findings}))


if __name__ == "__main__":
    main()
