# Contributing a Reporter Plugin

Argus reporters consume a `ScanSummary` and emit output in some format —
terminal text, a markdown file, a SARIF artifact, an HTTP webhook, a
Slack message, a PagerDuty incident, whatever you want. The
**reporter plugin system** lets you ship a reporter as a separate
Python package and have it light up under `argus scan --format <name>`
without forking Argus or shipping changes to `argus/reporters/`.

This guide walks through publishing a third-party reporter.

## What a reporter looks like

A reporter is any class that implements the `Reporter` protocol from
`argus.reporters`:

```python
from pathlib import Path
from typing import Optional

from argus.core.models import ScanSummary


class SlackReporter:
    """Post scan results to a Slack channel via webhook."""

    def report(self, summary: ScanSummary, output_dir: Optional[Path] = None) -> None:
        # The summary is a fully-populated ScanSummary — see
        # ``argus.core.models`` for the dataclass shape. ``output_dir``
        # is hint from the caller; reporters that don't write files can
        # ignore it.
        webhook = os.environ["SLACK_WEBHOOK_URL"]
        payload = self._format(summary)
        requests.post(webhook, json=payload, timeout=10)
```

Requirements:

* The class must be **constructible with no arguments**. Argus
  instantiates it via `Cls()` after entry-point resolution.
* The class must define **`.report(summary, output_dir=None)`**. The
  return value is ignored by `argus scan` but may be useful when
  consumers reach for the reporter programmatically.
* If your reporter writes files, honor `output_dir` (a
  `pathlib.Path`). Built-in reporters fall back to `./argus-results`
  when it's `None`.

That's the entire contract. There's no base class to subclass, no
required imports beyond the dataclass types you choose to consume.

## Publishing it as a plugin

1. **Create your package**. A minimal `pyproject.toml`:

   ```toml
   [build-system]
   requires = ["setuptools>=69"]
   build-backend = "setuptools.build_meta"

   [project]
   name = "argus-reporter-slack"
   version = "0.1.0"
   description = "Slack reporter for Argus security scans"
   requires-python = ">=3.11"
   dependencies = [
       "argus-security>=0.7",
       "requests>=2.31",
   ]

   [project.entry-points."argus.reporters"]
   slack = "argus_reporter_slack:SlackReporter"
   ```

   The key line is the entry-point block. The group name **must** be
   `argus.reporters`. The left-hand side (`slack`) is the name users
   pass to `--format`; the right-hand side (`argus_reporter_slack:SlackReporter`)
   is the import path of your class.

2. **Lay out your code.** A typical layout:

   ```text
   argus-reporter-slack/
   ├── pyproject.toml
   ├── src/argus_reporter_slack/__init__.py    # exports SlackReporter
   └── tests/test_slack_reporter.py
   ```

3. **Install + test.** From your project root:

   ```bash
   pip install -e .
   pip install argus-security
   argus scan --format slack --path /some/repo
   ```

   The first scan emits a Slack message. If the entry-point isn't
   discovered, double-check that `pip show argus-reporter-slack` lists
   the entry-point group `argus.reporters`.

4. **Publish.** Standard PyPI workflow (`python -m build`, `twine upload`,
   etc.). Once installed alongside `argus-security`, your reporter is
   live.

## Naming guidance

* **Don't shadow built-ins.** The built-in names are `terminal`,
  `markdown`, `container_markdown`, `sarif`, `json`, `github`,
  `gitlab`, `junit`. Even if you declare an entry-point with one of
  these names, the built-in always wins and a warning is logged at
  runtime — you'll just get a confusing user experience.
* **Pick a short, lowercase, dash-or-underscore name** that reads well
  on the CLI: `argus scan --format slack`, `argus scan --format pagerduty`,
  `argus scan --format newrelic`.
* **Convention for the distribution name:** `argus-reporter-<name>`.
  This makes it greppable on PyPI and discoverable by users searching
  for Argus reporters.

## Failure semantics

Argus is defensive about plugins on the principle that one broken
third-party package must not break `argus list` or `argus scan` for
users who have other reporters installed.

* **Import errors are logged at WARNING and skipped.** If your module
  raises `ImportError` on load, your reporter is unavailable but other
  reporters still work.
* **Construction failures are logged and skipped.** A class whose
  `__init__` raises is treated as if it weren't installed.
* **Protocol mismatches are logged and skipped.** A class without a
  `.report(summary, output_dir=None)` method is rejected.

If you suspect your plugin isn't being picked up, run with
`PYTHONLOGLEVEL=DEBUG` (or `argus scan --debug`) to see the loader's
diagnostics.

## Reference

* `argus/reporters/__init__.py` — the loader and the `Reporter` protocol.
* `argus/core/models.py` — `ScanSummary`, `ScanResult`, `Finding`,
  and the `Severity` enum.
* The seven built-in reporters in `argus/reporters/` — drop-in
  examples covering CLI emit, file writing, JSON serialization, SARIF
  output, and CI annotation formats.
* `.ai/decisions.yaml` — ADR-023 documents why we use Python
  entry-points (rather than a config-file scan or env-var-driven
  loader), why first-wins on collision, and why failures are silent
  except in the log.
