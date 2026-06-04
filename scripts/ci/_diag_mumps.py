"""TEMP diagnostic: dump MUMPS security findings for the grammar at
``ARGUS_MUMPS_GRAMMAR``. Used to prove a build-dependent parse divergence
on the GitHub runner (golden guard sees M005:2/M007:1 there; 4/2 everywhere
else). Remove once the grammar-build fix lands.
"""

import os
from collections import Counter

from argus.scanners.mumps.parser import MumpsParser
from argus.scanners.mumps.scanner import MumpsScanner

print(f"  grammar = {os.environ.get('ARGUS_MUMPS_GRAMMAR', '(default probe)')}")
result = MumpsScanner().scan("argus/tests/scanners/mumps/fixtures", {})
counts = {k: v for k, v in Counter(f.id for f in result.findings).items() if k[:2] == "M0"}
print("  COUNTS:", dict(sorted(counts.items())))
for rule_id in ("M005", "M007"):
    locations = sorted(f.location for f in result.findings if f.id == rule_id)
    print(f"  {rule_id}: {locations}")

# Show how the runner tokenizes the M007 fixture that should yield 2 hits.
try:
    fixture = "argus/tests/scanners/mumps/fixtures/m007_code_load.m"
    with open(fixture, "rb") as fh:
        parsed = MumpsParser.parse(fixture, fh.read())
    print("  m007 tree:", parsed.tree.root_node.sexp()[:600])
except Exception as exc:  # noqa: BLE001 - diagnostic only
    print(f"  (tree dump unavailable: {type(exc).__name__}: {exc})")
