"""Compute the `--deep would also check ...` hint shown after a clean
schema validation. Pure config inspection — no I/O, no Docker calls.

The hint is only printed when the config contains options that `--deep`
would actually exercise, so it stays out of the way for users running
plain `argus validate` on a minimal config.
"""

from __future__ import annotations


def compute_deep_hints(config_data: dict) -> list[str]:
    """Return one short hint line per config feature `--deep` would
    validate. Empty list means no hint is shown — the config has
    nothing extra for `--deep` to exercise.
    """
    hints: list[str] = []

    execution = config_data.get("execution") or {}
    if isinstance(execution, dict):
        registry = execution.get("registry")
        if isinstance(registry, str) and registry:
            hints.append(f"execution.registry set ({registry}) — verify the mirror resolves")

        registry_map = execution.get("registry_map")
        if isinstance(registry_map, dict) and registry_map:
            hints.append(
                f"{len(registry_map)} entries in execution.registry_map — "
                "verify each upstream mirror responds"
            )

    containers = config_data.get("containers")
    if isinstance(containers, dict):
        images = containers.get("images") or []
        if isinstance(images, list) and images:
            hints.append(
                f"{len(images)} container image(s) in containers.images — "
                "verify each manifest resolves (with any registry rewriting applied)"
            )

        search_paths = containers.get("search_paths") or []
        if isinstance(search_paths, list) and search_paths:
            hints.append(
                f"{len(search_paths)} entries in containers.search_paths — "
                "verify each directory exists on disk"
            )

        c_out = containers.get("output_dir")
        if isinstance(c_out, str) and c_out:
            hints.append(f"containers.output_dir '{c_out}' — verify writability before scan")

    reporting = config_data.get("reporting")
    if isinstance(reporting, dict):
        r_out = reporting.get("output_dir")
        if isinstance(r_out, str) and r_out:
            hints.append(f"reporting.output_dir '{r_out}' — verify writability before scan")

    return hints
