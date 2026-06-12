"""Compliance assets — control mappings and OSCAL schemas.

Data-only package. The YAML files under ``mappings/`` and the OSCAL JSON
schemas under ``schemas/`` are read at runtime by
[argus.core.control_mapping](argus/core/control_mapping.py) and the
[OscalReporter](argus/reporters/oscal.py). Shipped inside the wheel via
``[tool.setuptools.package-data]`` in ``pyproject.toml``.
"""
