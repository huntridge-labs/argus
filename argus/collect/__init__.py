"""Log collection and artifact aggregation for multi-job CI runs."""

from .collector import collect_results
from .merger import merge_manifests, merge_logs

__all__ = [
    "collect_results",
    "merge_manifests",
    "merge_logs",
]
