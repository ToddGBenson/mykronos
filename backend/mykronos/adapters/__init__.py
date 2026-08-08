"""Normalization adapters (spec 04 §4).

One per (capability, tool) pair, turning tool-native output into
`FindingSubmission` records.

These live inside the backend package rather than a top-level `adapters/`
directory as sketched in spec 04 §4, so that the adapter and the schema it
targets have one definition. The composite action installs the package in CI;
a separate copy of `FindingSubmission` that could drift from the server's
would be a worse trade than the directory layout.
"""

from mykronos.adapters.base import AdapterResult, ScanContext
from mykronos.adapters.registry import (
    REGISTRY,
    get_adapter,
    normalize_results,
    supported_tools,
)
from mykronos.adapters.sarif import sarif_to_findings, severity_from_security_score
from mykronos.adapters.snippet import best_snippet, infer_symbol, slice_snippet

__all__ = [
    "REGISTRY",
    "AdapterResult",
    "ScanContext",
    "best_snippet",
    "get_adapter",
    "infer_symbol",
    "normalize_results",
    "sarif_to_findings",
    "severity_from_security_score",
    "slice_snippet",
    "supported_tools",
]
