"""Patchwork — auto-remediation (spec 08).

Opens draft pull requests. Never merges: the GitHub client it uses exposes no
merge operation, which is the whole of the guarantee in spec 08 §3.
"""

from mykronos.patchwork.correlate import BUILT_IN_RULES, Combination, detect
from mykronos.patchwork.fixers import ProposedFix, generate
from mykronos.patchwork.pipeline import (
    CLASSIFICATIONS,
    STAGES,
    PatchworkPipeline,
    PipelineResult,
    StageOutcome,
    event_id,
)

__all__ = [
    "BUILT_IN_RULES",
    "CLASSIFICATIONS",
    "STAGES",
    "Combination",
    "PatchworkPipeline",
    "PipelineResult",
    "ProposedFix",
    "StageOutcome",
    "detect",
    "event_id",
    "generate",
]
