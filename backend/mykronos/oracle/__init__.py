"""Oracle — the risk decision engine (spec 09).

The one component in the spec set that does not exist anywhere else, and the
only one whose output is an opinion rather than an observation. Everything
about it is shaped by two constraints: it must be reproducible by hand, and it
must never be able to explain itself using an input it did not record.
"""

from mykronos.oracle.engine import Decision, OracleEngine, Term, render_reasoning
from mykronos.oracle.policy import Policy, PolicyError, cached_policy, load_policy, parse_policy

__all__ = [
    "Decision",
    "OracleEngine",
    "Policy",
    "PolicyError",
    "Term",
    "cached_policy",
    "load_policy",
    "parse_policy",
    "render_reasoning",
]
