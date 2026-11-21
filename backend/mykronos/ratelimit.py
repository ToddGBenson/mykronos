"""Per-token rate limiting (spec 05 §6).

Protects the compaction job from a misbehaving workflow. A sliding window
keyed on the token hash, in process memory — correct for the single-process
Phase 0 deployment, and the obvious thing to move behind Redis if the backend
is ever horizontally scaled.

The client half of this contract lives in the shared `upload-results`
composite action, which backs off on 429 and eventually fails the workflow
step rather than dropping findings (spec 05 §6, spec 01 §6).
"""

from __future__ import annotations

import time
from collections import defaultdict, deque


class SlidingWindowLimiter:
    def __init__(self, requests_per_minute: int, window_seconds: float = 60.0) -> None:
        self.limit = requests_per_minute
        self.window = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def check(self, key: str) -> tuple[bool, int]:
        """Record a request. Returns ``(allowed, retry_after_seconds)``."""
        now = time.monotonic()
        hits = self._hits[key]
        cutoff = now - self.window
        while hits and hits[0] < cutoff:
            hits.popleft()

        if len(hits) >= self.limit:
            retry_after = max(1, int(self.window - (now - hits[0])) + 1)
            return False, retry_after

        hits.append(now)
        return True, 0

    def refund(self, key: str) -> None:
        """Give back the newest hit recorded for ``key``. For a request that was
        allowed but then failed for a reason that is not the caller's: it must
        not use up the caller's allowance (TheHub #61379)."""
        hits = self._hits.get(key)
        if hits:
            hits.pop()

    def reset(self, key: str | None = None) -> None:
        if key is None:
            self._hits.clear()
        else:
            self._hits.pop(key, None)


def hourly_refusal(what: str, actor: str, limit: int, retry_after: int) -> str:
    """The 429 message for a per-actor hourly limit (TheHub #61379): what is
    limited, how many, who used them, and when to come back."""
    minutes = max(1, -(-retry_after // 60))
    return (
        f"{what} is limited to {limit} per hour for each actor, and {actor} has used "
        f"them. Try again in about {minutes} minute(s)."
    )
