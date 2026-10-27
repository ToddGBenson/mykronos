"""How much of one repository an analyser reads, and what that does to a verdict.

Two readers share this (TheHub #60795, #60962):

- `GET /api/dashboard/repos/{id}/coverage`, which tells an agent or a person
  what the scanners cannot read in one repository: the B-051 analyser gap beside
  regression coverage.
- The Oracle verdict, which carries a **confidence note** when the analysers
  read less of the code than a configured threshold (decision 60814, option 2).

**The note never changes the verdict.** Option 2 was chosen over withholding
`go` because what risk is worth is the operator's policy, and a policy that
moved on a language mix would move on every push that adds a shell script. The
note is computed when the verdict is read, from data outside the decision, so
it cannot reach the score, the recommendation or anything recorded with them.

**Unknown is said, never left out.** A note that is absent when GitHub could
not be asked would read exactly like a repository that is fully read, which is
the absence of evidence rendering as evidence of coverage -- the rule #444
applied to `not_assessed`, one level down.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from mykronos.analysers import readability

#: What the note says when coverage could not be read. Fixed text, so a
#: dashboard or an agent can recognise it without parsing a sentence.
UNKNOWN_NOTE = "read coverage unknown"


@dataclass(frozen=True)
class ReadCoverage:
    """What share of a repository's application source an analyser reads."""

    repo_full_name: str
    #: Whether the share was measured. False when GitHub could not be asked,
    #: or answered with no languages at all (a new or empty repository).
    available: bool
    #: Why it is unavailable; empty when it is available.
    reason: str = ""
    #: The analysers that report SAST here, or the configured one.
    tools: tuple[str, ...] = ()
    source_bytes: int = 0
    #: 0.0 to 1.0, or None when unavailable.
    share_read: float | None = None
    #: Languages nothing here reads, largest first, as (name, bytes).
    unread: list[tuple[str, int]] = field(default_factory=list)

    @property
    def share_unread(self) -> float | None:
        return None if self.share_read is None else 1 - self.share_read

    @property
    def percent_read(self) -> int | None:
        """Whole percent, rounded **down**.

        Down, so a repository read 79.6% under an 80% threshold is never
        described as "read 80%" in a note that exists because it is under 80.
        """
        if self.share_read is None:
            return None
        return int(math.floor(self.share_read * 100 + 1e-9))


def measure(
    repo_full_name: str,
    languages: dict[str, int] | None,
    tools: str | list[str] | tuple[str, ...],
) -> ReadCoverage:
    """One repository's read share from GitHub's byte counts.

    `languages` is None when GitHub could not be read. That is reported as
    unavailable with the reason, never as zero unread.
    """
    names = (tools,) if isinstance(tools, str) else tuple(tools)
    if languages is None:
        return ReadCoverage(
            repo_full_name=repo_full_name,
            available=False,
            reason="GitHub's language breakdown could not be read for this repository.",
            tools=names,
        )
    reading = readability(repo_full_name, languages, names)
    if not reading.known:
        return ReadCoverage(
            repo_full_name=repo_full_name,
            available=False,
            reason="GitHub reports no application source here, so nothing was measured.",
            tools=reading.tools,
        )
    return ReadCoverage(
        repo_full_name=repo_full_name,
        available=True,
        tools=reading.tools,
        source_bytes=reading.source_bytes,
        share_read=1 - reading.share_unread,
        unread=list(reading.unread),
    )


def confidence_note(
    coverage: ReadCoverage | None, recommendation: str | None, threshold: float
) -> str | None:
    """The note a verdict carries, or None when the analysers read enough.

    "go - read 31% of the code" when the read share is under `threshold`;
    "go - read coverage unknown" when it could not be measured. The verdict
    word is quoted, not judged: this function is given the recommendation and
    returns text, so it has no way to change it.
    """
    prefix = f"{recommendation} - " if recommendation else ""
    if coverage is None or not coverage.available or coverage.share_read is None:
        return prefix + UNKNOWN_NOTE
    if coverage.share_read >= threshold:
        return None
    return f"{prefix}read {coverage.percent_read}% of the code"


def as_dict(coverage: ReadCoverage) -> dict[str, object]:
    """The analyser half of the coverage route, and of the verdict's note."""
    return {
        "available": coverage.available,
        "reason": coverage.reason,
        "tools": list(coverage.tools),
        "source_bytes": coverage.source_bytes,
        "share_read": coverage.share_read,
        "share_unread": coverage.share_unread,
        "unread_languages": [
            {"language": name, "bytes": count} for name, count in coverage.unread[:5]
        ],
    }
