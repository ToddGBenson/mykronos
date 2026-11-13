"""Who does what about a Dependabot copy the sweep could not write (TheHub #60855).

The sweep records one of three reasons on the token (`github/secrets.py` and
`jobs.rotate_ingestion_tokens`), and each has a different remedy and a
different owner. Saying "grant the permission" for all three is wrong for two
of them, so every place that shows the gap asks this module, and a reason that
matches none of the three is shown on its own with no remedy invented for it.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from mykronos.github.secrets import DEPENDABOT_PERMISSION, write_failed_under_grant

#: The three recorded causes, in the order the sweep can record them.
PERMISSION_NOT_HELD = "permission_not_held"
CONCOURSE_BLOCKER = "concourse_blocker"
WRITE_FAILED = "write_failed_under_grant"
UNKNOWN = "unknown"

#: What a person reads for each cause.
ACTIONS: dict[str, str] = {
    PERMISSION_NOT_HELD: (
        "grant the App 'Dependabot secrets: Read and write' and accept it on the "
        "installation; the next sweep writes the secret"
    ),
    CONCOURSE_BLOCKER: "Rotate by hand: repair-ingestion-token.ps1",
    # Not "re-run the sweep": `jobs.rotate_ingestion_tokens` skips a repository
    # whose blocker is WRITE_FAILED until its next due rotation, so a re-run
    # retries nothing. See `remedy_for`, which adds the date.
    WRITE_FAILED: "the grant is held and the write failed",
    UNKNOWN: "",
}

#: Who acts: the operator holds the App's permissions; HubOps runs the sweep and
#: the hand rotation. An unrecognised reason has no owner invented for it.
OWNERS: dict[str, str] = {
    PERMISSION_NOT_HELD: "operator",
    CONCOURSE_BLOCKER: "hubops",
    WRITE_FAILED: "hubops",
    UNKNOWN: "",
}

#: What the "done when" line of the work-queue item requires.
DONE_WHEN: dict[str, str] = {
    PERMISSION_NOT_HELD: (
        "The App holds 'Dependabot secrets: Read and write', the next rotation sweep "
        "reports the secret written, and a Dependabot pull request's risk-decision "
        "records a decision."
    ),
    CONCOURSE_BLOCKER: (
        "The token has been rotated by hand with repair-ingestion-token.ps1, the sweep "
        "reports the Dependabot secret written, and a Dependabot pull request's "
        "risk-decision records a decision."
    ),
    WRITE_FAILED: (
        "The next due rotation writes the Dependabot secret and the sweep reports it "
        "written, and a Dependabot pull request's risk-decision records a decision."
    ),
    UNKNOWN: (
        "The sweep reports the Dependabot secret written and a Dependabot pull "
        "request's risk-decision records a decision."
    ),
}

_CONCOURSE_PREFIX = "The Dependabot secret is not written:"


@dataclass(frozen=True)
class Remedy:
    kind: str
    action: str
    owner: str
    done_when: str


def classify(reason: str) -> str:
    """Which of the recorded causes `reason` is."""
    if write_failed_under_grant(reason):
        return WRITE_FAILED
    if reason.startswith(_CONCOURSE_PREFIX):
        return CONCOURSE_BLOCKER
    # `permission_not_held_reason` and `dependabot_gap_reason` for 401/403/404
    # both name the permission; a plain write failure does not.
    if DEPENDABOT_PERMISSION in reason and "Grant it on the App" in reason:
        return PERMISSION_NOT_HELD
    return UNKNOWN


def remedy_for(reason: str, rotate_after: datetime | None = None) -> Remedy:
    """The remedy for a recorded `reason`.

    `rotate_after` is the active token's next due date, which is when the sweep
    retries a copy that failed under a held grant.
    """
    kind = classify(reason)
    action = ACTIONS[kind]
    done_when = DONE_WHEN[kind]
    if kind == WRITE_FAILED:
        when = f" on {rotate_after:%Y-%m-%d}" if rotate_after is not None else ""
        action = (
            f"{action}; the copy is retried at the next due rotation{when}. Nothing "
            "clears the blocker sooner: no command or route exists for it, and "
            "re-running the sweep skips this repository until then. Read the sweep log "
            "for the cause meanwhile"
        )
        if rotate_after is not None:
            done_when = done_when.replace(
                "The next due rotation", f"The next due rotation ({rotate_after:%Y-%m-%d})"
            )
    return Remedy(kind=kind, action=action, owner=OWNERS[kind], done_when=done_when)
