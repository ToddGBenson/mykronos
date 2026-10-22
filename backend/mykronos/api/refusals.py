"""A refused upload is a security event, and it reaches a person (B-062).

Every ingestion door -- findings, raw output, Aegis, Oracle, Patchwork -- is
guarded by the same capability check, and until 2026-09-09 a refusal was a
`403` and nothing else. That was the wrong shape for what it means. A
capability that is not granted has, almost always, a lane that thinks it is:
the lane ran, produced findings, and was turned away at the door. Four of
TheHub's lanes did exactly that on 2026-09-05 and stayed green, because the
quality lanes write their upload with `|| true` so a broken uploader cannot
fail a passing suite. The findings were produced and discarded, and the only
record was a line in a build log nobody opens when the build is green.

So a refusal is raised as its own exception and handled in one place, where
the notifier is. One notification per repository and capability per quiet
window, not one per request: a scheduled lane that has lost its grant would
otherwise repeat itself every run, and a channel that repeats itself gets
muted, which costs more than the alert was ever worth (spec 16 §14).

**And it is recorded, every time, as lane health (TheHub #60813).** The
notification is deduplicated; the record is not. `IngestRefusal` keeps one row
per repository and capability - first and last refusal, how many - so the
portfolio can say "refused" where it would otherwise say "never sent": both
leave no scan run behind, and only one of them means a lane is running and
being turned away.
"""

from __future__ import annotations

import logging
import time

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse

from mykronos.db.models import IngestRefusal
from mykronos.notify import Notification
from mykronos.schemas import utcnow

logger = logging.getLogger(__name__)

#: How long after notifying about one (repository, capability) refusal the
#: handler stays quiet about the same pair. An hour covers a lane retrying
#: inside one build and a schedule that fires more than once a day.
REFUSAL_QUIET_SECONDS = 3600


class CapabilityRefusedError(Exception):
    """A token tried to write a capability its repository is not granted."""

    def __init__(self, repo_full_name: str, capability: str, granted: frozenset[str]) -> None:
        self.repo_full_name = repo_full_name
        self.capability = capability
        self.granted = granted
        super().__init__(self.detail)

    @property
    def detail(self) -> str:
        granted = ", ".join(sorted(self.granted)) or "none"
        return (
            f"'{self.capability}' is not enabled for {self.repo_full_name}. "
            f"Currently granted: {granted}."
        )


def install(app: FastAPI) -> None:
    """Register the handler. Called once, from `create_app`."""

    @app.exception_handler(CapabilityRefusedError)
    async def _refused(request: Request, exc: CapabilityRefusedError) -> JSONResponse:
        record_refusal(request, exc)
        await notify_refusal(request, exc)
        # The same body a plain HTTPException would have sent, so every
        # uploader and every existing test reads the refusal exactly as before.
        return JSONResponse(status_code=status.HTTP_403_FORBIDDEN, content={"detail": exc.detail})


def record_refusal(request: Request, exc: CapabilityRefusedError) -> bool:
    """Count this refusal against its (repository, capability).

    Never raises: the refusal is the answer the uploader is owed, and a
    database that cannot be written must not turn a 403 into a 500. Returns
    whether the record was written.
    """
    db = getattr(request.app.state, "db", None)
    if db is None:
        return False
    try:
        with db.session() as session:
            row = session.get(IngestRefusal, (exc.repo_full_name, exc.capability))
            now = utcnow()
            if row is None:
                row = IngestRefusal(
                    repo_full_name=exc.repo_full_name,
                    capability=exc.capability,
                    first_refused_at=now,
                    refusals=0,
                )
                session.add(row)
            row.last_refused_at = now
            row.refusals = int(row.refusals or 0) + 1
            row.detail = exc.detail
            session.commit()
    except Exception:  # see the docstring: a 403 must not become a 500
        logger.exception("Could not record the refusal of %s for a repository", exc.capability)
        return False
    return True


async def notify_refusal(request: Request, exc: CapabilityRefusedError) -> bool:
    """Send the notification unless this pair was announced recently.

    Returns whether a notification was attempted, so a test can tell a
    deduplicated refusal from a failed send.
    """
    state = request.app.state
    seen: dict[tuple[str, str], float] | None = getattr(state, "refusals_seen", None)
    if seen is None:
        seen = {}
        state.refusals_seen = seen

    key = (exc.repo_full_name, exc.capability)
    now = time.monotonic()
    last = seen.get(key)
    if last is not None and now - last < REFUSAL_QUIET_SECONDS:
        return False
    seen[key] = now

    notifier = getattr(state, "notifier", None)
    if notifier is None:
        return False

    granted = ", ".join(sorted(exc.granted)) or "none"
    await notifier.send(
        Notification(
            title=f"{exc.capability} upload refused: not granted",
            detail=(
                f"A lane uploaded `{exc.capability}` for {exc.repo_full_name} and was "
                f"refused at the door. Findings were produced and discarded.\n"
                f"Currently granted: {granted}.\n"
                "If the lane is meant to report, grant it: "
                f"`mykronos grant {exc.repo_full_name} {exc.capability}`, or enable it "
                "from the repository page. If it is not, the lane should stop running. "
                f"Quiet for the next {REFUSAL_QUIET_SECONDS // 60} minutes on this pair."
            ),
            repo_full_name=exc.repo_full_name,
            level="warning",
        )
    )
    return True
