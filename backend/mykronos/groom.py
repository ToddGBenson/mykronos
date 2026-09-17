"""Opening (or updating) the GitHub issue for a groomed story — and closing
it again when the finding it describes stops being open.

Extracted from `api/triage.py` so the scheduled auto-routing pass (spec 19
§4.3) and the per-finding "groom as story" button run the *same* code. An
auto-filed story and a hand-filed one are indistinguishable once filed
because they are produced identically — not because two implementations were
kept in step by hand.

Idempotent by construction rather than by a guard: `story_id()` is derived
from repo + subject (spec 17 §7.2), so re-grooming the same subject finds the
row it wrote last time and updates that issue. A scheduled sweep running
nightly over findings it already groomed is a no-op update, not a growing
pile of duplicates.

**The edge this module was missing (#432).** Filing was the whole of it: the
platform opened an issue when a finding appeared and had no path that touched
it again when the finding closed. Measured 2026-09-17, 15 of the 16 auto-filed
advisory issues in the backlog described findings the platform had already
closed or dispositioned, and `atlas`, `containers` and `iac` had no open
finding at all. A backlog whose advisory half is stale trains its reader to
skim it, and then the one live entry is indistinguishable from the fourteen
dead ones — the same failure mode as a check that is not required (#340).
`sync_story_dispositions` is the missing edge.

**The asymmetry in that sweep is deliberate.** `fixed` and `false_positive`
are settled — the issue gets the evidence and is closed. `accepted_risk` is
not settled: it is a live decision with a review date, and closing its issue
would hide exactly the thing somebody has to come back to on the day the
acceptance lapses. So an acceptance is commented on and **left open**. Do not
"simplify" the two into one rule.

**Why a sweep and not a hook on the disposition.** The four writers that can
move a finding out of `open` are the disposition endpoint (`api/dashboard.py`),
the absence reconciler (`lake/reconcile.py`), the acceptance-expiry sweep
(`jobs.py`) and carry-forward inheritance (`lake/carry_forward.py`). A hook in
each is four places to keep in step, three of which have no GitHub client to
hand; and none of them would ever have closed the 15 issues that were already
stale when the gap was found. A sweep reconciling stored state against the
lake is self-correcting, catches a transition made by any writer, and fixes
the existing backlog on its first run.

Raises `GitHubError` rather than an HTTP exception — the API layer turns that
into a 502, and the job logs it and moves to the next repo. A module that
knew about `HTTPException` could not be called from a scheduled job without
pretending to be inside a request.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from mykronos.db import Database
from mykronos.db.models import AuditLogEntry, GroomedStory
from mykronos.github import GitHubClient
from mykronos.lake.catalog import Catalog
from mykronos.triage_story import TriageStory, story_id

logger = logging.getLogger(__name__)

#: Dispositions that settle a story, and the `state_reason` each closes its
#: issue with. `fixed` is `completed` because a scan confirmed the defect is
#: gone; `false_positive` is `not_planned` because the work was never real.
#: GitHub renders the two differently, and the distinction is free here.
CLOSING_DISPOSITIONS: dict[str, str] = {
    "fixed": "completed",
    "false_positive": "not_planned",
}

#: Dispositions that are commented on and **left open** — see the module
#: docstring. One entry, and it is the whole reason this is not a set
#: difference against `CLOSING_DISPOSITIONS`.
OPEN_DISPOSITIONS: tuple[str, ...] = ("accepted_risk",)

#: Every disposition this sweep has something to say about. A status outside
#: it (`open`, `suppressed`, `superseded`) is left alone: `open` is the state
#: the issue was filed for, `suppressed` is a standing instruction not to
#: report rather than a judgement about this occurrence, and `superseded`
#: means the finding moved identity — which `open_or_update_story` handles
#: from the other end, by not filing a second issue for the replacement.
SYNCED_DISPOSITIONS: tuple[str, ...] = (*CLOSING_DISPOSITIONS, *OPEN_DISPOSITIONS)

#: Columns `_read_disposition` needs from the lake, in the order it unpacks
#: them.
_DISPOSITION_COLUMNS: tuple[str, ...] = (
    "status",
    "rule_id",
    "resolved_at",
    "last_seen_at",
    "last_seen_scan_run_id",
    "accepted_until",
    "accepted_reason_code",
)


@dataclass(frozen=True)
class GroomOutcome:
    story_id: str
    github_issue_number: int
    github_issue_url: str
    #: True if this opened a new issue; false if it updated one an earlier
    #: groom of the same subject already opened.
    created: bool
    #: Set when this groom landed on the issue a *predecessor* finding opened
    #: rather than filing its own — the finding id whose issue was reused.
    #: `None` for the ordinary case (spec 05 §5a; see `_predecessor_story`).
    recurrence_of: str | None = None


@dataclass(frozen=True)
class Disposition:
    """One finding's current standing in the lake, as the sweep reads it.

    `actor` and `reason` come from the audit log rather than the lake: the
    lake records *what* a finding's status is, and spec 12 §7's audit log
    records *who* set it. Both are `None` where no audit entry exists, which
    is a real case — a disposition inherited through carry-forward belongs to
    the decision, not to a person who acted today — and is reported as such
    rather than guessed at.
    """

    finding_id: str
    status: str
    rule_id: str
    resolved_at: datetime | None
    last_seen_at: datetime | None
    last_seen_scan_run_id: str | None
    accepted_until: date | None
    accepted_reason_code: str | None
    actor: str | None
    reason: str | None

    @property
    def closes_the_issue(self) -> bool:
        return self.status in CLOSING_DISPOSITIONS

    @property
    def close_reason(self) -> str:
        return CLOSING_DISPOSITIONS[self.status]


@dataclass
class DispositionSyncResult:
    """What one pass of `sync_story_dispositions` changed."""

    closed: int = 0
    #: Commented on and deliberately left open — acceptances.
    left_open: int = 0
    #: Already at this disposition on a previous pass: nothing said twice.
    already_synced: int = 0
    #: Stories whose finding the lake no longer has a row for. Reported, not
    #: acted on: an issue is never closed on the *absence* of evidence.
    unknown_finding: int = 0
    failed: list[tuple[str, str]] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"{self.closed} closed, {self.left_open} left open (accepted), "
            f"{self.already_synced} already synced, "
            f"{self.unknown_finding} finding not in lake, "
            f"{len(self.failed)} failed"
        )


def _format_moment(value: Any) -> str:
    """A timestamp as a reader sees it, or the honest gap.

    DuckDB hands back `datetime`/`date` objects, the operational store hands
    back strings, and a column that was never written hands back `None`. All
    three arrive here rather than at three call sites.
    """
    if value is None or value == "":
        return "an unrecorded date"
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M UTC")
    if isinstance(value, date):
        return value.isoformat()
    return str(value)


def _read_disposition(catalog: Catalog, session: Session, finding_id: str) -> Disposition | None:
    """This finding's status, and who set it. `None` if the lake has no row —
    compacted away, or a story filed against an id that no longer exists."""
    rows = catalog.query(
        f"SELECT {', '.join(_DISPOSITION_COLUMNS)} FROM findings WHERE finding_id = ? LIMIT 1",
        [finding_id],
    )
    if not rows:
        return None
    record = dict(zip(_DISPOSITION_COLUMNS, rows[0], strict=True))

    entry = (
        session.execute(
            select(AuditLogEntry)
            .where(
                AuditLogEntry.action == "finding.status",
                AuditLogEntry.entity_id == finding_id,
            )
            .order_by(AuditLogEntry.created_at.desc())
        )
        .scalars()
        .first()
    )
    reason = str((entry.detail or {}).get("reason") or "") if entry is not None else ""

    return Disposition(
        finding_id=finding_id,
        status=str(record["status"] or ""),
        rule_id=str(record["rule_id"] or ""),
        resolved_at=record["resolved_at"],
        last_seen_at=record["last_seen_at"],
        last_seen_scan_run_id=(
            str(record["last_seen_scan_run_id"]) if record["last_seen_scan_run_id"] else None
        ),
        accepted_until=record["accepted_until"],
        accepted_reason_code=(
            str(record["accepted_reason_code"]) if record["accepted_reason_code"] else None
        ),
        actor=entry.actor if entry is not None else None,
        reason=reason or None,
    )


_TRAILER = (
    "<sub>Posted by Mykronos's i2i process (spec 17 §7) from the finding's "
    "current status in the lake. If the status changes again, this issue "
    "changes with it.</sub>"
)


def render_disposition_comment(disposition: Disposition) -> str:
    """What the issue is told when its finding leaves `open`.

    Pure, and one function for all three transitions, because the three are
    the same sentence with different evidence — and because a reader comparing
    two closed issues should not have to work out whether two templates say
    the same thing.
    """
    if disposition.status == "fixed":
        seen = _format_moment(disposition.last_seen_at)
        run = (
            f" (scan run `{disposition.last_seen_scan_run_id}`)"
            if disposition.last_seen_scan_run_id
            else ""
        )
        lines = [
            "### Closing — this finding is fixed",
            "",
            f"Mykronos recorded `{disposition.finding_id}` as `fixed` on "
            f"{_format_moment(disposition.resolved_at)}.",
            "",
            f"**The evidence is a scan, not a judgement.** The finding was last "
            f"reported on {seen}{run}; a lane that could see it has run since and "
            "did not report it, which is what closes a finding (spec 05 §5).",
            "",
            "Nothing is suppressed here: if a later scan reports "
            f"`{disposition.rule_id or 'this rule'}` at this location again, it "
            "reopens as a finding and gets an issue again.",
        ]
    elif disposition.status == "false_positive":
        who = (
            f"**{disposition.actor}** dispositioned it"
            if disposition.actor
            else "It was dispositioned"
        )
        lines = [
            "### Closing — dispositioned as a false positive",
            "",
            f"`{disposition.finding_id}` is marked `false_positive` in the lake as "
            f"of {_format_moment(disposition.resolved_at)}. {who}.",
        ]
        if disposition.reason:
            lines += ["", f"> {disposition.reason}"]
        elif disposition.actor is None:
            lines += [
                "",
                "No audit entry records who set it. That is a real case rather "
                "than a missing one: a disposition carried onto a replacement "
                "finding (spec 05 §5b) keeps the decision, not the person who "
                "made it.",
            ]
        else:
            lines += [
                "",
                "No reason was recorded with it — a dismissal without a written "
                "reason is barred from teaching the platform anything about the "
                "rule (spec 11 §4).",
            ]
    elif disposition.status == "accepted_risk":
        code = disposition.accepted_reason_code or "no reason code recorded"
        until = (
            f"until **{_format_moment(disposition.accepted_until)}**"
            if disposition.accepted_until is not None
            else "with **no review date recorded**"
        )
        lines = [
            "### Left open — the risk is accepted, not resolved",
            "",
            f"`{disposition.finding_id}` is `accepted_risk` under reason code "
            f"`{code}`, {until}.",
        ]
        if disposition.actor:
            lines += ["", f"Accepted by **{disposition.actor}**."]
        if disposition.reason:
            lines += ["", f"> {disposition.reason}"]
        lines += [
            "",
            "**This issue is deliberately left open.** An acceptance is a live "
            "decision with a review date, not a resolution; closing it would "
            "hide exactly the thing somebody has to come back to when the "
            "window lapses. The finding is real and the platform is living "
            "with it on purpose.",
        ]
    else:  # pragma: no cover - guarded by SYNCED_DISPOSITIONS at every caller
        raise ValueError(f"{disposition.status} is not a disposition this sweep reports")

    return "\n".join([*lines, "", "---", "", _TRAILER])


def render_recurrence_comment(story: TriageStory, predecessor_id: str) -> str:
    """What the *existing* issue is told when the same defect comes back under
    a new finding id — instead of a second issue.

    Filing per detection rather than per finding is how PCRE2 got four issues,
    `gha-curl-pipe-shell` two and `use-defused-xml` two (#432). The identity
    that links the two detections is `superseded_by` (spec 05 §5a), which is a
    recorded fact, not a title match.
    """
    return "\n".join(
        [
            "### This finding came back under a new identity",
            "",
            f"`{predecessor_id}` was re-fingerprinted as `{story.subject_id}` — the "
            "matched code changed, so its hash changed, but carry-forward "
            "(spec 05 §5b) recorded the two as the same defect.",
            "",
            "Commented rather than filed as a second issue: the work is the same "
            "work, and a duplicate would split its history. The issue body above "
            "has been refreshed from the new detection.",
            "",
            "---",
            "",
            _TRAILER,
        ]
    )


def _predecessor_story(
    session: Session, catalog: Catalog, story: TriageStory
) -> GroomedStory | None:
    """The groomed story for a finding this one replaced, if there is one.

    One level of the supersede chain, the same depth `triage_story._dedup_count`
    reads, and for the same reason: one level is what carry-forward writes per
    re-identification, and walking further would start guessing at links nobody
    recorded. Where a finding replaced more than one predecessor, the most
    recently groomed is chosen — that is the issue a reader is looking at.
    """
    rows = catalog.query(
        "SELECT finding_id FROM findings WHERE superseded_by = ?", [story.subject_id]
    )
    candidates = [
        prior
        for row in rows
        if (prior := session.get(GroomedStory, story_id(story.repo_full_name, str(row[0]))))
        is not None
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda prior: prior.created_at)


async def open_or_update_story(
    db: Database, github: GitHubClient, catalog: Catalog, actor: str, story: TriageStory
) -> GroomOutcome:
    """Open the issue for this story, or update the one already open for it.

    `catalog` is here for one reason: a finding that was re-fingerprinted has
    a new `subject_id` and therefore a new `story_id`, so the check above —
    "have we groomed this subject before?" — answers *no* for what is the same
    defect, and a second issue gets filed. Only the lake knows the two are
    linked, so only a caller holding the lake can avoid the duplicate.
    """
    with db.session() as session:
        existing = session.get(GroomedStory, story.id)
        recurrence_of: str | None = None

        if existing is None:
            prior = (
                _predecessor_story(session, catalog, story)
                if story.subject_type == "finding"
                else None
            )
            # An issue somebody (or an earlier sweep) closed is not somewhere
            # to put a live finding: the recurrence would land out of sight.
            # A new issue is correct then, and this is the only reading of
            # "already has an open issue" that is not an assumption.
            if prior is not None and (
                await github.issue_state(story.repo_full_name, prior.github_issue_number)
            ) == "open":
                await github.update_issue(
                    story.repo_full_name,
                    prior.github_issue_number,
                    title=story.title,
                    body=story.render_issue_body(),
                    labels=story.labels,
                )
                await github.comment_on_issue(
                    story.repo_full_name,
                    prior.github_issue_number,
                    render_recurrence_comment(story, prior.subject_id),
                )
                recurrence_of = prior.subject_id
                session.add(
                    GroomedStory(
                        id=story.id,
                        repo_full_name=story.repo_full_name,
                        subject_type=story.subject_type,
                        subject_id=story.subject_id,
                        github_issue_number=prior.github_issue_number,
                        github_issue_url=prior.github_issue_url,
                        dev_ready=story.dev_ready,
                    )
                )
                issue_number = prior.github_issue_number
                issue_url = prior.github_issue_url
                created = False
            else:
                ref = await github.create_issue(
                    story.repo_full_name,
                    story.title,
                    story.render_issue_body(),
                    labels=story.labels,
                )
                session.add(
                    GroomedStory(
                        id=story.id,
                        repo_full_name=story.repo_full_name,
                        subject_type=story.subject_type,
                        subject_id=story.subject_id,
                        github_issue_number=ref.number,
                        github_issue_url=ref.url,
                        dev_ready=story.dev_ready,
                    )
                )
                issue_number, issue_url = ref.number, ref.url
                created = True
        else:
            await github.update_issue(
                story.repo_full_name,
                existing.github_issue_number,
                title=story.title,
                body=story.render_issue_body(),
                labels=story.labels,
            )
            existing.dev_ready = story.dev_ready
            # A groom is a fresh statement that this subject is open, so the
            # sweep must be free to speak about its next disposition again.
            existing.synced_disposition = None
            issue_number, issue_url = existing.github_issue_number, existing.github_issue_url
            created = False

        db.audit(
            session,
            actor=actor,
            action="triage.groom",
            entity_type=story.subject_type,
            entity_id=story.subject_id,
            repo=story.repo_full_name,
            dev_ready=story.dev_ready,
            created=created,
            recurrence_of=recurrence_of,
        )

    return GroomOutcome(
        story_id=story.id,
        github_issue_number=issue_number,
        github_issue_url=issue_url,
        created=created,
        recurrence_of=recurrence_of,
    )


async def sync_story_dispositions(
    db: Database,
    github: GitHubClient,
    catalog: Catalog,
    *,
    repo_full_name: str,
    actor: str,
) -> DispositionSyncResult:
    """Bring every groomed issue in one repo into line with its finding's
    current disposition (#432).

    Idempotent through `GroomedStory.synced_disposition`, not through reading
    GitHub: an acceptance's issue stays open by design, so "is the issue still
    open?" cannot tell a first pass from the four-hundredth, and a sweep
    running on the routing interval would post the same acceptance comment
    every cycle. What must not repeat is the *statement*, so what is recorded
    is the statement already made.

    A session per story on purpose. The GitHub comment is not transactional;
    if story nine raises, stories one to eight must keep the record that they
    were already spoken about, or the next pass says everything twice.
    """
    result = DispositionSyncResult()

    with db.session() as session:
        pending = [
            (row.id, row.subject_id, row.github_issue_number, row.synced_disposition)
            for row in session.execute(
                select(GroomedStory).where(
                    GroomedStory.repo_full_name == repo_full_name,
                    GroomedStory.subject_type == "finding",
                )
            ).scalars()
        ]

    for row_id, finding_id, issue_number, synced in sorted(pending):
        with db.session() as session:
            disposition = _read_disposition(catalog, session, finding_id)

        if disposition is None:
            result.unknown_finding += 1
            continue
        if disposition.status not in SYNCED_DISPOSITIONS:
            continue
        if synced == disposition.status:
            result.already_synced += 1
            continue

        try:
            await github.comment_on_issue(
                repo_full_name, issue_number, render_disposition_comment(disposition)
            )
            if disposition.closes_the_issue:
                await github.close_issue(
                    repo_full_name, issue_number, reason=disposition.close_reason
                )
        except Exception as exc:  # noqa: BLE001
            # One issue failing must not stop the sweep; nothing is recorded
            # for it, so the next pass retries exactly this one.
            logger.warning(
                "Could not sync issue #%s in %s: %s", issue_number, repo_full_name, exc
            )
            result.failed.append((f"{repo_full_name}#{issue_number}", str(exc)))
            continue

        with db.session() as session:
            story_row = session.get(GroomedStory, row_id)
            if story_row is not None:
                story_row.synced_disposition = disposition.status
            db.audit(
                session,
                actor=actor,
                action="triage.story_disposition",
                entity_type="finding",
                entity_id=finding_id,
                repo=repo_full_name,
                issue=issue_number,
                status=disposition.status,
                closed=disposition.closes_the_issue,
            )

        if disposition.closes_the_issue:
            result.closed += 1
        else:
            result.left_open += 1

    return result
