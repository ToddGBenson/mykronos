"""A delegation that cannot cover the live reviewer, or is about to expire,
is said before it costs a pending queue (TheHub #61547).

On 2026-11-12 the only `pull_request_merge` delegation named
`["claude-opus-5"]` while the reviewer ran `claude-opus-5-5`: every review it
started was refused with 409 and the requests sat pending with nothing on
any surface to say why. These tests pin the clock wherever a window is read.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest

from mykronos import daily_briefing
from mykronos.approvals import delegation_notices, engine, reviewer
from mykronos.approvals.policy import load_policy
from mykronos.config import Settings
from mykronos.db import Database
from mykronos.db.models import Delegation
from mykronos.schemas import utcnow
from tests.test_agent_work import _build
from tests.test_daily_briefing import _get, _section, gathered  # noqa: F401 - fixture

#: A fixed "now" for every window test: never the wall clock.
NOW = datetime(2026, 11, 18, 12, 0)
RUNS = "claude-opus-5-5"
OLD = "claude-opus-5"
DUTY = "pull_request_merge"


@pytest.fixture
def db(settings: Settings) -> Any:
    database = Database(settings.database_url)
    database.create_all()
    yield database
    database.close()


def _grant(
    db: Any,
    *,
    families: list[str],
    expires_at: datetime,
    duty: str = DUTY,
    tiers: tuple[str, ...] = ("production", "routine"),
    constraints: dict[str, Any] | None = None,
) -> str:
    with db.session() as session:
        row = Delegation(
            duty=duty,
            tiers=list(tiers),
            approver_families=families,
            constraints=constraints or {},
            sampling=0.2,
            created_at=NOW - timedelta(days=20),
            expires_at=expires_at,
        )
        session.add(row)
        session.flush()
        return str(row.id)


def _notices(db: Any, *, now: datetime = NOW, mode: str = "live") -> list[Any]:
    return delegation_notices.notices(db, now=now, reviewer_model=RUNS, reviewer_mode=mode)


class TestTheReviewerIsNotCovered:
    def test_a_delegation_naming_another_family_is_one_notice(self, db) -> None:
        delegation_id = _grant(db, families=[OLD], expires_at=NOW + timedelta(days=30))

        [notice] = _notices(db)

        assert notice.delegation_id == delegation_id
        assert notice.reviewer_model == RUNS
        assert notice.uncovered_tiers == ("production", "routine")
        assert notice.expiring is False
        assert delegation_id[:8] in notice.what
        assert "['claude-opus-5']" in notice.what
        assert RUNS in notice.what

    def test_it_agrees_with_the_preflight_409(self, db, settings) -> None:
        """The notice and the refusal read the same rule, so they cannot disagree."""
        policy = load_policy(settings.approval_policy_path)
        req = {
            "duty": DUTY,
            "tier": "production",
            "requested_by": "agent:claude-sonnet-5:builder",
            "requester_kind": "agent",
            "requester_provenance": {"family": "claude-sonnet-5", "instance": "b"},
        }
        _grant(db, families=[OLD], expires_at=utcnow() + timedelta(days=30))
        moment = utcnow()

        assert delegation_notices.notices(db, now=moment, reviewer_model=RUNS)
        with pytest.raises(engine.ApprovalError, match="No active delegation"):
            reviewer._preflight(db, policy, req, RUNS)

        _grant(db, families=[RUNS], expires_at=utcnow() + timedelta(days=30))

        assert delegation_notices.notices(db, now=moment, reviewer_model=RUNS) == []
        reviewer._preflight(db, policy, req, RUNS)  # no 409

    def test_only_the_tiers_nothing_else_covers_are_named(self, db) -> None:
        _grant(db, families=[OLD], expires_at=NOW + timedelta(days=30))
        _grant(db, families=[RUNS], tiers=("routine",), expires_at=NOW + timedelta(days=30))

        [notice] = _notices(db)

        assert notice.uncovered_tiers == ("production",)

    def test_a_reviewer_switched_off_needs_no_delegation(self, db) -> None:
        _grant(db, families=[OLD], expires_at=NOW + timedelta(days=30))

        assert _notices(db, mode="off") == []

    def test_a_purpose_scoped_delegation_is_not_the_reviewers(self, db) -> None:
        _grant(
            db,
            families=[OLD],
            expires_at=NOW + timedelta(days=30),
            constraints={"approver_purposes": ["security-champion"]},
        )

        assert _notices(db) == []

    def test_a_purpose_scoped_delegation_naming_the_model_does_not_cover_the_reviewer(
        self, db
    ) -> None:
        """`decide` refuses the platform reviewer under a purpose-scoped
        delegation, so the check must ask as the reviewer: without
        `approver=reviewer` this one would read as covered (Fable 5.2 on #1194)."""
        old = _grant(db, families=[OLD], expires_at=NOW + timedelta(days=30))
        _grant(
            db,
            families=[RUNS],
            expires_at=NOW + timedelta(days=30),
            constraints={"approver_purposes": ["security-champion"]},
        )

        [notice] = _notices(db)

        assert notice.delegation_id == old
        assert notice.uncovered_tiers == ("production", "routine")

    def test_live_says_it_is_refused(self, db) -> None:
        _grant(db, families=[OLD], expires_at=NOW + timedelta(days=30))

        [notice] = _notices(db, mode="live")

        assert "is refused (409)" in notice.so_what
        assert "would" not in notice.so_what

    def test_shadow_says_going_live_would_refuse(self, db) -> None:
        """In shadow mode `run_review` skips the preflight: nothing is refused yet."""
        _grant(db, families=[OLD], expires_at=NOW + timedelta(days=30))

        [notice] = _notices(db, mode="shadow")

        assert "Once the reviewer is live" in notice.so_what
        assert "would be refused (409)" in notice.so_what
        assert "is refused" not in notice.so_what

    def test_a_revoked_or_lapsed_delegation_says_nothing(self, db) -> None:
        _grant(db, families=[OLD], expires_at=NOW - timedelta(seconds=1))
        revoked = _grant(db, families=[OLD], expires_at=NOW + timedelta(days=30))
        with db.session() as session:
            session.get(Delegation, revoked).revoked_at = NOW - timedelta(days=1)

        assert _notices(db) == []


class TestExpiry:
    @pytest.mark.parametrize("duty", [DUTY, "risk_acceptance", "finding_disposition"])
    def test_seven_days_out_is_warned_for_every_duty(self, db, duty: str) -> None:
        _grant(db, families=[RUNS], duty=duty, expires_at=NOW + timedelta(days=7))

        [notice] = _notices(db)

        assert notice.expiring is True
        assert notice.reviewer_model == ""
        assert "expires 2026-11-25 12:00Z" in notice.what

    def test_a_second_past_seven_days_is_not_yet(self, db) -> None:
        _grant(db, families=[RUNS], expires_at=NOW + timedelta(days=7, seconds=1))

        assert _notices(db) == []

    def test_once_not_daily(self, db) -> None:
        """The same item, word for word, every day of the window: a reader
        de-duplicating by id or text sees it once, not a new countdown line."""
        _grant(db, families=[RUNS], expires_at=NOW + timedelta(days=7))

        days = [_notices(db, now=NOW + timedelta(days=d)) for d in range(7)]

        assert all(len(found) == 1 for found in days)
        assert len({(n.delegation_id, n.what, n.so_what) for [n] in days}) == 1

    def test_a_purpose_scoped_one_does_not_renew_a_family_only_one(self, db) -> None:
        """The reviewer's delegation lapsing is not renewed by one only a
        person-minted credential can use (Fable 5.2 on #1194)."""
        expiring = _grant(db, families=[RUNS], expires_at=NOW + timedelta(days=3))
        _grant(
            db,
            families=[RUNS],
            expires_at=NOW + timedelta(days=33),
            constraints={"approver_purposes": ["security-champion"]},
        )

        [notice] = _notices(db)

        assert notice.delegation_id == expiring and notice.expiring is True

    def test_a_family_only_one_does_not_renew_a_purpose_scoped_one(self, db) -> None:
        """A person-minted credential under a family-only delegation keeps
        fresh_context and is refused, so it is no renewal either."""
        expiring = _grant(
            db,
            families=[RUNS],
            expires_at=NOW + timedelta(days=3),
            constraints={"approver_purposes": ["security-champion"]},
        )
        _grant(db, families=[RUNS], expires_at=NOW + timedelta(days=33))

        [notice] = _notices(db)

        assert notice.delegation_id == expiring and notice.expiring is True

    def test_the_same_purposes_do_renew(self, db) -> None:
        scoped = {"approver_purposes": ["security-champion"]}
        _grant(db, families=[RUNS], expires_at=NOW + timedelta(days=3), constraints=scoped)
        _grant(db, families=[RUNS], expires_at=NOW + timedelta(days=33), constraints=scoped)

        assert _notices(db) == []

    def test_a_renewed_delegation_says_nothing(self, db) -> None:
        _grant(db, families=[RUNS], expires_at=NOW + timedelta(days=3))
        _grant(db, families=[RUNS], expires_at=NOW + timedelta(days=33))

        assert _notices(db) == []

    def test_mismatched_and_expiring_is_still_one_item(self, db) -> None:
        _grant(db, families=[OLD], expires_at=NOW + timedelta(days=2))

        [notice] = _notices(db)

        assert notice.reviewer_model == RUNS and notice.expiring is True


class TestTheWorkQueue:
    def test_one_item_names_the_delegation_family_and_model(self, db) -> None:
        delegation_id = _grant(db, families=[OLD], expires_at=NOW + timedelta(days=30))

        queue = _build(delegations=_notices(db))

        [item] = [i for i in queue.items if i.kind == "delegation_attention"]
        assert item.item_id == f"delegation_attention:{delegation_id}"
        assert OLD in item.summary and RUNS in item.summary
        assert item.evidence[0].ref == delegation_id
        assert item.playbook == "delegation_attention@1.0"

    def test_unreadable_delegations_are_unknown_not_none(self) -> None:
        queue = _build(delegations=None)

        assert [u.source for u in queue.unknown] == ["delegations"]

    def test_the_route_carries_it(self, client, admin_auth) -> None:
        delegation_id = _grant(
            client.app.state.db, families=[OLD], expires_at=utcnow() + timedelta(days=30)
        )

        body = client.get("/api/agent/work", headers=admin_auth).json()

        items = [i for i in body["items"] if i["kind"] == "delegation_attention"]
        assert [i["item_id"] for i in items] == [f"delegation_attention:{delegation_id}"]
        assert OLD in items[0]["summary"] and RUNS in items[0]["summary"]


class TestTheDailyBriefing:
    def test_needs_you_carries_one_line(self, client, admin_auth, gathered) -> None:  # noqa: F811
        delegation_id = _grant(
            client.app.state.db, families=[OLD], expires_at=utcnow() + timedelta(days=30)
        )

        section = _section(_get(client, admin_auth), "needs_you_today")

        lines = [line for line in section["lines"] if delegation_id[:8] in line["what"]]
        assert len(lines) == 1
        assert OLD in lines[0]["what"] and RUNS in lines[0]["what"]
        assert lines[0]["work"] == "decision"
        assert section["data"]["delegations"] == [
            f"/api/approvals/delegations/{delegation_id}/stats"
        ]

    def test_an_unreadable_store_is_a_reason_not_silence(self, monkeypatch) -> None:
        def broken(*_a: Any, **_k: Any) -> Any:
            raise RuntimeError("database is locked")

        monkeypatch.setattr(delegation_notices, "notices", broken)

        lines, why = daily_briefing.delegation_lines(
            object(), SimpleNamespace(reviewer_model=RUNS, reviewer_mode="live"), now=NOW
        )

        assert lines == [] and "Delegations could not be read" in why


def test_shadow_reviews_reports_the_running_model(client, admin_auth) -> None:
    body = client.get("/api/approvals/shadow-reviews", headers=admin_auth).json()

    assert body["model"] == client.app.state.settings.reviewer_model
