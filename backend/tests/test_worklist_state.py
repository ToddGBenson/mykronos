"""Claiming and snoozing a queue row (spec 27 §3).

Two properties carry most of the weight here, and both are about what a
snooze is *not*: it is not a disposition, and it does not relax what a
disposition requires just because it arrived in a batch.
"""

from __future__ import annotations

from datetime import date, timedelta
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import select

from mykronos import worklist
from mykronos.db.models import RepoOnboarding, TriageState
from mykronos.lake.catalog import Catalog
from mykronos.schemas import utcnow
from tests.conftest import REPO, finding_payload, post_findings, post_scan
from tests.test_onboarding import onboard


def tomorrow() -> date:
    return utcnow().date() + timedelta(days=1)


def seed(
    client: TestClient,
    admin_auth: dict[str, str],
    auth: dict[str, str],
    run_compaction: Any,
    count: int = 1,
) -> list[str]:
    onboard(client, admin_auth)
    with client.app.state.db.session() as session:  # type: ignore[attr-defined]
        row = session.execute(
            select(RepoOnboarding).where(RepoOnboarding.github_repo_full_name == REPO)
        ).scalars().one()
        row.status = "active"
    post_scan(client, auth)
    post_findings(
        client,
        auth,
        [finding_payload(rule_id=f"CWE-{i}", symbol=f"fn_{i}") for i in range(count)],
    )
    run_compaction()
    return [
        str(r[0])
        for r in client.app.state.catalog.query(  # type: ignore[attr-defined]
            "SELECT finding_id FROM findings ORDER BY rule_id"
        )
    ]


def queue(client: TestClient, auth: dict[str, str], **params: Any) -> list[dict[str, Any]]:
    return client.get("/api/dashboard/triage", params=params, headers=auth).json()["items"]


class TestClaiming:
    def test_a_claim_shows_on_the_row(
        self, client: TestClient, admin_auth, auth, run_compaction
    ) -> None:
        [finding_id] = seed(client, admin_auth, auth, run_compaction)

        r = client.post(
            f"/api/dashboard/triage/{finding_id}/claim",
            json={"by": "@sam"},
            headers=admin_auth,
        )

        assert r.status_code == 200
        assert queue(client, admin_auth)[0]["state"]["claimed_by"] == "@sam"

    def test_a_second_person_is_refused_and_told_who_holds_it(
        self, client: TestClient, admin_auth, auth, run_compaction
    ) -> None:
        """A silent overwrite is two people fixing the same finding."""
        [finding_id] = seed(client, admin_auth, auth, run_compaction)
        client.post(
            f"/api/dashboard/triage/{finding_id}/claim",
            json={"by": "@sam"},
            headers=admin_auth,
        )

        r = client.post(
            f"/api/dashboard/triage/{finding_id}/claim",
            json={"by": "@alex"},
            headers=admin_auth,
        )

        assert r.status_code == 409
        assert "@sam" in r.json()["detail"]

    def test_reclaiming_your_own_row_extends_it(
        self, client: TestClient, admin_auth, auth, run_compaction
    ) -> None:
        [finding_id] = seed(client, admin_auth, auth, run_compaction)
        client.post(
            f"/api/dashboard/triage/{finding_id}/claim",
            json={"by": "@sam"},
            headers=admin_auth,
        )

        r = client.post(
            f"/api/dashboard/triage/{finding_id}/claim",
            json={"by": "@sam"},
            headers=admin_auth,
        )

        assert r.status_code == 200

    def test_an_expired_claim_reads_as_unclaimed(
        self, client: TestClient, admin_auth, auth, run_compaction
    ) -> None:
        """The row is kept so the queue can say 'lapsed' rather than quietly
        forgetting somebody meant to do this."""
        [finding_id] = seed(client, admin_auth, auth, run_compaction)
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            worklist.claim(session, finding_id, REPO, by="@sam", days=1)
            row = session.execute(
                select(TriageState).where(TriageState.finding_id == finding_id)
            ).scalars().one()
            state = worklist.state_of(row, now=utcnow() + timedelta(days=2))

        assert state.claimed_by is None

    def test_a_lapsing_claim_is_flagged_before_it_goes(
        self, client: TestClient, admin_auth, auth, run_compaction
    ) -> None:
        [finding_id] = seed(client, admin_auth, auth, run_compaction)
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            worklist.claim(session, finding_id, REPO, by="@sam", days=7)
            row = session.execute(
                select(TriageState).where(TriageState.finding_id == finding_id)
            ).scalars().one()
            state = worklist.state_of(row, now=utcnow() + timedelta(days=6))

        assert state.claim_lapsing is True

    def test_releasing_keeps_the_snooze(
        self, client: TestClient, admin_auth, auth, run_compaction
    ) -> None:
        """They are separate decisions and must not cancel each other."""
        [finding_id] = seed(client, admin_auth, auth, run_compaction)
        client.post(
            f"/api/dashboard/triage/{finding_id}/claim",
            json={"by": "@sam"},
            headers=admin_auth,
        )
        client.post(
            f"/api/dashboard/triage/{finding_id}/snooze",
            json={"until": tomorrow().isoformat(), "reason": "waiting on upstream"},
            headers=admin_auth,
        )

        r = client.delete(f"/api/dashboard/triage/{finding_id}/claim", headers=admin_auth)

        assert r.json()["claimed_by"] is None
        assert r.json()["snoozed_until"] == tomorrow().isoformat()

    def test_a_viewer_cannot_claim(
        self, client: TestClient, admin_auth, auth, viewer_auth, run_compaction
    ) -> None:
        [finding_id] = seed(client, admin_auth, auth, run_compaction)

        r = client.post(
            f"/api/dashboard/triage/{finding_id}/claim",
            json={"by": "@sam"},
            headers=viewer_auth,
        )

        assert r.status_code == 403


class TestSnoozing:
    def test_a_snoozed_row_leaves_the_default_queue(
        self, client: TestClient, admin_auth, auth, run_compaction
    ) -> None:
        [finding_id] = seed(client, admin_auth, auth, run_compaction)

        client.post(
            f"/api/dashboard/triage/{finding_id}/snooze",
            json={"until": tomorrow().isoformat(), "reason": "next sprint"},
            headers=admin_auth,
        )

        assert queue(client, admin_auth) == []
        assert len(queue(client, admin_auth, include_snoozed=True)) == 1

    def test_the_finding_stays_open_and_still_counts(
        self, client: TestClient, admin_auth, auth, catalog: Catalog, run_compaction
    ) -> None:
        """A snooze is about the week, not about the vulnerability. Letting it
        touch status is how 'not now' becomes 'not ever'."""
        [finding_id] = seed(client, admin_auth, auth, run_compaction)

        client.post(
            f"/api/dashboard/triage/{finding_id}/snooze",
            json={"until": tomorrow().isoformat(), "reason": "next sprint"},
            headers=admin_auth,
        )

        status_now = catalog.query(
            "SELECT status FROM findings WHERE finding_id = ?", [finding_id]
        )[0][0]
        assert status_now == "open"
        body = client.get("/api/dashboard/triage", headers=admin_auth).json()
        assert body["total_open"] == 1

    def test_a_snooze_needs_a_reason(
        self, client: TestClient, admin_auth, auth, run_compaction
    ) -> None:
        [finding_id] = seed(client, admin_auth, auth, run_compaction)

        r = client.post(
            f"/api/dashboard/triage/{finding_id}/snooze",
            json={"until": tomorrow().isoformat(), "reason": "   "},
            headers=admin_auth,
        )

        assert r.status_code == 422

    def test_a_past_date_is_refused(
        self, client: TestClient, admin_auth, auth, run_compaction
    ) -> None:
        [finding_id] = seed(client, admin_auth, auth, run_compaction)

        r = client.post(
            f"/api/dashboard/triage/{finding_id}/snooze",
            json={
                "until": (utcnow().date() - timedelta(days=1)).isoformat(),
                "reason": "oops",
            },
            headers=admin_auth,
        )

        assert r.status_code == 422

    def test_it_comes_back_on_its_date(
        self, client: TestClient, admin_auth, auth, run_compaction
    ) -> None:
        [finding_id] = seed(client, admin_auth, auth, run_compaction)
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            worklist.snooze(
                session, finding_id, REPO, until=tomorrow(), reason="next sprint"
            )
            row = session.execute(
                select(TriageState).where(TriageState.finding_id == finding_id)
            ).scalars().one()
            later = worklist.state_of(row, now=utcnow() + timedelta(days=2))

        assert later.snoozed_until is None

    def test_waking_early_keeps_the_claim(
        self, client: TestClient, admin_auth, auth, run_compaction
    ) -> None:
        [finding_id] = seed(client, admin_auth, auth, run_compaction)
        client.post(
            f"/api/dashboard/triage/{finding_id}/claim",
            json={"by": "@sam"},
            headers=admin_auth,
        )
        client.post(
            f"/api/dashboard/triage/{finding_id}/snooze",
            json={"until": tomorrow().isoformat(), "reason": "next sprint"},
            headers=admin_auth,
        )

        r = client.delete(f"/api/dashboard/triage/{finding_id}/snooze", headers=admin_auth)

        assert r.json()["snoozed_until"] is None
        assert r.json()["claimed_by"] == "@sam"


class TestBatch:
    def test_it_applies_across_a_selection(
        self, client: TestClient, admin_auth, auth, run_compaction
    ) -> None:
        ids = seed(client, admin_auth, auth, run_compaction, count=3)

        r = client.post(
            "/api/dashboard/triage/batch",
            json={"finding_ids": ids, "action": "claim", "by": "@sam"},
            headers=admin_auth,
        )

        assert sorted(r.json()["applied"]) == sorted(ids)
        assert r.json()["refused"] == {}

    def test_one_refusal_does_not_fail_the_batch(
        self, client: TestClient, admin_auth, auth, run_compaction
    ) -> None:
        """One row somebody else holds must not stop the other ninety-nine."""
        ids = seed(client, admin_auth, auth, run_compaction, count=3)
        client.post(
            f"/api/dashboard/triage/{ids[1]}/claim",
            json={"by": "@alex"},
            headers=admin_auth,
        )

        r = client.post(
            "/api/dashboard/triage/batch",
            json={"finding_ids": ids, "action": "claim", "by": "@sam"},
            headers=admin_auth,
        )

        body = r.json()
        assert len(body["applied"]) == 2
        assert ids[1] in body["refused"]
        assert "@alex" in body["refused"][ids[1]]

    def test_a_batch_snooze_still_needs_a_reason(
        self, client: TestClient, admin_auth, auth, run_compaction
    ) -> None:
        """Batching must not become the way to stop recording reasons."""
        ids = seed(client, admin_auth, auth, run_compaction, count=2)

        r = client.post(
            "/api/dashboard/triage/batch",
            json={
                "finding_ids": ids,
                "action": "snooze",
                "until": tomorrow().isoformat(),
                "reason": "  ",
            },
            headers=admin_auth,
        )

        assert r.json()["applied"] == []
        assert len(r.json()["refused"]) == 2

    def test_a_batch_snooze_needs_a_date(
        self, client: TestClient, admin_auth, auth, run_compaction
    ) -> None:
        ids = seed(client, admin_auth, auth, run_compaction, count=2)

        r = client.post(
            "/api/dashboard/triage/batch",
            json={"finding_ids": ids, "action": "snooze", "reason": "later"},
            headers=admin_auth,
        )

        assert r.json()["applied"] == []

    def test_a_viewer_cannot_batch(
        self, client: TestClient, admin_auth, auth, viewer_auth, run_compaction
    ) -> None:
        ids = seed(client, admin_auth, auth, run_compaction, count=2)

        r = client.post(
            "/api/dashboard/triage/batch",
            json={"finding_ids": ids, "action": "release"},
            headers=viewer_auth,
        )

        assert r.status_code == 403


class TestTheClaimedFilter:
    def test_it_narrows_to_one_person(
        self, client: TestClient, admin_auth, auth, run_compaction
    ) -> None:
        ids = seed(client, admin_auth, auth, run_compaction, count=3)
        client.post(
            f"/api/dashboard/triage/{ids[0]}/claim",
            json={"by": "@sam"},
            headers=admin_auth,
        )

        mine = queue(client, admin_auth, claimed_by="@sam")

        assert [i["finding_id"] for i in mine] == [ids[0]]


class TestOffboarding:
    def test_purge_drops_a_repository_s_rows(
        self, client: TestClient, admin_auth, auth, run_compaction
    ) -> None:
        """Queue state about a repository nobody scans any more is not work."""
        ids = seed(client, admin_auth, auth, run_compaction, count=2)
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            for finding_id in ids:
                worklist.claim(session, finding_id, REPO, by="@sam")

        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            removed = worklist.purge_for_repo(session, REPO)

        assert removed == 2
