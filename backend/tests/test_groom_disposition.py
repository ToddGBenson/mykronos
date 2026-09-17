"""An auto-filed issue must not outlive its finding — #432.

Measured 2026-09-17: of the 16 auto-filed advisory issues in the backlog, 15
described findings the platform had already closed or dispositioned. Filing
was implemented; the edge back was not.

Three transitions and one duplicate, and the asymmetry between them is the
point: `fixed` and `false_positive` close the issue, `accepted_risk` comments
and **leaves it open**, because an acceptance is a live decision with a review
date and closing it hides the thing somebody has to come back to.
"""

from __future__ import annotations

from datetime import date, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from mykronos.db.models import AuditLogEntry, GroomedStory
from mykronos.groom import render_disposition_comment, sync_story_dispositions
from mykronos.jobs import route_open_findings
from mykronos.lake.catalog import Catalog
from mykronos.lake.mutate import locate_findings, update_findings
from mykronos.schemas import utcnow
from tests.conftest import REPO, finding_payload, issue_token, post_findings, post_scan
from tests.test_onboarding import onboard


def seed(client, admin_auth, run_compaction, findings=None, scan_run_id="run-groom"):
    """One onboarded repo with `sast` on, and its findings compacted."""
    repo_id = onboard(client, admin_auth).json()["id"]
    client.patch(
        f"/api/repos/{repo_id}/capabilities",
        json={"capabilities": ["sast"], "install_workflows": False},
        headers=admin_auth,
    )
    auth = {"Authorization": f"Bearer {issue_token(client, REPO, 'sast')}"}
    post_scan(client, auth, scan_run_id=scan_run_id)
    post_findings(
        client, auth, findings or [finding_payload()], scan_run_id=scan_run_id
    )
    run_compaction()
    return repo_id


def finding_ids(client, admin_auth, repo_id) -> dict[str, str]:
    """rule_id -> finding_id, for the seeded repo."""
    page = client.get(
        f"/api/dashboard/repos/{repo_id}/findings", headers=admin_auth
    ).json()
    return {row["rule_id"]: row["finding_id"] for row in page["findings"]}


def groom(client, admin_auth, finding_id):
    response = client.post(f"/api/triage/{finding_id}/groom", headers=admin_auth)
    assert response.status_code == 200, response.text
    return response.json()


def set_status(catalog: Catalog, finding_id: str, clause: str, params: list) -> None:
    """Write a disposition through the same helper the endpoint uses, so the
    row is shaped exactly as a real one is."""
    update_findings(catalog, locate_findings(catalog, [finding_id]), clause, params)


async def sync(client, catalog):
    return await sync_story_dispositions(
        client.app.state.db,
        client.app.state.github_factory.client,
        catalog,
        repo_full_name=REPO,
        actor="tests",
    )


def the_issue(client, number: int = 1) -> dict:
    return next(
        i
        for i in client.app.state.github_factory.client.repos[REPO].issues
        if i["number"] == number
    )


class TestAFixedFindingClosesItsIssue:
    @pytest.mark.asyncio
    async def test_the_issue_is_closed(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction, catalog
    ) -> None:
        repo_id = seed(client, admin_auth, run_compaction)
        finding_id = finding_ids(client, admin_auth, repo_id)["CWE-89"]
        groom(client, admin_auth, finding_id)
        set_status(catalog, finding_id, "status = ?, resolved_at = ?", ["fixed", utcnow()])

        result = await sync(client, catalog)

        assert result.closed == 1
        assert the_issue(client)["state"] == "closed"
        assert the_issue(client)["state_reason"] == "completed"

    @pytest.mark.asyncio
    async def test_the_comment_carries_the_evidence(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction, catalog
    ) -> None:
        """Closing with no comment leaves a reader unable to tell a
        resolution from a tidy-up."""
        repo_id = seed(client, admin_auth, run_compaction)
        finding_id = finding_ids(client, admin_auth, repo_id)["CWE-89"]
        groom(client, admin_auth, finding_id)
        set_status(catalog, finding_id, "status = ?, resolved_at = ?", ["fixed", utcnow()])

        await sync(client, catalog)

        comment = the_issue(client)["comments"][0]
        assert "fixed" in comment
        assert finding_id in comment
        # The evidence is a scan that stopped reporting it, named as such.
        assert "run-groom" in comment


class TestAFalsePositiveClosesItsIssue:
    @pytest.mark.asyncio
    async def test_the_issue_is_closed_as_not_planned(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction, catalog
    ) -> None:
        repo_id = seed(client, admin_auth, run_compaction)
        finding_id = finding_ids(client, admin_auth, repo_id)["CWE-89"]
        groom(client, admin_auth, finding_id)
        client.patch(
            f"/api/dashboard/findings/{finding_id}/status",
            json={"status": "false_positive", "reason": "the query is parameterised"},
            headers=admin_auth,
        )

        result = await sync(client, catalog)

        assert result.closed == 1
        assert the_issue(client)["state"] == "closed"
        assert the_issue(client)["state_reason"] == "not_planned"

    @pytest.mark.asyncio
    async def test_the_comment_names_who_dispositioned_it(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction, catalog
    ) -> None:
        """The lake records *what* the status is; spec 12 §7's audit log
        records *who* set it. A dismissal with nobody's name on it is the one
        a reader cannot argue with."""
        repo_id = seed(client, admin_auth, run_compaction)
        finding_id = finding_ids(client, admin_auth, repo_id)["CWE-89"]
        groom(client, admin_auth, finding_id)
        client.patch(
            f"/api/dashboard/findings/{finding_id}/status",
            json={"status": "false_positive", "reason": "the query is parameterised"},
            headers=admin_auth,
        )

        await sync(client, catalog)

        comment = the_issue(client)["comments"][0]
        assert "false_positive" in comment
        assert "the query is parameterised" in comment
        with client.app.state.db.session() as session:
            actor = (
                session.execute(
                    select(AuditLogEntry).where(AuditLogEntry.action == "finding.status")
                )
                .scalars()
                .one()
                .actor
            )
        assert actor in comment


class TestAnAcceptanceIsCommentedAndLeftOpen:
    """The asymmetry #432 asks for explicitly. An acceptance is a live
    decision with a review date; closing its issue would hide exactly the
    thing somebody has to come back to."""

    def _accept(self, client, admin_auth, finding_id, until: date):
        response = client.patch(
            f"/api/dashboard/findings/{finding_id}/status",
            json={
                "status": "accepted_risk",
                "reason": "no vendor fix; compensating WAF rule in place",
                "accepted_reason_code": "no_vendor_fix",
                "accepted_until": until.isoformat(),
            },
            headers=admin_auth,
        )
        assert response.status_code == 200, response.text

    @pytest.mark.asyncio
    async def test_the_issue_stays_open(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction, catalog
    ) -> None:
        repo_id = seed(client, admin_auth, run_compaction)
        finding_id = finding_ids(client, admin_auth, repo_id)["CWE-89"]
        groom(client, admin_auth, finding_id)
        self._accept(client, admin_auth, finding_id, utcnow().date() + timedelta(days=30))

        result = await sync(client, catalog)

        assert result.closed == 0
        assert result.left_open == 1
        assert the_issue(client)["state"] == "open"

    @pytest.mark.asyncio
    async def test_the_comment_carries_the_reason_code_and_the_expiry(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction, catalog
    ) -> None:
        repo_id = seed(client, admin_auth, run_compaction)
        finding_id = finding_ids(client, admin_auth, repo_id)["CWE-89"]
        groom(client, admin_auth, finding_id)
        until = utcnow().date() + timedelta(days=30)
        self._accept(client, admin_auth, finding_id, until)

        await sync(client, catalog)

        comment = the_issue(client)["comments"][0]
        assert "no_vendor_fix" in comment
        assert until.isoformat() in comment


class TestTheSweepSaysNothingTwice:
    @pytest.mark.asyncio
    async def test_a_second_pass_adds_no_second_comment(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction, catalog
    ) -> None:
        """An acceptance's issue is deliberately left open, so "is it still
        open?" cannot tell a first pass from the four-hundredth. What is
        recorded is the statement already made."""
        repo_id = seed(client, admin_auth, run_compaction)
        finding_id = finding_ids(client, admin_auth, repo_id)["CWE-89"]
        groom(client, admin_auth, finding_id)
        client.patch(
            f"/api/dashboard/findings/{finding_id}/status",
            json={
                "status": "accepted_risk",
                "reason": "no vendor fix",
                "accepted_reason_code": "no_vendor_fix",
                "accepted_until": (utcnow().date() + timedelta(days=30)).isoformat(),
            },
            headers=admin_auth,
        )

        first = await sync(client, catalog)
        second = await sync(client, catalog)

        assert first.left_open == 1
        assert second.left_open == 0
        assert second.already_synced == 1
        assert len(the_issue(client)["comments"]) == 1


class TestWhatTheSweepLeavesAlone:
    @pytest.mark.asyncio
    async def test_an_open_finding_keeps_its_issue_untouched(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction, catalog
    ) -> None:
        repo_id = seed(client, admin_auth, run_compaction)
        finding_id = finding_ids(client, admin_auth, repo_id)["CWE-89"]
        groom(client, admin_auth, finding_id)

        result = await sync(client, catalog)

        assert (result.closed, result.left_open) == (0, 0)
        assert the_issue(client)["state"] == "open"
        assert the_issue(client).get("comments", []) == []

    @pytest.mark.asyncio
    async def test_a_story_whose_finding_the_lake_lost_is_reported_not_closed(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction, catalog
    ) -> None:
        """An issue is never closed on the absence of evidence. A story whose
        finding no longer has a row is a gap to name, not a resolution."""
        repo_id = seed(client, admin_auth, run_compaction)
        finding_id = finding_ids(client, admin_auth, repo_id)["CWE-89"]
        groom(client, admin_auth, finding_id)
        with client.app.state.db.session() as session:
            story = session.execute(select(GroomedStory)).scalars().one()
            story.subject_id = "a-finding-that-was-compacted-away"

        result = await sync(client, catalog)

        assert result.unknown_finding == 1
        assert the_issue(client)["state"] == "open"


class TestARecurrenceCommentsRatherThanFilingASecondIssue:
    """PCRE2 was filed four times, `gha-curl-pipe-shell` twice and
    `use-defused-xml` twice because issues were filed per *detection*. The
    identity linking two detections is `superseded_by` (spec 05 §5a) — a
    recorded fact, not a title match."""

    def _recurrence(self, client, admin_auth, run_compaction, catalog):
        repo_id = seed(
            client,
            admin_auth,
            run_compaction,
            findings=[
                finding_payload(),
                finding_payload(
                    rule_id="CWE-89-b",
                    file_path="orders/query_v2.py",
                    code_snippet="def get_order(order_id):\n    pass\n",
                ),
            ],
        )
        ids = finding_ids(client, admin_auth, repo_id)
        original, replacement = ids["CWE-89"], ids["CWE-89-b"]
        groom(client, admin_auth, original)
        # What carry-forward writes when the matched code changed under it.
        set_status(
            catalog,
            original,
            "status = ?, superseded_by = ?, resolved_at = ?",
            ["superseded", replacement, utcnow()],
        )
        return original, replacement

    @pytest.mark.asyncio
    async def test_no_second_issue_is_filed(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction, catalog
    ) -> None:
        original, replacement = self._recurrence(client, admin_auth, run_compaction, catalog)

        outcome = groom(client, admin_auth, replacement)

        assert outcome["created"] is False
        assert outcome["github_issue_number"] == 1
        assert len(client.app.state.github_factory.client.repos[REPO].issues) == 1
        comment = the_issue(client)["comments"][0]
        assert original in comment
        assert replacement in comment

    @pytest.mark.asyncio
    async def test_re_grooming_the_replacement_still_does_not_duplicate(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction, catalog
    ) -> None:
        """The second groom of the replacement finds its own stored row, so
        it updates — it must not comment a second time either."""
        _original, replacement = self._recurrence(client, admin_auth, run_compaction, catalog)

        groom(client, admin_auth, replacement)
        groom(client, admin_auth, replacement)

        assert len(client.app.state.github_factory.client.repos[REPO].issues) == 1
        assert len(the_issue(client)["comments"]) == 1

    @pytest.mark.asyncio
    async def test_a_closed_predecessor_issue_gets_a_new_one(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction, catalog
    ) -> None:
        """A recurrence must not be dropped into an issue nobody is looking
        at. "Already has an *open* issue" is read from GitHub, not assumed."""
        _original, replacement = self._recurrence(client, admin_auth, run_compaction, catalog)
        await client.app.state.github_factory.client.close_issue(REPO, 1)

        outcome = groom(client, admin_auth, replacement)

        assert outcome["created"] is True
        assert outcome["github_issue_number"] == 2


class TestTheRoutingSweepRunsIt:
    @pytest.mark.asyncio
    async def test_the_scheduled_pass_closes_a_stale_issue(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction, catalog
    ) -> None:
        """Wired into the pass that already files them: opening and closing
        the same backlog on two intervals is how the halves drift apart."""
        repo_id = seed(client, admin_auth, run_compaction)
        finding_id = finding_ids(client, admin_auth, repo_id)["CWE-89"]
        groom(client, admin_auth, finding_id)
        set_status(catalog, finding_id, "status = ?, resolved_at = ?", ["fixed", utcnow()])

        result = await route_open_findings(
            client.app.state.db,
            client.app.state.catalog,
            client.app.state.knowledge,
            client.app.state.github_factory,
        )

        assert result.issues_closed == 1
        assert result.failed == []
        assert the_issue(client)["state"] == "closed"


class TestTheCommentIsRenderedFromTheDisposition:
    def test_an_acceptance_never_renders_as_a_closure(self) -> None:
        """A pure check on the one sentence that must not drift: the
        acceptance comment has to say the issue is staying open."""
        from mykronos.groom import Disposition

        comment = render_disposition_comment(
            Disposition(
                finding_id="f1",
                status="accepted_risk",
                rule_id="CVE-2026-1",
                resolved_at=None,
                last_seen_at=None,
                last_seen_scan_run_id=None,
                accepted_until=date(2026, 10, 3),
                accepted_reason_code="no_vendor_fix",
                actor="alice",
                reason="mitigated at the edge",
            )
        )

        assert "Left open" in comment
        assert "2026-10-03" in comment
        assert "no_vendor_fix" in comment
        assert "Closing" not in comment
