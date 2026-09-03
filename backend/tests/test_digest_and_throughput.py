"""The weekly digest and the throughput panel (spec 27 §4, §5).

The property doing most of the work: an empty digest is not sent, and a
digest that only ever lists obligations is one people stop opening. What
closed — and whether it was *verified* closed — is why the rest gets read.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any

from fastapi.testclient import TestClient

from mykronos import digest
from mykronos.lake.catalog import Catalog
from mykronos.lake.mutate import locate_findings, update_findings
from mykronos.maturity import throughput
from mykronos.schemas import utcnow
from tests.conftest import REPO, finding_payload, post_findings, post_scan


class Recorder:
    def __init__(self) -> None:
        self.sent: list[Any] = []

    def send(self, notification: Any) -> None:
        self.sent.append(notification)


def seed(
    client: TestClient, auth: dict[str, str], run_compaction: Any, count: int = 1
) -> list[str]:
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


def set_owner(catalog: Catalog, finding_ids: list[str], owner: str) -> None:
    update_findings(
        catalog, locate_findings(catalog, finding_ids), "owner = ?, owner_source = ?",
        [owner, "codeowners"],
    )


class TestTheDigest:
    def test_an_owner_with_nothing_gets_nothing(
        self, client: TestClient, auth, catalog: Catalog, run_compaction
    ) -> None:
        """An empty weekly message is a training exercise in ignoring weekly
        messages."""
        seed(client, auth, run_compaction, count=0)

        assert digest.build(catalog) == []

    def test_findings_that_fell_to_the_account_are_addressed_to_it(
        self, client: TestClient, auth, catalog: Catalog, run_compaction
    ) -> None:
        """Previously these reached nobody, which was the point of B-034.

        Ownership now falls to the account the repository belongs to when
        CODEOWNERS is readable and matches nothing, so the digest has somewhere
        to send them. The weakness travels with the answer — `owner_source` is
        `repo_owner`, not `codeowners` — but a weekly message somebody can
        reassign beats work addressed to no one.
        """
        seed(client, auth, run_compaction, count=3)

        digests = digest.build(catalog)

        assert [d.owner for d in digests] == ["example-org"]
        assert digests[0].top_unclaimed, "the account's queue is what it is sent"

    def test_an_overdue_finding_reaches_its_owner(
        self, client: TestClient, auth, catalog: Catalog, run_compaction
    ) -> None:
        ids = seed(client, auth, run_compaction)
        set_owner(catalog, ids, "@org/payments")
        update_findings(
            catalog, locate_findings(catalog, ids), "due_at = ?", [datetime(2020, 1, 1)]
        )

        [built] = digest.build(catalog)

        assert built.owner == "@org/payments"
        assert len(built.newly_overdue) == 1

    def test_two_owners_get_two_digests(
        self, client: TestClient, auth, catalog: Catalog, run_compaction
    ) -> None:
        ids = seed(client, auth, run_compaction, count=2)
        set_owner(catalog, [ids[0]], "@org/payments")
        set_owner(catalog, [ids[1]], "@org/frontend")

        owners = {d.owner for d in digest.build(catalog)}

        assert owners == {"@org/payments", "@org/frontend"}

    def test_a_snoozed_finding_is_not_chased(
        self, client: TestClient, auth, catalog: Catalog, run_compaction
    ) -> None:
        """It was deferred deliberately, with a reason and a date. Chasing it
        weekly is how a snooze stops meaning anything."""
        from mykronos import worklist

        ids = seed(client, auth, run_compaction)
        set_owner(catalog, ids, "@org/payments")
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            state = worklist.snooze(
                session,
                ids[0],
                REPO,
                until=utcnow().date() + timedelta(days=5),
                reason="next sprint",
            )

        built = digest.build(catalog, states={ids[0]: state})

        assert built == []

    def test_closures_alone_are_worth_a_message(
        self, client: TestClient, auth, catalog: Catalog, run_compaction
    ) -> None:
        """"The four things you fixed last week are verified gone" is the
        message that makes the others get read."""
        ids = seed(client, auth, run_compaction)
        set_owner(catalog, ids, "@org/payments")
        update_findings(
            catalog,
            locate_findings(catalog, ids),
            "status = 'fixed', resolved_at = ?",
            [utcnow()],
        )

        [built] = digest.build(catalog)

        assert built.closed_last_week == 1
        assert built.newly_overdue == []

    def test_the_message_says_when_nothing_was_verified(
        self, client: TestClient, auth, catalog: Catalog, run_compaction
    ) -> None:
        """Closed and verified-closed are different claims, and the digest
        must not let one read as the other."""
        ids = seed(client, auth, run_compaction)
        set_owner(catalog, ids, "@org/payments")
        update_findings(
            catalog,
            locate_findings(catalog, ids),
            "status = 'fixed', resolved_at = ?",
            [utcnow()],
        )

        [built] = digest.build(catalog)
        message = digest.render(built)

        assert "none confirmed removed" in message.detail

    def test_an_overdue_digest_is_loud(
        self, client: TestClient, auth, catalog: Catalog, run_compaction
    ) -> None:
        ids = seed(client, auth, run_compaction)
        set_owner(catalog, ids, "@org/payments")
        update_findings(
            catalog, locate_findings(catalog, ids), "due_at = ?", [datetime(2020, 1, 1)]
        )

        message = digest.render(digest.build(catalog)[0])

        assert message.level == "critical"

    def test_send_all_sends_one_per_owner(
        self, client: TestClient, auth, catalog: Catalog, run_compaction
    ) -> None:
        ids = seed(client, auth, run_compaction, count=2)
        set_owner(catalog, [ids[0]], "@org/payments")
        set_owner(catalog, [ids[1]], "@org/frontend")
        recorder = Recorder()

        sent = digest.send_all(catalog, recorder)

        assert sent == 2
        assert len(recorder.sent) == 2

    def test_a_long_list_is_summarised_not_dumped(
        self, client: TestClient, auth, catalog: Catalog, run_compaction
    ) -> None:
        """A digest that lists everything is a report, and a report is what
        the queue already is."""
        ids = seed(client, auth, run_compaction, count=9)
        set_owner(catalog, ids, "@org/payments")

        message = digest.render(digest.build(catalog)[0])

        assert "and 4 more" in message.detail


class TestThroughput:
    def test_an_empty_lake_reports_zeroes(self, catalog: Catalog) -> None:
        result = throughput(catalog)
        assert result["this_week"]["opened"] == 0
        assert result["net"] == 0

    def test_it_counts_what_opened_this_week(
        self, client: TestClient, auth, catalog: Catalog, run_compaction
    ) -> None:
        seed(client, auth, run_compaction, count=3)

        assert throughput(catalog)["this_week"]["opened"] == 3

    def test_a_dismissal_is_not_a_closure(
        self, client: TestClient, auth, admin_auth, catalog: Catalog, run_compaction
    ) -> None:
        """Letting dismissals count would make the fastest way to improve this
        number a click."""
        ids = seed(client, auth, run_compaction)
        client.patch(
            f"/api/dashboard/findings/{ids[0]}/status",
            json={"status": "false_positive", "reason": "generated code"},
            headers=admin_auth,
        )

        assert throughput(catalog)["this_week"]["closed"] == 0

    def test_a_fix_is(
        self, client: TestClient, auth, catalog: Catalog, run_compaction
    ) -> None:
        ids = seed(client, auth, run_compaction)
        update_findings(
            catalog,
            locate_findings(catalog, ids),
            "status = 'fixed', resolved_at = ?",
            [utcnow()],
        )

        assert throughput(catalog)["this_week"]["closed"] == 1

    def test_net_is_stated_rather_than_left_to_the_reader(
        self, client: TestClient, auth, catalog: Catalog, run_compaction
    ) -> None:
        """A week that closed forty and opened forty-five did not have a good
        week."""
        seed(client, auth, run_compaction, count=5)

        assert throughput(catalog)["net"] == 5

    def test_verified_is_reported_separately(
        self, client: TestClient, auth, catalog: Catalog, run_compaction
    ) -> None:
        ids = seed(client, auth, run_compaction)
        client.app.state.buffer.append(  # type: ignore[attr-defined]
            "remediation_events",
            [
                {
                    "event_id": "e1",
                    "repo_full_name": REPO,
                    "finding_id": ids[0],
                    "toxic_combination_id": None,
                    "contributing_finding_ids": json.dumps([]),
                    "pipeline_stage_reached": "pr_opened",
                    "triage_classification": "true_positive",
                    "fix_pr_number": 1,
                    "fix_pr_url": None,
                    "pr_status": "merged",
                    "rationale": "pinned",
                    "fixer_name": "python-pin",
                    "rejection_reason_code": None,
                    "rejection_reason": None,
                    "verification_commit_sha": "abc",
                    "verification_dispatched_at": utcnow(),
                    "verification_scan_run_id": "v1",
                    "verification_outcome": "verified_fixed",
                    "verified_at": utcnow(),
                    "time_to_verified_seconds": 60,
                    "created_at": utcnow(),
                    "updated_at": utcnow(),
                }
            ],
        )
        run_compaction()

        assert throughput(catalog)["this_week"]["verified"] == 1

    def test_the_endpoint_serves_it(
        self, client: TestClient, auth, admin_auth, run_compaction
    ) -> None:
        seed(client, auth, run_compaction, count=2)

        body = client.get("/api/dashboard/triage/throughput", headers=admin_auth).json()

        assert body["this_week"]["opened"] == 2
        assert "dismissal is not a closure" in body["note"]
