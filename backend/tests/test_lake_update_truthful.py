"""A guarded no-op is not reported as updated (TheHub #60926).

`update_findings` returned every id it was handed, whether or not its
`only_if_status` guard let the row change. Every caller that read the result
inherited the lie: the reopen route's 409 could never fire on a race, and the
approval audit's `applied` flag said `true` for a disposition that did not
land - on a single finding and on every member of a cluster (#982).

These tests pin the result to what was written, and each caller to the result.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select

from mykronos.db.models import ApprovalRequest, AuditLogEntry
from mykronos.lake.mutate import locate_findings, update_findings
from tests.test_finding_disposition import _agent, _ask, _patch, _seed, _status
from tests.test_triage_clusters import REASON as CLUSTER_REASON
from tests.test_triage_clusters import seed_cluster, statuses


def _approve(client, admin_auth, request_id: str, digest: str):
    return client.post(
        f"/api/approvals/{request_id}/decisions",
        json={
            "verdict": "approve",
            "rationale": "Checked the agent's evidence against the raw record myself.",
            "evidence_digest": digest,
        },
        headers=admin_auth,
    )


def _approval_entries(client, request_id: str) -> list[dict[str, Any]]:
    with client.app.state.db.session() as session:
        entries = session.execute(
            select(AuditLogEntry).where(AuditLogEntry.action == "finding.status")
        ).scalars().all()
        return [
            dict(e.detail) | {"entity_id": e.entity_id}
            for e in entries
            if (e.detail or {}).get("approval_request_id") == request_id
        ]


class TestTheResultNamesOnlyRowsWritten:
    def test_a_guard_that_skips_the_row_reports_nothing(
        self, client, auth, run_compaction
    ) -> None:
        finding = _seed(client, auth, run_compaction, "medium")
        catalog = client.app.state.catalog

        outcome = update_findings(
            catalog,
            locate_findings(catalog, [finding]),
            "status = 'open'",
            [],
            only_if_status="false_positive",
        )

        assert outcome.updated == []
        assert outcome.count == 0
        assert outcome.partitions_written == 0, "nothing changed, nothing rewritten"
        assert _status(client, finding) == "open"

    def test_a_guard_that_matches_reports_the_row(self, client, auth, run_compaction) -> None:
        finding = _seed(client, auth, run_compaction, "medium")
        catalog = client.app.state.catalog

        outcome = update_findings(
            catalog,
            locate_findings(catalog, [finding]),
            "status = 'suppressed'",
            [],
            only_if_status="open",
        )

        assert outcome.updated == [finding]
        assert outcome.partitions_written == 1
        assert _status(client, finding) == "suppressed"

    def test_an_id_the_partition_does_not_hold_is_not_reported(
        self, client, auth, run_compaction
    ) -> None:
        finding = _seed(client, auth, run_compaction, "medium")
        catalog = client.app.state.catalog
        [(dt, _)] = locate_findings(catalog, [finding]).items()

        outcome = update_findings(
            catalog, {dt: [finding, "no-such-finding"]}, "status = 'suppressed'", []
        )

        assert outcome.updated == [finding]


class TestReopen:
    def test_a_finding_that_moved_before_the_write_is_a_409(
        self, client, auth, admin_auth, run_compaction, monkeypatch
    ) -> None:
        """The route read `false_positive`; by the write the finding is open
        again. The guarded update writes nothing, so the route must say so."""
        finding = _seed(client, auth, run_compaction, "high")
        from mykronos.api import dashboard

        real = dashboard.DashboardQueries.finding

        def stale(self, finding_id, *args, **kwargs):
            row = real(self, finding_id, *args, **kwargs)
            return None if row is None else {**row, "status": "false_positive"}

        monkeypatch.setattr(dashboard.DashboardQueries, "finding", stale)

        response = client.post(
            f"/api/dashboard/findings/{finding}/reopen",
            json={"reason": "Reopening a disposition that a scan already reversed."},
            headers=admin_auth,
        )

        assert response.status_code == 409, response.text
        with client.app.state.db.session() as session:
            reopened = session.execute(
                select(AuditLogEntry).where(AuditLogEntry.action == "finding.reopened")
            ).scalars().all()
            assert reopened == [], "a reopen that wrote nothing is not audited as one"


class TestTheApprovalAuditIsTruthful:
    def test_a_finding_dispositioned_while_the_request_waited_is_not_applied(
        self, client, auth, admin_auth, run_compaction
    ) -> None:
        finding = _seed(client, auth, run_compaction, "high")
        asked = _ask(client, _agent(client, admin_auth), finding)
        assert asked.status_code == 201, asked.text
        body = asked.json()
        # A person settles it another way while the request waits.
        assert _patch(client, admin_auth, finding, "suppressed").status_code == 200
        run_compaction()

        decided = _approve(
            client, admin_auth, body["approval_request_id"], body["evidence_digest"]
        )
        assert decided.status_code in (200, 201), decided.text
        run_compaction()

        assert _status(client, finding) == "suppressed", "the later decision stands"
        [entry] = _approval_entries(client, body["approval_request_id"])
        assert entry["applied"] is False

    def test_a_cluster_member_that_moved_is_not_applied_and_the_rest_are(
        self, client, admin_auth, run_compaction
    ) -> None:
        cluster_id = seed_cluster(client, admin_auth, run_compaction)
        agent = _agent(client, admin_auth)
        response = client.post(
            f"/api/dashboard/triage/clusters/{cluster_id}/disposition",
            json={"status": "false_positive", "reason": CLUSTER_REASON},
            headers=agent,
        )
        assert response.status_code == 200, response.text
        body = response.json()
        with client.app.state.db.session() as session:
            request_row = session.get(ApprovalRequest, body["approval_request_id"])
            assert request_row is not None
            digest = request_row.evidence_digest
        moved = sorted(statuses(client))[0]
        assert _patch(client, admin_auth, moved, "suppressed").status_code == 200
        run_compaction()

        decided = _approve(client, admin_auth, body["approval_request_id"], digest)
        assert decided.status_code in (200, 201), decided.text
        run_compaction()

        entries = {e["entity_id"]: e for e in _approval_entries(
            client, body["approval_request_id"]
        )}
        assert len(entries) == 3
        assert entries[moved]["applied"] is False
        assert all(e["applied"] is True for fid, e in entries.items() if fid != moved)
        assert statuses(client)[moved] == "suppressed"

