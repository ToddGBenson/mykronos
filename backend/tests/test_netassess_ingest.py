"""Pushing a network-assessment run to Mykronos — spec 32 §4.4.

The judgement itself is tested in `test_netassess.py` against the pure
functions. This is the contract around it: who may push, what gets stored, and
which runs are worth waking somebody for.

The design decision the whole endpoint rests on is push rather than pull. The
scan runs on Windows because a container cannot see LAN MAC addresses — an
nmap sweep from one reported all 256 addresses of a /24 as up while the host's
ARP table had 38 — and the publisher that archives it already runs there.
Polling an object store instead would mean an S3 client the backend does not
otherwise need and credentials it does not otherwise hold, to learn about an
event somebody could simply report.
"""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from mykronos.db.models import NetassessRun
from tests.conftest import REPO, issue_token

INVENTORY = (
    "address,mac,label\n"
    "192.168.0.1,AA:BB:CC:00:00:01,router\n"
    "192.168.0.14,AA:BB:CC:00:00:02,nas\n"
)
CLEAN = "# Network status\n\nNFS: no exports\nSMB: SMBv2 only\n"


def _push(client: TestClient, token: str, **body: Any):
    payload = {
        "run_key": "netassess-2026.8.28.zip",
        "inventory_csv": INVENTORY,
        "network_status_md": CLEAN,
        **body,
    }
    return client.post(
        "/api/ingest/netassess",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )


class TestAuth:
    def test_no_token_is_401(self, client: TestClient) -> None:
        response = client.post("/api/ingest/netassess", json={"run_key": "x"})

        assert response.status_code == 401

    def test_the_network_grant_is_required(self, client: TestClient) -> None:
        """Unlike a lane failure, this *is* a capability — the one spec 14
        defines — so what may write it is what the grant says."""
        token = issue_token(client, REPO)  # no grants

        response = _push(client, token)

        assert response.status_code == 403

    def test_a_granted_repo_may_push(self, client: TestClient) -> None:
        token = issue_token(client, REPO, "network")

        assert _push(client, token).status_code == 200


class TestJudgement:
    def test_a_clean_run_is_believable(self, client: TestClient) -> None:
        token = issue_token(client, REPO, "network")

        body = _push(client, token).json()

        assert body["believable"] is True
        assert body["host_count"] == 2
        assert body["problems"] == []

    def test_an_unknown_line_fails_the_run(self, client: TestClient) -> None:
        """The degradation case: the task still writes a report every week
        while the checks inside it no longer run."""
        token = issue_token(client, REPO, "network")

        body = _push(
            client, token, network_status_md="NFS: unknown (scan failed)\n"
        ).json()

        assert body["believable"] is False
        assert any("did not run" in p for p in body["problems"])

    def test_a_second_run_diffs_against_the_first(self, client: TestClient) -> None:
        """The reason anything is stored at all. The Concourse task fetched the
        previous archive from MinIO to get this, which was the one thing making
        it need an object store."""
        token = issue_token(client, REPO, "network")
        _push(client, token)

        body = _push(
            client,
            token,
            run_key="netassess-2026.9.4.zip",
            inventory_csv=INVENTORY + "192.168.0.99,AA:BB:CC:00:00:03,laptop\n",
        ).json()

        assert body["hosts_appeared"] == ["192.168.0.99 laptop"]
        assert body["hosts_disappeared"] == []

    def test_a_first_run_has_nothing_to_diff(self, client: TestClient) -> None:
        token = issue_token(client, REPO, "network")

        body = _push(client, token).json()

        assert body["hosts_appeared"] == []
        assert "No earlier run" in body["detail"]


class TestStorage:
    def test_the_run_is_recorded(self, client: TestClient) -> None:
        token = issue_token(client, REPO, "network")

        _push(client, token)

        with client.app.state.db.session() as session:
            row = session.get(NetassessRun, REPO)
        assert row is not None
        assert row.run_key == "netassess-2026.8.28.zip"
        assert row.run_date is not None
        assert row.believable is True

    def test_a_bad_run_is_still_recorded(self, client: TestClient) -> None:
        """"The last scan was bad" is exactly what the freshness check needs.
        Discarding it would make a degraded scanner look like a silent one."""
        token = issue_token(client, REPO, "network")

        _push(client, token, network_status_md="NFS: unknown (scan failed)\n")

        with client.app.state.db.session() as session:
            row = session.get(NetassessRun, REPO)
        assert row is not None
        assert row.believable is False

    def test_one_row_superseded_by_the_next(self, client: TestClient) -> None:
        """Current state, not history. The archive in MinIO is the history."""
        token = issue_token(client, REPO, "network")
        _push(client, token)
        _push(client, token, run_key="netassess-2026.9.4.zip")

        with client.app.state.db.session() as session:
            rows = session.query(NetassessRun).all()
        assert len(rows) == 1
        assert rows[0].run_key == "netassess-2026.9.4.zip"
