"""Reporting a CI lane that failed with nothing to upload — spec 32 §11 q6.

Concourse put `on_failure: *slack_alert` on every job. On Actions most lanes
need no equivalent, because `mykronos.upload` registers a ScanRun before it
interprets anything and finalises in a `finally` — so a failed scan already
reaches Slack through `/scan-run`, and `test_ingest_api.py` covers that.

What it *sends* is asserted in `test_notify.py`, beside every other
notification decision. What is here is the contract around it.

This is for the two cases that path cannot reach: a lane with nothing to
upload (`delivery.yml` builds and publishes and produces no findings by
design), and a lane that died before its upload step ever ran.

The property most worth pinning is the negative one. **Nothing may reach the
lake.** A build failure is not a finding, has no severity, and must not touch
a risk score — D-046's rule about test lanes, one step further out. An
endpoint that quietly wrote a row would put "the publish step broke" into the
same number as an unauthenticated RCE.
"""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from tests.conftest import REPO, issue_token


def _post(client: TestClient, token: str, **body: Any):
    payload = {"lane": "publish", **body}
    return client.post(
        "/api/ingest/lane-failure",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )


class TestAuth:
    def test_no_token_is_401(self, client: TestClient) -> None:
        response = client.post("/api/ingest/lane-failure", json={"lane": "publish"})

        assert response.status_code == 401

    def test_a_bad_token_is_401(self, client: TestClient) -> None:
        response = _post(client, "not-a-real-token")

        assert response.status_code == 401

    def test_no_capability_grant_is_needed(self, client: TestClient) -> None:
        """A lane failure is not a capability.

        Requiring a grant would mean a repository could not report that its
        build broke until somebody granted it something unrelated — and
        `delivery.yml`, the lane this exists for, produces no capability at
        all.
        """
        token = issue_token(client, REPO)  # deliberately no grants

        response = _post(client, token)

        assert response.status_code == 200


class TestValidation:
    def test_an_unknown_field_is_refused(self, client: TestClient) -> None:
        """`extra="forbid"`, as everywhere else on this API. A typo'd field
        silently ignored is a caller that thinks it sent something it did
        not."""
        token = issue_token(client, REPO)

        response = _post(client, token, severity="critical")

        assert response.status_code == 422

    def test_a_non_http_run_url_is_refused(self, client: TestClient) -> None:
        token = issue_token(client, REPO)

        response = _post(client, token, run_url="javascript:alert(1)")

        assert response.status_code == 422


class TestWritesNothing:
    def test_no_scan_run_is_recorded(self, client: TestClient) -> None:
        """The negative property this endpoint exists under.

        A build failure is not evidence about a repository's security posture.
        If it landed as a ScanRun the coverage cross-check would start seeing
        lanes that never scanned anything, and a risk score would move because
        a registry was briefly unreachable.
        """
        token = issue_token(client, REPO)
        buffer = client.app.state.buffer
        before = buffer.count_sealed()

        _post(client, token, detail="docker push returned 403")

        assert buffer.count_sealed() == before

    def test_the_response_says_so(self, client: TestClient) -> None:
        token = issue_token(client, REPO)

        body = _post(client, token).json()

        assert "Nothing was written to the lake" in body["detail"]
