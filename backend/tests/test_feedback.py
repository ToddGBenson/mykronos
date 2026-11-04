"""The dashboard's Feedback button files a TheHub story (TheHub #61132).

It used to open a pre-filled issue on the platform's own GitHub repository,
which is public: whatever the operator typed - a path, a hostname, the name
of an internal repo - was one click from being published. Feedback now goes
to TheHub, the private system of record, through this server's own Hub
credential. There is no fallback: with no Hub configured the answer is
"feedback is unavailable", never a GitHub issue.
"""

from __future__ import annotations

import json
from typing import Any

import httpx2
from fastapi.testclient import TestClient

from mykronos import product_owner as po
from tests.po_support import audit_entries

URL = "/api/feedback"


class StoryHub:
    """A TheHub that accepts story creation and records every request."""

    def __init__(self, status: int = 201, body: Any = None) -> None:
        self.status = status
        self.body = body if body is not None else {"id": 70001, "bucket": "backlog"}
        self.calls: list[tuple[str, str, Any]] = []

    def handler(self, request: httpx2.Request) -> httpx2.Response:
        payload = json.loads(request.content) if request.content else None
        self.calls.append((request.method, request.url.path, payload))
        return httpx2.Response(self.status, json=self.body)


def _attach(client: TestClient, hub: StoryHub) -> None:
    client.app.state.hub = po.HubClient(  # type: ignore[attr-defined]
        "http://hub.test", "hub-secret", transport=httpx2.MockTransport(hub.handler)
    )


def _detach(client: TestClient) -> None:
    client.app.state.hub = None  # type: ignore[attr-defined]


def _report(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "kind": "bug",
        "summary": "The findings table loses its filter on refresh",
        "detail": "Filtered to critical, pressed F5, the filter was gone.",
        "page": "/repos/r-1/findings",
        "release": "0.1.0",
    }
    body.update(overrides)
    return body


def _agent(client: TestClient, admin_auth: dict[str, str]) -> dict[str, str]:
    minted = client.post(
        "/api/agents/credentials",
        json={"family": "claude-opus-5.5", "purpose": "feedback-test"},
        headers=admin_auth,
    )
    assert minted.status_code == 201, minted.text
    return {"Authorization": f"Bearer {minted.json()['token']}"}


class TestFiledToTheHub:
    def test_a_report_becomes_one_backlog_story_with_the_tags(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        hub = StoryHub()
        _attach(client, hub)

        r = client.post(URL, json=_report(), headers=admin_auth)

        assert r.status_code == 201, r.text
        assert r.json()["story_id"] == 70001
        assert [(m, p) for m, p, _ in hub.calls] == [("POST", "/api/dev/stories")]
        payload = hub.calls[0][2]
        assert payload["bucket"] == "backlog"
        assert {"repo:mykronos", "source:dashboard-feedback", "bug"} <= set(payload["tags"])
        assert payload["source_kind"] == "dashboard-feedback"
        assert payload["title"] == "The findings table loses its filter on refresh"
        assert "Filtered to critical" in payload["detail"]
        assert "/repos/r-1/findings" in payload["detail"]

    def test_a_request_is_tagged_feature(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        hub = StoryHub()
        _attach(client, hub)

        r = client.post(URL, json=_report(kind="feature"), headers=admin_auth)

        assert r.status_code == 201, r.text
        tags = set(hub.calls[0][2]["tags"])
        assert "feature" in tags and "bug" not in tags

    def test_the_answer_never_names_the_hub(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        """The browser learns the story number, not where TheHub lives."""
        _attach(client, StoryHub())

        r = client.post(URL, json=_report(), headers=admin_auth)

        assert "hub.test" not in r.text
        assert "hub-secret" not in r.text

    def test_status_says_available_when_a_hub_is_connected(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        _attach(client, StoryHub())

        r = client.get(URL, headers=admin_auth)

        assert r.status_code == 200
        assert r.json() == {"available": True, "reason": None}

    def test_every_filing_is_audited(self, client: TestClient, admin_auth: dict[str, str]) -> None:
        _attach(client, StoryHub())

        client.post(URL, json=_report(), headers=admin_auth)

        entries = audit_entries(client, "feedback.filed")
        assert len(entries) == 1
        assert entries[0].detail["outcome"] == "filed"
        assert entries[0].detail["story_id"] == 70001


class TestNoHubNoFeedback:
    def test_status_says_unavailable_with_a_reason(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        _detach(client)

        r = client.get(URL, headers=admin_auth)

        assert r.status_code == 200
        body = r.json()
        assert body["available"] is False
        assert "TheHub" in body["reason"]

    def test_a_report_is_a_503_that_says_feedback_is_unavailable(
        self, client: TestClient, admin_auth: dict[str, str], github: Any
    ) -> None:
        _detach(client)

        r = client.post(URL, json=_report(), headers=admin_auth)

        assert r.status_code == 503
        detail = r.json()["detail"]
        assert "Feedback is unavailable" in detail
        # Never "open a GitHub issue instead": the public repo is the leak.
        assert "github" not in detail.lower()
        assert audit_entries(client, "feedback.filed")[0].detail["outcome"] == "unavailable"


class TestHubRefusals:
    def test_a_refusal_is_a_502_with_its_reason(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        _attach(client, StoryHub(status=422, body={"detail": "title too short"}))

        r = client.post(URL, json=_report(), headers=admin_auth)

        assert r.status_code == 502
        assert "title too short" in r.json()["detail"]
        assert audit_entries(client, "feedback.filed")[0].detail["outcome"] == "refused"

    def test_a_hub_failure_is_a_502_without_its_body(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        _attach(client, StoryHub(status=500, body={"detail": "Traceback: secret"}))

        r = client.post(URL, json=_report(), headers=admin_auth)

        assert r.status_code == 502
        assert "Traceback" not in r.text

    def test_an_unreachable_hub_is_a_502(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        def boom(request: httpx2.Request) -> httpx2.Response:
            raise httpx2.ConnectError("refused", request=request)

        client.app.state.hub = po.HubClient(  # type: ignore[attr-defined]
            "http://hub.test", "hub-secret", transport=httpx2.MockTransport(boom)
        )

        r = client.post(URL, json=_report(), headers=admin_auth)

        assert r.status_code == 502
        assert "hub.test" not in r.text


class TestWhoMayFile:
    def test_a_viewer_is_refused_and_the_hub_hears_nothing(
        self, client: TestClient, viewer_auth: dict[str, str]
    ) -> None:
        hub = StoryHub()
        _attach(client, hub)

        r = client.post(URL, json=_report(), headers=viewer_auth)

        assert r.status_code == 403
        assert hub.calls == []

    def test_an_agent_is_refused_and_the_hub_hears_nothing(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        """Agents file to TheHub with their own credential, not the operator's
        dashboard button."""
        hub = StoryHub()
        _attach(client, hub)

        r = client.post(URL, json=_report(), headers=_agent(client, admin_auth))

        assert r.status_code == 403
        assert hub.calls == []

    def test_no_credential_is_a_401(self, client: TestClient) -> None:
        assert client.post(URL, json=_report()).status_code == 401
        assert client.get(URL).status_code == 401


class TestTheShape:
    def test_an_unknown_kind_is_a_422(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        _attach(client, StoryHub())

        assert client.post(URL, json=_report(kind="issue"), headers=admin_auth).status_code == 422

    def test_a_page_must_be_a_path_on_this_site(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        _attach(client, StoryHub())

        r = client.post(URL, json=_report(page="https://elsewhere.example/x"), headers=admin_auth)

        assert r.status_code == 422

    def test_the_summary_is_capped(self, client: TestClient, admin_auth: dict[str, str]) -> None:
        _attach(client, StoryHub())

        r = client.post(URL, json=_report(summary="x" * 201), headers=admin_auth)

        assert r.status_code == 422

    def test_unknown_fields_are_refused(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        """No caller-chosen tags or bucket: a report cannot land in the sprint."""
        _attach(client, StoryHub())

        r = client.post(URL, json=_report(bucket="sprint"), headers=admin_auth)

        assert r.status_code == 422
