"""Asking the internet whether this platform is answering — spec 32 §8.

Written after an incident rather than before one. On 2026-08-29
`mykronos-backend` reported `healthy` for 22 hours while its host port was
unpublished: the process was fine, the frontend was fine — it reaches the
backend over the Docker network — and every scan upload from every pipeline
was failing with a 502 from the tunnel. Nothing said so, because nothing was
looking from outside.

**A container healthcheck cannot catch this**, by construction: it runs inside
the thing it is checking. Neither can a probe against `localhost`, which is
why the URL under test has to be the public one. That is the single property
these tests exist to pin.
"""

from __future__ import annotations

from typing import Any

import pytest

from mykronos import jobs
from mykronos.notify import Notification


class Recorder:
    def __init__(self) -> None:
        self.sent: list[Notification] = []

    async def send(self, note: Notification) -> bool:
        self.sent.append(note)
        return True


class FakeResponse:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code


class FakeClient:
    """Stands in for httpx2.AsyncClient, recording what was asked for."""

    requested: list[str] = []

    def __init__(self, *, behaviour: Any = 200, **_: Any) -> None:
        self._behaviour = behaviour

    async def __aenter__(self) -> FakeClient:
        return self

    async def __aexit__(self, *_: Any) -> None:
        return None

    async def get(self, url: str) -> FakeResponse:
        type(self).requested.append(url)
        if isinstance(self._behaviour, Exception):
            raise self._behaviour
        return FakeResponse(self._behaviour)


@pytest.fixture
def client_factory(monkeypatch):
    def install(behaviour: Any) -> None:
        FakeClient.requested = []
        monkeypatch.setattr(
            jobs.httpx2,
            "AsyncClient",
            lambda **kwargs: FakeClient(behaviour=behaviour, **kwargs),
        )

    return install


class TestReachable:
    @pytest.mark.asyncio
    async def test_a_200_is_reachable(self, client_factory) -> None:
        client_factory(200)
        notifier = Recorder()

        result = await jobs.check_public_reachability(
            "https://mykronos.example", notifier=notifier
        )

        assert result.reachable
        assert result.status_code == 200

    @pytest.mark.asyncio
    async def test_it_says_nothing_when_healthy(self, client_factory) -> None:
        """A channel that reports every successful minute is one nobody reads
        by the time it matters — the rule the netassess judgement follows."""
        client_factory(200)
        notifier = Recorder()

        await jobs.check_public_reachability("https://mykronos.example", notifier=notifier)

        assert notifier.sent == []


class TestTheUrlUnderTest:
    @pytest.mark.asyncio
    async def test_it_probes_the_public_url(self, client_factory) -> None:
        """The entire point. A localhost probe would have passed for every one
        of the 22 hours the ingestion API was unreachable, because the process
        was healthy the whole time — what was broken was the path to it."""
        client_factory(200)

        await jobs.check_public_reachability("https://mykronos.example")

        assert FakeClient.requested == ["https://mykronos.example/healthz"]

    @pytest.mark.asyncio
    async def test_a_trailing_slash_does_not_double_up(self, client_factory) -> None:
        client_factory(200)

        await jobs.check_public_reachability("https://mykronos.example/")

        assert FakeClient.requested == ["https://mykronos.example/healthz"]

    @pytest.mark.asyncio
    async def test_it_uses_healthz_not_the_ingestion_probe(
        self, client_factory
    ) -> None:
        """`/healthz` is exempt from the perimeter gate, so the check needs no
        credential and cannot fail for a reason of its own."""
        client_factory(200)

        await jobs.check_public_reachability("https://mykronos.example")

        assert FakeClient.requested[0].endswith("/healthz")


class TestUnreachable:
    @pytest.mark.asyncio
    async def test_a_502_is_not_reachable(self, client_factory) -> None:
        """The exact shape of the real incident: Cloudflare answering, the
        origin behind it not."""
        client_factory(502)
        notifier = Recorder()

        result = await jobs.check_public_reachability(
            "https://mykronos.example", notifier=notifier
        )

        assert not result.reachable
        assert result.status_code == 502
        assert "502" in result.detail

    @pytest.mark.asyncio
    async def test_a_connection_failure_is_not_reachable(
        self, client_factory
    ) -> None:
        client_factory(OSError("connection refused"))

        result = await jobs.check_public_reachability("https://mykronos.example")

        assert not result.reachable
        assert result.status_code is None
        assert "could not be reached" in result.detail

    @pytest.mark.asyncio
    async def test_it_is_critical(self, client_factory) -> None:
        """While this is false, every scan upload from every pipeline is
        failing and nothing else will say so. The dashboard keeps serving,
        which is what makes it dangerous rather than obvious."""
        client_factory(502)
        notifier = Recorder()

        await jobs.check_public_reachability("https://mykronos.example", notifier=notifier)

        assert len(notifier.sent) == 1
        assert notifier.sent[0].level == "critical"
        assert "not reachable" in notifier.sent[0].title

    @pytest.mark.asyncio
    async def test_it_warns_that_the_dashboard_will_look_fine(
        self, client_factory
    ) -> None:
        """The detail that turns a confusing alert into an actionable one:
        somebody checking the dashboard will see a working system."""
        client_factory(502)
        notifier = Recorder()

        await jobs.check_public_reachability("https://mykronos.example", notifier=notifier)

        assert "Docker network" in notifier.sent[0].detail

    @pytest.mark.asyncio
    async def test_no_notifier_is_not_a_crash(self, client_factory) -> None:
        """It runs unattended. A deployment with no Slack webhook must still
        get the result, and the CLI still exits non-zero on it."""
        client_factory(502)

        result = await jobs.check_public_reachability("https://mykronos.example")

        assert not result.reachable


class TestTheAlertCorroboratesBeforeClaimingLoss:
    """"Findings are being lost now" is sent at level="critical", on a schedule.

    It was asserted from the one vantage point that cannot establish it. A host
    inside this network reaches its own public hostname through hairpin NAT,
    which does not work here.

    MEASURED 2026-09-12. `mykronos.toddbenson.net/healthz` was unreachable from
    the backend container AND from the host, while GitHub Actions runs
    34683969779 and 34683887120 had uploaded at 08:43 and 08:41 that morning.
    Both carry a `github_workflow_run_id`, so both came from a GitHub-hosted
    runner — which cannot reach 192.168.0.14, so they went through the public
    URL. It was working for the callers that matter.

    The check is still right that the URL cannot be reached from here. It was
    the consequence that needed evidence, and a critical alert that is wrong is
    how a real outage stops being believed.
    """

    def test_a_recent_upload_replaces_the_loss_claim(self) -> None:
        body = jobs.reachability_alert("gone away", 4.9)

        assert "hairpin NAT" in body
        assert "Check from outside" in body
        assert "being lost now" not in body

    def test_a_stale_estate_keeps_the_stronger_wording(self) -> None:
        body = jobs.reachability_alert("gone away", 30.0)

        assert "findings are being lost now" in body
        assert "No GitHub Actions upload for 30.0h" in body, (
            "the corroborating fact belongs in the alert, not just the alarm"
        )

    def test_no_evidence_is_not_reassurance(self) -> None:
        """`None` means nothing corroborates either way.

        An unreadable lake means this job knows less than it did, which is not
        the same as nothing being wrong — so the alarm stands, with nothing
        appended, because there is no corroborating fact to offer.
        """
        body = jobs.reachability_alert("gone away", None)

        assert "findings are being lost now" in body
        assert "No GitHub Actions upload" not in body

    def test_the_boundary_is_inclusive(self) -> None:
        """The grace period decides between two opposite sentences, so it must
        not flip on a rounding error at its own edge."""
        assert "hairpin" in jobs.reachability_alert("x", jobs.ACTIONS_UPLOAD_GRACE_HOURS)
        assert "being lost" in jobs.reachability_alert(
            "x", jobs.ACTIONS_UPLOAD_GRACE_HOURS + 0.1
        )

    @pytest.mark.asyncio
    async def test_the_notification_carries_the_corroborated_body(
        self, client_factory
    ) -> None:
        """End to end: the wording has to reach Slack, not just exist."""
        client_factory(503)
        notifier = Recorder()

        await jobs.check_public_reachability(
            "https://mykronos.example",
            notifier=notifier,
            hours_since_actions_upload=4.9,
        )

        [sent] = notifier.sent
        assert sent.level == "critical", "an unreachable URL is still worth waking for"
        assert "hairpin NAT" in sent.detail
        assert "being lost now" not in sent.detail

    @pytest.mark.asyncio
    async def test_the_default_is_unchanged(self, client_factory) -> None:
        """Every existing caller passes nothing and must be unaffected."""
        client_factory(503)
        notifier = Recorder()

        await jobs.check_public_reachability(
            "https://mykronos.example", notifier=notifier
        )

        [sent] = notifier.sent
        assert "findings are being lost now" in sent.detail
