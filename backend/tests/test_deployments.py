"""Is the artifact being reported on the artifact that is running? (#361)

THE DEFECT THIS PINS. On 2026-09-13 production ran an image built eight days
earlier while `repos_with_stale_scans` and `overdue_findings` both sat at 0.
Both measure how recently a repository was *scanned*. Nothing compared the
scanned revision to the deployed one, so twenty-six merged PRs sat undeployed
behind entirely green indicators.

`test_the_2026_09_13_situation_is_reported` is that day, reproduced.

The rest of this file is mostly about the states that are **not** divergence,
because that is where this kind of check goes wrong. A comparison that reports
"behind" whenever it cannot see one side produces an alarm on every repository
that has no deployment, and a check everybody mutes is worth less than no check
at all -- it is the pattern that made `oracle-gate` and the rotation warnings
worth fixing. So `matches_scan` is a three-state answer and most repositories
are honestly in the third state.
"""

from __future__ import annotations

import pytest

from mykronos.deployments import (
    NOT_CONFIGURED,
    OK,
    UNPARSED,
    UNREACHABLE,
    DeploymentState,
    ProbeSweep,
    _extract_revision,
    probe,
    sweep,
)

DEPLOYED = "61f1f13a2b8c4d5e6f7a8b9c0d1e2f3a4b5c6d7e"
SCANNED = "63714b61df3743b16ff72b4d1dc7f2c2011b4aed"


class FakeResponse:
    def __init__(self, status_code: int, payload=None, raises: bool = False) -> None:
        self.status_code = status_code
        self._payload = payload
        self._raises = raises

    def json(self):
        if self._raises:
            raise ValueError("not json")
        return self._payload


class FakeClient:
    """Stands in for `httpx2.AsyncClient` as an async context manager."""

    def __init__(self, response=None, error: Exception | None = None) -> None:
        self._response = response
        self._error = error

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc) -> bool:
        return False

    async def get(self, url: str):
        if self._error is not None:
            raise self._error
        return self._response


@pytest.fixture
def fake_http(monkeypatch):
    def _install(response=None, error=None):
        monkeypatch.setattr(
            "mykronos.deployments.httpx2.AsyncClient",
            lambda **kw: FakeClient(response, error),
        )

    return _install


class TestTheComparisonThatWasMissing:
    def test_the_2026_09_13_situation_is_reported(self) -> None:
        """The whole point. Production on one commit, newest scan on another.

        Both revisions are known, so there is nothing to excuse the difference:
        every finding on record for this repository describes code that is not
        serving traffic.
        """
        state = DeploymentState(
            repo_full_name="ToddGBenson/mykronos",
            status=OK,
            revision=DEPLOYED,
            scanned_revision=SCANNED,
        )

        assert state.matches_scan is False
        assert ProbeSweep(states=[state]).diverged == [state]

    def test_agreement_is_not_reported(self) -> None:
        state = DeploymentState(
            repo_full_name="ToddGBenson/mykronos",
            status=OK,
            revision=SCANNED,
            scanned_revision=SCANNED,
        )

        assert state.matches_scan is True
        assert ProbeSweep(states=[state]).diverged == []

    def test_an_abbreviated_revision_still_matches(self) -> None:
        """TheHub serves a 12-character sha; the lake records 40. Treating
        those as a divergence would report every deployment as wrong for ever,
        which is the false-alarm shape this check has to avoid to stay worth
        reading."""
        state = DeploymentState(
            repo_full_name="ToddGBenson/TheHub",
            status=OK,
            revision=SCANNED[:12],
            scanned_revision=SCANNED,
        )

        assert state.matches_scan is True


class TestCannotSayIsNotFalse:
    """Three states, because two would make this check unreadable."""

    def test_no_deployment_known(self) -> None:
        state = DeploymentState("r", status=NOT_CONFIGURED, scanned_revision=SCANNED)

        assert state.matches_scan is None

    def test_no_scan_known(self) -> None:
        """A repository onboarded but not yet scanned. Not a divergence."""
        state = DeploymentState("r", status=OK, revision=DEPLOYED)

        assert state.matches_scan is None

    def test_neither_known(self) -> None:
        assert DeploymentState("r").matches_scan is None

    def test_unknowns_are_counted_rather_than_dropped(self) -> None:
        """`diverged: 0` means nothing without the denominator beside it.

        Silently omitting the repositories that could not be measured is how
        "nothing is wrong" and "nothing was checked" become the same number,
        which is the reporting failure the whole issue is about.
        """
        result = ProbeSweep(
            states=[
                DeploymentState("a", status=OK, revision=DEPLOYED, scanned_revision=SCANNED),
                DeploymentState("b", status=NOT_CONFIGURED),
                DeploymentState("c", status=UNREACHABLE, scanned_revision=SCANNED),
            ]
        )

        assert len(result.diverged) == 1
        assert result.unknown == 2


class TestTheProbeContractIsNarrow:
    def test_it_reads_build_sha(self) -> None:
        assert _extract_revision({"build": {"sha": DEPLOYED}}) == DEPLOYED

    @pytest.mark.parametrize(
        "payload",
        [
            {"sha": DEPLOYED},  # top level, not under build
            {"build": {"commit": DEPLOYED}},  # right place, wrong key
            {"build": {"sha": ""}},
            {"build": {"sha": None}},
            {"build": "not-a-dict"},
            {"version": "0.1.0"},
            [],
            None,
        ],
    )
    def test_it_guesses_at_nothing(self, payload) -> None:
        """No fallback to anything commit-shaped found elsewhere in the body.

        An endpoint in another shape has not been taught to answer this
        question, and reporting that is more useful than inferring an answer —
        a confident wrong answer about what is deployed is the entire defect.
        """
        assert _extract_revision(payload) is None

    def test_whitespace_is_stripped_not_accepted(self) -> None:
        assert _extract_revision({"build": {"sha": f"  {DEPLOYED}  "}}) == DEPLOYED
        assert _extract_revision({"build": {"sha": "   "}}) is None


@pytest.mark.asyncio
class TestProbeStates:
    async def test_a_good_probe(self, fake_http) -> None:
        fake_http(FakeResponse(200, {"build": {"sha": DEPLOYED}}))

        status, revision, detail = await probe("http://host/healthz")

        assert (status, revision) == (OK, DEPLOYED)
        assert detail == ""

    async def test_a_connection_failure_is_unreachable(self, fake_http) -> None:
        fake_http(error=OSError("connection refused"))

        status, revision, detail = await probe("http://host/healthz")

        assert status == UNREACHABLE
        assert revision is None
        assert "could not be reached" in detail

    async def test_a_non_200_is_unreachable(self, fake_http) -> None:
        fake_http(FakeResponse(503))

        status, _, detail = await probe("http://host/healthz")

        assert status == UNREACHABLE
        assert "503" in detail

    async def test_a_non_json_body_is_unparsed(self, fake_http) -> None:
        fake_http(FakeResponse(200, raises=True))

        status, _, detail = await probe("http://host/healthz")

        assert status == UNPARSED
        assert "did not return JSON" in detail

    async def test_the_wrong_json_shape_is_unparsed(self, fake_http) -> None:
        """Distinct from `unreachable`: the deployment answered, it just did
        not answer *this* question. Those need different things done."""
        fake_http(FakeResponse(200, {"status": "ok", "version": "0.1.0"}))

        status, _, detail = await probe("http://host/healthz")

        assert status == UNPARSED
        assert "build.sha" in detail

    async def test_a_failed_probe_does_not_invent_a_revision(self, fake_http) -> None:
        fake_http(FakeResponse(500))

        _, revision, _ = await probe("http://host/healthz")

        assert revision is None


@pytest.mark.asyncio
class TestTheSweep:
    async def test_it_pairs_each_probe_with_what_was_scanned(self, fake_http) -> None:
        fake_http(FakeResponse(200, {"build": {"sha": DEPLOYED}}))

        result = await sweep(
            {"ToddGBenson/mykronos": "http://host/healthz"},
            {"ToddGBenson/mykronos": SCANNED},
        )

        assert len(result.states) == 1
        assert result.states[0].scanned_revision == SCANNED
        assert result.diverged

    async def test_an_unreachable_probe_records_no_observation_time(
        self, fake_http
    ) -> None:
        """`observed_at` means "when we last actually read a revision back".
        Stamping it on a failure would make a stale value look fresh."""
        fake_http(error=OSError("down"))

        result = await sweep({"r": "http://host/healthz"}, {})

        assert result.states[0].observed_at is None
        assert result.states[0].revision is None

    async def test_no_probes_configured_is_an_empty_sweep(self) -> None:
        result = await sweep({}, {SCANNED: SCANNED})

        assert result.states == []
        assert result.diverged == []


class TestTheEndpointSaysWhatItCannotSee:
    """`GET /api/dashboard/deployments`.

    Reads what the scheduled job recorded rather than probing live: the value
    is in the sweep running on a timer whether or not anybody opens the page,
    because the failure it catches is one nobody was looking for.
    """

    @staticmethod
    def _onboard(client, repo: str, **fields):
        from mykronos.db.models import Organization, RepoOnboarding

        owner = repo.split("/")[0]
        with client.app.state.db.session() as session:
            org = (
                session.query(Organization)
                .filter(Organization.github_org_login == owner)
                .one_or_none()
            )
            if org is None:
                org = Organization(github_org_login=owner)
                session.add(org)
                session.flush()
            session.add(
                RepoOnboarding(
                    org_id=org.id,
                    github_repo_full_name=repo,
                    github_installation_id=1,
                    status="active",
                    enabled_capabilities=["sast"],
                    default_branch="main",
                    **fields,
                )
            )
            session.commit()

    def test_a_repo_with_no_probe_is_listed_not_omitted(self, client, admin_auth) -> None:
        """The coverage number is the denominator that makes `diverged: 0`
        mean something. Dropping unprobed repositories from the response is
        how "nothing is wrong" and "nothing is measured" become identical."""
        self._onboard(client, "ToddGBenson/keel")

        body = client.get("/api/dashboard/deployments", headers=admin_auth).json()

        names = [r["repo_full_name"] for r in body["repos"]]
        assert "ToddGBenson/keel" in names
        assert body["not_configured"] >= 1
        row = next(r for r in body["repos"] if r["repo_full_name"] == "ToddGBenson/keel")
        assert row["status"] == "not_configured"
        assert row["matches_scan"] is None

    def test_a_recorded_revision_is_returned(self, client, admin_auth) -> None:
        self._onboard(
            client,
            "ToddGBenson/thehub",
            deployment_probe_url="http://hub/health",
            deployed_revision=DEPLOYED,
            deployment_probe_status=OK,
        )

        body = client.get("/api/dashboard/deployments", headers=admin_auth).json()

        row = next(r for r in body["repos"] if r["repo_full_name"] == "ToddGBenson/thehub")
        assert row["deployed_revision"] == DEPLOYED
        assert row["status"] == OK
        # No scan on record for this repo in this test, so the comparison
        # cannot be made — and says so rather than guessing.
        assert row["matches_scan"] is None

    def test_it_needs_a_credential(self, client) -> None:
        assert client.get("/api/dashboard/deployments").status_code == 401


class TestTheProbeCanActuallyBeConfigured:
    """#367 shipped the probe with no way to set its URL.

    `deployment_probe_url` was read in three places and written in none, so
    every repository reported `not_configured` for ever and the sweep had
    nothing to sweep. A control that exists and cannot run is the defect this
    platform keeps finding in other people's systems; this one was mine.
    """

    @staticmethod
    def _repo_id(client) -> str:
        from mykronos.db.models import Organization, RepoOnboarding

        with client.app.state.db.session() as session:
            org = Organization(github_org_login="ToddGBenson")
            session.add(org)
            session.flush()
            row = RepoOnboarding(
                org_id=org.id,
                github_repo_full_name="ToddGBenson/probe-me",
                github_installation_id=1,
                status="active",
                enabled_capabilities=["sast"],
                default_branch="main",
            )
            session.add(row)
            session.commit()
            return str(row.id)

    def test_setting_a_url_makes_the_repo_probeable(self, client, admin_auth) -> None:
        repo_id = self._repo_id(client)

        response = client.put(
            f"/api/repos/{repo_id}/deployment-probe",
            json={"probe_url": "http://hub.example/health"},
            headers=admin_auth,
        )

        assert response.status_code == 200
        from mykronos.deployments import probe_targets

        assert probe_targets(client.app.state.db) == {
            "ToddGBenson/probe-me": "http://hub.example/health"
        }

    def test_clearing_it_also_clears_what_was_read_through_it(
        self, client, admin_auth
    ) -> None:
        """A stale revision behind a removed probe would leave the portfolio
        asserting what a repository runs on the strength of a probe nobody is
        making."""
        from sqlalchemy import select

        from mykronos.db.models import RepoOnboarding

        repo_id = self._repo_id(client)
        client.put(
            f"/api/repos/{repo_id}/deployment-probe",
            json={"probe_url": "http://hub.example/health"},
            headers=admin_auth,
        )
        with client.app.state.db.session() as session:
            row = session.scalars(
                select(RepoOnboarding).where(RepoOnboarding.id == repo_id)
            ).one()
            row.deployed_revision = DEPLOYED
            row.deployment_probe_status = OK
            session.commit()

        client.put(
            f"/api/repos/{repo_id}/deployment-probe",
            json={"probe_url": ""},
            headers=admin_auth,
        )

        with client.app.state.db.session() as session:
            row = session.scalars(
                select(RepoOnboarding).where(RepoOnboarding.id == repo_id)
            ).one()
            assert row.deployed_revision is None
            assert row.deployment_probe_status == NOT_CONFIGURED

    def test_a_non_http_url_is_refused(self, client, admin_auth) -> None:
        repo_id = self._repo_id(client)

        response = client.put(
            f"/api/repos/{repo_id}/deployment-probe",
            json={"probe_url": "file:///etc/passwd"},
            headers=admin_auth,
        )

        assert response.status_code == 422

    def test_it_needs_a_credential(self, client) -> None:
        repo_id = self._repo_id(client)

        assert (
            client.put(
                f"/api/repos/{repo_id}/deployment-probe",
                json={"probe_url": "http://x/health"},
            ).status_code
            == 401
        )
