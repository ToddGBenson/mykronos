"""Reading Concourse back (spec 15 §4a).

The failure this guards against is not a wrong link. It is a panel that says
nothing when Concourse is down and says the same nothing when a repository has
no pipeline — because then nobody can tell "we do not scan this here" from "the
CI server is restarting", and a panel that cannot distinguish those gets
ignored.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from mykronos.ci import (
    ALL_STAGES,
    ConcourseClient,
    JobStatus,
    coverage,
    pipeline_name_for,
    reconcile,
)


class FakeResponse:
    def __init__(self, payload: object, status: int = 200) -> None:
        self._payload = payload
        self.status = status

    def raise_for_status(self) -> None:
        if self.status >= 400:
            raise RuntimeError(f"HTTP {self.status}")

    def json(self) -> object:
        return json.loads(json.dumps(self._payload))


@pytest.fixture
def concourse(monkeypatch):
    """A ConcourseClient wired to a scripted API, keyed by path suffix."""

    routes: dict[str, object] = {}

    def fake_get(url: str, timeout: float = 0) -> FakeResponse:
        for suffix, payload in routes.items():
            if url.endswith(suffix):
                if isinstance(payload, Exception):
                    raise payload
                return FakeResponse(payload)
        return FakeResponse(None, status=404)

    monkeypatch.setattr("mykronos.ci.httpx2.get", fake_get)
    client = ConcourseClient(
        "http://concourse:8080", team="main", external_url="http://localhost:8080"
    )
    return client, routes


JOBS = [
    {
        "name": "unit",
        "finished_build": {
            "name": "8",
            "status": "succeeded",
            "end_time": 1786602220,
        },
    },
    {
        "name": "sast",
        "finished_build": {"name": "5", "status": "failed", "end_time": 1786602300},
    },
    {"name": "deploy"},
]


class TestPipelineNaming:
    def test_the_pipeline_is_the_repo_name_lowercased(self) -> None:
        assert pipeline_name_for("ToddGBenson/TheHub") == "thehub"
        assert pipeline_name_for("ToddGBenson/mykronos") == "mykronos"
        assert pipeline_name_for("ToddGBenson/personal-soc") == "personal-soc"


class TestStatus:
    def test_jobs_carry_a_link_to_their_last_build(self, concourse) -> None:
        client, routes = concourse
        routes["/api/v1/pipelines"] = [{"name": "mykronos"}]
        routes["/pipelines/mykronos/jobs"] = JOBS

        status = client.status_for("ToddGBenson/mykronos")

        assert status.pipeline == "mykronos"
        assert status.url == "http://localhost:8080/teams/main/pipelines/mykronos"
        unit = status.jobs[0]
        assert unit.status == "succeeded"
        assert unit.build_url == (
            "http://localhost:8080/teams/main/pipelines/mykronos/jobs/unit/builds/8"
        )

    def test_the_link_uses_the_browser_url_not_the_internal_one(self, concourse) -> None:
        """These genuinely differ: this process reaches Concourse by container
        name on a shared network, and a person reaches it on localhost. A link
        to http://concourse:8080 resolves nowhere from a laptop."""
        client, routes = concourse
        routes["/api/v1/pipelines"] = [{"name": "mykronos"}]
        routes["/pipelines/mykronos/jobs"] = JOBS

        status = client.status_for("ToddGBenson/mykronos")

        assert "concourse:8080" not in (status.url or "")

    def test_failing_jobs_are_named(self, concourse) -> None:
        client, routes = concourse
        routes["/api/v1/pipelines"] = [{"name": "mykronos"}]
        routes["/pipelines/mykronos/jobs"] = JOBS

        assert client.status_for("ToddGBenson/mykronos").failing == ["sast"]

    def test_a_job_that_never_ran_is_neither_pass_nor_fail(self, concourse) -> None:
        client, routes = concourse
        routes["/api/v1/pipelines"] = [{"name": "mykronos"}]
        routes["/pipelines/mykronos/jobs"] = JOBS

        deploy = client.status_for("ToddGBenson/mykronos").jobs[2]

        assert deploy.status is None
        assert deploy.build_url is None

    def test_a_repo_with_no_pipeline_says_which_ci_does_scan_it(self, concourse) -> None:
        """keel is in exactly this state: onboarded, scanned by Actions, and
        absent from Concourse. An empty panel would read as a coverage gap."""
        client, routes = concourse
        routes["/api/v1/pipelines"] = [{"name": "mykronos"}]

        status = client.status_for("ToddGBenson/keel")

        assert status.pipeline is None
        assert "No Concourse pipeline named 'keel'" in (status.unavailable or "")
        assert "GitHub Actions" in (status.unavailable or "")

    def test_an_unreachable_concourse_is_a_different_answer(self, concourse) -> None:
        """The distinction this whole module exists to preserve."""
        client, routes = concourse
        routes["/api/v1/pipelines"] = RuntimeError("connection refused")

        status = client.status_for("ToddGBenson/keel")

        assert "did not answer" in (status.unavailable or "")
        assert "No Concourse pipeline" not in (status.unavailable or "")

    def test_an_unreachable_concourse_never_raises(self, concourse) -> None:
        """A page about findings must not fail because a CI server restarted."""
        client, routes = concourse
        routes["/api/v1/pipelines"] = [{"name": "mykronos"}]
        routes["/pipelines/mykronos/jobs"] = TimeoutError("timed out")

        status = client.status_for("ToddGBenson/mykronos")

        assert status.pipeline == "mykronos"
        assert status.jobs == []
        assert status.unavailable is not None

    def test_no_concourse_configured_is_not_an_error(self) -> None:
        status = ConcourseClient("").status_for("ToddGBenson/mykronos")

        assert status.unavailable == "No Concourse is configured for this deployment."


class TestReporting:
    """A green pipeline and a stale capability used to be two facts on two
    pages that never contradicted each other. The sast lane failed on every
    run for a day and the dashboard simply showed sast as un-scanned."""

    @staticmethod
    def _job(name, status="succeeded", finished=None):
        return JobStatus(
            name=name,
            status=status,
            build_name="1",
            build_url="http://x",
            finished_at=finished,
        )

    def test_a_job_that_reported_is_reporting(self) -> None:
        built = datetime(2026, 8, 13, 12, 0, tzinfo=UTC)
        scanned = datetime(2026, 8, 13, 11, 58, tzinfo=UTC)

        [row] = reconcile([self._job("sast", finished=built)], {"sast": scanned})

        assert row.state == "reporting"

    def test_a_job_that_uploads_two_capabilities_is_checked_for_both(self) -> None:
        """demo-and-dast proxies the functional suite through ZAP and then
        scans: one build, two uploads. Crediting it to only `functional` left
        `dast` reading no_job forever - enabled, produced by a real lane, and
        reported as a permanent gap."""
        built = datetime(2026, 8, 13, 12, 0, tzinfo=UTC)
        scanned = datetime(2026, 8, 13, 11, 58, tzinfo=UTC)

        rows = reconcile(
            [self._job("demo-and-dast", finished=built)],
            {"functional": scanned, "dast": scanned},
        )

        assert {r.capability for r in rows} == {"functional", "dast"}
        assert all(r.state == "reporting" for r in rows)

    def test_one_capability_reporting_does_not_vouch_for_the_other(self) -> None:
        """The functional upload can land while the DAST upload fails - they
        are separate requests. Each capability answers for itself."""
        built = datetime(2026, 8, 13, 12, 0, tzinfo=UTC)

        rows = reconcile(
            [self._job("demo-and-dast", finished=built)],
            {"functional": datetime(2026, 8, 13, 11, 58, tzinfo=UTC)},
        )
        by_capability = {r.capability: r.state for r in rows}

        assert by_capability["functional"] == "reporting"
        assert by_capability["dast"] == "never_reported"

    def test_a_job_that_ran_after_the_newest_scan_is_silent(self) -> None:
        """The scan run predates the build, so this build's findings never
        arrived. Green pipeline, stale data, and nothing else says so."""
        built = datetime(2026, 8, 13, 12, 0, tzinfo=UTC)
        scanned = datetime(2026, 8, 11, 12, 0, tzinfo=UTC)

        [row] = reconcile([self._job("sast", finished=built)], {"sast": scanned})

        assert row.state == "silent"

    def test_minutes_of_lag_is_not_evidence_of_anything(self) -> None:
        """A build finishes after its upload, and compaction is asynchronous."""
        built = datetime(2026, 8, 13, 12, 0, tzinfo=UTC)
        scanned = datetime(2026, 8, 13, 11, 30, tzinfo=UTC)

        [row] = reconcile([self._job("sast", finished=built)], {"sast": scanned})

        assert row.state == "reporting"

    def test_a_naive_lake_timestamp_does_not_raise(self) -> None:
        """The two sides come from different worlds and only one carries a
        timezone: Concourse reports epoch seconds, the lake hands back what
        DuckDB stored, which is naive. Subtracting them raises TypeError -
        and did, as a 500 on the repository page, because every test here
        used aware datetimes on both sides."""
        built = datetime(2026, 8, 13, 12, 0, tzinfo=UTC)
        naive = datetime(2026, 8, 13, 11, 58)  # noqa: DTZ001 - the real shape

        [row] = reconcile([self._job("sast", finished=built)], {"sast": naive})

        assert row.state == "reporting"

    def test_a_naive_timestamp_still_detects_silence(self) -> None:
        built = datetime(2026, 8, 13, 12, 0, tzinfo=UTC)
        naive = datetime(2026, 8, 11, 12, 0)  # noqa: DTZ001

        [row] = reconcile([self._job("sast", finished=built)], {"sast": naive})

        assert row.state == "silent"

    def test_a_job_with_no_scan_run_at_all_is_named(self) -> None:
        built = datetime(2026, 8, 13, 12, 0, tzinfo=UTC)

        [row] = reconcile([self._job("containers", finished=built)], {})

        assert row.state == "never_reported"

    def test_a_failed_job_is_not_held_against_the_lake(self) -> None:
        """A lane that fails produces nothing, and the lake is right to be
        empty. The failure is the pipeline's to report, not this check's."""
        [row] = reconcile([self._job("sast", status="failed")], {})

        assert row.state == "not_run"

    def test_the_job_names_that_do_not_match_their_capability(self) -> None:
        """`dependencies` uploads as atlas and `cloud-posture` as cloud. Both
        have already been mistaken for a coverage gap."""
        built = datetime(2026, 8, 13, 12, 0, tzinfo=UTC)
        rows = reconcile(
            [
                self._job("dependencies", finished=built),
                self._job("cloud-posture", finished=built),
            ],
            {"atlas": built, "cloud": built},
        )

        assert [r.capability for r in rows] == ["atlas", "cloud"]
        assert all(r.state == "reporting" for r in rows)

    def test_the_insider_job_is_not_cross_checked(self) -> None:
        """Aegis assesses a pull request; these pipelines run on pushes to
        main, where there is usually no pull request and correctly no
        assessment. The job succeeds having recorded nothing on purpose -
        submitting one anyway would score 0/100 for exactly the case Aegis
        exists to notice. Checking it reported every green insider job as a
        silent failure."""
        built = datetime(2026, 8, 13, 12, 0, tzinfo=UTC)

        assert reconcile([self._job("insider", finished=built)], {}) == []

    def test_jobs_that_write_nothing_are_not_checked(self) -> None:
        """`build` and `publish` produce no lake record at all, and flagging
        them would drown the real signal in noise nobody can act on.

        `unit` used to be in this list and is deliberately no longer: since
        D-046 it reports a ScanRun, and because that run carries no findings
        the cross-check is the *only* thing that can notice its absence -
        there is no finding count to be conspicuously zero."""
        built = datetime(2026, 8, 13, 12, 0, tzinfo=UTC)
        jobs = [
            self._job(n, finished=built)
            for n in ("build", "publish-backend", "publish-frontend", "promote")
        ]

        assert reconcile(jobs, {}) == []

    def test_unit_is_checked_because_nothing_else_would_notice(self) -> None:
        built = datetime(2026, 8, 13, 12, 0, tzinfo=UTC)

        [row] = reconcile([self._job("unit", finished=built)], {})

        assert row.capability == "unit"
        assert row.state == "never_reported"


class TestStageCoverage:
    """PIP-6. The distinction that matters is between a stage nobody asked for
    and a stage somebody asked for that is not answering. Both look like an
    absence and only one is a problem."""

    @staticmethod
    def _reporting(**states):
        from mykronos.ci import Reporting

        rows = []
        for capability, state in states.items():
            built = datetime(2026, 8, 13, 12, 0, tzinfo=UTC)
            scanned = {
                "reporting": built,
                "silent": datetime(2026, 8, 1, tzinfo=UTC),
                "never_reported": None,
            }[state]
            rows.append(
                Reporting(
                    job=capability,
                    capability=capability,
                    built_at=built,
                    scanned_at=scanned,
                )
            )
        return rows

    def test_a_stage_nobody_enabled_is_not_a_problem(self) -> None:
        rows = coverage({"sast"}, self._reporting(sast="reporting"))
        dast = next(r for r in rows if r.stage == "dast")

        assert dast.state == "not_enabled"
        assert dast.problem is False

    def test_enabled_with_no_job_is_a_problem(self) -> None:
        """The gap hardest to see otherwise: the repository believes it is
        covered and no job disagrees, because no job exists."""
        rows = coverage({"sast", "dast"}, self._reporting(sast="reporting"))
        dast = next(r for r in rows if r.stage == "dast")

        assert dast.state == "no_job"
        assert dast.problem is True

    def test_an_event_driven_capability_is_not_a_gap(self) -> None:
        """Aegis is fed by webhooks, Oracle writes decisions, Patchwork opens
        pull requests. None of them has a pipeline lane or a ScanRun, so the
        job-versus-scan cross-check has nothing to compare - "no_job" was
        reporting three working capabilities as permanent problems."""
        rows = coverage({"aegis", "oracle", "patchwork"}, [])

        for stage in ("aegis", "oracle", "patchwork"):
            row = next(r for r in rows if r.stage == stage)
            assert row.state == "event_driven"
            assert row.problem is False

    def test_enabled_and_silent_is_a_problem(self) -> None:
        rows = coverage({"sast"}, self._reporting(sast="silent"))

        assert next(r for r in rows if r.stage == "sast").problem is True

    def test_enabled_and_reporting_is_not(self) -> None:
        rows = coverage({"sast"}, self._reporting(sast="reporting"))

        assert next(r for r in rows if r.stage == "sast").problem is False

    def test_every_stage_is_accounted_for(self) -> None:
        """No stage silently missing from the answer - the whole point is that
        a stage the platform claims to cover appears either way."""
        rows = coverage(set(), [])

        assert [r.stage for r in rows] == list(ALL_STAGES)

    def test_the_quality_stages_are_covered(self) -> None:
        assert "unit" in ALL_STAGES
        assert "functional" in ALL_STAGES


class TestAegisIsLookedUpWhereItActuallyWrites:
    """Found by running the check against the live platform: every `insider`
    job reported as never having produced anything.

    Aegis assesses a pull request rather than scanning a tree, so it writes an
    InsiderRiskSignal and no ScanRun at all (spec 06 §3). A cross-check that
    looks for it in scan_runs is permanently wrong in the alarming direction,
    which is how a panel earns being ignored."""

    def test_a_signal_counts_as_aegis_reporting(
        self, client, admin_auth, run_compaction, catalog, buffer
    ) -> None:
        from mykronos.dashboard import DashboardQueries
        from mykronos.schemas import utcnow
        from tests.conftest import REPO
        from tests.test_onboarding import onboard

        onboard(client, admin_auth)
        buffer.append(
            "insider_risk_signals",
            [
                {
                    "signal_id": "sig-1",
                    "repo_full_name": REPO,
                    "evaluated_at": utcnow(),
                    "insider_risk_score": 0,
                }
            ],
        )
        run_compaction()

        latest = DashboardQueries(catalog).last_successful_scan_at(REPO)

        assert "aegis" in latest

    def test_no_signals_means_no_entry(self, client, admin_auth, catalog) -> None:
        from mykronos.dashboard import DashboardQueries
        from tests.conftest import REPO
        from tests.test_onboarding import onboard

        onboard(client, admin_auth)

        assert "aegis" not in DashboardQueries(catalog).last_successful_scan_at(REPO)


class TestTheEndpoint:
    def test_it_always_links_to_github(self, client, admin_auth) -> None:
        """Even with no Concourse at all: the repository still exists and the
        page is still the place somebody looks for it."""
        from tests.test_onboarding import onboard

        onboard(client, admin_auth)
        repo = client.get("/api/dashboard/portfolio", headers=admin_auth).json()["repos"][0]

        page = client.get(f"/api/dashboard/repos/{repo['repo_id']}/ci", headers=admin_auth).json()

        assert page["github_url"] == f"https://github.com/{page['repo_full_name']}"
        assert page["github_actions_url"].endswith("/actions")
        assert page["pipeline"] is None
        assert page["unavailable"]

    def test_a_concourse_repo_is_enabled_by_its_grants(self, client, admin_auth, auth) -> None:
        """`enabled_capabilities` is the Actions installer's ledger, and a
        Concourse-scanned repo never merges an install PR - so the stages
        view showed every lane as not_enabled while eleven were reporting
        (2026-08-15). What may write is what is enabled: the grants."""
        from tests.test_onboarding import onboard

        onboard(client, admin_auth, scanned_by="concourse")
        repo = client.get("/api/dashboard/portfolio", headers=admin_auth).json()["repos"][0]

        page = client.get(f"/api/dashboard/repos/{repo['repo_id']}/ci", headers=admin_auth).json()
        stages = {s["stage"]: s for s in page["stages"]}

        # The conftest fixture grants `sast` when it issues the token.
        assert stages["sast"]["enabled"] is True
        assert stages["network"]["enabled"] is False, "never granted"

    def test_event_driven_capabilities_do_not_read_as_gaps(self, client, admin_auth, auth) -> None:
        from mykronos.auth import TokenRegistry
        from tests.conftest import REPO
        from tests.test_onboarding import onboard

        onboard(client, admin_auth, scanned_by="concourse")
        with client.app.state.db.session() as session:
            TokenRegistry(session).grant(REPO, "aegis")

        repo = client.get("/api/dashboard/portfolio", headers=admin_auth).json()["repos"][0]
        page = client.get(f"/api/dashboard/repos/{repo['repo_id']}/ci", headers=admin_auth).json()
        aegis = next(s for s in page["stages"] if s["stage"] == "aegis")

        assert aegis["enabled"] is True
        assert aegis["state"] == "event_driven"
        assert aegis["problem"] is False
