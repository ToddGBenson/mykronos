"""Production is N commits behind its branch, and the briefing says so (#452).

THE DEFECT THIS PINS. On 2026-09-18 the MyKronos backend ran an image 48
commits behind `main`. A briefing section merged the day before was absent from
the running briefing, a reconcile fix that would have closed twelve accepted
criticals had never run, and nothing on any page said production was behind.
The only way to find out was `curl /healthz` against `git rev-parse
origin/main`, by hand, about ten times a day.

Three things are pinned here:

1. The probe can read the revision at all. D-157 made `/healthz` serve
   `build.sha` only to a caller presenting the perimeter token, and the probe
   sent none, so it read `unparsed` everywhere. It now presents the token
   configured for the probe URL's origin, and only that origin's.
2. The lag is GitHub's `ahead_by`, in three states plus `unknown` -- and an
   unreadable probe is `unknown` with the reason, never "at head".
3. The briefing leads with it, next to the findings whose fix is in the
   undeployed commits.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select

from mykronos import briefing, briefing_sources, deployments
from mykronos.db.models import Organization, RepoOnboarding
from mykronos.deployments import (
    AT_HEAD,
    BEHIND,
    DIVERGED,
    UNKNOWN,
    UNPARSED,
    DeploymentLag,
    DeploymentState,
    compute_lag,
    fixes_not_deployed,
    measure_lags,
    probe,
    resolve_probe_tokens,
    run_probe_sweep,
)
from mykronos.github.client import CommitInfo, Comparison, FakeGitHubClient
from mykronos.github.factory import FakeGitHubClientFactory
from mykronos.lake.mutate import locate_findings, update_findings
from mykronos.schemas import utcnow
from tests.conftest import REPO, finding_payload, post_findings, post_scan

DEPLOYED = "a2a7566c" + "0" * 32
HEAD = "fa9f703b" + "1" * 32
MIDDLE = "6dfe35d0" + "2" * 32
OFF_BRANCH = "deadbeef" + "3" * 32


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class FakeResponse:
    def __init__(self, status_code: int, payload: Any = None) -> None:
        self.status_code = status_code
        self._payload = payload

    def json(self) -> Any:
        return self._payload


class RecordingClient:
    """`httpx2.AsyncClient`, recording what it was constructed with."""

    made: list[dict[str, Any]] = []

    def __init__(self, response: FakeResponse, **kwargs: Any) -> None:
        self._response = response
        RecordingClient.made.append(kwargs)

    async def __aenter__(self) -> RecordingClient:
        return self

    async def __aexit__(self, *exc: object) -> bool:
        return False

    async def get(self, url: str) -> FakeResponse:
        return self._response


@pytest.fixture
def http(monkeypatch: pytest.MonkeyPatch):
    RecordingClient.made = []

    def _install(response: FakeResponse) -> list[dict[str, Any]]:
        monkeypatch.setattr(
            "mykronos.deployments.httpx2.AsyncClient",
            lambda **kw: RecordingClient(response, **kw),
        )
        return RecordingClient.made

    return _install


def _commits(*shas: str, start: datetime) -> list[CommitInfo]:
    return [
        CommitInfo(sha=sha, message=f"commit {i}\n\nbody", committed_at=start + timedelta(hours=i))
        for i, sha in enumerate(shas)
    ]


def _github(repo: str = REPO, **comparisons: Comparison) -> FakeGitHubClient:
    client = FakeGitHubClient()
    fake = client.add_repo(repo)
    for branch, comparison in comparisons.items():
        fake.comparisons[(DEPLOYED, branch)] = comparison
    return client


# ---------------------------------------------------------------------------
# 1. The probe presents the perimeter token, and only where it belongs
# ---------------------------------------------------------------------------


class TestTheProbeSendsTheGateToken:
    def test_aliases_resolve_to_the_tokens_this_process_holds(self) -> None:
        resolved = resolve_probe_tokens(
            {
                "http://mykronos-backend:8000/": "@gate",
                "HTTP://TheHub-Backend:8000": "@hub",
                "https://other.example": "literal-token",
                "not a url": "x",
            },
            gate_token="gate-secret",
            hub_token="hub-secret",
        )

        assert resolved == {
            "http://mykronos-backend:8000": "gate-secret",
            "http://thehub-backend:8000": "hub-secret",
            "https://other.example": "literal-token",
        }
        # `@hub` with no hub token resolves to nothing, and nothing is sent.
        assert resolve_probe_tokens(
            {"http://unset.example": "@hub"}, gate_token="g", hub_token=""
        ) == {}

    @pytest.mark.asyncio
    async def test_the_token_is_sent_as_x_hub_token_when_configured(self, http) -> None:
        made = http(FakeResponse(200, {"build": {"sha": DEPLOYED}}))

        result = await deployments.sweep(
            {REPO: "http://mykronos-backend:8000/healthz"},
            {},
            tokens={"http://mykronos-backend:8000": "gate-secret"},
        )

        assert result.states[0].revision == DEPLOYED
        assert made[0]["headers"] == {"X-Hub-Token": "gate-secret"}
        # A token for one origin must not follow a redirect to another.
        assert made[0]["follow_redirects"] is False

    @pytest.mark.asyncio
    async def test_no_token_is_sent_to_an_origin_not_listed(self, http) -> None:
        """A probe URL is admin-editable. A global token would hand the secret
        to whatever host the URL names."""
        made = http(FakeResponse(200, {"status": "ok"}))

        result = await deployments.sweep(
            {REPO: "https://elsewhere.example/healthz"},
            {},
            tokens={"http://mykronos-backend:8000": "gate-secret"},
        )

        assert made[0]["headers"] == {}
        assert result.states[0].status == UNPARSED

    @pytest.mark.asyncio
    async def test_unparsed_without_a_token_names_the_setting(self, http) -> None:
        """The D-157 body is `{"status": "ok"}`. The detail must say what to
        configure, not only that the shape was wrong."""
        http(FakeResponse(200, {"status": "ok"}))

        status, revision, detail = await probe("http://mykronos-backend:8000/healthz")

        assert (status, revision) == (UNPARSED, None)
        assert "build.sha" in detail
        assert "MYKRONOS_DEPLOYMENT_PROBE_TOKENS" in detail
        assert "D-157" in detail

    @pytest.mark.asyncio
    async def test_unparsed_with_a_token_says_the_token_may_be_wrong(self, http) -> None:
        http(FakeResponse(200, {"status": "ok"}))

        _, _, detail = await probe("http://h/healthz", token="wrong")

        assert "token" in detail and "wrong" in detail

    def test_the_setting_reads_a_json_object_from_the_environment(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        from mykronos.config import Settings

        monkeypatch.setenv(
            "MYKRONOS_DEPLOYMENT_PROBE_TOKENS", '{"http://mykronos-backend:8000": "@gate"}'
        )
        monkeypatch.setenv("MYKRONOS_GATE_TOKEN", "gate-secret")
        settings = Settings(_env_file=None)  # type: ignore[call-arg]

        assert deployments.probe_tokens_from(settings) == {
            "http://mykronos-backend:8000": "gate-secret"
        }


# ---------------------------------------------------------------------------
# 2. The comparison: behind, at head, diverged, unknown
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestTheCompare:
    async def test_behind(self) -> None:
        start = datetime(2026, 10, 17, 9, tzinfo=UTC)
        github = _github(
            main=Comparison(
                files=[],
                ahead_by=3,
                behind_by=0,
                status="ahead",
                commits=_commits(MIDDLE, OFF_BRANCH, HEAD, start=start),
                head_sha=HEAD,
                base_committed_at=start - timedelta(days=2),
            )
        )

        lag = await compute_lag(github, REPO, "main", DEPLOYED)

        assert lag.status == BEHIND
        assert lag.behind_by == 3
        assert lag.not_on_branch == 0
        assert lag.head_revision == HEAD
        assert lag.deployed_committed_at == datetime(2026, 10, 15, 9)  # naive UTC
        assert lag.oldest_undeployed_at == datetime(2026, 10, 17, 9)
        assert [c["sha"] for c in lag.commits] == [MIDDLE, OFF_BRANCH, HEAD]
        assert lag.commits[0]["subject"] == "commit 0"
        assert ("compare", f"{REPO}@{DEPLOYED}...main") in github.calls

    async def test_at_head(self) -> None:
        github = _github(main=Comparison(files=[], ahead_by=0, status="identical"))

        lag = await compute_lag(github, REPO, "main", DEPLOYED)

        assert lag.status == AT_HEAD
        assert lag.behind_by == 0
        assert lag.head_revision == DEPLOYED

    async def test_diverged_is_not_folded_into_behind(self) -> None:
        """TheHub production ran a commit that is not on `develop`."""
        github = _github(
            develop=Comparison(files=[], ahead_by=5, behind_by=2, status="diverged")
        )

        lag = await compute_lag(github, REPO, "develop", DEPLOYED)

        assert lag.status == DIVERGED
        assert (lag.behind_by, lag.not_on_branch) == (5, 2)

    async def test_a_revision_github_does_not_know_is_unknown_with_why(self) -> None:
        lag = await compute_lag(_github(), REPO, "main", DEPLOYED)

        assert lag.status == UNKNOWN
        assert lag.behind_by is None
        assert "never pushed" in lag.detail

    async def test_an_unreadable_probe_is_unknown_never_at_head(self) -> None:
        """The failure mode the issue names: a page that claims production is
        up to date because the probe failed. And no compare is made from a
        revision some earlier probe read."""
        github = _github(main=Comparison(files=[], ahead_by=0, status="identical"))
        state = DeploymentState(
            REPO,
            status=UNPARSED,
            revision=None,
            detail="returned JSON with no string at `build.sha`. ... "
            "MYKRONOS_DEPLOYMENT_PROBE_TOKENS names no token",
        )

        [lag] = await measure_lags(
            [state], {REPO: (1, "main")}, FakeGitHubClientFactory(github)
        )

        assert lag.status == UNKNOWN
        assert "MYKRONOS_DEPLOYMENT_PROBE_TOKENS" in lag.detail
        assert not [c for c in github.calls if c[0] == "compare"]

    async def test_the_stored_answer_round_trips(self) -> None:
        github = _github(
            main=Comparison(
                files=[],
                ahead_by=1,
                commits=_commits(HEAD, start=datetime(2026, 10, 18, tzinfo=UTC)),
                head_sha=HEAD,
            )
        )
        lag = await compute_lag(github, REPO, "main", DEPLOYED)

        again = DeploymentLag.from_json(REPO, lag.to_json())

        assert again == lag
        assert DeploymentLag.from_json(REPO, None) is None
        assert DeploymentLag.from_json(REPO, {"behind_by": "not a number"}) is None


# ---------------------------------------------------------------------------
# The sweep stores it; the dashboard reads it without calling GitHub
# ---------------------------------------------------------------------------


def _onboard(client: Any, repo: str = REPO, **fields: Any) -> str:
    with client.app.state.db.session() as session:
        owner = repo.split("/")[0]
        org = session.scalars(
            select(Organization).where(Organization.github_org_login == owner)
        ).first()
        if org is None:
            org = Organization(github_org_login=owner)
            session.add(org)
            session.flush()
        row = RepoOnboarding(
            org_id=org.id,
            github_repo_full_name=repo,
            github_installation_id=1,
            status="active",
            enabled_capabilities=["sast"],
            default_branch="main",
            **fields,
        )
        session.add(row)
        session.commit()
        return str(row.id)


@pytest.mark.asyncio
async def test_the_sweep_stores_the_lag_and_the_dashboard_shows_it(
    client, admin_auth, http
) -> None:
    made = http(FakeResponse(200, {"build": {"sha": DEPLOYED}}))
    repo_id = _onboard(client, deployment_probe_url="http://mykronos-backend:8000/healthz")
    github = _github(
        main=Comparison(
            files=[],
            ahead_by=40,
            commits=_commits(HEAD, start=datetime(2026, 10, 17, tzinfo=UTC)),
            base_committed_at=datetime(2026, 10, 16, tzinfo=UTC),
        )
    )

    result = await run_probe_sweep(
        client.app.state.db,
        client.app.state.catalog,
        tokens={"http://mykronos-backend:8000": "gate-secret"},
        github_factory=FakeGitHubClientFactory(github),
    )

    assert made[0]["headers"] == {"X-Hub-Token": "gate-secret"}
    assert [lag.behind_by for lag in result.lags] == [40]

    calls_before = len(github.calls)
    body = client.get("/api/dashboard/deployments", headers=admin_auth).json()
    row = next(r for r in body["repos"] if r["repo_full_name"] == REPO)
    assert row["lag"]["status"] == BEHIND
    assert row["lag"]["behind_by"] == 40
    assert body["behind"] == 1

    portfolio = client.get("/api/dashboard/portfolio", headers=admin_auth).json()
    entry = next(r for r in portfolio["repos"] if r["repo_id"] == repo_id)
    assert entry["deploy_lag"]["behind_by"] == 40

    delivery = client.get(
        f"/api/dashboard/repos/{repo_id}/product-owner/delivery", headers=admin_auth
    )
    assert delivery.status_code == 200, delivery.text
    assert delivery.json()["deployment"]["lag"]["behind_by"] == 40

    # Reading is a cache read: nothing above asked GitHub again.
    assert len(github.calls) == calls_before


def test_a_repo_without_a_probe_has_no_lag_and_a_new_probe_is_unknown(
    client, admin_auth
) -> None:
    """No probe is `not_configured`, not behind and not unknown. A probe no
    sweep has answered is unknown, and says so."""
    plain = _onboard(client, "ToddGBenson/keel")
    probed = _onboard(client, "ToddGBenson/fresh", deployment_probe_url="http://h/healthz")

    portfolio = client.get("/api/dashboard/portfolio", headers=admin_auth).json()
    by_id = {r["repo_id"]: r for r in portfolio["repos"]}

    assert by_id[plain]["deploy_lag"] is None
    assert by_id[probed]["deploy_lag"]["status"] == UNKNOWN
    assert "not recorded" in by_id[probed]["deploy_lag"]["detail"]


def test_clearing_the_probe_clears_the_lag(client, admin_auth) -> None:
    repo_id = _onboard(
        client,
        deployment_probe_url="http://h/healthz",
        deployment_lag=DeploymentLag(REPO, status=BEHIND, behind_by=3).to_json(),
    )

    client.put(
        f"/api/repos/{repo_id}/deployment-probe", json={"probe_url": ""}, headers=admin_auth
    )

    with client.app.state.db.session() as session:
        assert session.get(RepoOnboarding, repo_id).deployment_lag is None


# ---------------------------------------------------------------------------
# 3. The findings whose fix is in the undeployed range
# ---------------------------------------------------------------------------


def _lag(**overrides: Any) -> DeploymentLag:
    fields: dict[str, Any] = {
        "repo_full_name": REPO,
        "status": BEHIND,
        "branch": "main",
        "deployed_revision": DEPLOYED,
        "behind_by": 2,
        "not_on_branch": 0,
        "deployed_committed_at": utcnow() - timedelta(days=2),
        "commits": [{"sha": MIDDLE}, {"sha": HEAD}],
        "checked_at": utcnow(),
    }
    fields.update(overrides)
    return DeploymentLag(**fields)


class TestFixesNotDeployed:
    def test_a_finding_last_seen_on_the_deployed_revision_is_undeployed(
        self, client, auth, catalog, run_compaction
    ) -> None:
        """Closed on `main`, and the last scan that still saw it was of the
        revision production runs: whatever removed it is not running."""
        post_scan(client, auth, commit_sha=DEPLOYED[:12], pr_number=None)
        post_findings(client, auth, [finding_payload(severity="high")])
        run_compaction()
        ids = [str(r[0]) for r in catalog.query("SELECT finding_id FROM findings")]
        update_findings(
            catalog, locate_findings(catalog, ids), "status = 'fixed', resolved_at = ?",
            [utcnow()],
        )

        found = fixes_not_deployed(catalog, _lag())

        assert [(f.finding_id, f.basis, f.status) for f in found.matched] == [
            (ids[0], deployments.LAST_SEEN_IN_RANGE, "fixed")
        ]
        assert found.closed_since_unmatched == 0

    def test_a_finding_last_seen_before_the_deployed_revision_is_only_counted(
        self, client, auth, catalog, run_compaction
    ) -> None:
        """Last seen on an older commit: the fix may be in what is running.
        Counted as the approximation, never listed as undeployed."""
        post_scan(client, auth, commit_sha="0123456789ab", pr_number=None)
        post_findings(client, auth, [finding_payload()])
        run_compaction()
        ids = [str(r[0]) for r in catalog.query("SELECT finding_id FROM findings")]
        update_findings(
            catalog, locate_findings(catalog, ids), "status = 'fixed', resolved_at = ?",
            [utcnow()],
        )

        found = fixes_not_deployed(catalog, _lag())

        assert found.matched == []
        assert found.closed_since_unmatched == 1

    def test_an_open_finding_whose_merged_fix_is_undeployed(
        self, client, auth, catalog, buffer, run_compaction
    ) -> None:
        post_scan(client, auth, commit_sha="0123456789ab", pr_number=None)
        post_findings(client, auth, [finding_payload(severity="critical")])
        run_compaction()
        [finding_id] = [str(r[0]) for r in catalog.query("SELECT finding_id FROM findings")]
        buffer.append(
            "remediation_events",
            [
                {
                    "event_id": "e-1",
                    "repo_full_name": REPO,
                    "finding_id": finding_id,
                    "fix_pr_number": 7,
                    "pr_status": "merged",
                    "verification_commit_sha": HEAD,
                    "verification_outcome": "pending",
                    "created_at": utcnow(),
                    "updated_at": utcnow(),
                }
            ],
        )
        run_compaction()

        found = fixes_not_deployed(catalog, _lag())

        assert [(f.finding_id, f.basis, f.status, f.commit) for f in found.matched] == [
            (finding_id, deployments.FIX_MERGED, "open", HEAD.lower())
        ]

    def test_nothing_is_matched_when_production_is_current(self, catalog) -> None:
        assert fixes_not_deployed(catalog, _lag(status=AT_HEAD)).matched == []


# ---------------------------------------------------------------------------
# The briefing line
# ---------------------------------------------------------------------------


def _render(lags: list[briefing.ProductionLag] | None) -> str:
    report = briefing.Briefing(
        generated_at=datetime(2026, 10, 19, 12),
        total_open=0,
        production_lag=list(lags or []),
        production_lag_unknown=lags is None,
    )
    return briefing.render(report)


class TestTheBriefingSaysProductionIsBehind:
    def test_behind_with_count_age_and_the_findings_it_explains(self) -> None:
        text = _render(
            [
                briefing.ProductionLag(
                    repo_full_name="ToddGBenson/mykronos",
                    status=BEHIND,
                    branch="main",
                    deployed_revision=DEPLOYED,
                    behind_by=40,
                    not_on_branch=0,
                    deployed_committed_at=datetime(2026, 10, 17, 12),
                    oldest_undeployed_at=datetime(2026, 10, 17, 14),
                    undeployed_fixes=[
                        {"finding_id": "f1", "rule_id": "python.lang.B608", "severity": "high",
                         "title": "t", "status": "fixed", "basis": "last_seen_in_range",
                         "commit": DEPLOYED},
                    ],
                    closed_since_unmatched=3,
                )
            ]
        )

        assert "PRODUCTION IS BEHIND" in text
        assert "ToddGBenson/mykronos  — 40 commits behind main" in text
        assert "running a2a7566c00, committed 2026-10-17 (2 days old)" in text
        assert "1 finding(s) fixed in those commits, NOT in production" in text
        assert "B608" in text
        assert "3 more closed on main" in text
        # It leads the page.
        assert text.index("PRODUCTION IS BEHIND") < text.index("OPEN FINDINGS")

    def test_at_head_is_one_quiet_line(self) -> None:
        text = _render(
            [
                briefing.ProductionLag(
                    repo_full_name="ToddGBenson/mykronos",
                    status=AT_HEAD,
                    branch="main",
                    deployed_revision=HEAD,
                    behind_by=0,
                )
            ]
        )

        assert "PRODUCTION IS BEHIND" not in text
        assert "Production is at the head of its branch: ToddGBenson/mykronos" in text

    def test_unknown_says_why_and_is_not_current(self) -> None:
        text = _render(
            [
                briefing.ProductionLag(
                    repo_full_name="ToddGBenson/TheHub",
                    status=UNKNOWN,
                    branch="develop",
                    detail="the probe could not read the running revision: set "
                    "MYKRONOS_DEPLOYMENT_PROBE_TOKENS",
                )
            ]
        )

        assert "PRODUCTION LAG COULD NOT BE MEASURED" in text
        assert "Unknown is not current" in text
        assert "MYKRONOS_DEPLOYMENT_PROBE_TOKENS" in text
        assert "at the head" not in text

    def test_an_unreadable_record_and_no_probe_are_different_sentences(self) -> None:
        assert "Could not read the deployment record" in _render(None)
        assert "No deployment probe is configured" in _render([])

    def test_a_probe_no_sweep_has_answered_is_unknown_in_the_briefing(
        self, client
    ) -> None:
        _onboard(client, deployment_probe_url="http://h/healthz")

        [lag] = briefing_sources.production_lag(
            client.app.state.db, client.app.state.catalog
        )

        assert lag.status == UNKNOWN
        assert "has not recorded an answer" in lag.detail

    def test_the_gatherer_joins_the_stored_lag_to_the_lake(self, client) -> None:
        _onboard(
            client,
            deployment_probe_url="http://h/healthz",
            deployment_lag=_lag(behind_by=12).to_json(),
        )

        [lag] = briefing_sources.production_lag(
            client.app.state.db, client.app.state.catalog
        )

        assert (lag.status, lag.behind_by, lag.branch) == (BEHIND, 12, "main")
        assert lag.undeployed_fixes == []


def test_the_compare_api_parses_counts_commits_and_the_base_date(monkeypatch) -> None:
    """`RestGitHubClient.compare` reads what #452 needs from GitHub's body."""
    import asyncio

    from mykronos.github.client import RestGitHubClient

    body = {
        "status": "ahead",
        "ahead_by": 2,
        "behind_by": 0,
        "merge_base_commit": {"sha": DEPLOYED},
        "base_commit": {"commit": {"committer": {"date": "2026-10-16T10:00:00Z"}}},
        "commits": [
            {"sha": MIDDLE,
             "commit": {"message": "one", "committer": {"date": "2026-10-17T10:00:00Z"}}},
            {"sha": HEAD,
             "commit": {"message": "two", "committer": {"date": "2026-10-18T10:00:00Z"}}},
        ],
        "files": [],
    }
    client = RestGitHubClient.__new__(RestGitHubClient)

    async def fake_json(self: Any, method: str, path: str, **kw: Any) -> Any:
        return body

    monkeypatch.setattr(RestGitHubClient, "_json", fake_json)

    comparison = asyncio.run(client.compare(REPO, DEPLOYED, "main"))

    assert (comparison.ahead_by, comparison.behind_by, comparison.status) == (2, 0, "ahead")
    assert [c.sha for c in comparison.commits] == [MIDDLE, HEAD]
    assert comparison.head_sha == HEAD
    assert comparison.base_committed_at == datetime(2026, 10, 16, 10, tzinfo=UTC)
    assert not comparison.commits_truncated

