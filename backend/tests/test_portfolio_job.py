"""The daily portfolio scoring job — spec 09 §5.

The gate answers "is this change safe to merge". This answers "how risky is
this repo right now", which nothing else in the system answers: a repo with no
pull requests open still needs a current number on the dashboard.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from mykronos.db.models import RepoOnboarding, get_or_create_organization
from mykronos.jobs import score_portfolio
from mykronos.oracle import load_policy
from mykronos.oracle.service import OracleService
from tests.conftest import (
    INSTALLATION,
    REPO,
    finding_payload,
    issue_token,
    post_findings,
    post_scan,
)

SECOND_REPO = "example-org/ledger-core"


@pytest.fixture
def service(client: TestClient, settings) -> OracleService:
    return OracleService(
        client.app.state.catalog,
        client.app.state.buffer,
        load_policy(settings.oracle_policy_path),
    )


def register(
    client: TestClient,
    repo: str,
    *,
    capabilities: list[str],
    status: str = "active",
) -> str:
    """An onboarding row in a given state, without going through the installer."""
    with client.app.state.db.session() as session:
        row = RepoOnboarding(
            org_id=get_or_create_organization(session, repo.split("/", 1)[0]).id,
            github_repo_full_name=repo,
            github_installation_id=INSTALLATION,
            default_branch="main",
            status=status,
            enabled_capabilities=capabilities,
        )
        session.add(row)
        session.flush()
        return row.id


def seed_findings(client: TestClient, repo: str, count: int, severity: str) -> None:
    auth = {"Authorization": f"Bearer {issue_token(client, repo, 'sast')}"}
    post_scan(client, auth, scan_run_id=f"scan-{repo}", repo_full_name=repo)
    post_findings(
        client,
        auth,
        [
            finding_payload(rule_id=f"R{i}", severity=severity, symbol=f"s{i}")
            for i in range(count)
        ],
        scan_run_id=f"scan-{repo}",
    )


class TestScorePortfolio:
    @pytest.mark.anyio
    async def test_scores_every_oracle_enabled_repo(
        self, client, service, run_compaction, catalog
    ) -> None:
        register(client, REPO, capabilities=["sast", "oracle"])
        register(client, SECOND_REPO, capabilities=["sast", "oracle"])
        seed_findings(client, REPO, 2, "critical")
        seed_findings(client, SECOND_REPO, 1, "low")
        run_compaction()

        result = await score_portfolio(client.app.state.db, service)
        run_compaction()

        assert sorted(repo for repo, _, _ in result.scored) == [SECOND_REPO, REPO]
        assert result.failed == []
        assert catalog.query(
            "SELECT count(*) FROM risk_decisions WHERE decision_type = 'portfolio'"
        ) == [(2,)]

    @pytest.mark.anyio
    async def test_a_repo_that_did_not_enable_oracle_is_not_judged(
        self, client, service, run_compaction
    ) -> None:
        """Consent to scanning is not consent to being scored.

        The dashboard still shows this repo's findings; what it does not show
        is a verdict nobody asked for.
        """
        register(client, REPO, capabilities=["sast"])
        seed_findings(client, REPO, 3, "critical")
        run_compaction()

        result = await score_portfolio(client.app.state.db, service)

        assert result.scored == []

    @pytest.mark.anyio
    async def test_offboarded_repos_are_skipped(
        self, client, service, run_compaction
    ) -> None:
        register(client, REPO, capabilities=["oracle"], status="removed")
        seed_findings(client, REPO, 3, "critical")
        run_compaction()

        result = await score_portfolio(client.app.state.db, service)

        assert result.scored == []

    @pytest.mark.anyio
    async def test_no_check_run_is_posted(
        self, client, service, run_compaction, github
    ) -> None:
        """There is no commit under discussion, so there is nowhere to post
        one — and annotating an arbitrary head SHA with a score that is not
        about that commit would be worse than posting nothing."""
        register(client, REPO, capabilities=["oracle"])
        seed_findings(client, REPO, 2, "critical")
        run_compaction()

        await score_portfolio(client.app.state.db, service)

        assert github.repos[REPO].check_runs == []

    @pytest.mark.anyio
    async def test_one_broken_repo_does_not_cost_the_others_their_decision(
        self, client, service, run_compaction, monkeypatch
    ) -> None:
        register(client, REPO, capabilities=["oracle"])
        register(client, SECOND_REPO, capabilities=["oracle"])
        seed_findings(client, REPO, 2, "critical")
        seed_findings(client, SECOND_REPO, 1, "high")
        run_compaction()

        real_evaluate = service.engine.evaluate

        def explode(repo_full_name: str, **kwargs):
            if repo_full_name == REPO:
                raise RuntimeError("partition is unreadable")
            return real_evaluate(repo_full_name, **kwargs)

        monkeypatch.setattr(service.engine, "evaluate", explode)

        result = await score_portfolio(client.app.state.db, service)

        assert [repo for repo, _, _ in result.scored] == [SECOND_REPO]
        assert result.failed == [(REPO, "partition is unreadable")]

    @pytest.mark.anyio
    async def test_a_repo_with_no_findings_still_gets_a_decision(
        self, client, service, run_compaction
    ) -> None:
        """spec 09 §10: an explicit 'go', not the absence of a verdict."""
        register(client, REPO, capabilities=["oracle"])
        seed_findings(client, REPO, 0, "low")
        run_compaction()

        result = await score_portfolio(client.app.state.db, service)

        assert result.scored == [(REPO, 0, "go")]

    @pytest.mark.anyio
    async def test_the_worst_repo_is_reported(
        self, client, service, run_compaction
    ) -> None:
        register(client, REPO, capabilities=["oracle"])
        register(client, SECOND_REPO, capabilities=["oracle"])
        seed_findings(client, REPO, 6, "critical")
        seed_findings(client, SECOND_REPO, 1, "low")
        run_compaction()

        result = await score_portfolio(client.app.state.db, service)

        assert result.worst is not None
        assert result.worst[0] == REPO

    @pytest.mark.anyio
    async def test_running_twice_leaves_two_decisions_not_one_edited(
        self, client, service, run_compaction, catalog
    ) -> None:
        """spec 09 §10: decisions are immutable, so the portfolio score is a
        series. Yesterday's number is what makes today's a trend."""
        register(client, REPO, capabilities=["oracle"])
        seed_findings(client, REPO, 2, "critical")
        run_compaction()

        await score_portfolio(client.app.state.db, service)
        await score_portfolio(client.app.state.db, service)
        run_compaction()

        assert catalog.count("risk_decisions") == 2


class TestDashboardUsesLatest:
    @pytest.mark.anyio
    async def test_latest_portfolio_decisions_returns_one_row_per_repo(
        self, client, service, run_compaction
    ) -> None:
        register(client, REPO, capabilities=["oracle"])
        seed_findings(client, REPO, 2, "critical")
        run_compaction()

        await score_portfolio(client.app.state.db, service)
        run_compaction()
        latest = service.latest_portfolio_decisions()

        assert set(latest) == {REPO}
        assert latest[REPO]["recommendation"] == "review_recommended"
        assert latest[REPO]["raw_score"] > 0
