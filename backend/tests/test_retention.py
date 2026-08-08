"""Insider-risk retention — spec 06 §9.

Not housekeeping. Spec 06 §9 makes this normative on the grounds that an
unenforced retention policy is just a sentence, so it is tested as a
requirement: rows past their window are actually gone from the files, not
flagged; the window is per-repo; and a repo with no configuration gets the
default rather than being skipped.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from mykronos.db.models import CapabilityConfig
from mykronos.jobs import purge_expired_insider_risk
from mykronos.lake.tables import column_names
from mykronos.schemas import utcnow
from tests.conftest import REPO, issue_token
from tests.test_onboarding import onboard
from tests.test_portfolio_job import register

SECOND_REPO = "example-org/ledger-core"


@pytest.fixture
def aegis_auth(client: TestClient) -> dict[str, str]:
    return {"Authorization": f"Bearer {issue_token(client, REPO, 'aegis')}"}


def buffer_signal(client, *, repo: str, pr: int, days_ago: int) -> None:
    """Write a signal row dated in the past.

    Straight to the buffer rather than through the API: the endpoint stamps
    `evaluated_at` from the clock, which is correct, and an aged row is exactly
    what this job needs to act on.
    """
    row = dict.fromkeys(column_names("insider_risk_signals"))
    row.update(
        signal_id=f"{repo}-{pr}",
        repo_full_name=repo,
        pr_number=pr,
        commit_sha="abc",
        author_login="octocat",
        insider_risk_score=30,
        signal_breakdown="{}",
        ai_authorship_flag=None,
        recommendation="pass",
        evaluated_at=(utcnow() - timedelta(days=days_ago)).isoformat(),
    )
    client.app.state.buffer.append("insider_risk_signals", [row])


def configure(client, repo_id: str, **config) -> None:
    with client.app.state.db.session() as session:
        session.add(
            CapabilityConfig(
                repo_onboarding_id=repo_id, capability="aegis", config_json=config
            )
        )


def purge(client, **kwargs):
    return purge_expired_insider_risk(
        client.app.state.db, client.app.state.catalog, **kwargs
    )


class TestRetention:
    def test_rows_past_the_window_are_deleted(
        self, client, admin_auth, run_compaction, catalog
    ) -> None:
        onboard(client, admin_auth)
        buffer_signal(client, repo=REPO, pr=1, days_ago=200)
        buffer_signal(client, repo=REPO, pr=2, days_ago=10)
        run_compaction()
        assert catalog.count("insider_risk_signals") == 2

        result = purge(client)

        assert result.rows_deleted == 1
        assert catalog.query("SELECT pr_number FROM insider_risk_signals") == [(2,)]

    def test_deletion_is_real_not_a_flag(
        self, client, admin_auth, run_compaction, catalog
    ) -> None:
        """A tombstone column would not honour a deletion request — it would
        only stop the dashboard from showing what the system still holds.

        Read straight out of the surviving Parquet file rather than through the
        catalog view, because a view could be filtering. One row is kept
        deliberately so there is still a file to inspect.
        """
        onboard(client, admin_auth)
        buffer_signal(client, repo=REPO, pr=1, days_ago=200)
        buffer_signal(client, repo=REPO, pr=2, days_ago=1)
        run_compaction()

        purge(client)

        files = catalog.all_files("insider_risk_signals")
        assert files, "the surviving row should still have a file"
        with catalog.connect_readonly() as con:
            on_disk = con.execute(
                f"SELECT pr_number FROM read_parquet('{files[0].as_posix()}')"
            ).fetchall()

        assert on_disk == [(2,)], "the expired row is still in the file"

    def test_an_emptied_partition_leaves_nothing_behind(
        self, client, admin_auth, run_compaction, catalog
    ) -> None:
        """An empty Parquet file in a dated directory still announces the day
        somebody was assessed."""
        onboard(client, admin_auth)
        buffer_signal(client, repo=REPO, pr=1, days_ago=200)
        run_compaction()
        assert catalog.all_files("insider_risk_signals")

        purge(client)

        assert catalog.all_files("insider_risk_signals") == []

    def test_a_repo_can_choose_a_shorter_window(
        self, client, admin_auth, run_compaction, catalog
    ) -> None:
        repo_id = onboard(client, admin_auth).json()["id"]
        configure(client, repo_id, retention_days=7)
        buffer_signal(client, repo=REPO, pr=1, days_ago=30)
        run_compaction()

        result = purge(client)

        assert result.rows_deleted == 1
        assert result.applied[REPO] == 7

    def test_a_repo_with_no_config_gets_the_default(
        self, client, admin_auth, run_compaction, catalog
    ) -> None:
        """The absence of a setting is not consent to keep the data forever."""
        onboard(client, admin_auth)
        buffer_signal(client, repo=REPO, pr=1, days_ago=120)
        run_compaction()

        result = purge(client)

        assert result.applied[REPO] == 90
        assert result.rows_deleted == 1

    def test_rows_for_an_offboarded_repo_are_still_purged(
        self, client, run_compaction, catalog
    ) -> None:
        """Nobody is left to configure a window, and leaving them would make
        deletion depend on an onboarding record that no longer exists."""
        buffer_signal(client, repo="example-org/long-gone", pr=1, days_ago=200)
        run_compaction()

        result = purge(client)

        assert result.rows_deleted == 1

    def test_windows_are_applied_per_repo_in_one_pass(
        self, client, admin_auth, run_compaction, catalog
    ) -> None:
        repo_id = onboard(client, admin_auth).json()["id"]
        configure(client, repo_id, retention_days=7)
        register(client, SECOND_REPO, capabilities=["aegis"])

        buffer_signal(client, repo=REPO, pr=1, days_ago=30)
        buffer_signal(client, repo=SECOND_REPO, pr=1, days_ago=30)
        run_compaction()

        result = purge(client)

        # 30 days is past REPO's 7-day window but inside the other's default 90.
        assert result.rows_deleted == 1
        assert catalog.query(
            "SELECT repo_full_name FROM insider_risk_signals"
        ) == [(SECOND_REPO,)]

    def test_it_is_safe_to_run_twice(
        self, client, admin_auth, run_compaction, catalog
    ) -> None:
        onboard(client, admin_auth)
        buffer_signal(client, repo=REPO, pr=1, days_ago=200)
        run_compaction()

        first = purge(client)
        second = purge(client)

        assert first.rows_deleted == 1
        assert second.rows_deleted == 0

    def test_an_empty_lake_is_not_an_error(self, client, admin_auth) -> None:
        onboard(client, admin_auth)

        assert purge(client).rows_deleted == 0

    def test_other_tables_are_untouched(
        self, client, admin_auth, aegis_auth, run_compaction, catalog
    ) -> None:
        """Findings and decisions are evidence about code and are kept
        indefinitely. Only the rows about people expire."""
        from tests.test_oracle_modifiers import one_critical

        onboard(client, admin_auth)
        one_critical(client, run_compaction)
        buffer_signal(client, repo=REPO, pr=1, days_ago=200)
        run_compaction()

        purge(client)

        assert catalog.count("findings") == 1
        assert catalog.count("insider_risk_signals") == 0
