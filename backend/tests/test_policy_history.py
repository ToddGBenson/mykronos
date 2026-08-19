"""Policy version history — spec 21 §5.

Not what the spec drafted. It imagined reading `oracle-policy-v1.yaml`'s
commit history through the GitHub API, which needs the App installed on the
Mykronos repository itself — still not true, and already the recorded blocker
for automatic policy-proposal PRs.

What ships instead is answered from `risk_decisions`, which has recorded
`policy_version` on every row since spec 09: which decisions were made under
which version. That is the question somebody has when they find an old
decision they disagree with. The textual diff is the part still missing, and
the endpoint says so.
"""

from __future__ import annotations

import pytest

from mykronos.oracle.service import OracleService
from mykronos.schemas import utcnow
from tests.test_portfolio_trend_and_terms import decision_row


@pytest.fixture
def write_decisions(buffer, run_compaction):
    def write(*rows):
        buffer.append("risk_decisions", list(rows))
        run_compaction()

    return write


def service(client) -> OracleService:
    state = client.app.state
    return OracleService(
        state.catalog, state.buffer, state.oracle_policy, state.knowledge, db=state.db
    )


def versioned(repo, version, *, at, recommendation="go"):
    row = decision_row(repo, 10, at=at, recommendation=recommendation)
    row["policy_version"] = version
    return row


class TestHistory:
    def test_each_version_is_one_row(self, client, write_decisions) -> None:
        now = utcnow()
        write_decisions(
            versioned("acme/a", "1.0", at=now),
            versioned("acme/b", "1.0", at=now),
            versioned("acme/c", "1.1", at=now),
        )

        history = {entry["version"]: entry for entry in service(client).policy_history()}

        assert history["1.0"]["decisions"] == 2
        assert history["1.1"]["decisions"] == 1

    def test_it_counts_repos_separately_from_decisions(
        self, client, write_decisions
    ) -> None:
        """One repository scored ten times is one repository. Both numbers
        matter and neither substitutes for the other."""
        now = utcnow()
        write_decisions(
            versioned("acme/a", "1.0", at=now),
            decision_row("acme/a", 20, at=now) | {"policy_version": "1.0",
                                                  "decision_id": "second"},
        )

        entry = service(client).policy_history()[0]

        assert entry["decisions"] == 2
        assert entry["repos"] == 1

    def test_no_go_decisions_are_counted(self, client, write_decisions) -> None:
        """The number that makes two versions comparable: a policy bump that
        doubled the no_go rate is the thing somebody wants to notice."""
        now = utcnow()
        write_decisions(
            versioned("acme/a", "1.1", at=now, recommendation="no_go"),
            versioned("acme/b", "1.1", at=now, recommendation="go"),
        )

        assert service(client).policy_history()[0]["no_go_decisions"] == 1

    def test_the_window_a_version_was_in_force_is_reported(
        self, client, write_decisions
    ) -> None:
        from datetime import timedelta

        now = utcnow()
        write_decisions(
            versioned("acme/a", "1.0", at=now - timedelta(days=30)),
            versioned("acme/b", "1.0", at=now - timedelta(days=1)),
        )

        entry = service(client).policy_history()[0]

        assert entry["first_used"] < entry["last_used"]

    def test_the_loaded_policy_is_flagged_current(
        self, client, write_decisions
    ) -> None:
        """Read from the policy this process loaded, not from whichever
        version decided most recently — a version bumped and deployed but not
        yet exercised is in force and has no rows at all."""
        loaded = client.app.state.oracle_policy.version
        write_decisions(
            versioned("acme/a", loaded, at=utcnow()),
            versioned("acme/b", "0.9", at=utcnow()),
        )

        history = {entry["version"]: entry for entry in service(client).policy_history()}

        assert history[loaded]["current"] is True
        assert history["0.9"]["current"] is False

    def test_no_decisions_is_an_empty_history_not_a_failure(self, client) -> None:
        assert service(client).policy_history() == []


class TestTheEndpoint:
    def test_a_viewer_can_read_it(self, client, viewer_auth) -> None:
        """Same reasoning as `/policy` itself: somebody looking at a decision
        they disagree with is entitled to know whether the rules that produced
        it are the rules in force today."""
        response = client.get("/api/oracle/policy/history", headers=viewer_auth)

        assert response.status_code == 200

    def test_it_names_what_is_still_missing(self, client, admin_auth) -> None:
        """The diff half needs the App installed on the Mykronos repo. Saying
        so is the difference between a partial feature and a feature that
        quietly does less than its name."""
        body = client.get("/api/oracle/policy/history", headers=admin_auth).json()

        assert "diff" in body["note"]
        assert body["current_version"]

    def test_it_is_not_shadowed_by_the_policy_route(self, client, admin_auth) -> None:
        """`/policy` and `/policy/history` are both literal, but the shorter
        one is declared first and a careless `{version}` parameter would have
        swallowed this."""
        assert (
            client.get("/api/oracle/policy/history", headers=admin_auth).json()
            != client.get("/api/oracle/policy", headers=admin_auth).json()
        )
