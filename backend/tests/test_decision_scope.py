"""A verdict about one change is filed as one — issue #275.

The estate ran two different gates for a year and filed both under the same
name. `portfolio` is meant to be a repository's standing posture: the nine
rows a scheduled `score-portfolio` run writes, no commit attached. But every
Concourse `oracle-gate` job, and the Actions gate template on a push with no
pull request, sent `decision_type: "portfolio"` *with a commit sha* — a
per-commit verdict wearing the label of a standing one.

Nothing rejected the pairing, so the two became indistinguishable in the lake.
Two things broke at once: "what did the gate decide for this commit?" had no
answer for the repositories gated from Concourse, and the portfolio trend for
those repositories was computed over a mixture of standing scores and commit
noise.

These tests are about the *identity* of a decision, not its score. They assert
that the scope a row is recorded under is derived from the evidence in the
payload — a commit sha, a pull request number — rather than from a label a
pipeline happened to hardcode.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from mykronos.oracle.engine import (
    DECISION_TYPES,
    GATE_DECISION_TYPES,
    OracleEngine,
    normalise_pr_number,
    resolve_decision_type,
)
from mykronos.oracle.service import OracleService
from tests.conftest import (
    REPO,
    finding_payload,
    issue_token,
    post_findings,
    post_scan,
)
from tests.test_onboarding import onboard

# --------------------------------------------------------------------------
# The resolver, on its own
# --------------------------------------------------------------------------


class TestResolvingScope:
    def test_a_portfolio_request_with_a_commit_is_a_commit_gate(self) -> None:
        """The defect, in one line. This is exactly what every Concourse
        `oracle-gate` job sends: a sha, and the word `portfolio`."""
        assert (
            resolve_decision_type("portfolio", commit_sha="a91f2c7") == "commit_gate"
        )

    def test_a_portfolio_request_naming_a_pull_request_is_a_pr_gate(self) -> None:
        assert (
            resolve_decision_type("portfolio", commit_sha="a91f2c7", pr_number=2841)
            == "pr_gate"
        )

    def test_a_portfolio_request_with_no_change_attached_stays_portfolio(self) -> None:
        """The scheduled `score-portfolio` job. It must not be reclassified —
        it is the one caller for which `portfolio` is the truth."""
        assert resolve_decision_type("portfolio") == "portfolio"

    def test_a_pr_gate_with_no_pull_request_is_a_commit_gate(self) -> None:
        """The mislabel in the other direction, and the trap in the obvious
        fix for this issue.

        `record_gate_outcome` finds its row by `(repo, pr_number)`. A `pr_gate`
        row with no pull request number can therefore never acquire a
        `gate_outcome`, and the shadow-mode statistic counts only decisions
        that have one. Relabelling a per-commit Concourse gate as `pr_gate`
        would put its rows in the table the statistic reads and still leave
        them invisible to it — a fix that looks like it worked.
        """
        assert resolve_decision_type("pr_gate", commit_sha="a91f2c7") == "commit_gate"

    def test_a_pull_request_zero_is_not_a_pull_request(self) -> None:
        """`0` is the Actions template's sentinel for "no PR", because a
        workflow output is a string and `jq --argjson` wants a number."""
        assert (
            resolve_decision_type("pr_gate", commit_sha="a91f2c7", pr_number=0)
            == "commit_gate"
        )
        assert normalise_pr_number(0) is None
        assert normalise_pr_number(None) is None
        assert normalise_pr_number(2841) == 2841

    def test_a_release_gate_is_left_alone(self) -> None:
        """A release is judged by its tag, and its sha is incidental. Nothing
        about this taxonomy change should move it."""
        assert (
            resolve_decision_type("release_gate", commit_sha="a91f2c7")
            == "release_gate"
        )

    def test_an_unknown_type_is_still_refused(self) -> None:
        with pytest.raises(ValueError, match="Unknown decision_type"):
            resolve_decision_type("advisory", commit_sha="a91f2c7")

    def test_commit_gate_is_a_gate_and_not_a_posture(self) -> None:
        assert "commit_gate" in DECISION_TYPES
        assert "commit_gate" in GATE_DECISION_TYPES
        assert "portfolio" not in GATE_DECISION_TYPES


# --------------------------------------------------------------------------
# The write path
# --------------------------------------------------------------------------


@pytest.fixture
def oracle_auth(client: TestClient) -> dict[str, str]:
    return {"Authorization": f"Bearer {issue_token(client, REPO, 'sast', 'oracle')}"}


@pytest.fixture
def seeded(client: TestClient, admin_auth, oracle_auth, run_compaction):
    onboard(client, admin_auth)
    post_scan(client, oracle_auth, scan_run_id="run-1")
    post_findings(
        client,
        oracle_auth,
        [finding_payload(rule_id="CWE-89", severity="critical", symbol="a")],
        scan_run_id="run-1",
    )
    run_compaction()


def _evaluate(client, auth, **body):
    return client.post("/api/oracle/evaluate", json=body, headers=auth)


def _service(client: TestClient) -> OracleService:
    return OracleService(
        client.app.state.catalog,
        client.app.state.buffer,
        client.app.state.oracle_policy,
        client.app.state.knowledge,
        db=client.app.state.db,
    )


class TestWhatIsRecorded:
    def test_the_concourse_payload_is_recorded_as_a_commit_gate(
        self, client, oracle_auth, seeded, run_compaction, catalog
    ) -> None:
        """The exact body `deploy/concourse/pipelines/thehub.yml` used to
        send. It must not land in the standing posture."""
        response = _evaluate(
            client, oracle_auth, decision_type="portfolio", commit_sha="a91f2c7"
        )
        assert response.status_code == 200
        run_compaction()

        assert catalog.query(
            "SELECT decision_type, commit_sha FROM risk_decisions"
        ) == [("commit_gate", "a91f2c7")]

    def test_the_response_says_what_was_recorded(
        self, client, oracle_auth, seeded
    ) -> None:
        """A pipeline that sent the wrong label has no other way to find out.
        Echoing the request back would hide the correction."""
        body = _evaluate(
            client, oracle_auth, decision_type="portfolio", commit_sha="a91f2c7"
        ).json()

        assert body["decision_type"] == "commit_gate"

    def test_a_pull_request_payload_is_still_a_pr_gate(
        self, client, oracle_auth, seeded, run_compaction, catalog
    ) -> None:
        """The path that already worked, held still. A regression here would
        empty the shadow-mode statistic."""
        body = _evaluate(
            client,
            oracle_auth,
            decision_type="pr_gate",
            commit_sha="a91f2c7",
            pr_number=2841,
        ).json()
        run_compaction()

        assert body["decision_type"] == "pr_gate"
        assert catalog.query(
            "SELECT decision_type, pr_number FROM risk_decisions"
        ) == [("pr_gate", 2841)]

    @pytest.mark.anyio
    async def test_a_scheduled_portfolio_score_is_left_alone(
        self, client, oracle_auth, seeded, run_compaction, catalog
    ) -> None:
        """`score-portfolio` sends no sha. That row is a standing posture and
        must stay one, or the trend loses its only honest input."""
        await _service(client).evaluate_and_publish(REPO, decision_type="portfolio")
        run_compaction()

        assert catalog.query(
            "SELECT decision_type, commit_sha FROM risk_decisions"
        ) == [("portfolio", "")]

    def test_a_portfolio_row_carrying_a_commit_cannot_be_written(
        self, client, seeded
    ) -> None:
        """The floor under the resolver.

        The resolver corrects callers rather than refusing them, because a 422
        would turn every gate job in the estate red before anyone could
        re-apply the pipelines. That leniency must not become a hole: the
        engine itself refuses to build the contradictory row, so no future
        write path can reintroduce it by skipping the resolver.
        """
        engine = OracleEngine(
            client.app.state.catalog,
            client.app.state.oracle_policy,
            client.app.state.knowledge,
            db=client.app.state.db,
        )
        with pytest.raises(ValueError, match="describes a repository, not a change"):
            engine.evaluate(REPO, decision_type="portfolio", commit_sha="a91f2c7")

    def test_pull_request_zero_is_never_written(
        self, client, oracle_auth, seeded, run_compaction, catalog
    ) -> None:
        """1,394 rows in the live lake claim to judge pull request #0."""
        _evaluate(
            client,
            oracle_auth,
            decision_type="portfolio",
            commit_sha="a91f2c7",
            pr_number=0,
        )
        run_compaction()

        assert catalog.query(
            "SELECT decision_type, pr_number FROM risk_decisions"
        ) == [("commit_gate", None)]


class TestCoverageIsStated:
    def test_the_shadow_report_names_the_repositories_it_covers(
        self, client, oracle_auth, seeded, run_compaction
    ) -> None:
        """"It would have refused 0 of the last 30 merges" is a different
        claim depending on how many repositories those 30 came from."""
        _evaluate(
            client, oracle_auth, decision_type="portfolio", commit_sha="a91f2c7"
        )
        run_compaction()

        report = _service(client).shadow_mode_report()

        # No merge outcome has been recorded, so the statistic covers nothing
        # — and says so, naming the repository it has judged but cannot count.
        assert report["repositories"] == []
        assert REPO in report["repositories_judged"]
        assert REPO in report["repositories_without_a_judged_merge"]
        assert "of" in report["coverage_note"]
