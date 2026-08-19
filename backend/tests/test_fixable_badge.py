"""The `fixable` badge on a findings group — spec 19 §3.2.

Read from what Patchwork actually did (`remediation_events`), never
predicted. A fixer cannot say whether it applies without the file content,
so a prediction would be wrong in a way that never self-corrects: a group
guessed fixable that Patchwork later declines would keep claiming to be
fixable on every later page load.
"""

from __future__ import annotations

import pytest

from tests.conftest import REPO, finding_payload, issue_token, post_findings, post_scan
from tests.test_onboarding import onboard


@pytest.fixture
def repo_with_finding(client, admin_auth, run_compaction):
    repo_id = onboard(client, admin_auth).json()["id"]
    client.patch(
        f"/api/repos/{repo_id}/capabilities",
        json={"capabilities": ["sast"], "install_workflows": False},
        headers=admin_auth,
    )
    auth = {"Authorization": f"Bearer {issue_token(client, REPO, 'sast')}"}
    post_scan(client, auth, scan_run_id="run-fixable")
    post_findings(
        client,
        auth,
        [finding_payload(rule_id="CWE-89", severity="critical")],
        scan_run_id="run-fixable",
    )
    run_compaction()
    return repo_id


def groups(client, admin_auth, repo_id, **params):
    return client.get(
        f"/api/dashboard/repos/{repo_id}/open-findings", params=params, headers=admin_auth
    ).json()["groups"]


def record_stage(client, run_compaction, finding_id: str, stage: str) -> None:
    """Write the RemediationEvent Patchwork would have written, without
    running the pipeline — this is a test of how the badge *reads* that
    record, not of how Patchwork produces it."""
    from mykronos.patchwork.pipeline import StageOutcome

    outcome = StageOutcome(
        finding_id=finding_id,
        stage=stage,
        classification="true_positive",
        rationale="recorded by a test",
    )
    client.app.state.buffer.append("remediation_events", [outcome.to_row(REPO)])
    run_compaction()


class TestTheBadge:
    def test_nobody_has_looked_is_null_not_false(
        self, client, admin_auth, repo_with_finding
    ) -> None:
        """"No mechanical fix exists" and "nobody has checked" send a reader
        to different places, so they are different values."""
        rows = groups(client, admin_auth, repo_with_finding)

        assert rows[0]["fixable"] is None

    def test_a_pr_makes_it_fixable(
        self, client, admin_auth, repo_with_finding, run_compaction
    ) -> None:
        rows = groups(client, admin_auth, repo_with_finding)
        record_stage(client, run_compaction, rows[0]["locations"][0]["finding_id"], "pr_opened")

        assert groups(client, admin_auth, repo_with_finding)[0]["fixable"] is True

    def test_patchwork_giving_up_makes_it_false(
        self, client, admin_auth, repo_with_finding, run_compaction
    ) -> None:
        rows = groups(client, admin_auth, repo_with_finding)
        record_stage(
            client, run_compaction, rows[0]["locations"][0]["finding_id"], "no_fix_available"
        )

        assert groups(client, admin_auth, repo_with_finding)[0]["fixable"] is False

    def test_being_merely_triaged_leaves_it_unknown(
        self, client, admin_auth, repo_with_finding, run_compaction
    ) -> None:
        """`triaged` means Patchwork classified it and stopped before trying
        to generate anything — that is not evidence either way."""
        rows = groups(client, admin_auth, repo_with_finding)
        record_stage(client, run_compaction, rows[0]["locations"][0]["finding_id"], "triaged")

        assert groups(client, admin_auth, repo_with_finding)[0]["fixable"] is None


class TestTheFilter:
    def test_fixable_true_keeps_only_fixable_groups(
        self, client, admin_auth, repo_with_finding, run_compaction
    ) -> None:
        rows = groups(client, admin_auth, repo_with_finding)
        record_stage(client, run_compaction, rows[0]["locations"][0]["finding_id"], "pr_opened")

        assert len(groups(client, admin_auth, repo_with_finding, fixable=True)) == 1
        assert groups(client, admin_auth, repo_with_finding, fixable=False) == []

    def test_an_unknown_group_matches_neither(
        self, client, admin_auth, repo_with_finding
    ) -> None:
        """Null is not false. A group nobody has assessed must not show up
        under "no fix available", which is a claim about it."""
        assert groups(client, admin_auth, repo_with_finding, fixable=False) == []
        assert groups(client, admin_auth, repo_with_finding, fixable=True) == []

    def test_omitting_the_filter_returns_everything(
        self, client, admin_auth, repo_with_finding
    ) -> None:
        assert len(groups(client, admin_auth, repo_with_finding)) == 1
