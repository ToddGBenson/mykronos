"""Auto-routing open findings to Patchwork or to a story — spec 19 §4.

The connective piece specs 17 and 18 never built: classification decided what
a finding *was*, and two manual buttons existed to act on it, with nothing
deciding which one applied.
"""

from __future__ import annotations

import pytest

from mykronos.jobs import route_open_findings
from tests.conftest import REPO, finding_payload, issue_token, post_findings, post_scan
from tests.test_onboarding import onboard


def seed(client, admin_auth, run_compaction, findings=None, capabilities=None):
    repo_id = onboard(client, admin_auth).json()["id"]
    client.patch(
        f"/api/repos/{repo_id}/capabilities",
        json={"capabilities": capabilities or ["sast"], "install_workflows": False},
        headers=admin_auth,
    )
    auth = {"Authorization": f"Bearer {issue_token(client, REPO, 'sast')}"}
    post_scan(client, auth, scan_run_id="run-route")
    post_findings(
        client,
        auth,
        findings or [finding_payload(rule_id="CWE-89", severity="critical")],
        scan_run_id="run-route",
    )
    run_compaction()
    return repo_id


async def run_routing(client):
    return await route_open_findings(
        client.app.state.db,
        client.app.state.catalog,
        client.app.state.knowledge,
        client.app.state.github_factory,
    )


class TestRoutingToAStory:
    @pytest.mark.asyncio
    async def test_a_finding_patchwork_will_not_see_gets_a_story(
        self, client, admin_auth, run_compaction
    ) -> None:
        """`patchwork` is not enabled here, so nothing else will ever act on
        this finding — waiting for a capability the repo declined would mean
        it is never routed at all."""
        seed(client, admin_auth, run_compaction)

        result = await run_routing(client)

        assert result.stories_opened == 1
        fake = client.app.state.github_factory.client
        assert len(fake.repos[REPO].issues) == 1

    @pytest.mark.asyncio
    async def test_the_story_carries_a_priority_label(
        self, client, admin_auth, run_compaction
    ) -> None:
        """Severity decides urgency, not which system handles it (spec 19
        §4.1) — so it lands as a label, not as a routing decision."""
        seed(client, admin_auth, run_compaction)

        await run_routing(client)

        fake = client.app.state.github_factory.client
        labels = fake.repos[REPO].issues[0]["labels"]
        assert "mykronos:priority-urgent" in labels

    @pytest.mark.asyncio
    async def test_a_low_finding_is_filed_at_low_priority(
        self, client, admin_auth, run_compaction
    ) -> None:
        seed(
            client,
            admin_auth,
            run_compaction,
            findings=[finding_payload(rule_id="CWE-79", severity="low", symbol="a")],
        )

        await run_routing(client)

        fake = client.app.state.github_factory.client
        assert "mykronos:priority-low" in fake.repos[REPO].issues[0]["labels"]

    @pytest.mark.asyncio
    async def test_running_twice_updates_rather_than_duplicating(
        self, client, admin_auth, run_compaction
    ) -> None:
        """`story_id()` is derived, so the second sweep finds what the first
        wrote. A nightly job must not grow a pile of duplicate issues."""
        seed(client, admin_auth, run_compaction)

        first = await run_routing(client)
        second = await run_routing(client)

        assert first.stories_opened == 1
        assert second.stories_opened == 0
        assert second.stories_updated == 1
        fake = client.app.state.github_factory.client
        assert len(fake.repos[REPO].issues) == 1


class TestRoutingAroundPatchwork:
    @pytest.mark.asyncio
    async def test_a_finding_patchwork_has_not_looked_at_yet_is_skipped(
        self, client, admin_auth, run_compaction
    ) -> None:
        """`patchwork` is enabled and has no event for this finding — it has
        not run yet. Skipped this cycle rather than raced; the next sweep
        sees whatever it decided."""
        seed(client, admin_auth, run_compaction, capabilities=["sast", "patchwork"])

        result = await run_routing(client)

        assert result.awaiting_patchwork == 1
        assert result.stories_opened == 0
        assert client.app.state.github_factory.client.repos[REPO].issues == []

    @pytest.mark.asyncio
    async def test_a_finding_patchwork_opened_a_pr_for_is_left_alone(
        self, client, admin_auth, run_compaction, github
    ) -> None:
        """Two places to act on one finding is worse than one."""
        from tests.test_patchwork import REQUIREMENTS, dependency_finding, put_file

        repo_id = onboard(client, admin_auth).json()["id"]
        client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={
                "capabilities": ["sast", "atlas", "patchwork"],
                "install_workflows": False,
            },
            headers=admin_auth,
        )
        put_file(github, REQUIREMENTS, "urllib3==2.0.4\n")
        auth = {
            "Authorization": f"Bearer {issue_token(client, REPO, 'sast', 'atlas', 'patchwork')}"
        }
        post_scan(client, auth, scan_run_id="run-route")
        post_findings(client, auth, [dependency_finding()], scan_run_id="run-route")
        run_compaction()

        client.post("/api/patchwork/run", json={}, headers=auth)
        run_compaction()

        result = await run_routing(client)

        assert result.left_to_patchwork == 1
        assert result.stories_opened == 0

    @pytest.mark.asyncio
    async def test_a_finding_patchwork_gave_up_on_gets_a_story(
        self, client, admin_auth, run_compaction, github
    ) -> None:
        """The case the whole section exists for: most high/critical findings
        have no deterministic fixer, so they sat in a queue looking urgent
        with no forcing function to get a person looking at them."""
        repo_id = onboard(client, admin_auth).json()["id"]
        client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": ["sast", "patchwork"], "install_workflows": False},
            headers=admin_auth,
        )
        # The file has to exist, or Patchwork reports the finding superseded
        # rather than unfixable — a different and better answer.
        put_file_content = "def get_order(order_id):\n    pass\n"
        github.repos[REPO].files["orders/query.py"] = put_file_content
        github.repos[REPO].branches.setdefault("main", {})["orders/query.py"] = put_file_content

        auth = {"Authorization": f"Bearer {issue_token(client, REPO, 'sast', 'patchwork')}"}
        post_scan(client, auth, scan_run_id="run-route")
        post_findings(
            client,
            auth,
            [finding_payload(rule_id="CWE-89", severity="critical")],
            scan_run_id="run-route",
        )
        run_compaction()

        client.post("/api/patchwork/run", json={}, headers=auth)
        run_compaction()

        result = await run_routing(client)

        assert result.stories_opened == 1


class TestWhatIsNeverRouted:
    @pytest.mark.asyncio
    async def test_a_dampened_finding_is_left_alone(
        self, client, admin_auth, run_compaction
    ) -> None:
        """Routing a `likely_false_positive` anywhere would undo a judgement
        somebody already recorded, with a written reason (spec 11)."""
        repo_id = seed(client, admin_auth, run_compaction)
        findings = client.get(
            f"/api/dashboard/repos/{repo_id}/findings", headers=admin_auth
        ).json()["findings"]
        # Three reasoned dismissals is what `classify()` requires before it
        # will call a rule likely-false-positive (spec 11 §6.1).
        for _ in range(3):
            client.patch(
                f"/api/dashboard/findings/{findings[0]['finding_id']}/status",
                json={"status": "false_positive", "reason": "vendor pattern, reviewed"},
                headers=admin_auth,
            )
        run_compaction()

        result = await run_routing(client)

        # The finding is no longer open at all once dismissed, so nothing is
        # routed — the point being that a dismissal is never re-litigated by
        # a scheduled job.
        assert result.stories_opened == 0

    @pytest.mark.asyncio
    async def test_a_repo_with_no_findings_is_a_no_op(
        self, client, admin_auth
    ) -> None:
        onboard(client, admin_auth)

        result = await run_routing(client)

        assert result.stories_opened == 0
        assert result.failed == []
