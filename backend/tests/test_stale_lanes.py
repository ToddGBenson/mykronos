"""A lane can be green, on time, and covering nothing (B-046).

`stalled_lanes` measures wall-clock silence, which is the right first question
and not the only one. A pipeline pinned to a branch that has stopped moving, or
to a cached checkout, produces a successful run on schedule forever against an
unchanging tree and never appears in that section. TheHub's lanes surfaced only
because they *also* went quiet for two days; at their usual ten-hour cadence,
330 findings would have been frozen with every indicator green.

The trap in writing this check is flagging quiet repositories. A lane scanning
a repository nobody has pushed to shares a commit with itself forever and is
covering it correctly, so the test is not "runs share a commit" but "the
repository moved and this lane did not".
"""

from __future__ import annotations

from datetime import timedelta

from mykronos import briefing
from mykronos.schemas import utcnow as _utcnow
from tests.conftest import REPO, finding_payload, issue_token, post_findings, post_scan

BRANCHES = {REPO: "main"}


def scan(
    client,
    token: str,
    capability: str,
    when,
    commit_sha: str,
    *,
    branch: str = "main",
    status: str = "success",
    findings: list | None = None,
) -> None:
    headers = {"Authorization": f"Bearer {token}"}
    run_id = f"{capability}-{commit_sha}-{when:%Y%m%d%H%M%S}"
    post_scan(
        client,
        headers,
        scan_run_id=run_id,
        capability=capability,
        scan_status=status,
        commit_sha=commit_sha,
        branch=branch,
        started_at=when.replace(tzinfo=None).isoformat(),
    )
    if findings:
        post_findings(client, headers, findings, scan_run_id=run_id, capability=capability)


def token(client) -> str:
    return issue_token(client, REPO, "sast", "unit", "iac")


def lanes(catalog, **kwargs):
    return briefing.stale_lanes(catalog, default_branches=BRANCHES, **kwargs)


class TestAPinnedLane:
    def test_a_lane_left_behind_by_the_repository_is_reported(
        self, client, catalog, run_compaction
    ) -> None:
        """The defect: `unit` keeps succeeding on an old commit while every
        other lane has moved on, for longer than any build race could
        explain."""
        tok = token(client)
        old = _utcnow() - timedelta(days=10)
        scan(client, tok, "unit", old, "aaaaaaa", findings=[finding_payload()])
        scan(client, tok, "iac", old, "aaaaaaa")
        # The repository moves, and only `iac` follows it.
        scan(client, tok, "iac", _utcnow() - timedelta(days=5), "bbbbbbb")
        # `unit` runs again, days later, still on the old tree.
        scan(client, tok, "unit", _utcnow() - timedelta(days=1), "aaaaaaa")
        run_compaction()

        rows = {lane.capability: lane for lane in lanes(catalog)}

        assert "unit" in rows, "a lane succeeding on a stale commit must be reported"
        assert rows["unit"].reason == "same_commit"
        assert rows["unit"].commit_sha == "aaaaaaa"
        assert rows["unit"].runs == 2
        assert rows["unit"].open_findings == 1
        assert "iac" not in rows, "the lane that followed the repository is fine"

    def test_the_date_it_stuck_is_named(self, client, catalog, run_compaction) -> None:
        """"Pinned" without a date is not something anybody can act on."""
        tok = token(client)
        stuck = _utcnow() - timedelta(days=10)
        scan(client, tok, "unit", stuck, "aaaaaaa")
        scan(client, tok, "iac", stuck, "aaaaaaa")
        scan(client, tok, "iac", _utcnow() - timedelta(days=5), "bbbbbbb")
        scan(client, tok, "unit", _utcnow() - timedelta(days=1), "aaaaaaa")
        run_compaction()

        lane = next(lane for lane in lanes(catalog) if lane.capability == "unit")

        assert lane.since is not None
        assert lane.since.date() == stuck.date()

    def test_re_running_it_is_not_offered_as_the_fix(
        self, client, catalog, run_compaction
    ) -> None:
        """A stalled lane's button dispatches it and the findings close. This
        lane is already succeeding: dispatching it produces one more clean
        scan of the same stale tree."""
        tok = token(client)
        old = _utcnow() - timedelta(days=10)
        scan(client, tok, "unit", old, "aaaaaaa")
        scan(client, tok, "iac", old, "aaaaaaa")
        scan(client, tok, "iac", _utcnow() - timedelta(days=5), "bbbbbbb")
        scan(client, tok, "unit", _utcnow() - timedelta(days=1), "aaaaaaa")
        run_compaction()

        lane = next(lane for lane in lanes(catalog) if lane.capability == "unit")

        assert lane.action.method == "GET"
        assert "re-run" in lane.action.effect.lower()
        assert "closes none" in lane.action.effect


class TestWhatMustNotBeReported:
    def test_a_quiet_repository_is_not_a_pinned_lane(
        self, client, catalog, run_compaction
    ) -> None:
        """Every lane on the same commit because nobody has pushed. This is
        the false positive that would light up the estate and make the
        section unreadable."""
        tok = token(client)
        for days in (12, 8, 4, 1):
            scan(client, tok, "unit", _utcnow() - timedelta(days=days), "aaaaaaa")
            scan(client, tok, "iac", _utcnow() - timedelta(days=days), "aaaaaaa")
        run_compaction()

        assert lanes(catalog) == []

    def test_a_lane_that_simply_has_not_run_yet_is_not_pinned(
        self, client, catalog, run_compaction
    ) -> None:
        """The repository moved an hour ago and this lane is next due. That is
        a lane waiting its turn, not a lane that stopped following."""
        tok = token(client)
        scan(client, tok, "unit", _utcnow() - timedelta(days=3), "aaaaaaa")
        scan(client, tok, "iac", _utcnow() - timedelta(hours=1), "bbbbbbb")
        run_compaction()

        assert [lane.capability for lane in lanes(catalog)] == []

    def test_a_build_race_is_not_a_pin(self, client, catalog, run_compaction) -> None:
        """Two lanes triggered by the same push race: a slow lane on commit N
        can finish after a fast lane on N+1 started. `STALE_FLOOR_DAYS` is
        what stops that reading as a pinned checkout."""
        tok = token(client)
        scan(client, tok, "iac", _utcnow() - timedelta(minutes=30), "bbbbbbb")
        scan(client, tok, "unit", _utcnow() - timedelta(minutes=5), "aaaaaaa")
        run_compaction()

        assert lanes(catalog) == []
        assert briefing.STALE_FLOOR_DAYS >= 1.0

    def test_a_repository_with_one_lane_is_never_reported(
        self, client, catalog, run_compaction
    ) -> None:
        """Nothing establishes that the repository moved, and guessing would
        be worse than the gap."""
        tok = token(client)
        scan(client, tok, "unit", _utcnow() - timedelta(days=10), "aaaaaaa")
        scan(client, tok, "unit", _utcnow() - timedelta(days=1), "aaaaaaa")
        run_compaction()

        assert lanes(catalog) == []

    def test_a_failing_lane_is_the_other_section_s_business(
        self, client, catalog, run_compaction
    ) -> None:
        """No successful run means nothing to say about coverage; that lane is
        `stalled`, and reporting it twice would double-count the same
        problem."""
        tok = token(client)
        scan(client, tok, "unit", _utcnow() - timedelta(days=10), "aaaaaaa", status="failure")
        scan(client, tok, "iac", _utcnow() - timedelta(days=10), "aaaaaaa")
        scan(client, tok, "iac", _utcnow() - timedelta(days=1), "bbbbbbb")
        run_compaction()

        assert [lane.capability for lane in lanes(catalog)] == []


class TestBranchDrift:
    def test_a_lane_on_the_wrong_branch_is_reported(
        self, client, catalog, run_compaction
    ) -> None:
        """B-045's instance: TheHub was scanned on `main` while every commit
        landed on `develop`, for sixteen days, with every lane green."""
        tok = token(client)
        scan(client, tok, "unit", _utcnow() - timedelta(days=1), "aaaaaaa", branch="stale-branch")
        scan(client, tok, "iac", _utcnow() - timedelta(days=1), "aaaaaaa")
        run_compaction()

        rows = {lane.capability: lane for lane in lanes(catalog)}

        assert rows["unit"].reason == "wrong_branch"
        assert rows["unit"].branch == "stale-branch"
        assert rows["unit"].default_branch == "main"
        assert "iac" not in rows

    def test_the_fix_named_is_the_pipeline_and_not_a_re_run(
        self, client, catalog, run_compaction
    ) -> None:
        tok = token(client)
        scan(client, tok, "unit", _utcnow() - timedelta(days=1), "aaaaaaa", branch="stale-branch")
        scan(client, tok, "iac", _utcnow() - timedelta(days=1), "aaaaaaa")
        run_compaction()

        lane = next(lane for lane in lanes(catalog) if lane.capability == "unit")

        assert "Point the resource at `main`" in lane.action.effect
        assert "a re-run changes nothing" in lane.action.effect

    def test_no_default_branch_recorded_means_no_claim(
        self, client, catalog, run_compaction
    ) -> None:
        """An onboarding with no default branch recorded cannot tell us the
        lane is on the wrong one, and asserting it anyway would be inventing
        the answer."""
        tok = token(client)
        scan(client, tok, "unit", _utcnow() - timedelta(days=1), "aaaaaaa", branch="anything")
        scan(client, tok, "iac", _utcnow() - timedelta(days=1), "aaaaaaa")
        run_compaction()

        assert briefing.stale_lanes(catalog, default_branches={REPO: ""}) == []
        assert briefing.stale_lanes(catalog) == []


class TestInTheBriefing:
    def _pin(self, client, catalog, run_compaction) -> None:
        tok = token(client)
        old = _utcnow() - timedelta(days=10)
        scan(client, tok, "unit", old, "aaaaaaa", findings=[finding_payload()])
        scan(client, tok, "iac", old, "aaaaaaa")
        scan(client, tok, "iac", _utcnow() - timedelta(days=5), "bbbbbbb")
        scan(client, tok, "unit", _utcnow() - timedelta(days=1), "aaaaaaa")
        run_compaction()

    def test_the_section_is_rendered_with_the_commit(
        self, client, catalog, run_compaction
    ) -> None:
        self._pin(client, catalog, run_compaction)

        rendered = briefing.render(briefing.build(catalog, default_branches=BRANCHES))

        assert "LANES THAT ARE REPORTING AND NOT COVERING" in rendered
        assert "aaaaaaa" in rendered

    def test_a_clean_estate_renders_no_section(
        self, client, catalog, run_compaction
    ) -> None:
        """A heading with nothing under it trains people to skip the heading."""
        tok = token(client)
        scan(client, tok, "unit", _utcnow(), "aaaaaaa")
        run_compaction()

        rendered = briefing.render(briefing.build(catalog, default_branches=BRANCHES))

        assert "NOT COVERING" not in rendered

    def test_scoping_to_a_repository_keeps_it(
        self, client, catalog, run_compaction
    ) -> None:
        self._pin(client, catalog, run_compaction)

        scoped = briefing.build(catalog, asset_id=REPO, default_branches=BRANCHES)
        elsewhere = briefing.build(
            catalog, asset_id="nobody/nothing", default_branches=BRANCHES
        )

        assert [lane.capability for lane in scoped.stale] == ["unit"]
        assert elsewhere.stale == []
