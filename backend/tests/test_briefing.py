"""The post-deployment briefing (`mykronos briefing`).

The case that matters is the one that prompted the module: findings that
cannot close because their lane is broken, not because nobody fixed them.
Every test here seeds through the ingest API rather than writing Parquet by
hand, so what is asserted is what a real scan would produce.
"""

from __future__ import annotations

from datetime import timedelta

from mykronos import briefing
from mykronos.schemas import utcnow as _utcnow
from tests.conftest import finding_payload, post_findings, post_scan


def _scan(client, auth, run_id: str, findings: list[dict], *, status: str = "success") -> None:
    post_scan(client, auth, scan_run_id=run_id, scan_status=status)
    post_findings(client, auth, findings, scan_run_id=run_id)


class TestStalledLanes:
    """The section the module exists for."""

    def test_a_failing_lane_is_reported_with_what_it_holds_open(
        self, client, auth, catalog, run_compaction
    ) -> None:
        """The defect this was written for.

        A finding closes only after two consecutive *successful* scans see it
        gone (`reconcile.REQUIRED_ABSENCES`). So a lane that is failing freezes
        its findings open however thoroughly the code was fixed — which is
        exactly what happened to 115 mykronos DAST findings whose security
        headers had already shipped and were being served.
        """
        _scan(client, auth, "run-1", [finding_payload()])
        run_compaction()
        _scan(client, auth, "run-2", [], status="failure")
        run_compaction()

        report = briefing.build(catalog)

        assert report.stalled, "a lane whose latest run failed must be reported"
        lane = report.stalled[0]
        assert lane.consecutive_failures == 1
        assert lane.last_success is not None, "run-1 succeeded; the streak is not the history"
        # The number is the point: it says how much is stuck behind the lane.
        assert lane.open_findings == 1
        assert report.blocked_findings == 1

    def test_a_recovered_lane_is_not_reported(
        self, client, auth, catalog, run_compaction
    ) -> None:
        """Failures are counted from the newest run backwards.

        A lane that broke and then recovered is working. Reporting it anyway
        is how this section becomes the part people stop reading.
        """
        _scan(client, auth, "run-1", [finding_payload()], status="failure")
        run_compaction()
        _scan(client, auth, "run-2", [finding_payload()])
        run_compaction()

        assert briefing.build(catalog).stalled == []

    def test_a_long_outage_is_not_understated(
        self, client, auth, catalog, run_compaction
    ) -> None:
        """Only `RECENT_RUNS` rows are read, so a longer streak must say so.

        Printing a bare count here claimed ten failures when the truth was
        seventeen, which reads as a bad afternoon rather than a two-day
        outage.
        """
        for index in range(briefing.RECENT_RUNS + 2):
            _scan(client, auth, f"run-{index}", [finding_payload()], status="failure")
        run_compaction()

        lane = briefing.build(catalog).stalled[0]

        assert lane.streak_capped is True
        assert lane.last_success is None, "nothing ever succeeded here"
        assert "at least" in briefing.render(briefing.build(catalog))

    def test_a_lane_that_stopped_running_is_reported(
        self, client, auth, catalog, run_compaction
    ) -> None:
        """The shape that was nearly missed, and the worse of the two.

        TheHub's lanes all *succeeded* and then simply never ran again after
        2026-08-27. A check that reads `scan_status` sees nothing wrong: there
        is no error to notice. 316 findings were frozen behind that silence,
        against 115 behind the one lane that was visibly failing.
        """
        for index in range(4):
            _scan(client, auth, f"run-{index}", [finding_payload()])
        run_compaction()

        report = briefing.build(catalog, now=_utcnow() + timedelta(days=30))

        assert report.stalled, "a lane that stopped running must be reported"
        lane = report.stalled[0]
        assert lane.reason == "silent"
        assert lane.consecutive_failures == 0, "nothing failed; it stopped"
        assert lane.open_findings == 1

    def test_silence_is_measured_against_the_lane_s_own_cadence(
        self, client, auth, catalog, run_compaction
    ) -> None:
        """This estate mixes daily and weekly schedules.

        Any fixed threshold either misses a stopped daily lane or cries wolf
        at every weekly one, so the gap is measured from the lane's own
        history. A few minutes of quiet is not an outage.
        """
        for index in range(4):
            _scan(client, auth, f"run-{index}", [finding_payload()])
        run_compaction()

        # Just after the last run: quiet, not silent.
        assert briefing.build(catalog, now=_utcnow() + timedelta(minutes=5)).stalled == []
        # `SILENCE_FLOOR_DAYS` is the floor, so a lane that runs constantly
        # still gets two days before anyone is told.
        assert briefing.build(catalog, now=_utcnow() + timedelta(hours=6)).stalled == []

    def test_a_silent_lane_is_told_to_re_run_without_the_repair_caveat(
        self, client, auth, catalog, run_compaction
    ) -> None:
        """A silent lane was working when it stopped, so dispatch *is* the fix.

        Flattening this into the failing lane's wording would make the button
        a lie half the time — and telling somebody to repair a job that has
        nothing wrong with it is how a briefing gets ignored.
        """
        _scan(client, auth, "run-1", [finding_payload()])
        run_compaction()

        lane = briefing.build(catalog, now=_utcnow() + timedelta(days=30)).stalled[0]

        assert lane.reason == "silent"
        assert "Repair the job first" not in lane.action.effect
        assert "was working when it stopped" in lane.action.effect

    def test_a_healthy_estate_says_so(self, client, auth, catalog, run_compaction) -> None:
        _scan(client, auth, "run-1", [finding_payload()])
        run_compaction()

        assert briefing.build(catalog).stalled == []
        assert "Findings can close." in briefing.render(briefing.build(catalog))


class TestGrouping:
    def test_findings_are_grouped_by_what_would_fix_them(
        self, client, auth, catalog, run_compaction
    ) -> None:
        _scan(client, auth, "run-1", [finding_payload(), finding_payload(file_path="b.py")])
        run_compaction()

        report = briefing.build(catalog)

        assert report.total_open == 2
        assert [entry.capability for entry in report.classes] == ["sast"]
        assert report.classes[0].route, "every class states what would fix it"

    def test_concentration_shortens_rule_ids(self) -> None:
        """`...avoid-sqlalchemy-text.avoid-sqlalchemy-text` is eighty characters
        to say `avoid-sqlalchemy-text`, and this line exists to be skimmed."""
        assert (
            briefing._short("python.sqlalchemy.security.audit.avoid-sqlalchemy-text.a-b-c")
            == "a-b-c"
        )
        # Package names and ZAP ids have no dots and must survive untouched.
        assert briefing._short("libc6") == "libc6"
        assert briefing._short("ZAP-10021-CWE-693") == "ZAP-10021-CWE-693"

    def test_an_empty_lake_is_not_an_error(self, catalog) -> None:
        report = briefing.build(catalog)

        assert report.total_open == 0
        assert report.stalled == []
        assert briefing.render(report)


class TestActions:
    """A button is offered only where a route already exists."""

    def test_a_stalled_lane_offers_the_dispatch_that_exists(
        self, client, auth, catalog, run_compaction
    ) -> None:
        _scan(client, auth, "run-1", [finding_payload()], status="failure")
        run_compaction()

        action = briefing.build(catalog).stalled[0].action

        assert action.method == "POST"
        assert action.path.startswith("/api/repos/")
        assert "capabilities=sast" in action.path
        # The order matters and the effect text must say so: re-running a
        # broken workflow fails again and closes nothing.
        assert "Repair the job first" in action.effect

    def test_classes_without_a_route_offer_no_button(self) -> None:
        """The Remediation tab's lesson, applied here.

        A base-image rebuild is a Dockerfile change and a committed secret
        needs rotating before anything else. Neither is an API call, and a
        button that claims otherwise is worse than none.
        """
        assert "containers" not in briefing.CLASS_ACTIONS
        assert "secrets" not in briefing.CLASS_ACTIONS
        assert "iac" not in briefing.CLASS_ACTIONS
        # ...and every class that does have one explains what it does.
        for capability, action in briefing.CLASS_ACTIONS.items():
            assert action.effect, f"{capability} offers a button with no stated effect"

    def test_every_class_with_findings_has_a_stated_route(self) -> None:
        """`ROUTES` and the fixers must not describe different worlds."""
        from mykronos.patchwork import fixers

        for entry in fixers.COVERAGE + fixers.NOT_COVERED:
            capability = entry["capability"]
            assert capability in briefing.ROUTES, (
                f"{capability} has a coverage verdict but no route in the briefing"
            )
