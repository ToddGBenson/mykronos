"""Two lanes that reach different things are not one better than the other (B-048).

`mykronos parity` compares whether each capability *reports*. For most
capabilities that is the same question as what it reaches: `sast` reads the
same tree wherever it runs. For `dast` and `functional` it is not.

The Concourse lanes target an address on this LAN, against a deployment that
outlives the build. The Actions lanes target `localhost` inside a
GitHub-hosted runner, against an ephemeral stack built and seeded per run, and
a hosted runner cannot reach an RFC1918 address on this network at all.

Read literally, `parity` reported Actions `improved` on both and therefore that
the Concourse pipeline could be retired. That would not have consolidated a
duplicate. It would have permanently removed the only path to scanning an
internal deployment, including TheHub's own production.
"""

from __future__ import annotations

from mykronos.ci import NOT_COMPARABLE, Parity, StageCoverage, compare


def row(capability: str, before: str, after: str) -> Parity:
    return Parity(capability=capability, before=before, after=after)


class TestTheVerdict:
    def test_a_capability_reaching_different_targets_is_never_improved(self) -> None:
        """The exact 2026-09-03 reading: failing under Concourse, reporting
        under Actions, and the conclusion "retire Concourse"."""
        assert row("dast", "failed", "reporting").verdict == "not comparable"
        assert row("functional", "failed", "reporting").verdict == "not comparable"

    def test_an_ordinary_capability_still_reads_as_improved(self) -> None:
        """The distinction has to cut both ways or it is just a way of never
        answering."""
        assert row("sast", "no_job", "reporting").verdict == "improved"

    def test_a_regression_still_outranks_everything(self) -> None:
        """Losing coverage is the answer whatever else is true of the lane.
        A capability that reached an internal target and now reaches nothing
        has still lost something."""
        assert row("dast", "reporting", "no_job").verdict == "REGRESSED"
        assert row("dast", "reporting", "no_job").regressed is True

    def test_identical_states_are_still_the_same(self) -> None:
        assert row("dast", "reporting", "reporting").verdict == "same"

    def test_the_reason_is_carried_with_the_verdict(self) -> None:
        """A verdict a reader cannot act on sends them back to the table that
        produced the wrong conclusion in the first place."""
        parity = row("dast", "failed", "reporting")

        assert parity.comparable is False
        assert "different targets" in parity.why_not_comparable
        assert row("sast", "failed", "reporting").why_not_comparable == ""


class TestWhichCapabilities:
    def test_only_the_two_that_reach_a_deployment(self) -> None:
        """`sast`, `secrets`, `iac` and the rest read a checkout, and a
        checkout is the same everywhere. Marking those non-comparable would
        make the check refuse to answer anything."""
        assert set(NOT_COMPARABLE) == {"dast", "functional"}

    def test_every_reason_names_both_sides(self) -> None:
        for reason in NOT_COMPARABLE.values():
            assert "Concourse" in reason
            assert "Actions" in reason


class TestThroughCompare:
    def test_the_full_comparison_marks_it(self) -> None:
        before = [
            StageCoverage("sast", enabled=True, state="reporting"),
            StageCoverage("dast", enabled=True, state="silent"),
        ]
        after = [
            StageCoverage("sast", enabled=True, state="reporting"),
            StageCoverage("dast", enabled=True, state="reporting"),
        ]

        verdicts = {row.capability: row.verdict for row in compare(before, after)}

        assert verdicts["sast"] == "same"
        assert verdicts["dast"] == "not comparable"
