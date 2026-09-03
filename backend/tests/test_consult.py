"""Consult the Champion: what it answers, and what it refuses to."""

from __future__ import annotations

from mykronos import consult


def _by_key(answers: list[consult.Answer]) -> dict[str, consult.Answer]:
    return {a.key: a for a in answers}


class TestTheOpenCount:
    def test_a_frozen_lane_is_said_before_the_number_is_read(self) -> None:
        """The most consequential sentence here.

        A finding closes only after two consecutive successful scans see it
        gone, so a broken lane holds findings open however well the code was
        fixed. Reporting "431 open" without that is a true number and a false
        impression.
        """
        answers = _by_key(
            consult.build(
                consult.Facts(
                    repo_full_name="o/r",
                    open_findings=431,
                    blocked_by_lane=316,
                    stalled_lanes=("dast", "sast"),
                )
            )
        )

        text = answers["open"].answer
        assert "316" in text
        assert "cannot close" in text
        assert "dast" in text and "sast" in text
        assert "Fix the lane before reading the number." in text

    def test_a_healthy_repository_gets_the_plain_count(self) -> None:
        answers = _by_key(
            consult.build(
                consult.Facts(repo_full_name="o/r", open_findings=12, critical=1, high=3)
            )
        )

        assert "12 findings open" in answers["open"].answer
        assert "cannot close" not in answers["open"].answer

    def test_nothing_open_reads_as_clean_not_as_empty(self) -> None:
        answers = _by_key(consult.build(consult.Facts(repo_full_name="o/r")))

        assert "Nothing is open" in answers["open"].answer


class TestAcceptedRisk:
    def test_an_unqualified_acceptance_is_called_what_it_is(self) -> None:
        """294 acceptances on this estate carried neither a date nor a reason.
        Counting them as governance would have been the wrong answer."""
        answers = _by_key(
            consult.build(
                consult.Facts(
                    repo_full_name="o/r", accepted=294, accepted_unqualified=294
                )
            )
        )

        assert "stopped looking" in answers["accepted"].answer

    def test_a_qualified_acceptance_is_not_criticised(self) -> None:
        answers = _by_key(
            consult.build(
                consult.Facts(repo_full_name="o/r", accepted=6, accepted_unqualified=0)
            )
        )

        assert "stopped looking" not in answers["accepted"].answer
        assert "review date" in answers["accepted"].answer


class TestCoverageAndProfile:
    def test_unmeasured_coverage_is_never_called_low(self) -> None:
        answers = _by_key(
            consult.build(
                consult.Facts(
                    repo_full_name="o/r",
                    test_kinds_total=11,
                    test_kinds_observed=4,
                    coverage_measured=False,
                )
            )
        )

        assert "unmeasured rather than low" in answers["testing"].answer

    def test_an_unconfirmed_profile_explains_the_worst_case_scores(self) -> None:
        """Without this the scores look like measurements. They are an upper
        bound, and the reason is a decision nobody has made yet."""
        answers = _by_key(
            consult.build(
                consult.Facts(repo_full_name="o/r", risk_profile_confirmed=False)
            )
        )

        assert "upper bound" in answers["profile"].answer

    def test_a_confirmed_profile_drops_the_explanation(self) -> None:
        answers = _by_key(
            consult.build(consult.Facts(repo_full_name="o/r", risk_profile_confirmed=True))
        )

        assert "profile" not in answers


class TestWhatItRefusesToAnswer:
    def test_the_questions_it_cannot_answer_are_listed_with_reasons(self) -> None:
        """The failure mode of an assistant is not saying "I do not know" — it
        is answering anyway. A reader who knows what it cannot do can trust
        what it does."""
        assert consult.UNANSWERABLE
        for item in consult.UNANSWERABLE:
            assert item.question.endswith("?")
            assert len(item.why) > 40

    def test_exploitability_is_refused_while_the_profile_is_unknown(self) -> None:
        questions = " ".join(item.question for item in consult.UNANSWERABLE)

        assert "exploitable" in questions

    def test_it_never_claims_to_have_read_the_code(self) -> None:
        why = " ".join(item.why for item in consult.UNANSWERABLE)

        assert "never opened the file" in why


class TestGrounding:
    def test_every_answer_names_somewhere_to_go_and_disagree(self) -> None:
        """An answer with no source is a claim. Each one points at the tab it
        came from, which is what makes it falsifiable."""
        answers = consult.build(
            consult.Facts(
                repo_full_name="o/r",
                open_findings=5,
                accepted=1,
                test_kinds_total=11,
                test_kinds_observed=4,
                ssdf_total=13,
                ssdf_met=9,
                libraries=42,
                vulnerable_libraries=3,
            )
        )

        assert answers
        for answer in answers:
            assert answer.tab, answer.key
            assert answer.question.endswith("?")

    def test_sections_with_no_data_are_omitted_rather_than_answered_emptily(self) -> None:
        """A repository with no SBOM should not be told it has zero libraries;
        it should not be told anything about libraries."""
        answers = _by_key(consult.build(consult.Facts(repo_full_name="o/r")))

        assert "dependencies" not in answers
        assert "adherence" not in answers


class TestDrift:
    def test_a_control_that_came_off_is_reported(self) -> None:
        answers = _by_key(
            consult.build(
                consult.Facts(
                    repo_full_name="o/r",
                    controls_regressed=("pull_request_required", "signed_commits_required"),
                )
            )
        )

        assert "2 controls came off" in answers["drift"].answer
        assert "pull request required" in answers["drift"].answer

    def test_nothing_is_said_when_nothing_moved(self) -> None:
        """No drift is the normal state. A permanent "nothing changed" row
        trains people to skip the region where the one thing that matters
        will eventually appear."""
        answers = _by_key(consult.build(consult.Facts(repo_full_name="o/r")))

        assert "drift" not in answers
