"""CVSS v3.1 scoring, checked against published vectors."""

from __future__ import annotations

import pytest

from mykronos import cvss


class TestAgainstPublishedScores:
    """Vectors whose base scores are published by FIRST and NVD.

    Pinned because this is an implementation of somebody else's arithmetic:
    a formula this platform got subtly wrong would produce numbers that look
    like a standard, are quoted as one, and are not one.
    """

    @pytest.mark.parametrize(
        ("vector", "expected"),
        [
            # CVE-2021-44228 (Log4Shell). Scope changed, everything high.
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
            # CVE-2014-0160 (Heartbleed). Confidentiality only.
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
            # A local, high-privilege, low-impact one — the other end.
            # 6.42 x 0.22 impact, plus 8.22 x 0.55 x 0.44 x 0.27 x 0.62
            # exploitability, is 1.745 and rounds up to 1.8.
            ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.8),
            # No impact at all scores zero, not a small number.
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
            # User interaction and adjacent access, mid-range.
            ("CVSS:3.1/AV:A/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 8.0),
        ],
    )
    def test_base_score(self, vector: str, expected: float) -> None:
        assert cvss.score(vector).base == expected

    def test_cvss_30_vectors_are_accepted(self) -> None:
        assert cvss.score("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N").base == 7.5


class TestUndefinedMeansTheBaseValue:
    """The property the whole module rests on.

    A repository that has told the platform nothing must score exactly its
    base — never lower. A number that quietly fell because nobody filled in a
    form is the worst failure available here.
    """

    def test_no_environment_scores_the_base(self) -> None:
        result = cvss.score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

        assert result.environmental == result.base
        assert not result.moved

    def test_an_empty_environment_scores_the_base(self) -> None:
        result = cvss.score(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", cvss.Environment()
        )

        assert result.environmental == result.base

    def test_an_empty_environment_knows_it_is_empty(self) -> None:
        """So the caller can say "this equals the base because nothing is
        known" rather than showing a figure that is silently identical."""
        assert not cvss.Environment().stated
        assert cvss.Environment(cr="H").stated

    @pytest.mark.parametrize(
        "vector",
        [
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L",
            "CVSS:3.1/AV:P/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:L",
        ],
    )
    def test_never_below_base_without_a_stated_fact(self, vector: str) -> None:
        result = cvss.score(vector)

        assert result.environmental >= result.base


class TestWhatKnowledgeChanges:
    def test_an_unreachable_service_lowers_a_network_flaw(self) -> None:
        """The single most valuable thing a risk profile buys: a
        network-exploitable flaw on something nothing outside can reach is not
        network-exploitable here."""
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        result = cvss.score(vector, cvss.Environment(mav="L"))

        assert result.environmental < result.base
        assert result.moved

    def test_regulated_data_raises_a_confidentiality_flaw(self) -> None:
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        result = cvss.score(vector, cvss.Environment(cr="H"))

        assert result.environmental > result.base

    def test_a_low_requirement_lowers_it(self) -> None:
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        result = cvss.score(vector, cvss.Environment(cr="L"))

        assert result.environmental < result.base

    def test_the_score_says_why_it_moved(self) -> None:
        """A score with no explanation is one nobody can argue with, which is
        not the same as one nobody disagrees with."""
        result = cvss.score(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cvss.Environment(mav="L", cr="H"),
        )

        assert any("attack vector is low here" in r for r in result.because)
        assert any("confidentiality matters high" in r for r in result.because)

    def test_nothing_stated_explains_nothing(self) -> None:
        assert cvss.score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").because == ()


class TestRefusingToGuess:
    def test_a_vector_missing_a_metric_raises(self) -> None:
        """Defaulting the missing metric would invent the attacker's position,
        which is the most consequential term in the formula."""
        with pytest.raises(cvss.VectorError, match="missing"):
            cvss.score("CVSS:3.1/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    def test_a_non_vector_raises_rather_than_scoring_zero(self) -> None:
        """Zero is a real CVSS score. An unparseable vector must never
        produce one."""
        for bad in ("", "7.5", "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P", "nonsense"):
            with pytest.raises(cvss.VectorError):
                cvss.score(bad)

    def test_an_unknown_metric_value_raises(self) -> None:
        with pytest.raises(cvss.VectorError, match="Unknown"):
            cvss.score("CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")


class TestRounding:
    def test_uses_the_specifications_roundup_not_pythons(self) -> None:
        """CVSS 3.1 §7.4 defines rounding as integer arithmetic precisely
        because floating-point rounding disagrees for some scores, and two
        tools differing in the first decimal on a published standard costs an
        afternoon."""
        assert cvss._roundup(4.02) == 4.1
        assert cvss._roundup(4.00) == 4.0
        # The case plain round() gets wrong.
        assert cvss._roundup(6.1) == 6.1


class TestProfileMapping:
    """A risk profile in the standard's own terms.

    The mapping is a judgement, so it lives in one place and is pinned here
    rather than being re-derived at each call site.
    """

    def test_an_unreachable_service_is_the_one_that_pays(self) -> None:
        env = cvss.environment_for(internet_facing=False)

        assert env.mav == "L"
        assert env.stated

    def test_internet_facing_true_sets_nothing(self) -> None:
        """The base vector already says AV:N where the flaw is network
        exploitable. A modifier re-asserting it cannot change anything while
        looking like it might."""
        assert cvss.environment_for(internet_facing=True).mav == "X"

    def test_public_data_does_not_demote_confidentiality(self) -> None:
        """A team that honestly declares its data public must not find every
        confidentiality finding quietly discounted for saying so."""
        assert cvss.environment_for(data_classification="public").cr == "M"
        assert cvss.environment_for(data_classification="regulated").cr == "H"

    def test_criticality_drives_availability_not_confidentiality(self) -> None:
        env = cvss.environment_for(business_criticality="critical")

        assert env.ar == "H"
        assert env.cr == "X"

    def test_compliance_scope_raises_integrity_and_nothing_lowers_it(self) -> None:
        """A regime in scope means somebody outside the team cares whether the
        data is right. Its absence is not evidence that nobody does."""
        assert cvss.environment_for(compliance_scope=["pci"]).ir == "H"
        assert cvss.environment_for(compliance_scope=[]).ir == "X"

    def test_an_empty_profile_states_nothing(self) -> None:
        assert not cvss.environment_for().stated

    def test_an_unrecognised_value_is_ignored_rather_than_guessed(self) -> None:
        assert cvss.environment_for(data_classification="banana").cr == "X"

    def test_each_stated_fact_moves_the_score_further(self) -> None:
        """A confidentiality-only flaw, so the requirement has room to act.

        Deliberately not the everything-high vector: there, `MISS` is already
        at its 0.915 cap and raising the requirements changes nothing. That is
        the standard behaving as specified rather than the mapping failing, and
        the next test pins it so nobody 'fixes' it.
        """
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        bare = cvss.score(vector).base
        raised = cvss.score(vector, cvss.environment_for(data_classification="regulated"))
        lowered = cvss.score(vector, cvss.environment_for(internet_facing=False))

        assert lowered.environmental < bare < raised.environmental

    def test_the_impact_cap_binds_and_that_is_the_standard(self) -> None:
        """With C, I and A all High the modified impact sub-score is already
        capped, so raising every requirement cannot raise the score. Pinned
        because it looks like the mapping silently failing."""
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        full = cvss.score(
            vector,
            cvss.environment_for(
                data_classification="regulated",
                business_criticality="critical",
                compliance_scope=["pci"],
            ),
        )

        assert full.environmental == cvss.score(vector).base
        # It still says what was stated, so a reader can see why it did not
        # move rather than assuming nothing was known.
        assert full.because
