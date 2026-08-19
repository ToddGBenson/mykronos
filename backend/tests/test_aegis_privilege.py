"""`privilege_adjacent` — spec 20 §2.

Capped and named in `SIGNAL_CAP` since spec 06 shipped, with no collector
behind it, deferred pending an HR/personnel feed nobody has. This is the
narrower reading that needs no new integration: GitHub org role, which the
App can already read.
"""

from __future__ import annotations

import pytest

from mykronos.aegis import SIGNAL_CAP, assess
from mykronos.aegis_signals import (
    ELEVATED_ROLES,
    PRIVILEGE_ADJACENT_SCORE,
    PullRequestFacts,
    collect,
    privilege_adjacent_signal,
)
from mykronos.schemas import InsiderRiskSubmission, SubSignal

REPO = "acme/widgets"


def facts(**overrides):
    base = {
        "author_login": "octocat",
        "changed_files": ["src/app.py"],
        "files_changed_count": 1,
        "author_prior_commits": 20,
        "author_median_files": 2.0,
        "pr_body": "",
    }
    base.update(overrides)
    return PullRequestFacts(**base)


def submission(**overrides) -> InsiderRiskSubmission:
    """What the runner would post, having run `collect` over those facts."""
    return InsiderRiskSubmission(
        pr_number=1,
        commit_sha="abc",
        author_login="octocat",
        signals=[
            SubSignal(**s) for s in collect(facts(**overrides), sensitive_paths=[])
        ],
    )


class TestTheSignal:
    @pytest.mark.parametrize("role", sorted(ELEVATED_ROLES))
    def test_an_elevated_role_fires(self, role: str) -> None:
        signal = privilege_adjacent_signal(facts(author_role=role))

        assert signal is not None
        assert signal["key"] == "privilege_adjacent"
        assert signal["score"] == PRIVILEGE_ADJACENT_SCORE
        assert role in signal["rationale"]

    @pytest.mark.parametrize("role", ["write", "triage", "read"])
    def test_ordinary_contributor_access_does_not(self, role: str) -> None:
        """The signal is about somebody who can change the rules the review
        process relies on, not about anybody who can open a pull request."""
        assert privilege_adjacent_signal(facts(author_role=role)) is None

    def test_an_unresolved_role_is_absent_not_zero(self) -> None:
        """An external contributor, or a permissions gap. Claiming somebody
        is unprivileged because the lookup failed is the wrong direction to
        be wrong in."""
        assert privilege_adjacent_signal(facts(author_role=None)) is None

    def test_the_rationale_does_not_judge_the_person(self) -> None:
        """spec 06 §9 — every signal is about a change, not a rating of
        whoever wrote it, and the text a colleague may end up reading is the
        place that promise is kept or broken."""
        signal = privilege_adjacent_signal(facts(author_role="admin"))

        assert signal is not None
        assert "octocat" not in signal["rationale"]


class TestItReachesTheScore:
    def test_collect_includes_it(self) -> None:
        signals = collect(facts(author_role="admin"), sensitive_paths=[])

        assert any(s["key"] == "privilege_adjacent" for s in signals)

    def test_it_contributes_to_the_assessment(self) -> None:
        without = assess(submission(author_role=None), REPO)
        with_signal = assess(submission(author_role="admin"), REPO)

        assert with_signal.insider_risk_score > without.insider_risk_score

    def test_it_still_cannot_block_alone(self) -> None:
        """The invariant `aegis.py` states outright: the two heaviest caps
        sum to less than the block threshold, so a block always needs three
        signals agreeing. Adding a 30-point signal must not break it."""
        heaviest = sorted(SIGNAL_CAP.values(), reverse=True)[:2]

        assert sum(heaviest) < 80

    def test_alone_it_only_reaches_review(self) -> None:
        outcome = assess(submission(author_role="admin"), REPO)

        assert outcome.recommendation != "block_recommended"
