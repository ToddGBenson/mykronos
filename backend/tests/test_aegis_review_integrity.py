"""Review-integrity signals (spec 06 §2a).

These exist because the insider scenarios worth worrying about — a person with
a second account, a person with an agent — all work the same way: they route a
change around independent review. That mechanism is observable on one pull
request, which is what makes it scoreable without modelling relationships
between people.

The tests below are mostly about when a signal *does not* fire. The base rate
of malicious insiders is near zero, so nearly every positive these produce
will be about somebody innocent, and the cost of that is higher here than
anywhere else in the platform.
"""

from __future__ import annotations

from mykronos.aegis import KNOWN_SIGNALS, SIGNAL_CAP
from mykronos.aegis_signals import (
    PullRequestFacts,
    ReviewFact,
    ci_config_signal,
    collect,
    fast_approval_signal,
    overridden_objection_signal,
    self_approval_signal,
    sole_approver_signal,
    unverified_ai_signal,
)

SENSITIVE = ["**/auth/**", "**/.github/workflows/**"]


def facts(**overrides) -> PullRequestFacts:
    payload = {
        "author_login": "octocat",
        "changed_files": ["src/app.py"],
        "files_changed_count": 1,
        "author_prior_commits": 50,
        "author_median_files": 3.0,
        "pr_body": "",
        "reviews": (),
        "diff_lines": 200,
        "ai_authored": False,
    }
    payload.update(overrides)
    return PullRequestFacts(**payload)


def review(login="hubber", state="APPROVED", seconds=3600, body="") -> ReviewFact:
    return ReviewFact(
        reviewer_login=login,
        state=state,
        seconds_after_head_commit=seconds,
        body=body,
    )


class TestSelfApproval:
    def test_the_author_approving_their_own_change_fires(self) -> None:
        signal = self_approval_signal(facts(reviews=(review(login="octocat"),)))

        assert signal is not None
        assert signal["key"] == "self_approval"

    def test_login_comparison_is_case_insensitive(self) -> None:
        """GitHub logins are case-preserving and case-insensitive. Missing a
        self-approval because of capitalisation would be the worst kind of
        miss: silent, and on the one signal here that has no heuristic in it."""
        signal = self_approval_signal(facts(reviews=(review(login="OctoCat"),)))

        assert signal is not None

    def test_one_independent_approval_clears_it(self) -> None:
        signal = self_approval_signal(
            facts(reviews=(review(login="octocat"), review(login="hubber")))
        )

        assert signal is None

    def test_no_reviews_at_all_does_not_fire(self) -> None:
        """The normal state of a pull request thirty seconds after opening.
        "Not reviewed yet" is not "reviewed by nobody independent"."""
        assert self_approval_signal(facts()) is None

    def test_a_comment_from_the_author_is_not_an_approval(self) -> None:
        signal = self_approval_signal(
            facts(reviews=(review(login="octocat", state="COMMENTED"),))
        )

        assert signal is None


class TestSoleApprover:
    def test_one_approval_on_a_sensitive_path_fires(self) -> None:
        signal = sole_approver_signal(
            facts(changed_files=[".github/workflows/deploy.yml"], reviews=(review(),)),
            SENSITIVE,
        )

        assert signal is not None
        assert "deploy.yml" in signal["rationale"]

    def test_one_approval_on_an_ordinary_path_does_not(self) -> None:
        """One reviewer is how most teams work. On its own it is not worth
        remarking on, and a signal that fires on every pull request is noise."""
        signal = sole_approver_signal(facts(reviews=(review(),)), SENSITIVE)

        assert signal is None

    def test_two_approvals_clear_it(self) -> None:
        signal = sole_approver_signal(
            facts(
                changed_files=[".github/workflows/deploy.yml"],
                reviews=(review(login="a"), review(login="b")),
            ),
            SENSITIVE,
        )

        assert signal is None

    def test_the_authors_own_approval_does_not_count_toward_two(self) -> None:
        signal = sole_approver_signal(
            facts(
                changed_files=[".github/workflows/deploy.yml"],
                reviews=(review(login="octocat"), review(login="hubber")),
            ),
            SENSITIVE,
        )

        assert signal is not None


class TestFastApproval:
    def test_an_impossibly_fast_approval_fires(self) -> None:
        signal = fast_approval_signal(facts(diff_lines=600, reviews=(review(seconds=5),)))

        assert signal is not None
        assert "600" in signal["rationale"]

    def test_a_small_change_is_never_too_fast(self) -> None:
        """A three-line typo fix genuinely can be approved in four seconds."""
        signal = fast_approval_signal(facts(diff_lines=6, reviews=(review(seconds=2),)))

        assert signal is None

    def test_a_plausible_reading_time_clears_it(self) -> None:
        signal = fast_approval_signal(
            facts(diff_lines=200, reviews=(review(seconds=600),))
        )

        assert signal is None

    def test_the_threshold_is_generous(self) -> None:
        """20 lines a second is far faster than anyone reads for meaning. The
        signal should only catch approvals that involved no reading at all."""
        # 200 lines needs 10s. An 11-second approval is absurd in practice and
        # deliberately still passes.
        assert (
            fast_approval_signal(facts(diff_lines=200, reviews=(review(seconds=11),)))
            is None
        )

    def test_an_untimed_review_does_not_fire(self) -> None:
        signal = fast_approval_signal(
            facts(diff_lines=600, reviews=(review(seconds=None),))
        )

        assert signal is None


class TestUnverifiedAi:
    def test_ai_authored_with_a_bare_approval_fires(self) -> None:
        signal = unverified_ai_signal(
            facts(ai_authored=True, reviews=(review(body="LGTM"),))
        )

        assert signal is not None

    def test_a_reviewer_stating_what_they_checked_clears_it(self) -> None:
        signal = unverified_ai_signal(
            facts(
                ai_authored=True,
                reviews=(review(body="I ran the migration against a copy of prod."),),
            )
        )

        assert signal is None

    def test_human_authored_never_fires(self) -> None:
        signal = unverified_ai_signal(facts(reviews=(review(body="LGTM"),)))

        assert signal is None

    def test_it_does_not_double_count_a_missing_reviewer(self) -> None:
        """With no independent approval, `self_approval` or the absence of any
        review already says so. Two signals for one missing person would score
        the same fact twice."""
        signal = unverified_ai_signal(
            facts(ai_authored=True, reviews=(review(login="octocat"),))
        )

        assert signal is None


class TestTheyStayPrompts:
    def test_no_single_signal_can_recommend_a_block(self) -> None:
        """spec 06 §2: a heuristic that fires wrongly costs a review, never a
        block. Blocking needs at least three independent signals agreeing."""
        heaviest = sorted(SIGNAL_CAP.values(), reverse=True)[:2]

        assert sum(heaviest) < 80

    def test_every_new_signal_has_a_cap(self) -> None:
        """An uncapped key is dropped by the platform rather than scored, so a
        signal missing from the table silently never counts."""
        for key in ("self_approval", "sole_approver", "fast_approval", "unverified_ai"):
            assert key in SIGNAL_CAP

    def test_a_clean_pull_request_produces_nothing(self) -> None:
        signals = collect(
            facts(reviews=(review(login="hubber", seconds=7200, body="I checked the tests"),)),
            SENSITIVE,
        )

        assert signals == []

    def test_no_signal_names_a_reviewer(self) -> None:
        """spec 06 §9. The rationale is what a challenged person reads, and it
        should describe the change, not identify who approved it."""
        signals = collect(
            facts(
                changed_files=[".github/workflows/deploy.yml"],
                diff_lines=900,
                ai_authored=True,
                reviews=(review(login="hubber", seconds=3, body="LGTM"),),
            ),
            SENSITIVE,
        )

        assert signals, "expected several signals to fire on this pull request"
        for signal in signals:
            assert "hubber" not in signal["rationale"]


class TestParsingGitHubsPayload:
    def test_it_reduces_a_review_to_four_fields(self) -> None:
        from mykronos.aegis_signals import parse_reviews

        parsed = parse_reviews(
            [
                {
                    "user": {"login": "hubber", "id": 42, "email": "h@example.com"},
                    "state": "APPROVED",
                    "submitted_at": "2026-08-11T10:05:00Z",
                    "body": "I ran the tests",
                    "author_association": "MEMBER",
                }
            ],
            "2026-08-11T10:00:00Z",
        )

        assert len(parsed) == 1
        assert parsed[0].reviewer_login == "hubber"
        assert parsed[0].seconds_after_head_commit == 300
        # spec 06 §9: nothing else about a reviewer is carried.
        assert not hasattr(parsed[0], "author_association")
        assert not hasattr(parsed[0], "email")

    def test_a_review_older_than_the_commit_has_no_elapsed_time(self) -> None:
        """The author pushed again after the approval. The elapsed time is
        then meaningless rather than suspicious, and `fast_approval` must not
        read a negative number as "approved instantly"."""
        from mykronos.aegis_signals import parse_reviews

        parsed = parse_reviews(
            [
                {
                    "user": {"login": "hubber"},
                    "state": "APPROVED",
                    "submitted_at": "2026-08-11T09:00:00Z",
                }
            ],
            "2026-08-11T10:00:00Z",
        )

        assert parsed[0].seconds_after_head_commit is None

    def test_a_broken_payload_yields_no_reviews_rather_than_raising(self) -> None:
        """A failed fetch should cost the review-integrity signals, not the
        whole assessment."""
        from mykronos.aegis_signals import parse_reviews

        assert parse_reviews(None) == ()
        assert parse_reviews({"message": "Not Found"}) == ()
        assert parse_reviews([{"no": "user"}]) == ()

    def test_a_missing_timestamp_is_survivable(self) -> None:
        from mykronos.aegis_signals import parse_reviews

        parsed = parse_reviews(
            [{"user": {"login": "hubber"}, "state": "APPROVED"}], None
        )

        assert parsed[0].seconds_after_head_commit is None


class TestTheWorkflowCanActuallySeeReviews:
    """The signals were written before anything fed them, and a `pull_request`
    trigger fires before any review exists."""

    def _rendered(self) -> str:
        from mykronos.config import get_settings
        from mykronos.installer import TemplateLibrary

        return TemplateLibrary(get_settings().workflow_templates_dir).render(
            "aegis",
            repo_full_name="example-org/repo",
            default_branch="main",
            ingestion_api_url="https://example.invalid",
            token_secret_name="MYKRONOS_INGESTION_TOKEN",
            upload_action_ref="example-org/repo/actions/upload-results@v1",
            mykronos_package_spec="mykronos @ git+https://example.invalid@v1",
        ).content

    def test_it_reruns_when_a_review_is_submitted(self) -> None:
        import yaml

        document = yaml.safe_load(self._rendered())
        triggers = document[True] if True in document else document["on"]

        assert "pull_request_review" in triggers
        assert "submitted" in triggers["pull_request_review"]["types"]

    def test_it_reruns_when_an_approval_is_withdrawn(self) -> None:
        """Leaving a stale "reviewed independently" check run behind would be
        worse than never having posted one."""
        import yaml

        document = yaml.safe_load(self._rendered())
        triggers = document[True] if True in document else document["on"]

        assert "dismissed" in triggers["pull_request_review"]["types"]

    def test_it_can_read_reviews_but_not_write_them(self) -> None:
        """spec 06 §6: Aegis never merges, closes or force-pushes, and all
        three need `pull-requests: write`. Read cannot mutate anything."""
        import yaml

        document = yaml.safe_load(self._rendered())

        assert document["permissions"]["pull-requests"] == "read"
        assert "write" not in str(document["permissions"]["pull-requests"])

    def test_a_failed_fetch_does_not_fail_the_assessment(self) -> None:
        rendered = self._rendered()

        assert "|| echo '[]' > reviews.json" in rendered


class TestOverriddenObjection:
    """Review integrity is about whether review happened. This is the case
    where it happened and did not count."""

    def test_an_unresolved_objection_beside_an_approval_fires(self) -> None:
        signal = overridden_objection_signal(
            facts(
                reviews=(
                    review(login="careful", state="CHANGES_REQUESTED"),
                    review(login="hurried", state="APPROVED"),
                )
            )
        )

        assert signal is not None
        assert signal["key"] == "overridden_objection"
        # Names the reviewer so somebody can ask them, rather than leaving the
        # reader to work out who objected.
        assert "careful" in signal["rationale"]

    def test_the_objector_approving_afterwards_does_not_fire(self) -> None:
        """A reviewer who asked for changes and then approved has resolved
        their own objection. That is the process working, and calling it a
        signal would teach people to ignore this one."""
        signal = overridden_objection_signal(
            facts(
                reviews=(
                    review(login="careful", state="CHANGES_REQUESTED"),
                    review(login="careful", state="APPROVED"),
                )
            )
        )

        assert signal is None

    def test_an_objection_with_no_approval_does_not_fire(self) -> None:
        """Nothing has been overridden yet — the pull request is simply not
        approved, which is the ordinary state of a change under review."""
        signal = overridden_objection_signal(
            facts(reviews=(review(login="careful", state="CHANGES_REQUESTED"),))
        )

        assert signal is None

    def test_no_reviews_does_not_fire(self) -> None:
        assert overridden_objection_signal(facts()) is None

    def test_it_cannot_block_on_its_own(self) -> None:
        signal = overridden_objection_signal(
            facts(
                reviews=(
                    review(login="careful", state="CHANGES_REQUESTED"),
                    review(login="hurried", state="APPROVED"),
                )
            )
        )

        assert signal is not None
        assert signal["score"] <= SIGNAL_CAP[signal["key"]]


class TestCiConfigModified:
    """The change edits the checks that would have caught it."""

    def test_a_workflow_edit_fires(self) -> None:
        signal = ci_config_signal(
            facts(changed_files=[".github/workflows/mykronos-sast.yml"])
        )

        assert signal is not None
        assert signal["key"] == "ci_config_modified"
        # Names the files rather than the person: workflows are edited for good
        # reasons constantly, and this is a prompt to look at a diff.
        assert "mykronos-sast.yml" in signal["rationale"]

    def test_ordinary_source_does_not_fire(self) -> None:
        assert ci_config_signal(facts(changed_files=["src/app.py"])) is None

    def test_a_path_merely_containing_the_word_workflow_does_not_fire(self) -> None:
        """Prefix-matched, not substring-matched. `src/workflows/engine.py` is
        application code that happens to be about workflows, and firing on it
        would be the near-miss that teaches people to ignore the signal."""
        assert ci_config_signal(facts(changed_files=["src/workflows/engine.py"])) is None

    def test_many_files_are_summarised_rather_than_listed(self) -> None:
        signal = ci_config_signal(
            facts(changed_files=[f".github/workflows/w{n}.yml" for n in range(6)])
        )

        assert signal is not None
        assert "+3 more" in signal["rationale"]

    def test_it_cannot_block_on_its_own(self) -> None:
        signal = ci_config_signal(facts(changed_files=[".github/workflows/x.yml"]))

        assert signal is not None
        assert signal["score"] <= SIGNAL_CAP[signal["key"]]


class TestBothReachCollect:
    def test_every_signal_collect_can_emit_is_registered(self) -> None:
        """The guard that would have caught this before it shipped.

        `KNOWN_SIGNALS` *drops* an unregistered key rather than scoring it, so
        a new signal that nobody adds to `SIGNAL_CAP` is computed on every pull
        request and silently discarded — working code, no error, no effect. Both
        of the signals added here did exactly that until this test existed.
        """
        emitted = {
            signal["key"]
            for signal in collect(
                facts(
                    changed_files=[".github/workflows/x.yml", "src/auth/login.py"],
                    author_prior_commits=0,
                    reviews=(
                        review(login="careful", state="CHANGES_REQUESTED"),
                        review(login="octocat", state="APPROVED", seconds=1),
                    ),
                    ai_authored=True,
                ),
                SENSITIVE,
            )
        }

        assert emitted, "the fixture should fire several signals"
        assert emitted <= KNOWN_SIGNALS, (
            f"{sorted(emitted - KNOWN_SIGNALS)} would be dropped by the scorer"
        )

    def test_the_new_signals_are_assembled(self) -> None:
        """A signal nothing calls is a signal that does not exist."""
        fired = {
            signal["key"]
            for signal in collect(
                facts(
                    changed_files=[".github/workflows/x.yml"],
                    reviews=(
                        review(login="careful", state="CHANGES_REQUESTED"),
                        review(login="hurried", state="APPROVED"),
                    ),
                ),
                SENSITIVE,
            )
        }

        assert "ci_config_modified" in fired
        assert "overridden_objection" in fired
