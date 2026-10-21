"""A governed change merged with no independent review (TheHub #60851, option B).

Every review-integrity signal in `aegis_signals` returns None for an empty
review list, and for an open pull request that is right: "not reviewed yet" is
not "reviewed by nobody independent". It stops being right once the pull
request has merged. Then an empty list is the fact itself - the change landed
and nobody but its author agreed to it - and on a governed path (the CI that
gates it, the pipelines, auth, CODEOWNERS) that is the case Aegis exists for.

The second half is the one a careless version gets wrong. Aegis has no GitHub
token in CI yet (TheHub #60867), and an anonymous reviews fetch is not
evidence this check will stand on. Without a token the check says it did not
run, and why. It never reports clean: an unread review list and an empty one
must not look the same.
"""

from __future__ import annotations

import json

import pytest

from mykronos.aegis import KNOWN_SIGNALS, SIGNAL_CAP, assess, render_check_run_summary
from mykronos.aegis_signals import (
    GOVERNED_MERGE_KEY,
    PullRequestFacts,
    ReviewFact,
    checks_not_run,
    collect,
    main,
    unreviewed_governed_merge_signal,
)
from mykronos.schemas import InsiderRiskSubmission

SENSITIVE = ["**/auth/**", "**/*secret*"]


def facts(**overrides) -> PullRequestFacts:
    payload = {
        "author_login": "octocat",
        "changed_files": [".github/workflows/ci.yml"],
        "files_changed_count": 1,
        "author_prior_commits": 50,
        "author_median_files": 3.0,
        "pr_body": "",
        "reviews": (),
        "diff_lines": 20,
        "ai_authored": False,
        "merged": True,
        "reviews_authenticated": True,
    }
    payload.update(overrides)
    return PullRequestFacts(**payload)


def review(login: str = "hubber", state: str = "APPROVED") -> ReviewFact:
    return ReviewFact(reviewer_login=login, state=state, seconds_after_head_commit=3600)


class TestItFires:
    def test_merged_governed_change_with_no_review_fires_with_a_clear_title(self) -> None:
        signal = unreviewed_governed_merge_signal(facts(), SENSITIVE)

        assert signal is not None
        assert signal["key"] == GOVERNED_MERGE_KEY
        assert signal["rationale"].startswith("Governed path merged with no independent review:")
        assert ".github/workflows/ci.yml" in signal["rationale"]

    def test_only_the_author_approving_is_still_no_independent_review(self) -> None:
        signal = unreviewed_governed_merge_signal(
            facts(reviews=(review(login="octocat"),)), SENSITIVE
        )

        assert signal is not None

    def test_an_independent_comment_is_not_an_approval(self) -> None:
        signal = unreviewed_governed_merge_signal(
            facts(reviews=(review(state="COMMENTED"),)), SENSITIVE
        )

        assert signal is not None

    @pytest.mark.parametrize(
        "path",
        [
            "deploy/concourse/pipelines/mykronos.yml",
            "workflow-templates/mykronos-sast.yml",
            "CODEOWNERS",
            ".github/CODEOWNERS",
            "backend/auth/tokens.py",
            "config/client_secret.json",
        ],
    )
    def test_every_governed_path_counts(self, path: str) -> None:
        assert unreviewed_governed_merge_signal(facts(changed_files=[path]), SENSITIVE)

    def test_it_is_known_to_the_scorer_and_cannot_block_alone(self) -> None:
        assert GOVERNED_MERGE_KEY in KNOWN_SIGNALS
        assert SIGNAL_CAP[GOVERNED_MERGE_KEY] < 80

    def test_collect_includes_it(self) -> None:
        keys = [s["key"] for s in collect(facts(), SENSITIVE)]

        assert GOVERNED_MERGE_KEY in keys


class TestItStaysSilent:
    def test_an_independent_approval_clears_it(self) -> None:
        assert unreviewed_governed_merge_signal(facts(reviews=(review(),)), SENSITIVE) is None

    def test_an_open_pull_request_is_not_judged(self) -> None:
        assert unreviewed_governed_merge_signal(facts(merged=False), SENSITIVE) is None
        assert checks_not_run(facts(merged=False), SENSITIVE) == []

    def test_a_change_off_the_governed_paths_is_not_judged(self) -> None:
        quiet = facts(changed_files=["src/app.py"])

        assert unreviewed_governed_merge_signal(quiet, SENSITIVE) is None
        assert checks_not_run(quiet, SENSITIVE) == []


class TestWithoutAToken:
    def test_it_does_not_run_and_never_reports_clean(self) -> None:
        anonymous = facts(reviews_authenticated=False)

        assert unreviewed_governed_merge_signal(anonymous, SENSITIVE) is None
        [entry] = checks_not_run(anonymous, SENSITIVE)
        assert entry["key"] == GOVERNED_MERGE_KEY
        assert "GitHub token" in entry["reason"]
        assert "TheHub #60867" in entry["reason"]

    def test_an_unknown_merge_state_is_an_open_pull_request(self) -> None:
        """The Actions workflow runs on open pull requests and does not say.

        No merge to judge yet, so neither a signal nor a "not run" line on every
        governed pull request in review.
        """
        unknown = facts(merged=None, reviews_authenticated=False)

        assert unreviewed_governed_merge_signal(unknown, SENSITIVE) is None
        assert checks_not_run(unknown, SENSITIVE) == []

    def test_main_reports_it_not_run_when_no_token_is_set(
        self, tmp_path, monkeypatch, capsys
    ) -> None:
        """The runner path end to end: no GITHUB_TOKEN, a merged PR."""
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        monkeypatch.setenv("AEGIS_PR_MERGED_AT", "2026-10-20T10:00:00Z")
        monkeypatch.setattr(
            "mykronos.aegis_signals.gather_facts",
            lambda *a, **k: facts(
                merged=k.get("merged"), reviews_authenticated=k["reviews_authenticated"]
            ),
        )
        reviews = tmp_path / "reviews.json"
        reviews.write_text("[]", encoding="utf-8")

        assert (
            main(
                [
                    "--pr-number",
                    "7",
                    "--commit-sha",
                    "abc",
                    "--author",
                    "octocat",
                    "--reviews-file",
                    str(reviews),
                ]
            )
            == 0
        )
        payload = json.loads(capsys.readouterr().out)

        assert GOVERNED_MERGE_KEY not in [s["key"] for s in payload["signals"]]
        assert [c["key"] for c in payload["not_run"]] == [GOVERNED_MERGE_KEY]

    def test_main_runs_it_when_a_token_is_set(self, tmp_path, monkeypatch, capsys) -> None:
        monkeypatch.setenv("GITHUB_TOKEN", "x")
        monkeypatch.setenv("AEGIS_PR_MERGED_AT", "2026-10-20T10:00:00Z")
        monkeypatch.setattr(
            "mykronos.aegis_signals.gather_facts",
            lambda *a, **k: facts(
                merged=k.get("merged"), reviews_authenticated=k["reviews_authenticated"]
            ),
        )

        assert main(["--pr-number", "7", "--commit-sha", "abc", "--author", "octocat"]) == 0
        payload = json.loads(capsys.readouterr().out)

        assert GOVERNED_MERGE_KEY in [s["key"] for s in payload["signals"]]
        assert "not_run" not in payload


class TestThePlatformSaysSo:
    def test_a_check_that_did_not_run_is_recorded_with_its_reason(self) -> None:
        submission = InsiderRiskSubmission(
            pr_number=7,
            commit_sha="abc",
            author_login="octocat",
            signals=[],
            not_run=[{"key": GOVERNED_MERGE_KEY, "reason": "No GitHub token."}],
        )

        assessment = assess(submission, "o/r")
        summary = render_check_run_summary(assessment, submission)

        assert assessment.breakdown["checks_not_run"] == [
            {"key": GOVERNED_MERGE_KEY, "reason": "No GitHub token."}
        ]
        assert "### Not run" in summary
        assert f"`{GOVERNED_MERGE_KEY}`: No GitHub token." in summary

    def test_an_unknown_not_run_key_is_rejected_not_recorded(self) -> None:
        submission = InsiderRiskSubmission(
            pr_number=7,
            commit_sha="abc",
            author_login="octocat",
            not_run=[{"key": "made_up", "reason": "?"}],
        )

        assessment = assess(submission, "o/r")

        assert assessment.breakdown["checks_not_run"] == []
        assert "made_up" in assessment.breakdown["signals_rejected"]
