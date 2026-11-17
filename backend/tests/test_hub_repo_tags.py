"""Every Hub filer tags a story with the short repo name (TheHub #61767).

The Hub convention is one lowercase short tag (`repo:mykronos`), not the
`owner/Name` GitHub form. The dedupe key stays `briefing-signal:<hash>`.
"""

from __future__ import annotations

import pytest

from mykronos import product_owner, raise_to_hub, sprint_signal

CASES = [
    ("ToddGBenson/mykronos", "repo:mykronos"),
    ("ToddGBenson/TheHub", "repo:thehub"),
    ("ToddGBenson/keel", "repo:keel"),
    ("ToddGBenson/binnacle", "repo:binnacle"),
    ("ToddGBenson/personal-soc", "repo:personal-soc"),
]


def _candidate(repo: str, kind: str = "fix") -> sprint_signal.Candidate:
    return sprint_signal.Candidate(
        signal_key="a" * 16,
        kind=kind,
        repo_full_name=repo,
        capability="sast",
        title="Fix it",
        ref="rule:CWE-89",
        findings=2,
        risk_removed=10.0,
        risk_basis={"high": 2},
        exposure=1.0,
        exposure_basis="x",
        effort=1.0,
        effort_basis="x",
        score=1.0,
    )


@pytest.mark.parametrize(("repo", "tag"), CASES)
class TestShortRepoTag:
    def test_the_briefing_signal_filer(self, repo: str, tag: str) -> None:
        tags = sprint_signal.story_payload(_candidate(repo), rank_at=1)["tags"]
        assert tag in tags
        assert not [t for t in tags if t.startswith("repo:") and t != tag]
        assert sprint_signal.key_tag("a" * 16) in tags  # the dedupe key is unchanged

    def test_the_raise_to_hub_filer(self, repo: str, tag: str) -> None:
        draft = raise_to_hub.Draft(
            kind="lane", subject="s", title="t", evidence="e", repo_full_name=repo
        )
        payload = raise_to_hub.story_payload(
            draft, title="t", actor="a", actor_kind="operator", note=None
        )
        assert [t for t in payload["tags"] if t.startswith("repo:")] == [tag]

    def test_the_shared_helper(self, repo: str, tag: str) -> None:
        assert product_owner.default_tag(repo) == tag


def test_a_story_without_a_repo_gets_no_repo_tag() -> None:
    draft = raise_to_hub.Draft(kind="lane", subject="s", title="t", evidence="e")
    payload = raise_to_hub.story_payload(
        draft, title="t", actor="a", actor_kind="operator", note=None
    )
    assert not [t for t in payload["tags"] if t.startswith("repo:")]


@pytest.mark.parametrize(("repo", "tag"), CASES)
def test_the_verified_metric_still_finds_the_full_repo(repo: str, tag: str) -> None:
    """The fix story's criterion carries the full name; the short tag does not."""
    payload = sprint_signal.story_payload(_candidate(repo), rank_at=1)
    story = {"tags": payload["tags"], "acceptance_criteria": payload["acceptance_criteria"]}
    assert sprint_signal._target(story) == (repo, "rule:CWE-89")
