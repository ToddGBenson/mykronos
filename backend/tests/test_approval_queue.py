"""The approval queue's decisions (D-149).

`scripts/approval-queue.ps1` waits, merges and pushes; what it decides lives
in `scripts/approval_queue.py` so it can be pinned here:

- which PRs it takes and in what order, and which it refuses to touch;
- who decides a request: governance is a person, always, and the reviewer
  only when it is live *and* a delegation covers the tier;
- whether a union-merged decision log is still an append-only log.

The union tests at the bottom run real git, because the failure they guard
was found by running real git: a rebase replayed a branch that appended
D-136 and later renamed it D-137, and union kept both headings.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import approval_queue as q  # noqa: E402


def pr(number: int, created: str, **overrides) -> dict:
    out = {
        "number": number,
        "createdAt": created,
        "headRefName": f"feat/{number}",
        "baseRefName": "main",
        "isDraft": False,
        "isCrossRepository": False,
    }
    out.update(overrides)
    return out


# -- Ordering --------------------------------------------------------------------


class TestOrder:
    def test_all_is_oldest_first(self) -> None:
        prs = [
            pr(774, "2026-10-11T13:15:45Z"),
            pr(770, "2026-10-11T07:58:48Z"),
            pr(773, "2026-10-11T08:21:43Z"),
        ]
        assert q.order(prs, None)["queue"] == [770, 773, 774]

    def test_named_prs_keep_the_operators_order(self) -> None:
        prs = [pr(770, "2026-10-11T07:00:00Z"), pr(773, "2026-10-11T08:00:00Z")]
        assert q.order(prs, [773, 770])["queue"] == [773, 770]

    def test_a_named_pr_that_is_not_open_is_reported_not_dropped(self) -> None:
        plan = q.order([pr(770, "2026-10-11T07:00:00Z")], [772, 770])
        assert plan["queue"] == [770]
        reason = "not open (merged, closed or unknown)"
        assert plan["skipped"] == [{"number": 772, "reason": reason}]

    def test_a_number_named_twice_is_taken_once(self) -> None:
        assert q.order([pr(770, "x")], [770, 770])["queue"] == [770]

    @pytest.mark.parametrize("branch", ["main", "master"])
    def test_it_never_rewrites_main(self, branch: str) -> None:
        plan = q.order([pr(1, "x", headRefName=branch)], None)
        assert plan["queue"] == []
        assert "refusing to rewrite" in plan["skipped"][0]["reason"]

    def test_a_head_equal_to_its_base_is_refused(self) -> None:
        plan = q.order([pr(1, "x", headRefName="release", baseRefName="release")], None)
        assert "refusing to rewrite" in plan["skipped"][0]["reason"]

    def test_a_fork_is_refused_because_it_cannot_be_pushed(self) -> None:
        plan = q.order([pr(1, "x", isCrossRepository=True)], None)
        assert "fork" in plan["skipped"][0]["reason"]

    def test_a_draft_is_refused_because_no_request_will_come(self) -> None:
        plan = q.order([pr(1, "x", isDraft=True)], None)
        assert "draft" in plan["skipped"][0]["reason"]

    def test_a_pr_against_another_base_is_refused(self) -> None:
        plan = q.order([pr(1, "x", baseRefName="develop")], None)
        assert "targets 'develop'" in plan["skipped"][0]["reason"]


# -- Routing ---------------------------------------------------------------------

ACTIVE = {
    "id": "dlg-1",
    "active": True,
    "duty": "pull_request_merge",
    "tiers": ["production", "routine"],
}


class TestRoute:
    @pytest.mark.parametrize("tier", ["production", "routine"])
    def test_a_live_reviewer_under_a_delegation_decides(self, tier: str) -> None:
        assert q.route(tier, "live", [ACTIVE])["route"] == "agent"

    def test_governance_is_a_person_even_if_a_delegation_claims_it(self) -> None:
        claims = {**ACTIVE, "tiers": ["governance", "production", "routine"]}
        r = q.route("governance", "live", [claims])
        assert r["route"] == "operator"
        assert "person only" in r["reason"]

    def test_an_unknown_tier_goes_to_a_person(self) -> None:
        assert q.route("critical", "live", [ACTIVE])["route"] == "operator"

    @pytest.mark.parametrize("mode", ["shadow", "off", None, "LIVE-ish"])
    def test_a_reviewer_that_is_not_live_does_not_count(self, mode) -> None:
        assert q.route("routine", mode, [ACTIVE])["route"] == "operator"

    def test_no_delegation_means_a_person(self) -> None:
        r = q.route("routine", "live", [])
        assert r["route"] == "operator"
        assert "no active delegation" in r["reason"]

    @pytest.mark.parametrize(
        "delegation",
        [
            {**ACTIVE, "active": False},
            {**ACTIVE, "duty": "risk_acceptance"},
            {**ACTIVE, "tiers": ["routine"]},
        ],
    )
    def test_a_delegation_that_does_not_cover_it_is_ignored(self, delegation) -> None:
        assert q.route("production", "live", [delegation])["route"] == "operator"


# -- The decision log after a union merge -------------------------------------------


def entry(number: int, title: str = "x") -> str:
    return f"## D-{number:03d} — {title}\n\n**Status:** Decided\n\nBody of {number}.\n\n---\n\n"


HEADER = "# Decision log\n\n---\n\n"
MAIN = HEADER + entry(135) + entry(136) + entry(139)


class TestCheckDecisions:
    def test_the_branchs_entries_after_mains_are_clean(self) -> None:
        assert q.check_decisions(MAIN, MAIN + entry(137) + entry(138)) == []

    def test_global_order_is_not_required_because_it_cannot_hold(self) -> None:
        """D-139 already sits before D-137 on main: numbers are taken when a PR
        is written and land in merge order."""
        assert q.check_decisions(MAIN, MAIN + entry(137)) == []

    def test_the_branchs_own_entries_must_ascend(self) -> None:
        problems = q.check_decisions(MAIN, MAIN + entry(138) + entry(137))
        assert any("out of numeric order" in p for p in problems)

    def test_a_number_main_already_uses_is_refused(self) -> None:
        """The real failure, from #770: union kept a superseded heading."""
        merged = MAIN + entry(136, "The notifier") + entry(137, "The notifier")
        problems = q.check_decisions(MAIN, merged)
        assert any("already uses: D-136" in p for p in problems)

    def test_the_same_new_number_twice_is_refused(self) -> None:
        problems = q.check_decisions(MAIN, MAIN + entry(140) + entry(140))
        assert any("same number twice: D-140" in p for p in problems)

    def test_mains_entries_must_come_first_and_intact(self) -> None:
        """Union with the branch as "ours" writes the branch's lines first."""
        merged = HEADER + entry(135) + entry(136) + entry(140) + entry(139)
        problems = q.check_decisions(MAIN, merged)
        assert any("not intact" in p for p in problems)

    def test_a_dropped_main_entry_is_caught(self) -> None:
        merged = HEADER + entry(135) + entry(139) + entry(140)
        assert q.check_decisions(MAIN, merged)

    def test_conflict_markers_are_caught(self) -> None:
        merged = MAIN + "<<<<<<< HEAD\n" + entry(140) + "=======\n>>>>>>> feat\n"
        assert any("conflict markers" in p for p in q.check_decisions(MAIN, merged))

    def test_an_unreadable_base_does_not_check_clean(self) -> None:
        """A base whose headings did not survive decoding would make every
        merge look fine: nothing to compare against."""
        mangled = MAIN.replace("—", "?")
        problems = q.check_decisions(mangled, MAIN + entry(140))
        assert any("no readable D- headings" in p for p in problems)

    def test_duplicates_main_already_carries_are_not_this_merges(self) -> None:
        old = HEADER + entry(46, "a") + entry(46, "b") + entry(139)
        assert q.check_decisions(old, old + entry(140)) == []

    def test_the_live_log_checks_clean_against_itself(self) -> None:
        text = (ROOT / "docs" / "DECISIONS.md").read_text(encoding="utf-8")
        assert q.check_decisions(text, text) == []


# -- What the operator is shown -------------------------------------------------------


class TestSummary:
    EVIDENCE = {
        "number": 770,
        "title": "Notifier reads the host Slack bot from Vault",
        "head_sha": "0123456789abcdef",
        "files": [
            {
                "path": "approval-policy-v1.yaml",
                "class": "governance",
                "status": "modified",
                "additions": 3,
                "deletions": 1,
                "patch_truncated": False,
                "binary_or_unrendered": False,
                "previous_path": None,
            },
            {
                "path": "docs/DECISIONS.md",
                "class": "routine",
                "status": "modified",
                "additions": 40,
                "deletions": 0,
                "patch_truncated": True,
                "binary_or_unrendered": False,
                "previous_path": None,
            },
        ],
        "files_listing_incomplete": False,
    }
    REQUEST = {
        "tier": "governance",
        "requested_by": "job:pull-request-requests",
        "requester_kind": "automation",
    }

    def test_the_default_rationale_clears_the_engines_floor(self) -> None:
        """The engine refuses under 20 characters or a placeholder (D-130)."""
        from mykronos.approvals.engine import rationale_problem

        out = q.summary(self.REQUEST, self.EVIDENCE)
        assert rationale_problem(out["default_rationale"]) is None
        assert "#770 at 01234567" in out["default_rationale"]
        assert "governance 1, routine 1" in out["default_rationale"]

    def test_the_lines_name_every_file_its_class_and_a_truncated_patch(self) -> None:
        lines = "\n".join(q.summary(self.REQUEST, self.EVIDENCE)["lines"])
        assert "[governance] modified approval-policy-v1.yaml +3/-1" in lines
        assert "docs/DECISIONS.md +40/-0 (patch truncated)" in lines
        assert "requested by job:pull-request-requests (automation)" in lines

    def test_an_incomplete_listing_is_said_out_loud(self) -> None:
        ev = {**self.EVIDENCE, "files_listing_incomplete": True}
        assert any("INCOMPLETE" in line for line in q.summary(self.REQUEST, ev)["lines"])


# -- .gitattributes and a real union merge ---------------------------------------------


def test_the_decision_log_merges_by_union() -> None:
    lines = [
        line.split()
        for line in (ROOT / ".gitattributes").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    assert ["docs/DECISIONS.md", "merge=union"] in lines


def test_the_queue_supplies_the_same_driver_before_main_has_it() -> None:
    """The queue merges with a temporary attributes file so it works on PRs
    opened before this .gitattributes landed. The two must say the same."""
    script = (ROOT / "scripts" / "approval-queue.ps1").read_text(encoding="utf-8")
    assert "'docs/DECISIONS.md merge=union'" in script


needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git is not on PATH")


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """main appends D-139 after the branch point; the branch appended D-136,
    then renamed it D-137 in a second commit - #770's shape."""
    r = tmp_path / "r"
    (r / "docs").mkdir(parents=True)
    _git(r, "init", "-q", "-b", "main")
    shutil.copy(ROOT / ".gitattributes", r / ".gitattributes")
    log = r / "docs" / "DECISIONS.md"
    log.write_text(HEADER + entry(135) + entry(136, "Concourse"), encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-qm", "base")
    _git(r, "checkout", "-qb", "feat")
    log.write_text(log.read_text(encoding="utf-8") + entry(136, "The notifier"), encoding="utf-8")
    _git(r, "commit", "-qam", "D-136")
    text = log.read_text(encoding="utf-8")
    renamed = text.replace("## D-136 — The notifier", "## D-137 — The notifier")
    log.write_text(renamed, encoding="utf-8")
    _git(r, "commit", "-qam", "renumber to D-137")
    _git(r, "checkout", "-q", "main")
    log.write_text(log.read_text(encoding="utf-8") + entry(139, "Symbols"), encoding="utf-8")
    _git(r, "commit", "-qam", "D-139")
    return r


@needs_git
def test_merging_from_mains_side_keeps_the_log_clean(repo: Path) -> None:
    base = (repo / "docs" / "DECISIONS.md").read_text(encoding="utf-8")
    result = _git(repo, "merge", "--no-ff", "-m", "queue", "feat")
    assert result.returncode == 0, result.stderr
    merged = (repo / "docs" / "DECISIONS.md").read_text(encoding="utf-8")

    assert q.check_decisions(base, merged) == []
    assert q.headings(merged) == ["D-135", "D-136", "D-139", "D-137"]
    assert _git(repo, "merge-base", "--is-ancestor", "feat", "HEAD").returncode == 0, (
        "the merge must descend from the PR head, so pushing it is a fast-forward"
    )


@needs_git
def test_a_rebase_keeps_the_superseded_heading_and_the_check_catches_it(repo: Path) -> None:
    """Why the queue merges instead of rebasing (measured on #770 and #773)."""
    base = (repo / "docs" / "DECISIONS.md").read_text(encoding="utf-8")
    _git(repo, "checkout", "-q", "feat")
    assert _git(repo, "rebase", "main").returncode == 0
    merged = (repo / "docs" / "DECISIONS.md").read_text(encoding="utf-8")

    assert "D-136" in q.headings(merged)[3:]
    assert any("already uses: D-136" in p for p in q.check_decisions(base, merged))


@needs_git
def test_the_conflict_test_ignores_union_as_github_does(repo: Path, tmp_path: Path) -> None:
    """GitHub's merge button runs no driver. With `merge=union` in the tree, a
    plain merge-tree calls a log-only conflict clean; the queue's form must not,
    or it would skip the merge and then fail at `gh pr merge`."""
    empty = tmp_path / "noattrs"
    empty.write_text("", encoding="utf-8")
    plain = _git(repo, "merge-tree", "--write-tree", "main", "feat")
    github = _git(
        repo,
        "-c",
        f"core.attributesFile={empty}",
        "--attr-source=4b825dc642cb6eb9a060e54bf8d69288fbee4904",
        "merge-tree",
        "--write-tree",
        "main",
        "feat",
    )
    assert plain.returncode == 0, plain.stdout
    assert github.returncode == 1, github.stdout
    script = (ROOT / "scripts" / "approval-queue.ps1").read_text(encoding="utf-8")
    assert '"--attr-source=$EmptyTree"' in script


@needs_git
def test_the_round_simulation_defers_a_pr_the_one_before_it_will_re_head(
    tmp_path: Path,
) -> None:
    """Two PRs that each merge cleanly into main alone, but both append to the
    log: once the first is squash-merged the second conflicts. The queue's
    simulation - merge-tree onto a dangling commit of the previous result -
    has to see that before the operator spends a decision on the second."""
    r = tmp_path / "r"
    (r / "docs").mkdir(parents=True)
    _git(r, "init", "-q", "-b", "main")
    log = r / "docs" / "DECISIONS.md"
    log.write_text(HEADER + entry(135), encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-qm", "base")
    for name, number in (("a", 140), ("b", 141)):
        _git(r, "checkout", "-qb", name, "main")
        log.write_text(HEADER + entry(135) + entry(number), encoding="utf-8")
        _git(r, "commit", "-qam", name)
    _git(r, "checkout", "-q", "main")

    def merge_tree(ours: str, theirs: str) -> subprocess.CompletedProcess[str]:
        return _git(r, "merge-tree", "--write-tree", ours, theirs)

    assert merge_tree("main", "a").returncode == 0
    assert merge_tree("main", "b").returncode == 0
    tree = merge_tree("main", "a").stdout.splitlines()[0].strip()
    tip = _git(r, "commit-tree", tree, "-p", "main", "-m", "sim").stdout.strip()

    assert merge_tree(tip, "b").returncode == 1
    script = (ROOT / "scripts" / "approval-queue.ps1").read_text(encoding="utf-8")
    assert "'commit-tree', $tree, '-p', $tip" in script
