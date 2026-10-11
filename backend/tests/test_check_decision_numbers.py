"""Decision numbers stay unique across main and the open pull requests (D-158).

On 2026-10-11 four numbers were taken twice by PRs open at the same time
(D-136 to D-139, and D-153 three times). Each branch was self-consistent, so
`test_decisions_log.py` passed on every one of them; only a comparison across
open PRs sees it. These pin that comparison and the approval queue's guard.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import check_decision_numbers as c  # noqa: E402

MAIN = set(range(1, 153))


class TestCollisions:
    def test_two_open_prs_that_each_add_d160_are_flagged(self) -> None:
        found = c.collisions(MAIN, [c.Change("#780", {160}, 780), c.Change("#781", {160}, 781)])

        assert len(found) == 1
        assert found[0].change == "#781", "the later PR renumbers"
        assert found[0].other == "#780"
        assert found[0].message == (
            "#781 adds D-160, but #780 also adds it: renumber D-160 -> D-161 in #781."
        )

    def test_distinct_numbers_pass(self) -> None:
        changes = [c.Change("#780", {160}, 780), c.Change("#781", {161}, 781)]
        assert c.collisions(MAIN, changes) == []

    def test_a_number_main_already_has_is_flagged(self) -> None:
        found = c.collisions(MAIN, [c.Change("#782", {152}, 782)])
        assert [f.message for f in found] == [
            "#782 adds D-152, but main already has it: renumber D-152 -> D-153 in #782."
        ]

    def test_three_prs_on_one_number_get_three_different_numbers(self) -> None:
        """D-153 was taken three times. Two must move, and not to the same place."""
        changes = [c.Change(f"#{n}", {153}, n) for n in (780, 781, 782)]
        found = c.collisions(MAIN, changes)
        assert sorted(f.change for f in found) == ["#781", "#782", "#782"]
        assert len({f.suggest for f in found}) == len(found)
        assert min(f.suggest for f in found) == 154

    def test_the_suggestion_clears_every_open_pr_not_just_main(self) -> None:
        changes = [c.Change("#780", {160}, 780), c.Change("#781", {160, 170}, 781)]
        assert c.collisions(MAIN, changes)[0].suggest == 171

    def test_focus_keeps_only_the_named_prs_collisions(self) -> None:
        changes = [
            c.Change("#780", {160}, 780),
            c.Change("#781", {160}, 781),
            c.Change("#782", {165}, 782),
            c.Change("#783", {165}, 783),
        ]
        assert {f.change for f in c.collisions(MAIN, changes, focus="#780")} == {"#781"}
        assert c.collisions(MAIN, changes, focus="#999") == []

    def test_next_free_is_above_main_and_every_open_pr(self) -> None:
        assert c.next_free(MAIN, [c.Change("#780", {156}, 780)]) == 157


class TestTheQueuesGuard:
    def test_a_pr_repeating_an_earlier_pr_in_the_round_is_refused(self) -> None:
        refused = c.round_refusals(MAIN, [c.Change("#775", {160}), c.Change("#777", {160})])
        assert [(r.change, r.other) for r in refused] == [("#777", "#775")]
        assert "renumber D-160 -> D-161 in #777" in refused[0].message

    def test_a_pr_repeating_main_is_refused(self) -> None:
        refused = c.round_refusals(MAIN, [c.Change("#775", {150})])
        assert refused[0].other == "main"

    def test_a_refused_pr_does_not_block_the_ones_after_it(self) -> None:
        """#777 is refused for repeating main; #778 repeating #777's number is
        not, because #777 will not merge with it."""
        refused = c.round_refusals(MAIN, [c.Change("#777", {150, 160}), c.Change("#778", {160})])
        assert {r.change for r in refused} == {"#777"}

    def test_distinct_numbers_pass_the_guard(self) -> None:
        assert c.round_refusals(MAIN, [c.Change("#775", {160}), c.Change("#777", {161})]) == []

    def test_the_queue_runs_the_guard_before_deciding(self) -> None:
        script = (ROOT / "scripts" / "approval-queue.ps1").read_text(encoding="utf-8")
        guard = script.index("& $Python $checker round $RepoPath")
        assert guard < script.index("# 3. Decide.")
        assert 'Drop ([int] $r.number) "refused: $($r.message)"' in script


class TestReadingTrees:
    def test_numbers_come_from_log_headings_and_file_names(self) -> None:
        log = "## D-001 — One\n\ntext\n\n## D-137 — In the log still\n"
        files = ["D-149-queue.md", "README.md", "D-152-evidence.md"]
        assert c.numbers_in(log, files) == {1, 137, 149, 152}


needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git is not on PATH")


def _git(repo: Path, *args: str) -> str:
    out = subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    return out.stdout.strip()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    r = tmp_path / "r"
    (r / "docs" / "decisions").mkdir(parents=True)
    _git(r, "init", "-q", "-b", "main")
    (r / "docs" / "DECISIONS.md").write_text(
        "# Decision log\n\n## D-001 — One\n\nx\n\n---\n\n## D-137 — Two\n\ny\n", encoding="utf-8"
    )
    (r / "docs" / "decisions" / "D-149-queue.md").write_text("## D-149 — Q\n", encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-qm", "base")
    _git(r, "update-ref", "refs/remotes/origin/main", "main")
    return r


@needs_git
def test_a_branch_adds_only_its_new_files(repo: Path) -> None:
    _git(repo, "checkout", "-qb", "feat")
    (repo / "docs" / "decisions" / "D-160-new.md").write_text("## D-160 — N\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "D-160")

    assert c.added_by(repo, "feat") == {160}


@needs_git
def test_moving_an_entry_from_the_log_into_a_file_adds_nothing(repo: Path) -> None:
    """scripts/move-decisions-to-files.py's PR: D-137 leaves the log and
    arrives as a file. Same number, not a new one."""
    _git(repo, "checkout", "-qb", "move")
    log = repo / "docs" / "DECISIONS.md"
    log.write_text("# Decision log\n\n## D-001 — One\n\nx\n", encoding="utf-8")
    (repo / "docs" / "decisions" / "D-137-two.md").write_text("## D-137 — Two\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "move")

    assert c.added_by(repo, "move") == set()


@needs_git
def test_an_entry_appended_to_the_log_counts_during_the_transition(repo: Path) -> None:
    _git(repo, "checkout", "-qb", "old-style")
    log = repo / "docs" / "DECISIONS.md"
    log.write_text(
        log.read_text(encoding="utf-8") + "\n---\n\n## D-161 — Old style\n\nz\n", encoding="utf-8"
    )
    _git(repo, "commit", "-qam", "append")

    assert c.added_by(repo, "old-style") == {161}
