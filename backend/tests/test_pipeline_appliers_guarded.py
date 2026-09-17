"""Every `fly set-pipeline` in this repository reads its configuration out of
the `main` commit (B-59073, B-59329).

WHAT WENT WRONG, TWICE, AND THEN TWICE MORE. A set-pipeline script that reads
its YAML off disk makes the live pipeline whatever the checkout happened to
hold when somebody ran it. B-59073 records two firings in opposite directions
-- a tree 129 commits behind on 2026-09-08, whose stale apply was then chased
as three separate bugs, and an unmerged feature branch 3 commits ahead on
2026-09-10 -- and fixed `set-thehub-pipeline.ps1`.

It fixed one of three siblings. `set-pipeline.ps1` and
`set-personal-soc-pipeline.ps1` kept reading off disk, from any branch, dirty,
for another week. The fourth firing was a worktree 162 commits behind on a
branch that does not define `dast-staging` -- one apply away from deleting a
security lane from the server, through the applier for the SECURITY pipeline.

WHY A TEST AND NOT THREE CAREFUL SCRIPTS. The defect this file is about is not
"a script lacks a guard". It is that a guard written into one of a set does
not reach the others, and nothing says so. Three copies kept in step is that
same shape waiting: the fourth applier somebody writes is unguarded by
default, exactly as the second and third were.

So there is one implementation, `deploy/concourse/PipelineSource.ps1`, and
this asserts that every applier goes through it -- found by globbing, not
listed, so a new one is covered the day it is written rather than the day
somebody remembers this file.

WHAT IS ACTUALLY ASSERTED. Not that the checks exist; checks are the part
B-59073 proved insufficient on its own. Verifying preconditions by hand and
then applying announced `docs/retro-2026-09-11 @ 62cfdac` -- somebody else
works in that tree and switched branches in the seconds in between. What
closes the race by construction is reading the bytes out of the commit, so
what is asserted is that no applier hands `fly set-pipeline` a path into the
working tree.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CONCOURSE = REPO_ROOT / "deploy" / "concourse"
SHARED_GUARD = CONCOURSE / "PipelineSource.ps1"

#: The function that performs the refusals and then resolves the blob. It
#: returns the only `--config` path an applier has, which is what makes the
#: guard unskippable rather than merely present: a script that does not call
#: it has nothing to apply.
RESOLVER = "Resolve-PipelineConfig"


def _appliers() -> list[Path]:
    """Found, not listed - the whole point.

    `test_pipeline_conformance` records what a hand-maintained list cost when
    `personal-soc.yml` was exempt from the pipeline standard until somebody
    remembered to add it. An applier is a script that runs `fly set-pipeline`;
    globbing the name pattern is how a fourth one arrives already covered.
    """
    return sorted(CONCOURSE.glob("set-*-pipeline.ps1")) + sorted(
        CONCOURSE.glob("set-pipeline.ps1")
    )


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


if not CONCOURSE.is_dir():  # pragma: no cover - the tree always has this
    pytest.skip("deploy/concourse not reachable", allow_module_level=True)


def test_the_appliers_are_findable() -> None:
    """A guard that silently measures nothing is worse than none.

    Every assertion below is parametrised over `_appliers()`. If the glob
    stops matching -- a rename, a move -- pytest generates zero cases and this
    file goes green having checked nothing, which is the failure mode of the
    thing it guards against turned on itself.
    """
    found = {path.name for path in _appliers()}

    assert found == {
        "set-pipeline.ps1",
        "set-personal-soc-pipeline.ps1",
        "set-thehub-pipeline.ps1",
    }, f"the set of pipeline appliers has changed: {sorted(found)}"
    assert SHARED_GUARD.is_file(), f"{SHARED_GUARD.name} is gone, so nothing is shared"


@pytest.mark.parametrize("path", _appliers(), ids=lambda p: p.name)
def test_every_applier_uses_the_shared_guard(path: Path) -> None:
    """One implementation, three callers. A script that re-implements the
    refusals locally passes its own review and drifts from the other two on
    the next change -- which is the history this story is made of.
    """
    body = _read(path)

    assert "PipelineSource.ps1" in body, (
        f"{path.name} does not dot-source PipelineSource.ps1, so it has its "
        "own answer to which commit a pipeline comes from"
    )
    assert RESOLVER in body, (
        f"{path.name} never calls {RESOLVER}, so whatever it applies did not "
        "come out of the `main` commit"
    )


@pytest.mark.parametrize("path", _appliers(), ids=lambda p: p.name)
def test_no_applier_applies_a_file_from_the_working_tree(path: Path) -> None:
    """THE PROPERTY THAT CLOSES THE RACE.

    `--config (Join-Path $PSScriptRoot "pipelines\\thehub.yml")` is the whole
    defect: it names a path in a mutable working tree, and between that
    expression and `fly` reading it anybody can change what is there.
    `git show <sha>:<path>` names an object nobody can edit.

    The override is the one legitimate on-disk read, and it lives inside
    `Resolve-PipelineConfig` where it announces itself in red -- not in the
    appliers, where it would be indistinguishable from the bug.
    """
    body = _read(path)
    on_disk = re.findall(r"Join-Path\s+\$PSScriptRoot\s+\"pipelines\\[^\"]+\"", body)

    assert not on_disk, (
        f"{path.name} builds a configuration path into the working tree: "
        f"{on_disk}. Whatever is at that path when `fly` reads it is what "
        f"gets applied. Take the path from {RESOLVER} instead."
    )


@pytest.mark.parametrize("path", _appliers(), ids=lambda p: p.name)
def test_every_applier_offers_the_same_named_override(path: Path) -> None:
    """One name across all three, because an operator who learns the escape
    hatch on one applier has learned it on the others. Three spellings of one
    flag is the same drift in miniature.
    """
    body = _read(path)

    assert "$AllowPipelineFromAnyBranch" in body, (
        f"{path.name} has no -AllowPipelineFromAnyBranch. Without a stated "
        "override, an operator who needs to try an unmerged pipeline edits "
        "the guard out instead, and it does not come back."
    )
    assert ".PARAMETER AllowPipelineFromAnyBranch" in body, (
        f"{path.name} does not document the override in its help, so the only "
        "way to find it is to read the guard"
    )


@pytest.mark.parametrize("path", _appliers(), ids=lambda p: p.name)
def test_every_applier_cleans_up_the_resolved_configuration(path: Path) -> None:
    """The resolved blob is written to the temp directory. A script that
    returns without deleting it leaves the pipeline configuration -- and for
    thehub, a config whose vars file sits beside it -- lying around the host.
    """
    body = _read(path)

    assert "$tempConfig" in body, f"{path.name} never captures the resolved temp path"
    assert re.search(r"finally\s*\{", body), f"{path.name} has no finally block"
    assert "Remove-Item $tempConfig -Force" in body, (
        f"{path.name} does not delete the resolved configuration it wrote"
    )


def test_the_shared_guard_reads_from_the_commit() -> None:
    """The one assertion about the guard itself rather than its callers.

    Everything above checks that the appliers delegate. If the thing they
    delegate to stopped reading from the commit, all three would still pass
    while all three applied a working tree again -- the same "green and
    measuring nothing" shape, one level down.
    """
    body = _read(SHARED_GUARD)

    assert '"show", $blob' in body, "the guard no longer reads the config with `git show`"
    assert "$($state.MainSha):" in body, (
        "the blob is not addressed by the resolved SHA, so it is not pinned to "
        "a commit"
    )
    # And the refusals must run inside the resolver, not merely somewhere in
    # the file -- a caller that can get a path without them is a caller that
    # can skip the guard.
    resolver = body[body.index(f"function {RESOLVER}") :]
    assert "Assert-PipelineSourceIsMain" in resolver, (
        f"{RESOLVER} hands back a configuration without re-running the "
        "refusals, so the checks and the apply are separated by whatever the "
        "caller does in between - which is the race B-59073 measured"
    )
