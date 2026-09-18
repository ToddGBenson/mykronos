"""#59329: the source guard had six tests and none of them ran it.

`test_pipeline_appliers_guarded.py` is six STATIC checks -- every applier
dot-sources the shared guard, none reads a file from the working tree, each
offers the same override name, each cleans up. All of that is worth having and
none of it establishes that the guard REFUSES anything.

The story is explicit about why that gap matters, and it is not hypothetical:

    "A guard that has only ever been observed passing is not known to work:
     each applier should be demonstrated refusing from a dirty tree and from a
     non-main branch before this is called done. Two guards written this week
     were green and blind, so this is not hypothetical."

Both of those blind guards were caught by running them. One was satisfied by
the script's own header comment; the other tested `-notin $null`, which is
always true, because the variable it read was defined further down the file.
Neither could fail. Both passed every static check anyone had written.

So `deploy/concourse/Test-PipelineSourceGuard.ps1` builds throwaway git
repositories under TEMP and calls `Assert-PipelineSourceIsMain` in every state
it claims to refuse -- no network, no real checkout, no Concourse. Executed
2026-09-17 against `PipelineSource.ps1`: **7 scenarios, 7 as documented.**

    clean, on main, level with origin      ALLOWED
    HEAD on a feature branch               REFUSED
    tracked file modified (dirty tree)     REFUSED
    main is behind origin/main             REFUSED
    no origin/main to compare against      REFUSED
    no local main branch at all            REFUSED
    -AllowAnyBranch on a feature branch    ALLOWED   (documented override)

The last one is deliberate. A guard with no escape hatch gets disabled
wholesale the first time somebody genuinely needs one, so the override is part
of the contract and is tested as such.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
GUARD = REPO_ROOT / "deploy" / "concourse" / "PipelineSource.ps1"
PROBE = REPO_ROOT / "deploy" / "concourse" / "Test-PipelineSourceGuard.ps1"


def test_the_probe_exists_beside_the_guard() -> None:
    """The execution test is part of the repo, not a thing somebody once ran."""
    assert GUARD.is_file(), GUARD
    assert PROBE.is_file(), (
        f"{PROBE.name} is missing. The guard's refusals are then only ever "
        "read, never run -- which is the state #59329 exists to leave."
    )


def test_every_refusal_branch_has_a_scenario() -> None:
    """The coverage assertion, and the one that runs everywhere.

    `Assert-PipelineSourceIsMain` accumulates into `$refusals`, one `+=` per
    condition. A new condition added without a scenario would leave the probe
    reporting all-green over a smaller set than the guard actually has -- the
    check quietly narrowing, which is this estate's recurring shape. So the
    count is asserted rather than trusted.
    """
    guard = GUARD.read_text(encoding="utf-8")
    # Deliberately NOT anchored to the start of a line. The canonical style
    # here is a multi-line `$refusals += "..."`, but a branch written inline
    # inside an `if` on one line is the same condition and must still count --
    # an anchored pattern would miss it and report full coverage over a
    # smaller set than the guard has.
    branches = re.findall(r"\$refusals\s*\+=", guard)
    assert branches, "no refusal branches found in the guard -- it cannot refuse at all"

    probe = PROBE.read_text(encoding="utf-8")
    scenarios = re.findall(r"^Probe\s+'([^']+)'", probe, re.MULTILINE)
    refusing = [s for s in scenarios if "clean" not in s]

    assert len(refusing) >= len(branches), (
        f"the guard has {len(branches)} refusal branches but the probe exercises "
        f"only {len(refusing)} refusing scenarios ({refusing}). A branch with no "
        "scenario is a refusal nobody has ever seen happen."
    )


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="pwsh not on PATH")
def test_the_guard_actually_refuses() -> None:
    """Run it. This is the whole point of the story.

    SKIPPED WHERE THERE IS NO POWERSHELL, and that is stated rather than hidden:
    the Concourse task containers are Linux without pwsh, so on those lanes only
    the coverage assertion above runs. The scripts under test are PowerShell and
    only ever execute on the Windows host, so the place this matters is the place
    it can run.
    """
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(PROBE)],
        capture_output=True,
        text=True,
        timeout=300,
    )
    tail = (result.stdout or "")[-2000:] + (result.stderr or "")[-2000:]
    assert result.returncode == 0, f"the guard did not behave as documented:\n{tail}"
    assert "did not" in tail, tail  # the summary line is always printed
    assert re.search(r"(\d+) scenarios, \1 behaved as documented, 0 did not", tail), (
        "the probe did not report every scenario passing:\n" + tail
    )
