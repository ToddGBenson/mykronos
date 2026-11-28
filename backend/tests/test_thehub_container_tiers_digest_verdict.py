"""container-tiers records one verdict per image digest (TheHub #62421).

FD-1 of TheHub's fast-deploy epic (61328): a deploy that pulls a digest which
already passed needs a verdict for THAT digest, readable from the deploy host
with the credential the risk gate already has (none: anonymous Concourse).
So `container-tiers`, already gating, runs the integration, unit and coverage
tiers in the image `fetch-image` resolved on this host, and a step on this
host prints one banner-framed `DIGEST VERDICT:` line naming the repo, the
commit, the digest, each tier's result and the time. TheHub's
`risk_gate.py digest-verdict <sha> <digest>` reads it from that step's log
events only, so a test, or the remote task, printing the banner forges
nothing.

The step runs whether the tiers passed or failed (an `ensure:` of the
wrapper), because a red verdict for a digest is as much a verdict as a green
one. It writes no verdict at all when this host cannot vouch for what it was
given: no exit code, another commit, an unknown result, or results that
disagree with the runner's exit code. The deploy reads that as `missing`.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.pipeline_steps import find, flat

ROOT = Path(__file__).resolve().parents[2]
PIPELINE = ROOT / "deploy" / "concourse" / "pipelines" / "thehub.yml"
JOB = "container-tiers"
TASK = "digest-verdict"
SHA = "a" * 40
DIGEST = "sha256:" + "b" * 64
# What TheHub's risk_gate.py matches (scripts/lib/risk_gate.py, #62421).
BLOCK = re.compile(r"(?m)^={50}\nDIGEST VERDICT: (\{[^\n]*\})\n={50}$")


def _doc() -> dict[str, Any]:
    doc: dict[str, Any] = yaml.safe_load(PIPELINE.read_text(encoding="utf-8"))
    return doc


def _plan() -> list[dict[str, Any]]:
    job = next(j for j in _doc()["jobs"] if j["name"] == JOB)
    plan: list[dict[str, Any]] = job["plan"]
    return plan


def _wrapper() -> dict[str, Any]:
    """The timed `do:` that holds the remote `tiers` task."""
    return next(
        s for s in _plan()
        if "do" in s and any(t.get("task") == "tiers" for t in flat(s["do"]))
    )


def _verdict_step() -> dict[str, Any]:
    ensure = _wrapper().get("ensure")
    assert isinstance(ensure, dict) and ensure.get("task") == TASK, (
        f"{JOB}: `{TASK}` must be the `ensure:` of the tiers wrapper, so a red "
        "tier gets a verdict for its digest too"
    )
    return ensure


def test_the_tiers_run_with_coverage() -> None:
    tiers = find(_plan(), "tiers")
    assert tiers["params"].get("CONTAINER_TIERS_COVERAGE") == "1", (
        "the coverage tier is deploy.sh's unit run with --cov; without it the "
        "digest verdict has no coverage result and can never be green"
    )


def test_the_tiers_hand_over_each_tiers_result() -> None:
    script = find(_plan(), "tiers")["config"]["run"]["args"][-1]
    assert '"$CONTAINER_TIERS_OUT/tiers.json" > ran/tiers.json' in script
    assert '"$CONTAINER_TIERS_OUT/coverage.pct" > ran/coverage.pct' in script


def test_the_digest_is_the_one_fetch_image_resolved_on_this_host() -> None:
    plan = _plan()
    names = [s.get("task") or s.get("load_var") for s in plan]
    loads = [s for s in plan if s.get("load_var") == "digest"]
    assert len(loads) == 1, f"{JOB}: one load_var of the fetched digest"
    assert loads[0]["file"] == "thehub-image/digest"
    assert names.index("digest") == names.index("fetch-image") + 1
    anchor = _doc()["anchors"]["fetch_image"]["config"]["run"]["args"][-1]
    assert '> thehub-image/digest' in anchor, "fetch-image must write the digest it resolved"
    assert _verdict_step()["params"]["DIGEST"] == "((.:digest))"


def test_the_verdict_is_decided_on_this_host() -> None:
    step = _verdict_step()
    assert step.get("tags") == ["thehub"], "the verdict is printed on this host, never remotely"
    assert step.get("image") == "python"
    inputs = {i["name"]: i for i in step["config"]["inputs"]}
    assert set(inputs) == {"ran", "commit"}
    assert inputs["ran"].get("optional") is True, "no linux worker ran it: still no crash"
    assert step.get("timeout") == "2m"


def _script() -> str:
    return str(_verdict_step()["config"]["run"]["args"][-1])


def _run(tmp_path: Path, *, rc: str | None = "0", commit: str = SHA,
         tiers: Any = None, pct: str | None = "61.4",
         digest: str = DIGEST, sha: str = SHA) -> tuple[int, str, dict[str, Any] | None]:
    (tmp_path / "commit").mkdir()
    (tmp_path / "commit" / "sha").write_text(sha + "\n", encoding="utf-8")
    ran = tmp_path / "ran"
    ran.mkdir()
    if rc is not None:
        (ran / "rc").write_text(rc + "\n", encoding="utf-8")
    (ran / "commit").write_text(commit, encoding="utf-8")
    if tiers is None:
        tiers = {"integration": "passed", "unit": "passed", "coverage": "passed"}
    if tiers != "absent":
        text = tiers if isinstance(tiers, str) else json.dumps(tiers)
        (ran / "tiers.json").write_text(text, encoding="utf-8")
    if pct is not None:
        (ran / "coverage.pct").write_text(pct, encoding="utf-8")
    out = subprocess.run(
        [sys.executable, "-c", _script()],
        cwd=tmp_path,
        env={"DIGEST": digest, **{k: os.environ[k] for k in ("SYSTEMROOT",) if k in os.environ}},
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    blocks = BLOCK.findall(out.stdout)
    assert len(blocks) <= 1, out.stdout
    return out.returncode, out.stdout + out.stderr, json.loads(blocks[0]) if blocks else None


def test_all_three_tiers_passing_is_a_green_verdict_for_the_digest(tmp_path: Path) -> None:
    rc, output, block = _run(tmp_path)
    assert rc == 0, output
    assert block is not None, output
    assert block["schema"] == 1
    assert block["repo"] == "ToddGBenson/TheHub"
    assert block["sha"] == SHA and block["digest"] == DIGEST
    assert block["verdict"] == "green"
    assert block["tiers"] == {"integration": "passed", "unit": "passed", "coverage": "passed"}
    assert block["coverage_pct"] == 61.4
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", block["at"])


def test_a_failing_tier_is_a_red_verdict_for_the_digest(tmp_path: Path) -> None:
    """AC4: a red tier gives a red verdict for that digest."""
    tiers = {"integration": "passed", "unit": "failed", "coverage": "passed"}
    rc, output, block = _run(tmp_path, rc="1", tiers=tiers)
    assert rc == 0, output
    assert block is not None and block["verdict"] == "red", output
    assert block["digest"] == DIGEST and block["tiers"]["unit"] == "failed"


def test_coverage_below_the_floor_is_red(tmp_path: Path) -> None:
    tiers = {"integration": "passed", "unit": "passed", "coverage": "failed"}
    _, output, block = _run(tmp_path, rc="1", tiers=tiers, pct="12.0")
    assert block is not None and block["verdict"] == "red", output


@pytest.mark.parametrize(
    ("rc", "tiers"),
    [
        # A TheHub from before #62421 writes no tiers.json: no coverage ran.
        ("0", "absent"),
        ("124", {"integration": "passed", "unit": "partial", "coverage": "partial"}),
        ("137", {"integration": "passed", "unit": "no_verdict", "coverage": "no_verdict"}),
        ("0", {"integration": "passed", "unit": "passed"}),
    ],
)
def test_a_tier_that_reached_no_verdict_is_indeterminate(
    tmp_path: Path, rc: str, tiers: Any
) -> None:
    _, output, block = _run(tmp_path, rc=rc, tiers=tiers)
    assert block is not None and block["verdict"] == "indeterminate", output


@pytest.mark.parametrize(
    "case",
    [
        {"rc": None},  # the task never ended: no EXIT trap ran
        {"rc": "x"},
        {"commit": "c" * 40},  # it judged another commit
        {"sha": "short"},  # this host exported nothing usable
        {"digest": "sha256:short"},
        {"digest": ""},
        {"tiers": "not json"},
        {"tiers": {"integration": "great", "unit": "passed", "coverage": "passed"}},
        {"tiers": {"integration": "passed", "unit": "passed", "coverage": "passed",
                   "e2e": "passed"}},
        # The runner's exit code and its per-tier results disagree.
        {"rc": "0", "tiers": {"integration": "failed", "unit": "passed", "coverage": "passed"}},
        {"rc": "1", "tiers": {"integration": "passed", "unit": "passed", "coverage": "passed"}},
        {"rc": "2", "tiers": {"integration": "passed", "unit": "passed", "coverage": "passed"}},
    ],
)
def test_nothing_this_host_cannot_vouch_for_becomes_a_verdict(
    tmp_path: Path, case: dict[str, Any]
) -> None:
    rc, output, block = _run(tmp_path, **case)
    assert rc == 0, "the step never fails the build: the job's exit code is linux-verdict's"
    assert block is None, f"{case} printed a verdict: {output}"
    assert "No DIGEST VERDICT" in output


def test_a_coverage_figure_that_is_not_a_percentage_is_dropped(tmp_path: Path) -> None:
    _, output, block = _run(tmp_path, pct="lots")
    assert block is not None and block["coverage_pct"] is None, output
