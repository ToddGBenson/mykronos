"""A Hub report cannot turn a post-merge build red (TheHub #61938, #62349).

TheHub's risk gate reads post-merge's build status. Two shapes refused a
deploy although nothing had graded the tip red:

* #2292 (and #2286, #2289, #2291): `grade` printed "Nothing to grade: this
  tip already has a determinate verdict" and exited 0, `report-verdict`
  exited 0, and then the build ended `timeout exceeded` four times and
  `failed`. Nothing in the plan was red; the timeouts were the job's own
  `report-to-hub` hooks (5m each, `attempts: 2`) against a Hub that did not
  answer. A failing hook fails the build in Concourse, and a timed-out step
  is failed, not errored. Because the watermark already held the tip, no
  later build could grade it again.
* #2743: `grade` graded the tip, `report-verdict` printed the VERDICT
  block, then the report hooks timed out while the Hub was frozen and the
  build ended `failed`. deploy.sh read the job as red.

Concourse has no way to make a build "errored" from a hook: the only
pipeline-side control is `try:`, which keeps a hook's failure, error or
timeout out of the build's status. So every report-to-hub hook of
post-merge is wrapped in `try:`, keeping its own `timeout:` and `attempts:`.
The verdict itself is untouched: `grade` and `report-verdict` are plan
steps, never in a `try:`, so a red or indeterminate verdict still ends the
build red and still refuses the sha.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from tests.pipeline_steps import flat

ROOT = Path(__file__).resolve().parents[2]
PIPELINE = ROOT / "deploy" / "concourse" / "pipelines" / "thehub.yml"
JOB = "post-merge"
HOOKS = ("on_success", "on_failure", "on_error", "on_abort")
HUB = "report-to-hub"
# The anchor's own ceiling (PS-7): one curl, five minutes.
HOOK_TIMEOUT = "5m"


def _job() -> dict[str, Any]:
    doc = yaml.safe_load(PIPELINE.read_text(encoding="utf-8"))
    return next(j for j in doc["jobs"] if j["name"] == JOB)


def _hook_steps(hook: str) -> list[dict[str, Any]]:
    node = _job().get(hook) or {}
    return list(node.get("do", [node] if node else []))


def test_every_post_merge_hook_still_reports_to_the_hub() -> None:
    """Guard: the four terminal states each still send exactly one report."""
    for hook in HOOKS:
        reports = [s for s in flat(_hook_steps(hook)) if s.get("task") == HUB]
        assert len(reports) == 1, f"post-merge {hook}: {len(reports)} report-to-hub steps"


def test_a_hub_report_that_times_out_cannot_fail_the_build() -> None:
    """The #2292 and #2743 shape: each report-to-hub hook is inside a `try:`."""
    bare = []
    for hook in HOOKS:
        for step in _hook_steps(hook):
            if step.get("task") == HUB:
                bare.append(hook)
    assert not bare, (
        f"post-merge's report-to-hub hook is not in a try: in {bare}; a Hub that "
        "does not answer times it out, which fails the build and makes TheHub's "
        "risk gate refuse a tip nothing graded red (#2292, #2743)"
    )


def test_a_guarded_hub_report_keeps_its_own_clock_and_retry() -> None:
    """`try:` must not remove the PS-7 ceiling: a hung report would hold the lane."""
    for hook in HOOKS:
        for step in _hook_steps(hook):
            inner = step.get("try")
            if not isinstance(inner, dict) or inner.get("task") != HUB:
                continue
            assert inner.get("timeout") == HOOK_TIMEOUT, f"{hook}: timeout {inner.get('timeout')!r}"
            assert inner.get("attempts"), f"{hook}: the hook lost its attempts"


def test_the_verdict_steps_are_never_guarded() -> None:
    """Guard: a red or indeterminate verdict still ends the build red.

    `grade` and `report-verdict` are plan steps outside any `try:`, so the
    exit code report-verdict takes from the verdict is the build's.
    """
    plan = _job()["plan"]
    guarded = [t for s in plan if "try" in s for t in flat([s["try"]])]
    names = {t.get("task") for t in flat(plan)}
    assert {"grade", "report-verdict"} <= names
    assert not {t.get("task") for t in guarded} & {"grade", "report-verdict"}
