"""MyKronos is actively scanned once a week, not only when someone remembers.

Every post-Delivery run is passive (D-053), and the active scan was reachable
only by a manual dispatch nobody had made: from 2026-10-08 to 2026-10-14 no
active scan ran anywhere. The weekly run turns it on, on a GitHub runner and
an ephemeral stack, so nothing it consumes is the shared host's.
"""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "demo-and-dast.yml"


def _workflow() -> dict:
    doc = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    # PyYAML reads the bare key `on` as the boolean True.
    doc["on"] = doc.pop(True, doc.get("on"))
    return doc


def _scan_step() -> dict:
    steps = _workflow()["jobs"]["demo-and-dast"]["steps"]
    return next(s for s in steps if s.get("id") == "zap")


def test_the_workflow_runs_on_a_weekly_schedule() -> None:
    crons = [entry["cron"] for entry in _workflow()["on"].get("schedule", [])]
    assert len(crons) == 1, "no scheduled run, so the active scan waits on a manual dispatch"
    assert crons[0].split()[2:] == ["*", "*", "0"], f"{crons[0]!r} is not weekly"


def test_the_job_does_not_skip_a_scheduled_run() -> None:
    condition = _workflow()["jobs"]["demo-and-dast"]["if"]
    assert "github.event_name == 'schedule'" in condition


def test_a_scheduled_run_is_an_active_scan() -> None:
    active = _scan_step()["env"]["ACTIVE"]
    assert "github.event_name == 'schedule'" in active
    assert "inputs.active_scan" in active, "a manual dispatch can no longer ask for one"


def test_a_delivery_cannot_cancel_the_weekly_scan() -> None:
    group = _workflow()["concurrency"]["group"]
    assert "github.event_name == 'schedule'" in group, (
        "the weekly run and post-Delivery runs share one cancel-in-progress group"
    )


def test_a_delivery_cannot_cancel_a_manual_active_scan() -> None:
    # 2026-10-15: the first manual active scan (run 38675775486) was cancelled
    # 7 minutes in by the next post-Delivery run, because the group split only
    # `schedule` from everything else. Any active run -- scheduled or asked
    # for -- queues apart from the passive post-Delivery runs.
    group = _workflow()["concurrency"]["group"]
    assert "inputs.active_scan" in group, (
        "a dispatched active scan shares the post-Delivery cancel-in-progress group"
    )
