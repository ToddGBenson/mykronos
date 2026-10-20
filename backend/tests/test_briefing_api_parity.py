"""`GET /api/dashboard/briefing` and `mykronos briefing` say the same thing (#60808).

The endpoint's docstring calls it "the same view `mykronos briefing` prints",
but only the CLI handed `briefing.build` the inputs from outside the lake, so
the API (and the MCP `briefing()` tool that reads it) silently had no paused,
failing or held-back lanes, no job health, no tokens, no toxic combinations
and no exposure. Both are built here from one stubbed `briefing_sources.gather`
and compared section by section.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import pytest

import mykronos.cli as cli
from mykronos import briefing_sources
from mykronos.briefing import (
    BlockedLane,
    FailingLane,
    PausedLane,
    ProductionLag,
    TokenDelivery,
)
from mykronos.platform_health import JobHealth
from tests.conftest import REPO, finding_payload, post_findings, post_scan
from tests.test_onboarding import onboard

#: Section name in both outputs -> the fields that identify an entry.
SECTIONS = {
    "paused": ("pipeline", "job", "last_status", "build_url"),
    "failing": ("pipeline", "job", "last_status", "build_url"),
    "blocked": ("pipeline", "job", "blocked_by", "root", "root_state"),
    "unhealthy_jobs": ("name", "status", "detail", "consecutive_failures"),
    "tokens": ("repo_full_name", "state", "scanned_by"),
    "exposure": ("url", "repo_full_name", "last_status"),
    # #452: the PRODUCTION IS BEHIND line, per repository.
    "production_lag": (
        "repo_full_name", "status", "behind_by", "not_on_branch", "detail",
        "closed_since_unmatched",
    ),
}

#: The CLI's flag for each source the API names in `unknown`.
UNKNOWN_FLAGS = {
    "concourse": ("paused_unknown", "failing_unknown", "blocked_unknown"),
    "job_runs": ("jobs_unknown",),
    "ingestion_tokens": ("tokens_unknown",),
    "toxic": ("toxic_unknown",),
    "exposure": ("exposure_unknown",),
    "deployments": ("production_lag_unknown",),
}


def _everything_read() -> briefing_sources.OperationalInputs:
    now = datetime(2026, 10, 1, tzinfo=UTC)
    return briefing_sources.OperationalInputs(
        paused_jobs=[PausedLane(pipeline="keel", job="dast", last_status="failed")],
        failing_jobs=[FailingLane(pipeline="soc", job="netassess", last_status="errored")],
        blocked_jobs=[
            BlockedLane(
                pipeline="thehub",
                job="go-no-go",
                blocked_by="deploy-demo",
                root="deploy-demo",
                root_state="failing",
            )
        ],
        unhealthy_jobs=[
            JobHealth(name="acceptance_sweep", status="failing", detail="boom",
                      consecutive_failures=4)
        ],
        tokens=[
            TokenDelivery(
                repo_full_name=REPO,
                state="due",
                issued_at=now,
                rotate_after=now,
                scanned_by="concourse",
            )
        ],
        toxic_combinations=[],
        toxic_coverage={"rules": 3, "cannot_fire": []},
        exposure=[{"url": "https://example.test", "repo_full_name": REPO,
                   "last_status": "open", "observations": []}],
        production_lag=[
            ProductionLag(
                repo_full_name=REPO,
                status="behind",
                branch="main",
                deployed_revision="a2a7566c0ffee",
                behind_by=40,
                not_on_branch=0,
                deployed_committed_at=now,
                undeployed_fixes=[
                    {"finding_id": "f-1", "rule_id": "B608", "severity": "high",
                     "title": "SQL", "status": "fixed", "basis": "last_seen_in_range",
                     "commit": "a2a7566c0ffee"},
                ],
                closed_since_unmatched=2,
            ),
            ProductionLag(
                repo_full_name="ToddGBenson/TheHub",
                status="unknown",
                branch="develop",
                detail="the probe could not read the running revision",
            ),
        ],
    )


def _nothing_read() -> briefing_sources.OperationalInputs:
    return briefing_sources.OperationalInputs()


def _both(
    client: Any,
    admin_auth: dict[str, str],
    settings: Any,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    inputs: briefing_sources.OperationalInputs,
) -> tuple[dict[str, Any], dict[str, Any]]:
    assert onboard(client, admin_auth).status_code in (200, 201)
    monkeypatch.setattr(briefing_sources, "gather", lambda *_args: inputs)
    monkeypatch.setattr(cli, "get_settings", lambda: settings)

    def _no_github(_settings: Any) -> Any:
        raise RuntimeError("no GitHub in this test")

    monkeypatch.setattr(cli, "_github_factory", _no_github)

    response = client.get("/api/dashboard/briefing", headers=admin_auth)
    assert response.status_code == 200, response.text
    capsys.readouterr()
    assert cli.main(["briefing", "--json"]) == 0
    return response.json(), json.loads(capsys.readouterr().out)


def _ids(entries: list[dict[str, Any]], keys: tuple[str, ...]) -> list[tuple[Any, ...]]:
    return [tuple(entry.get(k) for k in keys) for entry in entries]


def test_the_api_has_every_section_the_cli_prints(
    client, admin_auth, settings, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    api, terminal = _both(client, admin_auth, settings, monkeypatch, capsys, _everything_read())

    for section, keys in SECTIONS.items():
        assert terminal[section], f"the stub should fill {section}"
        assert _ids(api[section], keys) == _ids(terminal[section], keys), section
    assert api["toxic"] == terminal["toxic"] == []
    assert [lag["undeployed_fixes"] for lag in api["production_lag"]] == [
        lag["undeployed_fixes"] for lag in terminal["production_lag"]
    ]
    assert api["toxic_coverage"] == terminal["toxic_coverage"]
    assert api["total_open"] == terminal["total_open"]
    assert len(api["stalled"]) == len(terminal["stalled"])
    assert api["unknown"] == []
    assert not any(flag for flags in UNKNOWN_FLAGS.values() for flag in flags
                   if terminal[flag])


def test_a_source_that_cannot_be_read_is_listed_in_unknown(
    client, admin_auth, settings, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """`None` from the gatherer is "could not ask", which the CLI prints as
    such. The API must name it, not hand back an empty list that reads as "all
    clear"."""
    api, terminal = _both(client, admin_auth, settings, monkeypatch, capsys, _nothing_read())

    for section in SECTIONS:
        assert api[section] == terminal[section] == []
    named = {entry["source"] for entry in api["unknown"]}
    assert named == set(UNKNOWN_FLAGS)
    for source, flags in UNKNOWN_FLAGS.items():
        assert all(terminal[flag] for flag in flags), source
    assert all(entry["detail"] for entry in api["unknown"])


def test_the_jobs_held_behind_a_stalled_lane_reach_the_api(
    client, auth, admin_auth, settings, monkeypatch: pytest.MonkeyPatch, capsys,
    run_compaction,
) -> None:
    """#330's sentence on the page, not only in the terminal.

    `mykronos briefing` says "N jobs are held behind it" for a stalled lane
    that gates others, and the dashboard said "Nothing is stuck behind these"
    for the same lane because the API carried no such fact. Both now read the
    lane's `held_behind`, built once from the blocked list.
    """
    post_scan(client, auth, scan_run_id="run-1", scan_status="failure")
    post_findings(client, auth, [finding_payload()], scan_run_id="run-1")
    run_compaction()
    pipeline = REPO.rsplit("/", 1)[-1].lower()
    inputs = briefing_sources.OperationalInputs(
        blocked_jobs=[
            # Behind the lane directly, behind it transitively, and on another
            # pipeline -- the last must not count.
            BlockedLane(pipeline=pipeline, job="secrets", blocked_by="sast", root="sast",
                        root_state="failing"),
            BlockedLane(pipeline=pipeline, job="iac", blocked_by="secrets", root="sast",
                        root_state="failing"),
            BlockedLane(pipeline="elsewhere", job="dast", blocked_by="sast", root="sast",
                        root_state="failing"),
        ],
    )

    api, terminal = _both(client, admin_auth, settings, monkeypatch, capsys, inputs)

    assert [lane["capability"] for lane in api["stalled"]] == ["sast"]
    assert api["stalled"][0]["held_behind"] == ["iac", "secrets"]
    assert [lane["held_behind"] for lane in api["stalled"]] == [
        lane["held_behind"] for lane in terminal["stalled"]
    ]


def test_a_lane_nothing_waits_on_holds_nothing_behind_it(
    client, auth, admin_auth, settings, monkeypatch: pytest.MonkeyPatch, capsys,
    run_compaction,
) -> None:
    """Empty, not absent: the page keeps "nothing is stuck" only for this."""
    post_scan(client, auth, scan_run_id="run-1", scan_status="failure")
    post_findings(client, auth, [finding_payload()], scan_run_id="run-1")
    run_compaction()

    api, terminal = _both(client, admin_auth, settings, monkeypatch, capsys, _nothing_read())

    assert api["stalled"][0]["held_behind"] == []
    assert terminal["stalled"][0]["held_behind"] == []
