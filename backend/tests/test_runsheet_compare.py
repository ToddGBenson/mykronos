"""The run sheet's acceptance script (TheHub #61141): "for 7 days it matches
Start-Here -Check output, compared by a script".

`scripts/runsheet_compare.py` reads a `Start-Here -Check` transcript and the
`GET /api/dashboard/today` body, says per step whether they agree, appends
the verdict to a log, and summarises the log as a run of agreeing days. The
transcripts here are in the exact shapes Start-Here prints.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import runsheet_compare as rc  # noqa: E402

ID = "0f1e2d3c-aaaa-bbbb-cccc-000000000001"
OTHER = "9a8b7c6d-aaaa-bbbb-cccc-000000000002"
MAIN = "c" * 40
RUNNING = "d" * 40

TRANSCRIPT = f"""
== [Delivery] 0. Pre-flight: agent credentials, then review requests
  nothing to request
== [Delivery] 1. Decisions
  {ID[:8]}  pull_request_merge T2          acme/app#7@{"a" * 40}
  waits for the next run (the reviewer has not posted yet): acme/app#9@bbbbbbb
  (check mode: would ask)   Review these 1 now?
== [Delivery] 2. Merges
  acme/TheHub#561  not approved at its head 1234567: it waits for the next batch
  acme/TheHub#564  Re-export the mirror
  acme/app#7  Rate-limit the export route
  acme/app#8  Pin the uploader
      not yet: waiting on independent-review
  acme/keel#3  ShellCheck fixes
      not yet: needs your self-review record (see one-offs)
  app#1031 (registry -p20261026) is superseded by #1046 (-p20261030): decline it by closing it.
  (check mode: would ask)   Merge these 1 PR(s), oldest first?
== [Delivery] 3. Deploy MyKronos production
  running: {RUNNING[:7]}   main: {MAIN[:7]}   Delivery on main: completed success
  (check mode: would ask)   Deploy {MAIN[:7]} to production? (waits up to 45 min for the risk gate)
== [Delivery] 4. One-offs
  acme/app#7  this line is in a later section and is not a merge
"""


def item(ref: str, state: str) -> dict:
    return {"text": ref, "state": state, "reason": "", "owner": "you", "ref": ref, "url": ""}


def sheet(
    *,
    decide: list[dict] | None = None,
    merge: list[dict] | None = None,
    deploy_state: str = "ready",
    deploy_summary: str = f"deploy {MAIN[:7]}: production runs {RUNNING[:7]}",
) -> dict:
    def step(key: str, state: str, items: list[dict], summary: str = "") -> dict:
        return {
            "key": key,
            "title": key.title(),
            "state": state,
            "summary": summary,
            "items": items,
            "hidden": [],
            "status": "ok",
            "reason": "",
            "notes": [],
        }

    return {
        "generated_at": "2026-11-01T12:00:00",
        "steps": [
            step("decide", "ready", decide if decide is not None else [item(ID, "ready")]),
            step(
                "merge",
                "ready",
                merge
                if merge is not None
                else [
                    item("acme/TheHub#561", "waiting"),
                    item("acme/TheHub#564", "ready"),
                    item("acme/app#7", "ready"),
                    item("acme/app#8", "waiting"),
                    item("acme/keel#3", "waiting"),
                    item("acme/elsewhere#2", "ready"),
                ],
            ),
            step("deploy", deploy_state, [], deploy_summary),
            step("tasks", "done", []),
        ],
    }


class TestParseStartHere:
    def test_decisions_are_the_decidable_request_ids(self) -> None:
        parsed = rc.parse_start_here(TRANSCRIPT)
        assert parsed.decide == {ID[:8]}

    def test_merges_offered_are_those_with_no_not_yet_line(self) -> None:
        parsed = rc.parse_start_here(TRANSCRIPT)
        assert parsed.merge_ready == {"acme/TheHub#564", "acme/app#7"}
        assert parsed.merge_repos == {"acme/TheHub", "acme/app", "acme/keel"}

    def test_the_deploy_offer_reads_as_ready_with_its_shas(self) -> None:
        parsed = rc.parse_start_here(TRANSCRIPT)
        assert parsed.deploy == "ready"
        assert (parsed.running, parsed.main) == (RUNNING[:7], MAIN[:7])

    def test_each_deploy_outcome_maps_to_the_run_sheet_state(self) -> None:
        def deploy(line: str) -> str | None:
            text = f"== [Delivery] 3. Deploy MyKronos production\n  {line}\n"
            return rc.parse_start_here(text).deploy

        cases = {
            "production is on main": "done",
            "main is ahead, but 02:40-04:15Z (7:40-9:15 pm Arizona) is the backup window. "
            "Re-run after it.": "waiting",
            "main is ahead, but main's Delivery concluded 'failure': "
            "no image to deploy.": "blocked",
            "main is ahead, but its unit or lint-and-types lane is red - "
            "not deploying a broken main.": "blocked",
            "main is ahead, but its Delivery has not succeeded yet - "
            "re-run this script later": "waiting",
            "The gate refused ccccccc: it introduced blocking findings. Not deploying": "blocked",
            # Guards only the host can see: not comparable, never guessed.
            "main is ahead, but HubOps is deploying TheHub - one deploy at a time.": rc.HOST_ONLY,
            "main is ahead; the Delivery session deploys ccccccc itself "
            "after TheHub's deploy.": rc.HOST_ONLY,
        }
        assert {line: deploy(line) for line in cases} == cases

    def test_nothing_waiting_is_an_empty_set_not_a_missing_section(self) -> None:
        text = "== [Delivery] 1. Decisions\n  nothing waiting for your decision\n"
        parsed = rc.parse_start_here(text)
        assert parsed.decide == set()
        assert parsed.sections == {"decide"}


class TestCompare:
    def test_agreeing_output_agrees_on_every_compared_step(self) -> None:
        result = rc.compare(rc.parse_start_here(TRANSCRIPT), sheet())
        assert result.agree, result.diffs
        assert result.steps == {"decide": True, "merge": True, "deploy": True}

    def test_merge_compares_only_the_repositories_start_here_covers(self) -> None:
        # acme/elsewhere#2 is ready on the run sheet (the default sheet), and
        # Start-Here never lists that repository: out of scope, not a diff. A
        # covered repository's PR ready on one side only is a diff.
        body = sheet()
        body["steps"][1]["items"][4] = item("acme/keel#3", "ready")
        result = rc.compare(rc.parse_start_here(TRANSCRIPT), body)
        assert result.steps["merge"] is False
        assert result.diffs == ["merge: acme/keel#3 ready on the run sheet only"]

    def test_a_request_only_one_side_offers_is_a_diff_naming_it(self) -> None:
        result = rc.compare(
            rc.parse_start_here(TRANSCRIPT),
            sheet(decide=[item(ID, "ready"), item(OTHER, "ready")]),
        )
        assert result.steps["decide"] is False
        assert any(OTHER[:8] in d and "run sheet only" in d for d in result.diffs)

    def test_a_different_deploy_state_is_a_diff(self) -> None:
        result = rc.compare(rc.parse_start_here(TRANSCRIPT), sheet(deploy_state="waiting"))
        assert result.steps["deploy"] is False
        assert any("Start-Here ready, run sheet waiting" in d for d in result.diffs)

    def test_a_different_running_sha_is_a_diff_even_when_states_agree(self) -> None:
        result = rc.compare(
            rc.parse_start_here(TRANSCRIPT),
            sheet(deploy_summary=f"deploy {MAIN[:7]}: production runs eeeeeee"),
        )
        assert result.steps["deploy"] is False

    def test_a_host_only_deploy_guard_is_skipped_not_failed(self) -> None:
        text = TRANSCRIPT.replace(
            f"  (check mode: would ask)   Deploy {MAIN[:7]} to production? "
            "(waits up to 45 min for the risk gate)",
            "  main is ahead, but HubOps is deploying TheHub - one deploy at a time.",
        )
        result = rc.compare(rc.parse_start_here(text), sheet())
        assert "deploy" not in result.steps
        assert any("host" in s for s in result.skipped)

    def test_a_step_the_server_could_not_read_is_a_diff(self) -> None:
        body = sheet()
        body["steps"][0]["status"] = "unavailable"
        body["steps"][0]["state"] = "unknown"
        body["steps"][0]["items"] = []
        result = rc.compare(rc.parse_start_here(TRANSCRIPT), body)
        assert result.steps["decide"] is False


class TestLog:
    def record(self, at: str, agree: bool) -> str:
        return json.dumps({"at": at, "agree": agree, "steps": {}, "diffs": []})

    def test_seven_agreeing_days_in_a_row_pass(self) -> None:
        lines = [self.record(f"2026-11-0{d}T15:00:00Z", True) for d in range(1, 8)]
        summary = rc.summarise(lines)
        assert summary.streak == 7
        assert summary.passed

    def test_one_disagreeing_run_resets_the_streak_for_its_day(self) -> None:
        lines = [self.record(f"2026-11-0{d}T15:00:00Z", True) for d in range(1, 8)]
        lines.append(self.record("2026-11-04T18:00:00Z", False))
        summary = rc.summarise(lines)
        assert summary.streak == 3
        assert not summary.passed
        assert summary.disagreeing_days == ["2026-11-04"]

    def test_a_day_with_no_run_breaks_the_streak(self) -> None:
        lines = [self.record(f"2026-11-0{d}T15:00:00Z", True) for d in (1, 2, 3, 5, 6, 7, 8)]
        assert rc.summarise(lines).streak == 4

    def test_main_appends_one_record_and_exits_by_agreement(self, tmp_path: Path) -> None:
        transcript = tmp_path / "start-here.txt"
        transcript.write_text(TRANSCRIPT, encoding="utf-8")
        today = tmp_path / "today.json"
        today.write_text(json.dumps(sheet()), encoding="utf-8")
        log = tmp_path / "compare.jsonl"
        code = rc.main(
            ["--start-here", str(transcript), "--today", str(today), "--log", str(log)]
        )
        assert code == 0
        [line] = log.read_text(encoding="utf-8").splitlines()
        assert json.loads(line)["agree"] is True
        today.write_text(json.dumps(sheet(deploy_state="blocked")), encoding="utf-8")
        assert rc.main(["--start-here", str(transcript), "--today", str(today)]) == 1
