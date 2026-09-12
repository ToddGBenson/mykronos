"""The pipeline standard, enforced by the quality gate (D-078).

`docs/pipeline-standard.md` is twelve rules, each written because something failed
silently for long enough that a human had to notice it by accident. Rules held
only by a document decay exactly the way the `mykronos-ref` pin did — twice,
D-051 and D-074 — so the checker runs here, in the suite the `unit` lane runs,
which every scanning lane waits on.

Which means a pipeline edit that breaks the standard fails the quality gate
before a single scanner starts, rather than producing a lane that looks green
and reports nothing.

The rules themselves live in `scripts/check_pipeline_conformance.py`. These
tests assert two different things: that the pipelines conform *now*, and that
the checker would actually notice if they stopped — a green checker that
cannot fail is the thing it exists to prevent.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
CHECKER = REPO_ROOT / "scripts" / "check_pipeline_conformance.py"


def _load_checker():
    """Import the script by path.

    It lives in `scripts/` rather than in the package because it is a
    repository tool, not something a scanning task installs — the same place
    and for the same reason as `check_pinned_ref.py`.
    """
    spec = importlib.util.spec_from_file_location("check_pipeline_conformance", CHECKER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


checker = _load_checker()


@pytest.mark.parametrize("path", checker.pipelines(), ids=lambda p: p.name)
def test_pipeline_follows_the_standard(path: Path) -> None:
    """Every pipeline in the repository, found rather than listed (B-059).

    A hand-maintained list meant a new pipeline was exempt until somebody
    remembered to add it, and `personal-soc.yml` was exempt for long enough
    that all twelve of its tasks ran uncapped against the estate's single
    shared worker.
    """
    problems, rows = checker.check_pipeline(path)
    unrecorded = [p for p in problems if checker._gap_key(p) not in checker.KNOWN_GAPS]
    assert rows, f"{path.name} parsed to no jobs at all"
    assert not unrecorded, "\n".join(
        [f"{path.name} breaks docs/pipeline-standard.md:", *unrecorded]
    )


def test_every_recorded_gap_still_reproduces() -> None:
    """A baseline entry that no longer fires is a line that will outlive the
    problem it describes and start excusing a future one."""
    live = set()
    for path in checker.pipelines():
        problems, _ = checker.check_pipeline(path)
        live.update(checker._gap_key(p) for p in problems)

    stale = sorted(set(checker.KNOWN_GAPS) - live)

    assert not stale, "Fixed, so delete from KNOWN_GAPS: " + ", ".join(stale)


def test_every_recorded_gap_says_why() -> None:
    """`KNOWN_GAPS` is a baseline, not a pardon. An entry with no reason is
    an exemption by absence wearing a dictionary."""
    for key, reason in checker.KNOWN_GAPS.items():
        assert len(reason.split()) >= 6, f"{key} needs a reason, not a label"


def test_a_new_pipeline_is_covered_without_being_listed(tmp_path: Path) -> None:
    """The property the old shape did not have: coverage by default."""
    found = {path.name for path in checker.pipelines()}

    assert "personal-soc.yml" in found
    assert found == {path.name for path in checker.PIPELINE_DIR.glob("*.yml")}


def test_no_task_anywhere_runs_uncapped() -> None:
    """PS-7 across every pipeline, stated as its own test because it is an
    availability property of the estate rather than of one repository: there
    is one Concourse worker, and a hung task in any pipeline holds the others
    behind it."""
    uncapped: list[str] = []
    for path in checker.pipelines():
        problems, _ = checker.check_pipeline(path)
        uncapped.extend(p for p in problems if " PS-7 " in p)

    assert not uncapped, "\n".join(["Uncapped tasks share one worker:", *uncapped])


def _steps(document: dict) -> list[dict]:
    """Every mapping in the jobs section, hooks included."""
    found: list[dict] = []
    checker._walk(document["jobs"], found.append)
    return found


def test_no_verdict_step_is_ever_retried() -> None:
    """PS-12's first half, and the half that is a security control.

    `attempts:` re-runs a step on any non-success from inside the step, beneath
    the errored/failed routing the hooks use. On a scanner that makes a real
    finding and a DNS timeout the same event, and re-running until the answer
    changes is how a red gate becomes a green one. So it is allowed only where
    non-success is necessarily an error: a `get:`, which has no exit code, and
    the two hooks that end `exit 0` unconditionally.
    """
    offenders: list[str] = []
    for path in checker.pipelines():
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        for step in _steps(document):
            if "attempts" not in step or "get" in step:
                continue
            if step.get("task") not in checker.RETRYABLE_TASKS:
                offenders.append(f"{path.name}: {checker._step_label(step)}")

    assert not offenders, "\n".join(
        ["These can fail, not merely error, and something is retrying them:", *offenders]
    )


def test_the_two_named_refusals_keep_their_teeth() -> None:
    """The two controls story #59083 says a retry sweep would destroy.

    `dast-staging` refuses to report an empty scan as clean when its target is
    unreachable; `netassess-ingest` refuses to pass a check that reported
    `unknown`, because a check that did not run is not a pass. Both are the
    system being honest, both express it as a non-zero exit, and an `attempts:`
    on either would retry the refusal away. Named here rather than left to the
    general rule above because they are the reason the general rule exists.
    """
    named = {
        "thehub.yml": ("dast-staging", "zap-baseline"),
        "personal-soc.yml": ("netassess-ingest", "verify-and-diff"),
    }
    for path in checker.pipelines():
        if path.name not in named:
            continue
        job_name, task_name = named[path.name]
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        jobs = {job["name"]: job for job in document["jobs"]}
        assert job_name in jobs, f"{path.name} no longer defines {job_name}"

        tasks = [step for step in _steps({"jobs": [jobs[job_name]]}) if step.get("task") == task_name]
        assert tasks, f"{path.name}:{job_name} no longer has a {task_name} task"
        for task in tasks:
            assert "attempts" not in task, (
                f"{path.name}:{job_name} would retry {task_name} — that is the refusal "
                f"this job exists to make"
            )


def test_every_fetch_is_retried() -> None:
    """PS-12's second half, which is the one the story was actually about.

    Nothing retried anywhere, so a sealed Vault, a lost iptables lock and a DNS
    timeout each left a security lane dark for between eight hours and three
    days, and all three cleared on their own. Coverage has to be the default
    here: a `get:` added without `attempts:` is a lane that silently goes back
    to being one blip from silence.
    """
    unretried: list[str] = []
    for path in checker.pipelines():
        problems, _ = checker.check_pipeline(path)
        unretried.extend(p for p in problems if " PS-12 " in p and "no `attempts:`" in p)

    assert not unretried, "\n".join(["Fetches with no retry:", *unretried])


def test_the_checker_can_tell_a_verdict_from_a_fetch(tmp_path: Path) -> None:
    """The property PS-12 is worth nothing without.

    A green checker that cannot fail is the thing it exists to prevent, and
    here the two mutations are one keystroke apart in a diff: `attempts:` on a
    scanner, and `attempts:` missing from a fetch. It has to object to both,
    and it has to object differently.
    """
    source = checker.PIPELINE_DIR / "mykronos.yml"
    document = yaml.safe_load(source.read_text(encoding="utf-8"))

    for job in document["jobs"]:
        if job["name"] != "sast":
            continue
        for step in job["plan"]:
            if step.get("task") and step["task"] != "preflight":
                step["attempts"] = 2          # retrying a verdict
            if step.get("get") == "source":
                step.pop("attempts", None)    # a fetch left unprotected

    broken = tmp_path / "mykronos.yml"
    broken.write_text(yaml.safe_dump(document), encoding="utf-8")

    problems, _ = checker.check_pipeline(broken)
    retried = [p for p in problems if " PS-12 " in p and "can fail" in p]
    unretried = [p for p in problems if " PS-12 " in p and "no `attempts:`" in p]

    assert retried, problems
    assert unretried, problems


def test_a_hook_that_can_fail_loses_its_retry(tmp_path: Path) -> None:
    """The exemption is premised on `exit 0`, so it has to be checked.

    `notify-slack` and `report-to-hub` are allowed `attempts:` only because they
    end `exit 0` whatever happened, which makes never having run their only
    route to a non-success. An edit that gives either a non-zero exit path takes
    that premise away, and the exemption has to lapse with it rather than
    outlive the reason for it.
    """
    source = checker.PIPELINE_DIR / "thehub.yml"
    document = yaml.safe_load(source.read_text(encoding="utf-8"))

    patched = 0
    for step in _steps(document):
        if step.get("task") == "notify-slack" and "attempts" in step:
            args = step["config"]["run"]["args"]
            args[-1] = args[-1].rstrip() + "\nexit 1\n"
            patched += 1
    assert patched, "no retried notify-slack hook to break"

    broken = tmp_path / "thehub.yml"
    broken.write_text(yaml.safe_dump(document), encoding="utf-8")

    problems, _ = checker.check_pipeline(broken)
    assert any(" PS-12 " in p and "exemption has lapsed" in p for p in problems), problems


def test_every_reporting_job_is_cross_checked() -> None:
    """PS-1's second half: reporting without being checked is half the point.

    A job that uploads a capability and is absent from `CAPABILITY_BY_JOB`
    produces scan runs nothing compares against a build, so `silent` and
    `never_reported` can never be detected for it (spec 15 §4a.1). That is the
    state L0003 is about, and it is invisible by construction.
    """
    from mykronos.ci import CAPABILITY_BY_JOB

    missing: list[str] = []
    for path in checker.pipelines():
        relative = path.relative_to(REPO_ROOT).as_posix()
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        for job in document["jobs"]:
            body = checker._scripts(job)
            if "--capability" not in body:
                continue
            if job["name"] not in CAPABILITY_BY_JOB:
                missing.append(f"{Path(relative).name}:{job['name']}")

    assert not missing, (
        "These jobs upload a capability but are not in CAPABILITY_BY_JOB, so the "
        "coverage cross-check cannot see them: " + ", ".join(missing)
    )


def test_the_checker_can_actually_fail(tmp_path: Path) -> None:
    """Strip a timeout and a preflight; the checker must object to both."""
    source = checker.PIPELINE_DIR / "mykronos.yml"
    document = yaml.safe_load(source.read_text(encoding="utf-8"))

    for job in document["jobs"]:
        if job["name"] != "sast":
            continue
        job["plan"] = [step for step in job["plan"] if step.get("task") != "preflight"]
        for step in job["plan"]:
            step.pop("timeout", None)

    broken = tmp_path / "mykronos.yml"
    broken.write_text(yaml.safe_dump(document), encoding="utf-8")

    problems, _ = checker.check_pipeline(broken)
    assert any("PS-2" in problem and "sast" in problem for problem in problems), problems
    assert any("PS-7" in problem and "sast" in problem for problem in problems), problems
