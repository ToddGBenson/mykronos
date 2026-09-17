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
import re
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

        tasks = [
            step
            for step in _steps({"jobs": [jobs[job_name]]})
            if step.get("task") == task_name
        ]
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


# ---------------------------------------------------------------------------
# The `set-pipeline` job, and the vars that make it safe (#355)
# ---------------------------------------------------------------------------
#
# Seven commits sat merged and inert because applying a pipeline was a thing
# somebody had to remember. `set_pipeline: self` closes that, and introduces one
# failure mode worth more than a comment: `fly set-pipeline --load-vars-from`
# interpolates client side (D-043), so the *running* pipeline is the committed
# YAML plus a vars file that exists only inside a PowerShell script. A self-apply
# that does not reproduce those vars applies a different pipeline -- and for
# thehub the first casualty is `source`, whose `branch:` is one of them, which
# takes every job down including the one that could put it back.
#
# So these assert three things: the job is there, it can supply every var the
# pipeline uses, and the committed copy of those vars still equals what the
# apply script writes.

VARS_DIR = REPO_ROOT / "deploy" / "concourse" / "vars"
CONCOURSE_DIR = REPO_ROOT / "deploy" / "concourse"

#: pipeline stem -> the script that applies it by hand today.
APPLY_SCRIPT = {
    "mykronos": "set-pipeline.ps1",
    "personal-soc": "set-personal-soc-pipeline.ps1",
    "thehub": "set-thehub-pipeline.ps1",
}

#: Resolved from Vault at build time for every pipeline, so absent from both the
#: apply scripts' vars files and the committed ones. Neither script writes them
#: and both say why in a comment beside the omission.
TEAM_VAULT_VARS = frozenset({"slack-bot-token", "slack-alert-channel"})

#: Per-pipeline Vault vars that no `Add-Secret` call names.
EXTRA_VAULT_VARS = {
    # "The key itself is in Vault (concourse/main/thehub/source-deploy-key), so
    # it never appears in `fly get-pipeline` output" -- pipelines/thehub.yml.
    "thehub": frozenset({"source-deploy-key"}),
}

#: Vars a `set_pipeline` step cannot supply and Vault does not hold, so the
#: first automatic apply takes them away from the jobs that read them. Each is
#: argued in that pipeline's `set-pipeline` comment; this list is what stops one
#: being added quietly, and what goes red when one is finally closed.
UNRESOLVED_AFTER_SELF_APPLY = {
    "mykronos": frozenset(),
    "personal-soc": frozenset({"hibp-api-key", "monitor-emails"}),
    "thehub": frozenset(
        {
            "github-token",
            "azure-client-id",
            "azure-client-secret",
            "azure-tenant-id",
            "azure-subscription-id",
        }
    ),
}


def _set_pipeline_job(document: dict) -> dict:
    for job in document["jobs"]:
        if job["name"] == "set-pipeline":
            return job
    raise AssertionError("no set-pipeline job")


def _vars_used(document: object) -> set[str]:
    """Every `((var))` in the parsed pipeline.

    Parsed rather than grepped: these files describe vars they no longer use in
    comments, and a grep would report the explanation as a requirement.
    """
    found: set[str] = set()

    def visit(node: object) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                visit(key)
                visit(value)
        elif isinstance(node, list):
            for value in node:
                visit(value)
        elif isinstance(node, str):
            found.update(re.findall(r"\(\(([A-Za-z0-9_.-]+)\)\)", node))

    visit(document)
    return found


def _script_vars(stem: str) -> dict[str, str]:
    """`"<name>: <value>"` entries from an apply script's vars array.

    The value is resolved one step: a `$Param` reference becomes that
    parameter's default, which is where this repository keeps the decision --
    B-045 passed `-Branch develop` at apply time, left the default at `main`,
    and the next unrelated apply silently moved TheHub back. Anything computed
    at run time (`$(Read-EnvValueOptional ...)`, a minted token) resolves to the
    sentinel `<runtime>` and is expected to be absent from the committed file
    rather than guessed at.
    """
    text = (CONCOURSE_DIR / APPLY_SCRIPT[stem]).read_text(encoding="utf-8")
    resolved: dict[str, str] = {}
    for name, raw in re.findall(r'^\s*"([a-z0-9-]+):\s*(.*?)",?\s*$', text, re.MULTILINE):
        value = raw.strip()
        if value.startswith("'") and value.endswith("'"):
            value = value[1:-1]
        if value.startswith("$("):
            resolved[name] = "<runtime>"
            continue
        reference = re.fullmatch(r"\$(\w+)", value)
        if reference:
            default = re.search(
                rf'\[(?:string|int)\]\${reference.group(1)}\s*=\s*(?:"([^"]*)"|(\d+))',
                text,
            )
            resolved[name] = "<runtime>" if not default else (default.group(1) or default.group(2))
            continue
        resolved[name] = value
    return resolved


def _vault_vars(stem: str) -> set[str]:
    """Names this pipeline's apply script probes Vault for before falling back.

    Two shapes, because the three scripts grew apart: `set-pipeline.ps1` keeps a
    `$fallbacks` table of `"name" = { ... }`, the other two call `Add-Secret
    -Name "name"`. Both mean the same thing -- present in Vault, left out of the
    vars file, resolved at build time -- so both are read here rather than one
    being the canonical form.
    """
    text = (CONCOURSE_DIR / APPLY_SCRIPT[stem]).read_text(encoding="utf-8")
    named = set(re.findall(r'^Add-Secret\s+-Name\s+"([a-z0-9-]+)"', text, re.MULTILINE))
    named |= set(re.findall(r'^\s*"([a-z0-9-]+)"\s*=\s*\{', text, re.MULTILINE))
    return named | set(TEAM_VAULT_VARS) | set(EXTRA_VAULT_VARS.get(stem, ()))


@pytest.mark.parametrize("path", checker.pipelines(), ids=lambda p: p.name)
def test_every_pipeline_applies_itself(path: Path) -> None:
    """#355: seven merged commits, none of them running.

    keel has had this for twenty-one builds and has not drifted; these three had
    no `set_pipeline:` step between them, so every pipeline fix waited on
    somebody remembering a PowerShell script. One of the seven was a live
    information disclosure, fixed in `main` for two days and still serving.
    """
    stem = path.stem
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    job = _set_pipeline_job(document)

    fetch = [step for step in job["plan"] if step.get("get") == "pipelines"]
    assert fetch, f"{path.name}:set-pipeline does not fetch the pipeline repository"
    assert fetch[0].get("trigger") is True, (
        f"{path.name}:set-pipeline fetches without `trigger: true`, which leaves a job "
        f"somebody still has to remember"
    )

    applies = [step for step in job["plan"] if "set_pipeline" in step]
    assert applies, f"{path.name}:set-pipeline has no set_pipeline step"
    assert applies[0]["set_pipeline"] == "self"
    assert applies[0]["file"] == f"pipelines/deploy/concourse/pipelines/{stem}.yml"
    assert applies[0]["var_files"] == [f"pipelines/deploy/concourse/vars/{stem}.yml"]

    # The difference from keel, and the thing easiest to get wrong: keel's
    # pipeline lives in keel's own repo, so its `repo` resource is already the
    # right one. These three live in mykronos while `source` points at the
    # application they scan.
    resources = {resource["name"]: resource for resource in document["resources"]}
    assert "pipelines" in resources, f"{path.name} has no resource for the mykronos repo"
    assert resources["pipelines"]["source"]["uri"] == "https://github.com/ToddGBenson/mykronos.git"
    assert resources["pipelines"]["source"]["branch"] == "main"


@pytest.mark.parametrize("stem", sorted(APPLY_SCRIPT), ids=str)
def test_the_self_apply_can_supply_every_var(stem: str) -> None:
    """The lockout, asserted rather than commented.

    A `((var))` the committed vars file does not carry and Vault does not hold
    resolves to nothing after a self-apply. For most that costs one job; for
    `thehub.yml`'s `((thehub-branch))` it costs `source`, every job behind it,
    and this job with them -- which is exactly how keel's self-applying pipeline
    locked itself out once already.

    A new var added to a pipeline with nowhere to come from fails here, in the
    `unit` lane, rather than on the worker after the apply.
    """
    document = yaml.safe_load((checker.PIPELINE_DIR / f"{stem}.yml").read_text(encoding="utf-8"))
    committed = yaml.safe_load((VARS_DIR / f"{stem}.yml").read_text(encoding="utf-8"))

    homeless = _vars_used(document) - set(committed) - _vault_vars(stem)

    assert homeless == UNRESOLVED_AFTER_SELF_APPLY[stem], (
        f"{stem}.yml: vars with no home after a self-apply are {sorted(homeless)}, but "
        f"UNRESOLVED_AFTER_SELF_APPLY records {sorted(UNRESOLVED_AFTER_SELF_APPLY[stem])}. "
        f"Add it to deploy/concourse/vars/{stem}.yml, put it in Vault, or record the "
        f"cost in the pipeline's set-pipeline comment and here."
    )


@pytest.mark.parametrize("stem", sorted(APPLY_SCRIPT), ids=str)
def test_the_committed_vars_say_what_the_apply_script_applies(stem: str) -> None:
    """Two copies of one configuration, held together by this.

    `deploy/concourse/vars/<stem>.yml` exists so the `set-pipeline` job can
    re-supply what `fly set-pipeline --load-vars-from` interpolates client side.
    That makes it a second copy of values the apply script also holds, and a
    second copy nothing compares is a self-applying pipeline quietly reverting
    an operator: `mykronos-ref` bumped in the script alone would be downgraded
    again on the next commit to any pipeline file.
    """
    committed = yaml.safe_load((VARS_DIR / f"{stem}.yml").read_text(encoding="utf-8"))
    scripted = _script_vars(stem)

    assert scripted, f"no vars parsed out of {APPLY_SCRIPT[stem]} -- has its shape changed?"

    disagree = {
        name: (str(value), str(committed[name]))
        for name, value in scripted.items()
        if name in committed and str(committed[name]) != str(value)
    }
    assert not disagree, (
        f"{APPLY_SCRIPT[stem]} and vars/{stem}.yml disagree; the next self-apply would "
        f"impose the second (script, committed): {disagree}"
    )

    # And the other direction: a value the script computes at run time cannot be
    # committed, so committing one would mean committing a guess.
    guessed = sorted(
        name for name, value in scripted.items() if value == "<runtime>" and name in committed
    )
    assert not guessed, (
        f"vars/{stem}.yml commits values {APPLY_SCRIPT[stem]} computes at run time: {guessed}"
    )

    missing = sorted(
        name
        for name, value in scripted.items()
        if value != "<runtime>" and name not in committed and name not in _vault_vars(stem)
    )
    assert not missing, (
        f"{APPLY_SCRIPT[stem]} writes {missing}, which vars/{stem}.yml does not carry, so a "
        f"self-apply would drop them"
    )
