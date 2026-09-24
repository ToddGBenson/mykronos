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


#: A line that RUNS apt-get, as opposed to one that merely mentions it in a
#: comment. `dast-demo` and `dast-prod` are the reason this is not a substring
#: test: both explain that a venv "would mean apt-get, which needs the root
#: this task does not have", and neither calls it.
_APT_COMMAND = re.compile(r"(?:^|[;&|(]\s*|\bthen\s+|\bdo\s+|\belse\s+)apt-get\s+\S")


def _runs_apt(line: str) -> bool:
    stripped = line.strip()
    return not stripped.startswith("#") and bool(_APT_COMMAND.search(stripped))


def test_every_apt_task_forces_ipv4_first() -> None:
    """#59976, and the thing that stops fifty-seven copies of one line drifting.

    apt reaches Debian over IPv6 only from this host: every attempt goes to
    `2a04:4e42::/...` and returns "network is unreachable", with no IPv4
    attempt made at all. It is intermittent -- it killed a `prompt-evals` build
    fifteen minutes after an identical one succeeded -- which is the shape that
    gets written off as flaky infrastructure instead of fixed.

    The fix is one line per task, because a YAML anchor aliases a node and
    cannot splice a string into the middle of a block scalar (the reasoning is
    written out at the top of each pipeline's `anchors:`). One line per task is
    exactly the kind of convention that holds for a month and then does not, so
    it is asserted here rather than remembered: a new lane that installs a
    package and forgets the drop-in fails in the `unit` lane, not on the worker
    at 2am.

    Asserted per SCRIPT rather than per job. A job whose scan task forces IPv4
    and whose upload task does not is still a lane that dies on a network
    error, and concatenating a job's scripts would hide that.
    """
    missing: list[str] = []
    inspected: dict[str, int] = {}

    for path in checker.pipelines():
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        inspected[path.name] = 0
        for job in document["jobs"]:
            scripts: list[str] = []

            def collect(node: dict, into: list[str] = scripts) -> None:
                run = node.get("run")
                if isinstance(run, dict):
                    into.extend(
                        arg
                        for arg in (run.get("args") or [])
                        if isinstance(arg, str) and "\n" in arg
                    )

            checker._walk(job, collect)

            for script in scripts:
                lines = script.split("\n")
                apt = [i for i, line in enumerate(lines) if _runs_apt(line)]
                if not apt:
                    continue
                inspected[path.name] += 1
                drop_in = [
                    i
                    for i, line in enumerate(lines)
                    if "99force-ipv4" in line and not line.strip().startswith("#")
                ]
                if not drop_in:
                    missing.append(f"{path.name}:{job['name']} runs apt with no IPv4 drop-in")
                elif drop_in[0] > apt[0]:
                    missing.append(
                        f"{path.name}:{job['name']} writes the IPv4 drop-in after its first "
                        f"apt-get, which is after the connection it was meant to fix"
                    )

    # A check that found nothing to check is indistinguishable from a check
    # that passed, and this one walks four layers to find its subjects --
    # `pipelines()`, `jobs`, `_walk`, and an inline `run.args` block scalar.
    # Any of them narrowing (a task moving to `run.path`, a pipeline dropping
    # out of the glob) empties `missing` and turns this green while asserting
    # nothing. So the discovery is asserted alongside the property: 144 scripts
    # run apt today, 22/13/109 across the three pipelines.
    assert all(inspected.values()), (
        "This test inspected no apt-running script in "
        + ", ".join(name for name, count in inspected.items() if not count)
        + " -- discovery broke, so a green result here means nothing. "
        f"Found: {inspected}"
    )
    assert sum(inspected.values()) >= 100, (
        f"Only {sum(inspected.values())} apt-running scripts were found, against "
        "144 when this was written. A drop that large is discovery breaking, not "
        f"lanes being removed. Found: {inspected}"
    )

    assert not missing, "\n".join(
        [
            "apt reaches Debian over IPv6 only here (#59976); these tasks would "
            "fail intermittently with 'network is unreachable':",
            *missing,
        ]
    )


def test_the_ipv4_check_can_tell_a_comment_from_a_command() -> None:
    """The check above is only worth its cost if it cannot be fooled either way.

    A false negative loses the lane it was meant to protect. A false POSITIVE
    is worse here than it sounds: it would demand a write to
    /etc/apt/apt.conf.d in `dast-demo` and `dast-prod`, which run on the `zap`
    image as an unprivileged user -- taking two working DAST lanes down under
    `set -e` to fix a problem they do not have.
    """
    assert _runs_apt("                apt-get update -qq && apt-get install -y git")
    assert _runs_apt("  apt-get install -y -qq curl")
    assert _runs_apt("else apt-get update; fi")
    assert _runs_apt("if [ -z x ]; then apt-get update; fi")

    assert not _runs_apt("  # would mean apt-get, which needs the root this task does not")
    assert not _runs_apt("                # died in this task, on `apt-get update`, having done")
    assert not _runs_apt('  echo "this lane needs no apt-get at all"')


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
            if (path.stem, job["name"]) not in CAPABILITY_BY_JOB:
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
    # [#60004] `breach-check` was retired, and these two vars went with it --
    # they were only ever used by that job. Emptied rather than left behind:
    # this set records vars a self-apply CANNOT resolve, so a name that no
    # pipeline references any more is a claim about nothing.
    "personal-soc": frozenset(),
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

    # AND THE REVERSE, which this test did not check until #60014 and which is
    # the direction the `weekly` timer's own comment had described the cost of:
    # "using a variable nobody supplies here would apply an unresolved
    # reference and the resource would never fire."
    #
    # The two appliers are not interchangeable. The committed vars file feeds
    # the `set-pipeline` JOB; the script feeds a manual apply from a laptop. A
    # var in the file and not in the script resolves on a self-apply and is
    # left as the literal string `((name))` by the script -- so the pipeline
    # works until somebody applies it the other way, and then a resource
    # silently stops matching anything. Concourse does not reject it: an
    # unresolved var in a resource `source` is just a wrong value.
    #
    # Found by mutation: deleting `scan-timezone` from the script alone left
    # all 47 tests in this pair green.
    unsupplied = sorted(set(committed) - set(scripted))
    assert not unsupplied, (
        f"vars/{stem}.yml carries {unsupplied}, which {APPLY_SCRIPT[stem]} does not write, "
        f"so a manual apply would leave them as unresolved `((name))` literals"
    )


# --- Every timer says which clock it reads -----------------------------------
#
# `mykronos/weekly` was the only `time` resource in the estate with no
# `location`, and Concourse defaults to UTC. Phoenix is UTC-7 year round, so a
# window written as "Sunday 04:00-05:00" ran at 21:00-22:00 SATURDAY -- neither
# what the file says nor when the estate is quiet (#60014).
#
# The cost of getting this wrong is invisible rather than red. A timer in the
# wrong zone still fires, still succeeds, and still reports nothing unusual; it
# simply does so at an hour nobody chose. `mykronos/coverage` is the consumer
# that made it visible, and only because it had never built at all.
#
# A skipped assertion is not a passed one, so this asserts a floor first: fewer
# timers than this repository holds means the discovery broke, not that the
# estate got simpler.
#
# Three, not five: keel's `daily` and `weekly` are real timers in the same
# estate, but keel's pipeline lives in keel's own repository and nothing here
# can read it. Counting them would make this test unfalsifiable in exactly the
# way `ACKNOWLEDGED_UNMAPPED_JOBS` refuses to be.
MINIMUM_TIMERS = 3


def _time_resources() -> list[tuple[str, str, dict]]:
    """`(pipeline, resource, source)` for every `type: time` resource."""
    found = []
    for path in sorted(checker.PIPELINE_DIR.glob("*.yml")):
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        for resource in document.get("resources") or []:
            if resource.get("type") == "time":
                found.append((path.stem, resource["name"], resource.get("source") or {}))
    return found


def test_every_timer_names_the_timezone_it_reads_its_window_in() -> None:
    timers = _time_resources()
    assert len(timers) >= MINIMUM_TIMERS, (
        f"only {len(timers)} time resources found across the estate; expected at "
        f"least {MINIMUM_TIMERS}. A discovery that finds no timers would pass "
        "this test by inspecting nothing."
    )
    missing = sorted(
        f"{pipeline}/{name}" for pipeline, name, source in timers if not source.get("location")
    )
    assert not missing, (
        f"these timers set no `location`, so Concourse reads their window in UTC: "
        f"{missing}. That is seven hours off Phoenix and turns a pre-dawn Sunday "
        "slot into Saturday evening. Set `location: ((scan-timezone))` and make "
        "sure BOTH the apply script and vars/<pipeline>.yml supply it."
    )


# --- One scanner, one version ------------------------------------------------

DEMO_COMPOSE = REPO_ROOT / "deploy" / "demo" / "docker-compose.yml"
ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy"
EXACT_VERSION = re.compile(r"^\d+\.\d+\.\d+$")


def _zap_pins() -> dict[str, str]:
    """Every committed statement of which ZAP the estate scans with.

    Two shapes today, and the walker still looks for three. ZAP is installed as
    a Concourse `registry-image` resource (TheHub's baseline lanes) and as a
    compose `image:` (the demo stack the mykronos DAST lane proxies through).

    The third shape was a `ZAP_VERSION` task param, which unpacked the GitHub
    release tarball into a task cache. Its only user was TheHub's
    `functional-dast`, removed with Path B in #59100 because it drove the demo
    environment. The `ZAP_VERSION` branch below is deliberately kept rather
    than deleted with it: the tarball install is the shape a lane reaches for
    when it needs ZAP inside another image, so the next one to do it is
    collected automatically instead of being a pin nobody is comparing.

    Keyed by where it was read, so a failure names the line to edit rather than
    the fact of a disagreement.
    """
    pins: dict[str, str] = {}

    def walk(node: object, where: str) -> None:
        if isinstance(node, dict):
            source = node.get("source")
            if (
                node.get("name") == "zap"
                and isinstance(source, dict)
                and source.get("repository") == ZAP_IMAGE
            ):
                pins[f"{where}:zap resource tag"] = str(source.get("tag"))
            for key, value in node.items():
                if key == "ZAP_VERSION":
                    pins[f"{where}:ZAP_VERSION"] = str(value)
                else:
                    walk(value, where)
        elif isinstance(node, list):
            for item in node:
                walk(item, where)

    for path in checker.pipelines():
        walk(yaml.safe_load(path.read_text(encoding="utf-8")), path.name)

    compose = yaml.safe_load(DEMO_COMPOSE.read_text(encoding="utf-8"))
    for name, service in (compose.get("services") or {}).items():
        image = str(service.get("image", ""))
        if image.startswith(f"{ZAP_IMAGE}:"):
            pins[f"deploy/demo/docker-compose.yml:{name}"] = image.split(":", 1)[1]

    return pins


def test_the_estate_scans_with_one_zap() -> None:
    """TheHub ran 2.16.1 while mykronos ran 2.17.0, and nothing said so (#272).

    Passive scan rules are added and fixed per release, so two pins at two
    versions mean a rule that exists in one and not the other is a class of
    finding half the estate cannot produce — and a scanner that looked with
    fewer rules reports the same green as one that looked with all of them.

    The gap survived a release and surfaced only because ZAP filed
    `ZAP-10116` "ZAP is Out of Date" about *itself*, into a product backlog,
    where it read as a low defect in TheHub rather than as an estate-wide
    coverage hole. A bump is three edits across two files, so this is what
    notices when only some of them move.
    """
    pins = _zap_pins()

    # Two, not three, since #59100: the `ZAP_VERSION` tarball pin went with
    # `functional-dast`, whose target was the retired demo environment. Lowered
    # deliberately and with the count still asserted, because the failure this
    # guards against is the check quietly finding nothing and passing -- which
    # is what a missing pin looks like from here. `_zap_pins` still collects
    # `ZAP_VERSION` wherever one reappears, so this floor rises again on its
    # own the moment a lane installs ZAP from the tarball.
    assert len(pins) >= 2, (
        f"expected the zap resource and the demo compose image; found {pins}. "
        "If a pin moved, move this test with it rather than letting it stop looking."
    )

    versions = sorted(set(pins.values()))
    assert len(versions) == 1, (
        f"the estate pins ZAP at {versions}, so one half scans with rules the other lacks: {pins}"
    )


def test_every_zap_pin_is_an_exact_version() -> None:
    """`stable` and the weekly tags float, which D-114 ruled out.

    A scanner that changes underneath a lane cannot be compared against its own
    previous run, and a finding that appears is then indistinguishable from a
    rule that arrived.
    """
    floating = {
        where: value for where, value in _zap_pins().items() if not EXACT_VERSION.match(value)
    }
    assert not floating, f"these ZAP pins float rather than naming a release: {floating}"


def _zap_baseline_script() -> str:
    """The one task both of `dast-staging`'s curls live in."""
    document = yaml.safe_load(
        (checker.PIPELINE_DIR / "thehub.yml").read_text(encoding="utf-8")
    )
    jobs = {job["name"]: job for job in document["jobs"]}
    tasks = [
        step
        for step in _steps({"jobs": [jobs["dast-staging"]]})
        if step.get("task") == "zap-baseline"
    ]
    assert tasks, "dast-staging no longer has a zap-baseline task"
    return tasks[0]["config"]["run"]["args"][-1]


def test_the_probe_names_the_tool_before_it_blames_the_target() -> None:
    """#59975, and the reason that story took three days instead of one.

    `if ! curl ...` cannot distinguish "there is no curl in this image" (127)
    from "the target did not answer" (7): both make the `if` true and the
    message that prints names the target. `dast-staging` failed for two days
    with a message about an unreachable staging host while the build log said
    `curl: (23) Failure writing output to destination` — the fetch had already
    succeeded and the destination was unwritable. Three separate investigations
    went looking for a network fault that was never there.

    So the binary is established once, up front, before any curl runs. Every
    curl failure after that line is a statement about the target or the
    filesystem, and the messages are entitled to say so.

    This asserts the ordering, not merely the presence: a `command -v curl`
    placed *after* the reachability check would read as satisfying the rule
    while leaving the ambiguity exactly where it was.
    """
    script = _zap_baseline_script()

    guard = script.find("command -v curl")
    assert guard != -1, (
        "the zap-baseline task no longer establishes that curl exists before using it; "
        "a missing binary will be reported as an unreachable target again (#59975)"
    )

    first_curl = re.search(r"^\s*(if ! )?curl\s", script, re.MULTILINE)
    assert first_curl, "the zap-baseline task no longer invokes curl at all"
    assert guard < first_curl.start(), (
        "the curl guard runs after the first curl, so the first failure still cannot "
        "say whether the tool or the target is missing (#59975)"
    )


def test_the_two_probe_verdicts_do_not_share_one_message() -> None:
    """The story's first acceptance criterion, stated as a property.

    A missing binary and an unreachable target need different things done --
    fix the image, or bring staging up -- so one sentence covering both is the
    defect this guard exists to prevent, committed inside the guard. #392
    already made that mistake once here: "Could not fetch" was printed for
    "could not resolve", "connection refused", "HTTP 404" and "could not write
    the file" alike, and it named the wrong cause in production on its first
    real run.

    The two messages must therefore be distinguishable by reading them, which
    is the only place it matters -- a human at 02:00 looking at a red lane.
    """
    script = _zap_baseline_script()

    tool_lines = [
        line for line in script.splitlines() if "MISSING TOOL" in line or "not installed" in line
    ]
    target_lines = [
        line
        for line in script.splitlines()
        if "is not answering" in line or "TARGET is unreachable" in line
    ]

    assert tool_lines, "no message says plainly that curl itself is missing (#59975)"
    assert target_lines, "no message says plainly that the target is unreachable (#59975)"

    # And no single line may offer the two as alternatives. This is the shape
    # the regression actually takes -- nobody deletes the messages, they merge
    # them into one hedged sentence that saves a branch and costs the reader
    # the answer. "curl is missing or the target is not answering" tells an
    # operator at 02:00 precisely nothing.
    #
    # Contrastive negation is the opposite of the defect and is allowed: "a
    # MISSING TOOL, not an unreachable target" names one cause and rules the
    # other out, which is the whole point. The test therefore looks for the
    # two causes joined as a disjunction, not for their co-occurrence.
    hedged = [
        line
        for line in script.splitlines()
        if "::error::" in line
        and re.search(r"\bor\b", line)
        and re.search(r"not installed|missing tool|no curl", line, re.IGNORECASE)
        and re.search(r"not answering|unreachable|could not reach", line, re.IGNORECASE)
    ]
    assert not hedged, (
        "one message offers a missing binary and an unreachable target as alternatives, "
        "which is the hedge the story's first acceptance criterion rules out: "
        + "; ".join(line.strip() for line in hedged)
    )


def test_the_probe_translates_curl_127_rather_than_printing_the_number() -> None:
    """Belt and braces for the guard above.

    The `command -v curl` check makes 127 unreachable at the probe. It is
    still translated, because the guard is one refactor away from moving and
    `curl exited 127` is exactly the opaque message that sent this story
    looking at the network for two days.
    """
    script = _zap_baseline_script()
    case_block = re.search(r'case "\$rc" in(.*?)esac', script, re.DOTALL)
    assert case_block, "the probe no longer translates curl's exit code (#392)"
    body = case_block.group(1)

    for code in ("22", "23", "127"):
        assert re.search(rf"^\s*(?:\d+\|)*{code}(?:\|\d+)*\)", body, re.MULTILINE), (
            f"curl exit {code} is no longer given a message of its own; it falls to the "
            f"catch-all, which prints a number rather than a cause (#59975)"
        )


def _oracle_evaluate_payloads() -> dict[str, list[str]]:
    """Every `/api/oracle/evaluate` body a pipeline builds, by pipeline name.

    Read out of the raw text rather than the parsed YAML: the body is a jq
    program inside a bash script inside a task's `run.args`, so the structure
    that matters here is textual. A pipeline builds several jq bodies around a
    commit sha — SBOM provenance is one — so a body counts as a decision only
    if it names a `decision_type`.
    """
    payloads: dict[str, list[str]] = {}
    for path in checker.pipelines():
        text = path.read_text(encoding="utf-8")
        if "oracle/evaluate" not in text:
            continue
        bodies = re.findall(r"\{[^{}]*decision_type[^{}]*\}", text)
        assert bodies, f"{path.name} calls /api/oracle/evaluate with no readable body"
        payloads[path.name] = bodies
    return payloads


def test_no_pipeline_files_a_per_commit_verdict_as_a_standing_one() -> None:
    """A gate job judges one commit; `portfolio` is the repository's standing
    posture (#275).

    Every `oracle-gate` job sent `decision_type: "portfolio"` with a commit
    sha, which is a contradiction the endpoint used to accept. 1,601 per-commit
    verdicts accumulated inside the standing posture before anyone noticed, and
    "what did the gate decide for this commit?" had no answer at all for the
    repositories gated from Concourse.

    The server corrects the pairing now, so this is not what keeps the lake
    honest — it is what keeps the pipelines from relying on being corrected.
    """
    payloads = _oracle_evaluate_payloads()
    assert payloads, "no pipeline builds an /api/oracle/evaluate body any more"

    wrong = {
        name: body
        for name, bodies in payloads.items()
        for body in bodies
        if "commit_sha" in body and '"portfolio"' in body
    }
    assert not wrong, (
        "a commit-triggered gate job files its verdict as the standing "
        "repository posture: " + "; ".join(f"{k}: {v}" for k, v in wrong.items())
    )


def test_every_gate_payload_names_a_scope_the_api_accepts() -> None:
    """Guard on the guard above: a typo'd scope would satisfy it silently."""
    accepted = {"pr_gate", "commit_gate", "release_gate", "portfolio"}
    for name, bodies in _oracle_evaluate_payloads().items():
        for body in bodies:
            found = re.search(r'decision_type:\s*"([a-z_]+)"', body)
            assert found, f"{name}: a gate payload names no decision_type: {body}"
            assert found.group(1) in accepted, (
                f"{name}: decision_type {found.group(1)!r} is not one "
                f"`/api/oracle/evaluate` accepts"
            )


def test_no_git_over_ssh_can_ask_a_question() -> None:
    """[#496] A prompt is not a failure, and `|| true` cannot catch one.

    `thehub/insider` ran `git fetch origin "$BASE" || true` in a task whose
    remote is SSH (the `source` resource uses a deploy key deliberately) and
    whose container has no known_hosts. ssh asked

        Are you sure you want to continue connecting (yes/no/[fingerprint])?

    on a terminal nobody was attached to, and the build hung to its timeout.
    The guard against a non-zero exit was intact the whole time; it just does
    not apply to a question.

    Any `git fetch`/`git clone`/`git ls-remote` in a pipeline task must run
    under BatchMode so the question becomes an exit code.
    """
    offenders: list[str] = []
    for path in sorted((CONCOURSE_DIR / "pipelines").glob("*.yml")):
        for number, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if not re.search(r"\bgit\s+(fetch|clone|ls-remote)\b", stripped):
                continue
            # The Concourse git resource does its own host-key handling; this
            # is about git invoked inside a task script.
            if "BatchMode" in line or "GIT_SSH_COMMAND" in line:
                continue
            offenders.append(f"{path.name}:{number}: {stripped[:70]}")

    assert not offenders, (
        "These git invocations can block on an SSH host-key prompt, which "
        "hangs the task to its timeout rather than failing it:\n  "
        + "\n  ".join(offenders)
    )
