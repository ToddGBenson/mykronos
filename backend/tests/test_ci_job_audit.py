"""Every pipeline job is audited: mapped to a capability, or written down as
producing none (B-59330).

WHAT WENT WRONG. `reconcile()` was an allowlist with a silent default. A job
absent from `CAPABILITY_BY_JOB` was `continue`d, and nothing anywhere recorded
that a job had been passed over — so a lane was unmonitored from the moment it
was added until somebody remembered the table existed, and the gap was
invisible for as long as it lasted. Five keel jobs errored against a sealed
Vault on 2026-09-07 and stayed red for three days with nothing escalating. The
detector was not broken: `_DID_NOT_SUCCEED` covers `errored` exactly, and it
would have fired. It was pointed at 29 jobs and keel's were not among them.

Adding keel to the map fixes that occurrence. `reconcile()` reporting anything
unmapped as `unknown` fixes the class. This file is what stops the exclusion
list from quietly becoming the old silent default again.

TWO PROPERTIES, NOT A PROMISE IN A COMMENT.

  1. Every job in every pipeline is mapped or acknowledged. Add a job and this
     goes red, naming it, before the lane has a chance to go unwatched.
  2. No acknowledged job invokes `python -m mykronos.upload`. That is what
     makes an acknowledgement falsifiable rather than a claim nobody rechecks.

The second is the one that matters over time, and there is precedent: `unit`
sat on the old hard-coded skip list until D-046 gave it a ScanRun, and nothing
noticed it had started reporting. An acknowledgement that silently stops being
true is exactly how the allowlist failed in the first place.

SCOPE. Concourse pipelines in this repository, which is every pipeline
Mykronos itself writes. The Actions side is deliberately not asserted here:
`ActionsClient._job_name_for` drops a workflow it does not recognise one layer
earlier, because a repository's own `delivery.yml` belongs to somebody else and
claiming it produces a capability would invent coverage. That drop is a
separate decision from this one and is argued where it happens.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from mykronos.ci import (
    ACKNOWLEDGED_UNMAPPED_JOBS,
    CAPABILITY_BY_JOB,
    COLLIDING_KEEL_STUBS,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
PIPELINE_DIR = REPO_ROOT / "deploy" / "concourse" / "pipelines"

#: How a lane puts findings in the lake. One invocation, one spelling, in every
#: pipeline — which is what makes "does this job report?" answerable by reading
#: rather than by running it.
UPLOADER = "python -m mykronos.upload"


def _pipelines() -> list[Path]:
    """Found, not listed.

    A hand-maintained list means a new pipeline is exempt until somebody
    remembers to add it — the same shape as the bug this file is about, and the
    same one `test_pipeline_conformance` records `personal-soc.yml` falling
    through for long enough that all twelve of its tasks ran uncapped.
    """
    return sorted(PIPELINE_DIR.glob("*.yml"))


def _jobs(path: Path) -> list[dict]:
    parsed = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return [job for job in (parsed.get("jobs") or []) if isinstance(job, dict)]


if not PIPELINE_DIR.is_dir():  # pragma: no cover - the tree always has these
    pytest.skip("deploy/concourse/pipelines not reachable", allow_module_level=True)


def test_the_pipelines_are_readable() -> None:
    """A guard that silently measures nothing is worse than none.

    Every assertion below iterates jobs parsed out of the YAML. If the parse
    yields nothing — a moved directory, a schema change — each of them passes
    over an empty set and this file goes green having checked no job at all.
    That is the failure mode of the thing it is guarding against, turned on
    itself.
    """
    found = _pipelines()

    assert found, f"no pipelines parsed out of {PIPELINE_DIR}"
    for path in found:
        assert _jobs(path), f"{path.name} parsed to no jobs at all"


@pytest.mark.parametrize("path", _pipelines(), ids=lambda p: p.name)
def test_every_job_is_mapped_or_acknowledged(path: Path) -> None:
    """THE PROPERTY. A job is watched, or it is on the record as producing
    nothing. There is no third state, and there used to be: unmapped and
    unmentioned, which read to the platform as "fine".

    The failure message names the jobs, because the fix is one line either way
    and the hard part is knowing which line.
    """
    unaudited = sorted(
        job["name"]
        for job in _jobs(path)
        if job.get("name")
        and job["name"] not in CAPABILITY_BY_JOB
        and job["name"] not in ACKNOWLEDGED_UNMAPPED_JOBS
    )

    assert not unaudited, (
        f"{path.name} runs these jobs and nothing says what they produce, so "
        f"the coverage cross-check cannot answer for them: {unaudited}\n"
        "  Map it in CAPABILITY_BY_JOB if it uploads findings, or add it to "
        "ACKNOWLEDGED_UNMAPPED_JOBS with the reason it does not."
    )


def _uploading_jobs() -> dict[str, set[str]]:
    """job name -> the pipelines in which it invokes the uploader."""
    out: dict[str, set[str]] = {}
    for path in _pipelines():
        for job in _jobs(path):
            name = job.get("name")
            if name and UPLOADER in yaml.safe_dump(job):
                out.setdefault(name, set()).add(path.name)
    return out


def test_no_acknowledged_job_uploads_findings() -> None:
    """WHAT MAKES AN ACKNOWLEDGEMENT FALSIFIABLE.

    Without this, `ACKNOWLEDGED_UNMAPPED_JOBS` is a list of sentences nobody
    rechecks, and a job that starts reporting keeps its exemption — which is
    precisely what `unit` did. It was skipped as a job that "writes nothing"
    until D-046 gave it a ScanRun, and because a quality lane carries no
    findings there was no count to be conspicuously zero. The cross-check was
    the only thing that could have noticed, and it was excused from looking.

    Red here means the acknowledgement has expired, and the fix is to move the
    job into `CAPABILITY_BY_JOB` under whatever `--capability` it now sends.
    """
    uploading = _uploading_jobs()
    expired = sorted(
        f"{name} (in {', '.join(sorted(uploading[name]))})"
        for name in uploading
        if name in ACKNOWLEDGED_UNMAPPED_JOBS
    )

    assert not expired, (
        "these jobs are acknowledged as producing nothing and they call "
        f"`{UPLOADER}`, so their findings are in the lake and the cross-check "
        f"is excused from checking they arrive: {expired}\n"
        "  Move each into CAPABILITY_BY_JOB under the capability it uploads."
    )


def test_the_uploader_check_can_actually_find_an_uploader() -> None:
    """The other half of "measures nothing". `UPLOADER` is a literal matched
    against dumped YAML; a change to how lanes invoke the uploader would make
    the test above find zero uploading jobs and pass for ever.
    """
    uploading = _uploading_jobs()

    assert uploading, (
        f"no job in any pipeline invokes `{UPLOADER}`, so the acknowledgement "
        "check above is vacuous — either the lanes upload some other way now, "
        "or this literal is stale"
    )
    # And it must find the obvious one, rather than some incidental mention.
    assert "secrets" in uploading


def test_every_acknowledgement_names_a_job_that_exists() -> None:
    """A line that outlives the job it describes starts excusing a future one.

    The same reasoning as `test_every_recorded_gap_still_reproduces` in
    `test_pipeline_conformance`: a baseline entry with nothing behind it is an
    exemption waiting to be inherited by a name somebody reuses.
    """
    live = {job["name"] for path in _pipelines() for job in _jobs(path) if job.get("name")}
    stale = sorted(set(ACKNOWLEDGED_UNMAPPED_JOBS) - live)

    assert not stale, (
        "no pipeline runs these any more, so delete them from "
        f"ACKNOWLEDGED_UNMAPPED_JOBS: {stale}"
    )


def test_every_acknowledgement_says_why() -> None:
    """A reason, not a label. `"build": "build"` is an exemption by absence
    wearing a dictionary, and the next person re-deciding one cannot tell a
    judgement from a sweep.
    """
    for job, reason in ACKNOWLEDGED_UNMAPPED_JOBS.items():
        assert len(reason.split()) >= 6, f"{job} needs a reason, not a label: {reason!r}"


def test_nothing_is_both_mapped_and_acknowledged() -> None:
    """The two tables answer the same question and must not disagree. If a
    name were in both, which one wins would be decided by the order of two
    `if`s in `reconcile()` rather than by anybody's intent.
    """
    both = sorted(set(CAPABILITY_BY_JOB) & set(ACKNOWLEDGED_UNMAPPED_JOBS))

    assert not both, f"mapped to a capability AND acknowledged as producing none: {both}"


def test_the_jobs_this_repository_runs_are_actually_covered() -> None:
    """Coverage by default, asserted rather than assumed — the property the
    old shape did not have. Named pipelines, so that a rename or a move makes
    this file say so instead of quietly checking less.
    """
    found = {path.name for path in _pipelines()}

    assert {"mykronos.yml", "personal-soc.yml", "thehub.yml"} <= found


#: keel's three uploading lanes, and the capability each task DECLARES in its
#: `CAPABILITY:` param. Read off the running server with
#: `fly get-pipeline -p keel` on 2026-09-17, because keel's pipeline lives in
#: keel's own repo and nothing in this repository can see it.
KEEL_UPLOADING_LANES = {
    "mykronos-sast": "sast",
    "mykronos-secrets": "secrets",
    "mykronos-atlas": "atlas",
}


def test_keels_uploading_lanes_are_mapped() -> None:
    """THE OCCURRENCE THIS STORY STARTED FROM.

    Five keel jobs errored against a sealed Vault on 2026-09-07 and sat red
    for three days because none of keel's jobs was in `CAPABILITY_BY_JOB`.
    Reporting unmapped jobs as `unknown` fixes the class; this is the
    occurrence, and it needs the names, which needed a fly token.

    Asserted by the DECLARED capability rather than one inferred from the job
    name. `mykronos-atlas` runs `osv-scan` with `TOOL: osv-scanner` and
    uploads `atlas`; a reader going by names alone would not get there.
    """
    for job, capability in KEEL_UPLOADING_LANES.items():
        assert CAPABILITY_BY_JOB.get(job) == capability, (
            f"keel's {job} uploads {capability!r} and this table says "
            f"{CAPABILITY_BY_JOB.get(job)!r}"
        )


def test_keels_stubs_are_not_acknowledged_as_producing_nothing() -> None:
    """A STUB IS A DARK LANE, NOT AN EXEMPT ONE.

    23 of keel's 26 jobs invoke no scanner: 158-437 bytes each, among them
    `sca`, `container-scan`, `ai-guardrails`, `suppression-audit` and three
    `compliance-*` lanes. Three of them (`secrets`, `iac`, `container-scan`)
    even name gitleaks, checkov and trivy in their text without running them.

    Acknowledging those would write down that keel's container scanning
    correctly produces no findings. It does not produce findings because it
    does not exist, which is the opposite claim and the exact false green this
    module is for. They report `unknown` instead, which is true and is
    something a person can act on.

    Pinned as a test because it is the kind of decision a later reader
    reverses to quieten a page.
    """
    wrongly_acknowledged = sorted(
        job
        for job in ("sca", "container-scan", "suppression-audit", "platform-integrity",
                    "ai-guardrails", "ai-evals", "agent-assurance", "compliance-daily",
                    "compliance-weekly", "compliance-monthly", "full-suite",
                    "verify-artifact", "build-and-attest", "release-preflight",
                    "authorize-release", "metrics-snapshot", "test")
        if job in ACKNOWLEDGED_UNMAPPED_JOBS
    )

    assert not wrongly_acknowledged, (
        "these are keel stub jobs that run no scanner, and acknowledging them "
        "records that a named security control correctly produces nothing: "
        f"{wrongly_acknowledged}. They should report `unknown`."
    )


def test_the_job_name_collision_across_pipelines_is_still_recorded() -> None:
    """A KNOWN DEFECT, PINNED SO IT IS NOT FOUND A SECOND TIME.

    `CAPABILITY_BY_JOB` is keyed on the job name alone, so a name means the
    same thing in every pipeline. keel has stub jobs called `sast`, `secrets`,
    `iac` and `lint` that invoke nothing, and this table maps all four to real
    capabilities — so keel's stubs are credited with the uploads its
    differently-named real lanes (`mykronos-sast`, `mykronos-secrets`) make,
    and read `reporting`.

    Not fixable from either table: acknowledging `sast` here would un-monitor
    the real `sast` lane in three working pipelines. The fix is a
    pipeline-scoped key, which is a larger change than the one this was found
    during.

    This test fails the day somebody makes the table pipeline-scoped, which is
    the right moment to delete it and `COLLIDING_KEEL_STUBS` together.
    """
    assert set(CAPABILITY_BY_JOB) >= COLLIDING_KEEL_STUBS, (
        "these keel stub names are no longer mapped globally, so either the "
        "collision is fixed — delete this test and COLLIDING_KEEL_STUBS — or "
        "a real lane lost its mapping"
    )
    assert not (COLLIDING_KEEL_STUBS & set(ACKNOWLEDGED_UNMAPPED_JOBS)), (
        "a colliding name was acknowledged, which un-monitors the real lane "
        "of the same name in mykronos, thehub and personal-soc"
    )
