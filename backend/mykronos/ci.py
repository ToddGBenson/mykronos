"""Where a repository is built, and how to get there (spec 15 §4a, spec 32 §7).

The traffic between Mykronos and its CI has only ever run one way: pipelines
upload findings, and the lake cannot tell which CI produced any of them. That
is deliberate for analysis — spec 15 §4 — and useless for navigation. Somebody
looking at a repository's findings has no way to reach the build that produced
them without already knowing where to look.

This closes that, and nothing more. Nothing read here is an input to a
finding, a score or a decision; it is a link and a status next to it.

**Two CI systems, one set of answers.** `ConcourseClient` reads Concourse and
`ActionsClient` reads GitHub Actions, and everything downstream of them —
`JobStatus`, `PipelineStatus`, `reconcile`, `coverage`, the dashboard panel —
is shared and unaware of which answered. That is not a refactor made for
elegance: `reconcile()` and `coverage()` are the two functions spec 15 §4a.1
records getting wrong twice, and the cheapest way to avoid a third is to add a
second reader in front of them rather than a second copy of them behind.

Three properties worth stating, because each is a way this could go wrong:

*Which lane covers a repository is derived.* For Concourse the pipeline is the
repository name, lowercased, checked against the live list. For Actions it is
the workflow filename the installer itself chose, looked up in the template
registry — exact rather than heuristic. Neither is a configured mapping that
can go stale, and a repository nothing covers reports exactly that rather than
a dead link.

*It reads the job list, never build logs.* Logs carry scanner output and,
until CNC-2 lands, resolved `((var))` values. True of Actions runs for the
same reason.

*It fails soft, always.* Concourse restarting, or GitHub rate-limiting, must
not affect a page about findings. Every failure resolves to "unavailable, and
here is why", never an exception that reaches a request handler.

One property is *not* shared, and is called out where it is lost: the
Concourse read is anonymous, and the Actions read spends an installation
token against a limit other things need more (see `StatusCache`).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime

import httpx2

from mykronos.github.client import GitHubClient
from mykronos.logsafe import scrub

logger = logging.getLogger(__name__)

#: Short, because this runs inside a dashboard request. A Concourse that has
#: not answered in three seconds is reported as unavailable, which is both
#: true and better than a page that hangs.
TIMEOUT = 3.0


def pipeline_name_for(repo_full_name: str) -> str:
    """`ToddGBenson/TheHub` -> `thehub` (spec 15 §4a)."""
    return repo_full_name.rsplit("/", 1)[-1].lower()


#: The Concourse pipelines this platform writes, by the name Concourse knows
#: them by — which is what `pipeline_name_for()` returns for their repository.
MYKRONOS = "mykronos"
THEHUB = "thehub"
PERSONAL_SOC = "personal-soc"
KEEL = "keel"

#: The pseudo-pipeline every GitHub Actions lane belongs to, and the one place
#: a name may legitimately mean the same thing everywhere (B-59988).
#:
#: A Concourse pipeline is written by hand, so `sast` means whatever the person
#: who typed it meant. Actions workflows are not: the Workflow Installer
#: generates them from one template registry, so `mykronos-sast.yml` is the
#: same file in every repository that has it, and `ActionsClient._job_name_for`
#: resolves it through that registry before this map is consulted at all. The
#: names are global because the generator is, which is a fact about how they
#: are produced rather than an exemption granted to them.
#:
#: So Actions jobs carry ONE identity rather than one per repository. That is
#: the deliberate answer to "what pipeline is an Actions job on", and the
#: alternative — keying Actions by repository — would require an entry per
#: repository for names the installer guarantees are identical.
ACTIONS = "github-actions"


def jobs_for_capability(pipeline: str, capability: str) -> list[str]:
    """Which job(s) on THIS pipeline plausibly produce this capability, best
    first.

    The reverse of `CAPABILITY_BY_JOB`, and a heuristic in the same spirit and
    for the same reason as the mapping it derives from: a pipeline that names
    its job differently is simply not reached, which is the safe direction to
    be wrong in — a 404 from Concourse, not a crash.

    Lives here rather than in a caller because two of them now need it: the
    "scan now" button (spec 17 §2.5) and fix verification (spec 25 §1). A
    second private copy would be a second thing to update when a job is
    renamed, and the first one to be forgotten.

    **Scoped by pipeline since B-59988, and this one had teeth.** Both callers
    take the first job that answers and START A BUILD of it. Unscoped, this
    returned every job name mapped to the capability anywhere in the estate —
    so "re-run sast" on personal-soc offered `sast` (a job personal-soc does
    not have) and `mykronos-sast` (keel's), and only reached `lint`, the job
    that actually produces personal-soc's sast, after two 404s. Triggering a
    build on the wrong pipeline was prevented only by the pipeline argument the
    CALLER passes to `trigger_job`, which is a different pipeline from the one
    these names came from.

    **Ordered, and the order is load-bearing.** A capability produced by
    several jobs has to name the obvious one first. `unit` is produced by
    `unit` and by `coverage`, the weekly lane that runs the same suite with
    tracing on (D-121); sorting alphabetically would make "re-run unit" start
    the slow one. The capability's own name goes first where it is a job on
    this pipeline, then the rest in a stable order.

    An unknown pipeline falls back to the capability's own name rather than to
    nothing, which is what an unmapped pipeline did before this was scoped:
    one 404 instead of an empty list, and the same "safe direction" the
    docstring above claims.
    """
    jobs = _JOBS_BY_CAPABILITY.get((pipeline, capability)) or {capability}
    return sorted(jobs, key=lambda job: (job != capability, job))


#: Which capability a job's results should arrive under, ON WHICH PIPELINE.
#:
#: A heuristic, and named as one. Job names are chosen by whoever writes the
#: pipeline and nothing enforces this; a job absent from here is REPORTED as
#: `unknown` rather than skipped (B-59330). `dependencies` uploads as `atlas`
#: and `cloud-posture` as `cloud`, both of which have been mistaken for
#: coverage gaps.
#:
#: **Keyed on `(pipeline, job)` since B-59988, and the unscoped version was
#: actively wrong.** A job name used to mean the same thing everywhere, so
#: keel's stub jobs called `sast`, `secrets`, `iac` and `lint` - 158-437 bytes
#: each, invoking no scanner - were credited with the uploads keel's real,
#: differently-named lanes (`mykronos-sast`, `mykronos-secrets`) made. Their
#: green builds lined up against those lanes' scan runs and read `reporting`:
#: a job that does nothing, reported as covering a capability, because a
#: sibling uploaded.
#:
#: Scoping had to be the KEY rather than a filter somewhere downstream. The
#: collision could not be reached from the acknowledgement list either -
#: acknowledging `sast` globally would have un-monitored the real `sast` lane
#: in mykronos and thehub, which is the same defect pointed at two working
#: pipelines.
#:
#: **Every pipeline set below was READ, not guessed** - parsed out of
#: `deploy/concourse/pipelines/*.yml` for the three local pipelines, and off
#: the running server with `fly get-pipeline -p keel` for keel's, whose
#: pipeline lives in keel's own repo. `test_ci_job_audit.py` holds the three
#: local ones to that, in both directions.
#:
#: **`insider` is deliberately absent.** Aegis assesses a pull request, not a
#: commit, and these pipelines trigger on pushes to main - where there is
#: usually no pull request and therefore correctly no assessment. The job
#: succeeds having recorded nothing, on purpose: submitting an assessment
#: with no reviews, no base ref and no description would score 0/100 for
#: exactly the case Aegis exists to notice. Cross-checking it reported every
#: green insider job as a silent failure, which was this check being wrong
#: about what the job is for.
#:
#: Declared as (pipelines, job, capability) triples rather than written out
#: once per pipeline, because several of these genuinely run on more than one
#: and three hand-copied entries are three things to keep in step - the drift
#: this module keeps finding. A job name may appear more than once with
#: different pipelines and a different capability; nothing needs that yet, and
#: the shape allows it because the whole point of scoping is that a name is
#: free to mean two things.
_CAPABILITY_DECLARATIONS: tuple[tuple[tuple[str, ...], str, str | tuple[str, ...]], ...] = (
    ((MYKRONOS, THEHUB, ACTIONS), "sast", "sast"),
    # A second `sast` lane, not a second capability (B-051). CodeQL implements
    # no shell language, so a shell-heavy repository runs ShellCheck beside it
    # and both upload `sast` - which the cross-check has always supported,
    # since it maps jobs to capabilities rather than the reverse.
    # `sast-shell`, not `mykronos-sast-shell`: `ActionsClient._job_name_for`
    # resolves a workflow through the template registry first, so the Actions
    # lane already arrives here under its registry key. Adding the filename
    # stem as well would put it in `jobs_for_capability(ACTIONS, "sast")`, and
    # the "scan now" button would try to trigger a Concourse job that does not
    # exist before the one that does.
    ((ACTIONS,), "sast-shell", "sast"),
    ((ACTIONS,), "sast-powershell", "sast"),
    # personal-soc's PowerShell analyser, which is named `lint` because it
    # predates uploading anything - it gated on PSScriptAnalyzer errors for
    # months before it reported (#390). Registered under its real name rather
    # than renamed to `sast-powershell`: a rename orphans the job's build
    # history in Concourse, and the mapping exists precisely so a job can be
    # called whatever it is called and still be cross-checked.
    #
    # Scoped to personal-soc, and this entry shows why scoping was needed in
    # both directions: keel also has a job called `lint`, and keel's is a
    # stub. Unscoped, keel's stub inherited this meaning.
    ((PERSONAL_SOC,), "lint", "sast"),
    ((MYKRONOS, PERSONAL_SOC, THEHUB, ACTIONS), "secrets", "secrets"),
    ((MYKRONOS, THEHUB, ACTIONS), "containers", "containers"),
    ((ACTIONS,), "dast", "dast"),
    ((MYKRONOS, PERSONAL_SOC, THEHUB, ACTIONS), "iac", "iac"),
    ((MYKRONOS, THEHUB), "dependencies", "atlas"),
    ((ACTIONS,), "atlas", "atlas"),
    ((THEHUB,), "cloud-posture", "cloud"),
    ((ACTIONS,), "cloud", "cloud"),
    # Quality stages (D-046). They report a run and no findings, so the
    # cross-check is the only thing that can tell whether they reported at
    # all - there is no finding count to notice the absence of.
    ((MYKRONOS, THEHUB, ACTIONS), "unit", "unit"),
    # The weekly coverage lane runs the same suite with tracing on and uploads
    # as `unit`, because the coverage belongs to the lane a person reads it
    # against (D-121). Registered so the cross-check can see it; ordered after
    # `unit` by `jobs_for_capability`, so "re-run unit" does not start the
    # slow one.
    ((MYKRONOS,), "coverage", "unit"),
    ((THEHUB, ACTIONS), "qa", "qa"),
    ((MYKRONOS,), "qa-spec-links", "qa"),
    ((MYKRONOS, ACTIONS), "ai", "ai"),
    ((ACTIONS,), "ai-checks", "ai"),
    ((PERSONAL_SOC, ACTIONS), "functional", "functional"),
    ((MYKRONOS, ACTIONS), "demo-and-dast", ("functional", "dast")),
    # PS-1. These four ran green on every build and reported nothing, so the
    # cross-check had nothing to compare and said nothing about them. They
    # report now, and a job that reports has to be checked or the reporting
    # buys only half of what it should.
    #
    # `lint-and-types`, `frontend` and `api-inventory` all land under `qa`
    # alongside `qa-spec-links`: the capability has one registered adapter
    # (`adapters/registry.py`), quality stages carry no findings (D-046), and
    # so several runs per commit is a richer answer rather than a collision.
    ((MYKRONOS,), "lint-and-types", "qa"),
    ((MYKRONOS,), "frontend", "qa"),
    ((THEHUB,), "prompt-evals", "ai"),
    # thehub's `api-inventory` was declared here until #59100. It regenerated
    # the OpenAPI inventory against the RUNNING demo instance, so it went with
    # the demo environment when Path B was retired (ADR 0072).
    #
    # thehub's dast lanes. `dast-demo` was here too and went the same way: it
    # scanned ((thehub-demo-url)), and with no demo it would have reported on
    # whatever the host last served.
    ((THEHUB,), "dast-prod", "dast"),
    # [#477] Restored with the jobs themselves. #468 removed these alongside
    # `functional-dast` on the premise that the demo chain was dead; it was
    # blocked by the CRLF mismatch #388 fixed, and both lanes ran again on
    # 2026-09-17. Without these entries the coverage cross-check cannot see
    # them, which is what `test_every_reporting_job_is_cross_checked` caught.
    ((THEHUB,), "api-inventory", "qa"),
    ((THEHUB,), "dast-demo", "dast"),
    # `dast-staging` scans the standing staging environment on a daily timer
    # rather than after a deploy, because staging is deployed out of band. That
    # makes registering it matter more than for its two siblings, not less: a
    # timer-triggered lane has no upstream build to be conspicuous by its
    # absence, so the coverage cross-check is the only thing that can notice it
    # has stopped.
    ((THEHUB,), "dast-staging", "dast"),
    # `functional-dast` was the third entry here, the one lane declaring two
    # capabilities from one build. It drove the demo environment through ZAP's
    # proxy and was removed with Path B (#59100). `functional` now has no
    # declaring lane in any pipeline here, which is a real coverage loss and is
    # left visible as one rather than papered over with a lane that would
    # report on nothing.
    ((THEHUB,), "ai-models", "ai"),
    # keel's three uploading lanes (B-59330). keel's pipeline lives in keel's
    # own repo, so these were read off the running server with
    # `fly get-pipeline -p keel` rather than from a file here - which is why
    # they were missing in the first place, and why nothing in this repository
    # can check them.
    #
    # The capability is the one each task DECLARES in its `CAPABILITY:` param,
    # not one inferred from the job name. `mykronos-atlas` is the case that
    # makes the distinction worth stating: it runs `osv-scan` with
    # `TOOL: osv-scanner` and uploads `atlas`, and a reader going by the name
    # would have guessed "sca" - which is the name of one of keel's stubs.
    #
    # Only three of keel's 26 jobs upload anything. The other 23 are stubs and
    # are deliberately neither mapped nor acknowledged, so they report
    # `unknown` - see the note on `ACKNOWLEDGED_UNMAPPED_JOBS`.
    ((KEEL,), "mykronos-sast", "sast"),
    ((KEEL,), "mykronos-secrets", "secrets"),
    ((KEEL,), "mykronos-atlas", "atlas"),
)


def _scoped(
    declarations: tuple[tuple[tuple[str, ...], str, str | tuple[str, ...]], ...],
) -> dict[tuple[str, str], str | tuple[str, ...]]:
    """Expand the declarations into the `(pipeline, job)` table lookups use.

    A duplicate key raises rather than being silently resolved, because "which
    of the two wins" would be decided by the order of the rows - and a table
    whose meaning depends on its row order is the shape this whole exercise is
    about.
    """
    out: dict[tuple[str, str], str | tuple[str, ...]] = {}
    for pipelines, job, capability in declarations:
        for pipeline in pipelines:
            if (pipeline, job) in out:
                raise ValueError(f"{job!r} is declared twice for pipeline {pipeline!r}")
            out[(pipeline, job)] = capability
    return out


#: `(pipeline, job)` -> capability. Derived; declare in
#: `_CAPABILITY_DECLARATIONS` above.
CAPABILITY_BY_JOB: dict[tuple[str, str], str | tuple[str, ...]] = _scoped(
    _CAPABILITY_DECLARATIONS
)


#: keel's stub jobs whose names a real lane elsewhere also uses (B-59988).
#:
#: THE DEFECT THESE FOUR NAMED, now fixed by the key above rather than only
#: described. `CAPABILITY_BY_JOB` used to be keyed on the job name alone, so a
#: name meant the same thing on every pipeline. keel's stubs called `sast`,
#: `secrets`, `iac` and `lint` - 158-437 bytes each, invoking no scanner -
#: inherited the meaning of the real jobs of those names on mykronos, thehub
#: and personal-soc. Measured 2026-09-17: keel's real uploads arrive from
#: `mykronos-sast` and `mykronos-secrets`, the lake held recent `sast` and
#: `secrets` runs, and the stubs' green builds lined up against those runs and
#: read `reporting`. A job that does nothing, reported as covering a
#: capability, because a differently-named sibling uploaded.
#:
#: Kept as a named set after the fix, because it is what the regression test
#: points at. The property worth holding is not "these four are absent" but
#: that each is absent for KEEL and present for the pipeline that really runs
#: it - a map that had simply lost them would satisfy the first and not the
#: second. `test_ci_job_audit.py` asserts both directions.
#:
#: Delete this when keel's stubs are deleted, and not before: the names are a
#: property of keel's pipeline, not of this table.
KEEL_STUBS_THAT_LOOK_MAPPED: frozenset[str] = frozenset({"sast", "secrets", "iac", "lint"})

#: How far a successful build may lead its capability's newest scan run before
#: the results count as missing. Generous on purpose: a job's build finishes
#: after its upload, but compaction is asynchronous and a run started before a
#: deploy can land minutes later. Anything under an hour is not evidence.
REPORTING_GRACE_SECONDS = 3600


#: `(pipeline, capability)` -> the jobs on THAT pipeline producing it.
#:
#: Keyed by the pair for the same reason `CAPABILITY_BY_JOB` is: the reverse
#: of a scoped table has to carry the scope, or `jobs_for_capability` hands a
#: caller the name of a job that belongs to some other pipeline and the
#: caller starts a build of it.
_JOBS_BY_CAPABILITY: dict[tuple[str, str], set[str]] = {}
for (_pipeline, _job_name), _caps in CAPABILITY_BY_JOB.items():
    for _cap in _caps if isinstance(_caps, tuple) else (_caps,):
        _JOBS_BY_CAPABILITY.setdefault((_pipeline, _cap), set()).add(_job_name)


def _utc(moment: datetime | None) -> datetime | None:
    """Attach UTC to a naive timestamp.

    The two sides of this comparison come from different worlds and only one
    of them carries a timezone: Concourse reports epoch seconds, which become
    aware datetimes, while the lake stores what `utcnow()` wrote and DuckDB
    hands back naive. Subtracting them raises TypeError, which reached
    production as a 500 on the repository page - the unit tests used aware
    datetimes on both sides and never saw it.

    Naive lake timestamps are UTC by construction, so saying so is a
    statement of fact rather than an assumption.
    """
    if moment is None or moment.tzinfo is not None:
        return moment
    return moment.replace(tzinfo=UTC)


@dataclass(frozen=True)
class Reporting:
    """Whether a job's results actually reached the lake (spec 15 §4a).

    The gap this closes: a pipeline is green, the dashboard shows an old scan,
    and nothing anywhere says those two facts contradict each other. It
    happened here - the sast lane failed on every run for a day while the
    capability simply looked un-scanned.
    """

    job: str
    capability: str
    built_at: datetime | None
    scanned_at: datetime | None
    paused: bool = False
    """Somebody switched this lane off, and Concourse still lists it.

    A paused job reports its last build for ever, so the state derived from
    that build says `failed` — which reads as "fix this" when the truth is
    "decide whether you still want this control". On 2026-09-12 four security
    lanes were paused: TheHub's `cloud-posture` and `functional-dast`,
    personal-soc's `breach-check`, and mykronos's `demo-and-dast`. All four
    were paused between 2026-08-13 and 2026-08-16, each after a run of
    failures, and nothing anywhere recorded that they had been switched off
    rather than left broken.
    """
    last_build_failed: bool = False
    """The lane ran and its last build did not succeed.

    Separate from `built_at` rather than folded into it, because the two
    answer different questions and this check needs both: `built_at` is "when
    did a SUCCESSFUL build last happen", which is what the lake is measured
    against, and this is "did the lane run at all".
    """

    unmapped: bool = False
    """Nothing says what capability this job produces (B-59330).

    The row exists precisely because the question cannot be answered. Every
    other state here is a statement about a lane whose purpose is known;
    this one says the purpose itself is unrecorded, so no amount of green
    builds underneath it means anything.
    """

    @property
    def state(self) -> str:
        # First, ahead of `paused` and `failed`, because it is not a worse
        # version of either - it is the statement that this row's other
        # fields cannot be interpreted. A job nobody has mapped has no
        # capability to be silent about, so "failed" or "paused" would be
        # answering a question that was never asked.
        if self.unmapped:
            return "unknown"
        # Before `last_build_failed`, and deliberately: a paused job's last
        # build is usually the failure that prompted somebody to pause it, so
        # reporting `failed` would keep telling a reader to repair a lane that
        # is off on purpose. "Paused" is the more actionable fact and it
        # already implies the failure underneath.
        if self.paused:
            return "paused"
        # Before the built_at check, because a failed build leaves built_at
        # unset - that is the whole reason a failing lane used to read as one
        # that had never run.
        if self.last_build_failed:
            return "failed"
        built = _utc(self.built_at)
        scanned = _utc(self.scanned_at)
        if built is None:
            return "not_run"
        if scanned is None:
            return "never_reported"
        delta = (built - scanned).total_seconds()
        return "silent" if delta > REPORTING_GRACE_SECONDS else "reporting"


@dataclass(frozen=True)
class JobStatus:
    name: str
    status: str | None
    build_name: str | None
    build_url: str | None
    finished_at: datetime | None
    #: Concourse reports this on every job and it was being dropped here.
    paused: bool = False

    @property
    def ok(self) -> bool:
        return self.status == "succeeded"


@dataclass(frozen=True)
class PipelineStatus:
    """What Concourse says about one repository's pipeline."""

    repo_full_name: str
    pipeline: str | None
    url: str | None
    paused: bool = False
    jobs: list[JobStatus] = field(default_factory=list)
    #: Why there is nothing to show, when there is nothing to show. Rendered
    #: verbatim: "no pipeline" and "Concourse unreachable" are different
    #: facts and a panel that conflates them teaches people to ignore it.
    unavailable: str | None = None

    @property
    def failing(self) -> list[str]:
        return [job.name for job in self.jobs if job.status == "failed"]


class ConcourseClient:
    """Reads pipeline state from Concourse's API, anonymously (spec 15 §4a)."""

    def __init__(self, base_url: str, *, team: str = "main", external_url: str = "") -> None:
        self.base_url = base_url.rstrip("/")
        self.team = team
        # Where a browser goes, which is not where this process goes.
        self.external_url = (external_url or base_url).rstrip("/")

    @property
    def configured(self) -> bool:
        return bool(self.base_url)

    def _get(self, path: str) -> object | None:
        try:
            response = httpx2.get(f"{self.base_url}{path}", timeout=TIMEOUT)
            response.raise_for_status()
            payload: object = response.json()
            return payload
        except Exception as exc:  # noqa: BLE001 - see the module docstring
            # scrub() because the URL and any error text pass through a log
            # line, and this one is reachable by anything on the network.
            logger.warning("Concourse read of %s failed: %s", scrub(path), scrub(str(exc)))
            return None

    def pipelines(self) -> list[str] | None:
        """Every pipeline visible without authenticating, or None if unreachable."""
        payload = self._get("/api/v1/pipelines")
        if not isinstance(payload, list):
            return None
        return [str(p["name"]) for p in payload if isinstance(p, dict) and "name" in p]

    def pipeline_url(self, pipeline: str) -> str:
        """Where a browser reaches this pipeline (not where this process does)."""
        return f"{self.external_url}/teams/{self.team}/pipelines/{pipeline}"

    def job_names(self, pipeline: str) -> list[str] | None:
        """Every job in one pipeline, or None if that pipeline is unreadable.

        `None` rather than `[]`, for the reason this module repeats: a
        pipeline that cannot be read has not been shown to be healthy, and a
        sweep that silently skipped it would report a clean estate.
        """
        statuses = self.job_last_statuses(pipeline)
        return None if statuses is None else list(statuses)

    def job_last_statuses(self, pipeline: str) -> dict[str, str | None] | None:
        """Each job in one pipeline against its last *finished* build's status.

        One request answers "which lanes are worth asking about in detail",
        which matters because every read here costs a round trip and this
        estate has 79 lanes. `None` for a job means it has never finished a
        build — not a success, and the caller must not read it as one.
        """
        payload = self._get(f"/api/v1/teams/{self.team}/pipelines/{pipeline}/jobs")
        if not isinstance(payload, list):
            return None
        out: dict[str, str | None] = {}
        for raw in payload:
            if not isinstance(raw, dict) or "name" not in raw:
                continue
            build = raw.get("finished_build")
            status = build.get("status") if isinstance(build, dict) else None
            out[str(raw["name"])] = str(status) if isinstance(status, str) else None
        return out

    def job_builds(
        self, pipeline: str, job: str, *, limit: int = 10
    ) -> list[dict[str, object]] | None:
        """One job's recent builds, newest first, or None if unreadable.

        This is the one read in this module that looks at more than a lane's
        *latest* build, and it is still only the build list: id, name, status
        and timestamps. It does not fetch build logs or build events, which
        carry scanner output and resolved `((var))` values — the property
        stated at the top of this module holds here too. What that costs the
        detector built on it is measured and recorded in `ci_repeat`.
        """
        payload = self._get(
            f"/api/v1/teams/{self.team}/pipelines/{pipeline}/jobs/{job}/builds"
            f"?limit={int(limit)}"
        )
        if not isinstance(payload, list):
            return None
        return [b for b in payload if isinstance(b, dict)]

    def has_pipeline_for(self, repo_full_name: str) -> bool | None:
        """Is there a Concourse pipeline for this repository?

        Three answers, and the third is the point: `True`, `False`, or `None`
        for "could not be established" — Concourse unreachable, or not
        configured for this deployment at all. A caller deciding whether it is
        safe to rotate a credential has to be able to tell "no other reader"
        from "could not check", because those warrant opposite actions
        (D-097).

        Distinct from `status_for`, which asks how the pipeline is *doing*.
        This asks only whether it exists, which is a question about who reads
        the repository's ingestion token.
        """
        if not self.configured:
            return None
        available = self.pipelines()
        if available is None:
            return None
        return pipeline_name_for(repo_full_name) in available

    def status_for(self, repo_full_name: str) -> PipelineStatus:
        """Pipeline state for one repository. Never raises."""
        if not self.configured:
            return PipelineStatus(
                repo_full_name=repo_full_name,
                pipeline=None,
                url=None,
                unavailable="No Concourse is configured for this deployment.",
            )

        wanted = pipeline_name_for(repo_full_name)
        available = self.pipelines()
        if available is None:
            return PipelineStatus(
                repo_full_name=repo_full_name,
                pipeline=None,
                url=None,
                unavailable="Concourse did not answer, so its state is unknown.",
            )
        if wanted not in available:
            return PipelineStatus(
                repo_full_name=repo_full_name,
                pipeline=None,
                url=None,
                unavailable=(
                    f"No Concourse pipeline named '{wanted}'. This repository is "
                    "scanned by GitHub Actions."
                ),
            )

        url = f"{self.external_url}/teams/{self.team}/pipelines/{wanted}"
        payload = self._get(f"/api/v1/teams/{self.team}/pipelines/{wanted}/jobs")
        if not isinstance(payload, list):
            return PipelineStatus(
                repo_full_name=repo_full_name,
                pipeline=wanted,
                url=url,
                unavailable="Concourse did not return this pipeline's jobs.",
            )

        return PipelineStatus(
            repo_full_name=repo_full_name,
            pipeline=wanted,
            url=url,
            jobs=[self._job(raw, url) for raw in payload if isinstance(raw, dict)],
        )

    def paused_jobs(self) -> list[tuple[str, JobStatus]] | None:
        """Every paused job in every visible pipeline, or None if unreachable.

        Swept across pipelines rather than per repository, and deliberately
        **not** filtered through `CAPABILITY_BY_JOB` or a repository's enabled
        capabilities. Coverage is computed per capability and a capability is
        satisfied by any one of its jobs, so pausing one of three DAST lanes
        leaves the capability reading green and the paused job unexamined.
        Four security lanes sat paused for thirty-two days that way (#401) --
        `cloud-posture`, `breach-check`, `demo-and-dast` and `functional-dast`,
        each hidden by a different version of the same hole: a working sibling,
        a capability nobody enabled, or producing no scan runs at all and so
        having no home in that mapping.

        A paused job is a control somebody switched off, which is worth
        reporting on its own terms whatever else is covering for it.

        `None` rather than `[]` when Concourse cannot be reached, because
        "nothing is paused" and "could not ask" must not render the same -- that
        is the reporting failure this method exists to end, reproduced one
        level up.
        """
        names = self.pipelines()
        if names is None:
            return None
        out: list[tuple[str, JobStatus]] = []
        for pipeline in names:
            url = f"{self.external_url}/teams/{self.team}/pipelines/{pipeline}"
            payload = self._get(f"/api/v1/teams/{self.team}/pipelines/{pipeline}/jobs")
            if not isinstance(payload, list):
                # One unreadable pipeline does not invalidate the others, but it
                # does mean this answer is partial. Logged by `_get` already.
                continue
            for raw in payload:
                if not isinstance(raw, dict) or not raw.get("paused"):
                    continue
                out.append((pipeline, self._job(raw, url)))
        return out

    #: Build statuses that mean the job ran and did not succeed.
    #:
    #: `aborted` is deliberately absent. An abort is somebody cancelling, which
    #: is a decision with a person behind it -- the same reason a paused lane is
    #: reported separately rather than as a failure. `errored` IS here: that is
    #: the lane breaking before it got as far as a result, which is exactly the
    #: case this list exists for.
    FAILED_STATUSES = frozenset({"failed", "errored"})

    def failing_jobs(self) -> list[tuple[str, JobStatus]] | None:
        """Every job whose last finished build failed and which nobody paused.

        The gap between this and `paused_jobs` is where `netassess-ingest` sat
        for five weeks: **one success in ten builds**, failing on its timer
        since 2026-08-13, and absent from all five sections of the briefing.

        It qualified for none of them. Not switched off -- it is unpaused and
        running. Not a stalled lane -- those are keyed on lanes tied to open
        findings, and this one produces *evidence* (the `network` upload of
        #306), never a finding. Not an unread language, not an open finding,
        not something auto-remediation could take.

        So the four lanes #401 found were visible for one reason only:
        **somebody had already noticed them and switched them off.** Pausing is
        what made them reportable. A lane that fails honestly on a schedule,
        and that nobody ever got round to pausing, is in a strictly worse state
        and had no home on the page at all -- a paused lane represents a
        decision, and this represents nothing.

        Paused jobs are excluded rather than listed twice: `paused_jobs`
        already reports those and its rendering says something different about
        them ("turn it back on") than this one does ("find out why it throws").

        Not filtered by capability, for the reason `paused_jobs` gives at
        length: a capability is satisfied by any one of its jobs, so a failing
        lane with a working sibling reads green at that level.

        `None` rather than `[]` when Concourse cannot be reached. "Nothing is
        failing" and "could not ask" must not render the same.
        """
        names = self.pipelines()
        if names is None:
            return None
        out: list[tuple[str, JobStatus]] = []
        for pipeline in names:
            url = f"{self.external_url}/teams/{self.team}/pipelines/{pipeline}"
            payload = self._get(f"/api/v1/teams/{self.team}/pipelines/{pipeline}/jobs")
            if not isinstance(payload, list):
                continue
            for raw in payload:
                if not isinstance(raw, dict) or raw.get("paused"):
                    continue
                job = self._job(raw, url)
                if (job.status or "") in self.FAILED_STATUSES:
                    out.append((pipeline, job))
        return out

    def trigger_job(self, pipeline: str, job: str, *, token: str) -> bool:
        """Start a new build of `job` now (spec 17 §2.5), rather than
        waiting for the next commit the pipeline's own resource polls for.

        Unlike every read above, this is a write against infrastructure
        spec 15 §7 already flags as sensitive — a worker inside the LAN —
        so it is not anonymous the way `status_for` is. `token` is the
        caller's to obtain (`settings.concourse_api_token`, spec 15 §6's
        credential manager); this method only spends it.

        Returns whether Concourse accepted the request. Never raises: a
        trigger that fails is reported the same way a status read that
        fails is — a falsy result with the reason logged — so a dashboard
        action can say "couldn't start it" rather than 500.
        """
        try:
            response = httpx2.post(
                f"{self.base_url}/api/v1/teams/{self.team}/pipelines/"
                f"{pipeline}/jobs/{job}/builds",
                headers={"Authorization": f"Bearer {token}"},
                timeout=TIMEOUT,
            )
            response.raise_for_status()
            return True
        except Exception as exc:  # noqa: BLE001 - see the module docstring
            logger.warning(
                "Concourse trigger of %s/%s failed: %s",
                scrub(pipeline),
                scrub(job),
                scrub(str(exc)),
            )
            return False

    @staticmethod
    def _job(raw: dict[str, object], pipeline_url: str) -> JobStatus:
        name = str(raw.get("name", ""))
        build = raw.get("finished_build")
        if not isinstance(build, dict):
            # A job that has never finished a build. Not a failure and not a
            # success: it has not run, and saying so beats implying either.
            return JobStatus(
                name=name,
                status=None,
                build_name=None,
                build_url=None,
                finished_at=None,
                paused=bool(raw.get("paused")),
            )

        build_name = str(build.get("name", ""))
        end = build.get("end_time")
        return JobStatus(
            name=name,
            status=str(build.get("status")) if build.get("status") else None,
            build_name=build_name or None,
            build_url=f"{pipeline_url}/jobs/{name}/builds/{build_name}" if build_name else None,
            # Concourse reports epoch seconds.
            finished_at=datetime.fromtimestamp(int(end), tz=UTC)
            if isinstance(end, int | float) and end
            else None,
            paused=bool(raw.get("paused")),
        )


#: GitHub's run conclusions, mapped onto the status vocabulary the rest of
#: this module, the dashboard and `reconcile` already speak (spec 32 §7).
#:
#: Translating here rather than teaching four call sites a second vocabulary
#: is the whole reason `reconcile()` and `coverage()` need no edit to work
#: against Actions: they compare `status == "succeeded"`, and a client that
#: handed them `"success"` would have reported every green lane as one that
#: had never run — a silent, total false negative in exactly the check that
#: exists to catch silent failures.
#:
#: `skipped` maps to `None` — *not run*. A skipped job produced no outcome,
#: and calling it a success would let a lane that never executed vouch for a
#: capability. `None` is also what an unrecognised conclusion becomes, which
#: is the safe direction to be wrong in: "has not run" invites a look, while
#: a wrong "succeeded" ends the conversation.
_STATUS_BY_CONCLUSION: dict[str, str] = {
    "success": "succeeded",
    "failure": "failed",
    "timed_out": "errored",
    "startup_failure": "errored",
    "action_required": "errored",
    "cancelled": "aborted",
    "stale": "aborted",
}


def status_from_conclusion(conclusion: str | None) -> str | None:
    """One GitHub run conclusion as a platform status, or None for *not run*."""
    if not conclusion:
        return None
    return _STATUS_BY_CONCLUSION.get(conclusion)


def capability_by_workflow(templates: object) -> dict[str, str]:
    """`mykronos-sast.yml` -> `sast`, from the template registry.

    The Actions counterpart of `CAPABILITY_BY_JOB`, and unlike it, **not a
    heuristic**: the Workflow Installer chose these filenames, so this is the
    registry answering a question about its own output rather than a guess
    about names somebody else picked.

    Takes the library loosely rather than importing `TemplateLibrary`, which
    would point this module at the installer for one attribute — and the
    dependency runs the wrong way. A library without `specs` yields an empty
    map, so a caller with no templates configured reports "no workflow
    installed" rather than raising inside a status read that must not.
    """
    specs = getattr(templates, "specs", None)
    if not isinstance(specs, dict):
        return {}
    return {
        str(spec.target).rsplit("/", 1)[-1]: capability
        for capability, spec in specs.items()
        if getattr(spec, "target", None)
    }


class StatusCache:
    """A short-lived cache in front of a status read (spec 32 §7.1).

    Concourse was read anonymously off a server on the same host, so a read
    per request cost nothing anybody could measure. GitHub is a network
    round-trip against an installation limit of 5000/hour that token
    rotation, the installer and Patchwork all draw on — and this is the least
    important of the four. A repository page refreshed in a loop must not be
    what stops a token rotating.

    **Only successful reads are cached.** Caching a failure would pin a
    transient blip in place for the whole TTL, and "GitHub did not answer"
    is exactly the answer somebody re-loads the page to change.
    """

    def __init__(self, ttl_seconds: float = 60.0, limit: int = 512) -> None:
        self.ttl_seconds = ttl_seconds
        self.limit = limit
        self._entries: dict[str, tuple[float, PipelineStatus]] = {}

    def get(self, key: str, *, now: float) -> PipelineStatus | None:
        entry = self._entries.get(key)
        if entry is None:
            return None
        stored_at, value = entry
        if now - stored_at > self.ttl_seconds:
            self._entries.pop(key, None)
            return None
        return value

    def put(self, key: str, value: PipelineStatus, *, now: float) -> None:
        if value.unavailable is not None:
            return
        if len(self._entries) >= self.limit:
            # Oldest first. A dashboard reads a bounded set of repositories,
            # so this is a ceiling rather than an eviction strategy worth
            # tuning.
            oldest = min(self._entries, key=lambda k: self._entries[k][0])
            self._entries.pop(oldest, None)
        self._entries[key] = (now, value)


class ActionsClient:
    """Reads workflow state from GitHub Actions (spec 32 §7).

    The second implementation of what `ConcourseClient` does, for the
    repositories that moved. Everything downstream — `reconcile`, `coverage`,
    `PipelineStatus`, the dashboard panel — is unchanged and unaware, because
    those were always about job names, statuses and timestamps rather than
    about Concourse.

    Three properties are carried over deliberately, and one is lost:

    *Derived, not configured.* Which lane produces which capability comes from
    the template registry, because the installer chose the filename. Where the
    Concourse mapping is a documented heuristic about names somebody else
    picked, this one is exact.

    *Never reads logs.* Run metadata only, for the same reason as spec 15 §4a:
    logs carry scanner output.

    *Fails soft, always.* Every failure resolves to "unavailable, and here is
    why". The failure modes are richer than Concourse's — an expired
    installation token, a 403, a rate limit — and none of them may reach a
    request handler.

    *Reads anonymously.* *Lost*, and worth stating rather than discovering.
    Concourse was read with no credential because those pipelines are
    `public: true` on a loopback-bound server. This spends an installation
    token, against a limit shared with token rotation, the installer and
    Patchwork — which is why the read is cached (§7.1) and why the panel is
    the first consumer to give up.
    """

    def __init__(
        self,
        github: GitHubClient | None,
        *,
        capability_by_workflow: dict[str, str],
    ) -> None:
        self._github = github
        #: `mykronos-sast.yml` -> `sast`. Built by the caller from the
        #: template registry rather than restated here, so there is one
        #: answer to "which lane is this" and the installer owns it.
        self._capability_by_workflow = capability_by_workflow

    @property
    def configured(self) -> bool:
        return self._github is not None

    def _job_name_for(self, file_name: str) -> str | None:
        """What to call this workflow's job, or None if it is not ours.

        Two sources, in order, and the order is the point:

        **The template registry, which is exact.** The installer chose
        `mykronos-sast.yml`, so mapping it to `sast` is the registry answering
        a question about its own output.

        **`CAPABILITY_BY_JOB`, which is a heuristic and is already one.** A
        repository may legitimately produce a capability from a workflow this
        platform did not write — `demo-and-dast.yml` uploads `functional` and
        `dast` from an ephemeral stack the templates cannot express (spec 32
        §4.2). Before this fell back, both read `no_job`: rendered red, as a
        coverage gap, while the scans were arriving.

        Returning the *stem* rather than a resolved capability is what makes
        the one-job-to-several-capabilities case work without touching
        `reconcile()`. That function already splits a tuple — it has to, for
        Concourse's `demo-and-dast` — so handing it the same key the Concourse
        side hands it means the two CIs converge on one table rather than
        growing a second.
        """
        capability = self._capability_by_workflow.get(file_name)
        if capability is not None:
            return capability
        stem = file_name.rsplit(".", 1)[0]
        # `ACTIONS`, not the repository, and that is the deliberate answer to
        # "what pipeline is an Actions job on" rather than a default (B-59988).
        # These names come out of the Workflow Installer's template registry,
        # so `mykronos-sast.yml` is the same generated file in every repository
        # that has one - global because the generator is. Keying them per
        # repository would demand an identical entry per repository, and the
        # first repository somebody forgot would go dark.
        return stem if (ACTIONS, stem) in CAPABILITY_BY_JOB else None

    async def status_for(self, repo_full_name: str) -> PipelineStatus:
        """Workflow state for one repository. Never raises."""
        url = f"https://github.com/{repo_full_name}/actions"
        if not self.configured:
            return PipelineStatus(
                repo_full_name=repo_full_name,
                pipeline=None,
                url=None,
                unavailable="No GitHub App is configured for this deployment.",
            )

        github = self._github
        assert github is not None  # `configured` above
        try:
            workflows = await github.list_workflows(repo_full_name)
            runs = await github.latest_workflow_runs(repo_full_name)
        except Exception as exc:  # noqa: BLE001 - see the class docstring
            logger.warning(
                "Actions read of %s failed: %s", scrub(repo_full_name), scrub(str(exc))
            )
            return PipelineStatus(
                repo_full_name=repo_full_name,
                pipeline=None,
                url=url,
                unavailable=(
                    "GitHub did not answer, so this repository's workflow "
                    "state is unknown."
                ),
            )

        by_file = {run.workflow_file: run for run in runs}

        jobs: list[JobStatus] = []
        for workflow in workflows:
            capability = self._job_name_for(workflow.file_name)
            if capability is None:
                # A workflow neither the template registry nor the job-name
                # table recognises — the repository's own CI, `delivery.yml`
                # among them. Not cross-checked, which is the safe direction to
                # be wrong in: claiming somebody else's lane produces a
                # capability would invent coverage.
                continue
            run = by_file.get(workflow.file_name)
            # A workflow GitHub has switched off has not run and will not.
            # Reporting its last conclusion would show a lane as green while
            # it is paused, which is the "green pipeline, stale data"
            # disagreement spec 15 §4a.1 exists to surface rather than hide.
            status = (
                status_from_conclusion(run.conclusion)
                if run is not None and workflow.enabled
                else None
            )
            jobs.append(
                JobStatus(
                    name=capability,
                    status=status,
                    build_name=str(run.run_number) if run and run.run_number else None,
                    build_url=(run.url if run else None)
                    or f"{url}/workflows/{workflow.file_name}",
                    finished_at=run.finished_at if run and workflow.enabled else None,
                )
            )

        if not jobs:
            return PipelineStatus(
                repo_full_name=repo_full_name,
                pipeline=None,
                url=url,
                unavailable=(
                    "No Mykronos workflow is installed in this repository. Enabling a "
                    "capability opens the pull request that installs one (spec 03 §3)."
                ),
            )

        return PipelineStatus(
            repo_full_name=repo_full_name,
            pipeline="github-actions",
            url=url,
            jobs=jobs,
        )


#: Every stage the platform claims to cover, in the order a pipeline runs
#: them. Listed explicitly rather than derived from the Capability enum
#: because the enum is an implementation detail and this is a promise: a
#: stage that disappears from here should be a deliberate edit, not a
#: side-effect of renaming something.
ALL_STAGES: tuple[str, ...] = (
    "unit",
    "qa",
    "sast",
    "secrets",
    "atlas",
    "containers",
    "iac",
    "functional",
    "dast",
    "cloud",
    "network",
    "ai",
    "aegis",
    "oracle",
    "patchwork",
)


@dataclass(frozen=True)
class StageCoverage:
    """One stage, and whether this repository is actually covered by it.

    The distinction the portfolio view needs is between a stage nobody asked
    for and a stage somebody asked for that is not answering. Both look like
    an absence, and only one of them is a problem.
    """

    stage: str
    enabled: bool
    state: str
    lanes: tuple[tuple[str, str], ...] = ()
    """Every job that produces this capability, in the order the CI reported
    them, as `(job, state)`.

    Empty for a stage no job produces, and — deliberately — for a stage with
    exactly one, because there is nothing there a reader does not already have
    from `state`. It is populated only where the collapse below had to make a
    choice, which is the case worth being able to check.
    """

    @property
    def problem(self) -> bool:
        # `failed` is deliberately absent, and this was checked rather than
        # assumed: `test_a_failed_job_is_not_held_against_the_lake` states the
        # policy - a lane that fails produces nothing and the lake is right to
        # be empty, so the failure is the pipeline's to report and not this
        # check's. What this property means is "coverage gap", and the value
        # the cross-check adds is finding lanes that are GREEN and not
        # reporting. A red lane is already red everywhere a person looks.
        #
        # Reconsidered on 2026-09-17 while mapping keel's `mykronos-atlas`
        # (red since build 29, 2026-09-14) and left alone. The thing that
        # reports a failing lane is `ConcourseClient.failing_jobs()` from #459,
        # which reads every job the server lists and is not filtered by
        # capability at all - so it covers a lane whether or not this table
        # knows about it.
        return self.state in {"silent", "never_reported", "no_job", "job_not_enabled"}


#: Capabilities that never produce a ScanRun from a pipeline lane: Aegis is
#: fed by webhooks as reviews happen, Oracle writes decisions, Patchwork opens
#: fix pull requests. The coverage cross-check compares pipeline jobs against
#: scan runs, and these have neither side of that comparison - reporting them
#: as "no_job" flagged working capabilities as permanent gaps.
NON_SCANNING: frozenset[str] = frozenset({"aegis", "oracle", "patchwork"})

#: ...but "produces no scan run" and "needs no job" are two different claims,
#: and treating them as one said a capability was fine without checking that
#: anything ran it (B-061). `personal-soc` reported oracle as
#: `event_driven, problem: false` while its pipeline contained no oracle job
#: of any kind: the capability was granted, no lane was ever written, and the
#: exemption meant from the check reported it as healthy.
#:
#: Oracle is *gate*-driven in this estate rather than event-driven. It is run
#: by a named job -- `oracle-gate` on mykronos and TheHub, `oracle` on
#: personal-soc, and the `mykronos-oracle.yml` workflow, which the template
#: registry already resolves to `oracle`. Its absence is exactly the gap the
#: cross-check exists to report.
#:
#: Aegis and patchwork stay unconditionally exempt, and the distinction is the
#: whole point: both are driven from inside Mykronos -- aegis by webhooks as
#: reviews arrive, patchwork by a timer -- so neither needs a pipeline job for
#: the capability to be working, and demanding one would report two working
#: capabilities as gaps.
#:
#: The job names rather than the capability, because these jobs are NOT in
#: `CAPABILITY_BY_JOB` and must not be: that table maps a job to the
#: capability whose *scan runs* it produces, and an oracle gate produces none.
#: Registering it there would fix this reading by telling a lie in the other
#: direction -- the lane would then be expected to upload, and read as
#: `never_reported` forever.
GATE_JOBS: dict[str, frozenset[str]] = {
    "oracle": frozenset({"oracle", "oracle-gate"}),
}


def coverage(
    enabled_capabilities: set[str],
    reporting: list[Reporting],
    job_names: frozenset[str] = frozenset(),
) -> list[StageCoverage]:
    """Every stage against what this repository actually has (PIP-6).

    `job_names` is every job the CI system reports, whether or not it produces
    scan runs. It is what lets a gate-driven capability be checked for job
    *existence* rather than for scan-run existence -- a gate that ran and
    blocked nothing is still a gate that ran, and has no run to point at.
    An empty set reads as "no jobs seen", which is what an unreachable CI
    already produces for every scanning capability too.

    **A capability served by several jobs is only as covered as its weakest
    lane (B-380).** This used to be `{row.capability: row for row in
    reporting}`, so a capability with more than one producing job reported
    whichever job the CI system happened to list *last* — and the rest were
    discarded without a word. Measured 2026-09-17, that is not hypothetical:

    ```
    keel / actions / sast   sast-shell=failed, sast=reporting   -> reporting
    ```

    `keel` runs ShellCheck beside CodeQL because CodeQL implements no shell
    language (B-051), and both upload `sast`. The ShellCheck lane has run twice
    in its life, 2026-09-15, and failed both times. The capability reported
    `reporting`, `parity` called it `improved` over Concourse, and the count
    underneath the table said four capabilities were covered. Reorder the
    workflows and the same estate would have reported `failed` — the verdict
    depended on list order, which is not a property of the repository.

    So the covered/not-covered verdict is now taken from *every* lane: one that
    is not covered makes the capability not covered, whatever its siblings are
    doing. That is strictly the stricter direction, and deliberately — a
    capability reads as answering only when everything asked to answer does.

    Which *label* to show when several lanes are uncovered is a separate
    question and is settled by `_MOST_ACTIONABLE`, which decides nothing. The
    verdict is already fixed by the paragraph above; this only picks the word.
    `lanes` carries the rest, so nothing is dropped in silence.
    """
    # Distinct names throughout: `row` and `rows` are both bound further down
    # and reusing either makes mypy infer the wrong type — the same trap
    # `cli.py`'s parity branch already documents.
    ordered: dict[str, list[Reporting]] = {}
    for lane in reporting:
        ordered.setdefault(lane.capability, []).append(lane)

    by_capability: dict[str, Reporting] = {}
    lanes_by_capability: dict[str, tuple[tuple[str, str], ...]] = {}
    for capability, lanes in ordered.items():
        uncovered = [lane for lane in lanes if not _covers(lane.state)]
        by_capability[capability] = (
            min(uncovered, key=lambda lane: _actionability(lane.state))
            if uncovered
            else lanes[0]
        )
        if len(lanes) > 1:
            lanes_by_capability[capability] = tuple(
                (lane.job, lane.state) for lane in lanes
            )

    out: list[StageCoverage] = []
    for stage in ALL_STAGES:
        if stage not in enabled_capabilities:
            # A job exists for a capability this repository has not enabled.
            # The inverse of `no_job`, and the more dangerous one: the lane
            # runs, its upload is refused at the door, and the quality lanes
            # write that upload with `|| true`, so the build stays green while
            # the lake stays empty. B-062 is what this looked like from the
            # outside -- five of TheHub's grants deleted, four lanes green,
            # their findings discarded -- and `not_enabled` reported all of
            # it as "not a fault", because the check walked the enabled set
            # and this is the one direction that set cannot see.
            if stage in by_capability and stage not in NON_SCANNING:
                out.append(StageCoverage(stage, enabled=False, state="job_not_enabled"))
                continue
            out.append(StageCoverage(stage, enabled=False, state="not_enabled"))
            continue

        if stage in NON_SCANNING:
            # Gate-driven: exempt from needing a scan run, not from needing a
            # lane. Anything else here is driven from inside Mykronos and
            # needs neither (B-061).
            runs_it = GATE_JOBS.get(stage)
            if runs_it is not None and not (runs_it & job_names):
                out.append(StageCoverage(stage, enabled=True, state="no_job"))
                continue
            out.append(StageCoverage(stage, enabled=True, state="event_driven"))
            continue

        row = by_capability.get(stage)
        if row is None:
            # Enabled, and nothing in the pipeline produces it. The gap that
            # is hardest to see otherwise: the repository believes it is
            # covered and no job disagrees, because no job exists.
            out.append(StageCoverage(stage, enabled=True, state="no_job"))
            continue

        out.append(
            StageCoverage(
                stage,
                enabled=True,
                state=row.state,
                lanes=lanes_by_capability.get(stage, ()),
            )
        )

    return out


#: Whether a capability state constitutes *coverage* — findings from that
#: capability actually reaching the lake. Never rendered: it is a judgement
#: about a state, not a state a repository is in.
#:
#: Read in two places, and they are the same question asked across two axes.
#: `Parity.regressed` asks it across CI systems — is the new side worse than
#: the old one. `coverage()` asks it across the lanes of one capability — is
#: any lane serving this capability not covered (B-380). Both need one
#: definition of "covered" and neither may invent a second.
#:
#: Two tiers, not a gradient. This was a seven-step ranking, and the ordering
#: inside the uncovered tier was invented rather than observed: `not_run` sat
#: ABOVE `silent`, so a capability going from "ran and reported nothing" to
#: "has never run at all" was announced as an improvement. That is what
#: `mykronos parity ToddGBenson/keel` said on 2026-08-29 — "No capability is
#: worse under Actions" while every Actions lane read `not_run`, i.e. the new
#: system had never executed once. A ranking that produces that sentence is
#: not measuring what the gate exists to measure.
#:
#: There is no honest order within "not covered". `no_job`, `not_run`,
#: `never_reported` and `silent` are four ways of describing the same
#: outcome — nothing from this capability is in the lake — and they differ in
#: what a human should go look at, not in how covered the repository is. So
#: moving between them is never an improvement and never a regression.
#:
#: `event_driven` counts as covered: Aegis, Oracle and Patchwork are fed by
#: webhooks and have no lane to run, so treating them as a gap would report a
#: migration as having lost something it never had.
#:
#: `not_enabled` counts as NOT covered, which is a change. It used to rank
#: alongside `reporting` on the grounds that a capability nobody asked for is
#: not a gap — true when both sides agree, and that case still compares as
#: "same". But it also meant a capability that was reporting under Concourse
#: and merely never got enabled in the Actions ledger passed the gate in
#: silence, which is exactly the migration mistake this is here to catch.
_COVERED: frozenset[str] = frozenset({"reporting", "event_driven"})


def _covers(state: str) -> bool:
    return state in _COVERED


#: Which of several *equally uncovered* lanes gives a capability its label.
#:
#: Not a coverage ranking, and it must never become one — that mistake is
#: recorded above `_COVERED`: an ordering inside the uncovered tier once let
#: "ran and reported nothing" -> "has never run at all" be announced as an
#: improvement. This decides nothing. By the time it is consulted the verdict
#: is already fixed: `coverage()` has established that some lane is uncovered
#: and therefore that the capability is, and all that is left is which of the
#: siblings' words to print above `lanes`.
#:
#: Ordered by what a person does next, most to least. `silent` and
#: `never_reported` mean a job ran and its results are not in the lake, which
#: is the failure this whole cross-check exists for. `failed` is a red build to
#: go and read. `not_run` is a lane that has not come round yet. `paused` is
#: last because somebody switched it off on purpose, and it is the one state
#: here that may be nothing to act on at all.
#:
#: TheHub's `dast` is why it is not simply "the first uncovered lane": its four
#: lanes are `functional-dast=paused, dast-demo=reporting, dast-prod=reporting,
#: dast-staging=failed`, and taking the first would headline the one that was
#: switched off deliberately over the one that is failing today.
#:
#: An unrecognised state sorts last rather than raising. A new lane state is a
#: reason to extend this list, never a reason for the CI panel to 500.
_MOST_ACTIONABLE: tuple[str, ...] = (
    "silent",
    "never_reported",
    "failed",
    "not_run",
    "paused",
)


def _actionability(state: str) -> int:
    return _MOST_ACTIONABLE.index(state) if state in _MOST_ACTIONABLE else len(
        _MOST_ACTIONABLE
    )


#: Capabilities whose two lanes do not reach the same thing, and the sentence
#: that says why (B-048).
#:
#: `parity` compares whether each capability *reports*. It has never compared
#: what each one *reaches*, and for most capabilities those are the same
#: question: `sast` reads the same tree wherever it runs. For these two they
#: are not.
#:
#: The Concourse `dast` lane targets `((demo-host))`, an address on this LAN,
#: against a deployment that outlives the build. The Actions lane targets
#: `localhost` inside a GitHub-hosted runner, against an ephemeral stack built
#: and seeded per run. A hosted runner cannot reach an RFC1918 address on this
#: network, so the Actions lane is not a better version of the Concourse one --
#: it is the only one that can run without the LAN, and the Concourse one is
#: the only one that can scan anything actually deployed on it, including
#: TheHub's own production.
#:
#: Read literally, `parity` said Actions was `improved` on both and therefore
#: that Concourse could be retired. Doing that would not have consolidated a
#: duplicate; it would have permanently removed the only path to scanning an
#: internal deployment. The honest verdict for a capability whose two lanes
#: reach different things is not "improved" -- it is that they are not
#: comparable, and a person has to decide.
NOT_COMPARABLE: dict[str, str] = {
    "dast": (
        "the two lanes reach different targets: Concourse scans a deployment on "
        "this network, Actions an ephemeral stack inside a hosted runner"
    ),
    "functional": (
        "the two lanes exercise different environments: Concourse a deployment on "
        "this network, Actions an ephemeral stack inside a hosted runner"
    ),
}


@dataclass(frozen=True)
class Parity:
    """One capability, as each CI system reports it (spec 32 §9).

    The check that authorises step 8. Retiring a pipeline because its
    replacement looks green is how a lane goes quiet without anybody
    noticing — spec 15 §4a.1's first day of existence found a lane that had
    been green on every build and had never reported once.
    """

    capability: str
    before: str
    after: str

    @property
    def comparable(self) -> bool:
        """Do the two lanes reach the same thing at all (B-048)."""
        return self.capability not in NOT_COMPARABLE

    @property
    def why_not_comparable(self) -> str:
        return NOT_COMPARABLE.get(self.capability, "")

    @property
    def regressed(self) -> bool:
        """Did this capability lose coverage in the move."""
        return _covers(self.before) and not _covers(self.after)

    @property
    def verdict(self) -> str:
        if self.regressed:
            return "REGRESSED"
        if self.before == self.after:
            return "same"
        if not self.comparable:
            # Before "improved", deliberately. This is the case where the
            # cheerful answer is the dangerous one: both lanes report, the
            # new one reports more, and the conclusion a reader draws is
            # "retire the old pipeline" (B-048).
            return "not comparable"
        if _covers(self.after) and not _covers(self.before):
            return "improved"
        # Different states, same tier. Named rather than folded into "same",
        # because which uncovered state a capability is in is worth reading
        # even though it does not change the answer — and because calling it
        # "improved" is how a repository with no coverage at all came to be
        # reported as ready to have its pipeline deleted.
        return "no better"


def compare(before: list[StageCoverage], after: list[StageCoverage]) -> list[Parity]:
    """Line one CI system's coverage up against the other's (spec 32 §9).

    Deliberately compares *states* rather than counting green lanes. "Both
    systems report eleven capabilities" is satisfied by two systems reporting
    eleven different ones; what has to hold before a pipeline is destroyed is
    that no individual capability got worse.

    A capability missing from one side is treated as `no_job` there — the
    worst state — because a capability the new system does not know about is
    exactly the gap this is looking for, not an absence to skip over.
    """
    before_by = {row.stage: row.state for row in before}
    after_by = {row.stage: row.state for row in after}
    return [
        Parity(
            capability=stage,
            before=before_by.get(stage, "no_job"),
            after=after_by.get(stage, "no_job"),
        )
        for stage in sorted(set(before_by) | set(after_by))
    ]


#: Terminal statuses that mean the lane ran and produced no successful build.
#:
#: `aborted` is here with the two failures. A cancelled run is not a fault,
#: but it is equally not a successful build, and the question this feeds is
#: "does this lane have something to report from" rather than "whose fault is
#: it". Calling a cancelled run "never ran" is the same false statement.
#:
#: In-progress statuses (`started`, `pending`) are deliberately absent: a lane
#: mid-flight has not failed, and `ActionsClient` never sees them anyway
#: because it reads completed runs only.
_DID_NOT_SUCCEED: frozenset[str] = frozenset({"failed", "errored", "aborted"})


#: The capability an UNKNOWN row is filed under.
#:
#: Not a stage, and deliberately absent from `ALL_STAGES`: `coverage()` walks
#: that tuple, so an unmapped job cannot masquerade as a capability nor
#: displace a real one. It travels as a `Reporting` row instead, which is the
#: surface the CI page renders job-by-job.
UNMAPPED_CAPABILITY = "unknown"


#: Jobs that are unmapped ON PURPOSE, and why each one is (B-59330).
#:
#: THE DEFECT THIS EXISTS FOR. `reconcile()` used to `continue` on any job
#: absent from `CAPABILITY_BY_JOB`, so the cross-check was an allowlist with a
#: silent default: a job was unmonitored until somebody remembered to map it,
#: and nothing anywhere said a job had been skipped. On 2026-09-07 five keel
#: jobs errored against a sealed Vault and stayed red for three days with
#: nothing escalating. The detector would have fired -- `_DID_NOT_SUCCEED`
#: covers `errored` exactly -- and it was simply not pointed at those jobs.
#:
#: Mapping keel fixes that occurrence. This fixes the class: anything not
#: named here is reported as `unknown` rather than dropped, so the cost of
#: forgetting is a visible row instead of a lane nobody is watching.
#:
#: AN ENTRY IS A CLAIM, NOT A PARDON, and `test_ci_job_audit.py` holds it to
#: two properties rather than trusting the sentence: every job in every
#: pipeline is mapped or named here, and no job named here invokes
#: `python -m mykronos.upload`. The second is the one that matters over time.
#: `unit` sat on the old hard-coded skip list until D-046 gave it a ScanRun,
#: and nothing noticed it had started reporting -- an acknowledgement that
#: silently stops being true is how the allowlist failed in the first place.
#:
#: KEEL'S 23 STUBS ARE DELIBERATELY NOT HERE, and that is a decision rather
#: than an omission. Measured 2026-09-17: each is 158-437 bytes of pipeline
#: with no scanner invocation at all, and they include `sca`, `container-scan`,
#: `iac`, `secrets`, `ai-guardrails`, `suppression-audit`,
#: `platform-integrity` and three `compliance-*` lanes. Three reasons, and the
#: first is the one that decides it:
#:
#:   1. An entry here CLAIMS a job correctly produces nothing. That is true of
#:      `build`. It is not true of a job called `container-scan` that scans no
#:      container: the name is a statement that something is being checked, and
#:      writing down that it correctly checks nothing is the false green this
#:      module exists to remove. `unknown` is the honest answer - nothing is
#:      checking these - and it is also the actionable one.
#:   2. Four of them (`sast`, `secrets`, `iac`, `lint`) cannot be acknowledged
#:      at all, because this table is keyed on the job name alone and those
#:      names are mapped to real capabilities used by three working pipelines.
#:      See `COLLIDING_KEEL_STUBS`.
#:   3. Nothing here could check such an entry. keel's pipeline lives in keel's
#:      own repo, so `test_ci_job_audit.py` - which reads
#:      `deploy/concourse/pipelines/*.yml` - cannot see those job names to
#:      confirm they still exist or still upload nothing. An acknowledgement it
#:      cannot falsify is exactly the unrecheckable claim that test exists to
#:      prevent, and `unit` is the standing example of what one costs.
#:
#: So these record what each job does TODAY. A job here that starts uploading
#: should turn this file red, and the fix is a line in `CAPABILITY_BY_JOB`.
_UNMAPPED_DECLARATIONS: tuple[tuple[tuple[str, ...], str, str], ...] = (
    # Build and delivery. Nothing scans; there is no lake record to be absent.
    ((MYKRONOS, THEHUB), "build", "builds the image, runs no scanner and uploads nothing"),
    (
        (MYKRONOS,),
        "publish-backend",
        "pushes the backend image to the registry, produces no findings",
    ),
    (
        (MYKRONOS,),
        "publish-frontend",
        "pushes the frontend image to the registry, produces no findings",
    ),
    ((MYKRONOS,), "promote", "retags an image that is already built, runs no scanner"),
    # thehub's `deploy-demo` was removed under #59100 and is BACK, because the
    # premise that removed it expired before the change landed.
    #
    # #59100 retired Path B on the evidence that `deploy-demo` was dead: builds
    # #86, #87 and #88 each burned ~26 minutes and failed. That was true when it
    # was written. The cause was a CRLF acknowledgement mismatch fixed by #388 on
    # 2026-09-15, which did not reach the SERVER until `set-pipeline` ran for the
    # first time at 13:37 on 2026-09-17. `deploy-demo` #89 then SUCCEEDED at
    # 15:22 and #90 at 19:48, and `dast-demo` came back with them after seven
    # days dark.
    #
    # So the chain was never dead -- it was blocked by a fix that was merged and
    # not applied. A premise measured once, true then, and never re-derived is
    # exactly what this module exists to catch, and it happened here.
    #
    # It is ACKNOWLEDGED rather than mapped: it deploys, it uploads no finding,
    # and putting a deploy job in CAPABILITY_BY_JOB would credit it with a
    # security capability it does not have.
    #
    # `deploy-prod` WAS THE SECOND ENTRY HERE AND WENT WITH ITS JOB
    # (#59990/#59999/#60063, operator decision 2026-09-18). It is deleted in the
    # same change that deletes the job, and deliberately not left behind as a
    # harmless-looking line: `test_every_acknowledgement_names_a_job_that_exists`
    # would go red, and more to the point an acknowledgement that outlives its
    # job starts excusing a FUTURE job that reuses the name. The excuse here --
    # "publishes a deploy pointer to MinIO, runs no scanner" -- was a statement
    # about a specific job's plan, not about the word `deploy-prod`.
    ((THEHUB,), "deploy-demo", "publishes a deploy pointer to MinIO, runs no scanner"),
    (
        (PERSONAL_SOC,),
        "package",
        "bundles the skills release and publishes it to MinIO, scans nothing",
    ),
    # The pipeline's own upkeep.
    (
        (MYKRONOS, PERSONAL_SOC, THEHUB),
        "set-pipeline",
        "re-applies this pipeline's own configuration (#454), scans nothing",
    ),
    (
        (MYKRONOS,),
        "pin-check",
        "asserts the pinned runner still has the modules the lanes call; it "
        "fails the build rather than filing a finding",
    ),
    # Driven from inside Mykronos, and argued at length above
    # `CAPABILITY_BY_JOB` and beside `NON_SCANNING`/`GATE_JOBS`.
    (
        (MYKRONOS, THEHUB),
        "insider",
        "Aegis assesses a pull request and posts to /api/ingest/aegis; these "
        "pipelines run on pushes, where there is correctly no assessment",
    ),
    (
        (PERSONAL_SOC,),
        "oracle",
        "the Oracle gate asks for a decision and produces no scan run (B-061)",
    ),
    (
        (MYKRONOS, THEHUB),
        "oracle-gate",
        "the Oracle gate asks for a decision and produces no scan run (B-061)",
    ),
    (
        (MYKRONOS, THEHUB),
        "remediate",
        "Patchwork opens fix pull requests; `NON_SCANNING` already exempts it",
    ),
    # Gates and alerters. Each fails its build or posts to Slack on what it
    # finds; none of them writes to the lake, which is why a capability would
    # be the wrong thing to expect of them.
    (
        (PERSONAL_SOC,),
        "guard",
        "personal-soc's no-personal-data gate; it fails the build, it does not file",
    ),
    (
        (PERSONAL_SOC,),
        "skill-integrity",
        "checks SKILL.md references before delivery; fails the build, files nothing",
    ),
    (
        (PERSONAL_SOC,),
        "doc-drift",
        "compares the docs against the tree; fails the build, files nothing",
    ),
    (
        (PERSONAL_SOC,),
        "external-exposure",
        "reads the Shodan view of the household IP and alerts; uploads nothing",
    ),
    (
        (PERSONAL_SOC,),
        "netassess-ingest",
        "verifies and diffs the network scan published to MinIO and alerts on "
        "the difference; it writes no scan run of its own",
    ),
    (
        (PERSONAL_SOC,),
        "netassess-freshness",
        "ages the newest network scan and alerts when it is stale; files nothing",
    ),
    (
        (PERSONAL_SOC,),
        "breach-check",
        "queries HIBP for the monitored addresses and alerts; uploads nothing",
    ),
)


#: `(pipeline, job)` -> why that job produces nothing. Derived; declare in
#: `_UNMAPPED_DECLARATIONS` above.
#:
#: Scoped alongside `CAPABILITY_BY_JOB` (B-59988), and for the same reason
#: rather than for symmetry. An unscoped acknowledgement is a claim about a
#: NAME, and `build` on keel is not the job this repository looked at when it
#: wrote "builds the image, runs no scanner": keel's is a 158-byte stub that
#: nothing here can read. Keeping one global entry would have gone on excusing
#: a job on a pipeline nobody checked, which is the allowlist-with-a-silent-
#: default shape one level along.
ACKNOWLEDGED_UNMAPPED_JOBS: dict[tuple[str, str], str] = {
    (pipeline, job): reason
    for pipelines, job, reason in _UNMAPPED_DECLARATIONS
    for pipeline in pipelines
}


def reconcile(
    pipeline: str, jobs: list[JobStatus], last_scan_at: dict[str, datetime]
) -> list[Reporting]:
    """Line each scanning job up against the newest scan run it should have
    produced (spec 15 §4a).

    `pipeline` is which pipeline these jobs came from - `pipeline_name_for()`
    for a Concourse repository, `ACTIONS` for a GitHub Actions one. It is the
    first half of both lookups below and is required rather than defaulted,
    because a default would be a job name meaning the same thing everywhere,
    which is the defect B-59988 removed.

    A job in `CAPABILITY_BY_JOB` for THIS pipeline is checked against its
    capability. A job in `ACKNOWLEDGED_UNMAPPED_JOBS` for this pipeline is
    skipped, because somebody has written down that it produces nothing.
    **Anything else is reported as `unknown`** — it is not skipped, and that is
    the point (B-59330).

    Scoping deliberately produces MORE `unknown` rows, and they are not noise.
    keel's stub jobs called `sast`, `secrets`, `iac` and `lint` used to inherit
    the meaning of the real jobs of those names on other pipelines, and were
    credited with uploads they had nothing to do with. They now match nothing
    and say so: a job named after a control, running no control, reported as
    unrecognised rather than silently counted as coverage.

    The old shape was an allowlist with a silent default: `continue` on
    anything unmapped, and no record that a job had been passed over. That
    makes every job anybody ever adds to any pipeline unmonitored until
    somebody remembers this table exists, and keeps the omission invisible
    while it lasts. Five keel jobs errored on a sealed Vault on 2026-09-07 and
    stayed red for three days behind exactly that silence.

    `unknown` is not a judgement about the lane. It says the platform cannot
    say whether the lane is healthy, which is a different and more honest
    thing than saying nothing at all.

    A job may produce several capabilities: demo-and-dast runs the functional
    suite through ZAP's proxy and then scans, so one build uploads both
    `functional` and `dast`. Crediting it to only one left the other reading
    "no_job" forever - enabled, produced by a real lane, and reported as a
    permanent gap.
    """
    seen: set[str] = set()
    out: list[Reporting] = []
    for job in jobs:
        if job.name in seen:
            continue
        # Marked before the mapping is consulted, not after. The old order
        # only remembered jobs it had a capability for, so a pipeline listing
        # an unmapped job twice would now report it twice.
        seen.add(job.name)
        capabilities = CAPABILITY_BY_JOB.get((pipeline, job.name))
        if capabilities is None:
            if (pipeline, job.name) in ACKNOWLEDGED_UNMAPPED_JOBS:
                continue
            out.append(
                Reporting(
                    job=job.name,
                    capability=UNMAPPED_CAPABILITY,
                    # Both deliberately unset. There is no capability to have
                    # scanned, so a timestamp here would invite a comparison
                    # that has no meaning; `state` returns `unknown` before it
                    # reaches them.
                    built_at=None,
                    scanned_at=None,
                    unmapped=True,
                )
            )
            continue
        if isinstance(capabilities, str):
            capabilities = (capabilities,)
        for capability in capabilities:
            out.append(
                Reporting(
                    job=job.name,
                    capability=capability,
                    built_at=job.finished_at if job.status == "succeeded" else None,
                    scanned_at=last_scan_at.get(capability),
                    last_build_failed=job.status in _DID_NOT_SUCCEED,
                    paused=job.paused,
                )
            )
    return out
