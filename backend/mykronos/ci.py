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


#: Which capability a job's results should arrive under.
#:
#: A heuristic, and named as one. Job names are chosen by whoever writes the
#: pipeline and nothing enforces this; a job absent from here is simply not
#: cross-checked, which is the safe direction to be wrong in. `dependencies`
#: uploads as `atlas` and `cloud-posture` as `cloud`, both of which have been
#: mistaken for coverage gaps.
#:
#: **`insider` is deliberately absent.** Aegis assesses a pull request, not a
#: commit, and these pipelines trigger on pushes to main - where there is
#: usually no pull request and therefore correctly no assessment. The job
#: succeeds having recorded nothing, on purpose: submitting an assessment
#: with no reviews, no base ref and no description would score 0/100 for
#: exactly the case Aegis exists to notice. Cross-checking it reported every
#: green insider job as a silent failure, which was this check being wrong
#: about what the job is for.
def jobs_for_capability(capability: str) -> set[str]:
    """Which Concourse job(s) plausibly produce this capability.

    The reverse of `CAPABILITY_BY_JOB`, and a heuristic in the same spirit and
    for the same reason as the mapping it derives from: a pipeline that names
    its job differently is simply not reached, which is the safe direction to
    be wrong in — a 404 from Concourse, not a crash.

    Lives here rather than in a caller because two of them now need it: the
    "scan now" button (spec 17 §2.5) and fix verification (spec 25 §1). A
    second private copy would be a second thing to update when a job is
    renamed, and the first one to be forgotten.
    """
    return _JOBS_BY_CAPABILITY.get(capability, {capability})


CAPABILITY_BY_JOB: dict[str, str | tuple[str, ...]] = {
    "sast": "sast",
    "secrets": "secrets",
    "containers": "containers",
    "dast": "dast",
    "iac": "iac",
    "dependencies": "atlas",
    "atlas": "atlas",
    "cloud-posture": "cloud",
    "cloud": "cloud",
    # Quality stages (D-046). They report a run and no findings, so the
    # cross-check is the only thing that can tell whether they reported at
    # all - there is no finding count to notice the absence of.
    "unit": "unit",
    "qa": "qa",
    "qa-spec-links": "qa",
    "ai": "ai",
    "ai-checks": "ai",
    "functional": "functional",
    "demo-and-dast": ("functional", "dast"),
    # PS-1. These four ran green on every build and reported nothing, so the
    # cross-check had nothing to compare and said nothing about them. They
    # report now, and a job that reports has to be checked or the reporting
    # buys only half of what it should.
    #
    # `lint-and-types`, `frontend` and `api-inventory` all land under `qa`
    # alongside `qa-spec-links`: the capability has one registered adapter
    # (`adapters/registry.py`), quality stages carry no findings (D-046), and
    # so several runs per commit is a richer answer rather than a collision.
    "lint-and-types": "qa",
    "frontend": "qa",
    "api-inventory": "qa",
    "prompt-evals": "ai",
    # thehub's dast lanes, which were never named here. `functional-dast`
    # runs the Playwright suite through ZAP's proxy and then scans - one
    # build, two uploads, each answering for itself (spec 15 §4a.1).
    "dast-demo": "dast",
    "dast-prod": "dast",
    "functional-dast": ("functional", "dast"),
    "ai-models": "ai",
}

#: How far a successful build may lead its capability's newest scan run before
#: the results count as missing. Generous on purpose: a job's build finishes
#: after its upload, but compaction is asynchronous and a run started before a
#: deploy can land minutes later. Anything under an hour is not evidence.
REPORTING_GRACE_SECONDS = 3600


_JOBS_BY_CAPABILITY: dict[str, set[str]] = {}
for _job_name, _caps in CAPABILITY_BY_JOB.items():
    for _cap in _caps if isinstance(_caps, tuple) else (_caps,):
        _JOBS_BY_CAPABILITY.setdefault(_cap, set()).add(_job_name)


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

    @property
    def state(self) -> str:
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
        return stem if stem in CAPABILITY_BY_JOB else None

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

    @property
    def problem(self) -> bool:
        return self.state in {"silent", "never_reported", "no_job"}


#: Capabilities that never produce a ScanRun from a pipeline lane: Aegis is
#: fed by webhooks as reviews happen, Oracle writes decisions, Patchwork opens
#: fix pull requests. The coverage cross-check compares pipeline jobs against
#: scan runs, and these have neither side of that comparison - reporting them
#: as "no_job" flagged working capabilities as permanent gaps.
NON_SCANNING: frozenset[str] = frozenset({"aegis", "oracle", "patchwork"})


def coverage(enabled_capabilities: set[str], reporting: list[Reporting]) -> list[StageCoverage]:
    """Every stage against what this repository actually has (PIP-6)."""
    by_capability = {row.capability: row for row in reporting}

    out: list[StageCoverage] = []
    for stage in ALL_STAGES:
        if stage not in enabled_capabilities:
            out.append(StageCoverage(stage, enabled=False, state="not_enabled"))
            continue

        if stage in NON_SCANNING:
            out.append(StageCoverage(stage, enabled=True, state="event_driven"))
            continue

        row = by_capability.get(stage)
        if row is None:
            # Enabled, and nothing in the pipeline produces it. The gap that
            # is hardest to see otherwise: the repository believes it is
            # covered and no job disagrees, because no job exists.
            out.append(StageCoverage(stage, enabled=True, state="no_job"))
            continue

        out.append(StageCoverage(stage, enabled=True, state=row.state))

    return out


def reconcile(jobs: list[JobStatus], last_scan_at: dict[str, datetime]) -> list[Reporting]:
    """Line each scanning job up against the newest scan run it should have
    produced (spec 15 §4a).

    Only jobs in `CAPABILITY_BY_JOB` are checked. `build` and
    `publish-backend` produce no findings and their absence from the lake is
    not a fault.

    A job may produce several capabilities: demo-and-dast runs the functional
    suite through ZAP's proxy and then scans, so one build uploads both
    `functional` and `dast`. Crediting it to only one left the other reading
    "no_job" forever - enabled, produced by a real lane, and reported as a
    permanent gap.
    """
    seen: set[str] = set()
    out: list[Reporting] = []
    for job in jobs:
        capabilities = CAPABILITY_BY_JOB.get(job.name)
        if capabilities is None or job.name in seen:
            continue
        seen.add(job.name)
        if isinstance(capabilities, str):
            capabilities = (capabilities,)
        for capability in capabilities:
            out.append(
                Reporting(
                    job=job.name,
                    capability=capability,
                    built_at=job.finished_at if job.status == "succeeded" else None,
                    scanned_at=last_scan_at.get(capability),
                )
            )
    return out
