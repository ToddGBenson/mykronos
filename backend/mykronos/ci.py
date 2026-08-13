"""Where a repository is built, and how to get there (spec 15 §4a).

The traffic between Mykronos and Concourse has only ever run one way:
pipelines upload findings, and the lake cannot tell which CI produced any of
them. That is deliberate for analysis — spec 15 §4 — and useless for
navigation. Somebody looking at a repository's findings has no way to reach
the pipeline that produced them without already knowing which of three
pipelines to open.

This closes that, and nothing more. Nothing read here is an input to a
finding, a score or a decision; it is a link and a status next to it.

Three properties worth stating, because each is a way this could go wrong:

*Which pipeline covers a repository is derived.* The pipeline is the
repository name, lowercased, checked against the live list. No configured
mapping to go stale, and a repository Concourse does not cover reports
exactly that rather than a dead link.

*It reads the job list, never build logs.* Logs carry scanner output and,
until CNC-2 lands, resolved `((var))` values.

*It fails soft, always.* Concourse restarting must not affect a page about
findings. Every failure resolves to "unavailable, and here is why", never an
exception that reaches a request handler.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime

import httpx2

from mykronos.logsafe import scrub

logger = logging.getLogger(__name__)

#: Short, because this runs inside a dashboard request. A Concourse that has
#: not answered in three seconds is reported as unavailable, which is both
#: true and better than a page that hangs.
TIMEOUT = 3.0


def pipeline_name_for(repo_full_name: str) -> str:
    """`ToddGBenson/TheHub` -> `thehub` (spec 15 §4a)."""
    return repo_full_name.rsplit("/", 1)[-1].lower()


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
