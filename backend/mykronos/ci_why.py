"""Why a CI job failed, not only that it did (TheHub #60913).

`GET /api/dashboard/repos/{id}/ci` named its failing jobs and stopped there,
so finding out why meant leaving for Concourse or GitHub. For a Demo-and-DAST
failure the answer was a GitHub check annotation ("spider did not reach 100%
within 600s") that Mykronos could have shown. This reads that answer: the
failed step, its exit code if the CI says, the error the job raised, and a
link to the build.

**What is read, and what is not.** `ci.py` and spec 15 §4a say the status
read never reads build logs, because logs carry scanner output and resolved
`((var))` values, and secret redaction is not enabled in this stack's
Concourse. This module keeps the property for everything it *returns*:

- *GitHub Actions*: the run's job list (names, conclusions, step names) and
  the failed job's check-run annotations. An annotation is a message the job
  chose to raise (`::error::`, a problem matcher, the runner's "Process
  completed with exit code N"), not its log. No log is downloaded.
- *Concourse*: the build plan (step names by id) and the build's event
  stream, read only to find which step finished non-zero, its exit status,
  and Concourse's own `error` events. Log events are skipped without their
  text being looked at: no build log line is ever returned, logged or
  cached, `::error` lines included (operator decision on #1037). Showing
  `::error` lines may be revisited once Concourse redacts secrets.

Everything returned passes through `clean`: ANSI escapes stripped, values
shaped like credentials masked, then `logsafe.scrub` for control characters
and length.

**Bounded cost.** A completed build's reason does not change, so it is
cached by build id (`WhyCache`, successes only). Each read has a short
timeout, the Concourse stream stops at a byte and a line cap, and at most
`MAX_EXPLAINED` failing jobs are looked up per request, concurrently.

**Degrades, never raises.** Every failure becomes a `FailureWhy` with
`unavailable` saying why, which the page renders as "reason unavailable: ...".
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from collections import OrderedDict
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, replace

import httpx2

from mykronos.ci import JobStatus
from mykronos.github.client import CheckAnnotation, GitHubClient, WorkflowJob
from mykronos.logsafe import scrub

logger = logging.getLogger(__name__)

#: Failing jobs explained per request. A page with more red than this has a
#: bigger problem than any one reason, and each lookup costs a round trip.
MAX_EXPLAINED = 8
#: Messages kept per failure, and the length of each.
MAX_MESSAGES = 3
MAX_MESSAGE_LENGTH = 300
#: Concourse: per-request timeout, whole-read deadline, and the caps on the
#: event stream. A scanner lane's stream runs to megabytes; the failure is
#: usually near its end, and a reason not found inside these caps is
#: reported as not found rather than chased.
CONCOURSE_TIMEOUT = 3.0
CONCOURSE_DEADLINE = 5.0
MAX_EVENT_BYTES = 2_000_000
MAX_EVENT_LINES = 20_000
#: GitHub: the whole lookup for one run (two requests), on top of each
#: request's own `WHY_TIMEOUT`.
GITHUB_DEADLINE = 8.0

_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")

#: Shapes a credential takes in this estate's output. Masked, not dropped, so
#: a reader sees that something was there.
_SECRET_SHAPES = (
    re.compile(r"\b(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{16,}"),
    re.compile(r"\bmka_[A-Za-z0-9_\-]{8,}"),
    re.compile(r"\bhvs\.[A-Za-z0-9_\-]{16,}"),
    re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{8,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{8,}"),
    re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),
    re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=\-]{8,}"),
    re.compile(r"(?i)://[^/\s:@]+:[^/\s@]+@"),
    re.compile(
        r"(?i)\b([A-Za-z0-9_]*(?:token|secret|password|passwd|api[_-]?key)[A-Za-z0-9_]*)"
        r"(\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|\S+)"
    ),
)

_EXIT_CODE = re.compile(r"exit code (\d+)", re.IGNORECASE)
#: The runner's own closing annotation. Its exit code is kept; as a message
#: it repeats what `exit_code` already says.
_RUNNER_EXIT = re.compile(r"^Process completed with exit code \d+\.?$", re.IGNORECASE)


def _mask(match: re.Match[str]) -> str:
    if match.re.groups >= 3:
        return f"{match.group(1)}{match.group(2)}[redacted]"
    if match.re.groups == 1:
        return f"{match.group(1)} [redacted]"
    if match.group(0).startswith("://"):
        return "://[redacted]@"
    return "[redacted]"


def clean(text: str) -> str:
    """One line of CI output made fit to show: no escapes, no credential
    shapes, no control characters, bounded."""
    text = _ANSI.sub("", text).strip()
    for shape in _SECRET_SHAPES:
        text = shape.sub(_mask, text)
    return scrub(text, max_length=MAX_MESSAGE_LENGTH)


@dataclass(frozen=True)
class FailureWhy:
    """Why one failing job failed, as far as its CI says."""

    source: str  # "concourse" | "github"
    #: The step or task that failed: a Concourse step name, or
    #: "job: step" for Actions.
    step: str | None = None
    exit_code: int | None = None
    #: Concourse's own `error` events, or the failed job's GitHub check
    #: annotations, cleaned. Never build log text.
    messages: tuple[str, ...] = ()
    url: str | None = None
    #: What the reader should know about what is shown, e.g. that the step
    #: raised no error line and its log is not read.
    note: str | None = None
    #: Set when nothing could be read; the page prefixes "reason unavailable".
    unavailable: str | None = None


class WhyCache:
    """Reasons by build, for completed builds whose reason cannot change.

    Successes only, as `ci.StatusCache` does and for its reason: a failed
    lookup is what somebody reloads the page to retry.
    """

    def __init__(self, limit: int = 512) -> None:
        self.limit = limit
        self._entries: OrderedDict[tuple[str, str, str], FailureWhy] = OrderedDict()

    def get(self, key: tuple[str, str, str]) -> FailureWhy | None:
        value = self._entries.get(key)
        if value is not None:
            self._entries.move_to_end(key)
        return value

    def put(self, key: tuple[str, str, str], value: FailureWhy) -> None:
        if value.unavailable is not None:
            return
        self._entries[key] = value
        self._entries.move_to_end(key)
        while len(self._entries) > self.limit:
            self._entries.popitem(last=False)


# --- Concourse ----------------------------------------------------------

_STEP_KINDS = ("task", "get", "put", "check", "set_pipeline", "load_var", "run")


def step_names(plan: object) -> dict[str, str]:
    """Plan id -> step name, for every named step anywhere in a build plan."""
    names: dict[str, str] = {}

    def walk(node: object) -> None:
        if isinstance(node, list):
            for item in node:
                walk(item)
            return
        if not isinstance(node, dict):
            return
        plan_id = node.get("id")
        if isinstance(plan_id, str):
            for kind in _STEP_KINDS:
                body = node.get(kind)
                if isinstance(body, dict) and isinstance(body.get("name"), str):
                    names.setdefault(plan_id, str(body["name"]))
                    break
        for value in node.values():
            walk(value)

    walk(plan)
    return names


def _step_label(origin: str | None, names: dict[str, str]) -> str | None:
    if not origin:
        return None
    if origin in names:
        return names[origin]
    head, _, rest = origin.partition("/")
    if head in names:
        return f"{names[head]} ({rest})" if rest else names[head]
    return None


def why_from_events(
    names: dict[str, str],
    lines: Iterable[str],
    *,
    url: str | None,
    max_bytes: int = MAX_EVENT_BYTES,
    max_lines: int = MAX_EVENT_LINES,
) -> FailureWhy:
    """Read a Concourse build's event stream (SSE lines) for its failure.

    Keeps the first step to finish non-zero, its exit status, and
    Concourse's own `error` events. `log` events are skipped without their
    payload being read: no build log text is returned, `::error` lines
    included (operator decision on #1037, until Concourse redacts secrets).
    """
    failed_origin: str | None = None
    exit_code: int | None = None
    platform_errors: list[tuple[str | None, str]] = []
    read_bytes = 0
    read_lines = 0
    capped = False

    for raw_line in lines:
        read_lines += 1
        read_bytes += len(raw_line)
        if read_lines > max_lines or read_bytes > max_bytes:
            capped = True
            break
        if raw_line.startswith("event:") and raw_line[6:].strip() == "end":
            break
        if not raw_line.startswith("data:"):
            continue
        try:
            event = json.loads(raw_line[5:])
        except ValueError:
            continue
        if not isinstance(event, dict):
            continue
        kind = event.get("event")
        data = event.get("data")
        if not isinstance(data, dict):
            continue
        origin_raw = data.get("origin")
        origin = (
            str(origin_raw["id"])
            if isinstance(origin_raw, dict) and isinstance(origin_raw.get("id"), str)
            else None
        )

        if kind == "log":
            # Build output: counted against the caps above, never read.
            continue
        if kind in ("finish-task", "finish-get", "finish-put"):
            status = data.get("exit_status")
            if isinstance(status, int) and status != 0 and failed_origin is None:
                failed_origin, exit_code = origin, status
        elif kind == "finish":
            if data.get("succeeded") is False and failed_origin is None:
                failed_origin = origin
        elif kind == "error":
            message = data.get("message")
            if isinstance(message, str) and message.strip():
                platform_errors.append((origin, clean(message)))
        elif kind == "status" and data.get("status") in (
            "succeeded",
            "failed",
            "errored",
            "aborted",
        ):
            break

    if failed_origin is None and platform_errors:
        failed_origin = platform_errors[0][0]

    messages: list[str] = []
    if failed_origin is not None:
        messages.extend(m for o, m in platform_errors if o == failed_origin)
    if not messages:
        messages.extend(m for _o, m in platform_errors)
    messages = list(dict.fromkeys(messages))[:MAX_MESSAGES]

    step = _step_label(failed_origin, names)
    if step is None and failed_origin is None and not messages:
        reason = (
            f"the build's event stream ran past {max_lines} lines or "
            f"{max_bytes // 1_000_000} MB before the failure was found"
            if capped
            else "Concourse's events name no failed step"
        )
        return FailureWhy(source="concourse", url=url, unavailable=reason)

    note = None
    if not messages:
        note = (
            "Build log lines are not shown here (spec 15 §4a); "
            "open the build for the output."
        )
    elif capped:
        note = "Stopped reading the event stream at its size cap."
    return FailureWhy(
        source="concourse",
        step=step,
        exit_code=exit_code,
        messages=tuple(messages),
        url=url,
        note=note,
    )


class ConcourseWhyReader:
    """Reads one Concourse build's plan and events, anonymously.

    The same anonymous access `ConcourseClient` uses: these pipelines'
    jobs are `public: true`, which is what makes a public job's build
    readable without a credential. No new credential is involved.
    """

    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")

    def _plan(self, build_id: str) -> object | None:
        try:
            response = httpx2.get(
                f"{self.base_url}/api/v1/builds/{build_id}/plan", timeout=CONCOURSE_TIMEOUT
            )
            response.raise_for_status()
            payload: object = response.json()
            return payload
        except Exception as exc:  # noqa: BLE001 - degrades, never raises
            logger.warning(
                "Concourse plan read for build %s failed: %s", scrub(build_id), scrub(str(exc))
            )
            return None

    def _events(self, build_id: str, deadline: float) -> Iterator[str]:
        with httpx2.stream(
            "GET",
            f"{self.base_url}/api/v1/builds/{build_id}/events",
            headers={"Accept": "text/event-stream"},
            timeout=CONCOURSE_TIMEOUT,
        ) as response:
            response.raise_for_status()
            for line in response.iter_lines():
                if time.monotonic() > deadline:
                    return
                yield line

    def why(self, build_id: str, *, url: str | None) -> FailureWhy:
        if not build_id.isdigit():
            return FailureWhy(
                source="concourse", url=url, unavailable="Concourse gave no build id"
            )
        deadline = time.monotonic() + CONCOURSE_DEADLINE
        plan = self._plan(build_id)
        if plan is None:
            return FailureWhy(
                source="concourse",
                url=url,
                unavailable="Concourse did not return this build's plan",
            )
        names = step_names(plan)
        try:
            return why_from_events(names, self._events(build_id, deadline), url=url)
        except Exception as exc:  # noqa: BLE001 - degrades, never raises
            logger.warning(
                "Concourse events read for build %s failed: %s", scrub(build_id), scrub(str(exc))
            )
            return FailureWhy(
                source="concourse",
                url=url,
                unavailable="Concourse did not return this build's events",
            )


# --- GitHub Actions -----------------------------------------------------

_FAILED_CONCLUSIONS = ("failure", "timed_out", "startup_failure")


def _annotation_text(annotation: CheckAnnotation) -> str:
    message = annotation.message.strip()
    title = annotation.title.strip()
    if title and title not in message:
        message = f"{title}: {message}"
    where = annotation.path if annotation.path and annotation.path != ".github" else ""
    if where and annotation.line:
        where = f"{where}:{annotation.line}"
    return clean(f"{where}: {message}" if where else message)


def failed_job(jobs: list[WorkflowJob]) -> WorkflowJob | None:
    """The job that failed the run: a failure first, else any non-success."""
    failed = [j for j in jobs if j.conclusion in _FAILED_CONCLUSIONS] or [
        j for j in jobs if j.conclusion not in (None, "success", "skipped", "neutral")
    ]
    return failed[0] if failed else None


def why_from_run(
    jobs: list[WorkflowJob],
    annotations: list[CheckAnnotation] | None,
    *,
    run_url: str | None,
) -> FailureWhy:
    """Name the failed job and step of one run, and what it annotated."""
    job = failed_job(jobs)
    if job is None:
        return FailureWhy(
            source="github", url=run_url, unavailable="GitHub lists no failed job in this run"
        )
    step = next((s for s in job.steps if s.conclusion in _FAILED_CONCLUSIONS), None)
    label = f"{job.name}: {step.name}" if step else job.name
    url = job.url or run_url

    if annotations is None:
        return FailureWhy(
            source="github",
            step=label,
            url=url,
            note="GitHub did not return this job's annotations.",
        )

    exit_code: int | None = None
    for annotation in annotations:
        found = _EXIT_CODE.search(annotation.message)
        if found:
            exit_code = int(found.group(1))
            break
    meaningful = [a for a in annotations if not _RUNNER_EXIT.match(a.message.strip())]
    chosen = [a for a in meaningful if a.level == "failure"] or [
        a for a in meaningful if a.level == "warning"
    ]
    messages = tuple(dict.fromkeys(_annotation_text(a) for a in chosen))[:MAX_MESSAGES]
    note = None
    if not messages:
        note = (
            "The job raised no error annotation. Its log is not read here; "
            "open the run for the output."
        )
    return FailureWhy(
        source="github",
        step=label,
        exit_code=exit_code,
        messages=messages,
        url=url,
        note=note,
    )


async def github_why(
    github: GitHubClient, repo_full_name: str, run_id: int, *, run_url: str | None
) -> FailureWhy:
    """Read one failed run's jobs and the failed job's annotations."""

    async def read() -> FailureWhy:
        jobs = await github.workflow_run_jobs(repo_full_name, run_id)
        job = failed_job(jobs)
        if job is None:
            return why_from_run(jobs, [], run_url=run_url)
        try:
            annotations: list[CheckAnnotation] | None = await github.check_run_annotations(
                repo_full_name, job.id, limit=10
            )
        except Exception as exc:  # noqa: BLE001 - the step name is still worth showing
            logger.warning(
                "Annotations read for %s job %s failed: %s",
                scrub(repo_full_name),
                job.id,
                scrub(str(exc)),
            )
            annotations = None
        return why_from_run(jobs, annotations, run_url=run_url)

    try:
        return await asyncio.wait_for(read(), timeout=GITHUB_DEADLINE)
    except Exception as exc:  # noqa: BLE001 - degrades, never raises
        logger.warning(
            "Run jobs read for %s run %s failed: %s",
            scrub(repo_full_name),
            run_id,
            scrub(str(exc) or type(exc).__name__),
        )
        return FailureWhy(
            source="github",
            url=run_url,
            unavailable="GitHub did not return this run's jobs",
        )


# --- One page's worth ---------------------------------------------------


async def explain_failures(
    repo_full_name: str,
    jobs: list[JobStatus],
    *,
    source: str,
    cache: WhyCache,
    concourse: ConcourseWhyReader | None = None,
    github: GitHubClient | None = None,
) -> dict[str, FailureWhy]:
    """A reason for each failed job, keyed by job name.

    `source` is "concourse" or "github". A missing reader is a reason
    unavailable, not an exception.
    """
    failed = [job for job in jobs if job.status == "failed"]
    out: dict[str, FailureWhy] = {}
    pending: list[tuple[JobStatus, tuple[str, str, str]]] = []

    for index, job in enumerate(failed):
        if index >= MAX_EXPLAINED:
            out[job.name] = FailureWhy(
                source=source,
                url=job.build_url,
                unavailable=(
                    f"not looked up: only the first {MAX_EXPLAINED} failing jobs "
                    "are explained per request"
                ),
            )
            continue
        if not job.build_id:
            out[job.name] = FailureWhy(
                source=source,
                url=job.build_url,
                unavailable="the CI reported no build id for this job's last build",
            )
            continue
        key = (source, repo_full_name, job.build_id)
        cached = cache.get(key)
        if cached is not None:
            # The link is re-derived: it depends on configuration, not on the build.
            out[job.name] = replace(cached, url=cached.url or job.build_url)
            continue
        pending.append((job, key))

    async def one(job: JobStatus) -> FailureWhy:
        build_id = job.build_id or ""
        if source == "github":
            if github is None:
                return FailureWhy(
                    source=source,
                    url=job.build_url,
                    unavailable="no GitHub App installation to read this run with",
                )
            if not build_id.isdigit():
                return FailureWhy(
                    source=source, url=job.build_url, unavailable="GitHub gave no run id"
                )
            return await github_why(github, repo_full_name, int(build_id), run_url=job.build_url)
        if concourse is None:
            return FailureWhy(
                source=source,
                url=job.build_url,
                unavailable="no Concourse is configured for this deployment",
            )
        return await asyncio.to_thread(concourse.why, build_id, url=job.build_url)

    results = await asyncio.gather(*(one(job) for job, _key in pending))
    for (job, key), why in zip(pending, results, strict=True):
        cache.put(key, why)
        out[job.name] = why
    return out
