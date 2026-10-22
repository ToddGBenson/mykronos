"""What revision is actually running, next to the one that was scanned (#361).

THE GAP THIS CLOSES. On 2026-09-13 the backend serving this platform was an
image built eight days earlier. Twenty-six merged PRs were not running, and
every indicator the platform publishes was green throughout:
`repos_with_stale_scans: 0`, `overdue_findings: 0`. Both measure how recently a
repository was *scanned*. Nothing measured what was *deployed*, so nothing could
notice that the two had diverged.

That divergence is not a reporting nicety. Every finding this platform records
is a claim about a repository, and the useful version of that claim is about
the artifact serving traffic. When the deployed revision and the scanned
revision differ, an open finding may already be fixed in production and a closed
one may still be running -- and the platform presents both with equal
confidence. The estate has hit the "scanned artifact is not the running
artifact" class three times already (a `perl-base` package absent from the
running image, a `next` advisory against a version nobody deployed, and this).

TWO COMPARISONS, KEPT APART.

1. *Deployed revision vs most recently scanned revision* (`matches_scan`),
   which needs no GitHub call and is the claim the platform can stand behind:
   "the artifact I am reporting on is the artifact you are running."
2. *Deployed revision vs the default branch's head* (`DeploymentLag`, #452):
   "production is N commits behind `main`". Answered by the GitHub compare
   API's `ahead_by`, which is authoritative, never by counting scans or by
   dating an image -- a proxy presented as the real measurement is the defect
   class this module exists because of. Computed by the sweep and stored on
   the onboarding row, so the briefing and the dashboard read a cached answer
   and never call GitHub while rendering.

   A lag is `unknown` -- with the reason -- whenever the probe could not read
   a revision this sweep. It is never computed from the last revision a probe
   happened to read: a stale revision would report a deploy as not having
   happened, and an unreadable probe must not quietly read as "up to date".

THE PROBE CONTRACT is deliberately narrow: a GET returning JSON with a string
at `build.sha`. Both applications used to serve that shape unauthenticated --
mykronos at `/healthz` and TheHub at `/health`. Neither does any more: a
public sha tells anyone which commit to diff for what is unpatched, so both
now serve it only to a caller presenting the perimeter token (D-157, TheHub
#60709). The probe presents one when `MYKRONOS_DEPLOYMENT_PROBE_TOKENS` names
the probe URL's origin (#452, D-165); without an entry it sends nothing and
reads `unparsed`, and the detail names the missing setting.

A response in any other shape is reported `unparsed` rather than
pattern-matched for something commit-like: guessing which field
holds the revision is how a confident wrong answer gets made, and a confident
wrong answer about what is deployed is the thing being fixed.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

import httpx2
from sqlalchemy import select

from mykronos.gate import TOKEN_HEADER
from mykronos.logsafe import scrub
from mykronos.schemas import utcnow

if TYPE_CHECKING:
    from mykronos.github.client import GitHubClient
    from mykronos.github.factory import GitHubClientFactory

logger = logging.getLogger(__name__)

#: A probe answers in well under a second when healthy. The budget is for a
#: host that accepts the connection and then stalls, which is the failure that
#: would otherwise hold the whole sweep open.
DEFAULT_TIMEOUT_SECONDS = 10.0

#: Every state the probe can be in. `not_configured` is first because it is the
#: common one and is not a fault: a repository with no deployment this platform
#: can reach is a normal thing to be, and must not be rendered as a failure.
NOT_CONFIGURED = "not_configured"
OK = "ok"
UNREACHABLE = "unreachable"
UNPARSED = "unparsed"

#: How the deployment stands against its default branch (#452).
BEHIND = "behind"
AT_HEAD = "at_head"
#: Running a commit the branch does not contain -- TheHub on a commit that is
#: not on `develop`. Reported with both counts, never folded into `behind`.
DIVERGED = "diverged"
UNKNOWN = "unknown"

#: `MYKRONOS_DEPLOYMENT_PROBE_TOKENS` values that name a token this process
#: already holds, so neither secret has to be written down a second time.
GATE_ALIAS = "@gate"
HUB_ALIAS = "@hub"

#: The setting an operator needs to read when a probe cannot authenticate.
TOKENS_SETTING = "MYKRONOS_DEPLOYMENT_PROBE_TOKENS"

#: Where a repository's probe came from (TheHub #60918). Every repository read
#: `not_configured` because the only source was a per-repository URL nobody
#: had set. Two are now known without asking anybody: this platform's own
#: revision is `MYKRONOS_BUILD_SHA`, and TheHub is wherever
#: `MYKRONOS_HUB_API_URL` already sends the Product Owner tab, presenting the
#: `MYKRONOS_HUB_API_TOKEN` that call already presents. A URL set on the
#: repository always wins. "" is not configured.
SOURCE_CONFIGURED = "configured"
SOURCE_SELF = "this process (MYKRONOS_BUILD_SHA)"
SOURCE_HUB = "derived from MYKRONOS_HUB_API_URL"

#: Repository names (the part after the owner, lowercased) the two derived
#: probes belong to.
SELF_REPO_NAME = "mykronos"
HUB_REPO_NAME = "thehub"


@dataclass
class DeploymentState:
    """One repository's answer to "what is running?"."""

    repo_full_name: str
    status: str = NOT_CONFIGURED
    revision: str | None = None
    observed_at: datetime | None = None
    #: The newest commit any capability has scanned for this repo.
    scanned_revision: str | None = None
    detail: str = ""

    @property
    def matches_scan(self) -> bool | None:
        """True, False, or None for "cannot say" — never a defaulted False.

        None is the honest answer whenever either side is unknown, and it is
        the answer for most repositories. Collapsing it to False would invent
        a divergence; collapsing it to True would repeat the original defect
        in a new place.
        """
        if not self.revision or not self.scanned_revision:
            return None
        return self.revision.lower().startswith(
            self.scanned_revision.lower()
        ) or self.scanned_revision.lower().startswith(self.revision.lower())


@dataclass
class ProbeSweep:
    """What one pass over every configured probe found."""

    states: list[DeploymentState] = field(default_factory=list)
    #: How far each probed deployment sits behind its default branch (#452).
    #: Filled by `run_probe_sweep`, not by `sweep`, which makes no GitHub call.
    lags: list[DeploymentLag] = field(default_factory=list)

    @property
    def unknown(self) -> int:
        return sum(1 for s in self.states if s.revision is None)

    @property
    def diverged(self) -> list[DeploymentState]:
        """Repositories running something other than what was scanned.

        This is the list the 2026-09-13 outage would have appeared in, and the
        only number in this module that should ever raise an alert.
        """
        return [s for s in self.states if s.matches_scan is False]


def _extract_revision(payload: Any) -> str | None:
    """Read `build.sha`, and nothing else.

    No fallback to a top-level `sha`, a `version`, or anything commit-shaped
    found elsewhere in the body. The contract is documented and both
    applications meet it; an endpoint that does not is telling us it has not
    been taught to answer this question yet, which is worth knowing.
    """
    if not isinstance(payload, dict):
        return None
    build = payload.get("build")
    if not isinstance(build, dict):
        return None
    revision = build.get("sha")
    if not isinstance(revision, str) or not revision.strip():
        return None
    return revision.strip()


def origin_of(url: str) -> str:
    """`scheme://host[:port]`, lowercased; empty for anything without both."""
    parts = urlsplit((url or "").strip())
    if not parts.scheme or not parts.netloc:
        return ""
    return f"{parts.scheme}://{parts.netloc}".lower()


def resolve_probe_tokens(
    configured: dict[str, str] | None, *, gate_token: str = "", hub_token: str = ""
) -> dict[str, str]:
    """`MYKRONOS_DEPLOYMENT_PROBE_TOKENS`, keyed by normalised origin, with
    `@gate` / `@hub` replaced by the token they name. An entry that resolves to
    nothing (an alias whose token is unset) is dropped rather than sent empty.
    """
    resolved: dict[str, str] = {}
    for key, value in (configured or {}).items():
        origin = origin_of(str(key))
        if not origin:
            continue
        token = str(value or "").strip()
        if token == GATE_ALIAS:
            token = gate_token
        elif token == HUB_ALIAS:
            token = hub_token
        if token:
            resolved[origin] = token
    return resolved


@dataclass
class ProbeSetup:
    """How one repository's deployment is asked, and what is missing (TheHub #60918).

    `missing` names settings and routes only, never a value: it is printed in
    the briefing and served by the dashboard.
    """

    repo_full_name: str
    repo_id: str = ""
    #: What is asked. "" when nothing is, and for `SOURCE_SELF`, which asks
    #: nobody: this process knows its own revision.
    url: str = ""
    source: str = ""
    token: str = field(default="", repr=False)
    missing: list[str] = field(default_factory=list)
    #: `SOURCE_SELF` only: the revision this process was built from.
    revision: str = ""

    @property
    def configured(self) -> bool:
        return bool(self.source)

    def public(self) -> dict[str, Any]:
        """Everything but the token, for the briefing and the dashboard."""
        return {
            "repo_full_name": self.repo_full_name,
            "repo_id": self.repo_id,
            "url": self.url,
            "source": self.source,
            "missing": list(self.missing),
        }


def _token_gap(origin: str, settings: Any) -> str:
    """Why no token is presented to `origin`, by setting name."""
    for key, value in (getattr(settings, "deployment_probe_tokens", None) or {}).items():
        if origin_of(str(key)) != origin:
            continue
        alias = str(value or "").strip()
        if alias == GATE_ALIAS:
            return (
                f"MYKRONOS_GATE_TOKEN is not set, and {TOKENS_SETTING} names "
                f"{GATE_ALIAS} for {origin}"
            )
        if alias == HUB_ALIAS:
            return (
                f"MYKRONOS_HUB_API_TOKEN is not set, and {TOKENS_SETTING} names "
                f"{HUB_ALIAS} for {origin}"
            )
        return f"{TOKENS_SETTING} has an empty entry for {origin}"
    return (
        f"{TOKENS_SETTING} has no entry for {origin}, so the probe sends no "
        "perimeter token and the endpoint withholds build.sha (D-157)"
    )


def probe_setup_for(row: Any, settings: Any) -> ProbeSetup:
    """One repository's probe: configured, derived, or missing (TheHub #60918)."""
    repo = str(row.github_repo_full_name)
    repo_id = str(getattr(row, "id", "") or "")
    tokens = probe_tokens_from(settings) if settings is not None else {}
    url = (getattr(row, "deployment_probe_url", "") or "").strip()
    if url:
        origin = origin_of(url)
        setup = ProbeSetup(repo, repo_id, url, SOURCE_CONFIGURED, tokens.get(origin, ""))
        if not setup.token:
            setup.missing.append(_token_gap(origin, settings))
        return setup

    name = repo.rsplit("/", 1)[-1].lower()
    if settings is not None and name == SELF_REPO_NAME:
        setup = ProbeSetup(
            repo,
            repo_id,
            "",
            SOURCE_SELF,
            revision=str(getattr(settings, "build_sha", "") or "").strip(),
        )
        if not setup.revision:
            setup.missing.append(
                "MYKRONOS_BUILD_SHA is empty: the image was built without it, so "
                "this process cannot say which commit it is running"
            )
        return setup
    hub_url = str(getattr(settings, "hub_api_url", "") or "").strip().rstrip("/")
    if settings is not None and name == HUB_REPO_NAME and hub_url:
        health = hub_url + "/health"
        token = tokens.get(origin_of(health)) or str(
            getattr(settings, "hub_api_token", "") or ""
        ).strip()
        setup = ProbeSetup(repo, repo_id, health, SOURCE_HUB, token)
        if not token:
            setup.missing.append(
                "MYKRONOS_HUB_API_TOKEN is not set: TheHub's /health serves "
                "build.sha only to a caller presenting it"
            )
        return setup

    return ProbeSetup(
        repo,
        repo_id,
        missing=[
            "no deployment probe URL: set one with PUT /api/repos/"
            f"{repo_id or '<id>'}/deployment-probe if this repository has a "
            "deployment this platform can reach; one with none needs nothing"
        ],
    )


def probe_setups(db: Any, settings: Any) -> list[ProbeSetup]:
    """`probe_setup_for` over every active repository, by name."""
    from mykronos.db.models import RepoOnboarding

    with db.session() as session:
        rows = session.scalars(
            select(RepoOnboarding).where(RepoOnboarding.status == "active")
        ).all()
        setups = [probe_setup_for(row, settings) for row in rows]
    return sorted(setups, key=lambda s: s.repo_full_name.lower())


async def sweep_setups(
    setups: list[ProbeSetup],
    scanned: dict[str, str],
    *,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    tokens: dict[str, str] | None = None,
) -> list[DeploymentState]:
    """Ask every configured probe, derived ones included (TheHub #60918).

    A URL probe goes through `sweep`, presenting the setup's own token for a
    derived URL and `tokens` (MYKRONOS_DEPLOYMENT_PROBE_TOKENS) for a
    configured one. `SOURCE_SELF` asks nobody: an empty build sha is
    `unparsed`, never a guess.
    """
    by_url = {s.repo_full_name: s.url for s in setups if s.configured and s.url}
    merged = dict(tokens or {})
    for s in setups:
        if s.source == SOURCE_HUB and s.token:
            merged.setdefault(origin_of(s.url), s.token)
    states = (await sweep(by_url, scanned, timeout=timeout, tokens=merged)).states if by_url else []
    for s in setups:
        if s.source != SOURCE_SELF:
            continue
        states.append(
            DeploymentState(
                repo_full_name=s.repo_full_name,
                status=OK if s.revision else UNPARSED,
                revision=s.revision or None,
                observed_at=utcnow() if s.revision else None,
                scanned_revision=scanned.get(s.repo_full_name),
                detail="; ".join(s.missing),
            )
        )
    return sorted(states, key=lambda st: st.repo_full_name)


def probe_tokens_from(settings: Any) -> dict[str, str]:
    """`resolve_probe_tokens` over a `Settings`."""
    return resolve_probe_tokens(
        getattr(settings, "deployment_probe_tokens", None),
        gate_token=str(getattr(settings, "gate_token", "") or ""),
        hub_token=str(getattr(settings, "hub_api_token", "") or ""),
    )


async def probe(
    url: str, *, timeout: float = DEFAULT_TIMEOUT_SECONDS, token: str = ""
) -> tuple[str, str | None, str]:
    """Ask one deployment what it is. Returns `(status, revision, detail)`.

    `token` is presented as `X-Hub-Token` when given. Redirects are not
    followed: a token meant for one origin must not travel to another because
    the first said so.
    """
    headers = {TOKEN_HEADER: token} if token else {}
    try:
        async with httpx2.AsyncClient(
            timeout=timeout, headers=headers, follow_redirects=False
        ) as http:
            response = await http.get(url)
    except Exception as exc:  # noqa: BLE001 — any failure to reach is the answer
        return UNREACHABLE, None, f"{scrub(url)} could not be reached: {scrub(str(exc))}"

    if response.status_code != 200:
        return (
            UNREACHABLE,
            None,
            f"{scrub(url)} answered HTTP {response.status_code}.",
        )

    try:
        payload = response.json()
    except Exception:  # noqa: BLE001 — a non-JSON body is `unparsed`, not a crash
        return UNPARSED, None, f"{scrub(url)} did not return JSON."

    revision = _extract_revision(payload)
    if revision is None:
        if token:
            why = (
                " The perimeter token for this origin was sent, and the endpoint "
                "answers 200 either way (D-157): either that token is wrong, or the "
                "image was built without MYKRONOS_BUILD_SHA."
            )
        else:
            why = (
                " mykronos's /healthz and TheHub's /health serve it only to a caller "
                f"presenting the perimeter token (D-157), and {TOKENS_SETTING} names "
                f"no token for {scrub(origin_of(url)) or 'this origin'}."
            )
        return (
            UNPARSED,
            None,
            f"{scrub(url)} returned JSON with no string at `build.sha`.{why}",
        )
    return OK, revision, ""


def latest_scanned_revisions(catalog: Any) -> dict[str, str]:
    """The newest `commit_sha` any capability has scanned, per repository.

    Newest across all capabilities rather than per capability: the question is
    "what code did this platform most recently look at", and a repository whose
    lanes sit on different commits has a separate problem that
    `_capability_scan_state` already reports.
    """
    rows = catalog.query(
        """
        SELECT repo_full_name, commit_sha FROM (
            SELECT repo_full_name, commit_sha,
                   row_number() OVER (
                       PARTITION BY repo_full_name
                       ORDER BY coalesce(completed_at, started_at) DESC
                   ) AS rn
            FROM scan_runs
            WHERE commit_sha IS NOT NULL AND commit_sha <> ''
        ) WHERE rn = 1
        """
    )
    return {str(repo): str(sha) for repo, sha in rows}


async def sweep(
    probes: dict[str, str],
    scanned: dict[str, str],
    *,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    tokens: dict[str, str] | None = None,
) -> ProbeSweep:
    """Probe every configured deployment and pair it with what was scanned.

    `tokens` is `resolve_probe_tokens`' output: origin -> perimeter token.

    `probes` maps repository full name to probe URL; a repository absent from
    it is reported `not_configured` by the caller rather than omitted, so the
    coverage gap stays visible instead of shrinking the denominator.
    """
    result = ProbeSweep()
    for repo, url in sorted(probes.items()):
        token = (tokens or {}).get(origin_of(url), "")
        status, revision, detail = await probe(url, timeout=timeout, token=token)
        state = DeploymentState(
            repo_full_name=repo,
            status=status,
            revision=revision,
            observed_at=utcnow() if revision else None,
            scanned_revision=scanned.get(repo),
            detail=detail,
        )
        if state.matches_scan is False:
            # The one line in this module worth waking somebody for. Logged at
            # warning rather than info because the state it describes is the
            # one that was invisible for eight days.
            logger.warning(
                "%s is running %s but the newest scan was of %s — every finding "
                "for this repository describes code that is not deployed.",
                scrub(repo),
                scrub(state.revision or "?"),
                scrub(state.scanned_revision or "?"),
            )
        elif status in (UNREACHABLE, UNPARSED):
            logger.info("Deployment probe for %s: %s", scrub(repo), scrub(detail))
        result.states.append(state)
    return result


def probe_targets(db: Any) -> dict[str, str]:
    """Every active repository that has told us where to ask.

    Reads onboardings rather than a config file so the answer moves with the
    estate: a repository offboarded tomorrow stops being probed without anyone
    editing a list, which is the failure mode a static list always eventually
    has.
    """
    from mykronos.db.models import RepoOnboarding

    with db.session() as session:
        rows = session.scalars(
            select(RepoOnboarding).where(RepoOnboarding.status == "active")
        ).all()
        return {
            row.github_repo_full_name: row.deployment_probe_url
            for row in rows
            if (row.deployment_probe_url or "").strip()
        }


def record(db: Any, states: list[DeploymentState]) -> int:
    """Persist what the sweep saw. Returns the number of rows updated.

    A failed probe overwrites the status but **not** the last known revision.
    "The deployment was unreachable this minute" is not evidence that it
    stopped running what it was running, and blanking the field would turn a
    network blip into an apparent rollback to unknown.
    """
    from mykronos.db.models import RepoOnboarding

    updated = 0
    with db.session() as session:
        for state in states:
            row = session.scalars(
                select(RepoOnboarding).where(
                    RepoOnboarding.github_repo_full_name == state.repo_full_name
                )
            ).first()
            if row is None:
                continue
            row.deployment_probe_status = state.status
            if state.revision:
                row.deployed_revision = state.revision
                row.deployed_revision_at = state.observed_at
            updated += 1
        session.commit()
    return updated


# ---------------------------------------------------------------------------
# How far production sits behind the default branch (#452)
# ---------------------------------------------------------------------------


@dataclass
class DeploymentLag:
    """One repository's answer to "how far behind its branch is production?".

    Stored as JSON on `RepoOnboarding.deployment_lag` by the sweep, which is
    the cache: the briefing and the dashboard read it and never call GitHub.
    `checked_at` says how old the answer is.
    """

    repo_full_name: str
    #: behind | at_head | diverged | unknown
    status: str = UNKNOWN
    branch: str = ""
    deployed_revision: str | None = None
    head_revision: str | None = None
    #: Commits on the branch that production does not run. GitHub's
    #: `ahead_by` with the deployed revision as base. None when unknown.
    behind_by: int | None = None
    #: Commits production runs that the branch does not contain (`behind_by`
    #: in GitHub's terms). Non-zero only when `status` is `diverged`.
    not_on_branch: int | None = None
    #: When the deployed revision was committed -- the age of what is running.
    deployed_committed_at: datetime | None = None
    #: When the oldest commit production is missing was committed: how long
    #: the branch has had something undeployed.
    oldest_undeployed_at: datetime | None = None
    #: The undeployed commits, oldest first: `{sha, subject, committed_at}`.
    #: At most what GitHub lists on one page, the oldest 250
    #: (`commits_truncated`); a finding tied to a newer commit than those is
    #: counted as `closed_since_unmatched` rather than matched.
    commits: list[dict[str, Any]] = field(default_factory=list)
    commits_truncated: bool = False
    checked_at: datetime | None = None
    #: Why the answer is `unknown`, in a sentence an operator can act on.
    detail: str = ""

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in vars(self).items():
            out[key] = value.isoformat() if isinstance(value, datetime) else value
        return out

    @classmethod
    def from_json(cls, repo_full_name: str, data: Any) -> DeploymentLag | None:
        """The stored answer, or None when nothing was stored or it is not
        in the shape this version writes (read as "no answer", not a crash)."""
        if not isinstance(data, dict):
            return None
        try:
            return cls(
                repo_full_name=repo_full_name,
                status=str(data.get("status") or UNKNOWN),
                branch=str(data.get("branch") or ""),
                deployed_revision=data.get("deployed_revision") or None,
                head_revision=data.get("head_revision") or None,
                behind_by=_int_or_none(data.get("behind_by")),
                not_on_branch=_int_or_none(data.get("not_on_branch")),
                deployed_committed_at=_time_or_none(data.get("deployed_committed_at")),
                oldest_undeployed_at=_time_or_none(data.get("oldest_undeployed_at")),
                commits=[c for c in data.get("commits") or [] if isinstance(c, dict)],
                commits_truncated=bool(data.get("commits_truncated")),
                checked_at=_time_or_none(data.get("checked_at")),
                detail=str(data.get("detail") or ""),
            )
        except (TypeError, ValueError):
            return None

    def undeployed_shas(self) -> list[str]:
        return [str(c.get("sha") or "") for c in self.commits if c.get("sha")]


def _int_or_none(value: Any) -> int | None:
    return None if value is None else int(value)


def _time_or_none(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if not isinstance(value, str) or not value:
        return None
    return datetime.fromisoformat(value)


def _naive(value: datetime | None) -> datetime | None:
    """Naive UTC, as every stored timestamp here is."""
    if value is None or value.tzinfo is None:
        return value
    return value.astimezone(UTC).replace(tzinfo=None)


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def unknown_lag(
    repo_full_name: str, state: DeploymentState, *, branch: str = ""
) -> DeploymentLag:
    """The lag for a probe that read no revision this sweep: unknown, and why.

    Deliberately not computed from the last revision some earlier probe read.
    `record` keeps that revision so a blip does not look like a rollback, but
    a lag computed from it would keep reporting the pre-deploy number after a
    deploy, which is a confident wrong answer of exactly the kind #452 is
    about.
    """
    if state.status == UNPARSED:
        why = f"the probe could not read the running revision: {state.detail}"
    elif state.status == UNREACHABLE:
        why = f"the probe could not reach the deployment: {state.detail}"
    else:
        why = f"the probe reported `{state.status}`. {state.detail}".strip()
    return DeploymentLag(
        repo_full_name=repo_full_name,
        status=UNKNOWN,
        branch=branch,
        checked_at=utcnow(),
        detail=why,
    )


async def compute_lag(
    github: GitHubClient, repo_full_name: str, branch: str, revision: str
) -> DeploymentLag:
    """`revision...branch` through the GitHub compare API.

    `ahead_by` is the number of commits on the branch production does not run,
    which is the whole answer; it is GitHub's count, not ours. Never raises: a
    compare that fails is `unknown` with GitHub's reason.
    """
    from mykronos.github.client import GitHubError

    lag = DeploymentLag(
        repo_full_name=repo_full_name,
        branch=branch,
        deployed_revision=revision,
        checked_at=utcnow(),
    )
    try:
        comparison = await github.compare(repo_full_name, revision, branch)
    except GitHubError as exc:
        if exc.status == 404:
            lag.detail = (
                f"GitHub does not know {revision[:12]} in {repo_full_name} (or "
                f"`{branch}`): the running image was built from a commit that was "
                "never pushed, or that a force-push removed."
            )
        else:
            lag.detail = f"the GitHub compare API failed: {scrub(str(exc))}"
        return lag
    except Exception as exc:  # noqa: BLE001 — the job must keep sweeping
        lag.detail = f"the GitHub compare API could not be asked: {scrub(str(exc))}"
        return lag

    lag.behind_by = int(comparison.ahead_by)
    lag.not_on_branch = int(comparison.behind_by)
    lag.head_revision = comparison.head_sha or (revision if lag.behind_by == 0 else None)
    lag.deployed_committed_at = _naive(comparison.base_committed_at)
    lag.commits = [
        {
            "sha": c.sha,
            "subject": (c.message or "").splitlines()[0][:200] if c.message else "",
            "committed_at": _iso(_naive(c.committed_at)),
        }
        for c in comparison.commits
    ]
    lag.commits_truncated = comparison.commits_truncated
    # GitHub lists the range oldest first, so the first listed commit is the
    # oldest undeployed one even when the list stops short of `ahead_by`.
    if comparison.commits:
        lag.oldest_undeployed_at = _naive(comparison.commits[0].committed_at)
    if lag.not_on_branch:
        lag.status = DIVERGED
    elif lag.behind_by:
        lag.status = BEHIND
    else:
        lag.status = AT_HEAD
    return lag


def lag_targets(db: Any, probed: set[str] | None = None) -> dict[str, tuple[int, str]]:
    """Active repositories with a probe: installation id and default branch.

    `probed` names the repositories with a probe when some are derived
    (TheHub #60918); without it, a probe is a stored URL.
    """
    from mykronos.db.models import RepoOnboarding

    with db.session() as session:
        rows = session.scalars(
            select(RepoOnboarding).where(RepoOnboarding.status == "active")
        ).all()
        return {
            row.github_repo_full_name: (
                int(row.github_installation_id),
                str(row.default_branch or "main"),
            )
            for row in rows
            if (
                row.github_repo_full_name in probed
                if probed is not None
                else (row.deployment_probe_url or "").strip()
            )
        }


async def measure_lags(
    states: list[DeploymentState],
    targets: dict[str, tuple[int, str]],
    github_factory: GitHubClientFactory | None,
) -> list[DeploymentLag]:
    """One `DeploymentLag` per probed repository: compared where the probe read
    a revision this sweep, `unknown` with the reason everywhere else."""
    lags: list[DeploymentLag] = []
    for state in states:
        installation_id, branch = targets.get(state.repo_full_name, (0, ""))
        if not state.revision or state.status != OK:
            lags.append(unknown_lag(state.repo_full_name, state, branch=branch))
            continue
        if github_factory is None or not branch:
            lags.append(
                DeploymentLag(
                    repo_full_name=state.repo_full_name,
                    branch=branch,
                    deployed_revision=state.revision,
                    checked_at=utcnow(),
                    detail="no GitHub client to compare the running revision with.",
                )
            )
            continue
        try:
            github = github_factory.for_installation(installation_id)
        except Exception as exc:  # noqa: BLE001
            lags.append(
                DeploymentLag(
                    repo_full_name=state.repo_full_name,
                    branch=branch,
                    deployed_revision=state.revision,
                    checked_at=utcnow(),
                    detail=f"no GitHub client for this installation: {scrub(str(exc))}",
                )
            )
            continue
        lag = await compute_lag(github, state.repo_full_name, branch, state.revision)
        if lag.status in (BEHIND, DIVERGED):
            logger.warning(
                "%s production runs %s, %s commit(s) behind %s.",
                scrub(state.repo_full_name),
                scrub(state.revision[:12]),
                lag.behind_by,
                scrub(branch),
            )
        lags.append(lag)
    return lags


def record_lags(db: Any, lags: list[DeploymentLag]) -> int:
    """Store each answer on its onboarding row. This is the cache."""
    from mykronos.db.models import RepoOnboarding

    updated = 0
    with db.session() as session:
        for lag in lags:
            row = session.scalars(
                select(RepoOnboarding).where(
                    RepoOnboarding.github_repo_full_name == lag.repo_full_name
                )
            ).first()
            if row is None:
                continue
            row.deployment_lag = lag.to_json()
            updated += 1
        session.commit()
    return updated


#: How a finding was tied to the undeployed range, strongest first.
#: `fix_merged` -- the Patchwork fix's merge commit is in the range: exact.
#: `last_seen_in_range` -- closed on the branch, and the last scan that still
#: saw it was of the deployed revision or a commit after it, so whatever
#: removed it came later and is not running. Exact as far as scans can be.
FIX_MERGED = "fix_merged"
LAST_SEEN_IN_RANGE = "last_seen_in_range"


@dataclass
class UndeployedFix:
    """A finding whose fix is merged and not running (#452)."""

    finding_id: str
    rule_id: str
    severity: str
    title: str
    #: The finding's own status in the lake: `open` for a merged fix not yet
    #: verified, `fixed` for one closed by scans of the branch.
    status: str
    #: fix_merged | last_seen_in_range
    basis: str
    #: The commit that is the evidence: the merge commit, or the last commit
    #: a scan still saw the finding on.
    commit: str = ""


@dataclass
class FixesNotDeployed:
    matched: list[UndeployedFix] = field(default_factory=list)
    #: Findings closed on the branch since the deployed revision was committed
    #: that neither rule above could tie to the range: the last scan that saw
    #: them was of a commit older than the deployed one, or of no recorded
    #: commit. The fix may or may not be running. Counted, never listed as
    #: undeployed -- this is the approximation, and it is labelled as one.
    closed_since_unmatched: int = 0


def _matches(sha: str, candidates: set[str]) -> str:
    """The candidate `sha` names, comparing on the shorter of the two."""
    sha = (sha or "").lower()
    if not sha:
        return ""
    for candidate in candidates:
        if candidate.startswith(sha) or sha.startswith(candidate):
            return candidate
    return ""


def fixes_not_deployed(catalog: Any, lag: DeploymentLag) -> FixesNotDeployed:
    """The findings whose fixing change is in `lag`'s undeployed range.

    Two exact rules and one counted approximation, because the lake records the
    fixing commit only for Patchwork's own fixes. A human fix is never linked to
    a commit; what the lake has is the commit each scan was of. So a finding
    closed on the branch is tied to the range when the *last* scan that saw it
    was of the deployed revision or later: its removal must then be later still.
    Anything else closed since the deployed revision was committed is counted as
    `closed_since_unmatched` and said to be uncertain. Never raises.
    """
    result = FixesNotDeployed()
    if lag.status not in (BEHIND, DIVERGED) or not lag.deployed_revision:
        return result
    in_range = {sha.lower() for sha in lag.undeployed_shas()}
    seen_ok = in_range | {lag.deployed_revision.lower()}
    repo = lag.repo_full_name
    matched: dict[str, UndeployedFix] = {}

    try:
        if catalog.all_files("remediation_events") and catalog.all_files("findings"):
            rows = catalog.query(
                """
                SELECT DISTINCT e.finding_id, e.verification_commit_sha,
                       f.rule_id, f.severity, f.title, f.status
                FROM remediation_events e
                JOIN findings f ON f.finding_id = e.finding_id
                WHERE e.repo_full_name = ? AND e.pr_status = 'merged'
                  AND e.verification_commit_sha IS NOT NULL
                  AND f.status IN ('open', 'fixed', 'accepted_risk')
                """,
                [repo],
            )
            for finding_id, commit, rule_id, severity, title, status in rows:
                hit = _matches(str(commit or ""), in_range)
                if hit and str(finding_id) not in matched:
                    matched[str(finding_id)] = UndeployedFix(
                        finding_id=str(finding_id),
                        rule_id=str(rule_id or ""),
                        severity=str(severity or ""),
                        title=str(title or ""),
                        status=str(status or ""),
                        basis=FIX_MERGED,
                        commit=hit,
                    )
    except Exception:  # noqa: BLE001 — the remaining rule still answers
        logger.debug("Could not read merged fixes for %s", scrub(repo))

    try:
        if catalog.all_files("findings") and catalog.all_files("scan_runs"):
            rows = catalog.query(
                """
                SELECT f.finding_id, f.rule_id, f.severity, f.title, f.status,
                       r.commit_sha, f.resolved_at
                FROM findings f
                LEFT JOIN scan_runs r ON r.scan_run_id = f.last_seen_scan_run_id
                WHERE f.asset_id = ? AND f.status = 'fixed'
                """,
                [repo],
            )
            since = lag.deployed_committed_at
            for finding_id, rule_id, severity, title, status, commit, resolved in rows:
                key = str(finding_id)
                if key in matched:
                    continue
                hit = _matches(str(commit or ""), seen_ok)
                if hit:
                    matched[key] = UndeployedFix(
                        finding_id=key,
                        rule_id=str(rule_id or ""),
                        severity=str(severity or ""),
                        title=str(title or ""),
                        status=str(status or ""),
                        basis=LAST_SEEN_IN_RANGE,
                        commit=hit,
                    )
                elif since is not None and resolved is not None and resolved >= since:
                    result.closed_since_unmatched += 1
    except Exception:  # noqa: BLE001
        logger.debug("Could not read closed findings for %s", scrub(repo))

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    result.matched = sorted(
        matched.values(),
        key=lambda f: (order.get(f.severity.lower(), 9), f.rule_id, f.finding_id),
    )
    return result


def stored_lag(row: Any, *, probed: bool | None = None) -> DeploymentLag | None:
    """What the last sweep stored for one onboarding row, or None.

    None for a repository with no probe, which is `not_configured` and not a
    fault: a library has no production to be behind. `probed` says whether it
    has one when the probe may be derived (TheHub #60918); without it, a
    probe is a stored URL.
    """
    if probed is None:
        probed = bool((getattr(row, "deployment_probe_url", "") or "").strip())
    if not probed:
        return None
    return DeploymentLag.from_json(
        row.github_repo_full_name, getattr(row, "deployment_lag", None)
    )


async def run_probe_sweep(
    db: Any,
    catalog: Any,
    *,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    tokens: dict[str, str] | None = None,
    github_factory: GitHubClientFactory | None = None,
    settings: Any = None,
) -> ProbeSweep:
    """The scheduled job: probe, compare against what was scanned and against
    the default branch, record.

    With `settings`, derived probes are swept too (TheHub #60918), and each
    repository that has none is logged with what it is missing.
    """
    if settings is not None:
        setups = probe_setups(db, settings)
        for setup in setups:
            if setup.missing:
                logger.info(
                    "Deployment probe for %s: %s",
                    scrub(setup.repo_full_name),
                    scrub("; ".join(setup.missing)),
                )
        configured = [s for s in setups if s.configured]
        if not configured:
            return ProbeSweep()
        result = ProbeSweep(
            states=await sweep_setups(
                configured, latest_scanned_revisions(catalog), timeout=timeout, tokens=tokens
            )
        )
        probed: set[str] | None = {s.repo_full_name for s in configured}
    else:
        targets = probe_targets(db)
        if not targets:
            logger.info(
                "No deployment probes configured; nothing compares the running "
                "artifact to the scanned one."
            )
            return ProbeSweep()
        result = await sweep(
            targets, latest_scanned_revisions(catalog), timeout=timeout, tokens=tokens
        )
        probed = None
    record(db, result.states)
    result.lags = await measure_lags(result.states, lag_targets(db, probed), github_factory)
    record_lags(db, result.lags)
    return result
