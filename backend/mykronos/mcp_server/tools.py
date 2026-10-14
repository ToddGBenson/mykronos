"""The tools: a fixed, small set, each mapped to a route that already exists.

**Read tools** answer #319's narrow questions without SQL: what needs doing
(`work`, spec 36 §2), the briefing, findings by typed filter, one finding with
its DAST target already parsed, and a lane's health. Repository-scoped tools
take the onboarding **id** (the API's routes are id-only, TheHub #60739);
`repos()` maps names to ids.

**Write tools** are four, and each takes `dry_run`. A dry run names the
method, path, body and `governed_by` the real call would meet, and writes
nothing. `governed_by` is computed with the route's own rule
(`finding_disposition.governed`), so the tool and the route cannot disagree
about whether a person will be involved.

**What is absent is the design** (#319, spec 36 §4). No tool starts or stops
a scan, ends an acceptance, removes data, widens what an agent may do, settles
another principal's request, or issues a credential. An agent that can close
findings is already a risk; one that can also stop the scans is a worse one.
`TOOL_NAMES` pins the set, and a test holds it there: an MCP tool list nothing
pins drifts (#343, #351).
"""

from __future__ import annotations

import json
from datetime import date
from typing import Annotated, Any, Literal
from urllib.parse import quote

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import BaseModel, ConfigDict, Field

from mykronos import finding_disposition
from mykronos.adminauth import Principal
from mykronos.mcp_server.api import ApiError, MykronosApi
from mykronos.schemas import Capability, FindingStatus, Severity

#: The whole tool surface. Adding a tool means changing this and the test that
#: pins it, in a pull request somebody reads.
TOOL_NAMES = frozenset(
    {
        # read
        "whoami",
        "repos",
        "work",
        "briefing",
        "findings",
        "finding",
        "lane_health",
        "scan_run",
        # write, governed
        "claim",
        "disposition",
        "accept",
        "request_pr_review",
    }
)

#: Approval duties the write tools can meet (`approval-policy-v1.yaml`).
RISK_ACCEPTANCE_DUTY = "risk_acceptance"
PULL_REQUEST_DUTY = "pull_request_merge"

#: What each `governed_by` means for the caller, said once.
GOVERNED_MEANS: dict[str | None, str] = {
    None: "A direct write, attributed to you. It takes effect when the call returns.",
    finding_disposition.DUTY: (
        "Your evidence is frozen with the finding and its raw scanner record. The "
        "finding stays open until someone independent signs off (#713)."
    ),
    RISK_ACCEPTANCE_DUTY: (
        "The acceptance is proposed, not in force. It takes effect only when someone "
        "independent of you signs off (spec 33, spec 34)."
    ),
    PULL_REQUEST_DUTY: (
        "The platform reads the diff at its current head and asks someone independent "
        "to review it (spec 34 §6.1). It posts the `independent-review` check."
    ),
}

INSTRUCTIONS = """\
MyKronos, operated as an agent under your own credential.

Start with `work()`: an ordered queue of what needs doing, what to leave alone
(`waiting`) and what could not be read (`unknown`). Work from the top. A dead
lane comes before the findings in it, because nothing done to a finding in a
frozen lane can be observed. An entry in `unknown` means "could not ask", never
"nothing there". Read each item's `caveats` before acting on it.

Repository tools take the onboarding id, not owner/repo; `repos()` maps one to
the other. `accept` and `request_pr_review` take owner/repo, because their
routes do.

Every write tool takes `dry_run`. Use it to learn `governed_by` before acting:
null is a direct write, anything else names the duty a person or an independent
agent will weigh. A refusal from the API is returned word for word; read it,
do not retry it. You cannot mark work done: the platform observes it.
"""

_READ = ToolAnnotations(read_only_hint=True, open_world_hint=False)
_WRITE = ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=False)
#: A disposition can close a finding. Reversible (`reopen`), but it changes
#: what the platform reports, so it is not labelled harmless.
_CLOSING = ToolAnnotations(read_only_hint=False, destructive_hint=True, open_world_hint=False)

#: Pinned to the platform's own tuples by tests; Literal so the schema an agent
#: reads names the allowed values.
DispositionStatus = Literal["false_positive", "suppressed"]
DeviationType = Literal["vendor_dependency", "risk_adjustment", "operational_requirement"]
ResidualLevel = Literal["low", "moderate", "high", "very_high"]
AcceptanceResponse = Literal["accept", "transfer"]
PremiseType = Literal[
    "no_fixed_version",
    "port_not_published",
    "firewall_scope",
    "image_role",
    "container_command",
    "not_internet_facing",
    "not_kev_listed",
    "epss_below",
    "path_unreachable",
]
TriageVerdict = Literal[
    "true_positive", "likely_false_positive", "needs_human_judgment", "toxic_combination"
]

RepoId = Annotated[
    str,
    Field(
        min_length=1,
        description="The repository's onboarding id (from `repos()`), not owner/repo.",
    ),
]
FindingId = Annotated[str, Field(min_length=1, description="The finding's finding_id.")]
ScanRunId = Annotated[
    str, Field(min_length=1, description="The run's scan_run_id, e.g. from a work item.")
]
DryRun = Annotated[
    bool,
    Field(
        description=(
            "Answer with the method, path, body and governed_by the real call would "
            "meet, and write nothing."
        )
    ),
]


class AcceptanceScope(BaseModel):
    """Which findings the acceptance covers (spec 33 §1.2)."""

    model_config = ConfigDict(extra="forbid")

    capability: Capability
    rule_ids: list[str] | None = Field(
        default=None, description="Rules in scope. A code scope names rules or files."
    )
    file_paths: list[str] | None = Field(default=None, description="Path prefixes in scope.")
    image: str | None = Field(
        default=None, description="Required for containers: a decision about one image."
    )
    severities: list[Literal["low", "medium", "high", "critical"]] | None = None
    package_names: list[str] | None = None
    fixed_version: Literal["absent", "present", "any"] = "any"


class Milestone(BaseModel):
    """A step on the way out (spec 33 §3). At least one must end the weakness."""

    model_config = ConfigDict(extra="allow")

    title: str = Field(min_length=1)
    due: date | None = None
    ends_weakness: bool = False


class Premise(BaseModel):
    """A fact the acceptance rests on, of a type the platform can monitor (§4)."""

    model_config = ConfigDict(extra="allow")

    type: PremiseType


def _segment(value: str) -> str:
    """One path segment. An id is never allowed to become `../` or a query."""
    return quote(value, safe="")


def _refused(exc: ApiError) -> ToolError:
    if exc.status_code == 0:
        return ToolError(exc.detail)
    return ToolError(
        f"MyKronos answered {exc.method} {exc.path} with HTTP {exc.status_code}: {exc.detail}"
    )


async def _call(
    api: MykronosApi,
    method: str,
    path: str,
    *,
    params: dict[str, Any] | None = None,
    body: Any = None,
) -> Any:
    try:
        return await api.request_json(method, path, params=params, body=body)
    except ApiError as exc:
        raise _refused(exc) from exc


async def _write(
    api: MykronosApi,
    method: str,
    path: str,
    body: dict[str, Any],
    governed_by: str | None,
    dry_run: bool,
) -> dict[str, Any]:
    plan: dict[str, Any] = {
        "dry_run": dry_run,
        "method": method,
        "path": path,
        "body": body,
        "governed_by": governed_by,
        "governed_by_means": GOVERNED_MEANS[governed_by],
    }
    if dry_run:
        return plan
    plan["response"] = await _call(api, method, path, body=body)
    return plan


def _parsed(raw: Any) -> Any:
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except ValueError:
            return raw
    return raw


def dast_instance(record: dict[str, Any]) -> dict[str, Any]:
    """The concrete request a DAST finding is about, lifted out of the raw record.

    The route is the finding's identity; the URL, parameter and evidence are in
    `raw_finding_json.instance` (dast_zap.py). #319: an agent inferred the target
    from response codes for three cycles and got it wrong twice, because these
    three fields were one JSON path away. Empty for anything else.
    """
    finding = record.get("finding") or {}
    if finding.get("capability") != Capability.DAST.value:
        return {}
    raw = _parsed(finding.get("raw_finding_json"))
    instance = raw.get("instance") if isinstance(raw, dict) else None
    if not isinstance(instance, dict):
        return {}
    return {
        "uri": instance.get("uri"),
        "method": instance.get("method"),
        "param": instance.get("param"),
        "evidence": instance.get("evidence"),
    }


def build_server(api: MykronosApi, principal: Principal) -> MCPServer:
    """The server for one verified agent principal (see `api.verify_agent`)."""
    server: MCPServer = MCPServer(name="mykronos", instructions=INSTRUCTIONS)

    # -- read ---------------------------------------------------------------

    @server.tool(annotations=_READ)
    async def whoami() -> dict[str, Any]:
        """Who this server acts as: actor, kind, role and provenance (spec 34 §1)."""
        result: dict[str, Any] = await _call(api, "GET", "/api/agents/whoami")
        return result

    @server.tool(annotations=_READ)
    async def repos(include_removed: bool = False) -> dict[str, Any]:
        """Onboarded repositories, each with its onboarding `id` and owner/repo name.

        Repository-scoped tools take the `id`, never owner/repo. Use this to map
        one to the other. Offboarded repositories are left out unless asked for.
        """
        rows = await _call(
            api, "GET", "/api/repos", params={"include_removed": include_removed or None}
        )
        return {"repos": rows}

    @server.tool(annotations=_READ)
    async def work(
        repo_id: Annotated[
            str | None,
            Field(description="Narrow to one repository, by onboarding id (not owner/repo)."),
        ] = None,
        findings: Annotated[
            int, Field(ge=0, le=200, description="How many ranked findings to include.")
        ] = 25,
    ) -> dict[str, Any]:
        """What needs doing, in order, and what could not be read (spec 36 §2).

        Start here. Work from the top of `items`. `waiting` needs no action and
        must not be touched. `unknown` lists sources that could not be read,
        which is not the same as nothing to report. Each item names the actions
        that apply, the `governed_by` each will meet, its caveats, and what the
        platform will observe when it is done.
        """
        result: dict[str, Any] = await _call(
            api, "GET", "/api/agent/work", params={"repo_id": repo_id, "findings": findings}
        )
        return result

    @server.tool(annotations=_READ)
    async def briefing(
        repo_id: Annotated[
            str | None,
            Field(description="Narrow to one repository, by onboarding id (not owner/repo)."),
        ] = None,
    ) -> dict[str, Any]:
        """What `mykronos briefing` prints, structured (D-098).

        Lanes that cannot close findings come first, then the cheapest work.
        `work()` is built from this and is usually the better first call.
        """
        result: dict[str, Any] = await _call(
            api, "GET", "/api/dashboard/briefing", params={"repo_id": repo_id}
        )
        return result

    @server.tool(annotations=_READ)
    async def findings(
        repo_id: Annotated[
            str | None,
            Field(
                description=(
                    "One repository, by onboarding id (not owner/repo). Omit for the "
                    "estate-wide ranked queue of open findings."
                )
            ),
        ] = None,
        capability: Capability | None = None,
        severity: Severity | None = None,
        status: Annotated[
            FindingStatus | None,
            Field(description="Only with repo_id. The estate-wide queue is open findings."),
        ] = None,
        rule_id: Annotated[str | None, Field(max_length=200)] = None,
        triage: Annotated[
            TriageVerdict | None,
            Field(description="Only without repo_id: what the classifier concluded."),
        ] = None,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
        offset: Annotated[int, Field(ge=0, description="Only with repo_id.")] = 0,
    ) -> dict[str, Any]:
        """Findings by typed filter. No SQL, no column names to guess (#319).

        With `repo_id`: that repository's findings in any status
        (GET /api/dashboard/repos/{id}/findings), paged by limit and offset.
        Without it: the estate's open findings, ranked (GET /api/dashboard/triage).
        `finding(id)` reads one in full.
        """
        if repo_id:
            if triage is not None:
                raise ToolError(
                    "`triage` filters the estate-wide queue only; omit repo_id to use it."
                )
            path = f"/api/dashboard/repos/{_segment(repo_id)}/findings"
            params: dict[str, Any] = {
                "capability": capability,
                "severity": severity,
                "finding_status": status,
                "rule_id": rule_id,
                "limit": limit,
                "offset": offset or None,
            }
        else:
            if status not in (None, FindingStatus.OPEN):
                raise ToolError(
                    "The estate-wide queue holds open findings only. Pass repo_id to "
                    f"read findings with status '{status}'."
                )
            if offset:
                raise ToolError("The estate-wide queue is not paged; pass repo_id to page.")
            path = "/api/dashboard/triage"
            params = {
                "capability": capability,
                "severity": severity,
                "rule_id": rule_id,
                "triage": triage,
                "order": "rank",
                "limit": limit,
            }
        result: dict[str, Any] = await _call(api, "GET", path, params=params)
        return result

    @server.tool(annotations=_READ)
    async def finding(finding_id: FindingId) -> dict[str, Any]:
        """Everything about one finding, in one call (B-032).

        For a DAST finding, the concrete request is lifted to the top level:
        `uri`, `method`, `param` and `evidence` from the raw scanner record. The
        title names the route; these name the URL that was actually probed.
        """
        record: dict[str, Any] = await _call(
            api, "GET", f"/api/dashboard/findings/{_segment(finding_id)}/record"
        )
        return {**dast_instance(record), **record}

    @server.tool(annotations=_READ)
    async def lane_health(repo_id: RepoId) -> dict[str, Any]:
        """One repository's lanes: run history and freshness per capability, and
        where it is built.

        Composes GET /api/dashboard/repos/{id}/scan-health and
        GET /api/dashboard/repos/{id}/ci. If the CI half cannot be read it is
        listed in `unknown` with the reason, never shown as healthy.
        """
        segment = _segment(repo_id)
        health = await _call(api, "GET", f"/api/dashboard/repos/{segment}/scan-health")
        unknown: list[dict[str, str]] = []
        ci: Any = None
        try:
            ci = await api.request_json("GET", f"/api/dashboard/repos/{segment}/ci")
        except ApiError as exc:
            unknown.append({"source": "ci", "detail": str(_refused(exc))})
        return {"repo_id": repo_id, "scan_health": health, "ci": ci, "unknown": unknown}

    @server.tool(annotations=_READ)
    async def scan_run(scan_run_id: ScanRunId) -> dict[str, Any]:
        """One scan run: its outcome, tool and commit, and what it changed
        against the previous run on its lane (TheHub #60761).

        GET /api/dashboard/scan-runs/{id}. A `lane_stalled` work item cites
        its lane's latest run as evidence; this reads it. `changes.new` is
        exact; the other counts are lower bounds unless `exact` is true, and
        `not_reported` is null for a run that did not complete. `raw_files`
        names what was archived; fetch one from
        GET /api/dashboard/scan-runs/{id}/raw/{filename} with this credential.
        """
        path = f"/api/dashboard/scan-runs/{_segment(scan_run_id)}"
        result: dict[str, Any] = await _call(api, "GET", path)
        return result

    # -- write --------------------------------------------------------------

    @server.tool(annotations=_WRITE)
    async def claim(finding_id: FindingId, dry_run: DryRun = False) -> dict[str, Any]:
        """Take a finding, so nobody else works it at the same time (spec 27 §3.1).

        The claim is made in your actor name. First write wins: a finding someone
        else holds is refused, and that refusal is returned as it was given.
        """
        path = f"/api/dashboard/triage/{_segment(finding_id)}/claim"
        return await _write(api, "POST", path, {"by": principal.actor}, None, dry_run)

    @server.tool(annotations=_CLOSING)
    async def disposition(
        finding_id: FindingId,
        status: DispositionStatus,
        reason: Annotated[
            str,
            Field(
                min_length=1,
                max_length=2000,
                description="What was checked and why the finding is not real here.",
            ),
        ],
        dry_run: DryRun = False,
    ) -> dict[str, Any]:
        """Close a finding as a false positive or suppressed, by the route the
        platform requires of you.

        Reads the finding's severity first. For a critical or high finding an
        agent's word is not enough (#713): this files
        POST /api/dashboard/findings/{id}/disposition-requests, and the finding
        stays open until someone independent signs off. Otherwise it sets the
        status directly with PATCH /api/dashboard/findings/{id}/status. To accept
        a risk instead, use `accept`. A dry run still reads the finding, because
        the route depends on it, and writes nothing.
        """
        segment = _segment(finding_id)
        row = await _call(api, "GET", f"/api/dashboard/findings/{segment}")
        severity = row.get("severity") if isinstance(row, dict) else None
        body = {"status": status, "reason": reason}
        if finding_disposition.governed(principal, severity):
            path = finding_disposition.ROUTE.format(finding_id=segment)
            return await _write(api, "POST", path, body, finding_disposition.DUTY, dry_run)
        path = f"/api/dashboard/findings/{segment}/status"
        return await _write(api, "PATCH", path, body, None, dry_run)

    @server.tool(annotations=_WRITE)
    async def accept(
        repo: Annotated[
            str, Field(min_length=3, description="owner/repo: this route takes the full name.")
        ],
        scope: AcceptanceScope,
        deviation_type: Annotated[
            DeviationType,
            Field(
                description=(
                    "What kind of claim this is; it sets the reason code. "
                    "vendor_dependency = no fix exists; operational_requirement = the "
                    "fix costs more than the risk; risk_adjustment = a checkable premise "
                    "lowers the risk here."
                )
            ),
        ],
        justification: Annotated[str, Field(min_length=1, max_length=8000)],
        residual_likelihood: ResidualLevel,
        residual_impact: ResidualLevel,
        risk_owner: Annotated[
            str,
            Field(min_length=1, description="The person who answers for it. Never an agent."),
        ],
        requested_until: Annotated[
            date,
            Field(
                description=(
                    "The review date. Required: an acceptance with no end is a decision "
                    "nobody revisits, and this route has no indefinite option."
                )
            ),
        ],
        milestones: Annotated[
            list[Milestone],
            Field(min_length=1, description="The way out. One must set ends_weakness."),
        ],
        premises: list[Premise] | None = None,
        compensating_controls: list[dict[str, Any]] | None = None,
        response: AcceptanceResponse = "accept",
        dry_run: DryRun = False,
    ) -> dict[str, Any]:
        """Propose a risk acceptance for findings in one repository (spec 33).

        Goes to POST /api/risk-acceptances with every rule that route enforces: a
        deviation type (the reason code), a review date, a named person as risk
        owner, and a milestone that ends the weakness. It is a proposal: nothing
        about the findings changes until someone independent of you signs off.
        """
        body: dict[str, Any] = {
            "repo": repo,
            "scope": scope.model_dump(mode="json", exclude_none=True),
            "deviation_type": deviation_type,
            "justification": justification,
            "residual_likelihood": residual_likelihood,
            "residual_impact": residual_impact,
            "risk_owner": risk_owner,
            "requested_until": requested_until.isoformat(),
            "milestones": [m.model_dump(mode="json", exclude_none=True) for m in milestones],
            "premises": [p.model_dump(mode="json") for p in premises or []],
            "compensating_controls": list(compensating_controls or []),
            "response": response,
        }
        return await _write(
            api, "POST", "/api/risk-acceptances", body, RISK_ACCEPTANCE_DUTY, dry_run
        )

    @server.tool(annotations=_WRITE)
    async def request_pr_review(
        repo: Annotated[
            str, Field(min_length=3, description="owner/repo: this route takes the full name.")
        ],
        number: Annotated[int, Field(ge=1, description="The pull request number.")],
        statement: Annotated[
            str,
            Field(
                max_length=4000,
                description="Your account of the change. It is shown labelled as a claim.",
            ),
        ] = "",
        dry_run: DryRun = False,
    ) -> dict[str, Any]:
        """Ask for an independent review of one pull request at its current head
        (spec 34 §6.1). The platform reads the diff itself; the tier is its
        change class, not anything said here.
        """
        body = {"repo": repo, "number": number, "statement": statement}
        return await _write(
            api, "POST", "/api/approvals/pull-requests", body, PULL_REQUEST_DUTY, dry_run
        )

    return server
