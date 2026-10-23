"""The agent's MCP server (spec 36 §4, #319).

Driven through the real MCP protocol in-process (`mcp.Client` against the
server object), with MyKronos replaced by `httpx2.MockTransport`. What these
pin:

- the tool set, exactly, and that nothing in it offers a forbidden verb. An
  MCP tool list nothing pins drifts (#343, #351);
- every path a tool calls is a route the API really serves;
- the governed/direct choice for a disposition, made with the route's own rule;
- a dry run writes nothing, and says which duty the real call would meet;
- the API's refusal text comes back verbatim, once, with no retry;
- the server will not start without an agent credential, or with anything the
  platform does not call an agent.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any, get_args

import httpx2
import pytest
import yaml
from fastapi.routing import APIRoute
from mcp import Client

from mykronos import finding_disposition
from mykronos import risk_acceptance as ra
from mykronos.adminauth import ActorKind, Principal, Role
from mykronos.mcp_server import __main__ as entry
from mykronos.mcp_server import tools
from mykronos.mcp_server.api import (
    AGENT_TOKEN_ENV,
    DEFAULT_URL,
    GATE_TOKEN_ENV,
    URL_ENV,
    ConfigError,
    MykronosApi,
    Settings,
    verify_agent,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
AGENT = Principal(actor="agent:claude-opus-5.5:abc12345", role=Role.AGENT, kind=ActorKind.AGENT)
SETTINGS = Settings(url=DEFAULT_URL, agent_token="mka_test", gate_token="gate-test")

EXPECTED_TOOLS = {
    "whoami",
    "repos",
    "work",
    "briefing",
    "findings",
    "finding",
    "lane_health",
    "coverage",
    "scan_run",
    "playbook",
    "scorecard",
    "surfaces",
    "controls",
    "rule_vectors",
    "claim",
    "disposition",
    "accept",
    "request_pr_review",
    "declare_surface",
    "declare_control",
    "propose_rule_vector",
}
WRITE_TOOLS = {
    "claim",
    "disposition",
    "accept",
    "request_pr_review",
    "declare_surface",
    "declare_control",
    "propose_rule_vector",
}
#: #319 and spec 36 §4: what no tool may do, and so what no tool may say.
FORBIDDEN_VERBS = ("dispatch", "revoke", "purge", "grant", "decide", "approve", "mint", "delete")

Handler = Callable[[httpx2.Request], httpx2.Response]


class FakeMykronos:
    """Canned answers keyed by (method, path); records every request."""

    def __init__(self, answers: dict[tuple[str, str], httpx2.Response] | None = None) -> None:
        self.answers = answers or {}
        self.requests: list[httpx2.Request] = []

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        key = (request.method, request.url.path)
        if key in self.answers:
            return self.answers[key]
        return httpx2.Response(200, json={"ok": True})

    @property
    def calls(self) -> list[tuple[str, str]]:
        return [(r.method, r.url.path) for r in self.requests]

    def body(self, index: int = -1) -> Any:
        return json.loads(self.requests[index].content)


def _server(fake: FakeMykronos) -> Any:
    api = MykronosApi(SETTINGS, transport=httpx2.MockTransport(fake))
    return tools.build_server(api, AGENT)


async def _call(fake: FakeMykronos, name: str, args: dict[str, Any]) -> Any:
    async with Client(_server(fake)) as client:
        return await client.call_tool(name, args)


def _text(result: Any) -> str:
    return "".join(getattr(c, "text", "") for c in result.content)


def _finding(severity: str, capability: str = "sast", **extra: Any) -> httpx2.Response:
    return httpx2.Response(
        200,
        json={"finding_id": "f1", "severity": severity, "capability": capability, **extra},
    )


# -- the tool set ------------------------------------------------------------


async def test_the_tool_set_is_exactly_this() -> None:
    async with Client(_server(FakeMykronos())) as client:
        listed = {t.name for t in (await client.list_tools()).tools}
    assert listed == EXPECTED_TOOLS
    assert set(tools.TOOL_NAMES) == EXPECTED_TOOLS


async def test_no_tool_names_or_describes_a_forbidden_verb() -> None:
    async with Client(_server(FakeMykronos())) as client:
        listed = (await client.list_tools()).tools
    offenders = []
    for tool in listed:
        text = " ".join(
            [tool.name, tool.description or "", json.dumps(tool.input_schema)]
        ).lower()
        offenders += [f"{tool.name}: {verb}" for verb in FORBIDDEN_VERBS if verb in text]
    assert not offenders


async def test_every_write_takes_dry_run_and_every_read_says_it_is_one() -> None:
    async with Client(_server(FakeMykronos())) as client:
        listed = (await client.list_tools()).tools
    for tool in listed:
        assert tool.annotations is not None
        if tool.name in WRITE_TOOLS:
            assert "dry_run" in tool.input_schema["properties"], tool.name
            assert tool.annotations.read_only_hint is False
        else:
            assert "dry_run" not in tool.input_schema["properties"], tool.name
            assert tool.annotations.read_only_hint is True


def test_the_literals_match_the_platform() -> None:
    """The tool schemas spell these out so an agent sees them; they must not
    drift from the tuples the routes validate against."""
    assert get_args(tools.DispositionStatus) == finding_disposition.DISPOSITIONS
    assert get_args(tools.DeviationType) == ra.DEVIATION_TYPES
    assert get_args(tools.ResidualLevel) == ra.LEVELS
    assert get_args(tools.AcceptanceResponse) == ra.RESPONSES
    assert get_args(tools.PremiseType) == ra.PREMISE_TYPES


def test_the_threat_model_literals_match_the_register() -> None:
    """TheHub #60825: an agent reads these in the schema; the routes validate
    against the module tuples. They must be the same list."""
    from mykronos import controls, surfaces
    from mykronos.dashboard import STRIDE_CATEGORIES
    from mykronos.surface_match import REQUIREMENT_LEVELS

    assert get_args(tools.SurfaceKind) == surfaces.SURFACE_KINDS
    assert get_args(tools.Exposure) == surfaces.EXPOSURES
    assert get_args(tools.Sensitivity) == surfaces.SENSITIVITIES
    assert get_args(tools.RequirementLevel) == REQUIREMENT_LEVELS
    assert get_args(tools.ControlKind) == controls.CONTROL_KINDS
    assert get_args(tools.StrideCategory) == STRIDE_CATEGORIES


def test_every_named_duty_is_in_the_approval_policy() -> None:
    policy = yaml.safe_load((REPO_ROOT / "approval-policy-v1.yaml").read_text(encoding="utf-8"))
    named = {d for d in tools.GOVERNED_MEANS if d is not None}
    assert named == {
        finding_disposition.DUTY,
        tools.RISK_ACCEPTANCE_DUTY,
        tools.PULL_REQUEST_DUTY,
    }
    assert named <= set(policy["duties"])


# -- every call reaches a route that exists ----------------------------------


def _api_routes() -> list[tuple[set[str], re.Pattern[str]]]:
    from mykronos.api.agent import router as agent_router
    from mykronos.api.agents import router as agents_router
    from mykronos.api.approvals import router as approvals_router
    from mykronos.api.dashboard import router as dashboard_router
    from mykronos.api.repos import router as repos_router
    from mykronos.api.risk_acceptances import router as risk_router
    from mykronos.api.rule_vectors import router as rule_vectors_router

    out = []
    for router in (
        agent_router,
        agents_router,
        approvals_router,
        dashboard_router,
        repos_router,
        risk_router,
        rule_vectors_router,
    ):
        for route in router.routes:
            if isinstance(route, APIRoute):
                pattern = re.sub(r"\{[^}]+\}", "[^/]+", route.path)
                out.append((set(route.methods), re.compile(f"^{pattern}$")))
    return out


ACCEPT_ARGS: dict[str, Any] = {
    "repo": "acme/api",
    "scope": {"capability": "containers", "image": "acme/api", "fixed_version": "absent"},
    "deviation_type": "vendor_dependency",
    "justification": "No fixed version is published for this package.",
    "residual_likelihood": "low",
    "residual_impact": "moderate",
    "risk_owner": "operator",
    "requested_until": "2026-12-01",
    "milestones": [{"title": "Rebuild on the patched base", "ends_weakness": True}],
}

EVERY_TOOL_CALL: list[tuple[str, dict[str, Any]]] = [
    ("whoami", {}),
    ("repos", {}),
    ("work", {"repo_id": "r1"}),
    ("briefing", {"repo_id": "r1"}),
    ("findings", {}),
    ("findings", {"repo_id": "r1", "status": "fixed"}),
    ("finding", {"finding_id": "f1"}),
    ("lane_health", {"repo_id": "r1"}),
    ("coverage", {"repo_id": "r1"}),
    ("scan_run", {"scan_run_id": "run-1"}),
    ("playbook", {"kind": "lane_stalled"}),
    ("scorecard", {}),
    ("scorecard", {"family": "claude-opus-5.5", "instance": "abc12345"}),
    ("claim", {"finding_id": "f1"}),
    ("disposition", {"finding_id": "f1", "status": "false_positive", "reason": "x"}),
    ("accept", ACCEPT_ARGS),
    ("request_pr_review", {"repo": "acme/api", "number": 7}),
    ("surfaces", {"repo_id": "r1"}),
    ("controls", {"repo_id": "r1"}),
    ("declare_surface", {"repo_id": "r1", "kind": "asset", "name": "db"}),
    ("declare_control", {"repo_id": "r1", "stride": "spoofing", "kind": "perimeter_gate"}),
    ("rule_vectors", {"repo_id": "r1"}),
    ("propose_rule_vector", {"capability": "sast", "tool": "semgrep", "rule_id": "x.y",
                             "template_id": "CWE-79"}),
]


async def test_every_path_a_tool_calls_is_a_route_the_api_serves() -> None:
    routes = _api_routes()
    for severity in ("high", "low"):
        fake = FakeMykronos({("GET", "/api/dashboard/findings/f1"): _finding(severity)})
        async with Client(_server(fake)) as client:
            for name, args in EVERY_TOOL_CALL:
                result = await client.call_tool(name, args)
                assert not result.is_error, (name, _text(result))
        for method, path in fake.calls:
            assert any(
                method in methods and pattern.match(path) for methods, pattern in routes
            ), f"{method} {path} is not a route"


# -- read routing --------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "args", "path", "params"),
    [
        ("whoami", {}, "/api/agents/whoami", {}),
        ("repos", {}, "/api/repos", {}),
        ("work", {}, "/api/agent/work", {"findings": "25"}),
        ("work", {"repo_id": "r1", "findings": 5}, "/api/agent/work",
         {"repo_id": "r1", "findings": "5"}),
        ("briefing", {"repo_id": "r1"}, "/api/dashboard/briefing", {"repo_id": "r1"}),
        (
            "findings",
            {"capability": "dast", "severity": "high", "triage": "needs_human_judgment"},
            "/api/dashboard/triage",
            {"capability": "dast", "severity": "high", "triage": "needs_human_judgment",
             "order": "rank", "limit": "100"},
        ),
        (
            "findings",
            {"repo_id": "r1", "status": "accepted_risk", "rule_id": "CVE-1", "offset": 50},
            "/api/dashboard/repos/r1/findings",
            {"finding_status": "accepted_risk", "rule_id": "CVE-1", "limit": "100",
             "offset": "50"},
        ),
        ("finding", {"finding_id": "f1"}, "/api/dashboard/findings/f1/record", {}),
        ("playbook", {"kind": "lane_stalled"}, "/api/agent/playbooks/lane_stalled", {}),
        ("scorecard", {}, "/api/agent/scorecard", {}),
        ("surfaces", {"repo_id": "r1"}, "/api/dashboard/repos/r1/surfaces", {}),
        ("controls", {"repo_id": "r1"}, "/api/dashboard/repos/r1/controls", {}),
        ("coverage", {"repo_id": "r1"}, "/api/dashboard/repos/r1/coverage", {}),
        ("rule_vectors", {"repo_id": "r1"}, "/api/dashboard/repos/r1/rule-vectors", {}),
        ("scorecard", {"family": "claude-opus-5.5"}, "/api/agent/scorecard",
         {"family": "claude-opus-5.5"}),
        ("scorecard", {"family": "claude-opus-5.5", "instance": "abc12345"},
         "/api/agent/scorecard", {"family": "claude-opus-5.5", "instance": "abc12345"}),
    ],
)
async def test_read_tools_call_their_route(
    name: str, args: dict[str, Any], path: str, params: dict[str, str]
) -> None:
    fake = FakeMykronos()
    result = await _call(fake, name, args)
    assert not result.is_error, _text(result)
    assert fake.calls == [("GET", path)]
    assert dict(fake.requests[0].url.params) == params


@pytest.mark.parametrize("name", ["lane_health", "coverage"])
async def test_repository_ids_cannot_become_another_path(name: str) -> None:
    fake = FakeMykronos()
    await _call(fake, name, {"repo_id": "../../agents/whoami"})
    assert all(path.startswith("/api/dashboard/repos/") for _, path in fake.calls)
    assert "%2F" in str(fake.requests[0].url)


async def test_coverage_returns_the_routes_unknown_list_as_it_came() -> None:
    """TheHub #60795: a half the route could not read stays visible to the agent."""
    body = {
        "repo_id": "r1",
        "repo_full_name": "acme/api",
        "analysers": {"available": False, "reason": "GitHub could not be read"},
        "regression": {"available": True, "fixed_findings": 3},
        "unknown": [{"source": "analysers", "detail": "GitHub could not be read"}],
    }
    fake = FakeMykronos(
        {("GET", "/api/dashboard/repos/r1/coverage"): httpx2.Response(200, json=body)}
    )
    out = (await _call(fake, "coverage", {"repo_id": "r1"})).structured_content
    assert out["unknown"] == [{"source": "analysers", "detail": "GitHub could not be read"}]
    assert out["regression"]["fixed_findings"] == 3


@pytest.mark.parametrize(
    ("args", "message"),
    [
        ({"status": "fixed"}, "open findings only"),
        ({"offset": 10}, "not paged"),
        ({"repo_id": "r1", "triage": "true_positive"}, "estate-wide queue only"),
    ],
)
async def test_findings_refuses_filters_its_route_cannot_apply(
    args: dict[str, Any], message: str
) -> None:
    fake = FakeMykronos()
    result = await _call(fake, "findings", args)
    assert result.is_error
    assert message in _text(result)
    assert fake.calls == []


async def test_a_dast_finding_carries_its_target_at_the_top() -> None:
    """#319: the URL was in `raw_finding_json.instance` the whole time."""
    raw = {
        "pluginid": "40012",
        "instance": {
            "uri": "http://127.0.0.1:8002/repos/1234?tab=x",
            "method": "GET",
            "param": "tab",
            "evidence": "<script>alert(1)</script>",
        },
    }
    record = {
        "finding": {"finding_id": "f1", "capability": "dast", "raw_finding_json": json.dumps(raw)},
        "repo_full_name": "acme/api",
    }
    fake = FakeMykronos(
        {("GET", "/api/dashboard/findings/f1/record"): httpx2.Response(200, json=record)}
    )
    result = await _call(fake, "finding", {"finding_id": "f1"})
    out = result.structured_content
    assert out["uri"] == "http://127.0.0.1:8002/repos/1234?tab=x"
    assert out["param"] == "tab"
    assert out["evidence"] == "<script>alert(1)</script>"
    assert out["method"] == "GET"
    assert out["finding"] == record["finding"]


async def test_a_non_dast_finding_gets_no_invented_target() -> None:
    record = {"finding": {"finding_id": "f1", "capability": "sast", "raw_finding_json": {}}}
    fake = FakeMykronos(
        {("GET", "/api/dashboard/findings/f1/record"): httpx2.Response(200, json=record)}
    )
    out = (await _call(fake, "finding", {"finding_id": "f1"})).structured_content
    assert "uri" not in out
    assert "param" not in out


async def test_lane_health_composes_both_routes() -> None:
    fake = FakeMykronos(
        {
            ("GET", "/api/dashboard/repos/r1/scan-health"): httpx2.Response(
                200, json={"lanes": [{"capability": "sast"}]}
            ),
            ("GET", "/api/dashboard/repos/r1/ci"): httpx2.Response(
                200, json={"pipeline": "acme-api", "failing": []}
            ),
        }
    )
    out = (await _call(fake, "lane_health", {"repo_id": "r1"})).structured_content
    assert out["scan_health"] == {"lanes": [{"capability": "sast"}]}
    assert out["ci"]["pipeline"] == "acme-api"
    assert out["unknown"] == []


async def test_scan_run_reads_one_run_and_cannot_become_another_path() -> None:
    fake = FakeMykronos()
    await _call(fake, "scan_run", {"scan_run_id": "run-1"})
    await _call(fake, "scan_run", {"scan_run_id": "../../agents/whoami"})
    assert fake.calls[0] == ("GET", "/api/dashboard/scan-runs/run-1")
    assert all(path.startswith("/api/dashboard/scan-runs/") for _, path in fake.calls)


async def test_an_unknown_playbook_kind_comes_back_as_the_apis_404() -> None:
    detail = "No playbook for kind 'nope'. Kinds: lane_dead, lane_stalled."
    fake = FakeMykronos(
        {("GET", "/api/agent/playbooks/nope"): httpx2.Response(404, json={"detail": detail})}
    )
    result = await _call(fake, "playbook", {"kind": "nope"})
    assert result.is_error
    assert detail in _text(result)
    assert "HTTP 404" in _text(result)
    assert len(fake.requests) == 1


async def test_an_unloadable_playbooks_file_comes_back_as_the_apis_503() -> None:
    detail = "The agent playbooks could not be loaded: agent-playbooks-v1.yaml: not found"
    fake = FakeMykronos(
        {("GET", "/api/agent/playbooks/lane_stalled"): httpx2.Response(
            503, json={"detail": detail}
        )}
    )
    result = await _call(fake, "playbook", {"kind": "lane_stalled"})
    assert result.is_error
    assert detail in _text(result)
    assert "HTTP 503" in _text(result)


async def test_a_playbook_kind_cannot_become_another_path() -> None:
    fake = FakeMykronos()
    await _call(fake, "playbook", {"kind": "../../agents/whoami"})
    assert all(path.startswith("/api/agent/playbooks/") for _, path in fake.calls)
    assert "%2F" in str(fake.requests[0].url)


async def test_lane_health_reports_an_unreadable_ci_half_as_unknown() -> None:
    fake = FakeMykronos(
        {("GET", "/api/dashboard/repos/r1/ci"): httpx2.Response(502, json={"detail": "CI down"})}
    )
    out = (await _call(fake, "lane_health", {"repo_id": "r1"})).structured_content
    assert out["ci"] is None
    assert out["unknown"][0]["source"] == "ci"
    assert "CI down" in out["unknown"][0]["detail"]


# -- writes --------------------------------------------------------------------


@pytest.mark.parametrize("severity", ["critical", "high", "HIGH"])
async def test_a_serious_finding_is_routed_to_a_disposition_request(severity: str) -> None:
    fake = FakeMykronos({("GET", "/api/dashboard/findings/f1"): _finding(severity)})
    result = await _call(
        fake,
        "disposition",
        {"finding_id": "f1", "status": "false_positive", "reason": "Input is never rendered."},
    )
    out = result.structured_content
    assert fake.calls == [
        ("GET", "/api/dashboard/findings/f1"),
        ("POST", "/api/dashboard/findings/f1/disposition-requests"),
    ]
    assert fake.body() == {"status": "false_positive", "reason": "Input is never rendered."}
    assert out["governed_by"] == "finding_disposition"


@pytest.mark.parametrize("severity", ["medium", "low", "info"])
async def test_a_lesser_finding_is_dispositioned_directly(severity: str) -> None:
    fake = FakeMykronos({("GET", "/api/dashboard/findings/f1"): _finding(severity)})
    result = await _call(
        fake, "disposition", {"finding_id": "f1", "status": "suppressed", "reason": "Test code."}
    )
    assert fake.calls == [
        ("GET", "/api/dashboard/findings/f1"),
        ("PATCH", "/api/dashboard/findings/f1/status"),
    ]
    assert fake.body() == {"status": "suppressed", "reason": "Test code."}
    assert result.structured_content["governed_by"] is None


def test_the_choice_is_the_routes_own_rule() -> None:
    """Spec 36 §2.1: computed with `finding_disposition.governed`, so the tool
    and the route cannot disagree."""
    for severity in ("critical", "high", "medium", "low", "info", None):
        assert finding_disposition.governed(AGENT, severity) == (
            str(severity or "") in finding_disposition.GOVERNED_SEVERITIES
        )


async def test_disposition_offers_no_acceptance_and_needs_a_reason() -> None:
    fake = FakeMykronos({("GET", "/api/dashboard/findings/f1"): _finding("low")})
    async with Client(_server(fake)) as client:
        accepted = await client.call_tool(
            "disposition", {"finding_id": "f1", "status": "accepted_risk", "reason": "x"}
        )
        blank = await client.call_tool(
            "disposition", {"finding_id": "f1", "status": "suppressed", "reason": ""}
        )
    assert accepted.is_error
    assert blank.is_error
    assert fake.calls == []


async def test_a_dry_run_disposition_reads_but_writes_nothing() -> None:
    fake = FakeMykronos({("GET", "/api/dashboard/findings/f1"): _finding("critical")})
    result = await _call(
        fake,
        "disposition",
        {"finding_id": "f1", "status": "false_positive", "reason": "r", "dry_run": True},
    )
    out = result.structured_content
    assert fake.calls == [("GET", "/api/dashboard/findings/f1")]
    assert out["dry_run"] is True
    assert out["method"] == "POST"
    assert out["path"] == "/api/dashboard/findings/f1/disposition-requests"
    assert out["body"] == {"status": "false_positive", "reason": "r"}
    assert out["governed_by"] == "finding_disposition"
    assert "stays open" in out["governed_by_means"]


async def test_claim_is_made_in_the_agents_own_name() -> None:
    fake = FakeMykronos()
    out = (await _call(fake, "claim", {"finding_id": "f1"})).structured_content
    assert fake.calls == [("POST", "/api/dashboard/triage/f1/claim")]
    assert fake.body() == {"by": AGENT.actor}
    assert out["response"] == {"ok": True}
    assert out["governed_by"] is None


@pytest.mark.parametrize(
    ("name", "args", "method", "path", "duty"),
    [
        ("claim", {"finding_id": "f1"}, "POST", "/api/dashboard/triage/f1/claim", None),
        ("accept", ACCEPT_ARGS, "POST", "/api/risk-acceptances", "risk_acceptance"),
        (
            "request_pr_review",
            {"repo": "acme/api", "number": 7, "statement": "Bumps a pin."},
            "POST",
            "/api/approvals/pull-requests",
            "pull_request_merge",
        ),
    ],
)
async def test_a_dry_run_makes_no_request(
    name: str, args: dict[str, Any], method: str, path: str, duty: str | None
) -> None:
    fake = FakeMykronos()
    out = (await _call(fake, name, {**args, "dry_run": True})).structured_content
    assert fake.calls == []
    assert (out["dry_run"], out["method"], out["path"], out["governed_by"]) == (
        True,
        method,
        path,
        duty,
    )
    assert "response" not in out


async def test_declare_surface_sends_selectors_and_overrides() -> None:
    fake = FakeMykronos()
    args = {
        "repo_id": "r1",
        "kind": "asset",
        "name": "Findings database",
        "sensitivity": "source",
        "selectors": {"paths": ["backend/mykronos/db/**"], "addresses": ["10.0.0.5:5433"]},
        "cr": "H",
    }
    out = (await _call(fake, "declare_surface", args)).structured_content
    assert fake.calls == [("POST", "/api/dashboard/repos/r1/surfaces")]
    body = fake.body()
    assert body["selectors"] == {
        "paths": ["backend/mykronos/db/**"],
        "images": [],
        "addresses": ["10.0.0.5:5433"],
        "hostnames": [],
    }
    assert (body["cr"], body["ir"], out["governed_by"]) == ("H", None, None)


async def test_propose_rule_vector_says_it_scores_nothing_and_has_no_confirm_twin() -> None:
    """TheHub #60832: an agent may propose a rule vector, never confirm one, so
    no tool reaches a confirm route and the proposal says it moves nothing."""
    fake = FakeMykronos()
    out = (
        await _call(
            fake,
            "propose_rule_vector",
            {"repo_id": "r1", "capability": "secrets", "tool": "gitleaks",
             "rule_id": "generic-api-key", "template_id": "CWE-798"},
        )
    ).structured_content
    assert fake.calls == [("POST", "/api/dashboard/rule-vectors")]
    assert fake.body() == {
        "capability": "secrets",
        "tool": "gitleaks",
        "rule_id": "generic-api-key",
        "note": "",
        "repo_id": "r1",
        "template_id": "CWE-798",
    }
    assert out["governed_by"] is None
    assert "changes no score" in out["governed_by_means"]
    for name, args in EVERY_TOOL_CALL:
        fake = FakeMykronos()
        await _call(fake, name, args)
        assert not any("confirm" in path or "retire" in path for _, path in fake.calls), name


async def test_an_estate_wide_proposal_sends_no_repo() -> None:
    fake = FakeMykronos()
    await _call(
        fake,
        "propose_rule_vector",
        {"capability": "dast", "tool": "zap", "rule_id": "10202",
         "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"},
    )
    assert "repo_id" not in fake.body()
    assert "template_id" not in fake.body()


async def test_declare_control_names_its_surface_only_when_given() -> None:
    fake = FakeMykronos()
    await _call(
        fake,
        "declare_control",
        {"repo_id": "r1", "stride": "spoofing", "kind": "perimeter_gate",
         "applies_to_surface_id": "s-1"},
    )
    await _call(fake, "declare_control", {"repo_id": "r1", "stride": "spoofing",
                                          "kind": "waf"})
    assert fake.body(0)["applies_to_surface_id"] == "s-1"
    assert "applies_to_surface_id" not in fake.body(1)


async def test_an_invented_control_kind_is_refused_before_any_request() -> None:
    fake = FakeMykronos()
    result = await _call(
        fake, "declare_control", {"repo_id": "r1", "stride": "spoofing", "kind": "vibes"}
    )
    assert result.is_error
    assert fake.calls == []


async def test_accept_sends_the_routes_body() -> None:
    fake = FakeMykronos()
    out = (await _call(fake, "accept", ACCEPT_ARGS)).structured_content
    assert fake.calls == [("POST", "/api/risk-acceptances")]
    assert fake.body() == {
        "repo": "acme/api",
        "scope": {"capability": "containers", "image": "acme/api", "fixed_version": "absent"},
        "deviation_type": "vendor_dependency",
        "justification": "No fixed version is published for this package.",
        "residual_likelihood": "low",
        "residual_impact": "moderate",
        "risk_owner": "operator",
        "requested_until": "2026-12-01",
        "milestones": [{"title": "Rebuild on the patched base", "ends_weakness": True}],
        "premises": [],
        "compensating_controls": [],
        "response": "accept",
    }
    assert out["governed_by"] == "risk_acceptance"


@pytest.mark.parametrize(
    "missing", ["deviation_type", "requested_until", "risk_owner", "milestones", "justification"]
)
async def test_accept_cannot_skip_what_the_route_requires(missing: str) -> None:
    """#319: an `accept` that let an agent skip the reason code or the review
    date would quietly undo spec 24 §3.2."""
    fake = FakeMykronos()
    args = {k: v for k, v in ACCEPT_ARGS.items() if k != missing}
    result = await _call(fake, "accept", args)
    assert result.is_error
    assert fake.calls == []


async def test_accept_refuses_an_unknown_reason_code() -> None:
    fake = FakeMykronos()
    result = await _call(fake, "accept", {**ACCEPT_ARGS, "deviation_type": "indefinite"})
    assert result.is_error
    assert fake.calls == []


async def test_request_pr_review_sends_the_routes_body() -> None:
    fake = FakeMykronos()
    await _call(fake, "request_pr_review", {"repo": "acme/api", "number": 7, "statement": "s"})
    assert fake.calls == [("POST", "/api/approvals/pull-requests")]
    assert fake.body() == {"repo": "acme/api", "number": 7, "statement": "s"}


# -- errors ----------------------------------------------------------------------


async def test_a_refusal_comes_back_word_for_word_and_is_not_retried() -> None:
    detail = (
        "An agent may not set a high finding to 'false_positive' directly: closing a "
        "serious finding is a governed decision (#713)."
    )
    fake = FakeMykronos(
        {("POST", "/api/dashboard/triage/f1/claim"): httpx2.Response(403, json={"detail": detail})}
    )
    result = await _call(fake, "claim", {"finding_id": "f1"})
    assert result.is_error
    assert detail in _text(result)
    assert "HTTP 403" in _text(result)
    assert len(fake.requests) == 1


async def test_a_validation_refusal_is_readable() -> None:
    errors = [{"loc": ["body", "requested_until"], "msg": "Input should be a valid date"}]
    fake = FakeMykronos(
        {("POST", "/api/risk-acceptances"): httpx2.Response(422, json={"detail": errors})}
    )
    result = await _call(fake, "accept", ACCEPT_ARGS)
    assert "body.requested_until: Input should be a valid date" in _text(result)
    assert len(fake.requests) == 1


async def test_both_credentials_are_sent() -> None:
    fake = FakeMykronos()
    await _call(fake, "whoami", {})
    headers = fake.requests[0].headers
    assert headers["authorization"] == "Bearer mka_test"
    assert headers["x-hub-token"] == "gate-test"


# -- starting up -----------------------------------------------------------------


def test_no_agent_token_refuses_to_start() -> None:
    with pytest.raises(ConfigError, match="MYKRONOS_AGENT_TOKEN is not set"):
        Settings.from_env({})


def test_an_admin_token_refuses_to_start_before_it_is_sent() -> None:
    with pytest.raises(ConfigError, match="not an agent credential"):
        Settings.from_env({AGENT_TOKEN_ENV: "an-operator-admin-token"})


def test_localhost_is_refused() -> None:
    with pytest.raises(ConfigError, match="127.0.0.1"):
        Settings.from_env({AGENT_TOKEN_ENV: "mka_x", URL_ENV: "http://localhost:8100"})


def test_settings_default_and_strip() -> None:
    """#319: an unstripped newline is an HTTP 000 that looks like a dead token."""
    settings = Settings.from_env({AGENT_TOKEN_ENV: " mka_x\r\n", GATE_TOKEN_ENV: "g\n"})
    assert settings == Settings(url="http://127.0.0.1:8100", agent_token="mka_x", gate_token="g")


def _whoami(payload: dict[str, Any], status: int = 200) -> MykronosApi:
    fake = FakeMykronos(
        {("GET", "/api/agents/whoami"): httpx2.Response(status, json=payload)}
    )
    return MykronosApi(SETTINGS, transport=httpx2.MockTransport(fake))


async def test_whoami_must_say_agent() -> None:
    api = _whoami({"actor": "operator", "kind": "human", "role": "admin", "provenance": {}})
    with pytest.raises(ConfigError, match="not an agent"):
        await verify_agent(api)


async def test_a_rejected_credential_refuses_to_start_with_the_apis_words() -> None:
    api = _whoami({"detail": "Agent credential expired."}, status=401)
    with pytest.raises(ConfigError, match="Agent credential expired."):
        await verify_agent(api)


async def test_an_agent_is_accepted_as_itself() -> None:
    api = _whoami(
        {
            "actor": AGENT.actor,
            "kind": "agent",
            "role": "agent",
            "provenance": {"family": "claude-opus-5.5"},
        }
    )
    principal = await verify_agent(api)
    assert principal.actor == AGENT.actor
    assert principal.kind is ActorKind.AGENT
    assert principal.role is Role.AGENT


def test_the_entry_point_refuses_without_a_token(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv(AGENT_TOKEN_ENV, raising=False)
    assert entry.main() == 2
    assert "refused to start" in capsys.readouterr().err
