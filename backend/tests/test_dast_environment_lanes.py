"""Each DAST environment is its own lane and its own identity (TheHub #60723, D-155).

TheHub's three LAN lanes -- `dast-demo`, `dast-prod`, `dast-staging` -- all
uploaded as `zap`, and the ZAP adapter keys a finding on the route alone. So a
route all three serve was one finding, and absence reconciliation, which
partitions on `(repo, capability, branch, tool)`, saw one lane: two prod runs
closed a staging-only finding as `fixed` and the next staging run reopened it.

Each lane now uploads under its own tool, and the environment is the finding's
symbol. The decisions made about the old shared identity move to the new ones
by D-139's exact link: at ingestion, and then `carry_forward` withdraws the old
row once every environment has had its chance to claim it.

Findings here come out of the real adapter, from a ZAP report, rather than
being written by hand -- the identity under test is the adapter's.
"""

from __future__ import annotations

import json
import re
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import yaml

from mykronos.adapters import ScanContext, supported_tools
from mykronos.adapters.dast_zap import normalize as zap_normalize
from mykronos.adapters.registry import get_adapter
from mykronos.fingerprint import (
    DAST_ENVIRONMENT_TOOLS,
    FINGERPRINT_V2_SNIPPET,
    FINGERPRINT_V3_ROUTE_ENV,
    LANE_SUCCESSORS,
    compute_finding_id,
    identity_rule_of,
    v2_predecessor_id,
)
from mykronos.lake import carry_forward, reconcile_absences
from tests.conftest import ADMIN_TOKEN, REPO, issue_token, post_findings, post_scan

ROOT = Path(__file__).resolve().parents[2]
PIPELINE = ROOT / "deploy" / "concourse" / "pipelines" / "thehub.yml"
BRANCH = "develop"
_RUNS = iter(range(1, 10_000))


def _report(*routes: str, host: str = "http://192.168.0.14:8081") -> bytes:
    """A ZAP baseline report with one CSP alert on each route."""
    alert = {
        "pluginid": "10038",
        "alertRef": "10038",
        "alert": "Content Security Policy Header Not Set",
        "riskcode": "2",
        "cweid": "693",
        "desc": "No CSP header.",
        "instances": [{"uri": f"{host}{route}?v=abc", "method": "GET"} for route in routes],
    }
    return json.dumps({"site": [{"@name": host, "alerts": [alert]}]}).encode()


def _context(tool: str) -> ScanContext:
    return ScanContext(
        repo_full_name=REPO,
        capability="dast",
        tool_name=tool,
        tool_version="",
        commit_sha="abc123",
        branch=BRANCH,
    )


def _findings(tool: str, *routes: str) -> list[Any]:
    return zap_normalize(_report(*routes), _context(tool)).findings


def _id(finding: Any) -> str:
    return compute_finding_id(
        repo_full_name=REPO,
        capability="dast",
        rule_id=finding.rule_id,
        file_path=finding.file_path,
        symbol=finding.symbol,
        code_snippet=finding.code_snippet,
        line_start=finding.line_start,
        identity_rule=identity_rule_of(finding.raw_finding_json),
    )[0]


# ---------------------------------------------------------------------------
# The adapter
# ---------------------------------------------------------------------------


class TestTheAdapter:
    def test_each_environment_is_a_registered_dast_tool(self) -> None:
        assert {"zap", "zap-demo", "zap-prod", "zap-staging"} <= set(supported_tools("dast"))
        for tool in DAST_ENVIRONMENT_TOOLS:
            assert get_adapter("dast", tool).normalize is zap_normalize

    def test_the_environment_is_the_symbol_and_the_route_is_unchanged(self) -> None:
        finding = _findings("zap-staging", "/frontend/app.js")[0]

        assert finding.symbol == "staging"
        assert finding.file_path == "/frontend/app.js"
        assert finding.code_snippet == "GET /frontend/app.js"

    def test_one_route_in_three_environments_is_three_findings(self) -> None:
        ids = {_id(_findings(tool, "/")[0]) for tool in DAST_ENVIRONMENT_TOOLS}
        assert len(ids) == 3

    def test_the_host_is_not_identity(self) -> None:
        """A port that moves must not re-key the environment's findings (#274)."""
        staging = _context("zap-staging")
        before = zap_normalize(_report("/", host="http://192.168.0.14:8081"), staging)
        after = zap_normalize(_report("/", host="http://192.168.0.14:8091"), staging)
        assert _id(before.findings[0]) == _id(after.findings[0])

    def test_plain_zap_is_unchanged(self) -> None:
        """`mykronos.yml` still uploads as `zap`; its identities must not move."""
        finding = _findings("zap", "/")[0]

        assert finding.symbol is None
        assert identity_rule_of(finding.raw_finding_json) is None
        assert compute_finding_id(
            repo_full_name=REPO,
            capability="dast",
            rule_id=finding.rule_id,
            file_path=finding.file_path,
            code_snippet=finding.code_snippet,
        )[1] == FINGERPRINT_V2_SNIPPET

    def test_the_predecessor_is_the_id_the_finding_had_as_zap(self) -> None:
        old = _findings("zap", "/admin")[0]
        new = _findings("zap-prod", "/admin")[0]

        assert compute_finding_id(
            repo_full_name=REPO,
            capability="dast",
            rule_id=new.rule_id,
            file_path=new.file_path,
            symbol=new.symbol,
            code_snippet=new.code_snippet,
            identity_rule=identity_rule_of(new.raw_finding_json),
        )[1] == FINGERPRINT_V3_ROUTE_ENV
        assert v2_predecessor_id(
            repo_full_name=REPO,
            capability="dast",
            rule_id=new.rule_id,
            file_path=new.file_path,
            symbol=new.symbol,
            code_snippet=new.code_snippet,
            line_start=new.line_start,
            raw_finding_json=new.raw_finding_json,
        ) == _id(old)


class TestTheWiring:
    def test_the_old_lane_is_succeeded_by_every_environment(self) -> None:
        assert set(LANE_SUCCESSORS["zap"]) == set(DAST_ENVIRONMENT_TOOLS)

    def test_each_thehub_lane_uploads_under_its_own_environment(self) -> None:
        jobs = {j["name"]: j for j in yaml.safe_load(PIPELINE.read_text(encoding="utf-8"))["jobs"]}
        tools = {}
        for name in ("dast-demo", "dast-prod", "dast-staging"):
            text = yaml.safe_dump(jobs[name], width=10_000)
            tools[name] = re.findall(r"--capability dast --tool (\S+)", text)
        assert tools == {
            "dast-demo": ["zap-demo"],
            "dast-prod": ["zap-prod"],
            "dast-staging": ["zap-staging"],
        }

    def test_the_pin_check_requires_the_new_tools(self) -> None:
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "check_pinned_ref", ROOT / "scripts" / "check_pinned_ref.py"
        )
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        required = set(module.REQUIRED_ADAPTERS)
        assert {("dast", tool) for tool in DAST_ENVIRONMENT_TOOLS} <= required


# ---------------------------------------------------------------------------
# The lake
# ---------------------------------------------------------------------------


def _scan(client: Any, token: str, tool: str, *routes: str) -> str:
    """One successful scan of `tool`'s lane, findings from the real adapter.

    `zap` posts what the adapter produces for plain `zap` -- the identity every
    existing TheHub DAST finding has.
    """
    run_id = f"00000000-0000-0000-0000-{next(_RUNS):012d}"
    headers = {"Authorization": f"Bearer {token}"}
    response = post_scan(
        client,
        headers,
        scan_run_id=run_id,
        capability="dast",
        tool_name=tool,
        branch=BRANCH,
        scan_status="success",
        pr_number=None,
        triggered_by="push",
    )
    assert response.status_code == 200, response.text
    payload = [f.model_dump(mode="json") for f in _findings(tool, *routes)]
    response = post_findings(client, headers, payload, scan_run_id=run_id, capability="dast")
    assert response.status_code == 200, response.text
    return run_id


def _rows(catalog: Any, route: str) -> dict[str | None, dict[str, Any]]:
    """Every row on `route`, keyed by its symbol (the environment)."""
    columns = ("finding_id", "status", "symbol", "first_seen_at", "superseded_by",
               "superseded_source", "accepted_reason_code")
    return {
        row[2]: dict(zip(columns, row, strict=True))
        for row in catalog.query(
            f"SELECT {', '.join(columns)} FROM findings WHERE file_path = ?", [route]
        )
    }


def _dispose(client: Any, finding_id: str, status: str = "false_positive") -> None:
    response = client.patch(
        f"/api/dashboard/findings/{finding_id}/status",
        json={"status": status, "reason": "the CSP is set by the reverse proxy"},
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
    )
    assert response.status_code == 200, response.text


class TestTheLanesAreSeparate:
    def test_a_staging_only_finding_stays_open_across_prod_and_demo_runs(
        self, client, catalog, run_compaction
    ) -> None:
        """The story's defect. Before, two prod runs closed it as `fixed`."""
        token = issue_token(client, REPO, "dast")
        _scan(client, token, "zap-staging", "/", "/staging-only")
        run_compaction()

        for tool in ("zap-prod", "zap-demo", "zap-prod", "zap-demo"):
            _scan(client, token, tool, "/")
            run_compaction()
        reconcile_absences(catalog)

        assert _rows(catalog, "/staging-only")["staging"]["status"] == "open"

    def test_staging_can_still_close_its_own_finding(
        self, client, catalog, run_compaction
    ) -> None:
        """Separating the lanes is worthless if it means nothing ever closes."""
        token = issue_token(client, REPO, "dast")
        _scan(client, token, "zap-staging", "/", "/staging-only")
        run_compaction()
        for _ in range(2):
            _scan(client, token, "zap-staging", "/")
            run_compaction()
        reconcile_absences(catalog)

        assert _rows(catalog, "/staging-only")["staging"]["status"] == "fixed"

    def test_a_route_fixed_in_one_environment_stays_open_in_another(
        self, client, catalog, run_compaction
    ) -> None:
        token = issue_token(client, REPO, "dast")
        _scan(client, token, "zap-staging", "/", "/admin")
        _scan(client, token, "zap-prod", "/", "/admin")
        run_compaction()
        for _ in range(2):
            _scan(client, token, "zap-staging", "/")
            run_compaction()
        reconcile_absences(catalog)

        rows = _rows(catalog, "/admin")
        assert rows["staging"]["status"] == "fixed"
        assert rows["prod"]["status"] == "open"


class TestDispositionsCarryAcrossTheChange:
    def test_a_decision_on_the_shared_finding_reaches_every_environment(
        self, client, catalog, run_compaction
    ) -> None:
        """One route all three lanes served was one finding, and the decision
        about it was about all three. Each environment inherits it as it first
        uploads, and the old row is withdrawn only after all three have."""
        token = issue_token(client, REPO, "dast")
        _scan(client, token, "zap", "/")
        run_compaction()
        old = _rows(catalog, "/")[None]
        _dispose(client, old["finding_id"])

        _scan(client, token, "zap-prod", "/")
        run_compaction()
        rows = _rows(catalog, "/")
        assert rows["prod"]["status"] == "false_positive"
        assert rows["prod"]["first_seen_at"] == old["first_seen_at"]

        # Staging and demo have not scanned since: they may still claim it, and
        # they can only inherit from a predecessor that is still live.
        carry_forward(catalog)
        assert _rows(catalog, "/")[None]["status"] == "false_positive"

        _scan(client, token, "zap-staging", "/")
        _scan(client, token, "zap-demo", "/")
        run_compaction()
        result = carry_forward(catalog)

        rows = _rows(catalog, "/")
        for environment in ("demo", "prod", "staging"):
            assert rows[environment]["status"] == "false_positive", environment
            assert rows[environment]["first_seen_at"] == old["first_seen_at"]
        assert rows[None]["status"] == "superseded"
        assert rows[None]["superseded_by"] == rows["demo"]["finding_id"]
        assert rows[None]["superseded_source"] == "carry_forward"
        assert {c.to_finding_id for c in result.carried} == {
            rows[e]["finding_id"] for e in ("demo", "prod", "staging")
        }
        assert all(c.exact for c in result.carried)
        assert not result.stranded

        # Idempotent: a second pass has nothing left to do.
        assert not carry_forward(catalog).carried

    def test_an_acceptance_carries_with_its_reason(
        self, client, catalog, run_compaction
    ) -> None:
        token = issue_token(client, REPO, "dast")
        _scan(client, token, "zap", "/admin")
        run_compaction()
        old = _rows(catalog, "/admin")[None]
        response = client.patch(
            f"/api/dashboard/findings/{old['finding_id']}/status",
            json={
                "status": "accepted_risk",
                "reason": "LAN only",
                "accepted_reason_code": "no_vendor_fix",
                "accepted_until": (date.today() + timedelta(days=30)).isoformat(),
            },
            headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
        )
        assert response.status_code == 200, response.text
        old = _rows(catalog, "/admin")[None]

        _scan(client, token, "zap-staging", "/admin")
        run_compaction()

        staging = _rows(catalog, "/admin")["staging"]
        assert staging["status"] == "accepted_risk"
        assert staging["accepted_reason_code"] == old["accepted_reason_code"]

    def test_an_environment_that_never_saw_it_is_not_given_it(
        self, client, catalog, run_compaction
    ) -> None:
        """Only an environment that reports the route claims the old row."""
        token = issue_token(client, REPO, "dast")
        _scan(client, token, "zap", "/staging-only")
        run_compaction()
        _dispose(client, _rows(catalog, "/staging-only")[None]["finding_id"])

        _scan(client, token, "zap-staging", "/staging-only")
        _scan(client, token, "zap-prod", "/")
        _scan(client, token, "zap-demo", "/")
        run_compaction()
        carry_forward(catalog)

        rows = _rows(catalog, "/staging-only")
        assert set(rows) == {None, "staging"}
        assert rows["staging"]["status"] == "false_positive"
        assert rows[None]["status"] == "superseded"
