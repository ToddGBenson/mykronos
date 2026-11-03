"""Triage T7 (TheHub #60894): toxic combinations on the same entry point.

The built-in rules group findings by file or by repository. Neither is an
attacker's path: two findings in one repository may sit behind different
doors, and the file a CVE is reported in is a lockfile, never the handler.
A threat model's declared entry points say where the doors are, and
`surface_match` already places a finding inside one.

A chain is a declared internet-facing entry point plus an authentication
weakness plus a known-vulnerable component (or an injectable sink), every
member located inside that same entry point. These tests pin:

- a chain forms only when every member is inside the same internet-facing
  entry point, and the chain - entry point, then each link and why it
  qualifies - is shown wherever the combination is;
- an entry point that is internal, unknown or unlocated forms nothing, and the
  coverage report says the chain rules could not fire rather than that the
  estate is clean;
- a chain raises the risk decision through the existing toxic-combination
  term, and raises the work-queue rank of each member through its own term.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from sqlalchemy import select

from mykronos import toxic
from mykronos.config import get_settings
from mykronos.dashboard import RANK_INPUTS, DashboardQueries, rank_terms
from mykronos.db.models import RepoOnboarding, RepoSurface
from mykronos.oracle import OracleEngine, load_policy
from mykronos.patchwork import correlate
from mykronos.surface_match import normalize_selectors
from tests.conftest import (
    REPO,
    dependency_finding,
    finding_payload,
    issue_token,
    post_findings,
    post_scan,
)

AUTH_FILE = "backend/api/orders.py"
LOCKFILE = "backend/requirements.txt"


@pytest.fixture
def policy():
    return load_policy(get_settings().oracle_policy_path)


def row(
    finding_id: str,
    rule_id: str,
    capability: str,
    *,
    severity: str = "medium",
    entry_points: tuple[str, ...] = (),
    cwe_ids: tuple[str, ...] = (),
    title: str = "",
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "finding_id": finding_id,
        "rule_id": rule_id,
        "title": title or rule_id,
        "file_path": "",
        "capability": capability,
        "severity": severity,
        "cwe_ids": list(cwe_ids),
    }
    if entry_points:
        out[correlate.ENTRY_POINTS_KEY] = entry_points
    return out


def _chain_rules() -> tuple[correlate.CombinationRule, ...]:
    return correlate.ENTRY_POINT_CHAIN_RULES + correlate.BUILT_IN_RULES


class TestTheRule:
    """Pure detection: findings already placed in entry points."""

    def test_an_auth_weakness_and_a_vulnerable_component_on_one_entry_point_chain(
        self,
    ) -> None:
        auth = row("a1", "python.flask.missing-authz", "sast", cwe_ids=("CWE-862",),
                   entry_points=("ep-api",))
        cve = row("c1", "CVE-2024-4812", "atlas", severity="high", entry_points=("ep-api",))

        [combo] = correlate.detect([auth, cve], _chain_rules())

        assert combo.rule_id == "entry-point-unauth-vulnerable-component"
        assert combo.entry_point == "ep-api"
        assert combo.finding_ids == frozenset({"a1", "c1"})
        why = dict(combo.qualifications)
        assert "CWE-862" in why["a1"]
        assert "CVE-2024-4812" in why["c1"]

    def test_members_behind_different_entry_points_do_not_chain(self) -> None:
        auth = row("a1", "CWE-306", "sast", entry_points=("ep-api",))
        cve = row("c1", "CVE-2024-4812", "atlas", severity="high", entry_points=("ep-admin",))

        assert correlate.detect([auth, cve], _chain_rules()) == []

    def test_a_finding_in_no_entry_point_does_not_chain(self) -> None:
        auth = row("a1", "CWE-306", "sast", entry_points=("ep-api",))
        cve = row("c1", "CVE-2024-4812", "atlas", severity="high")

        assert correlate.detect([auth, cve], _chain_rules()) == []

    def test_a_low_cve_is_not_a_vulnerable_component(self) -> None:
        auth = row("a1", "CWE-306", "sast", entry_points=("ep-api",))
        cve = row("c1", "CVE-2024-4812", "atlas", severity="low", entry_points=("ep-api",))

        assert correlate.detect([auth, cve], _chain_rules()) == []

    def test_an_auth_weakness_and_an_injectable_sink_chain(self) -> None:
        auth = row("a1", "CWE-287", "sast", entry_points=("ep-api",))
        sink = row("s1", "python.sqli", "sast", cwe_ids=("CWE-89",), entry_points=("ep-api",))

        [combo] = correlate.detect([auth, sink], _chain_rules())

        assert combo.rule_id == "entry-point-unauth-injection"

    def test_a_route_naming_auth_does_not_qualify_a_dast_alert(self) -> None:
        """The #60965 lesson: a ZAP title ends with the route, so a header
        alert on `/auth/login` must not read as an authentication weakness."""
        header = row(
            "d1", "ZAP-10038-CWE-693", "dast",
            title="Content Security Policy (CSP) Header Not Set at GET /auth/login",
            entry_points=("ep-api",),
        )
        cve = row("c1", "CVE-2024-4812", "containers", severity="high", entry_points=("ep-api",))

        assert correlate.detect([header, cve], _chain_rules()) == []

    def test_the_built_in_rules_never_read_entry_points(self) -> None:
        """Patchwork calls `detect` with the built-in rules; adding chains must
        not change what it sees."""
        auth = row("a1", "CWE-306", "sast", cwe_ids=("CWE-306",), entry_points=("ep-api",))
        cve = row("c1", "CVE-2024-4812", "atlas", severity="high", entry_points=("ep-api",))

        assert correlate.detect([auth, cve]) == []

    def test_a_chain_takes_its_members_before_a_pair_does(self) -> None:
        """A finding is in at most one combination; the chain, which knows
        the way in, is the one that claims it."""
        auth = row("a1", "CWE-306", "sast", entry_points=("ep-api",))
        sink = row("s1", "CWE-89", "sast", entry_points=("ep-api",))
        for f in (auth, sink):
            f["file_path"] = AUTH_FILE

        combos = correlate.detect([auth, sink], _chain_rules())

        assert [c.rule_id for c in combos] == ["entry-point-unauth-injection"]


# ---------------------------------------------------------------------------
# Through the lake, the threat model and the decision
# ---------------------------------------------------------------------------


def _surface(
    db: Any,
    *,
    exposure: str = "internet",
    selectors: dict[str, list[str]] | None = None,
    name: str = "Public API",
    declared_by: str = "manifest",
) -> None:
    with db.session() as session:
        session.add(
            RepoSurface(
                id=str(uuid.uuid4()),
                repo_full_name=REPO,
                kind="entry_point",
                name=name,
                exposure=exposure,
                sensitivity="unknown",
                evidence_ref="backend/api/routes.py",
                selectors=normalize_selectors(
                    selectors if selectors is not None else {"paths": ["backend/**"]}
                ),
                manifest_key="public-api" if declared_by == "manifest" else None,
                declared_by=declared_by,
            )
        )


def _post(client, auth, capability: str, payload: dict[str, Any]) -> None:
    if capability != "sast":
        auth = {"Authorization": f"Bearer {issue_token(client, REPO, capability)}"}
    run = str(uuid.uuid4())
    post_scan(client, auth, scan_run_id=run, capability=capability)
    response = post_findings(client, auth, [payload], scan_run_id=run, capability=capability)
    assert response.status_code in (200, 201), response.text


def _seed_code_chain(client, auth, run_compaction, *, cve_severity: str = "high") -> None:
    _post(
        client, auth, "sast",
        finding_payload(
            rule_id="python.flask.security.missing-authorization",
            title="Route handler performs no authorization check",
            severity="medium", file_path=AUTH_FILE, cwe_ids=["CWE-862"],
        ),
    )
    _post(
        client, auth, "atlas",
        dependency_finding(severity=cve_severity, file_path=LOCKFILE),
    )
    run_compaction()


class TestDetectionReadsTheThreatModel:
    def test_the_chain_is_shown_entry_point_first(
        self, client, auth, run_compaction, catalog
    ) -> None:
        db = client.app.state.db
        _surface(db)
        _seed_code_chain(client, auth, run_compaction)

        with db.session() as session:
            [combo] = toxic.detect(catalog, repo=REPO, session=session)

        assert combo.rule_id == "entry-point-unauth-vulnerable-component"
        chain = combo.to_dict()["chain"]
        assert chain["entry_point"]["name"] == "Public API"
        assert chain["entry_point"]["exposure"] == "internet"
        assert chain["entry_point"]["declared_via"] == "manifest"
        assert chain["entry_point"]["evidence_ref"] == "backend/api/routes.py"
        steps = [link["step"] for link in chain["links"]]
        assert steps == ["entry_point", "auth_weakness", "vulnerable_component"]
        auth_link, component_link = chain["links"][1], chain["links"][2]
        assert auth_link["file_path"] == AUTH_FILE
        assert auth_link["located_by"] == "paths `backend/**`"
        assert "CWE-862" in auth_link["qualifies"]
        assert component_link["rule_id"] == "CVE-2024-4812"
        assert "Public API" in combo.rationale

    def test_dast_and_an_image_chain_on_the_hostname_and_image_they_declare(
        self, client, auth, run_compaction, catalog
    ) -> None:
        db = client.app.state.db
        _surface(
            db,
            selectors={
                "hostnames": ["pay.example.net"],
                "images": ["ghcr.io/example-org/payments-api"],
            },
        )
        _post(
            client, auth, "dast",
            finding_payload(
                rule_id="ZAP-10105-CWE-287", title="Weak Authentication Method at GET /login",
                severity="medium", file_path=None, line_start=None, line_end=None,
                symbol=None, code_snippet=None,
                raw_finding_json={"instance": {"uri": "https://pay.example.net/login"}},
            ),
        )
        _post(
            client, auth, "containers",
            dependency_finding(
                severity="critical", file_path="ghcr.io/example-org/payments-api:1.4",
                raw_finding_json={"image": "ghcr.io/example-org/payments-api:1.4"},
            ),
        )
        run_compaction()

        with db.session() as session:
            [combo] = toxic.detect(catalog, repo=REPO, session=session)

        links = combo.to_dict()["chain"]["links"]
        assert links[1]["capability"] == "dast"
        assert links[1]["located_by"] == "hostnames `pay.example.net`"
        assert links[2]["located_by"] == "images `ghcr.io/example-org/payments-api`"

    @pytest.mark.parametrize("exposure", ["internal", "local", "unknown"])
    def test_an_entry_point_not_declared_internet_facing_forms_nothing(
        self, client, auth, run_compaction, catalog, exposure
    ) -> None:
        db = client.app.state.db
        _surface(db, exposure=exposure)
        _seed_code_chain(client, auth, run_compaction)

        with db.session() as session:
            assert toxic.detect(catalog, repo=REPO, session=session) == []

    def test_an_entry_point_with_no_selectors_locates_nothing(
        self, client, auth, run_compaction, catalog
    ) -> None:
        db = client.app.state.db
        _surface(db, selectors={})
        _seed_code_chain(client, auth, run_compaction)

        with db.session() as session:
            assert toxic.detect(catalog, repo=REPO, session=session) == []

    def test_coverage_says_the_chain_rules_cannot_fire_without_an_entry_point(
        self, client, auth, run_compaction, catalog
    ) -> None:
        db = client.app.state.db
        _seed_code_chain(client, auth, run_compaction)

        with db.session() as session:
            report = toxic.coverage(catalog, session=session)
        dark = {r["rule_id"]: r["missing"] for r in report["cannot_fire"]}
        assert dark["entry-point-unauth-vulnerable-component"] == [
            "internet-facing entry point"
        ]
        assert report["rules"] == len(correlate.BUILT_IN_RULES) + len(
            correlate.ENTRY_POINT_CHAIN_RULES
        )

        _surface(db)
        with db.session() as session:
            report = toxic.coverage(catalog, session=session)
        live = {r["rule_id"] for r in report["can_fire"]}
        assert "entry-point-unauth-vulnerable-component" in live

    def test_the_estate_endpoint_shows_the_chain(
        self, client, auth, admin_auth, run_compaction
    ) -> None:
        _surface(client.app.state.db)
        _seed_code_chain(client, auth, run_compaction)

        body = client.get("/api/dashboard/toxic-combinations", headers=admin_auth).json()

        [combo] = body["combinations"]
        assert combo["chain"]["entry_point"]["name"] == "Public API"
        live = {r["rule_id"] for r in body["coverage"]["can_fire"]}
        assert "entry-point-unauth-vulnerable-component" in live

    def test_the_vulnerability_management_page_shows_the_chain(
        self, client, auth, admin_auth, run_compaction
    ) -> None:
        _surface(client.app.state.db)
        _seed_code_chain(client, auth, run_compaction)

        page = client.get(
            "/api/dashboard/vulnerability-management", headers=admin_auth
        ).json()

        [combo] = page["toxic_combination_list"]
        assert combo["chain"]["links"][0]["step"] == "entry_point"


class TestTheRiskDecision:
    def _terms(self, decision) -> dict[str, float]:
        return {t["key"]: t["contribution"] for t in decision.inputs_snapshot["terms"]}

    def test_without_the_entry_point_the_pair_is_not_a_combination(
        self, client, auth, run_compaction, catalog, policy
    ) -> None:
        _seed_code_chain(client, auth, run_compaction)

        decision = OracleEngine(catalog, policy, db=client.app.state.db).evaluate(REPO)

        assert decision.inputs_snapshot["toxic_combinations"]["count"] == 0
        assert "toxic_combination_no_go" not in self._terms(decision)

    def test_a_chain_raises_the_decision_and_names_its_entry_point(
        self, client, auth, run_compaction, catalog, policy
    ) -> None:
        _seed_code_chain(client, auth, run_compaction)
        before = OracleEngine(catalog, policy, db=client.app.state.db).evaluate(REPO)
        _surface(client.app.state.db)

        decision = OracleEngine(catalog, policy, db=client.app.state.db).evaluate(REPO)

        snap = decision.inputs_snapshot["toxic_combinations"]
        [combo] = snap["combinations"]
        # A high component behind a medium auth weakness: one band above the
        # worst member, so critical, which forces no_go.
        assert combo["severity"] == "critical"
        assert combo["entry_point"] == "Public API"
        assert [link["step"] for link in combo["chain"]["links"]] == [
            "entry_point", "auth_weakness", "vulnerable_component",
        ]
        assert decision.recommendation == "no_go"
        assert decision.overall_risk_score > before.overall_risk_score
        assert "toxic_combination_no_go" in self._terms(decision)

    def test_a_medium_chain_adds_points_without_forcing_no_go(
        self, client, auth, run_compaction, catalog, policy
    ) -> None:
        _surface(client.app.state.db)
        _post(
            client, auth, "sast",
            finding_payload(rule_id="CWE-306", title="Missing authentication",
                            severity="low", file_path=AUTH_FILE),
        )
        _post(
            client, auth, "sast",
            finding_payload(rule_id="CWE-89", title="SQL injection", severity="low",
                            file_path="backend/db/query.py"),
        )
        run_compaction()

        decision = OracleEngine(catalog, policy, db=client.app.state.db).evaluate(REPO)

        [combo] = decision.inputs_snapshot["toxic_combinations"]["combinations"]
        assert combo["rule_id"] == "entry-point-unauth-injection"
        assert combo["severity"] == "medium"
        assert self._terms(decision)["toxic_combinations"] == pytest.approx(
            policy.toxic_combinations.points["medium"]
        )


def _activate(client, admin_auth) -> None:
    from tests.test_onboarding import onboard

    onboard(client, admin_auth)
    with client.app.state.db.session() as session:
        for onboarding in session.scalars(select(RepoOnboarding)):
            onboarding.status = "active"


class TestTheRank:
    def _item(self, **overrides: Any) -> dict[str, Any]:
        item: dict[str, Any] = {"severity": "medium"}
        item.update(overrides)
        return item

    def test_the_term_is_declared_and_weighted_in_policy(self, policy) -> None:
        assert "toxic_chain" in RANK_INPUTS
        assert policy.triage_rank.entry_point_chain > 0

    def test_a_chain_member_ranks_above_the_same_finding_alone(self, policy) -> None:
        chain = {
            "combination_id": "x", "name": "Unauthenticated way in to a known-vulnerable "
            "component", "entry_point": "Public API", "severity": "critical",
        }
        alone, _ = rank_terms(self._item(), policy)
        linked, terms = rank_terms(self._item(entry_point_chain=chain), policy)

        assert linked - alone == policy.triage_rank.entry_point_chain
        [term] = [t for t in terms if t["key"] == "toxic_chain"]
        assert "Public API" in term["detail"]

    def test_the_queue_ranks_chain_members_by_it(
        self, client, auth, admin_auth, run_compaction
    ) -> None:
        db = client.app.state.db
        _activate(client, admin_auth)
        _surface(db)
        _seed_code_chain(client, auth, run_compaction)

        response = client.get(
            "/api/dashboard/triage", params={"order": "rank"}, headers=admin_auth
        )

        assert response.status_code == 200, response.text
        items = response.json()["items"]
        assert items, "the seeded findings should be queued"
        for item in items:
            keys = {t["key"] for t in item["rank_terms"]}
            assert "toxic_chain" in keys, item["rule_id"]

    def test_the_queue_without_entry_points_has_no_chain_term(
        self, client, auth, admin_auth, run_compaction
    ) -> None:
        _activate(client, admin_auth)
        _seed_code_chain(client, auth, run_compaction)

        items = client.get(
            "/api/dashboard/triage", params={"order": "rank"}, headers=admin_auth
        ).json()["items"]

        assert items
        assert all("toxic_chain" not in {t["key"] for t in i["rank_terms"]} for i in items)


def test_the_vulnerability_management_query_still_works_without_a_session(catalog) -> None:
    """Callers that have no session get the built-in rules, as before."""
    assert DashboardQueries(catalog).vulnerability_management()["toxic_combinations"] == 0
