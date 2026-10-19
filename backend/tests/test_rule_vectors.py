"""Analyst-confirmed rule vectors for findings with no CVE (TheHub #60832, D3).

The properties the story rests on, each pinned:

- a proposal (from a template or by hand) never changes any score;
- a confirmation does, through the same resolver, with provenance;
- an agent principal can propose and cannot confirm, at the route and in the
  module;
- a retired vector stops applying;
- a published vector (NVD) always beats an analyst's.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient
from sqlalchemy import select

from mykronos import cvss, environment, rule_vectors
from mykronos.adminauth import ActorKind, Principal, Role
from mykronos.db.models import AuditLogEntry, EnvironmentalScore, RuleVector, ThreatIntelMatch
from mykronos.db.session import Database
from tests.conftest import REPO, finding_payload, issue_token, post_findings, post_scan
from tests.test_onboarding import onboard

ROOT = Path(__file__).resolve().parents[2]
TEMPLATE_PATH = ROOT / "cwe-vector-templates-v1.yaml"
TEMPLATES = rule_vectors.load_templates(TEMPLATE_PATH)
POLICY = environment.load_policy(ROOT / "environment-map-v1.yaml")
NOW = datetime(2026, 10, 18, 12, 0, 0)
CVE = "CVE-2024-0001"
CRITICAL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # 9.8
XSS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"  # 6.1
RULE = "python.flask.security.xss.direct-use-of-jinja2"

PERSON = Principal(actor="alice", role=Role.ADMIN, kind=ActorKind.HUMAN)
AGENT = Principal(actor="agent:claude:abc", role=Role.AGENT, kind=ActorKind.AGENT)
AUTOMATION = Principal(actor="job:environment", role=Role.ADMIN, kind=ActorKind.AUTOMATION)

_OPEN: list[Database] = []


@pytest.fixture(autouse=True)
def _clean() -> Iterator[None]:
    environment.clear()
    yield
    environment.clear()
    while _OPEN:
        _OPEN.pop().close()


def _db(tmp_path: Path) -> Database:
    db = Database(f"sqlite:///{(tmp_path / 'rv.db').as_posix()}")
    _OPEN.append(db)
    db.create_all()
    with db.session() as session:
        session.add(ThreatIntelMatch(cve_id=CVE, cvss_vector=CRITICAL))
    return db


def finding(**overrides: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "finding_id": "s" * 64,
        "capability": "sast",
        "tool": "semgrep",
        "rule_id": RULE,
        "title": "Direct use of jinja2",
        "severity": "medium",
        "file_path": "src/app.py",
        "address": None,
        "port": None,
        "cwe_ids_json": '["CWE-79"]',
        "raw_finding_json": None,
        "last_seen_at": NOW,
    }
    values.update(overrides)
    return values


def _inject(monkeypatch: pytest.MonkeyPatch, findings: list[dict[str, Any]]) -> None:
    monkeypatch.setattr(environment, "open_findings", lambda catalog, repo: findings)


def _propose(db: Database, **overrides: Any) -> str:
    values: dict[str, Any] = {
        "repo_full_name": REPO,
        "capability": "sast",
        "tool": "semgrep",
        "rule_id": RULE,
        "asserted_by": "agent:claude:abc",
        "template_id": "CWE-79",
        "templates": TEMPLATES,
        "now": NOW,
    }
    values.update(overrides)
    with db.session() as session:
        return rule_vectors.propose(session, **values).id


def _confirm(db: Database, row_id: str, principal: Principal = PERSON, **kw: Any) -> None:
    with db.session() as session:
        rule_vectors.confirm(session, row_id, principal=principal, now=NOW, **kw)


def _rescore(db: Database) -> environment.RescoreResult:
    return environment.rescore(db, None, REPO, now=NOW, policy=POLICY)


def _stored(db: Database, finding_id: str = "s" * 64) -> EnvironmentalScore | None:
    with db.session() as session:
        row = session.get(EnvironmentalScore, finding_id)
        if row is not None:
            session.expunge(row)
        return row


# ---------------------------------------------------------------------------
# The template file
# ---------------------------------------------------------------------------


class TestTemplates:
    STARTER = {
        "CWE-79", "CWE-89", "CWE-78", "CWE-22", "CWE-798", "CWE-352",
        "CWE-611", "CWE-918", "CWE-502", "CWE-287", "CWE-862", "CWE-200",
    }

    def test_the_starter_set_is_all_there(self) -> None:
        assert set(TEMPLATES.templates) >= self.STARTER

    def test_every_vector_is_a_base_only_31_vector_and_its_stated_score_is_true(self) -> None:
        raw = yaml.safe_load(TEMPLATE_PATH.read_text(encoding="utf-8"))
        for cwe, entry in raw["templates"].items():
            assert rule_vectors.normalize_vector(entry["vector"]) == entry["vector"], cwe
            assert cvss.score(entry["vector"]).base == entry["base_score"], cwe
            assert len(entry["rationale"].split()) >= 15, f"{cwe} needs a rationale"

    def test_secrets_without_a_cwe_is_pre_filled_as_hard_coded_credentials(self) -> None:
        suggested = TEMPLATES.suggest([], "secrets")
        assert suggested is not None and suggested.cwe == "CWE-798"
        assert TEMPLATES.suggest([], "dast") is None

    def test_the_lowest_numbered_cwe_with_a_template_is_suggested(self) -> None:
        suggested = TEMPLATES.suggest(["CWE-89", "79", "CWE-99999"], "sast")
        assert suggested is not None and suggested.id == "cwe-vector-templates-v1:CWE-79"

    def test_an_unreadable_file_pre_fills_nothing(self, tmp_path: Path) -> None:
        assert rule_vectors.load_templates(tmp_path / "missing.yaml").templates == {}

    def test_a_template_with_an_environmental_metric_is_refused(self) -> None:
        with pytest.raises(rule_vectors.RuleVectorError):
            rule_vectors.parse_templates(
                {"templates": {"CWE-79": {"vector": XSS + "/MAV:L", "base_score": 6.1}}}
            )


class TestVectorValidation:
    @pytest.mark.parametrize(
        "vector",
        [
            "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 3.1 only (D1)
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",  # missing A
            XSS + "/CR:H",  # environment is the resolver's
            XSS + "/E:F",  # no temporal on a rule
            XSS + "/AV:L",  # repeated
            "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "",
        ],
    )
    def test_refused(self, vector: str) -> None:
        with pytest.raises(rule_vectors.RuleVectorError):
            rule_vectors.normalize_vector(vector)

    def test_reordered_metrics_are_put_in_canonical_order(self) -> None:
        shuffled = "CVSS:3.1/S:C/AV:N/AC:L/PR:N/UI:R/C:L/I:L/A:N"
        assert rule_vectors.normalize_vector(shuffled) == XSS


# ---------------------------------------------------------------------------
# Scoring: the properties the story is about
# ---------------------------------------------------------------------------


class TestAProposalNeverChangesAScore:
    def test_a_template_proposal_leaves_the_finding_unscored(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db = _db(tmp_path)
        _inject(monkeypatch, [finding()])
        before = _rescore(db)
        _propose(db)
        after = _rescore(db)
        assert (before.scored, before.unscored) == (0, 1)
        assert (after.scored, after.unscored) == (0, 1)
        assert _stored(db) is None
        with db.session() as session:
            assert environment.choose_vectors(session, [finding()], repo_full_name=REPO) == {}

    def test_a_proposal_beside_a_confirmed_vector_does_not_replace_it(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db = _db(tmp_path)
        _inject(monkeypatch, [finding()])
        _confirm(db, _propose(db))
        _rescore(db)
        _propose(db, template_id=None, vector=CRITICAL)
        _rescore(db)
        stored = _stored(db)
        assert stored is not None and stored.vector == XSS and stored.base == 6.1


class TestConfirmationScoresWithProvenance:
    def test_a_confirmed_vector_is_scored_through_the_same_resolver(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db = _db(tmp_path)
        _inject(monkeypatch, [finding()])
        row_id = _propose(db)
        _confirm(db, row_id)
        result = _rescore(db)
        assert (result.scored, result.unscored) == (1, 0)
        stored = _stored(db)
        assert stored is not None
        assert (stored.vector, stored.vector_version, stored.vector_source) == (
            XSS, "3.1", "analyst",
        )
        assert stored.vector_ref == row_id
        assert stored.base == 6.1
        with db.session() as session:
            row = session.get(RuleVector, row_id)
            assert row is not None
            assert (row.status, row.confirmed_by, row.confirmed_at) == ("confirmed", "alice", NOW)
            assert row.proposed_from == "cwe-vector-templates-v1:CWE-79"
            assert row.asserted_by == "agent:claude:abc"

    def test_the_choice_carries_who_confirmed_it_and_the_template(self, tmp_path: Path) -> None:
        db = _db(tmp_path)
        row_id = _propose(db)
        _confirm(db, row_id)
        with db.session() as session:
            choice = environment.choose_vectors(session, [finding()], repo_full_name=REPO)
        chosen = choice["s" * 64]
        assert (chosen.source, chosen.ref, chosen.confirmed_by, chosen.confirmed_at) == (
            "analyst", row_id, "alice", NOW,
        )
        assert chosen.proposed_from == "cwe-vector-templates-v1:CWE-79"
        assert chosen.rescored is True

    def test_editing_while_confirming_scores_the_edited_vector(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db = _db(tmp_path)
        _inject(monkeypatch, [finding()])
        behind_login = "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N"
        _confirm(db, _propose(db), vector=behind_login)
        _rescore(db)
        stored = _stored(db)
        assert stored is not None and stored.vector == behind_login
        assert stored.base == cvss.score(behind_login).base

    def test_confirming_a_replacement_retires_the_old_one_and_rescores(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db = _db(tmp_path)
        _inject(monkeypatch, [finding()])
        first = _propose(db)
        _confirm(db, first)
        _rescore(db)
        second = _propose(db, template_id=None, vector=CRITICAL)
        _confirm(db, second)
        result = _rescore(db)
        assert result.scored == 1
        stored = _stored(db)
        assert stored is not None and (stored.vector, stored.vector_ref) == (CRITICAL, second)
        with db.session() as session:
            old = session.get(RuleVector, first)
            assert old is not None and (old.status, old.retired_by) == ("retired", "alice")

    def test_the_resolver_still_applies_facts_to_an_analyst_vector(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Not a second scoring path: the environment raises it like any other."""
        from mykronos.db.models import RepoSurface

        db = _db(tmp_path)
        with db.session() as session:
            session.add(
                RepoSurface(
                    id="s-db", repo_full_name=REPO, kind="asset", name="db",
                    exposure="internal", sensitivity="credentials",
                    selectors={"paths": ["src/**"], "images": [], "addresses": [],
                               "hostnames": []},
                    declared_by="alice",
                )
            )
        _inject(monkeypatch, [finding()])
        _confirm(db, _propose(db))
        _rescore(db)
        stored = _stored(db)
        assert stored is not None
        assert stored.environmental > stored.base
        assert any(f["metric"] == "CR" and f["applied"] for f in stored.facts_json)


class TestAnAgentCannotConfirm:
    @pytest.mark.parametrize("principal", [AGENT, AUTOMATION])
    def test_the_module_refuses_anything_but_a_person(
        self, tmp_path: Path, principal: Principal
    ) -> None:
        db = _db(tmp_path)
        row_id = _propose(db)
        with pytest.raises(rule_vectors.NotAPersonError):
            _confirm(db, row_id, principal=principal)
        with db.session() as session:
            row = session.get(RuleVector, row_id)
            assert row is not None and row.status == "proposed"

    def test_an_agent_cannot_retire_a_confirmed_vector_but_can_withdraw_a_proposal(
        self, tmp_path: Path
    ) -> None:
        db = _db(tmp_path)
        confirmed = _propose(db)
        _confirm(db, confirmed)
        proposal = _propose(db, template_id=None, vector=CRITICAL)
        with db.session() as session:
            with pytest.raises(rule_vectors.NotAPersonError):
                rule_vectors.retire(session, confirmed, principal=AGENT)
            assert rule_vectors.retire(session, proposal, principal=AGENT).status == "retired"


class TestRetiredStopsApplying:
    def test_retiring_returns_the_finding_to_unscored(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db = _db(tmp_path)
        _inject(monkeypatch, [finding()])
        row_id = _propose(db)
        _confirm(db, row_id)
        assert _rescore(db).scored == 1
        with db.session() as session:
            rule_vectors.retire(session, row_id, principal=PERSON, note="rule withdrawn")
        result = _rescore(db)
        assert (result.removed, result.unscored) == (1, 1)
        assert _stored(db) is None


class TestPrecedence:
    def test_nvd_beats_a_confirmed_analyst_vector(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db = _db(tmp_path)
        cve_finding = finding(rule_id=CVE, capability="dependencies", tool="grype")
        _inject(monkeypatch, [cve_finding])
        _confirm(
            db,
            _propose(db, rule_id=CVE, capability="dependencies", tool="grype",
                     template_id=None, vector=XSS),
        )
        _rescore(db)
        stored = _stored(db)
        assert stored is not None
        assert (stored.vector, stored.vector_source, stored.vector_ref) == (CRITICAL, "nvd", "")

    def test_an_advisory_vector_beats_a_confirmed_analyst_vector(self, tmp_path: Path) -> None:
        db = _db(tmp_path)
        advised = finding(
            raw_finding_json={"cvss_vectors": [
                {"version": "3.1", "vector": CRITICAL, "source": "trivy"}
            ]}
        )
        _confirm(db, _propose(db))
        with db.session() as session:
            chosen = environment.choose_vectors(session, [advised], repo_full_name=REPO)
        assert chosen["s" * 64].source == "advisory"

    def test_the_repositorys_own_vector_beats_an_estate_wide_one(self, tmp_path: Path) -> None:
        db = _db(tmp_path)
        _confirm(db, _propose(db, repo_full_name=None, template_id=None, vector=CRITICAL))
        with db.session() as session:
            estate = environment.choose_vectors(session, [finding()], repo_full_name=REPO)
        assert estate["s" * 64].vector == CRITICAL
        own = _propose(db)
        _confirm(db, own)
        with db.session() as session:
            chosen = environment.choose_vectors(session, [finding()], repo_full_name=REPO)
        assert (chosen["s" * 64].vector, chosen["s" * 64].ref) == (XSS, own)

    @pytest.mark.parametrize(
        "other",
        [
            {"tool": "codeql"},
            {"tool": None},
            {"capability": "dast"},
            {"rule_id": "another.rule"},
        ],
    )
    def test_another_tool_capability_or_rule_does_not_match(
        self, tmp_path: Path, other: dict[str, Any]
    ) -> None:
        db = _db(tmp_path)
        _confirm(db, _propose(db))
        with db.session() as session:
            chosen = environment.choose_vectors(
                session, [finding(**other)], repo_full_name=REPO
            )
        assert chosen == {}

    def test_another_repositorys_vector_does_not_apply(self, tmp_path: Path) -> None:
        db = _db(tmp_path)
        _confirm(db, _propose(db, repo_full_name="example-org/other"))
        with db.session() as session:
            assert environment.choose_vectors(session, [finding()], repo_full_name=REPO) == {}


class TestTheRegister:
    def test_one_proposal_per_rule(self, tmp_path: Path) -> None:
        db = _db(tmp_path)
        _propose(db)
        with pytest.raises(rule_vectors.RuleVectorConflictError):
            _propose(db, template_id=None, vector=CRITICAL)

    def test_a_confirmed_vector_is_not_edited_in_place(self, tmp_path: Path) -> None:
        db = _db(tmp_path)
        row_id = _propose(db)
        _confirm(db, row_id)
        with db.session() as session, pytest.raises(rule_vectors.RuleVectorConflictError):
            rule_vectors.edit(session, row_id, vector=CRITICAL)

    def test_an_unknown_template_is_refused(self, tmp_path: Path) -> None:
        db = _db(tmp_path)
        with pytest.raises(rule_vectors.RuleVectorError):
            _propose(db, template_id="CWE-1")

    def test_writes_mark_the_repository_and_estate_wide_marks_all(self, tmp_path: Path) -> None:
        db = _db(tmp_path)
        environment.clear()
        _propose(db)
        assert REPO in environment.pending()
        environment.clear()
        _propose(db, repo_full_name=None)
        assert environment.ALL in environment.pending()


class TestRulesWithoutVector:
    def test_rules_are_grouped_counted_and_pre_filled(self, tmp_path: Path) -> None:
        db = _db(tmp_path)
        rows = [
            finding(finding_id="a" * 64),
            finding(finding_id="b" * 64),
            finding(finding_id="c" * 64, capability="secrets", tool="gitleaks",
                    rule_id="generic-api-key", cwe_ids_json=None),
            finding(finding_id="d" * 64, rule_id=CVE, capability="dependencies"),
        ]
        with db.session() as session:
            rules = rule_vectors.rules_without_vector(
                session, rows, repo_full_name=REPO, templates=TEMPLATES
            )
        assert [(r.rule_id, r.findings) for r in rules] == [(RULE, 2), ("generic-api-key", 1)]
        assert rules[0].suggested is not None and rules[0].suggested.cwe == "CWE-79"
        assert rules[1].suggested is not None and rules[1].suggested.cwe == "CWE-798"
        assert rules[0].applies is None

    def test_a_confirmed_rule_stays_listed_as_applying(self, tmp_path: Path) -> None:
        db = _db(tmp_path)
        row_id = _propose(db)
        _confirm(db, row_id)
        with db.session() as session:
            rules = rule_vectors.rules_without_vector(
                session, [finding()], repo_full_name=REPO, templates=TEMPLATES
            )
            assert rules[0].applies is not None and rules[0].applies.id == row_id


# ---------------------------------------------------------------------------
# The API
# ---------------------------------------------------------------------------


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _agent(client: TestClient, admin_auth: dict[str, str]) -> dict[str, str]:
    minted = client.post(
        "/api/agents/credentials", json={"family": "claude-opus-5.5"}, headers=admin_auth
    )
    assert minted.status_code == 201, minted.text
    return _bearer(minted.json()["token"])


def _audits(client: TestClient, action: str) -> list[AuditLogEntry]:
    with client.app.state.db.session() as session:  # type: ignore[attr-defined]
        return list(
            session.scalars(select(AuditLogEntry).where(AuditLogEntry.action == action))
        )


class TestTheApi:
    def _repo_with_sast(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction: Any
    ) -> str:
        repo_id = onboard(client, admin_auth).json()["id"]
        client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": ["sast"]},
            headers=admin_auth,
        )
        auth = _bearer(issue_token(client, REPO, "sast"))
        post_scan(client, auth, scan_run_id="run-sast", tool_name="semgrep")
        post_findings(
            client,
            auth,
            [
                finding_payload(rule_id=RULE, cwe_ids=["CWE-79"], symbol="a",
                                severity="medium"),
                finding_payload(rule_id=RULE, cwe_ids=["CWE-79"], symbol="b",
                                line_start=10, line_end=11, severity="medium"),
            ],
            scan_run_id="run-sast",
        )
        run_compaction()
        return str(repo_id)

    def test_list_propose_confirm_scores_and_is_audited_as_a_person(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction: Any
    ) -> None:
        repo_id = self._repo_with_sast(client, admin_auth, run_compaction)
        page = client.get(f"/api/dashboard/repos/{repo_id}/rule-vectors", headers=admin_auth)
        assert page.status_code == 200, page.text
        body = page.json()
        assert (body["unscored_rules"], body["unscored_findings"]) == (1, 2)
        rule = body["rules"][0]
        assert (rule["capability"], rule["tool"], rule["rule_id"], rule["findings"]) == (
            "sast", "semgrep", RULE, 2,
        )
        assert rule["suggested_template"]["id"] == "cwe-vector-templates-v1:CWE-79"
        assert rule["applies"] is None
        assert {t["cwe"] for t in body["templates"]} >= {"CWE-79", "CWE-89"}

        agent = _agent(client, admin_auth)
        proposed = client.post(
            "/api/dashboard/rule-vectors",
            json={"repo_id": repo_id, "capability": "sast", "tool": "semgrep",
                  "rule_id": RULE, "template_id": "CWE-79"},
            headers=agent,
        )
        assert proposed.status_code == 201, proposed.text
        row = proposed.json()
        assert (row["status"], row["vector"], row["base_score"]) == ("proposed", XSS, 6.1)

        finding_id = client.get(
            f"/api/dashboard/repos/{repo_id}/findings", headers=admin_auth
        ).json()["findings"][0]["finding_id"]
        record = client.get(f"/api/dashboard/findings/{finding_id}/record", headers=admin_auth)
        assert record.json()["severity_here"] is None, "a proposal must not score"

        refused = client.post(
            f"/api/dashboard/rule-vectors/{row['id']}/confirm", json={}, headers=agent
        )
        assert refused.status_code == 403
        assert "agent" in refused.json()["detail"]

        confirmed = client.post(
            f"/api/dashboard/rule-vectors/{row['id']}/confirm",
            json={"note": "checked: reflected, no login"},
            headers=admin_auth,
        )
        assert confirmed.status_code == 200, confirmed.text
        assert confirmed.json()["status"] == "confirmed"

        here = client.get(
            f"/api/dashboard/findings/{finding_id}/record", headers=admin_auth
        ).json()["severity_here"]
        assert (here["vector"], here["vector_source"], here["base"]) == (XSS, "analyst", 6.1)

        state = client.app.state  # type: ignore[attr-defined]
        assert environment.rescore(state.db, state.catalog, REPO).scored == 2

        after = client.get(
            f"/api/dashboard/repos/{repo_id}/rule-vectors", headers=admin_auth
        ).json()
        assert after["unscored_rules"] == 0
        assert after["rules"][0]["applies"]["id"] == row["id"]

        (proposal_entry,) = _audits(client, "rule_vector.propose")
        assert proposal_entry.actor_kind == "agent"
        (confirm_entry,) = _audits(client, "rule_vector.confirm")
        assert confirm_entry.actor_kind == "human"
        assert confirm_entry.detail["vector"] == XSS
        assert confirm_entry.detail["edited"] is False

    def test_a_viewer_cannot_propose_and_a_bad_vector_is_422(
        self, client: TestClient, admin_auth: dict[str, str], viewer_auth: dict[str, str]
    ) -> None:
        body = {"capability": "sast", "tool": "semgrep", "rule_id": RULE}
        assert client.post(
            "/api/dashboard/rule-vectors", json={**body, "vector": XSS}, headers=viewer_auth
        ).status_code == 403
        bad = client.post(
            "/api/dashboard/rule-vectors", json={**body, "vector": XSS + "/MAV:L"},
            headers=admin_auth,
        )
        assert bad.status_code == 422
        assert "environment" in bad.json()["detail"]
        assert client.post(
            "/api/dashboard/rule-vectors", json=body, headers=admin_auth
        ).status_code == 422

    def test_estate_wide_edit_and_retire(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        agent = _agent(client, admin_auth)
        created = client.post(
            "/api/dashboard/rule-vectors",
            json={"capability": "secrets", "tool": "gitleaks", "rule_id": "generic-api-key",
                  "template_id": "CWE-798"},
            headers=agent,
        ).json()
        assert (created["scope"], created["repo_full_name"]) == ("estate", None)

        edited = client.patch(
            f"/api/dashboard/rule-vectors/{created['id']}",
            json={"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
            headers=agent,
        )
        assert edited.status_code == 200, edited.text
        assert edited.json()["proposed_from"] == "cwe-vector-templates-v1:CWE-798"

        client.post(
            f"/api/dashboard/rule-vectors/{created['id']}/confirm", json={}, headers=admin_auth
        )
        assert client.post(
            f"/api/dashboard/rule-vectors/{created['id']}/retire", json={}, headers=agent
        ).status_code == 403
        retired = client.post(
            f"/api/dashboard/rule-vectors/{created['id']}/retire",
            json={"note": "rotated"},
            headers=admin_auth,
        )
        assert retired.status_code == 200
        assert retired.json()["status"] == "retired"

        listed = client.get(
            "/api/dashboard/rule-vectors", params={"status": "retired"}, headers=admin_auth
        ).json()["rule_vectors"]
        assert [r["id"] for r in listed] == [created["id"]]
        assert client.get(
            "/api/dashboard/rule-vectors", params={"status": "bogus"}, headers=admin_auth
        ).status_code == 422
        assert client.post(
            "/api/dashboard/rule-vectors/nope/confirm", json={}, headers=admin_auth
        ).status_code == 404
