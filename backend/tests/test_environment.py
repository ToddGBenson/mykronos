"""Environmental CVSS resolver, storage and triggers (TheHub #60827)."""

from __future__ import annotations

import asyncio
import itertools
from collections.abc import Iterator
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from mykronos import cvss, environment, main
from mykronos.config import Settings
from mykronos.db.models import (
    EnvironmentalScore,
    RepoControl,
    RepoSurface,
    ScoringContext,
    ThreatIntelMatch,
)
from mykronos.db.session import Database
from mykronos.environment import (
    ChosenVector,
    Policy,
    RepoInputs,
    build_context,
    effective_severity,
    score_finding,
)
from tests.conftest import REPO, finding_payload, issue_token, post_findings, post_scan
from tests.test_onboarding import onboard

ROOT = Path(__file__).resolve().parents[2]
POLICY = environment.load_policy(ROOT / "environment-map-v1.yaml")
NOW = datetime(2026, 10, 18, 12, 0, 0)
CVE = "CVE-2024-0001"
CRITICAL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # 9.8
HEARTBLEED = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"  # 7.5


_OPEN: list[Database] = []


@pytest.fixture(autouse=True)
def _clean_flags() -> Iterator[None]:
    environment.clear()
    yield
    environment.clear()
    while _OPEN:
        _OPEN.pop().close()


def surface(**overrides: Any) -> SimpleNamespace:
    values: dict[str, Any] = {
        "id": "s-api",
        "kind": "entry_point",
        "name": "API",
        "exposure": "internal",
        "sensitivity": "unknown",
        "selectors": {
            "paths": ["src/api/**"],
            "images": [],
            "addresses": [],
            "hostnames": ["api.example.net"],
        },
        "cr": None,
        "ir": None,
        "ar": None,
        "declared_by": "alice",
        "declared_at": NOW - timedelta(days=1),
        "updated_at": NOW - timedelta(days=1),
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def observation(**overrides: Any) -> SimpleNamespace:
    values: dict[str, Any] = {
        "id": "obs-1",
        "subject": "surface:s-api",
        "surface_id": "s-api",
        "control_id": None,
        "assertion": "firewall_scope",
        "state": "pass",
        "vantage": "host",
        "tool": "Publish-ControlObservations.ps1",
        "collector": "host-collector@NAS",
        "collected_at": NOW - timedelta(days=1),
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def control(**overrides: Any) -> SimpleNamespace:
    values: dict[str, Any] = {
        "id": "c-gate",
        "kind": "perimeter_gate",
        "stride": "spoofing",
        "verified_by_capability": "dast",
        "applies_to_surface_id": None,
        "declared_by": "alice",
        "last_verified_at": NOW - timedelta(days=3),
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def profile(**overrides: Any) -> SimpleNamespace:
    values: dict[str, Any] = {
        "id": "p-1",
        "internet_facing": None,
        "data_classification": None,
        "business_criticality": None,
        "compliance_scope": [],
        "updated_by": "alice",
        "updated_at": NOW - timedelta(days=5),
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def finding(**overrides: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "finding_id": "f" * 64,
        "capability": "sast",
        "rule_id": CVE,
        "title": "something",
        "severity": "high",
        "file_path": "src/api/app.py",
        "address": None,
        "port": None,
        "cwe_ids_json": None,
        "raw_finding_json": None,
        "last_seen_at": NOW,
    }
    values.update(overrides)
    return values


def inputs(**overrides: Any) -> RepoInputs:
    values: dict[str, Any] = {"repo_full_name": REPO, "observations_available": True}
    values.update(overrides)
    return RepoInputs(**values)


def scored(
    f: dict[str, Any] | None = None,
    repo: RepoInputs | None = None,
    vector: str = CRITICAL,
    now: datetime = NOW,
    policy: Policy = POLICY,
) -> environment.FindingScore:
    context = build_context(repo or inputs(), policy=policy, now=now)
    return score_finding(f or finding(), context, ChosenVector(vector, "3.1", "nvd"))


def fact(result: environment.FindingScore, metric: str) -> environment.Fact:
    found = [f for f in result.facts if f.metric == metric]
    assert found, f"no {metric} fact among {result.facts}"
    return found[0]


def every_base_vector() -> Iterator[str]:
    for av, ac, pr, ui, s, c, i, a in itertools.product(
        "NALP", "LH", "NLH", "NR", "UC", "HLN", "HLN", "HLN"
    ):
        yield f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"


class TestNoFactsIsTheBaseScore:
    def test_every_base_vector_scores_its_base_with_no_facts(self) -> None:
        """The property the whole feature rests on, over all 2,592 base vectors."""
        context = build_context(inputs(), policy=POLICY, now=NOW)
        assert context.candidates == ()
        count = 0
        for vector in every_base_vector():
            result = score_finding(finding(), context, ChosenVector(vector, "3.1", "nvd"))
            assert result.facts == ()
            assert result.scored.environmental == result.scored.base, vector
            assert result.effective_severity == "high"
            count += 1
        assert count == 2592

    def test_unverified_lowering_facts_never_move_any_vector(self) -> None:
        """Declarations that could only lower (not internet-facing, an internal
        surface, a gate nobody observed) leave every vector at its base."""
        repo = inputs(
            profile=profile(internet_facing=False),
            surfaces=[surface(exposure="local")],
            controls=[control()],
            observations_available=False,
        )
        context = build_context(repo, policy=POLICY, now=NOW)
        assert context.candidates
        for vector in every_base_vector():
            result = score_finding(finding(), context, ChosenVector(vector, "3.1", "nvd"))
            assert result.scored.environmental == result.scored.base, vector
            assert not any(f.applied and f.direction == "lower" for f in result.facts)

    def test_observed_lowering_facts_never_raise_any_vector(self) -> None:
        repo = inputs(
            surfaces=[surface(exposure="local")],
            observations=[observation(assertion="bound_loopback")],
            controls=[control()],
        )
        repo.observations = [
            *repo.observations,
            observation(id="o-401", subject="app.example.net", surface_id=None,
                        assertion="anonymous_401", vantage="internet"),
        ]
        context = build_context(repo, policy=POLICY, now=NOW)
        moved = 0
        for vector in every_base_vector():
            result = score_finding(finding(), context, ChosenVector(vector, "3.1", "nvd"))
            assert result.scored.environmental <= result.scored.base, vector
            moved += result.scored.environmental < result.scored.base
        assert moved > 1000

    def test_a_missing_policy_file_maps_nothing(self, tmp_path: Path) -> None:
        empty = environment.load_policy(tmp_path / "absent.yaml")
        result = scored(
            repo=inputs(profile=profile(data_classification="regulated")), policy=empty
        )
        assert result.facts == ()
        assert result.scored.environmental == result.scored.base


class TestLoweringOnlyFromVerifiedFreshFacts:
    def test_an_internal_surface_without_an_observation_does_not_lower(self) -> None:
        result = scored(repo=inputs(surfaces=[surface()]))
        mav = fact(result, "MAV")
        assert mav.applied is False
        assert mav.tier == "declared"
        assert mav.not_applied_reason and "fresh observation" in mav.not_applied_reason
        assert result.scored.environmental == result.scored.base

    def test_without_the_observation_register_it_says_so(self) -> None:
        result = scored(repo=inputs(surfaces=[surface()], observations_available=False))
        reason = fact(result, "MAV").not_applied_reason or ""
        assert "not installed" in reason

    def test_a_fresh_observation_lowers_and_names_who_saw_it(self) -> None:
        result = scored(repo=inputs(surfaces=[surface()], observations=[observation()]))
        mav = fact(result, "MAV")
        assert mav.applied is True
        assert (mav.tier, mav.value, mav.direction) == ("observed", "A", "lower")
        assert mav.asserted_by == "host-collector@NAS"
        assert mav.evidence_id == "obs-1"
        assert mav.expires_at == NOW - timedelta(days=1) + timedelta(days=14)
        assert result.scored.environmental < result.scored.base

    def test_a_firewall_rule_does_not_verify_local(self) -> None:
        """`firewall_scope` supports adjacent; only `bound_loopback` supports local."""
        repo = inputs(surfaces=[surface(exposure="local")], observations=[observation()])
        assert fact(scored(repo=repo), "MAV").applied is False
        repo = inputs(
            surfaces=[surface(exposure="local")],
            observations=[observation(assertion="bound_loopback")],
        )
        assert fact(scored(repo=repo), "MAV").applied is True

    def test_a_newer_failing_observation_withdraws_the_older_pass(self) -> None:
        repo = inputs(
            surfaces=[surface()],
            observations=[
                observation(id="old", collected_at=NOW - timedelta(days=3)),
                observation(id="new", state="fail", collected_at=NOW - timedelta(days=1)),
            ],
        )
        mav = fact(scored(repo=repo), "MAV")
        assert mav.applied is False
        assert "did not hold" in (mav.not_applied_reason or "")

    def test_a_finding_outside_the_surface_gets_none_of_its_facts(self) -> None:
        repo = inputs(surfaces=[surface()], observations=[observation()])
        result = scored(finding(file_path="docs/readme.md"), repo=repo)
        assert result.facts == ()
        assert result.scored.environmental == result.scored.base

    def test_a_confirmed_declared_requirement_lowers(self) -> None:
        asset = surface(id="s-db", kind="asset", name="Logs", ar="L", exposure="unknown",
                        selectors={"paths": ["logs/**"]})
        result = scored(finding(), repo=inputs(surfaces=[surface(), asset]))
        # The finding is in the API entry point, not the asset: no AR fact.
        assert not [f for f in result.facts if f.metric == "AR"]

        result = scored(
            finding(file_path="logs/x.py"),
            repo=inputs(surfaces=[surface(id="s-db", kind="asset", name="Logs", ar="L",
                                          exposure="unknown",
                                          selectors={"paths": ["logs/**"]})]),
        )
        ar = fact(result, "AR")
        assert (ar.value, ar.direction, ar.tier, ar.applied) == ("L", "lower", "declared", True)
        assert result.scored.environmental < result.scored.base

    def test_a_declaration_confirmed_too_long_ago_does_not_lower(self) -> None:
        old = NOW - timedelta(days=91)
        result = scored(
            finding(file_path="logs/x.py"),
            repo=inputs(surfaces=[surface(id="s-db", kind="asset", ar="L", exposure="unknown",
                                          selectors={"paths": ["logs/**"]},
                                          declared_at=old, updated_at=old)]),
        )
        ar = fact(result, "AR")
        assert ar.applied is False
        assert (ar.not_applied_reason or "").startswith("stale:")
        assert result.scored.environmental == result.scored.base

    def test_a_repository_wide_declaration_lowers_nothing_outside_a_surface(self) -> None:
        result = scored(repo=inputs(profile=profile(business_criticality="low")))
        ar = fact(result, "AR")
        assert ar.applied is False
        assert "no declared surface" in (ar.not_applied_reason or "")

    def test_the_profile_saying_not_internet_facing_is_reported_and_not_applied(self) -> None:
        result = scored(repo=inputs(profile=profile(internet_facing=False)))
        mav = fact(result, "MAV")
        assert (mav.source_kind, mav.value, mav.applied) == ("risk_profile", "A", False)
        assert result.scored.environmental == result.scored.base

    def test_a_tool_image_tag_lowers_while_the_scan_is_fresh(self) -> None:
        tool = finding(
            capability="containers",
            file_path=None,
            raw_finding_json='{"image": "ghcr.io/x/scanner:1", "image_role": "tool"}',
        )
        mav = fact(scored(tool), "MAV")
        assert (mav.source_kind, mav.value, mav.applied) == ("adapter_tag", "L", True)
        stale = dict(tool, last_seen_at=NOW - timedelta(days=20))
        assert fact(scored(stale), "MAV").applied is False

    def test_exploitability_is_never_raised_and_the_fact_says_capped(self) -> None:
        repo = inputs(surfaces=[surface()], observations=[observation()])
        local_flaw = "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        result = scored(repo=repo, vector=local_flaw)
        mav = fact(result, "MAV")
        assert mav.applied is False
        assert (mav.not_applied_reason or "").startswith("capped:")
        assert result.scored.environmental == result.scored.base


class TestFifteenDayOldObservation:
    def test_it_reverts_to_base_in_the_resolver(self) -> None:
        repo = inputs(
            surfaces=[surface()],
            observations=[observation(collected_at=NOW - timedelta(days=15))],
        )
        result = scored(repo=repo)
        mav = fact(result, "MAV")
        assert mav.applied is False
        assert (mav.not_applied_reason or "").startswith("stale:")
        assert result.scored.environmental == result.scored.base

    def test_the_daily_rescore_raises_the_stored_score_back(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db = _db(tmp_path)
        _seed_surface(db)
        observed_at = NOW - timedelta(days=1)
        _inject(monkeypatch, [finding()], [observation(collected_at=observed_at)])

        first = environment.rescore(db, None, REPO, now=NOW, policy=POLICY)
        assert (first.scored, first.context_changed) == (1, True)
        with db.session() as session:
            row = session.get(EnvironmentalScore, "f" * 64)
            assert row is not None
            lowered = row.environmental
            assert lowered < row.base
            assert row.context_id == first.context_id

        # Same facts the next hour: nothing written.
        again = environment.rescore(db, None, REPO, now=NOW + timedelta(hours=1), policy=POLICY)
        assert (again.context_changed, again.unchanged, again.scored) == (False, 1, 0)

        # The daily job, fifteen days after the observation.
        monkeypatch.setattr(environment, "load_policy", lambda path=None: POLICY)
        later = observed_at + timedelta(days=15)
        results = environment.rescore_all(db, None, now=later)
        assert [r.context_changed for r in results] == [True]
        with db.session() as session:
            row = session.get(EnvironmentalScore, "f" * 64)
            assert row is not None
            assert row.environmental == row.base > lowered
            mav = next(f for f in row.facts_json if f["metric"] == "MAV")
            assert mav["applied"] is False
            assert mav["not_applied_reason"].startswith("stale:")
            assert session.scalar(select(func.count()).select_from(ScoringContext)) == 2


class TestContradictionCancels:
    def test_a_port_published_to_the_internet_cancels_internal(self) -> None:
        repo = inputs(
            surfaces=[surface()],
            observations=[
                observation(),
                observation(
                    id="obs-2", subject="api.example.net:443", surface_id=None,
                    assertion="port_published", vantage="internet",
                ),
            ],
        )
        result = scored(repo=repo)
        mav = fact(result, "MAV")
        assert mav.applied is False
        assert (mav.not_applied_reason or "").startswith("contradicted:")
        assert result.scored.environmental == result.scored.base

    def test_a_lan_port_does_not_contradict_internal(self) -> None:
        repo = inputs(
            surfaces=[surface()],
            observations=[
                observation(),
                observation(id="obs-2", assertion="port_published", vantage="lan"),
            ],
        )
        assert fact(scored(repo=repo), "MAV").applied is True

    def test_a_stale_contradiction_does_not_cancel(self) -> None:
        repo = inputs(
            surfaces=[surface()],
            observations=[
                observation(),
                observation(id="obs-2", assertion="ingress_published",
                            collected_at=NOW - timedelta(days=20)),
            ],
        )
        assert fact(scored(repo=repo), "MAV").applied is True

    def _gate(self, **overrides: Any) -> RepoInputs:
        values: dict[str, Any] = {
            "controls": [control()],
            "observations": [
                observation(id="o-401", subject="app.example.net", surface_id=None,
                            assertion="anonymous_401", vantage="internet"),
            ],
        }
        values.update(overrides)
        return inputs(**values)

    def test_an_observed_gate_turns_pr_none_into_low(self) -> None:
        result = scored(repo=self._gate())
        mpr = fact(result, "MPR")
        assert (mpr.applied, mpr.value, mpr.tier, mpr.source_kind) == (
            True, "L", "observed", "control",
        )
        assert result.scored.environmental < result.scored.base

    def test_an_open_secrets_finding_cancels_the_gate(self) -> None:
        repo = self._gate(open_findings=[finding(capability="secrets", rule_id="aws-key")])
        mpr = fact(scored(repo=repo), "MPR")
        assert mpr.applied is False
        assert "secrets" in (mpr.not_applied_reason or "")

    def test_an_open_dast_finding_in_the_gates_category_contradicts_it(self) -> None:
        unauth = finding(finding_id="d" * 64, capability="dast", rule_id="10202")
        mpr = fact(scored(repo=self._gate(open_findings=[unauth])), "MPR")
        assert mpr.applied is False
        assert (mpr.not_applied_reason or "").startswith("contradicted:")

    def test_a_secrets_finding_is_never_scored_as_behind_the_gate(self) -> None:
        mpr = fact(scored(finding(capability="secrets"), repo=self._gate()), "MPR")
        assert mpr.applied is False
        assert "secrets finding" in (mpr.not_applied_reason or "")

    def test_a_gate_exempt_path_is_not_behind_the_gate(self) -> None:
        dast = finding(
            capability="dast",
            file_path="/api/healthz",
            raw_finding_json='{"instance": {"uri": "https://app.example.net/api/healthz"}}',
        )
        mpr = fact(scored(dast, repo=self._gate()), "MPR")
        assert mpr.applied is False
        assert "exempt" in (mpr.not_applied_reason or "")

    def test_a_flaw_that_already_needs_privileges_is_untouched(self) -> None:
        needs_low = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
        mpr = fact(scored(repo=self._gate(), vector=needs_low), "MPR")
        assert mpr.applied is False
        assert (mpr.not_applied_reason or "").startswith("not applicable:")


class TestSecurityRequirementsRaiseOnly:
    def test_a_credentials_asset_raises_even_on_a_stale_unattributed_declaration(self) -> None:
        old = NOW - timedelta(days=400)
        vault = surface(id="s-vault", kind="asset", name="Vault", sensitivity="credentials",
                        exposure="unknown", declared_by="", declared_at=old, updated_at=old)
        result = scored(repo=inputs(surfaces=[vault]), vector=HEARTBLEED)
        cr = fact(result, "CR")
        assert (cr.value, cr.direction, cr.applied) == ("H", "raise", True)
        assert result.scored.environmental > result.scored.base

    def test_confidentiality_is_never_low(self) -> None:
        public = surface(id="s-p", kind="asset", sensitivity="public", cr="L", exposure="unknown")
        cr = fact(scored(repo=inputs(surfaces=[public]), vector=HEARTBLEED), "CR")
        assert cr.applied is False
        assert (cr.not_applied_reason or "").startswith("policy:")

    def test_a_raising_profile_fact_outweighs_a_lower_surface_one(self) -> None:
        public = surface(id="s-p", kind="asset", sensitivity="public", exposure="unknown")
        result = scored(
            repo=inputs(surfaces=[public], profile=profile(data_classification="regulated")),
            vector=HEARTBLEED,
        )
        crs = {f.source_kind: f for f in result.facts if f.metric == "CR"}
        assert crs["risk_profile"].applied is True
        assert crs["surface"].applied is False
        assert (crs["surface"].not_applied_reason or "").startswith("outweighed:")

    def test_requirements_alone_never_lower_any_vector(self) -> None:
        old = NOW - timedelta(days=400)
        repo = inputs(
            profile=profile(data_classification="public", business_criticality="low",
                            compliance_scope=["pci"], updated_at=old),
        )
        context = build_context(repo, policy=POLICY, now=NOW)
        for vector in every_base_vector():
            result = score_finding(finding(), context, ChosenVector(vector, "3.1", "nvd"))
            assert result.scored.environmental >= result.scored.base, vector


class TestEffectiveSeverity:
    @pytest.mark.parametrize(
        ("scanner", "base_band", "env_band", "expected"),
        [
            ("high", "high", "high", "high"),
            ("high", "high", "medium", "medium"),
            ("high", "critical", "medium", "low"),
            ("medium", "high", "critical", "high"),
            ("critical", "high", "critical", "critical"),
            ("low", "medium", "low", "low"),
            ("low", "high", "low", "low"),
            ("info", "medium", "medium", "info"),
            ("info", "medium", "high", "low"),
            ("info", "high", "medium", "low"),
            ("", "high", "medium", "medium"),
        ],
    )
    def test_the_band_shift_is_applied_and_clamped(
        self, scanner: str, base_band: str, env_band: str, expected: str
    ) -> None:
        assert effective_severity(scanner, base_band, env_band) == expected

    def test_a_lowered_score_lowers_the_scanners_word(self) -> None:
        repo = inputs(surfaces=[surface(exposure="local")],
                      observations=[observation(assertion="bound_loopback")])
        result = scored(repo=repo)
        assert (result.base_band, result.env_band) == ("critical", "high")
        assert result.effective_severity == "medium"


class TestContextHash:
    def _repo(self, **overrides: Any) -> RepoInputs:
        values: dict[str, Any] = {
            "profile": profile(data_classification="regulated"),
            "surfaces": [surface(), surface(id="s-db", kind="asset", sensitivity="pii")],
            "controls": [control()],
            "observations": [observation()],
        }
        values.update(overrides)
        return inputs(**values)

    def test_the_same_facts_hash_the_same_in_any_order(self) -> None:
        a = build_context(self._repo(), policy=POLICY, now=NOW)
        repo = self._repo()
        repo.surfaces = list(reversed(list(repo.surfaces)))
        b = build_context(repo, policy=POLICY, now=NOW + timedelta(hours=3))
        assert a.context_id == b.context_id
        assert len(a.context_id) == 64

    def test_a_reobservation_is_the_same_context(self) -> None:
        a = build_context(self._repo(), policy=POLICY, now=NOW)
        b = build_context(
            self._repo(observations=[observation(id="obs-9", collected_at=NOW)]),
            policy=POLICY, now=NOW,
        )
        assert a.context_id == b.context_id

    def test_a_lapse_is_a_new_context(self) -> None:
        a = build_context(self._repo(), policy=POLICY, now=NOW)
        b = build_context(self._repo(), policy=POLICY, now=NOW + timedelta(days=14))
        assert a.context_id != b.context_id

    def test_another_repository_with_the_same_facts_is_another_context(self) -> None:
        a = build_context(self._repo(), policy=POLICY, now=NOW)
        b = build_context(self._repo(repo_full_name="other/repo"), policy=POLICY, now=NOW)
        assert a.context_id != b.context_id

    def test_a_changed_fact_is_a_new_context(self) -> None:
        a = build_context(self._repo(), policy=POLICY, now=NOW)
        b = build_context(
            self._repo(profile=profile(data_classification="internal")), policy=POLICY, now=NOW
        )
        assert a.context_id != b.context_id


class TestTheJobIsRegistered:
    def test_environment_runs_daily_and_rescores_everything(
        self, settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: dict[str, Any] = {}

        async def record(name: str, interval: int, job: Any, db: Any = None) -> None:
            captured[name] = (interval, job, db)

        monkeypatch.setattr(main, "_every", record)
        calls: list[Any] = []

        def fake_rescore_all(db: Any, catalog: Any) -> list[environment.RescoreResult]:
            calls.append((db, catalog))
            return [environment.RescoreResult(REPO, "c" * 64, True, 3)]

        monkeypatch.setattr(environment, "rescore_all", fake_rescore_all)
        settings = settings.model_copy(update={"run_jobs_in_background": True})
        with TestClient(main.create_app(settings)) as client:
            interval, job, db = captured["environment"]
            assert interval == 86_400
            # Job health: the db is handed to `_every`, which records each run.
            assert db is client.app.state.db
            asyncio.run(job())
        assert len(calls) == 1

    def test_a_failed_repository_fails_the_job(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db = _db(tmp_path)
        _seed_surface(db)
        monkeypatch.setattr(environment, "known_repos", lambda db: ["a/ok", "b/broken"])

        def flaky(db: Any, catalog: Any, repo: str, **_: Any) -> environment.RescoreResult:
            if repo == "b/broken":
                raise RuntimeError("boom")
            return environment.RescoreResult(repo)

        monkeypatch.setattr(environment, "rescore", flaky)
        with pytest.raises(environment.RescoreError, match="b/broken"):
            environment.rescore_all(db, None)


class TestTriggersCallRescore:
    def test_a_surface_write_marks_its_repository_and_drain_rescores_it(
        self, tmp_path: Path
    ) -> None:
        db = _db(tmp_path)
        _seed_surface(db)
        assert REPO in environment.pending()

        called: list[str] = []

        def fake(db: Any, catalog: Any, repo: str) -> environment.RescoreResult:
            called.append(repo)
            return environment.RescoreResult(repo)

        clock = iter([0.0, 10.0, 100.0])
        environment.clear()
        environment.mark_dirty(REPO, "test", clock=lambda: next(clock))
        # Debounced: marked at 0, drained at 10 with a 30s window -> waits.
        assert environment.drain(db, None, clock=lambda: next(clock), rescore_fn=fake) == []
        environment.drain(db, None, clock=lambda: next(clock), rescore_fn=fake)
        assert called == [REPO]
        assert environment.pending() == {}

    def test_a_control_write_marks_its_repository(self, tmp_path: Path) -> None:
        db = _db(tmp_path)
        environment.clear()
        with db.session() as session:
            session.add(RepoControl(repo_full_name="org/ctl", stride="spoofing",
                                    kind="perimeter_gate"))
        assert "org/ctl" in environment.pending()

    def test_a_risk_profile_write_resolves_to_its_repository(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        repo_id = onboard(client, admin_auth).json()["id"]
        environment.clear()
        put = client.put(
            f"/api/repos/{repo_id}/risk-profile",
            json={"business_criticality": "high"},
            headers=admin_auth,
        )
        assert put.status_code == 200, put.text
        assert f"onboarding:{repo_id}" in environment.pending()

        called: list[str] = []
        environment.drain(
            client.app.state.db,  # type: ignore[attr-defined]
            None,
            debounce_seconds=0,
            rescore_fn=lambda db, catalog, repo: called.append(repo)
            or environment.RescoreResult(repo),
        )
        assert called == [REPO]

    def test_finding_ingest_marks_its_repository(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        onboard(client, admin_auth)
        token = issue_token(client, REPO, "sast")
        auth = {"Authorization": f"Bearer {token}"}
        post_scan(client, auth, scan_run_id="run-env")
        environment.clear()
        post_findings(client, auth, [finding_payload(symbol="a")], scan_run_id="run-env")
        assert REPO in environment.pending()

    def test_a_vector_refresh_marks_every_repository(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from mykronos import threat_intel, worklist

        db = _db(tmp_path)
        monkeypatch.setattr(threat_intel, "refresh", lambda session, relevant: None)
        monkeypatch.setattr(threat_intel, "apply_kev_due_dates", lambda s, c: 0)
        monkeypatch.setattr(threat_intel, "refresh_vectors", lambda session: 2)
        monkeypatch.setattr(worklist, "break_snoozes_on_kev", lambda db, catalog: None)
        catalog = SimpleNamespace(query=lambda sql, params=None: [])
        threat_intel.refresh_job(db, catalog)  # type: ignore[arg-type]
        assert environment.ALL in environment.pending()

    def test_the_compaction_loop_drains_after_compacting(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        order: list[str] = []

        def fake_compact(catalog: Any, buffer: Any, db: Any = None) -> Any:
            order.append("compact")
            return SimpleNamespace(total_rows=0)

        def fake_drain(db: Any, catalog: Any) -> list[Any]:
            order.append("drain")
            return []

        monkeypatch.setattr(main, "compact", fake_compact)
        monkeypatch.setattr(environment, "drain", fake_drain)
        app = SimpleNamespace(state=SimpleNamespace(catalog=None, buffer=None, db=None))

        async def run() -> None:
            task = asyncio.create_task(main._compaction_loop(app, 0))  # type: ignore[arg-type]
            for _ in range(50):
                await asyncio.sleep(0.01)
                if "drain" in order:
                    break
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

        asyncio.run(run())
        assert order[:2] == ["compact", "drain"]


class TestRescoreStorage:
    def test_a_finding_without_a_vector_is_not_stored_and_a_closed_one_is_removed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db = _db(tmp_path)
        no_cve = finding(finding_id="n" * 64, rule_id="semgrep.rule", title="pattern")
        _inject(monkeypatch, [finding(), no_cve], [])
        result = environment.rescore(db, None, REPO, now=NOW, policy=POLICY)
        assert (result.scored, result.unscored) == (1, 1)
        with db.session() as session:
            row = session.get(EnvironmentalScore, "f" * 64)
            assert row is not None
            assert (row.vector_source, row.vector_version) == ("nvd", "3.1")
            assert row.base == row.environmental == 9.8
            assert (row.base_band, row.env_band, row.effective_severity) == (
                "critical", "critical", "high",
            )
            assert session.get(EnvironmentalScore, "n" * 64) is None

        _inject(monkeypatch, [], [])
        result = environment.rescore(db, None, REPO, now=NOW, policy=POLICY)
        assert result.removed == 1
        with db.session() as session:
            assert session.get(EnvironmentalScore, "f" * 64) is None

    def test_a_changed_scanner_severity_is_rescored_in_an_unchanged_context(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db = _db(tmp_path)
        _inject(monkeypatch, [finding()], [])
        environment.rescore(db, None, REPO, now=NOW, policy=POLICY)
        _inject(monkeypatch, [finding(severity="critical")], [])
        result = environment.rescore(db, None, REPO, now=NOW, policy=POLICY)
        assert (result.context_changed, result.scored) == (False, 1)


class TestSeverityHereReadsTheStoredScore:
    def _cve_finding(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction: Any
    ) -> tuple[str, str]:
        repo_id = onboard(client, admin_auth).json()["id"]
        client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": ["sast"]},
            headers=admin_auth,
        )
        token = issue_token(client, REPO, "sast")
        auth = {"Authorization": f"Bearer {token}"}
        post_scan(client, auth, scan_run_id="run-cve")
        post_findings(
            client,
            auth,
            [finding_payload(rule_id="CVE-2014-0160", severity="high", symbol="a")],
            scan_run_id="run-cve",
        )
        run_compaction()
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            session.add(ThreatIntelMatch(cve_id="CVE-2014-0160", cvss_vector=HEARTBLEED))
        finding_id = client.get(
            f"/api/dashboard/repos/{repo_id}/findings", headers=admin_auth
        ).json()["findings"][0]["finding_id"]
        return repo_id, finding_id

    def test_stored_then_on_read_agree_and_both_return_facts(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction: Any
    ) -> None:
        repo_id, finding_id = self._cve_finding(client, admin_auth, run_compaction)
        client.put(
            f"/api/repos/{repo_id}/risk-profile",
            json={"data_classification": "regulated", "internet_facing": False},
            headers=admin_auth,
        )

        on_read = client.get(
            f"/api/dashboard/findings/{finding_id}/record", headers=admin_auth
        ).json()["severity_here"]
        assert on_read["computed_at"] is None

        state = client.app.state  # type: ignore[attr-defined]
        result = environment.rescore(state.db, state.catalog, REPO)
        assert result.scored == 1

        stored = client.get(
            f"/api/dashboard/findings/{finding_id}/record", headers=admin_auth
        ).json()["severity_here"]
        assert stored["computed_at"] is not None
        for here in (on_read, stored):
            assert here["base"] == 7.5
            assert here["environmental"] > here["base"]
            assert here["effective_severity"] == "critical"
            by_metric = {f["metric"]: f for f in here["facts"]}
            assert by_metric["CR"]["applied"] is True
            assert by_metric["MAV"]["applied"] is False
            assert by_metric["MAV"]["not_applied_reason"]
        assert stored["environmental"] == on_read["environmental"]


# ---------------------------------------------------------------------------


def _db(tmp_path: Path) -> Database:
    db = Database(f"sqlite:///{(tmp_path / 'env.db').as_posix()}")
    _OPEN.append(db)
    db.create_all()
    with db.session() as session:
        session.add(ThreatIntelMatch(cve_id=CVE, cvss_vector=CRITICAL))
    return db


def _seed_surface(db: Database) -> None:
    with db.session() as session:
        session.add(
            RepoSurface(
                id="s-api",
                repo_full_name=REPO,
                kind="entry_point",
                name="API",
                exposure="internal",
                sensitivity="unknown",
                selectors={"paths": ["src/api/**"], "images": [], "addresses": [],
                           "hostnames": []},
                declared_by="alice",
            )
        )


def _inject(
    monkeypatch: pytest.MonkeyPatch, findings: list[dict[str, Any]], observations: list[Any]
) -> None:
    """Lake findings and S4 observations, without a lake or #918."""
    original = environment.load_inputs

    def load(session: Any, repo: str, rows: Any, **kwargs: Any) -> RepoInputs:
        loaded = original(session, repo, rows, **kwargs)
        loaded.observations = observations
        loaded.observations_available = True
        return loaded

    monkeypatch.setattr(environment, "open_findings", lambda catalog, repo: findings)
    monkeypatch.setattr(environment, "load_inputs", load)


def test_cvss_still_caps_so_the_resolver_does_not_double_implement_it() -> None:
    """The resolver labels a capped fact; the arithmetic cap stays in cvss.py."""
    env = cvss.Environment(mav="N")
    local = "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert cvss.score(local, env).environmental == cvss.score(local).base
