"""The reviewer's preflight refuses exactly when `decide` would (TheHub #62132).

`reviewer._preflight` runs before a live review spends an API call, so it must
refuse a review `decide` would refuse, and no other. It asked for a delegation
without the approver, so a delegation naming `approver_purposes` - which
admits only a person-minted credential, never the platform reviewer - passed
the preflight, the review ran, and `decide` refused the verdict. Each case
here builds the request and the delegations, then asks both: the preflight
with the request as `run_review` loads it, and `decide` with the reviewer
`run_review` would mint. Their answers must agree, both ways.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest

from mykronos.approvals import engine, reviewer
from mykronos.approvals.policy import load_policy
from mykronos.config import Settings
from mykronos.db import Database
from mykronos.db.models import ApprovalRequest, Delegation
from mykronos.schemas import utcnow

RUNS = "claude-opus-5-5"
OLD = "claude-opus-5"
RATIONALE = "Checked the premise and the scope against the evidence bundle."
BUILDER = {"family": "claude-sonnet-5", "instance": "builder-1", "lineage": []}


@pytest.fixture
def db(settings: Settings) -> Any:
    database = Database(settings.database_url)
    database.create_all()
    yield database
    database.close()


@pytest.fixture
def policy(settings: Settings) -> Any:
    return load_policy(settings.approval_policy_path)


def _grant(
    db: Any,
    *,
    duty: str,
    tiers: list[str],
    families: list[str],
    constraints: dict[str, Any] | None = None,
    revoked: bool = False,
) -> None:
    now = utcnow()
    with db.session() as session:
        session.add(
            Delegation(
                duty=duty,
                tiers=tiers,
                approver_families=families,
                constraints=constraints or {},
                sampling=0.0,
                created_at=now - timedelta(days=1),
                expires_at=now + timedelta(days=30),
                revoked_at=now - timedelta(hours=1) if revoked else None,
            )
        )


def _request(db: Any, *, duty: str, tier: str, provenance: dict[str, Any]) -> str:
    now = utcnow()
    with db.session() as session:
        row = ApprovalRequest(
            duty=duty,
            tier=tier,
            subject_ref="subject-1",
            evidence={"what": "a frozen bundle"},
            evidence_digest="d" * 64,
            requester_statement="Please review.",
            requested_by=f"agent:{provenance['family']}:{provenance['instance']}",
            requester_kind="agent",
            requester_provenance=provenance,
            state="pending",
            created_at=now,
            expires_at=now + timedelta(days=1),
        )
        session.add(row)
        session.flush()
        return str(row.id)


def _preflight_refuses(db: Any, policy: Any, request_id: str) -> str | None:
    try:
        reviewer._preflight(db, policy, reviewer._load(db, request_id), RUNS)
    except engine.ApprovalError as exc:
        return str(exc)
    return None


def _decide_refuses(db: Any, policy: Any, request_id: str) -> str | None:
    approver = reviewer._mint_reviewer(db, request_id=request_id, family=RUNS, started_by="test")
    try:
        engine.decide(
            db,
            policy,
            request_id=request_id,
            approver=approver,
            verdict="approve",
            rationale=RATIONALE,
            evidence_digest="d" * 64,
            # The duty's approved handler acts on the subject after every
            # refusal has been passed; it is not what is compared here.
            on_approved=lambda _session, _request: None,
        )
    except engine.ApprovalError as exc:
        return str(exc)
    return None


PRM = "pull_request_merge"
RISK = "risk_acceptance"
SCOPED = {"approver_purposes": ["security-champion"]}

#: (id, duty, tier, delegations, requester provenance, decide refuses?)
CASES: list[tuple[str, str, str, list[dict[str, Any]], dict[str, Any], bool]] = [
    ("no-delegation", PRM, "routine", [], BUILDER, True),
    ("another-family", PRM, "routine", [{"families": [OLD]}], BUILDER, True),
    ("covered", PRM, "routine", [{"families": [RUNS]}], BUILDER, False),
    # The case the preflight let through: the review ran, then `decide` refused.
    ("purpose-scoped-only", PRM, "routine", [{"families": [RUNS], "constraints": SCOPED}],
     BUILDER, True),
    ("purpose-scoped-and-family-only", PRM, "routine",
     [{"families": [RUNS], "constraints": SCOPED}, {"families": [RUNS]}], BUILDER, False),
    ("another-tier", PRM, "routine", [{"families": [RUNS], "tiers": ["production"]}],
     BUILDER, True),
    ("revoked", PRM, "routine", [{"families": [RUNS], "revoked": True}], BUILDER, True),
    ("human-only-tier", PRM, "governance", [{"families": [RUNS], "tiers": ["governance"]}],
     BUILDER, True),
    # risk_acceptance high requires different_family, read by vendor lineage:
    # Sonnet and Opus are both `anthropic`, so both refuse ...
    ("same-lineage-requester", RISK, "high", [{"families": [RUNS], "tiers": ["high"]}],
     BUILDER, True),
    # ... and a requester of another lineage is admitted by both.
    ("another-lineage-requester", RISK, "high", [{"families": [RUNS], "tiers": ["high"]}],
     {"family": "gpt-5", "instance": "builder-3", "lineage": []}, False),
]


@pytest.mark.parametrize(
    ("duty", "tier", "grants", "provenance", "refused"),
    [case[1:] for case in CASES],
    ids=[case[0] for case in CASES],
)
def test_the_preflight_refuses_exactly_when_decide_would(
    db: Any,
    policy: Any,
    duty: str,
    tier: str,
    grants: list[dict[str, Any]],
    provenance: dict[str, Any],
    refused: bool,
) -> None:
    for grant in grants:
        _grant(
            db,
            duty=duty,
            tiers=grant.get("tiers", ["production", "routine"]),
            families=grant["families"],
            constraints=grant.get("constraints"),
            revoked=grant.get("revoked", False),
        )
    request_id = _request(db, duty=duty, tier=tier, provenance=provenance)

    preflight = _preflight_refuses(db, policy, request_id)
    decision = _decide_refuses(db, policy, request_id)

    assert (decision is not None) is refused, decision
    assert (preflight is not None) is (decision is not None), (preflight, decision)


def test_a_purpose_scoped_refusal_says_why(db: Any, policy: Any) -> None:
    """The preflight's 409 carries `decide`'s reason, not only "no delegation"."""
    _grant(db, duty=PRM, tiers=["routine"], families=[RUNS], constraints=SCOPED)
    request_id = _request(db, duty=PRM, tier="routine", provenance=BUILDER)

    refusal = _preflight_refuses(db, policy, request_id)

    assert refusal is not None
    assert "No active delegation" in refusal
    assert "admits only approver_purposes" in refusal
