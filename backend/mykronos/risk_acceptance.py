"""Risk acceptance as a governed decision (spec 33, phase 1).

A risk acceptance used to be `status = accepted_risk` written onto each finding
by whoever held the admin token. Here it is a record: a scope that chose the
findings, a deviation type saying what kind of claim is being made, a residual
risk rating that decides who must approve, premises, milestones, and a named
owner - approved through the spec 34 engine by someone other than the
requester.

**The tier is computed, not chosen.** Residual severity is likelihood x impact
(RA-3). For `vendor_dependency` and `operational_requirement` it can never be
lower than the worst scanner severity in scope - nothing in those claims lowers
the risk. Only `risk_adjustment`, which must name a premise the platform can
check, may rate the residual below the scanner. A requester cannot choose a low
tier to get an easier approver.

Whatever the deviation type, the tier is never below the worst open toxic
combination a covered finding belongs to (review of #1018, PO decision): since
#1018 an accepted member stops counting, so accepting the low half of a
critical pair dissolves a critical, and that is approved as a critical.
It dissolves only the combinations the approver was shown: the frozen
evidence names them, read with nothing suppressed, and a combination that
forms later fails the acceptance's premise (TheHub #61013, `toxic`,
`premise_monitor`).

**The lake still carries the status.** On approval, the covered findings are
stamped `accepted_risk` with the record's expiry and reason code, so the Oracle,
the dashboard and `sweep_acceptances` keep working unchanged.
"""

from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from mykronos import risk_evidence
from mykronos.adminauth import Principal
from mykronos.approvals.engine import (
    ApprovalError,
    Subject,
    _append_event,
    create_request,
    register_adapter,
    register_dedicated_route,
    register_on_approved,
)
from mykronos.approvals.policy import ApprovalPolicy, InterimReview
from mykronos.db.models import (
    ApprovalDecision,
    ApprovalRequest,
    AuditLogEntry,
    RiskAcceptance,
    new_id,
)
from mykronos.fingerprint import image_repository
from mykronos.lake.catalog import Catalog
from mykronos.lake.mutate import locate_findings, update_findings
from mykronos.schemas import utcnow
from mykronos.threat_intel import extract_cve

logger = logging.getLogger(__name__)

SEVERITIES = ("low", "medium", "high", "critical")
LEVELS = ("low", "moderate", "high", "very_high")
DEVIATION_TYPES = ("vendor_dependency", "risk_adjustment", "operational_requirement")
RESPONSES = ("accept", "transfer")
#: spec 33 §4.1. Phase 1 requires that a `risk_adjustment` names at least one,
#: so the premise is checkable the day its monitor ships rather than prose that
#: can never be re-evaluated. `premise_monitor.MONITORED` lists the types it
#: evaluates and `premise_monitor.UNMONITORED` every other one, with the reason
#: (TheHub #60831, #60903).
PREMISE_TYPES = (
    "no_fixed_version",
    "port_not_published",
    "firewall_scope",
    "image_role",
    "container_command",
    "not_internet_facing",
    "not_kev_listed",
    "epss_below",
    "path_unreachable",
)
#: Statuses a record can still act in. `needs_review` is an acceptance whose
#: interim review lapsed (TheHub #60817): it still holds its findings - it is
#: never expired quietly - but it reads as needing a decision everywhere.
LIVE = ("active", "review_due", "needs_review")


class RiskAcceptanceError(ValueError):
    """A proposal the rules refuse. The message names the rule."""


# -- Binding to the lake -------------------------------------------------------

#: Set at startup. `on_approved` runs inside the engine's database transaction
#: and needs the lake too; passing it through the generic engine would teach
#: the engine about one duty's storage.
_CATALOG: Catalog | None = None


def bind(catalog: Catalog) -> None:
    global _CATALOG
    _CATALOG = catalog


def _catalog() -> Catalog:
    if _CATALOG is None:
        raise RuntimeError("risk_acceptance.bind(catalog) was never called.")
    return _CATALOG


# -- Residual risk (RA-3) ------------------------------------------------------


def residual_severity(likelihood: str, impact: str) -> str:
    """A 4x4 likelihood x impact matrix onto the scanner's severity scale."""
    try:
        score = LEVELS.index(likelihood) + LEVELS.index(impact)
    except ValueError as exc:
        raise RiskAcceptanceError(
            f"Likelihood and impact must each be one of {', '.join(LEVELS)}."
        ) from exc
    if score <= 1:
        return "low"
    if score <= 3:
        return "medium"
    if score <= 5:
        return "high"
    return "critical"


def _worst(severities: list[str]) -> str:
    ranked = [s for s in severities if s in SEVERITIES]
    return max(ranked, key=SEVERITIES.index) if ranked else "low"


def reason_code_for(deviation_type: str, compensating_controls: list[dict[str, Any]]) -> str:
    """The row-level reason code the lake and the Oracle already understand."""
    if deviation_type == "vendor_dependency":
        return "no_vendor_fix"
    if deviation_type == "operational_requirement":
        return "cost_exceeds_risk"
    return "compensating_control" if compensating_controls else "not_exploitable_here"


# -- Interim review (TheHub #60817) --------------------------------------------


def interim_review_owed(
    deviation_type: str,
    compensating_controls: list[dict[str, Any]],
    premises: list[dict[str, Any]],
    rule: InterimReview,
) -> bool:
    """Whether an acceptance rests on a reason nothing watches.

    The reason code is the one the findings carry. `no_vendor_fix` is watched
    already - the finding re-opens the day a fix ships - and a record with a
    premise `premise_monitor` evaluates is re-read every day. The rest would
    run to their severity cap with nobody looking, so they are reviewed at
    `rule.days`.
    """
    from mykronos.premise_monitor import REOPENS

    if reason_code_for(deviation_type, compensating_controls) not in rule.reason_codes:
        return False
    return not (
        rule.unless_monitored_premise
        and any(isinstance(p, dict) and p.get("type") in REOPENS for p in premises)
    )


def interim_review_date(
    record: RiskAcceptance, rule: InterimReview, *, starting: date
) -> date | None:
    """The day `record` owes its interim review, or None when it owes none.

    None too when the review before expiry (`review_by`) falls on or before
    that day: that review asks the same question sooner.
    """
    if not interim_review_owed(
        record.deviation_type,
        list(record.compensating_controls or []),
        list(record.premises or []),
        rule,
    ):
        return None
    due = starting + timedelta(days=rule.days)
    if record.review_by is not None and record.review_by <= due:
        return None
    return due


def interim_state(record: RiskAcceptance, today: date, rule: InterimReview) -> str:
    """none | scheduled | due | lapsed | done - where the interim review stands."""
    if record.interim_reviewed_at is not None:
        return "done"
    if record.interim_review_by is None:
        return "none"
    if today < record.interim_review_by:
        return "scheduled"
    if today < record.interim_review_by + timedelta(days=rule.grace_days):
        return "due"
    return "lapsed"


# -- Scope (spec 33 §1.2) ------------------------------------------------------


@dataclass(frozen=True)
class MatchedFinding:
    finding_id: str
    rule_id: str
    package: str
    severity: str
    location: str
    image: str
    fixed_version: str
    status: str
    #: `"debian 10.13"` where the containers adapter tagged the finding
    #: `base_os_eol` (#712), else empty.
    base_os_eol: str = ""
    #: Where an OSV-derived Atlas finding carries its CVE: its rule id is the
    #: GHSA id (`threat_intel.extract_cve` reads both, as the Oracle does).
    title: str = ""

    @property
    def cve(self) -> str | None:
        """The rule id when it is a CVE, as before; else the CVE the title names."""
        if self.rule_id.upper().startswith("CVE-"):
            return self.rule_id.upper()
        return extract_cve(None, self.title)


def validate_scope(scope: dict[str, Any]) -> None:
    capability = str(scope.get("capability") or "").strip()
    if not capability:
        raise RiskAcceptanceError("A scope names its capability.")
    if capability == "containers" and not scope.get("image"):
        raise RiskAcceptanceError(
            "A container scope names its image: a decision about one image must not "
            "cover another (D-127)."
        )
    wildcard_rules = scope.get("rule_ids") in (None, [], ["*"])
    if capability != "containers" and wildcard_rules and not scope.get("file_paths"):
        raise RiskAcceptanceError(
            "A code scope names its rules or its files; a scope matching every finding "
            "in a repository is refused (spec 33 §1.2)."
        )
    if scope.get("fixed_version", "any") not in ("absent", "present", "any"):
        raise RiskAcceptanceError("scope.fixed_version is absent, present or any.")


def scope_images(scope_image: str) -> frozenset[str]:
    """The repositories a scope's `image` may name.

    `image_repository` is not idempotent for an image built here: a finding's
    `registry.lan:5000/mykronos-backend:<sha>` becomes `mykronos-backend`, and
    feeding that back in - which is exactly what the legacy migration stored as
    the scope - gives `library/mykronos-backend`, because a bare single name
    reads as a Docker Hub official image. So a migrated acceptance on one of
    our own images matched nothing, could not be renewed or re-proposed with
    the scope it carried, and lapsed (c62c9d7d, 2026-10-03).

    A bare single name is genuinely ambiguous - `postgres` is Docker Hub's,
    `mykronos-backend` is ours - so it matches either reading. Anything with a
    `/` or a registry host is unambiguous and matches only itself.
    """
    canonical = image_repository(scope_image)
    ref = scope_image.strip().split("@", 1)[0]
    if ref.rfind(":") > ref.rfind("/"):
        ref = ref[: ref.rfind(":")]
    if "/" not in ref and ref:
        return frozenset({canonical, ref.lower()})
    return frozenset({canonical})


def match_scope(
    catalog: Catalog,
    repo: str,
    scope: dict[str, Any],
    statuses: tuple[str, ...] = ("open",),
) -> list[MatchedFinding]:
    validate_scope(scope)
    if not catalog.all_files("findings"):
        return []
    placeholders = ", ".join("?" for _ in statuses)
    rows = catalog.query(
        "SELECT finding_id, rule_id, coalesce(package_name, ''), lower(severity), "
        "       coalesce(file_path, ''), "
        "       coalesce(json_extract_string(raw_finding_json, '$.image'), ''), "
        "       coalesce(json_extract_string(raw_finding_json, '$.fixed_version'), ''), "
        "       status, "
        "       CASE WHEN json_extract_string(raw_finding_json, '$.base_os_eol') = 'true' "
        "            THEN coalesce(json_extract_string(raw_finding_json, '$.base_os'), "
        "                          'an end-of-life OS') ELSE '' END, "
        "       coalesce(title, '') "
        "FROM findings WHERE repo_full_name = ? AND capability = ? "
        f"AND status IN ({placeholders})",
        [repo, scope["capability"], *statuses],
    )
    want_images = scope_images(scope["image"]) if scope.get("image") else None
    rules = set(scope.get("rule_ids") or ["*"])
    severities = set(scope.get("severities") or SEVERITIES)
    packages = set(scope.get("package_names") or [])
    paths = tuple(scope.get("file_paths") or [])
    fixed = scope.get("fixed_version", "any")
    out: list[MatchedFinding] = []
    for fid, rule, pkg, sev, path, image, fixed_version, status, eol, title in rows:
        if want_images is not None and (not image or image_repository(image) not in want_images):
            continue
        if "*" not in rules and rule not in rules:
            continue
        if sev not in severities:
            continue
        if packages and pkg not in packages:
            continue
        if paths and not str(path).startswith(paths):
            continue
        has_fix = bool(str(fixed_version).strip())
        if (fixed == "absent" and has_fix) or (fixed == "present" and not has_fix):
            continue
        out.append(
            MatchedFinding(
                finding_id=str(fid),
                rule_id=str(rule),
                package=str(pkg),
                severity=str(sev),
                location=str(path),
                image=str(image),
                fixed_version=str(fixed_version),
                status=str(status),
                base_os_eol=str(eol or ""),
                title=str(title or ""),
            )
        )
    return out


def _summary(matched: list[MatchedFinding]) -> dict[str, Any]:
    by_severity = Counter(m.severity for m in matched)
    by_package = Counter(m.package or m.location for m in matched)
    return {
        "findings": len(matched),
        "by_severity": dict(sorted(by_severity.items())),
        "top_packages": dict(by_package.most_common(15)),
        "with_fixed_version": sum(1 for m in matched if m.fixed_version.strip()),
        "images": sorted({image_repository(m.image) for m in matched if m.image}),
    }


def premise_flags(deviation_type: str, matched: list[MatchedFinding]) -> list[dict[str, Any]]:
    """Reasons an approver should doubt this acceptance's premise (#712).

    A `vendor_dependency` claims no fix exists *yet* and becomes `no_vendor_fix`
    on the findings, which re-opens the day a vendor ships one (spec 33
    `no_fixed_version`). On an end-of-life base OS no vendor ever will, so the
    premise is false from day one and the acceptance would never re-open.

    **Flagged, not refused**, deliberately. The base-image move that fixes
    these is a migration, often of a third-party image nobody here builds, and
    a time-boxed acceptance whose milestone *is* that migration is a legitimate
    record of the interim. Refusing would push the same request to
    `operational_requirement` with the reason stripped out; flagging keeps the
    reason in the evidence the approver signs and in the audit log. The
    platform also only knows a base is end-of-life where the lane stamped
    Trivy's OS metadata, so a refusal would bite unevenly across lanes.
    """
    if deviation_type != "vendor_dependency":
        return []
    eol = [m for m in matched if m.base_os_eol]
    if not eol:
        return []
    bases = sorted({m.base_os_eol for m in eol})
    images = sorted({image_repository(m.image) for m in eol if m.image})
    return [
        {
            "code": "base_os_eol",
            "findings": len(eol),
            "bases": bases,
            "images": images,
            "reason": (
                f"{len(eol)} finding(s) in scope are on an end-of-life base OS "
                f"({', '.join(bases)}): no vendor fix will ever ship, so this "
                "vendor_dependency acceptance will never re-open on its own. "
                f"The fix is a supported base image for {', '.join(images) or 'the image'}; "
                "a milestone that moves it is the way out."
            ),
        }
    ]


# -- Validation ----------------------------------------------------------------


def _kev_listed(session: Session, matched: list[MatchedFinding]) -> list[str]:
    # The one KEV read every risk decision shares, over the CVEs the Oracle
    # reads: the rule id's, else the title's (TheHub #60901).
    return risk_evidence.kev_listed(session, {c for m in matched if (c := m.cve)})


def _validate(
    *,
    policy: ApprovalPolicy,
    deviation_type: str,
    response: str,
    residual: str,
    premises: list[dict[str, Any]],
    milestones: list[dict[str, Any]],
    risk_owner: str,
    requested_until: date,
    renewal_count: int,
    legacy: bool,
) -> None:
    limits = policy.risk_acceptance
    if deviation_type not in DEVIATION_TYPES:
        raise RiskAcceptanceError(f"deviation_type is one of {', '.join(DEVIATION_TYPES)}.")
    if response not in RESPONSES:
        raise RiskAcceptanceError(
            f"response is one of {', '.join(RESPONSES)}; mitigate and avoid are POA&M "
            "items, not acceptances (spec 33 §1.3)."
        )
    owner = risk_owner.strip()
    if not owner or owner.startswith("agent:"):
        raise RiskAcceptanceError(
            "A risk acceptance names the person who answers for it; an agent or a blank "
            "is not a risk owner (spec 33 §1.1)."
        )
    if (
        deviation_type == "operational_requirement"
        and residual == "critical"
        and limits.refuse_critical_operational_requirement
    ):
        raise RiskAcceptanceError(
            "A critical residual risk cannot be an operational requirement: that is a "
            "conversation about the architecture, not an acceptance."
        )
    for p in premises:
        if p.get("type") not in PREMISE_TYPES:
            raise RiskAcceptanceError(
                f"Premise type '{p.get('type')}' is not one the platform can monitor: "
                f"{', '.join(PREMISE_TYPES)}."
            )
    if deviation_type == "risk_adjustment" and not premises and not legacy:
        raise RiskAcceptanceError(
            "A risk adjustment names at least one premise the platform can check. A "
            "control nobody can point at cannot be checked when it is removed."
        )
    if not any(m.get("ends_weakness") for m in milestones) and not legacy:
        raise RiskAcceptanceError(
            "At least one milestone must end the weakness (spec 33 §3): an acceptance "
            "with no way out is a deferral."
        )
    if renewal_count > limits.max_renewals.get(residual, 0):
        raise RiskAcceptanceError(
            f"A {residual} acceptance may be renewed {limits.max_renewals.get(residual, 0)} "
            "time(s). Beyond that the answer is remediation, avoidance or re-architecture."
        )
    if not legacy:
        cap = limits.max_duration_days.get(residual, 0)
        if requested_until > utcnow().date() + timedelta(days=cap):
            raise RiskAcceptanceError(
                f"A {residual} acceptance runs at most {cap} days; requested until "
                f"{requested_until.isoformat()}."
            )


# -- Proposing -----------------------------------------------------------------


def _snapshot(
    record: RiskAcceptance,
    matched: list[MatchedFinding],
    flags: list[dict[str, Any]] | None = None,
    premise_checks: list[dict[str, Any]] | None = None,
    evidence: dict[str, Any] | None = None,
    control_checks: list[dict[str, Any]] | None = None,
    combinations: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    """The evidence an approver sees, frozen into the request's digest."""
    snapshot = {
        "risk_acceptance_id": record.id,
        "repo": record.repo_full_name,
        "scope": record.scope,
        "response": record.response,
        "deviation_type": record.deviation_type,
        "justification": record.justification,
        "residual": {
            "likelihood": record.residual_likelihood,
            "impact": record.residual_impact,
            "severity": record.residual_severity,
        },
        "premises": record.premises,
        "compensating_controls": record.compensating_controls,
        "milestones": record.milestones,
        "risk_owner": record.risk_owner,
        "requested_until": record.requested_until.isoformat() if record.requested_until else None,
        "legacy": record.legacy,
        "renews_id": record.renews_id,
        "renewal_count": record.renewal_count,
        "matched": _summary(matched),
        "covered_finding_ids": sorted(m.finding_id for m in matched),
    }
    # Only when present, so the evidence (and its digest) of every proposal
    # without a flag is exactly what it was.
    if flags:
        snapshot["flags"] = flags
    # What the premise monitor reads today (spec 33 §4), so the approver
    # signs knowing whether a premise is affirmed or only asserted. Only when
    # there are premises, for the same reason as the flags.
    if premise_checks:
        snapshot["premise_checks"] = premise_checks
    # The shared evidence model (TheHub #60901): the categories the Oracle
    # reads, read the same way, for the findings this decision covers.
    if evidence:
        snapshot["risk_evidence"] = evidence
    # Each compensating control as the observations read it (TheHub #60902).
    if control_checks:
        snapshot["control_checks"] = control_checks
    # The toxic combinations this acceptance would dissolve, which set its
    # floor (review of #1018). Only when present, as above.
    if combinations:
        snapshot["combinations"] = combinations
    return snapshot


def _combination_floor(
    db: Any, catalog: Catalog, repo: str, matched: list[MatchedFinding]
) -> tuple[str | None, list[dict[str, str]], bool]:
    """(the worst combination severity over the covered findings, those
    combinations, whether detection failed).

    Read as the disposition guard reads it (`finding_disposition.
    governing_severities`): the combinations the risk decision sees, KEV
    included. Detection that cannot run floors at `critical` (fail closed)
    whatever the finding's own severity: a critical finding governs at
    `critical` either way, so failure is read from `failed`, never inferred
    from a raised severity (review of #1018)."""
    from mykronos import finding_disposition

    undetected: set[str] = set()
    governing = finding_disposition.governing_severities(
        [
            {"finding_id": m.finding_id, "severity": m.severity, "repo_full_name": repo}
            for m in matched
        ],
        catalog=catalog,
        db=db,
        failed=undetected,
        # A renewal is floored at what the record it renews suppressed.
        suppress=False,
    )
    floor: str | None = None
    combinations: dict[str, dict[str, str]] = {}
    failed = False
    for m in matched:
        severity, combos = governing.get(m.finding_id, (m.severity, []))
        if m.finding_id in undetected:
            failed = True
            severity = "critical"
        elif combos:
            combinations.update({c["combination_id"]: c for c in combos})
        else:
            continue
        if severity in SEVERITIES and (
            floor is None or SEVERITIES.index(severity) > SEVERITIES.index(floor)
        ):
            floor = severity
    return floor, list(combinations.values()), failed


def check_controls(
    session: Session,
    repo: str,
    controls: list[dict[str, Any]],
    *,
    fresh_days: int | None = None,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    """Each compensating control: verified | contradicted | unverified, with
    the observation behind it (TheHub #60902).

    A control names `observation_id` (a `ControlObservation`, read as the
    newest of its subject and assertion) or `control_id` (a declared
    `RepoControl`, read against the observations tied to it). One that names
    neither is free text, and free text is unverified.
    """
    when = now or utcnow()
    days = fresh_days or risk_evidence.FRESH_DAYS
    out = []
    for index, control in enumerate(controls):
        control = control if isinstance(control, dict) else {}
        if control.get("observation_id"):
            status = risk_evidence.observation_verification(
                session, repo, str(control["observation_id"]), now=when, fresh_days=days
            )
        elif control.get("control_id"):
            status = risk_evidence.control_verification(
                session, repo, str(control["control_id"]), now=when, fresh_days=days
            )
        else:
            status = risk_evidence.ControlStatus(
                status="unverified",
                reason="Cites no observation or declared control; free text cannot be checked.",
            )
        out.append({"index": index, **status.as_dict()})
    return out


def _refuse_uncited(controls: list[dict[str, Any]], checks: list[dict[str, Any]]) -> None:
    for control, check in zip(controls, checks, strict=True):
        if not (control.get("observation_id") or control.get("control_id")):
            raise RiskAcceptanceError(
                "A compensating control cites the observation or the declared control that "
                "shows it (observation_id or control_id); free text cannot be checked "
                "(TheHub #60902)."
            )
        if check["missing"]:
            raise RiskAcceptanceError(f"Compensating control {check['index']}: {check['reason']}")


def _premise_checks(
    session: Session,
    catalog: Catalog,
    repo: str,
    scope: dict[str, Any],
    premises: list[dict[str, Any]],
    matched: list[MatchedFinding],
    fresh_days: int | None,
) -> list[dict[str, Any]]:
    if not premises:
        return []
    from mykronos import premise_monitor

    return [
        c.as_dict()
        for c in premise_monitor.check_premises(
            session,
            repo=repo,
            premises=premises,
            scope=scope,
            covered_finding_ids=[m.finding_id for m in matched],
            catalog=catalog,
            fresh_days=fresh_days or premise_monitor.FRESH_DAYS,
        )
    ]


#: The categories an acceptance's tier reads (`risk_evidence.CATEGORIES`):
#: a KEV-listed CVE is refused. The rest are shown to the approver.
EVIDENCE_SCORED: tuple[str, ...] = ("threat_intel",)
EVIDENCE_NOTES = {
    "environmental": (
        "Shown to the approver. The tier is residual likelihood x impact, floored at "
        "the scanner's severity for every deviation type but risk_adjustment."
    ),
}


def decision_evidence(
    session: Session,
    catalog: Catalog,
    repo: str,
    matched: list[MatchedFinding],
    *,
    fresh_days: int | None = None,
    now: datetime | None = None,
    controls_cited: bool = False,
) -> dict[str, Any]:
    """The `risk_evidence` block for the findings one acceptance covers.

    Verified controls are scored when the acceptance cites compensating
    controls: only a verified one may lower its tier (TheHub #60902).
    """
    return risk_evidence.gather(
        session,
        catalog,
        repo=repo,
        findings=[
            {
                "finding_id": m.finding_id,
                "rule_id": m.rule_id,
                "title": m.title,
                "file_path": m.location,
            }
            for m in matched
        ],
        as_of=now or utcnow(),
        fresh_days=fresh_days or risk_evidence.FRESH_DAYS,
        scored=(*EVIDENCE_SCORED, "verified_controls") if controls_cited else EVIDENCE_SCORED,
        notes=EVIDENCE_NOTES,
        # Every combination the findings are in, none dissolved by an earlier
        # acceptance: this block is what later suppresses them (TheHub #61013),
        # so a renewal must see what the record it renews suppressed.
        combinations=risk_evidence.toxic_combinations(catalog, session, repo, suppress=False),
    ).as_dict()


def _adapter(subject_ref: str, context: dict[str, Any]) -> Subject:
    snapshot = context.get("snapshot")
    if not snapshot or snapshot.get("risk_acceptance_id") != subject_ref:
        raise ApprovalError(
            "Risk acceptance requests are created through /api/risk-acceptances, which "
            "computes the tier from the record."
        )
    return Subject(tier=snapshot["residual"]["severity"], evidence=snapshot)


def propose(
    db: Any,
    catalog: Catalog,
    policy: ApprovalPolicy,
    *,
    requested_by: Principal,
    repo: str,
    scope: dict[str, Any],
    deviation_type: str,
    justification: str,
    residual_likelihood: str,
    residual_impact: str,
    risk_owner: str,
    requested_until: date,
    premises: list[dict[str, Any]] | None = None,
    compensating_controls: list[dict[str, Any]] | None = None,
    milestones: list[dict[str, Any]] | None = None,
    response: str = "accept",
    legacy: bool = False,
    renews: RiskAcceptance | None = None,
    statuses: tuple[str, ...] = ("open",),
    matched: list[MatchedFinding] | None = None,
    fresh_days: int | None = None,
) -> tuple[RiskAcceptance, ApprovalRequest]:
    if not justification.strip():
        raise RiskAcceptanceError("A justification says why this is true here.")
    premises = list(premises or [])
    controls = list(compensating_controls or [])
    milestones = list(milestones or [])
    if matched is None:
        matched = match_scope(catalog, repo, scope, statuses)
    else:
        validate_scope(scope)
    if not matched:
        raise RiskAcceptanceError("The scope matches no findings; there is nothing to accept.")

    # TheHub #60902: a compensating control cites what observes it, and only
    # a verified one may lower the tier.
    with db.session() as session:
        control_checks = check_controls(session, repo, controls, fresh_days=fresh_days)
    if renews is None and not legacy:
        _refuse_uncited(controls, control_checks)
    controls = [
        {**c, "status_at_proposal": check["status"]}
        for c, check in zip(controls, control_checks, strict=True)
    ]

    residual = residual_severity(residual_likelihood, residual_impact)
    worst = _worst([m.severity for m in matched])
    floored_by_unverified = False
    if deviation_type != "risk_adjustment":
        residual = max(residual, worst, key=SEVERITIES.index)
    elif controls and not any(c["status"] == "verified" for c in control_checks):
        floored_by_unverified = SEVERITIES.index(residual) < SEVERITIES.index(worst)
        residual = max(residual, worst, key=SEVERITIES.index)
    # Never below a combination a covered finding is in, whatever the type:
    # accepting a member dissolves the combination (review of #1018).
    combo_floor, combinations, detection_failed = _combination_floor(
        db, catalog, repo, matched
    )
    floored_by_combination = combo_floor is not None and SEVERITIES.index(
        combo_floor
    ) > SEVERITIES.index(residual)
    if combo_floor is not None:
        residual = max(residual, combo_floor, key=SEVERITIES.index)
    renewal_count = (renews.renewal_count + 1) if renews else 0
    _validate(
        policy=policy,
        deviation_type=deviation_type,
        response=response,
        residual=residual,
        premises=premises,
        milestones=milestones,
        risk_owner=risk_owner,
        requested_until=requested_until,
        renewal_count=renewal_count,
        legacy=legacy,
    )
    if deviation_type == "vendor_dependency" and any(m.fixed_version.strip() for m in matched):
        raise RiskAcceptanceError(
            "A vendor dependency says no fix exists, and findings in this scope name one. "
            "Narrow the scope with fixed_version: absent, or choose another response."
        )
    with db.session() as session:
        kev = _kev_listed(session, matched)
        checks = _premise_checks(session, catalog, repo, scope, premises, matched, fresh_days)
        evidence = decision_evidence(
            session, catalog, repo, matched, fresh_days=fresh_days, controls_cited=bool(controls)
        )
        claimed = covered_by(
            session,
            {m.finding_id for m in matched},
            statuses=("pending_approval", *LIVE),
            exclude=renews.id if renews else None,
        )
    if claimed and len(claimed) == len({m.finding_id for m in matched}):
        # Every finding is already accepted, or waiting to be. A second
        # record changes nothing but the count: on 2026-10-15 an agent filed
        # five container acceptances twice, half an hour apart, while the
        # first five were still pending, and both sets were approved.
        holders = sorted({r.id[:8] for r in claimed.values()})
        raise RiskAcceptanceError(
            "Every finding in this scope is already covered by risk acceptance "
            f"{', '.join(holders)}. Renew or revoke that record instead of filing another."
        )
    if kev and policy.risk_acceptance.refuse_kev_listed:
        raise RiskAcceptanceError(
            f"KEV-listed CVEs cannot be accepted, only mitigated: {', '.join(kev[:10])}."
        )
    flags = premise_flags(deviation_type, matched)
    if floored_by_unverified:
        flags.append(
            {
                "code": "unverified_controls",
                "controls": [c["index"] for c in control_checks if c["status"] != "verified"],
                "reason": (
                    "The residual was rated below the scanner's severity on the strength of "
                    "compensating controls, and none of them is verified by a fresh "
                    f"observation. The tier stays at {worst} until one is (TheHub #60902)."
                ),
            }
        )
    if combinations or detection_failed:
        names = ", ".join(sorted({c["name"] for c in combinations})) or "unknown"
        flags.append(
            {
                "code": "toxic_combination_member",
                "combinations": sorted(c["combination_id"] for c in combinations),
                "floored": floored_by_combination,
                "reason": (
                    "Toxic combination detection could not run, so the tier is "
                    "critical until it can (fail closed)."
                    if detection_failed and not combinations
                    else f"A covered finding is a member of {names}. Accepting it dissolves "
                    f"the combination, so the tier is at least {combo_floor} "
                    "(review of #1018)."
                ),
            }
        )
    for flag in flags:
        logger.warning("risk acceptance on %s flagged: %s", repo, flag["reason"])

    record = RiskAcceptance(
        id=new_id(),
        repo_full_name=repo,
        scope=scope,
        covered_finding_ids=sorted(m.finding_id for m in matched),
        response=response,
        deviation_type=deviation_type,
        justification=justification.strip(),
        residual_likelihood=residual_likelihood,
        residual_impact=residual_impact,
        residual_severity=residual,
        premises=premises,
        compensating_controls=controls,
        milestones=milestones,
        risk_owner=risk_owner.strip(),
        requested_by=requested_by.actor,
        status="pending_approval",
        legacy=legacy,
        renews_id=renews.id if renews else None,
        renewal_count=renewal_count,
        requested_until=requested_until,
        first_effective_at=renews.first_effective_at if renews else None,
    )
    approval = create_request(
        db,
        policy,
        duty="risk_acceptance",
        subject_ref=record.id,
        requested_by=requested_by,
        statement=justification.strip(),
        context={
            "snapshot": _snapshot(
                record, matched, flags, checks, evidence, control_checks, combinations
            )
        },
    )
    record.approval_request_id = approval.id
    with db.session() as session:
        session.add(record)
        db.audit(
            session,
            actor=requested_by.actor,
            action="risk_acceptance.requested",
            entity_type="risk_acceptance",
            entity_id=record.id,
            repo=repo,
            residual_severity=residual,
            deviation_type=deviation_type,
            findings=len(matched),
            legacy=legacy,
            approval_request_id=approval.id,
            **({"premise_flags": [f["code"] for f in flags]} if flags else {}),
        )
        session.flush()
        session.expunge(record)
    return record, approval


# -- Approval ------------------------------------------------------------------


def _stamp_findings(record: RiskAcceptance) -> int:
    if not record.covered_finding_ids or record.expires_at is None:
        return 0
    catalog = _catalog()
    outcome = update_findings(
        catalog,
        locate_findings(catalog, list(record.covered_finding_ids)),
        "status = 'accepted_risk', accepted_until = ?, accepted_reason_code = ?, "
        "resolved_at = coalesce(resolved_at, ?)",
        [
            record.expires_at,
            reason_code_for(record.deviation_type, record.compensating_controls or []),
            utcnow(),
        ],
    )
    return outcome.count


def on_approved(session: Session, request: ApprovalRequest) -> None:
    record = session.get(RiskAcceptance, request.subject_ref)
    if record is None:
        raise ApprovalError(f"No risk acceptance {request.subject_ref}.")
    # Only the request the record was proposed with can activate it. Any
    # other request for the same record carries evidence - and a tier, and a
    # duration cap - that the platform did not compute from the record.
    if record.approval_request_id != request.id or record.status != "pending_approval":
        raise ApprovalError(
            f"Risk acceptance {record.id} was proposed with approval request "
            f"{record.approval_request_id} and is {record.status}; approving request "
            f"{request.id} cannot activate it."
        )
    policy_limits_days = _limits_days(request)
    now = utcnow()
    approver = session.execute(
        select(ApprovalDecision.approver)
        .where(ApprovalDecision.request_id == request.id, ApprovalDecision.verdict == "approve")
        .order_by(ApprovalDecision.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()
    cap = now.date() + timedelta(days=policy_limits_days)
    until = record.requested_until or cap
    record.expires_at = until if record.legacy else min(until, cap)
    record.review_by = record.expires_at - timedelta(days=_review_lead(request))
    record.interim_review_by = interim_review_date(record, interim_rule(), starting=now.date())
    record.status = "active"
    record.approved_by = approver
    record.effective_at = now
    record.first_effective_at = record.first_effective_at or now
    if record.renews_id:
        parent = session.get(RiskAcceptance, record.renews_id)
        if parent is not None and parent.status in LIVE:
            parent.status = "closed"
            parent.closed_at = now
            parent.closed_reason = f"renewed by {record.id}"
    stamped = _stamp_findings(record)
    logger.info("Risk acceptance %s active: %s finding(s) stamped", record.id, stamped)


#: The limits the approving policy carried, looked up at approval time.
_POLICY: ApprovalPolicy | None = None


def bind_policy(policy: ApprovalPolicy) -> None:
    global _POLICY
    _POLICY = policy


def _limits_days(request: ApprovalRequest) -> int:
    limits = _POLICY.risk_acceptance if _POLICY else None
    days = limits.max_duration_days if limits else {}
    return int(days.get(request.tier, 90))


def _review_lead(request: ApprovalRequest) -> int:
    return _POLICY.risk_acceptance.review_lead_days if _POLICY else 14


def interim_rule() -> InterimReview:
    return _POLICY.risk_acceptance.interim_review if _POLICY else InterimReview()


register_adapter("risk_acceptance", _adapter)
register_on_approved("risk_acceptance", on_approved)
register_dedicated_route("risk_acceptance", "/api/risk-acceptances")


# -- Revocation, renewal, the sweep ---------------------------------------------


def covered_by(
    session: Session,
    finding_ids: set[str],
    *,
    statuses: tuple[str, ...] = LIVE,
    exclude: str | None = None,
) -> dict[str, RiskAcceptance]:
    """Which other record covers each of these findings, if any.

    Where several do, the one that runs longest: it is the date a finding's
    `accepted_until` should carry once the others are gone.
    """
    if not finding_ids:
        return {}
    out: dict[str, RiskAcceptance] = {}
    rows = session.execute(
        select(RiskAcceptance).where(RiskAcceptance.status.in_(statuses))
    ).scalars()
    for other in rows:
        if other.id == exclude:
            continue
        for fid in set(other.covered_finding_ids or []) & finding_ids:
            held = out.get(fid)
            if held is None or (other.expires_at or date.max) > (held.expires_at or date.max):
                out[fid] = other
    return out


def revoke(db: Any, *, record_id: str, revoked_by: Principal, reason: str) -> int:
    if not (revoked_by.is_human and revoked_by.may_write):
        raise RiskAcceptanceError("Only a person may revoke a risk acceptance.")
    if not reason.strip():
        raise RiskAcceptanceError("Revoking needs a reason.")
    with db.session() as session:
        record = session.get(RiskAcceptance, record_id)
        if record is None or record.status not in (*LIVE, "pending_approval"):
            raise RiskAcceptanceError(f"No live risk acceptance {record_id}.")
        was_live = record.status in LIVE
        record.status = "revoked"
        record.closed_at = utcnow()
        record.closed_reason = reason.strip()
        db.audit(
            session,
            actor=revoked_by.actor,
            action="risk_acceptance.revoked",
            entity_type="risk_acceptance",
            entity_id=record_id,
            reason=reason.strip(),
        )
        ids = list(record.covered_finding_ids or [])
    if not was_live or not ids:
        return 0
    return len(release_findings(db, _catalog(), record_id=record_id, finding_ids=ids))


def release_findings(
    db: Any, catalog: Catalog, *, record_id: str, finding_ids: list[str]
) -> list[str]:
    """Reopen the findings a record no longer covers; returns the reopened ids.

    A finding another live record still covers stays accepted. Two records
    can cover the same findings - a corrected re-filing approved beside the
    one it supersedes - and ending the stale one must not undo the decision
    that still stands; its date and reason do. Used by `revoke` and by the
    premise monitor (spec 33 §4.2).
    """
    ids = list(finding_ids)
    if not ids:
        return []
    with db.session() as session:
        holders = covered_by(session, set(ids), exclude=record_id)
        restamp: dict[tuple[date | None, str], list[str]] = {}
        for fid, other in holders.items():
            key = (
                other.expires_at,
                reason_code_for(other.deviation_type, other.compensating_controls or []),
            )
            restamp.setdefault(key, []).append(fid)
    for (until, code), kept in restamp.items():
        # The remaining record's date, not the revoked one's, now holds.
        update_findings(
            catalog,
            locate_findings(catalog, kept),
            "accepted_until = ?, accepted_reason_code = ?",
            [until, code],
            only_if_status="accepted_risk",
        )
    reopen = [fid for fid in ids if fid not in holders]
    if not reopen:
        return []
    return list(
        update_findings(
            catalog,
            locate_findings(catalog, reopen),
            "status = 'open', resolved_at = NULL, accepted_until = NULL, "
            "accepted_reason_code = NULL",
            [],
            only_if_status="accepted_risk",
        ).updated
    )


@dataclass
class SweepResult:
    not_approved: int = 0
    review_due: int = 0
    expired: int = 0
    closed: int = 0
    drift: int = 0
    #: Interim reviews that came due, and ones that lapsed unreviewed (#60817).
    interim_due: int = 0
    needs_review: int = 0


def sweep(db: Any, catalog: Catalog, *, today: date | None = None) -> SweepResult:
    """Record-level transitions, each audited (spec 33 §1.4, §7).

    The findings themselves are reopened by `sweep_acceptances` when their
    `accepted_until` passes; this moves the *decision* through its lifecycle
    and says so in the audit log, which the row-level sweep never did.
    """
    today = today or utcnow().date()
    result = SweepResult()
    rule = interim_rule()
    with db.session() as session:
        result.not_approved = _close_unapproved(db, session)
        records = list(
            session.execute(select(RiskAcceptance).where(RiskAcceptance.status.in_(LIVE))).scalars()
        )
        for record in records:
            if record.expires_at and today >= record.expires_at:
                record.status = "expired"
                record.closed_at = utcnow()
                record.closed_reason = "reached expires_at without renewal"
                result.expired += 1
                _audit_sweep(db, session, record, "risk_acceptance.expired")
                continue
            covered = list(record.covered_finding_ids or [])
            if covered and catalog.all_files("findings"):
                placeholders = ", ".join("?" for _ in covered)
                remaining = catalog.query(
                    f"SELECT count(*) FROM findings WHERE finding_id IN ({placeholders}) "
                    "AND status IN ('open', 'accepted_risk')",
                    covered,
                )[0][0]
                if not remaining:
                    record.status = "closed"
                    record.closed_at = utcnow()
                    record.closed_reason = "every covered finding was remediated"
                    result.closed += 1
                    _audit_sweep(db, session, record, "risk_acceptance.closed")
                    continue
            if record.status == "active" and record.review_by and today >= record.review_by:
                record.status = "review_due"
                result.review_due += 1
                _audit_sweep(db, session, record, "risk_acceptance.review_due")
            _sweep_interim(db, session, record, rule, today, result)
            drift = [
                m.finding_id
                for m in match_scope(catalog, record.repo_full_name, record.scope, ("open",))
                if m.finding_id not in set(covered)
            ]
            if sorted(drift) != sorted(record.drift_finding_ids or []):
                record.drift_finding_ids = sorted(drift)
                if drift:
                    result.drift += 1
                    _audit_sweep(
                        db, session, record, "risk_acceptance.scope_drift", count=len(drift)
                    )
    return result


def _sweep_interim(
    db: Any,
    session: Session,
    record: RiskAcceptance,
    rule: InterimReview,
    today: date,
    result: SweepResult,
) -> None:
    """Move a record through its interim review (TheHub #60817).

    A record approved before the rule existed owes the review too: it is
    scheduled from when it took effect, but never earlier than today, so it
    reads `review_due` for the whole grace period before it can lapse - none
    goes straight to `needs_review` on the day this ships.
    """
    if record.interim_reviewed_at is not None:
        return
    if record.interim_review_by is None:
        if record.effective_at is None:
            return
        due = interim_review_date(record, rule, starting=record.effective_at.date())
        if due is None:
            return
        record.interim_review_by = max(due, today)
        _audit_sweep(
            db,
            session,
            record,
            "risk_acceptance.interim_review_scheduled",
            interim_review_by=record.interim_review_by.isoformat(),
        )
    due_on = record.interim_review_by
    state = interim_state(record, today, rule)
    if state == "due" and record.status == "active":
        record.status = "review_due"
        result.interim_due += 1
        _audit_sweep(
            db,
            session,
            record,
            "risk_acceptance.interim_review_due",
            interim_review_by=due_on.isoformat(),
        )
    elif state == "lapsed" and record.status in ("active", "review_due"):
        # Not expired: the findings stay accepted and nothing changes quietly.
        # The record says loudly that nobody has looked at it.
        record.status = "needs_review"
        result.needs_review += 1
        _audit_sweep(
            db,
            session,
            record,
            "risk_acceptance.needs_review",
            interim_review_by=due_on.isoformat(),
            grace_days=rule.grace_days,
        )


def record_interim_review(
    db: Any, *, record_id: str, reviewed_by: Principal, note: str, today: date | None = None
) -> RiskAcceptance:
    """A person has looked again and the acceptance still stands (TheHub #60817).

    The record goes back to `active` - or stays `review_due` when its review
    before expiry is also due, which only a renewal answers.
    """
    if not (reviewed_by.is_human and reviewed_by.may_write):
        raise RiskAcceptanceError("Only a person may record an interim review.")
    if not note.strip():
        raise RiskAcceptanceError("An interim review says what was checked.")
    today = today or utcnow().date()
    with db.session() as session:
        record: RiskAcceptance | None = session.get(RiskAcceptance, record_id)
        if record is None or record.status not in LIVE:
            raise RiskAcceptanceError(f"No live risk acceptance {record_id}.")
        due_on = record.interim_review_by
        if due_on is None or record.interim_reviewed_at is not None:
            raise RiskAcceptanceError(
                f"Risk acceptance {record_id} owes no interim review: renew or revoke it instead."
            )
        record.interim_reviewed_at = utcnow()
        record.interim_reviewed_by = reviewed_by.actor
        expiry_review_due = record.review_by is not None and today >= record.review_by
        record.status = "review_due" if expiry_review_due else "active"
        db.audit(
            session,
            actor=reviewed_by.actor,
            action="risk_acceptance.interim_reviewed",
            entity_type="risk_acceptance",
            entity_id=record_id,
            repo=record.repo_full_name,
            note=note.strip(),
            interim_review_by=due_on.isoformat(),
        )
        session.flush()
        session.expunge(record)
    return record


def _close_unapproved(db: Any, session: Session) -> int:
    """Pending records whose approval request was rejected or ran out of time.

    Without this they stay `pending_approval` for good, and a pending record
    claims its findings: the legacy migration skips them and nothing can
    propose them again. A rejection is an answer, and an expiry is the
    absence of one; either way the record is not going to take effect.
    """
    now = utcnow()
    closed = 0
    pending = session.execute(
        select(RiskAcceptance, ApprovalRequest)
        .join(ApprovalRequest, ApprovalRequest.id == RiskAcceptance.approval_request_id)
        .where(RiskAcceptance.status == "pending_approval")
    ).all()
    for record, request in pending:
        if request.state == "pending" and request.expires_at <= now:
            # Recorded on the request's own chain, as `decide` would on a late
            # decision, so the chain says why it ended.
            request.state = "expired"
            _append_event(session, request.id, "expired", "job:risk-acceptances", {})
        if request.state not in ("rejected", "expired"):
            continue
        record.status = "not_approved"
        record.closed_at = now
        record.closed_reason = f"approval request {request.id} {request.state}"
        closed += 1
        _audit_sweep(
            db, session, record, "risk_acceptance.not_approved", request_state=request.state
        )
    return closed


def _audit_sweep(
    db: Any, session: Session, record: RiskAcceptance, action: str, **detail: Any
) -> None:
    db.audit(
        session,
        actor="job:risk-acceptances",
        action=action,
        entity_type="risk_acceptance",
        entity_id=record.id,
        repo=record.repo_full_name,
        **detail,
    )


# -- Migration of row-level acceptances (spec 33 §10) ---------------------------

_DEVIATION_FOR_CODE = {
    "no_vendor_fix": "vendor_dependency",
    "not_exploitable_here": "risk_adjustment",
    "compensating_control": "risk_adjustment",
    "cost_exceeds_risk": "operational_requirement",
    "other": "risk_adjustment",
}


@dataclass
class LegacyGroup:
    repo: str
    capability: str
    image: str
    location: str
    reason_code: str
    accepted_until: date | None
    severity: str
    findings: list[MatchedFinding]

    @property
    def key(self) -> str:
        return "|".join(
            [
                self.repo,
                self.capability,
                self.image or self.location,
                self.reason_code,
                self.accepted_until.isoformat() if self.accepted_until else "",
                self.severity,
            ]
        )


def legacy_groups(db: Any, catalog: Catalog, repo: str | None = None) -> list[LegacyGroup]:
    """Row-level acceptances not yet covered by any record, grouped into
    the few dozen decisions they really are."""
    if not catalog.all_files("findings"):
        return []
    with db.session() as session:
        claimed: set[str] = set()
        for ids in session.execute(
            select(RiskAcceptance.covered_finding_ids).where(
                RiskAcceptance.status.in_(("pending_approval", *LIVE))
            )
        ).scalars():
            claimed.update(ids or [])
    where = "status = 'accepted_risk'"
    params: list[Any] = []
    if repo:
        where += " AND repo_full_name = ?"
        params.append(repo)
    rows = catalog.query(
        "SELECT finding_id, repo_full_name, capability, rule_id, coalesce(package_name, ''), "
        "       lower(severity), coalesce(file_path, ''), "
        "       coalesce(json_extract_string(raw_finding_json, '$.image'), ''), "
        "       coalesce(json_extract_string(raw_finding_json, '$.fixed_version'), ''), "
        "       coalesce(accepted_reason_code, 'other'), accepted_until "
        f"FROM findings WHERE {where}",
        params,
    )
    groups: dict[str, LegacyGroup] = {}
    for fid, r, cap, rule, pkg, sev, path, image, fixed, code, until in rows:
        if str(fid) in claimed:
            continue
        image_key = image_repository(image) if image else ""
        location = "" if image_key else str(path)
        g = LegacyGroup(
            repo=str(r),
            capability=str(cap),
            image=image_key,
            location=location,
            reason_code=str(code),
            accepted_until=until,
            severity=str(sev) if sev in SEVERITIES else "low",
            findings=[],
        )
        groups.setdefault(g.key, g).findings.append(
            MatchedFinding(
                finding_id=str(fid),
                rule_id=str(rule),
                package=str(pkg),
                severity=str(sev),
                location=str(path),
                image=str(image),
                fixed_version=str(fixed),
                status="accepted_risk",
            )
        )
    return sorted(groups.values(), key=lambda g: (g.repo, g.severity, g.key))


def _legacy_justification(db: Any, finding_ids: list[str]) -> str:
    with db.session() as session:
        reasons = [
            (e.detail or {}).get("reason", "")
            for e in session.execute(
                select(AuditLogEntry)
                .where(
                    AuditLogEntry.action == "finding.status",
                    AuditLogEntry.entity_id.in_(finding_ids[:500]),
                )
                .order_by(AuditLogEntry.created_at.desc())
            ).scalars()
        ]
    reasons = [r for r in reasons if r]
    if not reasons:
        return "Migrated from row-level acceptances; no reason was recorded with them."
    common, _ = Counter(reasons).most_common(1)[0]
    return f"Migrated from {len(finding_ids)} row-level acceptance(s). Recorded reason: {common}"


def migrate_legacy(
    db: Any,
    catalog: Catalog,
    policy: ApprovalPolicy,
    *,
    requested_by: Principal,
    risk_owner: str,
    repo: str | None = None,
    severities: list[str] | None = None,
    dry_run: bool = True,
) -> list[dict[str, Any]]:
    """Propose one `pending_approval` legacy record per group. Findings are not
    touched: they keep their current acceptance until it expires or a person
    approves the record (spec 33 §10)."""
    out: list[dict[str, Any]] = []
    wanted = {s.lower() for s in severities} if severities else None
    for g in legacy_groups(db, catalog, repo):
        if wanted is not None and g.severity not in wanted:
            continue
        deviation = _DEVIATION_FOR_CODE.get(g.reason_code, "risk_adjustment")
        scope: dict[str, Any] = {
            "capability": g.capability,
            "severities": [g.severity],
            "rule_ids": sorted({m.rule_id for m in g.findings}),
        }
        if g.image:
            scope["image"] = g.image
        elif g.location:
            scope["file_paths"] = [g.location]
        premises = (
            [{"type": "no_fixed_version", "inferred": True}]
            if deviation == "vendor_dependency"
            else []
        )
        until = g.accepted_until or (utcnow().date() + timedelta(days=30))
        milestones = [
            {
                "title": "Re-assess this migrated acceptance with its evidence",
                "due": (until - timedelta(days=7)).isoformat(),
                "ends_weakness": False,
            },
            {
                "title": "Remediate, or renew with premises the platform can monitor",
                "due": until.isoformat(),
                "ends_weakness": True,
            },
        ]
        item = {
            "group": g.key,
            "findings": len(g.findings),
            "residual_severity": g.severity,
            "deviation_type": deviation,
            "accepted_until": until.isoformat(),
        }
        if not dry_run:
            record, approval = propose(
                db,
                catalog,
                policy,
                requested_by=requested_by,
                repo=g.repo,
                scope=scope,
                deviation_type=deviation,
                justification=_legacy_justification(db, [m.finding_id for m in g.findings]),
                residual_likelihood="moderate",
                residual_impact="moderate",
                risk_owner=risk_owner,
                requested_until=until,
                premises=premises,
                milestones=milestones,
                legacy=True,
                matched=g.findings,
            )
            item["risk_acceptance_id"] = record.id
            item["approval_request_id"] = approval.id
        out.append(item)
    return out


def serialize(record: RiskAcceptance) -> dict[str, Any]:
    def iso(v: Any) -> Any:
        return v.isoformat() if isinstance(v, (date, datetime)) else v

    return {
        "id": record.id,
        "repo": record.repo_full_name,
        "scope": record.scope,
        "findings": len(record.covered_finding_ids or []),
        "drift": len(record.drift_finding_ids or []),
        "response": record.response,
        "deviation_type": record.deviation_type,
        "justification": record.justification,
        "residual_severity": record.residual_severity,
        "residual_likelihood": record.residual_likelihood,
        "residual_impact": record.residual_impact,
        "premises": record.premises,
        "compensating_controls": record.compensating_controls,
        "milestones": record.milestones,
        "risk_owner": record.risk_owner,
        "requested_by": record.requested_by,
        "approved_by": record.approved_by,
        "approval_request_id": record.approval_request_id,
        "status": record.status,
        "legacy": record.legacy,
        "renews_id": record.renews_id,
        "renewal_count": record.renewal_count,
        "requested_until": iso(record.requested_until),
        "effective_at": iso(record.effective_at),
        "first_effective_at": iso(record.first_effective_at),
        "review_by": iso(record.review_by),
        "interim_review_by": iso(record.interim_review_by),
        "interim_reviewed_at": iso(record.interim_reviewed_at),
        "interim_reviewed_by": record.interim_reviewed_by,
        "expires_at": iso(record.expires_at),
        "closed_at": iso(record.closed_at),
        "closed_reason": record.closed_reason,
        "created_at": iso(record.created_at),
    }
