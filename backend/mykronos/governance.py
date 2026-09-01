"""The controls that would catch a bad change (spec 30).

Aegis is the most carefully-reasoned component in the platform. It scores
changes, refuses to score people, requires a written rationale on every
sub-signal, and treats a low-confidence classifier answer as null rather than
as a hedge. **None of that changes here and all of it is inherited.**

The gap is one step further on. Nine signals, and every one describes a pull
request *after the fact*:

    `self_approval` fires when somebody approved their own change. It is a
    symptom. "Self-approval is permitted on the default branch" is the cause,
    and it was invisible from anywhere in this platform.

Branch protection, required reviewers, CODEOWNERS coverage, signed-commit
enforcement, admin enforcement — the controls that make the difference between
a repository where a malicious change is hard and one where it is trivial —
were not read, not scored and not shown. The GitHub App has been installed
this whole time and the client had no operation that read any of them.

**Unknown is a state, and it is the one this module is most careful about.** A
control the platform could not read is `unknown` with a reason, never a red
cross. A permissions gap is not a security failure and must not be scored as
one — so `administration: read` is deliberately *not* added to the required
permission set. Adding it would fail the spec 02 §8 smoke test for every
installation that already exists, turning an optional new capability into a
breaking change for the whole estate. An App without it reports every control
as unknown and says exactly which permission would answer them.

**Observed, never written.** This platform does not turn on branch protection
for anybody. Every control here is read and reported; changing one is an action
the repository's owners take in GitHub, where the audit trail for it belongs.

**Facts about the repository, not about people.** The counts alongside the
panel are aggregated by repository — *"3 of the last 40 merges had a single
approver on a sensitive path"* is a statement about a control whose remedy is a
settings change. The same data grouped by person is a statement about
colleagues, and spec 06 §9 already decided that question.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy.orm import Session

from mykronos.codeowners import owner_for, parse
from mykronos.config import get_settings
from mykronos.db.models import RepoGovernance
from mykronos.github.client import GitHubClient, GitHubError, PermissionDeniedError
from mykronos.lake.catalog import Catalog
from mykronos.schemas import utcnow

logger = logging.getLogger(__name__)

#: What the panel reports on, in the order it reads best: the controls that
#: decide whether a change can get in at all, then the ones that decide what
#: happens to it afterwards.
CONTROL_ORDER = (
    "pull_request_required",
    "approving_reviews_required",
    "dismiss_stale_reviews",
    "codeowner_review_required",
    "codeowners_coverage",
    "enforced_for_admins",
    "signed_commits_required",
    "required_status_checks",
    "force_push_blocked",
)

#: Which Aegis signal each control would have prevented (spec 30 §2). The link
#: is the whole point of the panel: it turns a log of oddities into a diagnosis
#: with a remedy the team can action themselves.
PREVENTS: dict[str, tuple[str, ...]] = {
    "approving_reviews_required": ("self_approval", "sole_approver"),
    "codeowner_review_required": ("sensitive_path", "sole_approver"),
    "dismiss_stale_reviews": ("fast_approval",),
    "codeowners_coverage": ("sensitive_path",),
    "enforced_for_admins": ("self_approval",),
    "signed_commits_required": (),
    "pull_request_required": ("self_approval",),
    "required_status_checks": (),
    "force_push_blocked": (),
}

UNKNOWN = "unknown"


@dataclass(frozen=True)
class Control:
    """One control, and what the platform can honestly say about it."""

    key: str
    #: `on`, `off`, `partial`, or `unknown`. Four rather than two, because a
    #: control can be present and too weak to matter — one required approval
    #: on a repository with no CODEOWNERS is not the same as two, and neither
    #: is the same as none.
    state: str
    detail: str = ""
    #: Only meaningful for `codeowners_coverage`.
    value: float | None = None

    @property
    def known(self) -> bool:
        return self.state != UNKNOWN


@dataclass(frozen=True)
class Governance:
    """A repository's change-governance posture (spec 30 §2, §3)."""

    repo_full_name: str
    controls: list[Control] = field(default_factory=list)
    read_at: datetime | None = None
    #: Why nothing could be read, where that is the case. The panel shows this
    #: instead of nine identical unknown rows.
    unreadable: str = ""
    #: `branch_protection`, `ruleset`, `both`, or `none` — which model this
    #: repository actually governs itself with. A repository governed entirely
    #: by rulesets would read as unprotected if only the older model were
    #: consulted.
    source: str = "none"

    @property
    def readable(self) -> bool:
        return not self.unreadable


def _bool_control(
    key: str, value: bool | None, *, on: str, off: str, unknown: str
) -> Control:
    if value is None:
        return Control(key=key, state=UNKNOWN, detail=unknown)
    return Control(key=key, state="on" if value else "off", detail=on if value else off)


def _from_protection(protection: dict[str, Any] | None) -> dict[str, Any]:
    """Flatten GitHub's branch-protection shape into plain facts.

    `None` means the branch is unprotected — an answer, and a bad one. It is
    reached only when GitHub returned 404; a refusal raises instead, so
    "not allowed to look" can never render as "there is no protection".
    """
    if protection is None:
        return {
            "pull_request_required": False,
            "required_approvals": 0,
            "dismiss_stale_reviews": False,
            "codeowner_review_required": False,
            "enforced_for_admins": False,
            "signed_commits_required": False,
            "required_status_checks": 0,
            "force_push_blocked": False,
        }

    reviews = protection.get("required_pull_request_reviews") or {}
    checks = protection.get("required_status_checks") or {}
    contexts = checks.get("contexts") or checks.get("checks") or []
    return {
        "pull_request_required": bool(reviews),
        "required_approvals": int(reviews.get("required_approving_review_count") or 0),
        "dismiss_stale_reviews": bool(reviews.get("dismiss_stale_reviews")),
        "codeowner_review_required": bool(reviews.get("require_code_owner_reviews")),
        "enforced_for_admins": bool(
            (protection.get("enforce_admins") or {}).get("enabled")
        ),
        "signed_commits_required": bool(
            (protection.get("required_signatures") or {}).get("enabled")
        ),
        "required_status_checks": len(contexts),
        "force_push_blocked": not bool(
            (protection.get("allow_force_pushes") or {}).get("enabled")
        ),
    }


def _merge_rulesets(facts: dict[str, Any], rulesets: list[dict[str, Any]]) -> dict[str, Any]:
    """Fold in anything the newer ruleset model adds (spec 30 §1.2).

    Rules are merged as *the strongest wins*, never as the newest wins: a
    repository with both models is protected by the union of them, and taking
    either one alone would under-report a repository that is in fact governed
    twice over.

    Only active rulesets count. An `evaluate`-mode ruleset is a dry run — it
    reports what it would have done and blocks nothing — and counting it would
    credit a repository for a control that is switched off.
    """
    merged = dict(facts)
    for ruleset in rulesets:
        if str(ruleset.get("enforcement") or "").lower() != "active":
            continue
        for rule in ruleset.get("rules") or []:
            kind = str(rule.get("type") or "")
            parameters = rule.get("parameters") or {}
            if kind == "pull_request":
                merged["pull_request_required"] = True
                merged["required_approvals"] = max(
                    int(merged.get("required_approvals") or 0),
                    int(parameters.get("required_approving_review_count") or 0),
                )
                merged["dismiss_stale_reviews"] = merged.get(
                    "dismiss_stale_reviews"
                ) or bool(parameters.get("dismiss_stale_reviews_on_push"))
                merged["codeowner_review_required"] = merged.get(
                    "codeowner_review_required"
                ) or bool(parameters.get("require_code_owner_review"))
            elif kind == "required_signatures":
                merged["signed_commits_required"] = True
            elif kind == "required_status_checks":
                merged["required_status_checks"] = max(
                    int(merged.get("required_status_checks") or 0),
                    len(parameters.get("required_status_checks") or []),
                )
            elif kind == "non_fast_forward":
                merged["force_push_blocked"] = True
    return merged


def codeowners_coverage(content: str | None, paths: list[str]) -> float | None:
    """The fraction of source paths CODEOWNERS routes to somebody.

    Uncovered paths are where review routing silently does not happen, which
    is the failure this number exists to make visible: a repository can have
    `require_code_owner_reviews` on and still have most of its code owned by
    nobody, in which case the control fires on almost nothing.

    `None` where there is no file at all, and where there are no paths to
    measure against — an empty repository has not failed a coverage check.
    """
    if content is None or not paths:
        return None
    rules = parse(content)
    if not rules:
        return 0.0
    # `owner_for` rather than a second matcher: it already implements
    # CODEOWNERS' last-match-wins rule, and a coverage number computed by
    # different matching logic than the routing would disagree with the
    # routing exactly where it mattered.
    covered = sum(1 for path in paths if owner_for(path, rules) is not None)
    return round(covered / len(paths), 3)


async def read(
    github: GitHubClient,
    repo_full_name: str,
    default_branch: str,
    *,
    source_paths: list[str] | None = None,
    now: datetime | None = None,
) -> Governance:
    """Read this repository's controls. Never raises."""
    stamp = now or utcnow()

    protection: dict[str, Any] | None = None
    rulesets: list[dict[str, Any]] = []
    source = "none"
    try:
        protection = await github.get_branch_protection(repo_full_name, default_branch)
        if protection is not None:
            source = "branch_protection"
    except PermissionDeniedError:
        return Governance(
            repo_full_name=repo_full_name,
            read_at=stamp,
            unreadable=(
                "The GitHub App installation does not carry `administration: "
                "read`, so none of these controls can be read. That is a "
                "permissions gap, not a security failure, and nothing here is "
                "scored against this repository because of it."
            ),
        )
    except GitHubError as exc:
        logger.warning("Could not read branch protection for %s: %s", repo_full_name, exc)
        return Governance(
            repo_full_name=repo_full_name,
            read_at=stamp,
            unreadable=f"GitHub refused the read: {exc}",
        )

    try:
        rulesets = await github.get_rulesets(repo_full_name)
    except (GitHubError, PermissionDeniedError) as exc:
        # Not fatal on its own. A repository with branch protection and an
        # unreadable ruleset list is still mostly describable, and reporting
        # nothing would throw away what was read.
        logger.info("Could not read rulesets for %s: %s", repo_full_name, exc)

    active = [r for r in rulesets if str(r.get("enforcement") or "").lower() == "active"]
    if active:
        source = "both" if source == "branch_protection" else "ruleset"

    facts = _merge_rulesets(_from_protection(protection), rulesets)

    coverage: float | None = None
    try:
        content = await github.get_file(repo_full_name, ".github/CODEOWNERS", default_branch)
        if content is None:
            content = await github.get_file(repo_full_name, "CODEOWNERS", default_branch)
        coverage = codeowners_coverage(content, source_paths or [])
    except GitHubError as exc:
        logger.info("Could not read CODEOWNERS for %s: %s", repo_full_name, exc)

    return Governance(
        repo_full_name=repo_full_name,
        read_at=stamp,
        source=source,
        controls=_controls(facts, coverage),
    )


def _controls(facts: dict[str, Any], coverage: float | None) -> list[Control]:
    approvals = int(facts.get("required_approvals") or 0)
    checks = int(facts.get("required_status_checks") or 0)

    by_key = {
        "pull_request_required": _bool_control(
            "pull_request_required",
            facts.get("pull_request_required"),
            on="A pull request is required to reach the default branch.",
            off="Anybody with write access can push straight to the default branch.",
            unknown="Not read.",
        ),
        "approving_reviews_required": Control(
            key="approving_reviews_required",
            # One approval is `partial`, not `on`. It is the configuration
            # under which `self_approval` and `sole_approver` both fire, and
            # calling it "on" would put a repository one rubber stamp from a
            # bad merge in the same column as one that requires two people.
            state="on" if approvals >= 2 else "partial" if approvals == 1 else "off",
            detail=(
                f"{approvals} approving review(s) required."
                if approvals
                else "No approving review is required."
            )
            + (
                " One approval means a single reviewer can admit a change,"
                " which is the configuration `sole_approver` fires under."
                if approvals == 1
                else ""
            ),
        ),
        "dismiss_stale_reviews": _bool_control(
            "dismiss_stale_reviews",
            facts.get("dismiss_stale_reviews"),
            on="A new push discards existing approvals.",
            off=(
                "An approval survives later pushes, so a reviewed change and "
                "the change that merges need not be the same one."
            ),
            unknown="Not read.",
        ),
        "codeowner_review_required": _bool_control(
            "codeowner_review_required",
            facts.get("codeowner_review_required"),
            on="A CODEOWNERS reviewer is required.",
            off="Any reviewer satisfies the requirement, whoever owns the code.",
            unknown="Not read.",
        ),
        "codeowners_coverage": (
            Control(
                key="codeowners_coverage",
                state=UNKNOWN,
                detail=(
                    "No CODEOWNERS file, or nothing to measure it against. "
                    "Without one, a code-owner review requirement routes to "
                    "nobody."
                ),
            )
            if coverage is None
            else Control(
                key="codeowners_coverage",
                state="on" if coverage >= 0.9 else "partial" if coverage >= 0.5 else "off",
                detail=f"{coverage:.0%} of source paths route to an owner.",
                value=coverage,
            )
        ),
        "enforced_for_admins": _bool_control(
            "enforced_for_admins",
            facts.get("enforced_for_admins"),
            on="Administrators are bound by these rules too.",
            off=(
                "An administrator can bypass every rule above, which makes "
                "them a description of what usually happens rather than of "
                "what is enforced."
            ),
            unknown="Not read.",
        ),
        "signed_commits_required": _bool_control(
            "signed_commits_required",
            facts.get("signed_commits_required"),
            on="Every commit must carry a verified signature.",
            off="Commits need not be signed.",
            unknown="Not read.",
        ),
        "required_status_checks": Control(
            key="required_status_checks",
            state="on" if checks else "off",
            detail=(
                f"{checks} status check(s) must pass."
                if checks
                else "No status check has to pass before a merge."
            ),
        ),
        "force_push_blocked": _bool_control(
            "force_push_blocked",
            facts.get("force_push_blocked"),
            on="Force pushes to the default branch are blocked.",
            off="History on the default branch can be rewritten.",
            unknown="Not read.",
        ),
    }
    return [by_key[key] for key in CONTROL_ORDER]


# ---------------------------------------------------------------------------
# The aggregate (spec 30 §3)
# ---------------------------------------------------------------------------


@lru_cache(maxsize=1)
def weights(path: Path | None = None) -> dict[str, float]:
    """Per-control weights, from a reviewed file rather than from code.

    The same discipline `oracle-policy-v1.yaml` and `stride-map-v1.yaml`
    follow, and for the same reason: this decides what a team is told to aim
    at, which is a judgement that belongs where it can be argued with in a
    pull request.
    """
    # Via settings, not a module-relative path: `parents[2]` is the repo root
    # from a checkout and the site-packages parent from an installed wheel,
    # which is why production scored every repository off an empty table.
    source = path or get_settings().governance_policy_path
    try:
        document = yaml.safe_load(source.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        logger.warning("Governance policy unreadable at %s; no score computed.", source)
        return {}
    raw = document.get("weights") or {}
    return {
        str(key): float(value)
        for key, value in raw.items()
        if key in CONTROL_ORDER and isinstance(value, int | float)
    }


def score(governance: Governance, *, policy: dict[str, float] | None = None) -> int | None:
    """0–100, or `None` when too little is known to say (spec 30 §3).

    **Scored over what was read, not over what exists.** A repository whose
    controls could not be read has no score, rather than a bad one — the same
    `available: False` rule spec 09 §9 applies to every Oracle input, for the
    identical reason: a permissions gap is not a posture.

    `partial` earns half. A single required approval genuinely is better than
    none and genuinely is not two, and a binary would have to call it one or
    the other.
    """
    table = weights() if policy is None else policy
    if not table or not governance.readable:
        return None

    known = [c for c in governance.controls if c.known and c.key in table]
    if not known:
        return None

    possible = sum(table[c.key] for c in known)
    if not possible:
        return None
    earned = sum(
        table[c.key] * (1.0 if c.state == "on" else 0.5 if c.state == "partial" else 0.0)
        for c in known
    )
    return int(round(100 * earned / possible))


def merge_counts(
    catalog: Catalog, repo_full_name: str, *, days: int = 90, now: datetime | None = None
) -> dict[str, Any]:
    """Three counts over the window, **by repository and never by person**.

    "3 of the last 40 merges had a single approver on a sensitive path" is a
    statement about a control, and its remedy is a settings change. The same
    data grouped by author is a statement about colleagues; spec 06 §9 already
    decided that question and this agrees with it.
    """
    if not catalog.all_files("insider_risk_signals"):
        return {"available": False, "reason": "Insider risk has not assessed anything here."}

    since = (now or utcnow()) - timedelta(days=days)
    rows = catalog.query(
        """
        SELECT count(*),
               count(*) FILTER (WHERE signal_breakdown LIKE '%sole_approver%'
                                  AND signal_breakdown LIKE '%sensitive_path%'),
               count(*) FILTER (WHERE signal_breakdown LIKE '%fast_approval%'),
               count(*) FILTER (WHERE signal_breakdown LIKE '%self_approval%')
        FROM insider_risk_signals
        WHERE repo_full_name = ? AND evaluated_at >= ?
        """,
        [repo_full_name, since],
    )
    if not rows or not rows[0][0]:
        return {
            "available": False,
            "reason": f"No pull request has been assessed here in {days} days.",
        }

    assessed, sole_sensitive, fast, self_approved = (int(v or 0) for v in rows[0])
    return {
        "available": True,
        "days": days,
        "assessed": assessed,
        "sole_approver_on_sensitive_path": sole_sensitive,
        "approved_faster_than_readable": fast,
        "self_approved": self_approved,
        "note": (
            "By repository, never by author. Each of these is a statement "
            "about a control whose remedy is a settings change; the same data "
            "grouped by person would be a statement about colleagues, which "
            "spec 06 §9 rules out."
        ),
    }


#: After this a stored reading is not reported to Oracle. Fourteen days: long
#: enough that a weekly refresh has slack, short enough that a score never
#: rests on a setting somebody changed a month ago. A score that quietly
#: outlives its evidence is the failure this platform keeps refusing to ship.
STALE_AFTER_DAYS = 14


def remember(session: Session, governance: Governance) -> None:
    """Store the reading so Oracle can score it (spec 30 §4).

    Oracle cannot make an HTTP call — it scores from the lake and the
    operational store — so the panel's live read is copied here on its way
    past. One row per repository, replaced outright: this is configuration,
    and a time series of a setting is not evidence the way a scan result is.
    """
    row = session.get(RepoGovernance, governance.repo_full_name)
    if row is None:
        row = RepoGovernance(repo_full_name=governance.repo_full_name)
        session.add(row)
    row.governance_score = score(governance)
    row.source = governance.source
    row.controls_read = sum(1 for c in governance.controls if c.known)
    row.read_at = governance.read_at or utcnow()
    session.flush()


def stored(
    session: Session, repo_full_name: str, *, now: datetime | None = None
) -> dict[str, Any] | None:
    """The last reading, or `None` if there is none or it has gone stale.

    Stale returns `None` rather than an old number, so the Oracle term reports
    `available: False` with a reason. An out-of-date reading of a setting is
    not a weaker version of a current one — it is a claim about a repository
    that may have been reconfigured twice since, and scoring it would be worse
    than scoring nothing.
    """
    row = session.get(RepoGovernance, repo_full_name)
    if row is None or row.governance_score is None:
        return None
    cutoff = (now or utcnow()) - timedelta(days=STALE_AFTER_DAYS)
    if row.read_at < cutoff:
        return None
    return {
        "governance_score": int(row.governance_score),
        "source": row.source,
        "controls_read": int(row.controls_read),
        "read_at": row.read_at,
    }


def as_dict(
    governance: Governance, *, policy: dict[str, float] | None = None
) -> dict[str, Any]:
    return {
        "repo_full_name": governance.repo_full_name,
        "read_at": governance.read_at,
        "readable": governance.readable,
        "unreadable_reason": governance.unreadable,
        "source": governance.source,
        "governance_score": score(governance, policy=policy),
        "controls": [
            {
                "key": control.key,
                "state": control.state,
                "detail": control.detail,
                "value": control.value,
                # What this control would have prevented (spec 30 §2). The
                # link is the point of the panel: it turns a log of oddities
                # into a diagnosis with a remedy the team can action.
                "prevents": list(PREVENTS.get(control.key, ())),
            }
            for control in governance.controls
        ],
        "note": (
            "Read, never written: this platform does not turn on branch "
            "protection for anybody. A control shown as `unknown` could not "
            "be read — a permissions gap, which is not a security failure and "
            "is not scored as one."
        ),
    }
