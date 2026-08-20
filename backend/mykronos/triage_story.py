"""i2i — from a triaged finding or toxic combination to a dev-ready story
(spec 17 §7).

This is the translation step nothing in specs 00-16 defines: a human reads
the triage queue or a Patchwork draft PR and turns it into a ticket with
acceptance criteria by hand, every time. `build_story` does that translation
mechanically, from data the platform already has — it adds no new analysis
of its own, which is the point: everything in a `TriageStory` is already
traceable to a lake row or a Knowledge Store entry (same rule as Oracle's
`inputs_snapshot`, spec 09 §9).

A story missing a field is rendered anyway, with the gap named
(`dev_ready: False`, `missing_fields`) — never a section that silently
disappears. `reachability` and `exploitability` being `unknown`/absent does
**not** block dev-ready status (spec 17 §7.1): v1 has no reachability engine
at all (spec 17 §5.3) and not every finding names a CVE, and neither is a
reason to withhold a story that is otherwise complete.
"""

from __future__ import annotations

import hashlib
import json
from contextlib import suppress
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session

from mykronos.db.models import ThreatIntelMatch
from mykronos.knowledge.store import KnowledgeEntry, KnowledgeStore
from mykronos.lake.catalog import Catalog
from mykronos.patchwork import correlate
from mykronos.schemas import Severity
from mykronos.threat_intel import extract_cve

#: Per-capability acceptance criterion, filled from the finding/combination
#: itself. Deliberately short and mechanical — "how would a re-scan confirm
#: this is fixed" — not a design for the fix, which is the developer's job.
ACCEPTANCE_CRITERIA_TEMPLATES: dict[str, str] = {
    "sast": (
        "The flagged line no longer matches `{rule_id}`'s pattern on a "
        "re-scan of `{location}`."
    ),
    "secrets": (
        "The credential is rotated and removed from the working tree; a "
        "re-scan of `{location}` reports no match for `{rule_id}`."
    ),
    "containers": (
        "The base image or package is upgraded past the fixed version; a "
        "re-scan of `{location}` reports no `{rule_id}` finding."
    ),
    "iac": (
        "The flagged resource is updated to satisfy `{rule_id}`; a re-scan "
        "of `{location}` reports no match."
    ),
    "dast": (
        "The flagged endpoint no longer exhibits the behaviour `{rule_id}` "
        "describes on a re-scan."
    ),
    "cloud": (
        "The flagged resource's posture is corrected; a re-scan reports no "
        "`{rule_id}` finding for it."
    ),
    "atlas": (
        "The pinned lockfile version for `{location}` is at or above the "
        "fixed version; a re-scan reports no `{rule_id}` finding."
    ),
    "network": (
        "The exposed service at `{location}` is closed or firewalled; a "
        "re-scan reports no `{rule_id}` finding."
    ),
}
DEFAULT_ACCEPTANCE_CRITERION = "The finding no longer appears on a re-scan of this repository."

#: GitHub labels a groomed issue carries — dev_ready or not, so a backlog
#: view can tell the two apart without opening every issue (spec 17 §7.2).
LABEL_DEV_READY = "mykronos:dev-ready"
LABEL_NEEDS_TRIAGE = "mykronos:needs-triage"

#: Severity -> the priority label an auto-filed story carries (spec 19 §4.3).
#: A label on the issue rather than a field on `TriageStory`, so a tracker can
#: sort a backlog without Mykronos owning what "priority" means to a team.
PRIORITY_LABELS = {
    "critical": "mykronos:priority-urgent",
    "high": "mykronos:priority-urgent",
    "medium": "mykronos:priority-normal",
    "low": "mykronos:priority-low",
    "info": "mykronos:priority-low",
}


def story_id(repo_full_name: str, subject_id: str) -> str:
    """Derived, not random (spec 17 §7.2) — same rule as `finding_id`
    (spec 05 §5), `event_id` (spec 08 §4), `entry_id` (spec 11 §3): grooming
    the same finding or combination twice must resolve to the same story,
    or re-grooming would open a second issue instead of updating the first.
    """
    material = repo_full_name + "\x00" + subject_id
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def acceptance_criterion(rule_id: str, capability: str, location: str) -> str:
    template = ACCEPTANCE_CRITERIA_TEMPLATES.get(capability, DEFAULT_ACCEPTANCE_CRITERION)
    return template.format(rule_id=rule_id, location=location or "the flagged location")


def false_positive_precedent(
    entries: list[tuple[KnowledgeEntry, float]], rule_id: str, repo_full_name: str
) -> str | None:
    """Any reasoned dismissal of this rule in this repo (spec 17 §7.1) —
    surfaced, never suppressing the story. The same lookup
    `patchwork/triage.py::classify` uses, restated as a sentence rather than
    a classification, since this reader wants the precedent, not a verdict.
    """
    for entry, _confidence in entries:
        if (
            entry.source_type == "finding_dismissal"
            and entry.subject == rule_id
            and entry.repo_full_name in (None, repo_full_name)
            and entry.has_reason
        ):
            reason = entry.reasons[0] if entry.reasons else ""
            return (
                f"This repository has dismissed {rule_id} {entry.observations} "
                f"time(s) with a written reason, most recently: “{reason}”. "
                "Confirm this occurrence is not the same case before treating "
                "it as a true positive."
            )
    return None


@dataclass(frozen=True)
class OracleContext:
    """What the repo's last portfolio decision said about this severity band
    — not a per-finding split, which Oracle's log2 curve does not have a
    clean way to produce (spec 09 §5's curve is deliberately sub-linear).
    Honest about that rather than fabricating a precise number."""

    overall_risk_score: int
    recommendation: str
    band_contribution: float | None
    band_detail: str | None


@dataclass(frozen=True)
class TriageStory:
    subject_id: str
    subject_type: str  # "finding" | "combination"
    repo_full_name: str
    title: str
    description: str
    severity: str
    capability: str
    location: str
    oracle: OracleContext | None
    reachability: str  # always "unknown" in v1 — see module docstring
    cve_id: str | None
    in_kev: bool | None
    epss_score: float | None
    dedup_count: int
    false_positive_note: str | None
    suggested_fix: str
    acceptance_criteria: list[str] = field(default_factory=list)

    @property
    def id(self) -> str:
        return story_id(self.repo_full_name, self.subject_id)

    @property
    def missing_fields(self) -> list[str]:
        """Fields whose absence genuinely blocks dev-ready status.
        Reachability/exploitability/dedup/false-positive-precedent are
        exempt by design (spec 17 §7.1) — `unknown`/`None`/`0` are honest
        answers for them, not gaps."""
        missing = []
        if not self.title:
            missing.append("title")
        if not self.description:
            missing.append("description")
        if not self.acceptance_criteria:
            missing.append("acceptance_criteria")
        return missing

    @property
    def dev_ready(self) -> bool:
        return not self.missing_fields

    def render_issue_body(self) -> str:
        lines = [
            self.description or "_No description was reported by the scanner._",
            "",
            "## Triage",
            "",
            f"- **Severity:** {self.severity}",
            f"- **Capability:** {self.capability}",
            f"- **Location:** `{self.location or 'unknown'}`",
        ]

        if self.oracle is not None:
            lines.append(
                f"- **Oracle:** repo's last portfolio decision is "
                f"{self.oracle.recommendation} ({self.oracle.overall_risk_score}/100)"
                + (
                    f" — {self.severity} findings contributed "
                    f"+{self.oracle.band_contribution:.1f} ({self.oracle.band_detail})"
                    if self.oracle.band_contribution is not None
                    else ""
                )
            )
        else:
            lines.append("- **Oracle:** not assessed — Oracle is not enabled for this repository")

        lines.append(
            "- **Reachability:** unknown — no reachability analysis is "
            "configured for this deployment (spec 17 §5.3)"
        )

        if self.cve_id is None:
            lines.append("- **Exploitability:** this finding names no CVE — no data available")
        elif self.in_kev:
            lines.append(
                f"- **Exploitability:** {self.cve_id} is listed in CISA's Known "
                "Exploited Vulnerabilities catalog"
            )
        else:
            epss = f", EPSS {self.epss_score:.0%}" if self.epss_score is not None else ""
            lines.append(f"- **Exploitability:** {self.cve_id} is not KEV-listed{epss}")

        lines.append(
            f"- **Dedup history:** this identity has recurred {self.dedup_count} time(s) "
            "under a prior fingerprint"
            if self.dedup_count
            else "- **Dedup history:** no prior fingerprint for this identity"
        )

        if self.false_positive_note:
            lines += ["", "## False-positive precedent", "", self.false_positive_note]

        lines += ["", "## Suggested fix", "", self.suggested_fix]

        lines += ["", "## Acceptance criteria", ""]
        lines += [f"- [ ] {criterion}" for criterion in self.acceptance_criteria]
        if not self.acceptance_criteria:
            lines.append("_None generated — this story is not dev-ready._")

        lines += [
            "",
            "---",
            "",
            f"<sub>Opened by Mykronos's i2i process (spec 17 §7) from "
            f"{self.subject_type} `{self.subject_id}`. Re-grooming this "
            f"{self.subject_type} updates this issue rather than opening a "
            f"second one.</sub>",
        ]
        return "\n".join(lines)

    @property
    def labels(self) -> list[str]:
        labels = [LABEL_DEV_READY if self.dev_ready else LABEL_NEEDS_TRIAGE]
        priority = PRIORITY_LABELS.get(self.severity)
        if priority:
            labels.append(priority)
        return labels


# ---------------------------------------------------------------------------
# Gathering — the impure half. Reads the lake and the operational database;
# everything above this line is a pure function of what gets handed to it.
# ---------------------------------------------------------------------------


def _dedup_count(catalog: Catalog, finding_id: str) -> int:
    """How many prior identities were re-fingerprinted into this one
    (spec 05 §5a) — a single level of the chain, which is the honest,
    simple reading of "this pattern has recurred N times" for v1."""
    rows = catalog.query(
        "SELECT count(*) FROM findings WHERE superseded_by = ?", [finding_id]
    )
    return int(rows[0][0]) if rows else 0


def _suggested_fix(catalog: Catalog, *, finding_id: str | None, combination_id: str | None) -> str:
    """The most recent Patchwork verdict for this finding or combination
    (spec 08 §4), or the honest `no_fix_available` when Patchwork has never
    run on it — never fabricated, and never silently blank."""
    if finding_id is not None:
        rows = catalog.query(
            "SELECT rationale, pipeline_stage_reached FROM remediation_events "
            "WHERE finding_id = ? ORDER BY created_at DESC LIMIT 1",
            [finding_id],
        )
    else:
        rows = catalog.query(
            "SELECT rationale, pipeline_stage_reached FROM remediation_events "
            "WHERE toxic_combination_id = ? ORDER BY created_at DESC LIMIT 1",
            [combination_id],
        )
    upstream = _upstream_fix_note(catalog, finding_id)
    if not rows:
        return (
            "no_fix_available — Patchwork has not run on this repository, "
            "or has not reached it yet." + upstream
        )
    rationale, stage = rows[0]
    verdict = str(rationale) if rationale else f"no_fix_available (pipeline stage: {stage})"
    return verdict + upstream


def _upstream_fix_note(catalog: Catalog, finding_id: str | None) -> str:
    """Whether a fixed version exists at all, per the scanner.

    Patchwork's `no_fix_available` means *this platform* has no fixer for it,
    and a developer reads that as unassigned work. For a distribution package
    it usually means something else entirely: the scanner reported no fixed
    version, so the upstream maintainer has not shipped one and nobody can
    remediate it today at any price.

    Sixteen critical Perl CVEs on TheHub read as a backlog for a week on that
    ambiguity. All sixteen had `fixed_version: null` — no rebuild, no bump and
    no fixer would have closed any of them.

    Silent when the finding names no package or the scanner recorded a fixed
    version: this is only here to name the case where remediation is not
    available, never to imply one exists.
    """
    if finding_id is None:
        return ""
    rows = catalog.query(
        "SELECT package_name, package_version, raw_finding_json FROM findings "
        "WHERE finding_id = ? LIMIT 1",
        [finding_id],
    )
    if not rows:
        return ""
    package, version, raw = rows[0]
    if not package:
        return ""
    try:
        fixed = (json.loads(raw) if raw else {}).get("fixed_version")
    except (TypeError, json.JSONDecodeError):
        return ""

    if fixed:
        return (
            f"\n\nUpstream has a fix: `{package}` {version or '?'} → "
            f"`{fixed}`. Rebuilding or bumping to that version closes this."
        )
    return (
        f"\n\n**No upstream fix exists yet** for `{package}` {version or ''}"
        " — the scanner reported no fixed version, so this cannot be"
        " remediated by rebuilding, bumping, or any patch this platform could"
        " write. The available dispositions are to accept the risk with a"
        " reason, or to wait for the maintainer and let the next scan close"
        " it automatically."
    )


def _oracle_context(catalog: Catalog, repo_full_name: str, severity: str) -> OracleContext | None:
    """The repo's last portfolio decision, and this severity band's own
    contribution to it if that decision scored one (spec 09 §5's terms are
    per severity band, not per finding — see `OracleContext`'s own
    docstring for why this stops there rather than fabricating a split)."""
    rows = catalog.query(
        "SELECT overall_risk_score, recommendation, inputs_snapshot "
        "FROM risk_decisions WHERE repo_full_name = ? AND decision_type = 'portfolio' "
        "ORDER BY evaluated_at DESC LIMIT 1",
        [repo_full_name],
    )
    if not rows:
        return None
    score, recommendation, snapshot_json = rows[0]
    terms: list[dict[str, Any]] = []
    if snapshot_json:
        with suppress(TypeError, json.JSONDecodeError):
            terms = json.loads(snapshot_json).get("terms", [])
    band = next((t for t in terms if t.get("key") == f"findings.{severity}"), None)
    return OracleContext(
        overall_risk_score=int(score),
        recommendation=str(recommendation),
        band_contribution=float(band["contribution"]) if band else None,
        band_detail=str(band["detail"]) if band else None,
    )


def _threat_intel_for(session: Session, cve_id: str | None) -> tuple[bool | None, float | None]:
    if cve_id is None:
        return None, None
    match = session.get(ThreatIntelMatch, cve_id)
    if match is None:
        return False, None  # checked, not (yet) matched — see TriageStory.cve_id's docstring
    return bool(match.in_kev), match.epss_score


def gather_finding_story(
    catalog: Catalog,
    session: Session,
    store: KnowledgeStore | None,
    finding: dict[str, Any],
) -> TriageStory:
    """Assemble a `TriageStory` for one finding (spec 17 §7.1). `finding` is
    `DashboardQueries.finding()`'s row — the caller looks it up and checks
    for `None` (unknown id), so this only ever handles a real one."""
    repo_full_name = str(finding["repo_full_name"])
    finding_id = str(finding["finding_id"])
    rule_id = str(finding.get("rule_id") or "")
    capability = str(finding.get("capability") or "")
    severity = str(finding.get("severity") or "")
    location = str(finding.get("file_path") or finding.get("package_name") or "")
    title = str(finding.get("title") or rule_id)

    cve_id = extract_cve(rule_id, title)
    in_kev, epss_score = _threat_intel_for(session, cve_id)

    entries = [] if store is None else store.active_entries()

    return TriageStory(
        subject_id=finding_id,
        subject_type="finding",
        repo_full_name=repo_full_name,
        title=title,
        description=str(finding.get("description") or ""),
        severity=severity,
        capability=capability,
        location=location,
        oracle=_oracle_context(catalog, repo_full_name, severity),
        reachability="unknown",
        cve_id=cve_id,
        in_kev=in_kev,
        epss_score=epss_score,
        dedup_count=_dedup_count(catalog, finding_id),
        false_positive_note=false_positive_precedent(entries, rule_id, repo_full_name),
        suggested_fix=_suggested_fix(catalog, finding_id=finding_id, combination_id=None),
        acceptance_criteria=[acceptance_criterion(rule_id, capability, location)],
    )


def gather_combination_story(
    catalog: Catalog,
    session: Session,
    store: KnowledgeStore | None,
    repo_full_name: str,
    combination: correlate.Combination,
    rule: correlate.CombinationRule | None,
    members: list[dict[str, Any]],
) -> TriageStory:
    """Assemble a `TriageStory` for a detected toxic combination. `members`
    are the contributing findings' rows, in the same shape `finding()`
    returns them, from whichever repo query re-ran `correlate.detect()` to
    find this combination in the first place."""
    entries = [] if store is None else store.active_entries()

    severities = [str(m.get("severity") or "info") for m in members]
    order = [s.value for s in Severity]
    worst = max(severities, key=lambda s: order.index(s) if s in order else -1)

    criteria = [
        acceptance_criterion(
            str(m.get("rule_id") or ""),
            str(m.get("capability") or ""),
            str(m.get("file_path") or m.get("package_name") or ""),
        )
        for m in members
    ]

    cve_ids = [
        cve
        for m in members
        if (cve := extract_cve(str(m.get("rule_id") or ""), str(m.get("title") or "")))
    ]
    # A combination can name more than one CVE; the first is reported the
    # same way a single finding's is — this is a summary field, not a full
    # accounting, and the full member list is in the rendered body.
    cve_id = cve_ids[0] if cve_ids else None
    in_kev, epss_score = _threat_intel_for(session, cve_id)

    fp_notes = [
        note
        for m in members
        if (note := false_positive_precedent(entries, str(m.get("rule_id") or ""), repo_full_name))
    ]

    return TriageStory(
        subject_id=combination.combination_id,
        subject_type="combination",
        repo_full_name=repo_full_name,
        title=rule.name if rule else combination.rule_id,
        description=combination.rationale,
        severity=worst,
        capability="/".join(sorted({str(m.get("capability") or "") for m in members})),
        location="; ".join(
            sorted({str(m.get("file_path") or m.get("package_name") or "") for m in members} - {""})
        ),
        oracle=_oracle_context(catalog, repo_full_name, worst),
        reachability="unknown",
        cve_id=cve_id,
        in_kev=in_kev,
        epss_score=epss_score,
        dedup_count=0,  # combinations are not fingerprinted/superseded themselves
        false_positive_note=" ".join(fp_notes) if fp_notes else None,
        suggested_fix=_suggested_fix(
            catalog, finding_id=None, combination_id=combination.combination_id
        ),
        acceptance_criteria=criteria,
    )
