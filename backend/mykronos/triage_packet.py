"""The pre-sprint security triage packet (ARRI D2.6, TheHub #61346).

`mykronos triage-packet --for-next-sprint` builds what the operator selects
security work from before a sprint starts: one candidate per change (the
`guidance` fix group, per repository), each with

- the scanner's band and a contextual band side by side, with the reason it
  moved, and the environmental band where one is scored (shadow mode);
- every factor that moved it marked **observed**, **declared** or
  **unknown**, with the evidence for that state. Unknown is never read as the
  safe answer (D-176): an unfetched CVE is "exploitability unknown", never
  "not in KEV";
- the mandatory rules applied (KEV-listed, overdue at high or above, an
  exposed secret, a toxic-combination member, contextual critical);
- a remediation outline, a mitigation, the tests, acceptance criteria that end
  in a production check, and a size.

A group with no published fix is not a candidate: there is no change to make,
so it is an operator item (accept with `no_vendor_fix` and a review date,
mitigate, or replace the component). A high whose key factors are mostly
unknown becomes a small validation spike rather than a fix nobody can size.

**Sprints are not measured in days** (TheHub #61357). A sprint starts when the
operator starts it and finishes when its work ships, so the packet is built
for *the next sprint*, never for a date, and names no weekday.

Nothing private leaves this module: every string in the packet is passed
through `redact`, which removes URLs, IP addresses and host names. The packet
never reads a token.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import select

from mykronos import guidance, sprint_signal
from mykronos.lake.catalog import Catalog
from mykronos.threat_intel import extract_cve

#: Bands from lowest to highest.
BANDS = ("info", "low", "medium", "high", "critical")

#: The factors whose state decides whether a high is fixed or validated
#: first. Severity and the deadline are always known or not key.
KEY_FACTORS = ("exploitability", "exposure", "reachability")

#: Two unknown key factors at high or above: confirm before fixing.
SPIKE_UNKNOWNS = 2

FOR_NEXT_SPRINT = "next_sprint"

SPRINT_MODEL = (
    "A sprint starts when the operator starts it and finishes when its work "
    "ships (TheHub #61357). This packet is for the next one; it names no date."
)

STATES = ("observed", "declared", "unknown")

_SIZE_BY_EFFORT = {"config": "S", "upgrade": "S", "rotate": "S", "judgement": "M"}

_MITIGATION = {
    "dast": "Block or rate-limit the affected route at the proxy until the change ships.",
    "containers": "Restrict the image's network reach and run it unprivileged until rebuilt.",
    "atlas": "Pin the dependency away from the affected code path until upgraded.",
    "sast": "Guard the affected code path (input validation or a feature flag) until fixed.",
    "iac": "Apply the setting by hand on the live resource until the template is fixed.",
    "secrets": "Revoke the credential now; rotation is the fix, revocation the mitigation.",
    "network": "Close the port at the host firewall until the service is reconfigured.",
}


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------

_URL = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s)\"'<>]+", re.I)
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b")
_IPV6 = re.compile(r"\b(?:[0-9a-f]{1,4}:){3,7}[0-9a-f]{1,4}\b", re.I)
#: Under a top-level name a host carries: `db.internal.example.test`. Not
#: any dotted word, so `os.path.join` and `package.json` survive.
_TLDS = (
    "com|net|org|io|dev|test|example|invalid|local|localhost|internal|lan|home|"
    "arpa|cloud|ai|co|uk|us|de|app|info|biz|me|tv|xyz|site|online|tech"
)
_HOST = re.compile(rf"\b(?:[a-z0-9-]+\.)+(?:{_TLDS})\b", re.I)


def redact(text: str) -> str:
    """`text` with every URL, address and host name replaced."""
    out = _URL.sub("[url]", text)
    out = _IPV4.sub("[address]", out)
    out = _IPV6.sub("[address]", out)
    return _HOST.sub("[host]", out)


def _scrub(value: Any) -> Any:
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, list):
        return [_scrub(v) for v in value]
    if isinstance(value, dict):
        return {k: _scrub(v) for k, v in value.items()}
    return value


# ---------------------------------------------------------------------------
# The packet
# ---------------------------------------------------------------------------


@dataclass
class Factor:
    name: str
    #: observed | declared | unknown
    state: str
    evidence: str


@dataclass
class TriageCandidate:
    id: str
    title: str
    repo: str
    #: fix | validation
    type: str
    fix_id: str
    capability: str
    findings: int
    existing_story: int | None
    scanner_band: str
    contextual_band: str
    environmental_band: str | None
    rationale: str
    factors: list[Factor]
    evidence: list[str]
    remediation_outline: list[str]
    mitigation: str
    tests: list[str]
    acceptance_criteria: list[str]
    size: str
    unknowns: list[str]
    downgrade_needs_confirmation: bool
    #: mandatory | recommended | optional
    classification: str
    mandatory_reasons: list[str]
    priority: int = 0


@dataclass
class OperatorItem:
    #: no_fix | lane
    kind: str
    title: str
    repo: str
    detail: str
    options: list[str]
    recommendation: str


@dataclass
class Packet:
    generated_at: datetime
    candidates: list[TriageCandidate] = field(default_factory=list)
    operator_items: list[OperatorItem] = field(default_factory=list)
    board_read: bool = False
    budget: int | None = None
    #: Inputs that could not be read, by name. Never shown as "none found".
    unknown_sources: list[str] = field(default_factory=list)

    def capacity(self) -> dict[str, Any]:
        mandatory = sum(1 for c in self.candidates if c.classification == "mandatory")
        return {
            "unit": "stories",
            "security_budget": self.budget,
            "mandatory": mandatory,
            "over_budget_by": (
                max(0, mandatory - self.budget) if self.budget is not None else None
            ),
            "note": (
                "Mandatory work is listed whatever the budget; when it exceeds the "
                "budget the operator decides what else moves."
                if self.budget is not None
                else "No security budget given (--budget N), so no overflow is computed."
            ),
        }

    def to_dict(self) -> dict[str, Any]:
        def factor(f: Factor) -> dict[str, Any]:
            return {"name": f.name, "state": f.state, "evidence": f.evidence}

        candidates = []
        for c in self.candidates:
            row = dict(c.__dict__)
            row["factors"] = [factor(f) for f in c.factors]
            candidates.append(row)
        data = {
            "for": FOR_NEXT_SPRINT,
            "sprint_model": SPRINT_MODEL,
            "generated_at": self.generated_at.isoformat(timespec="seconds"),
            "board_read": self.board_read,
            "capacity": self.capacity(),
            "candidates": candidates,
            "operator_items": [dict(i.__dict__) for i in self.operator_items],
            "unknown_sources": list(self.unknown_sources),
        }
        return dict(_scrub(data))


def _band(severity: str | None) -> str | None:
    value = str(severity or "").lower()
    return value if value in BANDS else None


def _step(band: str, steps: int) -> str:
    return BANDS[max(0, min(len(BANDS) - 1, BANDS.index(band) + steps))]


def _naive(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value.replace(tzinfo=None)
    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(value).replace(tzinfo=None)
        except ValueError:
            return None
    return None


def _open_findings(catalog: Catalog) -> list[dict[str, Any]]:
    if not catalog.all_files("findings"):
        return []
    rows = catalog.query(
        """
        SELECT finding_id, coalesce(repo_full_name, asset_id), capability, rule_id,
               title, lower(coalesce(severity, '')), raw_finding_json, due_at,
               file_path
        FROM findings WHERE status = 'open'
        """
    )
    keys = (
        "finding_id", "repo", "capability", "rule_id", "title", "severity",
        "raw", "due_at", "file_path",
    )
    found = []
    for row in rows:
        entry = dict(zip(keys, row, strict=True))
        try:
            entry["raw"] = json.loads(entry["raw"]) if entry["raw"] else {}
        except (ValueError, TypeError):
            entry["raw"] = {}
        if not isinstance(entry["raw"], dict):
            entry["raw"] = {}
        found.append(entry)
    return found


@dataclass
class _Context:
    """Everything outside the lake the factors read, each None when unread."""

    intel: dict[str, Any] | None = None
    internet_facing: dict[str, bool | None] | None = None
    probed_repos: set[str] | None = None
    reachability: dict[str, tuple[set[str], bool]] | None = None
    environmental: dict[str, str] | None = None
    unknown_sources: list[str] = field(default_factory=list)


def _context(db: Any, cves: set[str], ids: list[str]) -> _Context:
    from mykronos.db.models import (
        EnvironmentalScore,
        PublicEndpoint,
        ReachabilityReport,
        RepoOnboarding,
        RiskProfile,
        ThreatIntelMatch,
    )

    ctx = _Context()
    if db is None:
        ctx.unknown_sources.append("operational database")
        return ctx

    def read(name: str, fn: Any) -> Any:
        try:
            with db.session() as session:
                return fn(session)
        except Exception:  # noqa: BLE001 - reported as an unknown source
            ctx.unknown_sources.append(name)
            return None

    ctx.intel = read(
        "threat intelligence",
        lambda s: {
            m.cve_id: m
            for m in s.execute(
                select(ThreatIntelMatch).where(ThreatIntelMatch.cve_id.in_(sorted(cves)))
            ).scalars()
        }
        if cves
        else {},
    )

    def profiles(s: Any) -> dict[str, bool | None]:
        rows = s.execute(
            select(RepoOnboarding.github_repo_full_name, RiskProfile.internet_facing).join(
                RiskProfile, RiskProfile.repo_onboarding_id == RepoOnboarding.id
            )
        ).all()
        return {str(name): value for name, value in rows}

    ctx.internet_facing = read("risk profiles", profiles)
    ctx.probed_repos = read(
        "public endpoints",
        lambda s: {
            str(e.repo_full_name)
            for e in s.execute(
                select(PublicEndpoint).where(PublicEndpoint.last_status == "probed")
            ).scalars()
        },
    )

    def reach(s: Any) -> dict[str, tuple[set[str], bool]]:
        found: dict[str, tuple[set[str], bool]] = {}
        rows = s.execute(
            select(RepoOnboarding.github_repo_full_name, ReachabilityReport).join(
                ReachabilityReport, ReachabilityReport.repo_onboarding_id == RepoOnboarding.id
            )
        ).all()
        for name, report in rows:
            complete = int(report.files_unparseable or 0) == 0 and int(
                report.files_analysed or 0
            ) > 0
            found[str(name)] = (
                {str(p).lstrip("./") for p in report.orphaned_paths or []},
                complete,
            )
        return found

    ctx.reachability = read("reachability", reach)
    ctx.environmental = read(
        "environmental scores",
        lambda s: {
            str(r.finding_id): str(r.effective_severity)
            for r in s.execute(
                select(EnvironmentalScore).where(EnvironmentalScore.finding_id.in_(ids))
            ).scalars()
        }
        if ids
        else {},
    )
    return ctx


def _exploitability(cves: list[str], ctx: _Context) -> tuple[Factor, bool, bool]:
    """(factor, any KEV-listed, any elevated) for the group's CVEs."""
    if not cves:
        return (
            Factor(
                "exploitability",
                "unknown",
                "No CVE named, so no exploit intelligence applies: exploitability unknown.",
            ),
            False,
            False,
        )
    if ctx.intel is None:
        return (
            Factor(
                "exploitability",
                "unknown",
                "Threat intelligence could not be read: exploitability unknown.",
            ),
            False,
            False,
        )
    checked = [ctx.intel[c] for c in cves if c in ctx.intel]
    unchecked = [c for c in cves if c not in ctx.intel]
    if not checked:
        return (
            Factor(
                "exploitability",
                "unknown",
                f"KEV and EPSS never fetched for {', '.join(unchecked[:5])}: "
                "exploitability unknown.",
            ),
            False,
            False,
        )
    kev = [m.cve_id for m in checked if m.in_kev]
    epss = [m.epss_score for m in checked if m.epss_score is not None]
    elevated = bool(kev) or any(e >= 0.1 for e in epss) or any(
        m.exploit_refs_json for m in checked
    )
    parts = []
    if kev:
        parts.append(f"listed in CISA KEV: {', '.join(kev[:5])}")
    else:
        parts.append(f"{len(checked)} CVE(s) checked against CISA KEV, none listed")
    parts.append(f"highest EPSS {max(epss):.3f}" if epss else "EPSS not scored yet")
    if unchecked:
        parts.append(f"{len(unchecked)} CVE(s) not yet checked")
    return Factor("exploitability", "observed", "; ".join(parts) + "."), bool(kev), elevated


def _exposure(repo: str, capability: str, ctx: _Context) -> tuple[Factor, bool]:
    """(factor, observed or declared internet-facing)."""
    if ctx.probed_repos is not None and repo in ctx.probed_repos and capability == "dast":
        return (
            Factor(
                "exposure",
                "observed",
                "Found by the dynamic scan of an application with a probed public endpoint.",
            ),
            True,
        )
    if ctx.internet_facing is not None and ctx.internet_facing.get(repo) is not None:
        facing = bool(ctx.internet_facing[repo])
        return (
            Factor(
                "exposure",
                "declared",
                "The risk profile declares this repository "
                + ("internet-facing." if facing else "not internet-facing."),
            ),
            facing,
        )
    return (
        Factor(
            "exposure",
            "unknown",
            "Not observed, and no risk profile records whether it is internet-facing: "
            "exposure unknown.",
        ),
        False,
    )


def _reachability(
    repo: str, capability: str, paths: list[str], ctx: _Context
) -> tuple[Factor, bool]:
    """(factor, observed unreachable)."""
    if capability == "sast" and paths and ctx.reachability is not None:
        entry = ctx.reachability.get(repo)
        if entry is not None and entry[1]:
            orphaned = [p for p in paths if p.lstrip("./") in entry[0]]
            if orphaned and len(orphaned) == len(paths):
                return (
                    Factor(
                        "reachability",
                        "observed",
                        "The import graph shows every affected file is imported by nothing.",
                    ),
                    True,
                )
            return (
                Factor(
                    "reachability",
                    "observed",
                    "The import graph shows the affected code is imported by the application.",
                ),
                False,
            )
    return (
        Factor(
            "reachability",
            "unknown",
            "No complete reachability analysis covers this code: reachability unknown.",
        ),
        False,
    )


def _deadline(dues: list[datetime], now: datetime) -> tuple[Factor, bool]:
    if not dues:
        return Factor("deadline", "unknown", "No remediation deadline recorded."), False
    first = min(dues)
    if first < now:
        days = (now - first).days
        return Factor("deadline", "declared", f"Overdue by {days} day(s) under the SLA."), True
    return (
        Factor("deadline", "declared", f"Due in {(first - now).days} day(s) under the SLA."),
        False,
    )


def _existing(
    key: str, title: str, fix_id: str, board: Any
) -> int | None:
    if board is None:
        return None
    from mykronos.daily_briefing import STORY, Line, on_board

    stories = [s for bucket in (board.stories or {}).values() for s in bucket]
    for story in stories:
        if sprint_signal.story_key(story) == key:
            return int(story["id"])
    match = on_board(
        Line(what=title, so_what="", work=STORY, ref=fix_id),
        [s for s in stories if s.get("bucket") != "done"],
    )
    return int(match["id"]) if match else None


def _toxic_members(report: Any) -> dict[str, str]:
    """finding_id -> the combination's name, from the briefing's read."""
    members: dict[str, str] = {}
    for combo in getattr(report, "toxic", None) or []:
        entry = combo if isinstance(combo, dict) else getattr(combo, "__dict__", {})
        for member in entry.get("members") or []:
            fid = member.get("finding_id") if isinstance(member, dict) else None
            if fid:
                members[str(fid)] = str(entry.get("name") or "a toxic combination")
    return members


def build(
    catalog: Catalog,
    db: Any,
    *,
    now: datetime,
    report: Any = None,
    board: Any = None,
    budget: int | None = None,
) -> Packet:
    """The packet for the next sprint. Never raises for an unreadable input:
    it is named in `unknown_sources` and its factors read unknown."""
    packet = Packet(generated_at=now, board_read=board is not None, budget=budget)
    if board is None:
        packet.unknown_sources.append("TheHub board (existing stories not checked)")

    findings = _open_findings(catalog)
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    for f in findings:
        fix_id, action, effort, steps = guidance.fix_of(
            str(f["capability"]), f["rule_id"], f["title"], f["raw"]
        )
        entry = groups.setdefault(
            (str(f["repo"]), fix_id),
            {
                "action": action,
                "title": guidance._clean(
                    guidance._AT_LOCATION.sub("", str(f["title"] or "")), 255
                ),
                "effort": effort,
                "steps": steps,
                "capability": str(f["capability"]),
                "findings": [],
            },
        )
        entry["findings"].append(f)

    ids = [str(f["finding_id"]) for f in findings]
    cves = {
        c for f in findings if (c := extract_cve(f["rule_id"], f["title"])) is not None
    }
    ctx = _context(db, cves, ids)
    packet.unknown_sources.extend(ctx.unknown_sources)
    toxic = _toxic_members(report)

    for (repo, fix_id), entry in sorted(groups.items()):
        members = entry["findings"]
        capability = entry["capability"]
        title = entry["action"] if not fix_id.startswith("rule:") else entry["title"]
        title = title or fix_id
        if entry["effort"] == "no_fix":
            packet.operator_items.append(
                OperatorItem(
                    kind="no_fix",
                    title=title,
                    repo=repo,
                    detail=f"{len(members)} open finding(s) with no published fix.",
                    options=[
                        "Accept with no_vendor_fix and a review date; MyKronos re-opens "
                        "it when a fix ships.",
                        f"Mitigate: {_MITIGATION.get(capability, 'reduce exposure')}",
                        "Remove or replace the component.",
                    ],
                    recommendation="Accept with no_vendor_fix and a review date: there is "
                    "nothing to upgrade to, so a story would be work that closes nothing.",
                )
            )
            continue

        severities = Counter(_band(f["severity"]) or "unknown" for f in members)
        known = [b for b in severities if b in BANDS]
        scanner = max(known, key=BANDS.index) if known else None
        group_cves = sorted(
            {c for f in members if (c := extract_cve(f["rule_id"], f["title"])) is not None}
        )
        exploit, kev, elevated = _exploitability(group_cves, ctx)
        exposure, internet = _exposure(repo, capability, ctx)
        paths = [str(f["file_path"]) for f in members if f["file_path"]]
        reach, unreachable = _reachability(repo, capability, paths, ctx)
        dues = [d for f in members if (d := _naive(f["due_at"])) is not None]
        deadline, overdue = _deadline(dues, now)
        severity = Factor(
            "severity",
            "observed" if scanner else "unknown",
            (
                "Scanner severity: "
                + ", ".join(f"{n} {s}" for s, n in sorted(severities.items()))
                + "."
            )
            if scanner
            else "The scanner gave no severity: unknown, and not weighted as low.",
        )
        factors = [severity, exploit, exposure, reach, deadline]

        # Contextual band: raised by what was observed or declared, lowered
        # only by an observed fact, and never moved by an unknown.
        base = scanner or "medium"
        contextual, moved = base, []
        if kev:
            contextual, moved = "critical", ["listed in CISA KEV"]
        else:
            if elevated and internet:
                contextual = _step(contextual, 1)
                moved.append("an exploit signal on an internet-facing service")
            if unreachable:
                contextual = _step(contextual, -1)
                moved.append("the affected code is imported by nothing")
        env = None
        if ctx.environmental is not None:
            bands = [
                b for f in members
                if (b := _band(ctx.environmental.get(str(f["finding_id"])))) is not None
            ]
            env = max(bands, key=BANDS.index) if bands else None

        unknowns = [f.name for f in factors if f.name in KEY_FACTORS and f.state == "unknown"]
        reasons: list[str] = []
        if kev:
            reasons.append("a CVE is listed in CISA KEV")
        if overdue and BANDS.index(base) >= BANDS.index("high"):
            reasons.append("overdue at high or above")
        if capability == "secrets":
            reasons.append("an exposed secret")
        combos = sorted(
            {toxic[fid] for f in members if (fid := str(f["finding_id"])) in toxic}
        )
        if combos:
            reasons.append(f"member of {', '.join(combos)}")
        if contextual == "critical" and not kev:
            reasons.append("contextual critical")
        if reasons:
            classification = "mandatory"
        elif BANDS.index(contextual) >= BANDS.index("high"):
            classification = "recommended"
        else:
            classification = "optional"

        spike = (
            classification != "mandatory"
            and BANDS.index(base) >= BANDS.index("high")
            and len(unknowns) >= SPIKE_UNKNOWNS
        )
        size = "S" if spike else _SIZE_BY_EFFORT.get(str(entry["effort"]), "M")
        if not spike and len(members) > 20 and size == "S":
            size = "M"

        rationale = f"Scanner {base.title()} → Contextual {contextual.title()}"
        rationale += f": {'; '.join(moved)}." if moved else ": nothing observed moved it."
        if unknowns:
            rationale += f" Unknown: {', '.join(unknowns)}."

        key = sprint_signal.signal_key(repo, "fix", fix_id)
        evidence = [
            f"{len(members)} open {capability} finding(s) under {fix_id}",
            *(f"finding {f['finding_id']}" for f in members[:5]),
        ]
        if spike:
            outline = [
                f"Confirm before fixing: establish {', '.join(unknowns)} for {title}.",
                "Record what was found on the findings (evidence or a disposition).",
                "Re-triage: file the fix, or request a downgrade with the evidence.",
            ]
            tests = ["The evidence gathered is attached to each finding."]
            criteria = [
                f"Each of {', '.join(unknowns)} is observed or declared, with evidence.",
                "Production check: the triage packet for the following sprint shows "
                "these factors as observed or declared, not unknown.",
            ]
        else:
            outline = [entry["action"], *entry["steps"]]
            tests = [
                "A regression test or check that fails before the change and passes after.",
                f"The next {capability} scan no longer reports {fix_id}.",
            ]
            criteria = [
                f"The change ({fix_id}) is merged with its test.",
                f"Production check: the next successful {capability} scan of the "
                f"deployed default branch no longer reports the {len(members)} "
                "finding(s), and MyKronos closes them by absence.",
            ]
        packet.candidates.append(
            TriageCandidate(
                id=f"C-{key[:8]}",
                title=title,
                repo=repo,
                type="validation" if spike else "fix",
                fix_id=fix_id,
                capability=capability,
                findings=len(members),
                existing_story=_existing(key, title, fix_id, board),
                scanner_band=base,
                contextual_band=contextual,
                environmental_band=env,
                rationale=rationale,
                factors=factors,
                evidence=evidence,
                remediation_outline=outline,
                mitigation=_MITIGATION.get(capability, "Reduce exposure until the change ships."),
                tests=tests,
                acceptance_criteria=criteria,
                size=size,
                unknowns=unknowns,
                downgrade_needs_confirmation=BANDS.index(contextual) < BANDS.index(base),
                classification=classification,
                mandatory_reasons=reasons,
            )
        )

    _lanes(packet, report)
    order = {"mandatory": 0, "recommended": 1, "optional": 2}
    packet.candidates.sort(
        key=lambda c: (
            order[c.classification],
            -BANDS.index(c.contextual_band),
            -c.findings,
            c.title,
        )
    )
    for index, candidate in enumerate(packet.candidates, start=1):
        candidate.priority = index
    return packet


def _lanes(packet: Packet, report: Any) -> None:
    """A stalled lane freezes its findings open: the operator's item, not a
    candidate, because no code change in the product closes it."""
    if report is None:
        packet.unknown_sources.append("briefing (stalled lanes and toxic combinations)")
        return
    for lane in getattr(report, "stalled", None) or []:
        packet.operator_items.append(
            OperatorItem(
                kind="lane",
                title=f"Repair the {lane.capability} lane",
                repo=str(lane.repo_full_name),
                detail=f"The lane is {lane.reason}: its findings cannot close until it scans.",
                options=[
                    "Repair the lane before the sprint starts.",
                    "Retire the capability on purpose and give its findings an owner.",
                    "Leave it, and treat its findings' state as unknown this sprint.",
                ],
                recommendation="Repair the lane: every fix in it is otherwise unverifiable.",
            )
        )


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------


def render(packet: Packet) -> str:
    data = packet.to_dict()
    cap = data["capacity"]
    budget = cap["security_budget"] if cap["security_budget"] is not None else "not given"
    out = [
        "# Pre-sprint security triage: for the next sprint",
        "",
        f"Generated {data['generated_at']}. {data['sprint_model']}",
        "",
        "## Capacity",
        "",
        f"- Security budget: {budget} ({cap['unit']})",
        f"- Mandatory: {cap['mandatory']}"
        + (f", over budget by {cap['over_budget_by']}" if cap["over_budget_by"] else ""),
        f"- {cap['note']}",
    ]
    if not data["board_read"]:
        out.append("- Existing stories: not checked (TheHub's board was not read).")
    if data["unknown_sources"]:
        out.append(f"- Not read: {', '.join(data['unknown_sources'])}.")
    out += [
        "",
        "## Candidates",
        "",
        "| # | Id | Class | Type | Scanner → Contextual | Size | Repo | Title | Story |",
        "|---|----|-------|------|----------------------|------|------|-------|-------|",
    ]
    for c in data["candidates"]:
        story = f"#{c['existing_story']}" if c["existing_story"] else "-"
        out.append(
            f"| {c['priority']} | {c['id']} | {c['classification']} | {c['type']} | "
            f"{c['scanner_band']} → {c['contextual_band']} | {c['size']} | {c['repo']} | "
            f"{c['title'].replace('|', '/')} | {story} |"
        )
    for c in data["candidates"]:
        out += ["", f"### {c['id']}: {c['title']}", "", c["rationale"], ""]
        if c["mandatory_reasons"]:
            out.append(f"Mandatory: {'; '.join(c['mandatory_reasons'])}.")
        if c["environmental_band"]:
            out.append(f"Environmental band (shadow): {c['environmental_band']}.")
        if c["downgrade_needs_confirmation"]:
            out.append("The contextual band is lower than the scanner's: confirm the downgrade.")
        out += ["", "Factors:"]
        out += [f"- {f['name']}: **{f['state']}**. {f['evidence']}" for f in c["factors"]]
        out += ["", "Remediation:"] + [f"1. {s}" for s in c["remediation_outline"]]
        out += ["", f"Mitigation: {c['mitigation']}", "", "Acceptance criteria:"]
        out += [f"- {a}" for a in c["acceptance_criteria"]]
    out += ["", "## Operator items", ""]
    if not data["operator_items"]:
        out.append("None.")
    for item in data["operator_items"]:
        out += [f"### {item['title']} ({item['repo']})", "", item["detail"], ""]
        out += [f"{n}. {o}" for n, o in enumerate(item["options"], start=1)]
        out += ["", f"Recommendation: {item['recommendation']}", ""]
    out += [
        "",
        "## PO changes",
        "",
        "Record each change to this packet here: a candidate accepted, deferred, "
        "re-sized or downgraded, and why.",
        "",
    ]
    return "\n".join(out)
