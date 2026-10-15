"""The operator's review inbox, kept where it can be tested.

`scripts/review-inbox.ps1` fetches and asks; everything it concludes lives
here, so a test can pin it. It turns every pending approval request - pull
request merges, risk acceptances, delegations, anything else the engine holds
- into one item the operator answers with agree or not:

- **what it is**, from the platform's evidence, never from the requester's
  claim (which is shown, labelled as a claim);
- **what the independent reviewer said** in shadow mode, as advice;
- **a recommendation**: AGREE, CHECK (something specific to read first) or
  WAIT (not decidable yet: a check is red or still running). Only the
  operator decides; the recommendation is the reason, printed.

It also refuses to offer what cannot or should not be decided: a request on a
head the PR has moved past, a PR that is closed, and a request the operator
opened themself (the engine refuses a requester approving their own request).

And it reports what needs attention without a decision: risk acceptances
expiring soon or already expired, and sampled agent decisions waiting for a
spot-check.

CLI: `python review_inbox.py build <input.json>` prints JSON.
"""

from __future__ import annotations

import json
import re
import sys
import textwrap
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

AGREE = "AGREE"
CHECK = "CHECK"
WAIT = "WAIT"

MIN_RATIONALE_CHARS = 20
#: Risk acceptances that end within this many days are reported (policy
#: `risk_acceptance.review_lead_days`).
EXPIRY_LEAD_DAYS = 14
#: A requested end date further out than this is flagged for a closer read.
LONG_ACCEPTANCE_DAYS = 90
#: The check this approval itself produces: pending until the operator decides.
SELF_CHECK = "independent-review"

SUBJECT = re.compile(r"^(?P<repo>[^#]+)#(?P<number>\d+)@(?P<sha>[0-9a-f]{7,40})$")


def _when(value: Any) -> datetime | None:
    if not value:
        return None
    text = str(value).replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _wrap(text: str, indent: str = "    ", width: int = 100, limit: int = 0) -> list[str]:
    text = " ".join(str(text or "").split())
    if limit and len(text) > limit:
        text = text[:limit].rstrip() + " ... (d shows it all)"
    return textwrap.wrap(text, width=width, initial_indent=indent, subsequent_indent=indent)


def checks(rollup: list[dict[str, Any]] | None) -> dict[str, str]:
    """GitHub's statusCheckRollup as {name: pass|fail|pending|skipped}.

    The rollup mixes check runs (name/status/conclusion) and commit statuses
    (context/state). A name that appears twice keeps its last entry, which is
    the latest run.
    """
    out: dict[str, str] = {}
    for c in rollup or []:
        name = str(c.get("name") or c.get("context") or "?")
        if "state" in c and "conclusion" not in c:
            state = str(c.get("state") or "").upper()
            out[name] = {"SUCCESS": "pass", "PENDING": "pending", "EXPECTED": "pending"}.get(
                state, "fail"
            )
            continue
        if str(c.get("status") or "").upper() != "COMPLETED":
            out[name] = "pending"
            continue
        conclusion = str(c.get("conclusion") or "").upper()
        if conclusion in {"SUCCESS", "NEUTRAL"}:
            out[name] = "pass"
        elif conclusion == "SKIPPED":
            out[name] = "skipped"
        else:
            out[name] = "fail"
    return out


def _reviewer_lines(review: dict[str, Any] | None, tier: str) -> tuple[list[str], str | None]:
    """The shadow reviewer's verdict, and the concern it raises, if any."""
    if not review or not review.get("shadow_verdict"):
        return ["  reviewer: no shadow verdict for this request"], None
    verdict = str(review["shadow_verdict"])
    lines = [f"  reviewer (shadow, advice only): {verdict}"]
    lines += _wrap(review.get("shadow_rationale") or "", limit=600)
    concern = None
    if verdict != "approve":
        if tier == "governance":
            # Governance goes to a person by rule; the reviewer says so with a
            # reject. Its substance is still worth reading, but the verdict
            # itself is not a finding.
            lines.append("    (governance always goes to you; the reviewer's verdict is advice)")
        else:
            concern = f"the reviewer said {verdict}: read its reason"
    return lines, concern



def _pr_item(
    req: dict[str, Any],
    ev: dict[str, Any],
    pr: dict[str, Any] | None,
    review: dict[str, Any] | None,
) -> dict[str, Any]:
    m = SUBJECT.match(str(req.get("subject_ref", "")))
    number = int(m["number"]) if m else ev.get("number")
    sha = m["sha"] if m else str(ev.get("head_sha", ""))
    title = str(ev.get("title") or (pr or {}).get("title") or "").strip()
    item: dict[str, Any] = {
        "kind": "pull_request",
        "pr_number": number,
        "title": f"#{number} {title}",
    }
    if pr is None:
        return item | {"offer": False, "why_not": "gh could not read the pull request"}
    if str(pr.get("state", "")).upper() != "OPEN":
        return item | {"offer": False, "why_not": f"#{number} is {str(pr['state']).lower()}"}
    head = str(pr.get("headRefOid") or "")
    if head and not head.startswith(sha) and not sha.startswith(head):
        return item | {
            "offer": False,
            "why_not": (
                f"superseded: #{number} is now at {head[:8]}, this request is for {sha[:8]}. "
                "The platform opens a request for the new head."
            ),
        }

    files = list(ev.get("files") or [])
    classes = Counter(str(f.get("class", "?")) for f in files)
    adds = sum(int(f.get("additions") or 0) for f in files)
    dels = sum(int(f.get("deletions") or 0) for f in files)
    class_text = ", ".join(f"{c} {n}" for c, n in sorted(classes.items())) or "no files"
    lines = [
        (
            f"  tier {req.get('tier')} | head {sha[:8]} | {len(files)} file(s): "
            f"{class_text}; +{adds}/-{dels}"
        )
    ]
    for f in files[:12]:
        lines.append(
            f"    [{f.get('class')}] {f.get('status')} {f.get('path')} "
            f"+{f.get('additions')}/-{f.get('deletions')}"
        )
    if len(files) > 12:
        lines.append(f"    ... and {len(files) - 12} more (d shows the diff)")
    if ev.get("files_listing_incomplete"):
        lines.append("  file listing INCOMPLETE: GitHub truncated it")

    state = checks(pr.get("statusCheckRollup"))
    state.pop(SELF_CHECK, None)
    failed = sorted(n for n, s in state.items() if s == "fail")
    pending = sorted(n for n, s in state.items() if s == "pending")
    passed = sorted(n for n, s in state.items() if s == "pass")
    parts = [
        f"pass: {', '.join(passed)}" if passed else "",
        f"FAIL: {', '.join(failed)}" if failed else "",
        f"running: {', '.join(pending)}" if pending else "",
    ]
    lines.append("  checks: " + ("; ".join(p for p in parts if p) or "none reported"))

    rlines, concern = _reviewer_lines(review, str(req.get("tier")))
    lines += rlines

    reviewer_agrees = (review or {}).get("shadow_verdict") == "approve"
    if failed:
        rec = WAIT
        why = f"{', '.join(failed)} failed: fix it first; a new head gets a new request"
    elif pending:
        rec, why = WAIT, f"{', '.join(pending)} still running"
    elif ev.get("files_listing_incomplete"):
        rec, why = CHECK, "GitHub truncated the file list: read the diff on GitHub"
    elif concern:
        rec, why = CHECK, concern
    else:
        rec, why = AGREE, "checks green" + (" and the reviewer agrees" if reviewer_agrees else "")
    rationale = (
        f"Read the evidence for #{number} at {sha[:8]} ({title[:80]}): {len(files)} file(s), "
        f"{class_text}, +{adds}/-{dels}; checks {', '.join(passed) or 'none'} green. "
        "The diff matches the stated purpose and widens no agent's authority."
    )
    return item | {
        "offer": True,
        "lines": lines,
        "recommendation": rec,
        "why": why,
        "approve_rationale": rationale,
        "diff": [
            {"path": f.get("path"), "class": f.get("class"), "patch": f.get("patch")}
            for f in files
        ],
    }


def _risk_item(
    req: dict[str, Any],
    ev: dict[str, Any],
    review: dict[str, Any] | None,
    now: datetime,
) -> dict[str, Any]:
    scope = ev.get("scope") or {}
    matched = ev.get("matched") or {}
    residual = ev.get("residual") or {}
    by_sev = matched.get("by_severity") or {}
    fixed = int(matched.get("with_fixed_version") or 0)
    findings = int(matched.get("findings") or len(ev.get("covered_finding_ids") or []))
    target = scope.get("image") or scope.get("path") or scope.get("package")
    title_bits = [scope.get("capability"), target]
    title = f"risk acceptance {ev.get('repo', '')}: " + " ".join(str(b) for b in title_bits if b)
    rules = list(scope.get("rule_ids") or [])
    until = _when(ev.get("requested_until"))
    days = (until - now).days if until else None

    head = (
        f"  tier {req.get('tier')} | {ev.get('response')} / {ev.get('deviation_type')} "
        f"| risk owner {ev.get('risk_owner')}"
    )
    if ev.get("renewal_count"):
        head += f" | renewal #{ev['renewal_count']}"
    severities = ", ".join(f"{n} {s}" for s, n in sorted(by_sev.items())) or "none"
    covers = f"  covers {findings} finding(s): {severities}"
    if fixed:
        covers += f"; {fixed} with a published fix"
    lines = [head, covers]
    if rules:
        more = f" (+{len(rules) - 6})" if len(rules) > 6 else ""
        lines.append(f"  rules: {', '.join(rules[:6])}{more}")
    if scope.get("package_names"):
        lines.append(f"  packages: {', '.join(scope['package_names'][:6])}")
    lines.append(
        f"  residual: likelihood {residual.get('likelihood')}, impact {residual.get('impact')}"
        f" -> {residual.get('severity')}"
    )
    left = f" ({days} days)" if days is not None else ""
    lines.append(f"  until {ev.get('requested_until')}{left}")
    lines.append("  justification:")
    lines += _wrap(ev.get("justification") or "", limit=700)
    premises = list(ev.get("premises") or [])
    controls = list(ev.get("compensating_controls") or [])
    milestones = list(ev.get("milestones") or [])
    for p in premises:
        lines.append(f"  premise ({p.get('type')}): {p.get('asserts') or p}")
    for c in controls:
        lines.append(f"  control: {c.get('description') or c.get('title') or c}")
    for ms in milestones:
        lines.append(f"  milestone {ms.get('due')}: {ms.get('title')}")

    rlines, concern = _reviewer_lines(review, str(req.get("tier")))
    lines += rlines

    flags = []
    if findings == 0:
        flags.append("it covers no finding")
    if int(by_sev.get("critical") or 0):
        flags.append(f"{by_sev['critical']} critical finding(s)")
    if str(residual.get("severity")) in {"high", "critical"}:
        flags.append(f"residual risk is {residual.get('severity')}")
    if not premises and not controls:
        flags.append("no premise or compensating control backs it")
    if days is not None and days > LONG_ACCEPTANCE_DAYS:
        flags.append(f"it runs {days} days")
    if fixed:
        if scope.get("capability") == "containers":
            # A fixed_version on an image finding means a patched *package*
            # exists, not a patched image: for an upstream image the fix
            # arrives when its publisher rebuilds, which is what these
            # acceptances usually say. Shown, not flagged.
            lines.append(
                f"  note: {fixed} finding(s) have a patched package; that is not a patched image"
            )
        else:
            flags.append(f"{fixed} finding(s) have a published fix: is fixing possible?")
    if concern:
        flags.append(concern)
    if flags:
        rec, why = CHECK, "; ".join(flags)
    else:
        rec, why = AGREE, "scoped, backed by premises or controls, time-boxed"
    rationale = (
        f"Read risk acceptance {str(ev.get('risk_acceptance_id', ''))[:8]} for {ev.get('repo')}: "
        f"{findings} finding(s) ({', '.join(rules[:3])}), residual {residual.get('severity')}, "
        f"until {ev.get('requested_until')}. The justification, premises and milestones "
        "support accepting it for that period."
    )
    return {
        "kind": "risk_acceptance",
        "title": title,
        "offer": True,
        "lines": lines,
        "recommendation": rec,
        "why": why,
        "approve_rationale": rationale,
        "full_text": ev.get("justification") or "",
    }


def _other_item(
    req: dict[str, Any], ev: dict[str, Any], review: dict[str, Any] | None
) -> dict[str, Any]:
    duty = str(req.get("duty"))
    lines = [f"  tier {req.get('tier')} | subject {req.get('subject_ref')}"]
    lines += _wrap(json.dumps(ev, default=str), limit=900)
    rlines, _ = _reviewer_lines(review, str(req.get("tier")))
    lines += rlines
    why = "read the evidence: there is no summary for this kind of request"
    if "delegation" in duty:
        why = "a delegation lets an agent approve alone: read its tiers, families and sampling"
    return {
        "kind": duty,
        "title": f"{duty} {req.get('subject_ref')}",
        "offer": True,
        "lines": lines,
        "recommendation": CHECK,
        "why": why,
        "approve_rationale": (
            f"Read the evidence for {duty} {req.get('subject_ref')} and agree with it as stated."
        ),
        "full_text": json.dumps(ev, indent=2, default=str),
    }


def _item(
    entry: dict[str, Any],
    operator: str,
    shadow: dict[Any, Any],
    prs: dict[int, Any],
    now: datetime,
) -> dict[str, Any]:
    req = entry.get("request") or {}
    ev = entry.get("evidence") or {}
    review = shadow.get(req.get("id"))
    duty = req.get("duty")
    if duty == "pull_request_merge":
        m = SUBJECT.match(str(req.get("subject_ref", "")))
        item = _pr_item(req, ev, prs.get(int(m["number"])) if m else None, review)
    elif duty == "risk_acceptance":
        item = _risk_item(req, ev, review, now)
    else:
        item = _other_item(req, ev, review)
    if item.get("offer") and req.get("requested_by") == operator:
        why_not = "you opened this request, so you cannot also approve it"
        item = item | {"offer": False, "why_not": why_not}
    answered = [d for d in req.get("decisions") or [] if d.get("approver") == operator]
    if item.get("offer") and answered:
        why_not = f"you already answered it ({answered[-1].get('verdict')})"
        item = item | {"offer": False, "why_not": why_not}
    item |= {
        "request_id": req.get("id"),
        "duty": duty,
        "tier": req.get("tier"),
        "requested_by": req.get("requested_by"),
        "requester_statement": req.get("requester_statement") or "",
        "evidence_digest": entry.get("evidence_digest") or req.get("evidence_digest"),
        "expires_at": req.get("expires_at"),
    }
    rationale = str(item.get("approve_rationale", ""))
    if len(rationale) < MIN_RATIONALE_CHARS:
        item["approve_rationale"] = rationale.ljust(MIN_RATIONALE_CHARS, ".")
    return item


def _notices(bundle: dict[str, Any], now: datetime) -> list[str]:
    notices: list[str] = []
    for ra in bundle.get("acceptances") or []:
        end = _when(ra.get("expires_at"))
        if ra.get("status") != "active" or not end:
            continue
        name = f"risk acceptance {str(ra.get('id'))[:8]} ({ra.get('repo')})"
        left = (end - now).days
        if left < 0:
            notices.append(f"{name} is past its end date: its findings count again")
        elif left <= EXPIRY_LEAD_DAYS:
            ends = str(ra.get("expires_at"))[:10]
            notices.append(f"{name} ends in {left} day(s), {ends}: renew or remediate")
    samples = int(bundle.get("samples") or 0)
    if samples:
        notices.append(
            f"{samples} sampled agent decision(s) wait for your spot-check: "
            "approval-queue.ps1 -SamplesOnly"
        )
    return notices


def build(bundle: dict[str, Any]) -> dict[str, Any]:
    operator = str(bundle.get("operator") or "admin")
    now = _when(bundle.get("now")) or datetime.now(UTC)
    shadow = {r.get("request_id"): r for r in bundle.get("shadow") or []}
    prs = {int(k): v for k, v in (bundle.get("prs") or {}).items()}
    items = [_item(e, operator, shadow, prs, now) for e in bundle.get("requests") or []]

    order = {AGREE: 0, CHECK: 1, WAIT: 2}
    offered = sorted(
        (i for i in items if i["offer"]),
        key=lambda i: (order[i["recommendation"]], str(i["title"])),
    )
    skipped = [
        {"title": i["title"], "request_id": i.get("request_id"), "why_not": i["why_not"]}
        for i in items
        if not i["offer"]
    ]
    return {
        "offered": offered,
        "skipped": skipped,
        "notices": _notices(bundle, now),
        "counts": dict(Counter(i["recommendation"] for i in offered)),
    }


def main(argv: list[str]) -> int:
    if len(argv) != 3 or argv[1] != "build":
        print("usage: review_inbox.py build <input.json>", file=sys.stderr)
        return 2
    data = json.loads(Path(argv[2]).read_text(encoding="utf-8-sig"))
    print(json.dumps(build(data), default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
