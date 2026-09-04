"""What the scanner said to do about each finding, grouped so it can be acted on.

Every scanner ships remediation advice and this platform was throwing all of
it away. `raw_finding_json` has carried it since the first ingest: ZAP writes a
`solution` per alert, Trivy writes a `Fixed Version` per package, Semgrep and
Checkov write a message that says what the pattern is. Nothing read any of it,
so the Remediation surfaces offered advice written *here*, from a general sense
of what a class of finding usually needs.

That is not merely lossy, it is wrong. The standing text for containers said
**"rebuild on a current base image and one rebuild closes them together."**
Reading what Trivy actually reported, on 2026-09-01:

    container findings with a Fixed Version : 3
    container findings with NO fix available: 231

A rebuild would have closed **nothing**. Those 231 are Debian packages for
which no patched version has been published; the right route is an acceptance
with `no_vendor_fix` and a review date — which spec 24 §3 already re-opens
automatically the day a vendor ships. Guidance invented from a category was
confidently telling somebody to do a day of work that could not have helped.

So this module reads the scan. Where the scanner has nothing useful to say the
standing advice remains, and says which it is (`source`), because "the tool
told us" and "we think" deserve different amounts of trust.
"""

from __future__ import annotations

import html
import json
import re
from dataclasses import dataclass, field
from typing import Any

from mykronos.lake.catalog import Catalog

#: ZAP writes HTML into `solution`; Trivy writes a flat block. Neither is
#: meant for a table cell.
_TAGS = re.compile(r"<[^>]+>")
_SPACE = re.compile(r"\s+")

#: A ZAP alert title carries the URL it fired on — "X-Content-Type-Options
#: Header Missing at GET /retro". Thirty-three of those are one problem, and
#: grouping needs the part before the location.
_AT_LOCATION = re.compile(r"\s+at\s+(GET|POST|PUT|DELETE|HEAD|PATCH)\s.*$", re.I)

#: Trivy's SARIF message, which is a flat key/value block rather than prose.
_PACKAGE = re.compile(r"Package:\s*(\S+)")
_INSTALLED = re.compile(r"Installed Version:\s*(\S+)")
_FIXED = re.compile(r"Fixed Version:\s*(\S+)")

#: What a group needs from a person, which is not the same as its severity.
#: The ordering is the useful part: `config` is a few lines and closes many,
#: `no_fix` cannot be worked at all however long anybody stares at it.
EFFORT = ("config", "upgrade", "judgement", "rotate", "no_fix")


@dataclass
class RuleGuidance:
    """One rule, everything open under it, and what the scanner said to do."""

    capability: str
    rule_id: str
    title: str
    count: int
    #: The remediation, short enough for a table cell.
    fix: str
    #: "scanner" when the tool said it, "standing" when this repository did.
    #: A reader deserves to know which, and they are not equally trustworthy.
    source: str
    effort: str

    @property
    def actionable(self) -> bool:
        """Whether anybody can do anything about this today."""
        return self.effort != "no_fix"


@dataclass
class CapabilityGuidance:
    capability: str
    count: int
    rules: list[RuleGuidance] = field(default_factory=list)

    @property
    def actionable(self) -> int:
        return sum(r.count for r in self.rules if r.actionable)

    @property
    def unactionable(self) -> int:
        return self.count - self.actionable


def _clean(text: str, limit: int = 160) -> str:
    # Unescape before stripping tags, and twice: Trivy double-encodes, so a
    # CVE title arrives as `EUC_JISX0213 -&amp;gt; UCS4` and one pass leaves
    # `-&gt;` on the page.
    out = html.unescape(html.unescape(text or ""))
    out = _SPACE.sub(" ", _TAGS.sub(" ", out)).strip()
    if len(out) <= limit:
        return out
    # Cut at a sentence if there is one inside the budget; a fix truncated
    # mid-clause reads as though the tool ran out of things to say.
    cut = out.rfind(". ", 0, limit)
    return (out[: cut + 1] if cut > 40 else out[:limit].rstrip() + "...").strip()


def _dast(raw: dict[str, Any], title: str) -> tuple[str, str, str]:
    """ZAP's own `solution`, which is the best remediation text in the estate."""
    solution = _clean(str(raw.get("solution", "")))
    if not solution:
        return ("No solution text in the alert.", "standing", "judgement")
    # A missing-header alert is a config change and closes across every route
    # it was reported on; an injection alert is not. `CSP:` is in the list
    # because ZAP titles those without the word "header" — "CSP: style-src
    # unsafe-inline" is 41 findings and one policy line, and calling it a
    # judgement buried the second-cheapest thing on the page.
    header_ish = re.search(
        r"header|CSP|Content-Security-Policy|cookie|flag|site isolation|spectre",
        title,
        re.I,
    )
    # ...but a *content* disclosure is not fixed by a header, whatever its
    # title says. Suspicious comments are 55 findings and every one is a
    # separate decision about a line of source.
    content_ish = re.search(r"suspicious comment|user controllable|disclosure of", title, re.I)
    if content_ish:
        return (solution, "scanner", "judgement")
    return (solution, "scanner", "config" if header_ish else "judgement")


def _containers(raw: dict[str, Any]) -> tuple[str, str, str]:
    """Trivy's `Fixed Version`, and the far commoner absence of one.

    The absence is the finding. 231 of 234 open container findings on this
    estate have no published fix, so "upgrade" is advice for three of them and
    misdirection for the rest.
    """
    text = str((raw.get("message") or {}).get("text", ""))
    package = (_PACKAGE.search(text) or [None, ""])[1] if _PACKAGE.search(text) else ""
    installed = _INSTALLED.search(text)
    fixed = _FIXED.search(text)
    fixed_version = fixed.group(1) if fixed else ""

    if fixed_version and not fixed_version.startswith("Link"):
        now = f" (from {installed.group(1)})" if installed else ""
        return (f"Upgrade {package} to {fixed_version}{now}.", "scanner", "upgrade")

    return (
        f"No fixed version published for {package or 'this package'}. "
        "Nothing to upgrade to, so a rebuild closes nothing — accept with "
        "`no_vendor_fix` and a review date, which re-opens when a fix ships.",
        "scanner",
        "no_fix",
    )


def _sast(raw: dict[str, Any]) -> tuple[str, str, str]:
    text = str((raw.get("message") or {}).get("text", ""))
    if not text:
        return ("Read the finding and disposition it.", "standing", "judgement")
    return (
        _clean(text) + " — a judgement, and often a false positive worth dispositioning.",
        "scanner",
        "judgement",
    )


def _iac(raw: dict[str, Any]) -> tuple[str, str, str]:
    text = str((raw.get("message") or {}).get("text", ""))
    return (
        _clean(text) or "Read the control before changing infrastructure that works.",
        "scanner" if text else "standing",
        "judgement",
    )


def _secrets(raw: dict[str, Any]) -> tuple[str, str, str]:
    """Gitleaks reports the match, not a remedy — and the remedy has an order.

    Removing the commit is the part people do first and it is the part that
    does nothing: the credential is disclosed by having been in git history,
    and stays disclosed after the commit that removes it.
    """
    where = str(raw.get("File", "")) or "the repository"
    return (
        f"Rotate the credential first, then remove it from {where}. "
        "Removing without rotating leaves it compromised.",
        "standing",
        "rotate",
    )


def _for(capability: str, raw: dict[str, Any], title: str) -> tuple[str, str, str]:
    if capability == "dast":
        return _dast(raw, title)
    if capability in ("containers", "atlas"):
        return _containers(raw)
    if capability == "sast":
        return _sast(raw)
    if capability == "iac":
        return _iac(raw)
    if capability == "secrets":
        return _secrets(raw)
    return ("No standing guidance recorded for this class.", "standing", "judgement")


def by_rule(catalog: Catalog, *, asset_id: str | None = None) -> list[CapabilityGuidance]:
    """Open findings grouped by rule, with the scanner's remediation attached.

    Grouped on the rule rather than the finding because that is the unit the
    fix has: thirty-three `X-Content-Type-Options Header Missing` alerts across
    thirty-three URLs are one response header, and listing them as thirty-three
    rows of work is how a five-minute change looks like a sprint.
    """
    if not catalog.all_files("findings"):
        return []

    where = "status = 'open'" + (" AND asset_id = ?" if asset_id else "")
    rows = catalog.query(
        f"""
        SELECT capability, rule_id, title, raw_finding_json
        FROM findings WHERE {where}
        """,
        [asset_id] if asset_id else None,
    )

    groups: dict[tuple[str, str], dict[str, Any]] = {}
    for capability, rule_id, title, raw_json in rows:
        key = (str(capability), str(rule_id or "(unattributed)"))
        entry = groups.get(key)
        if entry is None:
            try:
                raw = json.loads(raw_json) if raw_json else {}
            except (ValueError, TypeError):
                raw = {}
            clean_title = _clean(_AT_LOCATION.sub("", str(title or "")), 90)
            fix, source, effort = _for(str(capability), raw, clean_title)
            entry = groups[key] = {
                "title": clean_title or str(rule_id),
                "count": 0,
                "fix": fix,
                "source": source,
                "effort": effort,
            }
        entry["count"] += 1

    per_capability: dict[str, CapabilityGuidance] = {}
    for (capability, rule_id), entry in groups.items():
        summary = per_capability.setdefault(
            capability, CapabilityGuidance(capability=capability, count=0)
        )
        summary.count += int(entry["count"])
        summary.rules.append(
            RuleGuidance(
                capability=capability,
                rule_id=rule_id,
                title=str(entry["title"]),
                count=int(entry["count"]),
                fix=str(entry["fix"]),
                source=str(entry["source"]),
                effort=str(entry["effort"]),
            )
        )

    for summary in per_capability.values():
        # Cheapest first within a capability, then biggest: the point of the
        # page is to find the few lines that close the most.
        summary.rules.sort(key=lambda r: (EFFORT.index(r.effort), -r.count))

    # And across capabilities, most actionable first — not most findings.
    # Ranking containers top because it has 234 would put the one class nobody
    # can act on above the one that is a few lines of config.
    return sorted(per_capability.values(), key=lambda c: -c.actionable)


# ---------------------------------------------------------------------------
# Grouping by fix rather than by rule
# ---------------------------------------------------------------------------

#: A header named in a remediation sentence: `X-Content-Type-Options header`,
#: `Content-Security-Policy header`. Hyphenated capitalised tokens only, so
#: ordinary prose does not produce one.
_HEADER = re.compile(r"\b([A-Z][A-Za-z]*(?:-[A-Za-z]+)+)\s+header", re.I)


@dataclass
class FixGroup:
    """Everything one change would close, and how to make it.

    Grouping by rule was already a large collapse — thirty-three
    `X-Content-Type-Options` alerts across thirty-three URLs are one row. This
    is the collapse above it: **two different rules that share one fix.**

    On this estate that is not hypothetical. `ZAP-10038` ("CSP Header Not Set")
    and `ZAP-10055` ("CSP: style-src unsafe-inline") are separate ZAP plugins
    with separate ids and separate findings, and both are answered by one
    `Content-Security-Policy` value. Presented as two rows, somebody does the
    work twice or does half of it.

    The key is derived from what the scanner said, never from a taxonomy
    written here. A hand-maintained "these rules are the same really" table is
    exactly the kind of mapping that is wrong the moment a tool adds a plugin,
    and nobody notices because it fails silently towards *more* rows.
    """

    fix_id: str
    #: One line: the change itself.
    action: str
    capability: str
    findings: int
    #: Distinct scanner rules this one change answers. More than one is the
    #: whole point of the type.
    rules: list[str] = field(default_factory=list)
    repos: list[str] = field(default_factory=list)
    effort: str = "judgement"
    #: Ordered, and the last one is always closure — a change nobody scans
    #: again does not close anything (D-098).
    steps: list[str] = field(default_factory=list)

    @property
    def collapses_rules(self) -> bool:
        return len(self.rules) > 1


def _header_named_by(solution: str, title: str) -> str:
    """Which header this remediation is actually about.

    A ZAP solution often names two: *"sets the Content-Type header
    appropriately, and that it sets the X-Content-Type-Options header to
    'nosniff'"*. Taking the first — or the first alphabetically — picks
    `Content-Type`, which is not the missing header and would file the finding
    under a fix that does not exist.

    The title names the operative one, so the title wins. Falling back to the
    last mentioned rather than the first, because these sentences build towards
    the header they are asking for.
    """
    candidates = [match.group(1) for match in _HEADER.finditer(solution)]
    if not candidates:
        return ""
    # Longest first, because `Content-Type` is a substring of
    # `X-Content-Type-Options`: a plain containment check against the title
    # matches the shorter one and files the finding under a fix that does not
    # exist.
    for candidate in sorted(candidates, key=len, reverse=True):
        if candidate.lower() in title.lower():
            return candidate
    # `X-`-prefixed headers are the ones ZAP reports as missing; a bare
    # `Content-Type` in the same sentence is context, not the ask.
    prefixed = [c for c in candidates if c.lower().startswith("x-")]
    return prefixed[-1] if prefixed else candidates[-1]


def _fix_key(capability: str, rule: RuleGuidance, raw: dict[str, Any]) -> tuple[str, str]:
    """`(fix_id, action)` — what change closes this rule, said once."""
    if capability == "dast":
        header = _header_named_by(rule.fix, rule.title)
        if header:
            return (
                f"header:{header.lower()}",
                f"Set the {header} response header",
            )
    if capability in ("containers", "atlas"):
        text = str((raw.get("message") or {}).get("text", ""))
        package = _PACKAGE.search(text)
        fixed = _FIXED.search(text)
        version = fixed.group(1) if fixed else ""
        if package and version and not version.startswith("Link"):
            # Keyed on the package, not the package-and-version. Two advisories
            # against `setuptools` fixed in 78.1.1 and 83.0.0 are one upgrade,
            # to 83.0.0 — presenting them as two groups asks somebody to do it
            # twice, and the first of them would not have closed the second.
            name = package.group(1)
            return (f"upgrade:{name}", f"Upgrade {name} to {version}")
    if capability == "secrets":
        return ("rotate:credentials", "Rotate the credential, then remove it")

    # No shared fix to claim. One rule, one group — which is honest rather
    # than a collapse that reads as progress.
    return (f"rule:{rule.rule_id}", rule.title)


#: How to actually make each kind of change, and how to know it worked. The
#: last step is always closure, because a change nobody scans again closes
#: nothing however correct it is — the defect D-098 exists to report.
_STEPS: dict[str, list[str]] = {
    "header": [
        "Set the header at whatever serves the application — the framework's "
        "response-header config, the reverse proxy, or the CDN. One place, not "
        "per route: every finding in this group is the same header missing "
        "from a different URL.",
        "Check it on the wire rather than in the config: "
        "`curl -sI <url> | grep -i <header>`. A header set in a file that "
        "never reaches a response is the failure mode worth ruling out.",
        "Re-run the DAST lane. Two consecutive successful scans close these; "
        "one is not enough, and a failing lane closes nothing at all.",
    ],
    "upgrade": [
        "Change the pinned version wherever this package is declared, then "
        "regenerate the lock file so transitive pins move with it.",
        "Run the test suite. A version bump that closes an advisory and breaks "
        "the build has not made anything safer.",
        "Re-run the dependency lane. Two consecutive successful scans close "
        "these.",
    ],
    "rotate": [
        "Rotate the credential first, at the system that issued it. The value "
        "is disclosed by having been in git history and stays disclosed after "
        "the commit that removes it — removing first buys nothing and costs "
        "the audit trail.",
        "Then remove it from the file and replace it with a reference to a "
        "secret store.",
        "Re-run the secrets lane. If the credential is still in history the "
        "finding stays open, which is correct: history is where it leaked.",
    ],
}


def fix_groups(catalog: Catalog, *, asset_id: str | None = None) -> list[FixGroup]:
    """Open findings grouped by the change that would close them.

    One level above `by_rule`. That collapses many URLs into one rule; this
    collapses several rules into one change, where the scanner's own text says
    they share one.
    """
    if not catalog.all_files("findings"):
        return []

    where = "status = 'open'" + (" AND asset_id = ?" if asset_id else "")
    rows = catalog.query(
        f"""
        SELECT capability, rule_id, title, raw_finding_json, asset_id
        FROM findings WHERE {where}
        """,
        [asset_id] if asset_id else None,
    )

    grouped: dict[str, dict[str, Any]] = {}
    for capability, rule_id, title, raw_json, repo in rows:
        try:
            raw = json.loads(raw_json) if raw_json else {}
        except (ValueError, TypeError):
            raw = {}

        clean_title = _clean(_AT_LOCATION.sub("", str(title or "")), 90)
        fix, source, effort = _for(str(capability), raw, clean_title)
        rule = RuleGuidance(
            capability=str(capability),
            rule_id=str(rule_id or "(unattributed)"),
            title=clean_title or str(rule_id),
            count=1,
            fix=fix,
            source=source,
            effort=effort,
        )
        fix_id, action = _fix_key(str(capability), rule, raw)

        entry = grouped.setdefault(
            fix_id,
            {
                "action": action,
                "capability": str(capability),
                "findings": 0,
                "rules": set(),
                "repos": set(),
                "effort": effort,
                "kind": fix_id.split(":", 1)[0],
                "versions": set(),
            },
        )
        entry["findings"] += 1
        if fix_id.startswith("upgrade:"):
            fixed = _FIXED.search(str((raw.get("message") or {}).get("text", "")))
            if fixed and not fixed.group(1).startswith("Link"):
                entry["versions"].add(fixed.group(1))
        entry["rules"].add(rule.rule_id)
        entry["repos"].add(str(repo))
        # `config` beats `judgement` for a group somebody can act on in one
        # place; the cheapest reading of a shared fix is the true one.
        if EFFORT.index(effort) < EFFORT.index(str(entry["effort"])):
            entry["effort"] = effort

    groups = [
        FixGroup(
            fix_id=fix_id,
            action=(
                f"Upgrade {fix_id.split(':', 1)[1]} to "
                f"{_highest(entry['versions'])}"
                if entry["versions"]
                else str(entry["action"])
            ),
            capability=str(entry["capability"]),
            findings=int(entry["findings"]),
            rules=sorted(entry["rules"]),
            repos=sorted(entry["repos"]),
            effort=str(entry["effort"]),
            steps=_STEPS.get(str(entry["kind"]), []),
        )
        for fix_id, entry in grouped.items()
    ]

    # Cheapest first, then by how much one change closes. A group that answers
    # seventy findings with one header belongs above one that answers four.
    groups.sort(key=lambda g: (EFFORT.index(g.effort), -g.findings, g.action))
    return groups


def _highest(versions: set[str]) -> str:
    """The version that closes all of them.

    Compared numerically per dotted segment rather than as strings, because
    `"9.0" > "10.0"` lexically and offering 9.0 as the fix would leave the
    advisory that needed 10.0 open. Anything unparseable falls back to string
    order, which is wrong less often than crashing.
    """

    def key(value: str) -> tuple[int, ...]:
        parts: list[int] = []
        for chunk in re.split(r"[.\-+~]", value):
            digits = re.match(r"\d+", chunk)
            parts.append(int(digits.group()) if digits else 0)
        return tuple(parts)

    try:
        return max(versions, key=key)
    except (TypeError, ValueError):
        return max(versions)
