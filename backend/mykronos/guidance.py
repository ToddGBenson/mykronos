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
