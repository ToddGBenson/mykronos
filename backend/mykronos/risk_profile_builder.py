"""Proposing a repository's risk profile from evidence (B-041).

0 of 4 repositories on this deployment have a risk profile, so
`internet_facing`, `data_classification` and `business_criticality` are unset
everywhere. The consequence is already visible: the triage queue now says out
loud that it ranks by severity and threat intelligence rather than by risk,
because the business context it would weigh does not exist.

**Asking humans to fill in a form has failed everywhere it has been tried.**
So this proposes, and a person confirms — the same pattern the controls
register already uses, and the same one ownership uses when it falls back to
the account and labels the answer as weaker.

**The rule that keeps it honest: an absent field stays absent.** A builder that
guessed "internal, low criticality" whenever it could not tell would be worse
than the empty profile we have now, because an empty profile is visibly empty
and a guessed one looks like an answer. Unknown means unknown, and the score
assumes the worst — which is what CVSS's environmental metrics already do with
an undefined modifier.

**What this taught me while writing it.** The obvious inference is wrong.
"DAST has run successfully 35 times, therefore this is internet-facing" is
exactly the sort of confident nonsense that discredits a whole feature: this
platform's own DAST runs against an ephemeral compose stack inside CI, so a
successful scan proves an HTTP surface *exists*, not that anybody outside can
reach it. The proposal says so, and points at what would settle it.

The most useful thing this returns is therefore not the proposals. It is
`what_would_settle_it` — the empty form becomes a short list of evidence to go
and get.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

#: How much to trust a proposed value.
#:
#: `observed` — the platform watched this and it cannot reasonably mean
#: something else. `inferred` — consistent with the evidence and not proven by
#: it. `unknown` — say so, and let the score assume the worst.
CONFIDENCE = ("observed", "inferred", "unknown")


@dataclass
class Proposal:
    """One field of a risk profile, and why."""

    field: str
    value: Any | None
    confidence: str
    #: What the platform read. Named specifically enough that somebody can
    #: disagree with the evidence rather than with the machine.
    evidence: str
    #: What would turn `unknown` into an answer. The point of the feature.
    what_would_settle_it: str | None = None


@dataclass
class ProfileProposal:
    repo_full_name: str
    proposals: list[Proposal] = field(default_factory=list)
    already_confirmed: bool = False


def _dast_runs(catalog: Any, repo_full_name: str) -> int:
    if not catalog.all_files("scan_runs"):
        return 0
    rows = catalog.query(
        "SELECT count(*) FROM scan_runs WHERE repo_full_name = ? "
        "AND capability = 'dast' AND scan_status = 'success'",
        [repo_full_name],
    )
    return int(rows[0][0]) if rows else 0


def _network_findings(catalog: Any, repo_full_name: str) -> int:
    if not catalog.all_files("findings"):
        return 0
    rows = catalog.query(
        "SELECT count(*) FROM findings WHERE asset_id = ? "
        "AND capability IN ('cloud', 'network') AND status = 'open'",
        [repo_full_name],
    )
    return int(rows[0][0]) if rows else 0


def _secret_rules(catalog: Any, repo_full_name: str) -> list[str]:
    """Which credential *kinds* this repository has leaked.

    Says something narrow and true: this codebase handles these classes of
    credential. It says nothing about what data the system stores, which is
    what `data_classification` actually asks — and conflating the two would be
    the kind of plausible guess this module exists to avoid.
    """
    if not catalog.all_files("findings"):
        return []
    rows = catalog.query(
        "SELECT DISTINCT rule_id FROM findings WHERE asset_id = ? "
        "AND capability = 'secrets' AND status = 'open' ORDER BY 1 LIMIT 10",
        [repo_full_name],
    )
    return [str(row[0]) for row in rows]


def propose(
    catalog: Any,
    repo_full_name: str,
    *,
    declared_surfaces: int = 0,
    owner: str | None = None,
    owner_source: str | None = None,
    already_confirmed: bool = False,
) -> ProfileProposal:
    """What the platform can and cannot say about this repository."""
    out = ProfileProposal(
        repo_full_name=repo_full_name, already_confirmed=already_confirmed
    )

    # --- internet_facing -------------------------------------------------
    dast = _dast_runs(catalog, repo_full_name)
    network = _network_findings(catalog, repo_full_name)

    if declared_surfaces:
        out.proposals.append(
            Proposal(
                field="internet_facing",
                value=True,
                confidence="observed",
                evidence=(
                    f"{declared_surfaces} attack surface(s) declared for this "
                    "repository. A declared surface is somebody's statement "
                    "about the system and outranks anything inferred here."
                ),
            )
        )
    elif network:
        out.proposals.append(
            Proposal(
                field="internet_facing",
                value=True,
                confidence="observed",
                evidence=(
                    f"{network} open network finding(s) — a port answered from "
                    "outside the host."
                ),
            )
        )
    elif dast:
        # The inference this module exists to refuse.
        out.proposals.append(
            Proposal(
                field="internet_facing",
                value=None,
                confidence="unknown",
                evidence=(
                    f"DAST has completed {dast} successful scan(s), so this "
                    "system serves HTTP and something reached it. That is not "
                    "the same as being reachable from the internet: a DAST "
                    "lane commonly runs inside CI against an ephemeral stack, "
                    "which is exactly what this platform's own lane does."
                ),
                what_would_settle_it=(
                    "Declare the attack surface with its exposure, or run a "
                    "network assessment from outside the network."
                ),
            )
        )
    else:
        out.proposals.append(
            Proposal(
                field="internet_facing",
                value=None,
                confidence="unknown",
                evidence="No DAST run, no network finding, no declared surface.",
                what_would_settle_it=(
                    "Enable a DAST lane against the deployed system, or declare "
                    "the attack surface."
                ),
            )
        )

    # --- data_classification ---------------------------------------------
    secrets = _secret_rules(catalog, repo_full_name)
    out.proposals.append(
        Proposal(
            field="data_classification",
            value=None,
            confidence="unknown",
            evidence=(
                (
                    "This repository has leaked "
                    + ", ".join(secrets[:3])
                    + ", which says it handles those credential kinds. It says "
                    "nothing about what data the system stores, which is what "
                    "this field asks."
                )
                if secrets
                else "Nothing the platform observes speaks to what data this system holds."
            ),
            what_would_settle_it=(
                "A person. No scanner reads a privacy notice, and inferring "
                "'holds personal data' from a dependency on an auth library "
                "would be a guess wearing a citation."
            ),
        )
    )

    # --- business_criticality --------------------------------------------
    out.proposals.append(
        Proposal(
            field="business_criticality",
            value=None,
            confidence="unknown",
            evidence=(
                "Nothing the platform observes measures what breaks when this "
                "is down. Scan volume and finding counts measure how much is "
                "watched, not how much depends on it."
            ),
            what_would_settle_it=(
                "A person, or an upstream service catalogue if one exists."
            ),
        )
    )

    # --- owner -----------------------------------------------------------
    if owner and owner_source == "codeowners":
        out.proposals.append(
            Proposal(
                field="owner",
                value=owner,
                confidence="observed",
                evidence=f"CODEOWNERS routes this repository's paths to {owner}.",
            )
        )
    elif owner:
        out.proposals.append(
            Proposal(
                field="owner",
                value=owner,
                confidence="inferred",
                evidence=(
                    f"{owner} owns the repository ({owner_source}). Weaker than "
                    "a CODEOWNERS answer — nobody has claimed it by name."
                ),
                what_would_settle_it="Add a CODEOWNERS file.",
            )
        )
    else:
        out.proposals.append(
            Proposal(
                field="owner",
                value=None,
                confidence="unknown",
                evidence="No CODEOWNERS entry and no repository owner resolved.",
                what_would_settle_it="Add a CODEOWNERS file.",
            )
        )

    return out
