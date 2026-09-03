"""Adherence to the NIST Secure Software Development Framework (SP 800-218).

**The rule this module is built around: evidence, never intent.** A practice is
reported as met only when this platform has *observed* something that meets it —
a lane that reported, a control GitHub confirmed, an artifact in the archive.
It never counts a capability that is enabled and silent, and it never counts a
control nobody demonstrated.

That is the same standard the maturity model already holds itself to, applied
to a compliance frame. It matters more here, because the output of a compliance
view gets shown to an auditor, and a framework mapping that inflates itself is
worse than no mapping at all: it converts "we do not know" into "we comply",
which is the one transformation nobody can afford.

**Why SSDF rather than 800-53.** SP 800-218 is written in terms of what a
software team *does* — review code, test executable code, archive each release,
respond to vulnerabilities — so its practices map onto observable events. SP
800-53 is written in terms of organisational controls, most of which no CI
pipeline can see. Mapping to 800-53 would require this platform to assert
things about processes it has no visibility into, which is exactly the failure
this module exists to avoid. A subset of 800-53 is reachable *through* SSDF and
is named per practice, for anyone who has to cross-reference.

**Partial is a real answer**, and the most common one. A practice covered by
three lanes where two report is not met and is not unmet; saying so is more
useful than either rounding.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Literal

logger = logging.getLogger(__name__)

Status = Literal["met", "partial", "not_evidenced", "not_applicable"]


@dataclass(frozen=True)
class Practice:
    """One SSDF practice, and what would evidence it here."""

    practice_id: str
    group: str
    title: str
    #: Capabilities whose *reporting* evidences this practice. Enabled is not
    #: enough — a silent lane evidences nothing, which is the whole point.
    capabilities: tuple[str, ...] = ()
    #: Governance controls whose confirmation evidences this practice.
    controls: tuple[str, ...] = ()
    #: Reachable 800-53 families, for anyone cross-referencing. Named, not
    #: claimed: this platform evidences the SSDF practice, and whether that
    #: satisfies a given 800-53 control is an assessor's judgement.
    nist_800_53: tuple[str, ...] = ()
    #: Said when nothing evidences it, so the gap is actionable.
    how_to_evidence: str = ""


#: The practices this platform can speak to. Deliberately not all of SSDF —
#: PO.1 (define security requirements) and PO.2 (roles and responsibilities)
#: are organisational and no scanner observes them, so they are absent rather
#: than reported as unmet. A framework view that lists practices it cannot
#: assess teaches people to ignore the ones it can.
PRACTICES: tuple[Practice, ...] = (
    Practice(
        "PO.3", "Prepare the Organization", "Implement supporting toolchains",
        capabilities=("sast", "secrets", "containers", "iac", "dast", "atlas"),
        nist_800_53=("SA-11", "SA-15"),
        how_to_evidence="Enable and run at least one analysis lane.",
    ),
    Practice(
        "PO.4", "Prepare the Organization", "Define criteria for software security checks",
        capabilities=("oracle",),
        nist_800_53=("SA-15", "RA-5"),
        how_to_evidence="Enable the risk-decision engine so a policy exists and is applied.",
    ),
    Practice(
        "PS.1", "Protect the Software", "Protect all forms of code from unauthorized access",
        controls=("pull_request_required", "force_push_blocked", "enforced_for_admins"),
        nist_800_53=("AC-3", "CM-5"),
        how_to_evidence="Require pull requests, block force pushes, and apply the rules to admins.",
    ),
    Practice(
        "PS.2", "Protect the Software", "Provide a mechanism to verify software integrity",
        controls=("signed_commits_required",),
        nist_800_53=("SI-7", "CM-14"),
        how_to_evidence="Require signed commits on the default branch.",
    ),
    Practice(
        "PS.3", "Protect the Software", "Archive and protect each software release",
        capabilities=("atlas",),
        nist_800_53=("CM-2", "SR-4"),
        how_to_evidence="Run the dependency lane so each release archives an SBOM.",
    ),
    Practice(
        "PW.1", "Produce Well-Secured Software", "Design software to meet security requirements",
        nist_800_53=("SA-8", "SA-17"),
        how_to_evidence=(
            "Declare the attack surface and record the controls that mitigate it. "
            "A threat model derived only from findings evidences detection, not design."
        ),
    ),
    Practice(
        "PW.4", "Produce Well-Secured Software", "Reuse existing, well-secured software",
        capabilities=("atlas", "containers"),
        nist_800_53=("SA-4", "SR-3"),
        how_to_evidence="Run the dependency and container lanes.",
    ),
    Practice(
        "PW.7", "Produce Well-Secured Software", "Review and/or analyze human-readable code",
        capabilities=("sast", "secrets"),
        controls=("approving_reviews_required", "codeowner_review_required"),
        nist_800_53=("SA-11",),
        how_to_evidence="Run static analysis and require a reviewer other than the author.",
    ),
    Practice(
        "PW.8", "Produce Well-Secured Software", "Test executable code",
        capabilities=("unit", "functional", "dast", "qa"),
        nist_800_53=("SA-11", "CA-8"),
        how_to_evidence="Run the test lanes and report their JUnit results.",
    ),
    Practice(
        "PW.9",
        "Produce Well-Secured Software",
        "Configure software with secure settings by default",
        capabilities=("iac",),
        nist_800_53=("CM-6",),
        how_to_evidence="Run the infrastructure-as-code lane.",
    ),
    Practice(
        "RV.1",
        "Respond to Vulnerabilities",
        "Identify and confirm vulnerabilities on an ongoing basis",
        capabilities=("sast", "containers", "atlas", "dast", "secrets"),
        nist_800_53=("RA-5", "SI-2"),
        how_to_evidence="Run at least one lane on a schedule rather than on demand.",
    ),
    Practice(
        "RV.2", "Respond to Vulnerabilities", "Assess, prioritize, and remediate vulnerabilities",
        capabilities=("oracle", "patchwork"),
        nist_800_53=("RA-5", "SI-2"),
        how_to_evidence=(
            "Findings must carry an owner and a remediation target, and dispositions "
            "must be recorded with grounds."
        ),
    ),
    Practice(
        "RV.3", "Respond to Vulnerabilities", "Analyze vulnerabilities to identify root causes",
        capabilities=("aegis",),
        nist_800_53=("RA-5", "SI-2"),
        how_to_evidence=(
            "Record dismissals with a written reason so recurring causes accumulate "
            "rather than being re-decided."
        ),
    ),
)


@dataclass
class PracticeResult:
    practice_id: str
    group: str
    title: str
    status: Status
    #: Exactly what was observed. Specific enough to disagree with.
    evidence: list[str] = field(default_factory=list)
    #: What is missing, when something is.
    missing: list[str] = field(default_factory=list)
    how_to_evidence: str = ""
    nist_800_53: list[str] = field(default_factory=list)


def assess(
    *,
    reporting_capabilities: set[str],
    enabled_capabilities: set[str],
    confirmed_controls: set[str],
    known_controls: set[str],
) -> list[PracticeResult]:
    """Which practices this repository can evidence right now.

    `reporting_capabilities` is deliberately separate from
    `enabled_capabilities`. A lane that is switched on and has never produced a
    successful scan evidences nothing, and counting it would let a repository
    claim coverage by flipping a toggle — which is the exact move the maturity
    model was written to refuse.

    `known_controls` is separate from `confirmed_controls` for the same reason
    in the other direction: a control this platform could not read is unknown,
    not absent, and reporting it as a failure would be as wrong as reporting it
    as a pass.
    """
    results: list[PracticeResult] = []

    for practice in PRACTICES:
        evidence: list[str] = []
        missing: list[str] = []

        for capability in practice.capabilities:
            if capability in reporting_capabilities:
                evidence.append(f"{capability} lane is reporting successful scans")
            elif capability in enabled_capabilities:
                missing.append(f"{capability} is enabled but has never reported")
            else:
                missing.append(f"{capability} is not enabled")

        for control in practice.controls:
            if control in confirmed_controls:
                evidence.append(f"{control.replace('_', ' ')} is enforced")
            elif control in known_controls:
                missing.append(f"{control.replace('_', ' ')} is not enforced")
            else:
                missing.append(f"{control.replace('_', ' ')} could not be read")

        if not practice.capabilities and not practice.controls:
            # PW.1 — design. Nothing observable maps to it, and saying so is
            # more honest than mapping it to a scanner that answers a
            # different question.
            status: Status = "not_evidenced"
        elif evidence and not missing:
            status = "met"
        elif evidence:
            status = "partial"
        else:
            status = "not_evidenced"

        results.append(
            PracticeResult(
                practice_id=practice.practice_id,
                group=practice.group,
                title=practice.title,
                status=status,
                evidence=evidence,
                missing=missing,
                how_to_evidence=practice.how_to_evidence,
                nist_800_53=list(practice.nist_800_53),
            )
        )

    return results


def summarise(results: list[PracticeResult]) -> dict[str, int]:
    """Counts by status. No percentage — see the note in the API."""
    counts = {"met": 0, "partial": 0, "not_evidenced": 0, "not_applicable": 0}
    for result in results:
        counts[result.status] += 1
    return counts
