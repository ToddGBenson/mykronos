"""Adapter contract (spec 04 §4).

One adapter per (capability, tool) pair. Each turns a tool's native output
into `FindingSubmission` records the Ingestion API accepts.

Note the return type. Spec 04 §4 writes the signature as
`normalize(...) -> list[Finding]`, but a `Finding` (spec 05 §3) carries
server-assigned fields — `finding_id`, `status`, `first_seen_at` — that an
adapter must not and cannot supply. `FindingSubmission` is the accurate type;
see docs/DECISIONS.md D-012.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from mykronos.fingerprint import FINGERPRINT_V1_LINE, compute_finding_id
from mykronos.schemas import FindingSubmission, ScanStatus, TriggeredBy

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ScanContext:
    """Stamped onto every finding an adapter produces (spec 04 §4)."""

    repo_full_name: str
    capability: str
    tool_name: str
    tool_version: str
    commit_sha: str
    branch: str
    workflow_run_id: str = ""
    triggered_by: TriggeredBy = TriggeredBy.PUSH
    pr_number: int | None = None

    #: Root of the checked-out working tree. Snippet extraction reads from
    #: here, and it is the reason spec 04's SAST template checks out full
    #: history: without the source on disk, findings degrade to positional
    #: identity (spec 05 §5).
    workspace: Path | None = None


@dataclass
class AdapterResult:
    """What an adapter produced, including how badly it went.

    Partial success is a first-class outcome (spec 04 §8): a tool that crashed
    halfway still yields real findings, and those must be preserved *and* the
    run still marked failed, so CI is visibly red without losing data.
    """

    findings: list[FindingSubmission] = field(default_factory=list)
    scan_status: ScanStatus = ScanStatus.SUCCESS
    #: Human-readable notes about anything skipped or degraded.
    warnings: list[str] = field(default_factory=list)
    #: Count of results the parser could not make sense of at all.
    skipped: int = 0
    #: Line and branch coverage, 0..1, where the runner reported it (spec 31
    #: §4). `None` means the report did not carry it — distinct from 0.0,
    #: which means the runner measured and found none.
    #:
    #: **Not a security metric, and labelled that way everywhere it is shown.**
    #: It is context that stops a green pass-rate sparkline being read as more
    #: than it is: 90% coverage with zero regression links means the tests are
    #: thorough about something other than the things that have gone wrong
    #: here.
    line_coverage: float | None = None
    branch_coverage: float | None = None

    @property
    def degraded(self) -> bool:
        return self.scan_status is not ScanStatus.SUCCESS or bool(self.warnings)

    def warn(self, message: str) -> None:
        logger.warning("adapter: %s", message)
        self.warnings.append(message)

    def summarise(self) -> str:
        """One line for `$GITHUB_STEP_SUMMARY` (spec 04 §2)."""
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
        order = ["critical", "high", "medium", "low", "info"]
        parts = [f"{counts[s]} {s}" for s in order if s in counts]
        body = ", ".join(parts) if parts else "no findings"
        if self.skipped:
            body += f" ({self.skipped} unparseable result(s) skipped)"
        return body


def identity_version(finding: FindingSubmission, context: ScanContext) -> str:
    """The fingerprint version ingestion will stamp on this finding.

    Asks `compute_finding_id` rather than restating its dispatch table, so an
    adapter cannot disagree with the API about what identity a finding gets.
    Restating it is what produced #325: the adapter layer decided "no code
    snippet" meant "positional", which is one of three anchors and not the
    rule.
    """
    _, version = compute_finding_id(
        repo_full_name=context.repo_full_name,
        capability=context.capability,
        rule_id=finding.rule_id,
        file_path=finding.file_path,
        symbol=finding.symbol,
        code_snippet=finding.code_snippet,
        line_start=finding.line_start,
        package_name=finding.package_name,
        address=finding.address,
        port=finding.port,
        title=finding.title,
    )
    return version


def warn_if_identity_degrades(
    outcome: AdapterResult,
    findings: Iterable[FindingSubmission],
    context: ScanContext,
) -> int:
    """Warn about the findings that really will be keyed on a line number.

    **Call this after the adapter has finished enriching, never before.** The
    fingerprint reads `package_name`, and an adapter that fills that field in
    after parsing — `containers_trivy`, `atlas_osv` — has not set it yet while
    the parser is running. Asking too early is #325: every container scan
    announced that all of its findings would churn while every one of them was
    stored against a stable package key.

    Returns the count so a caller can act on it as well as report it.
    """
    degraded = sum(
        1 for finding in findings if identity_version(finding, context) == FINGERPRINT_V1_LINE
    )
    if degraded:
        # Visible now, rather than as an unexplained trend break later.
        outcome.warn(
            f"{degraded} finding(s) have no package, snippet or symbol to anchor "
            "identity and will use positional identity (fingerprint v1-line). "
            "Those findings churn when unrelated lines shift above them — see "
            "spec 05 §5."
        )
    return degraded
