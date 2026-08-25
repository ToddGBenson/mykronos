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
from dataclasses import dataclass, field
from pathlib import Path

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
