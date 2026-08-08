"""The client half of the ingestion contract (spec 04 §2, spec 05 §6).

Runs as the final step of every scanner workflow, via the shared
`upload-results` composite action. Collects the tool's output, normalizes it,
archives the original, and posts everything to the Ingestion API.

The rule that shapes this whole module: **findings are never silently
dropped** (spec 01 §6). Every failure path either retries or exits non-zero,
and a `ScanRun` row is written whatever happens, so the lake can always tell
"scanned, clean" from "scanned, broken" from "never ran".
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx2

from mykronos.adapters.base import AdapterResult, ScanContext
from mykronos.adapters.sast_codeql import normalize_directory, tool_version_from_sarif
from mykronos.schemas import (
    Capability,
    FindingSubmission,
    ScanStatus,
    Severity,
    TriggeredBy,
    utcnow,
)

logger = logging.getLogger("mykronos.upload")

MAX_BATCH = 10_000  # spec 05 §6
RETRY_STATUSES = {429, 500, 502, 503, 504}
MAX_ATTEMPTS = 6
BASE_BACKOFF_SECONDS = 2.0

SEVERITY_ORDER = [
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
]


class UploadError(RuntimeError):
    """Ingestion failed after exhausting retries. Always fatal to the step."""


@dataclass
class UploadOutcome:
    scan_run_id: str
    findings_accepted: int = 0
    raw_output_ref: str | None = None
    scan_status: ScanStatus = ScanStatus.SUCCESS
    blocking_findings: int = 0
    warnings: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------


class IngestionClient:
    """Talks to the Ingestion API, with the backoff spec 05 §6 requires."""

    def __init__(self, base_url: str, token: str, timeout: float = 60.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
        }

    def post(
        self,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
        content: bytes | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """POST with exponential backoff, then fail loudly.

        Retries only what is worth retrying. A 4xx other than 429 means the
        payload is wrong and will be just as wrong next time; retrying it
        wastes CI minutes and buries the real error.
        """
        last_detail = ""
        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                with httpx2.Client(timeout=self.timeout) as http:
                    response = http.post(
                        f"{self.base_url}{path}",
                        headers=self._headers(),
                        json=json_body,
                        content=content,
                        params=params,
                    )
            except httpx2.HTTPError as exc:
                last_detail = f"transport error: {exc}"
                self._sleep(attempt, None)
                continue

            if response.status_code < 400:
                if response.headers.get("X-Mykronos-Token-Rotated") == "true":
                    logger.warning(
                        "This repo's ingestion token has been rotated and is inside its "
                        "overlap window. Re-run the workflow installer to pick up the "
                        "new secret before the window closes."
                    )
                return dict(response.json()) if response.content else {}

            last_detail = f"HTTP {response.status_code}: {response.text[:400]}"

            if response.status_code not in RETRY_STATUSES:
                raise UploadError(f"{path} failed and will not be retried — {last_detail}")

            self._sleep(attempt, response.headers.get("Retry-After"))

        raise UploadError(
            f"{path} failed after {MAX_ATTEMPTS} attempts — {last_detail}. "
            "Findings were NOT recorded; this step fails deliberately rather than "
            "letting the scan look clean (spec 01 §6)."
        )

    @staticmethod
    def _sleep(attempt: int, retry_after: str | None) -> None:
        if retry_after:
            try:
                delay = float(retry_after)
            except ValueError:
                delay = BASE_BACKOFF_SECONDS * (2 ** (attempt - 1))
        else:
            delay = BASE_BACKOFF_SECONDS * (2 ** (attempt - 1))
        delay = min(delay, 60.0)
        logger.warning("Ingestion retry %s/%s in %.0fs", attempt, MAX_ATTEMPTS, delay)
        time.sleep(delay)


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def run_adapter(
    capability: str, tool: str, results_path: Path, context: ScanContext
) -> AdapterResult:
    """Dispatch to the (capability, tool) adapter."""
    if (capability, tool) == ("sast", "codeql"):
        return normalize_directory(results_path, context)
    raise UploadError(
        f"No adapter for capability '{capability}' with tool '{tool}'. "
        "Adapters are registered per (capability, tool) pair — spec 04 §4."
    )


def detect_tool_version(results_path: Path, fallback: str) -> str:
    if fallback and fallback != "unknown":
        return fallback
    for sarif in sorted(results_path.rglob("*.sarif"))[:1]:
        try:
            return tool_version_from_sarif(sarif.read_bytes())
        except OSError:
            break
    return "unknown"


def count_blocking(findings: list[FindingSubmission], threshold: Severity) -> int:
    floor = SEVERITY_ORDER.index(threshold)
    return sum(1 for f in findings if SEVERITY_ORDER.index(f.severity) >= floor)


def archive_raw(
    client: IngestionClient,
    results_path: Path,
    scan_run_id: str,
    capability: str,
) -> str | None:
    """Archive the tool's original output (spec 05 §7).

    Best-effort by design: the archive copy is for later dispute resolution,
    and losing it must not discard the normalized findings, which are the
    thing the platform actually runs on.
    """
    candidates = sorted(results_path.rglob("*.sarif")) if results_path.is_dir() else [results_path]
    candidates = [p for p in candidates if p.is_file()]
    if not candidates:
        return None

    refs: list[str] = []
    for path in candidates:
        try:
            payload = client.post(
                "/api/ingest/raw",
                content=path.read_bytes(),
                params={
                    "scan_run_id": scan_run_id,
                    "capability": capability,
                    "filename": path.name,
                },
            )
            refs.append(str(payload.get("raw_output_ref", "")))
        except (UploadError, OSError) as exc:
            logger.warning("Could not archive %s: %s", path.name, exc)
    return refs[0] if refs else None


def write_step_summary(
    outcome: UploadOutcome, result: AdapterResult, capability: str, tool: str
) -> None:
    """Emit the PR-visible summary (spec 04 §2).

    Exists so the Actions UI always shows a readable result without anyone
    opening the dashboard — for most developers this is the only Mykronos
    surface they will ever see.
    """
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return

    counts: dict[Severity, int] = {}
    for finding in result.findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1

    lines = [
        f"## Mykronos — {capability} ({tool})",
        "",
        f"**{len(result.findings)}** finding(s) uploaded · scan status "
        f"`{outcome.scan_status.value}`",
        "",
        "| Severity | Count |",
        "| --- | ---: |",
    ]
    for severity in reversed(SEVERITY_ORDER):
        if counts.get(severity):
            lines.append(f"| {severity.value} | {counts[severity]} |")
    if not counts:
        lines.append("| _none_ | 0 |")

    if result.warnings:
        lines += ["", "### Warnings", ""]
        lines += [f"- {w}" for w in result.warnings]

    lines += ["", f"<sub>scan run `{outcome.scan_run_id}`</sub>"]

    try:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
    except OSError as exc:
        logger.warning("Could not write step summary: %s", exc)


def upload(
    args: argparse.Namespace, client: IngestionClient | None = None
) -> UploadOutcome:
    client = client or IngestionClient(args.ingestion_url, args.token)
    results_path = Path(args.results_path)
    workspace = Path(args.workspace).resolve() if args.workspace else None

    scan_run_id = args.scan_run_id or str(uuid.uuid4())
    # GitHub expression fallbacks yield 0 for "not a pull request"; a
    # ScanRun with pr_number 0 would claim to belong to a PR that does not
    # exist, so normalise it back to null here rather than in shell.
    pr_number = args.pr_number if args.pr_number and args.pr_number > 0 else None
    started_at = utcnow()
    tool_version = detect_tool_version(results_path, args.tool_version)

    context = ScanContext(
        repo_full_name=args.repo,
        capability=args.capability,
        tool_name=args.tool,
        tool_version=tool_version,
        commit_sha=args.commit_sha,
        branch=args.branch,
        workflow_run_id=args.workflow_run_id,
        triggered_by=TriggeredBy(args.triggered_by),
        pr_number=pr_number,
        workspace=workspace,
    )

    def scan_run_payload(**overrides: Any) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "scan_run_id": scan_run_id,
            "repo_full_name": args.repo,
            "capability": args.capability,
            "tool_name": args.tool,
            "tool_version": tool_version,
            "commit_sha": args.commit_sha,
            "branch": args.branch,
            "pr_number": pr_number,
            "triggered_by": args.triggered_by,
            "github_workflow_run_id": args.workflow_run_id,
            "started_at": started_at.isoformat(),
        }
        payload.update(overrides)
        return payload

    # Register the run before scanning is interpreted, so a crash between here
    # and the finalise still leaves evidence the run happened (spec 04 §7).
    client.post("/api/ingest/scan-run", json_body=scan_run_payload())

    outcome = UploadOutcome(scan_run_id=scan_run_id)
    result = AdapterResult()

    try:
        result = run_adapter(args.capability, args.tool, results_path, context)
        outcome.scan_status = result.scan_status
        outcome.warnings = list(result.warnings)

        for start in range(0, max(len(result.findings), 1), MAX_BATCH):
            chunk = result.findings[start : start + MAX_BATCH]
            if not chunk and start:
                break
            response = client.post(
                "/api/ingest/findings",
                json_body={
                    "scan_run_id": scan_run_id,
                    "capability": args.capability,
                    "findings": [f.model_dump(mode="json") for f in chunk],
                },
            )
            outcome.findings_accepted += int(response.get("accepted", 0))

        outcome.raw_output_ref = archive_raw(
            client, results_path, scan_run_id, args.capability
        )
        outcome.blocking_findings = count_blocking(
            result.findings, Severity(args.severity_threshold)
        )
    finally:
        # Always finalise. A run that failed must still be visible in the lake
        # as a run that failed, not as a gap (spec 04 §7).
        client.post(
            "/api/ingest/scan-run",
            json_body=scan_run_payload(
                completed_at=utcnow().isoformat(),
                scan_status=outcome.scan_status.value,
                finding_count=outcome.findings_accepted,
                raw_output_ref=outcome.raw_output_ref,
            ),
        )

    write_step_summary(outcome, result, args.capability, args.tool)
    return outcome


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mykronos-upload",
        description="Normalize scanner output and upload it to Mykronos.",
    )
    parser.add_argument("--capability", required=True, choices=[c.value for c in Capability])
    parser.add_argument("--tool", required=True)
    parser.add_argument("--tool-version", default="")
    parser.add_argument("--results-path", required=True)
    parser.add_argument("--ingestion-url", required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--commit-sha", required=True)
    parser.add_argument("--branch", required=True)
    parser.add_argument("--workflow-run-id", default="")
    parser.add_argument(
        "--triggered-by", default="push", choices=[t.value for t in TriggeredBy]
    )
    parser.add_argument("--pr-number", type=int, default=None)
    parser.add_argument("--workspace", default=".")
    parser.add_argument("--scan-run-id", default="")
    parser.add_argument(
        "--severity-threshold", default="low", choices=[s.value for s in Severity]
    )
    parser.add_argument(
        "--blocking",
        default="false",
        help="If true, findings at or above the threshold fail this step.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args = build_parser().parse_args(argv)

    try:
        outcome = upload(args)
    except UploadError as exc:
        logger.error("%s", exc)
        return 1

    logger.info(
        "Uploaded %s finding(s) for scan run %s (%s)",
        outcome.findings_accepted,
        outcome.scan_run_id,
        outcome.scan_status.value,
    )

    # A degraded scan reddens CI even though its findings were preserved
    # (spec 04 §8). Partial data plus a green tick is the worst outcome.
    if outcome.scan_status is not ScanStatus.SUCCESS:
        logger.error(
            "Scan status is %s — failing the step so this run is visibly broken.",
            outcome.scan_status.value,
        )
        return 1

    if args.blocking.lower() == "true" and outcome.blocking_findings:
        logger.error(
            "%s finding(s) at or above '%s' and blocking is enabled for this repo.",
            outcome.blocking_findings,
            args.severity_threshold,
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
