"""CodeQL adapter (spec 04 §3, §4).

CodeQL emits standards-compliant SARIF, so almost all the work is the shared
converter. What lives here is the CodeQL-specific handling: it writes one
SARIF file per analysed language, and it reports severity through the
`security-severity` rule property rather than SARIF's four-value `level`.
"""

from __future__ import annotations

import logging
from pathlib import Path

from mykronos.adapters.base import AdapterResult, ScanContext
from mykronos.adapters.sarif import sarif_to_findings
from mykronos.schemas import ScanStatus

logger = logging.getLogger(__name__)

TOOL_NAME = "codeql"


def normalize(raw_output: bytes, context: ScanContext) -> AdapterResult:
    """Parse one CodeQL SARIF document."""
    return sarif_to_findings(raw_output, context)


def normalize_directory(results_dir: Path, context: ScanContext) -> AdapterResult:
    """Parse every SARIF file CodeQL wrote for this run.

    `codeql-action/analyze` emits one file per language into an output
    directory, so a polyglot repo produces several. They are merged into one
    result set here; the fingerprint already includes `capability`, and
    findings from different languages are in different files, so nothing
    collides.
    """
    outcome = AdapterResult()

    if not results_dir.exists():
        # Distinct from "scanned, found nothing": CodeQL was expected to write
        # here and did not, which usually means the analyse step failed.
        # spec 04 §6 requires those to be distinguishable.
        outcome.warn(f"No CodeQL output at {results_dir} — did the analyse step run?")
        outcome.scan_status = ScanStatus.FAILURE
        return outcome

    sarif_files = sorted(results_dir.rglob("*.sarif"))
    if not sarif_files:
        outcome.warn(f"No .sarif files under {results_dir}")
        outcome.scan_status = ScanStatus.FAILURE
        return outcome

    for path in sarif_files:
        try:
            raw = path.read_bytes()
        except OSError as exc:
            outcome.warn(f"Could not read {path.name}: {exc}")
            outcome.scan_status = ScanStatus.PARTIAL_FAILURE
            continue
        sarif_to_findings(raw, context, result=outcome)

    logger.info(
        "CodeQL: %s finding(s) from %s file(s)", len(outcome.findings), len(sarif_files)
    )
    return outcome


def tool_version_from_sarif(raw_output: bytes) -> str:
    """Best-effort tool version for the ScanRun record (spec 05 §3)."""
    import json

    try:
        document = json.loads(raw_output.decode("utf-8", errors="replace"))
        driver = document["runs"][0]["tool"]["driver"]
        return str(driver.get("semanticVersion") or driver.get("version") or "unknown")
    except Exception:  # noqa: BLE001 - a missing version must not fail a scan
        return "unknown"
