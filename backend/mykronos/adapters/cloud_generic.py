"""Cloud posture adapter — Prowler OCSF JSON (spec 04 §3, §4).

Cloud findings attach to a *resource* in an account, not a file. Identity is
therefore (repo, capability, check, resource uid, account) — stable while the
resource exists, and correctly retired when it is deleted.

Only failing checks are ingested. Prowler can emit passes too, and a portfolio
that stores every passing control for every resource on every daily scan grows
without bound while telling you nothing you would ever query.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from mykronos.adapters.base import AdapterResult, ScanContext
from mykronos.schemas import FindingSubmission, ScanStatus, Severity

logger = logging.getLogger(__name__)

TOOL_NAME = "prowler"

_SEVERITY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFO,
    "info": Severity.INFO,
}

_FAILING = {"fail", "failed", "new", "warning"}


def _load(raw_output: bytes) -> tuple[list[Any], str | None]:
    """Accept either a JSON array or newline-delimited JSON.

    Prowler has shipped both shapes across versions, and a posture scan that
    silently produced nothing because the writer changed format would look
    exactly like a clean account.
    """
    text = raw_output.decode("utf-8", errors="replace").strip()
    if not text:
        return [], None

    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        records: list[Any] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        if records:
            return records, None
        return [], "output is neither a JSON array nor newline-delimited JSON"

    if isinstance(document, list):
        return document, None
    if isinstance(document, dict):
        for key in ("findings", "results", "data"):
            if isinstance(document.get(key), list):
                return document[key], None
        return [document], None
    return [], "unrecognised output shape"


def normalize(raw_output: bytes, context: ScanContext) -> AdapterResult:
    result = AdapterResult()

    records, error = _load(raw_output)
    if error:
        result.warn(f"Cloud posture output unusable: {error}")
        result.scan_status = ScanStatus.PARTIAL_FAILURE
        return result

    for record in records:
        if not isinstance(record, dict):
            result.skipped += 1
            continue

        status = str(
            record.get("status_code") or record.get("status") or ""
        ).strip().lower()
        if status and status not in _FAILING:
            continue  # A passing control is not a finding.

        info = record.get("finding_info") or {}
        check_id = str(
            record.get("check_id")
            or info.get("uid")
            or (record.get("metadata") or {}).get("event_code")
            or ""
        ).strip()
        title = str(info.get("title") or record.get("check_title") or "").strip()
        if not check_id and not title:
            result.skipped += 1
            continue

        resources = record.get("resources") or []
        resource_uid = ""
        if resources and isinstance(resources[0], dict):
            resource_uid = str(resources[0].get("uid") or resources[0].get("name") or "")

        account = str(
            ((record.get("cloud") or {}).get("account") or {}).get("uid")
            or record.get("account_uid")
            or ""
        )

        severity = _SEVERITY.get(
            str(record.get("severity") or "").strip().lower(), Severity.MEDIUM
        )

        result.findings.append(
            FindingSubmission(
                rule_id=(check_id or title)[:255],
                title=(title or check_id)[:1000],
                description=str(
                    record.get("status_detail")
                    or record.get("risk_details")
                    or info.get("desc")
                    or ""
                )[:100_000],
                severity=severity,
                # The resource is the location.
                file_path=(resource_uid or "account")[:2000],
                symbol=account[:500] or None,
                raw_finding_json=record,
            )
        )

    if result.skipped:
        result.warn(f"{result.skipped} cloud record(s) were unusable and skipped")
        result.scan_status = ScanStatus.PARTIAL_FAILURE

    return result
