"""OWASP ZAP baseline adapter (spec 04 §3, §4).

DAST findings have no file and no line — they have a URL and an HTTP method.
That makes the fingerprint inputs different from every other adapter: the
"location" is the request, so identity is (repo, capability, rule, url path,
method + path). Stable across scans as long as the endpoint exists, and it
changes when the endpoint does, which is the correct behaviour.

ZAP groups by alert with a list of instances. One alert affecting five URLs is
five findings here, not one: they are fixed and tracked separately, and
collapsing them would make "how many are left" unanswerable.
"""

from __future__ import annotations

import json
import logging
from typing import Any
from urllib.parse import urlparse

from mykronos.adapters.base import AdapterResult, ScanContext
from mykronos.schemas import FindingSubmission, ScanStatus, Severity

logger = logging.getLogger(__name__)

TOOL_NAME = "zap"

#: ZAP `riskcode`. There is no critical band — the highest ZAP expresses is
#: High, and inventing a critical tier the tool did not report would
#: misrepresent it.
_RISK_TO_SEVERITY = {
    "3": Severity.HIGH,
    "2": Severity.MEDIUM,
    "1": Severity.LOW,
    "0": Severity.INFO,
}

MAX_INSTANCES_PER_ALERT = 25


def _severity(alert: dict[str, Any]) -> Severity:
    return _RISK_TO_SEVERITY.get(str(alert.get("riskcode", "")).strip(), Severity.MEDIUM)


def _path_of(uri: str) -> str:
    try:
        parsed = urlparse(uri)
        return (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")
    except ValueError:
        return uri


def normalize(raw_output: bytes, context: ScanContext) -> AdapterResult:
    """Parse a ZAP baseline JSON report."""
    result = AdapterResult()

    try:
        text = raw_output.decode("utf-8", errors="replace").strip()
        document = json.loads(text) if text else {}
    except json.JSONDecodeError as exc:
        result.warn(f"ZAP output is not parseable JSON ({exc})")
        result.scan_status = ScanStatus.PARTIAL_FAILURE
        return result

    if not isinstance(document, dict):
        result.warn("ZAP output is not a JSON object")
        result.scan_status = ScanStatus.PARTIAL_FAILURE
        return result

    truncated = 0

    for site in document.get("site") or []:
        if not isinstance(site, dict):
            result.skipped += 1
            continue

        for alert in site.get("alerts") or []:
            if not isinstance(alert, dict):
                result.skipped += 1
                continue

            rule_id = str(alert.get("pluginid") or alert.get("alertRef") or "").strip()
            name = str(alert.get("alert") or "").strip()
            if not rule_id or not name:
                result.skipped += 1
                continue

            severity = _severity(alert)
            description = str(alert.get("desc") or "")
            solution = str(alert.get("solution") or "")
            cwe = str(alert.get("cweid") or "").strip()

            instances = [i for i in (alert.get("instances") or []) if isinstance(i, dict)]
            if not instances:
                # An alert with no instance is site-wide (a missing header on
                # every response, say). Keep it, anchored to the site.
                instances = [{"uri": str(site.get("@name") or ""), "method": "GET"}]

            if len(instances) > MAX_INSTANCES_PER_ALERT:
                truncated += len(instances) - MAX_INSTANCES_PER_ALERT
                instances = instances[:MAX_INSTANCES_PER_ALERT]

            for instance in instances:
                uri = str(instance.get("uri") or "")
                method = str(instance.get("method") or "GET").upper()
                path = _path_of(uri)

                result.findings.append(
                    FindingSubmission(
                        rule_id=(f"ZAP-{rule_id}" + (f"-CWE-{cwe}" if cwe else ""))[:255],
                        title=f"{name} at {method} {path}"[:1000],
                        description="\n\n".join(p for p in (description, solution) if p)[
                            :100_000
                        ],
                        severity=severity,
                        # The request *is* the location.
                        file_path=path[:2000] or "/",
                        # Method plus path: stable while the endpoint exists,
                        # and changes when it does. Deliberately not the
                        # matched evidence, which varies per response.
                        code_snippet=f"{method} {path}",
                        raw_finding_json={
                            **{k: v for k, v in alert.items() if k != "instances"},
                            "instance": instance,
                        },
                    )
                )

    if truncated:
        # Silent truncation would read as "that is all of them".
        result.warn(
            f"{truncated} additional ZAP instance(s) beyond "
            f"{MAX_INSTANCES_PER_ALERT} per alert were not ingested. A single "
            "alert matching hundreds of URLs is usually one systemic issue; "
            "raise the cap if you need every instance tracked separately."
        )

    if result.skipped:
        result.warn(f"{result.skipped} ZAP record(s) were unusable and skipped")
        result.scan_status = ScanStatus.PARTIAL_FAILURE

    return result
