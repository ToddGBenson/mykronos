"""Shared SARIF converter (spec 04 §4).

Most security tools emit SARIF, so this exists once rather than per tool —
"prefer a single shared `sarif_to_finding` converter over a bespoke per-tool
parser". Tool-specific quirks belong in the tool's own adapter, which passes
overrides in.

Nothing here raises on bad input. A tool that crashed mid-write leaves
truncated JSON, a result with no location, or a rule index pointing nowhere;
the contract (spec 04 §4, §8) is to keep whatever parsed and report the rest.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from mykronos.adapters.base import AdapterResult, ScanContext
from mykronos.adapters.snippet import best_snippet
from mykronos.schemas import FindingSubmission, ScanStatus, Severity

logger = logging.getLogger(__name__)

#: SARIF `level` → our scale. Only four values exist and none of them mean
#: "critical", which is why `security-severity` below is preferred when the
#: tool provides it.
_LEVEL_TO_SEVERITY = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
    "none": Severity.INFO,
}

#: Thresholds for the `security-severity` rule property, matching GitHub code
#: scanning's own bands so a finding's severity in Mykronos agrees with what
#: the same rule shows on github.com.
_SECURITY_SEVERITY_BANDS = [
    (9.0, Severity.CRITICAL),
    (7.0, Severity.HIGH),
    (4.0, Severity.MEDIUM),
    (0.1, Severity.LOW),
]


def severity_from_security_score(score: float) -> Severity:
    for threshold, severity in _SECURITY_SEVERITY_BANDS:
        if score >= threshold:
            return severity
    return Severity.INFO


def _clean_uri(uri: str) -> str:
    """Normalise a SARIF artifact URI to a repo-relative path."""
    for prefix in ("file://", "file:"):
        if uri.startswith(prefix):
            uri = uri[len(prefix) :]
    return uri.lstrip("/").removeprefix("./")


def _rule_index(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Rules by id, for looking up severity and descriptions."""
    driver = run.get("tool", {}).get("driver", {})
    rules: dict[str, dict[str, Any]] = {}
    for rule in driver.get("rules", []) or []:
        if isinstance(rule, dict) and rule.get("id"):
            rules[str(rule["id"])] = rule
    for extension in driver.get("extensions", []) or []:
        for rule in extension.get("rules", []) or []:
            if isinstance(rule, dict) and rule.get("id"):
                rules.setdefault(str(rule["id"]), rule)
    return rules


def _severity_for(
    result: dict[str, Any], rule: dict[str, Any] | None
) -> tuple[Severity, float | None]:
    """Precedence: security-severity, then result level, then rule default."""
    if rule:
        raw = (rule.get("properties") or {}).get("security-severity")
        if raw is not None:
            try:
                score = float(raw)
            except (TypeError, ValueError):
                score = None
            if score is not None:
                return severity_from_security_score(score), score

    level = result.get("level")
    if isinstance(level, str) and level in _LEVEL_TO_SEVERITY:
        return _LEVEL_TO_SEVERITY[level], None

    if rule:
        default = (rule.get("defaultConfiguration") or {}).get("level")
        if isinstance(default, str) and default in _LEVEL_TO_SEVERITY:
            return _LEVEL_TO_SEVERITY[default], None

    # SARIF's own default when level is unspecified.
    return Severity.MEDIUM, None


def _title_and_description(
    result: dict[str, Any], rule: dict[str, Any] | None
) -> tuple[str, str]:
    message = (result.get("message") or {}).get("text") or ""
    short = ""
    full = ""
    if rule:
        short = (rule.get("shortDescription") or {}).get("text") or ""
        full = (rule.get("fullDescription") or {}).get("text") or ""

    title = (short or message or rule and rule.get("name") or "Unnamed finding").strip()
    # The per-result message is the specific one ("this call is tainted by X");
    # the rule description is the general one. Both are useful, so keep both,
    # message first because it is about *this* occurrence.
    description = "\n\n".join(part for part in (message, full) if part and part != title)
    return title[:1000], description[:100_000]


def sarif_to_findings(
    raw_output: bytes | str,
    context: ScanContext,
    *,
    result: AdapterResult | None = None,
) -> AdapterResult:
    """Convert a SARIF document into `FindingSubmission` records."""
    outcome = result or AdapterResult()

    try:
        text = (
            raw_output.decode("utf-8", errors="replace")
            if isinstance(raw_output, bytes)
            else raw_output
        )
        document = json.loads(text)
    except (json.JSONDecodeError, UnicodeError) as exc:
        # spec 04 §8: preserve what exists, and still fail the run.
        outcome.warn(f"SARIF is not parseable JSON ({exc}); no findings recovered")
        outcome.scan_status = ScanStatus.PARTIAL_FAILURE
        return outcome

    if not isinstance(document, dict):
        outcome.warn("SARIF root is not an object")
        outcome.scan_status = ScanStatus.PARTIAL_FAILURE
        return outcome

    runs = document.get("runs") or []
    if not runs:
        # A genuinely empty SARIF is a real result: scanned, found nothing.
        return outcome

    snippet_sources: dict[str, int] = {}

    for run in runs:
        if not isinstance(run, dict):
            outcome.skipped += 1
            continue
        rules = _rule_index(run)

        for raw_result in run.get("results") or []:
            if not isinstance(raw_result, dict):
                outcome.skipped += 1
                continue
            try:
                finding, source = _convert_result(raw_result, rules, context)
            except Exception as exc:  # noqa: BLE001 - one bad result must not sink the batch
                logger.debug("Skipping unparseable SARIF result: %s", exc)
                outcome.skipped += 1
                continue
            if finding is None:
                outcome.skipped += 1
                continue
            snippet_sources[source] = snippet_sources.get(source, 0) + 1
            outcome.findings.append(finding)

    degraded = snippet_sources.get("none", 0)
    if degraded:
        # Visible now, rather than as an unexplained trend break later.
        outcome.warn(
            f"{degraded} finding(s) had no code snippet and will use positional "
            "identity (fingerprint v1-line). Those findings churn when unrelated "
            "lines shift above them — see spec 05 §5."
        )
    if outcome.skipped:
        outcome.warn(f"{outcome.skipped} SARIF result(s) could not be parsed and were skipped")
        outcome.scan_status = ScanStatus.PARTIAL_FAILURE

    return outcome


def _convert_result(
    raw: dict[str, Any],
    rules: dict[str, dict[str, Any]],
    context: ScanContext,
) -> tuple[FindingSubmission | None, str]:
    rule_id = str(raw.get("ruleId") or "").strip()
    if not rule_id:
        rule = None
        index = raw.get("ruleIndex")
        if isinstance(index, int):
            ordered = list(rules.values())
            rule = ordered[index] if 0 <= index < len(ordered) else None
        rule_id = str((rule or {}).get("id") or "").strip()
        if not rule_id:
            return None, "none"
    else:
        rule = rules.get(rule_id)

    severity, score = _severity_for(raw, rule)
    title, description = _title_and_description(raw, rule)

    locations = raw.get("locations") or []
    physical: dict[str, Any] = {}
    if locations and isinstance(locations[0], dict):
        physical = locations[0].get("physicalLocation") or {}

    artifact = physical.get("artifactLocation") or {}
    file_path = _clean_uri(str(artifact.get("uri") or "")) or None

    region = physical.get("region") or {}
    context_region = physical.get("contextRegion") or {}
    start_line = region.get("startLine")
    end_line = region.get("endLine") or start_line

    snippet, symbol, source = best_snippet(
        context_region_snippet=(context_region.get("snippet") or {}).get("text"),
        region_snippet=(region.get("snippet") or {}).get("text"),
        workspace=context.workspace,
        file_path=file_path,
        start_line=start_line,
        end_line=end_line,
    )

    # A logical location from the tool beats our heuristic every time.
    logical = raw.get("logicalLocations") or []
    if logical and isinstance(logical[0], dict):
        named = logical[0].get("fullyQualifiedName") or logical[0].get("name")
        if named:
            symbol = str(named)[:500]

    return (
        FindingSubmission(
            rule_id=rule_id[:255],
            title=title,
            description=description,
            severity=severity,
            cvss_score=score,
            file_path=file_path,
            line_start=start_line if isinstance(start_line, int) else None,
            line_end=end_line if isinstance(end_line, int) else None,
            symbol=symbol,
            code_snippet=snippet,
            raw_finding_json=raw,
        ),
        source,
    )
