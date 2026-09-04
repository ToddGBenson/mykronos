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
import re
from pathlib import Path
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


def _clean_uri(uri: str, workspace: Path | None = None) -> str:
    """Normalise a SARIF artifact URI to a repo-relative path.

    This used to only strip the scheme, which left an absolute path absolute.
    That claim in the docstring was false for any tool emitting a full
    `file:///` URI, and osv-scanner does — so Atlas findings recorded paths
    like `home/runner/work/TheHub/TheHub/backend/requirements.txt`.

    Two things break when that happens. A path is not clickable against the
    repository, so triage cannot open the file. Worse, the finding's identity
    derives from its path (spec 05 §5): move the checkout, change runner
    image layout, and every finding reopens as new work that nobody did.

    The runner path is stripped by matching the workspace root the upload
    action already passes. GitHub's `/home/runner/work/<repo>/<repo>/` layout
    is the fallback for anything that arrives without one.
    """
    for prefix in ("file://", "file:"):
        if uri.startswith(prefix):
            uri = uri[len(prefix) :]
    uri = uri.replace("\\", "/")

    if workspace is not None:
        root = str(workspace).replace("\\", "/").rstrip("/")
        for candidate in (root, root.lstrip("/")):
            if candidate and uri.lstrip("/").startswith(candidate.lstrip("/")):
                uri = uri.lstrip("/")[len(candidate.lstrip("/")) :]
                break

    uri = uri.lstrip("/").removeprefix("./")

    # Fallback for absolute runner paths with no workspace to match against.
    # `/home/runner/work/<repo>/<repo>/rest` — the doubled name is Actions'
    # own layout, and matching it is safer than guessing at a prefix length.
    match = re.match(r"^home/runner/work/([^/]+)/\1/(?P<rest>.*)$", uri)
    if match:
        uri = match.group("rest")

    return uri


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


#: `external/cwe/cwe-089`, `CWE-89`, `cwe-89`, `89` — four spellings of one
#: identifier, and this platform has seen three of them. Normalised to
#: `CWE-89` so a map keyed on one shape is not silently missed by another.
_CWE = re.compile(r"(?:^|/)cwe[-_]?(\d{1,4})(?![0-9])", re.IGNORECASE)


def _cwe_ids(rule: dict[str, Any] | None, result: dict[str, Any]) -> list[str]:
    """Every CWE the tool declared, in `CWE-89` form (spec 28 §1).

    Read from `properties.tags` — where CodeQL writes `external/cwe/cwe-089`
    and Semgrep writes its own — and from `properties.cwe`, which some tools
    populate directly. Both the rule and the result are checked: SARIF allows
    either, and a tool that annotates results rather than rules would
    otherwise report nothing.

    **Nothing is inferred.** A CWE is not guessed from a rule name or a title.
    A tool that declares one is taking responsibility for it; a regex over
    `rule_id` would be this platform manufacturing a taxonomy claim, which is
    exactly what spec 18 §6 declined to do.
    """
    found: list[str] = []
    for holder in (rule or {}, result):
        properties = holder.get("properties") if isinstance(holder, dict) else None
        if not isinstance(properties, dict):
            continue
        candidates: list[Any] = []
        tags = properties.get("tags")
        if isinstance(tags, list):
            candidates.extend(tags)
        direct = properties.get("cwe")
        if isinstance(direct, str):
            candidates.append(direct)
        elif isinstance(direct, list):
            candidates.extend(direct)
        for candidate in candidates:
            if not isinstance(candidate, str):
                continue
            match = _CWE.search(candidate)
            if match:
                # Leading zeros are cosmetic in CodeQL's spelling and would
                # make CWE-089 and CWE-89 two different keys.
                identifier = f"CWE-{int(match.group(1))}"
                if identifier not in found:
                    found.append(identifier)
    return found[:20]


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
    suppressed_rules: list[str] = []

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
            # Suppressed at the source. Not an open finding, and not a
            # platform decision either -- see the warning below.
            if _is_suppressed(raw_result):
                suppressed_rules.append(str(raw_result.get("ruleId") or "?"))
                continue
            snippet_sources[source] = snippet_sources.get(source, 0) + 1
            outcome.findings.append(finding)

    if suppressed_rules:
        # Reported rather than ingested. A pragma in the scanned repository is
        # the author saying "I have answered this", which is not the same act
        # as the platform accepting the risk -- `suppressed` is a decision a
        # rescan must not overwrite (spec 05 §7), and a scanner comment
        # rewriting it on every run would make it an observation again.
        #
        # Ingesting them as open findings, which is what happened before this,
        # is worse than either: documenting a skip made the finding count go
        # UP, because the pragma shifts line numbers and positional identity
        # then reads the same finding as a new one.
        counted = ", ".join(sorted(set(suppressed_rules)))
        outcome.warn(
            f"{len(suppressed_rules)} result(s) suppressed in the scanned "
            f"repository and not ingested: {counted}"
        )

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


def _is_suppressed(raw: dict[str, Any]) -> bool:
    """True when the tool reports this result as suppressed in the scanned repo.

    SARIF 2.1.0 §3.27.23. A result carries `suppressions` when the author
    silenced it at the source -- `# checkov:skip=`, `# nosemgrep`, a Trivy
    `.trivyignore` entry. Each suppression has an optional `status`, and only
    `rejected` means the silencing was refused and the result still stands.
    An absent status means accepted, per the spec.
    """
    suppressions = raw.get("suppressions")
    if not isinstance(suppressions, list) or not suppressions:
        return False
    return any(
        str((s or {}).get("status") or "accepted").strip() != "rejected"
        for s in suppressions
        if isinstance(s, dict)
    )


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
    file_path = _clean_uri(str(artifact.get("uri") or ""), context.workspace) or None

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
            cwe_ids=_cwe_ids(rule, raw),
            raw_finding_json=raw,
        ),
        source,
    )
