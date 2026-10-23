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
from datetime import date
from pathlib import Path
from typing import Any

from mykronos.adapters.base import AdapterResult, ScanContext, warn_if_identity_degrades
from mykronos.adapters.snippet import best_snippet, v2_identity
from mykronos.schemas import (
    FindingSubmission,
    ScanStatus,
    Severity,
    SuppressionSubmission,
    utcnow,
)

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


#: Concourse runs a task in `/tmp/build/<handle>/` with each input mounted
#: beside it by name, and every pipeline here names the checkout `source`. The
#: handle differs per container, so the analyser's task and the upload's task
#: need not share one, and `--workspace` cannot be relied on to match it
#: (TheHub #60734).
_CONCOURSE_BUILD_DIR = re.compile(r"^tmp/build/[0-9a-f]+/source/(?P<rest>.+)$")


def _clean_uri(uri: str, workspace: Path | None = None, *, strip_build_dir: bool = True) -> str:
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

    # The same fallback for Concourse. Before it, PSScriptAnalyzer findings
    # were stored as `tmp/build/e542859e/source/scripts/...`: not a path in
    # the repository, so no snippet could be read and every one of them was
    # keyed on its line. `strip_build_dir=False` reproduces that path, which
    # is the identity those findings already have in the lake (see
    # `legacy_file_path`).
    if strip_build_dir:
        build = _CONCOURSE_BUILD_DIR.match(uri)
        if build:
            uri = build.group("rest")

    return uri


def legacy_file_path(uri: str, workspace: Path | None, file_path: str | None) -> str | None:
    """The path this URI was stored under before the Concourse prefix was
    stripped, when that differs from `file_path` (TheHub #60734).

    An adapter records it so ingestion can link the finding to the id it
    already has, rather than the lake counting one finding fixed and the same
    one introduced (`snippet.v2_identity`, D-160).
    """
    legacy = _clean_uri(uri, workspace, strip_build_dir=False) or None
    return legacy if legacy != file_path else None


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
            # [#497] A score of exactly 0.0 is not a measurement of "no risk",
            # it is how a tool spells "I have not scored this". Trivy emits it
            # for every UNKNOWN-severity vulnerability and says so in the same
            # rule: `tags: ['vulnerability', 'security', 'UNKNOWN']`. The bands
            # below start at 0.1, so 0.0 fell past all of them to INFO, and an
            # unrated CVE was filed with the weight of a cosmetic observation.
            # 100 of 138 `info` container findings reached that band this way.
            #
            # Treated as absent instead, so the `level` below decides —
            # `note` -> LOW for the trivy case. LOW is not a guess at the real
            # severity; it is the floor the tool's own level already implied,
            # and it does not read as reassurance. `surfaces.py` makes the same
            # argument for exposure: "the wrong direction to be wrong in is the
            # one that reads as reassurance."
            #
            # The score is deliberately not carried forward either. Reporting
            # 0.0 as this finding's score would assert a measurement nobody
            # made.
            if score is not None and score > 0.0:
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


def _title_and_description(result: dict[str, Any], rule: dict[str, Any] | None) -> tuple[str, str]:
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


#: Where a tool declares that it had no subject. Nested under a vendor key so
#: it cannot collide with a property a scanner already emits.
_MYKRONOS_PROPERTY = "mykronos"
_SCAN_STATUS_PROPERTY = "scanStatus"


def _mykronos_properties(run: Any) -> dict[str, Any]:
    if not isinstance(run, dict):
        return {}
    properties = run.get("properties")
    if not isinstance(properties, dict):
        return {}
    ours = properties.get(_MYKRONOS_PROPERTY)
    return ours if isinstance(ours, dict) else {}


def _declares_no_applicable_targets(runs: list[Any]) -> bool:
    """True only when EVERY run says it had nothing to scan.

    Every, not any. A document holding one run that scanned Terraform and one
    that found no charts describes a repository that HAS infrastructure, and
    calling that "not applicable" would hide the half that was scanned. The
    all-quantifier is the safe direction: a mixed document falls through to the
    normal path and reports what it found.
    """
    declared = [str(_mykronos_properties(run).get(_SCAN_STATUS_PROPERTY) or "") for run in runs]
    return bool(declared) and all(
        value == ScanStatus.NO_APPLICABLE_TARGETS.value for value in declared
    )


def _no_target_reasons(runs: list[Any]) -> list[str]:
    """The tool's own words for why there was nothing, deduplicated in order.

    A status with no reason is the shape that gets argued about six months
    later. The tool knows which file types it looked for; the platform does
    not, and must not guess on its behalf.
    """
    seen: list[str] = []
    for run in runs:
        reason = str(_mykronos_properties(run).get("reason") or "").strip()
        if reason and reason not in seen:
            seen.append(reason[:1000])
    return seen or ["The tool reported no applicable targets and gave no reason."]


def sarif_to_findings(
    raw_output: bytes | str,
    context: ScanContext,
    *,
    result: AdapterResult | None = None,
    warn_degraded: bool = True,
) -> AdapterResult:
    """Convert a SARIF document into `FindingSubmission` records.

    `warn_degraded=False` for an adapter that enriches after parsing. The
    churn warning reads `package_name`, which such an adapter has not filled
    in yet; it owns calling `warn_if_identity_degrades` once it has. See #325.
    """
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

    # From here the document is SARIF, and SARIF can say "suppressed": an
    # empty set is an answer (none), where `None` would mean "not asked".
    if outcome.suppressions is None:
        outcome.suppressions = []

    runs = document.get("runs") or []
    if not runs:
        # A genuinely empty SARIF is a real result: scanned, found nothing.
        return outcome

    # "Nothing to scan" is not "scanned and found nothing", and until now SARIF
    # had no way to say so. A repository with no Terraform, no Dockerfile and no
    # chart is a legitimate state, and a scanner that correctly declines to run
    # over it produced either an empty SARIF -- indistinguishable from a clean
    # scan -- or no SARIF at all, which `normalize_results` reports as FAILURE.
    # Both are wrong, in opposite directions.
    #
    # The marker rides in the run's property bag, which SARIF 2.1.0 §3.8 defines
    # for exactly this, so nothing here is outside the format. A tool that does
    # not set it is unaffected.
    if _declares_no_applicable_targets(runs):
        outcome.scan_status = ScanStatus.NO_APPLICABLE_TARGETS
        for reason in _no_target_reasons(runs):
            outcome.warn(reason)
        return outcome

    # Only what *this* call parsed. `result=` lets a caller accumulate several
    # documents into one outcome (CodeQL writes one SARIF per language), and
    # counting `outcome.findings` would re-count every earlier file's findings
    # on every subsequent one.
    produced: list[FindingSubmission] = []
    suppressed_rules: list[str] = []
    recorded: list[SuppressionSubmission] = []

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
                finding = _convert_result(raw_result, rules, context)
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
                recorded.append(_suppression_of(raw_result, finding))
                continue
            produced.append(finding)
            outcome.findings.append(finding)

    outcome.suppressions.extend(recorded)

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
        #
        # Since TheHub #60963 they are also kept, as suppressions rather than
        # findings: `outcome.suppressions` is posted beside the findings and
        # listed on the repository page with its justification and expiry.
        counted = ", ".join(sorted(set(suppressed_rules)))
        outcome.warn(
            f"{len(suppressed_rules)} result(s) suppressed in the scanned "
            f"repository and not ingested: {counted}"
        )

    # A lapsed suppression still silences its result -- the pragma does not
    # remove itself -- so the date passing is a fact about the lane, raised
    # where a person reads it. Front-loaded like `atlas_osv`'s constraint
    # facts: only the first warning reaches the ScanRun's `detail`.
    expired = expired_suppression_facts(recorded, context.tool_name, utcnow().date())
    if expired:
        for fact in expired:
            logger.warning("adapter: %s", fact)
        outcome.warnings[0:0] = expired

    if warn_degraded:
        warn_if_identity_degrades(outcome, produced, context)
    if outcome.skipped:
        outcome.warn(f"{outcome.skipped} SARIF result(s) could not be parsed and were skipped")
        outcome.scan_status = ScanStatus.PARTIAL_FAILURE

    return outcome


#: Property-bag keys a tool or a wrapper may use for a suppression's expiry.
#: SARIF 2.1.0 has no field for it, so this is convention, read generously.
_EXPIRY_KEYS = ("expiry", "expires", "expires_at", "expiresAt", "expiration", "until")

#: "expires 2026-12-31", "until: 2026-12-31", "exp=2026-12-31" inside a
#: justification -- where a pragma's author writes the date when the tool
#: offers no field for it.
_EXPIRY_IN_TEXT = re.compile(
    r"\b(?:expires?|expiry|expiration|until|exp)\b\s*[:=]?\s*(\d{4}-\d{2}-\d{2})\b",
    re.IGNORECASE,
)

#: How many lapsed suppressions a scan names one by one; the rest are counted.
_EXPIRED_FACTS_NAMED = 5


def _parse_day(value: Any) -> date | None:
    if isinstance(value, date):
        return value
    if not isinstance(value, str) or len(value.strip()) < 10:
        return None
    try:
        return date.fromisoformat(value.strip()[:10])
    except ValueError:
        return None


def _suppression_of(raw: dict[str, Any], finding: FindingSubmission) -> SuppressionSubmission:
    """The suppression a result carries, as one row (TheHub #60963).

    The first entry that is not `rejected` (the one that silenced it). The
    location is the finding's, already cleaned of the CI workspace prefix.
    """
    entries = [s for s in raw.get("suppressions") or [] if isinstance(s, dict)]
    entry = next(
        (s for s in entries if str(s.get("status") or "accepted").strip() != "rejected"),
        {},
    )
    justification = str(entry.get("justification") or "").strip()
    properties = entry.get("properties") if isinstance(entry.get("properties"), dict) else {}
    expires_at = next(
        (
            day
            for day in (_parse_day(properties.get(key)) for key in _EXPIRY_KEYS)
            if day is not None
        ),
        None,
    )
    if expires_at is None and justification:
        match = _EXPIRY_IN_TEXT.search(justification)
        if match:
            expires_at = _parse_day(match.group(1))
    return SuppressionSubmission(
        rule_id=finding.rule_id,
        file_path=finding.file_path[:1024] if finding.file_path else None,
        line=finding.line_start if finding.line_start and finding.line_start >= 0 else None,
        justification=justification[:2000],
        expires_at=expires_at,
        kind=str(entry.get("kind") or "")[:32],
        status=str(entry.get("status") or "accepted")[:32],
    )


def expiry_state(expires_at: date | None, today: date) -> str:
    """`expired`, `no_expiry` or `active`. A suppression expiring today still holds."""
    if expires_at is None:
        return "no_expiry"
    return "expired" if expires_at < today else "active"


def suppression_location(file_path: str | None, line: int | None) -> str:
    if not file_path:
        return "(no file)"
    return f"{file_path}:{line}" if line is not None else file_path


def expired_suppression_facts(suppressions: Any, tool: str, today: date) -> list[str]:
    """One lane-health fact per suppression whose declared expiry has passed.

    Takes anything with `rule_id`, `file_path`, `line` and `expires_at` -- the
    adapter's submissions and the stored rows alike, so the scan and the
    repository page say the same sentence. The first few are named; the rest
    are counted in one more fact, so a repository full of lapsed pragmas does
    not push every other warning off the run.
    """
    lapsed = sorted(
        (s for s in suppressions if expiry_state(s.expires_at, today) == "expired"),
        key=lambda s: (s.expires_at, s.rule_id, s.file_path or "", s.line or 0),
    )
    facts = [
        f"Suppression expired: {s.rule_id} at {suppression_location(s.file_path, s.line)} "
        f"({tool}) passed its expiry {s.expires_at.isoformat()} and still silences "
        "the result in the repository. Renew or remove it."
        for s in lapsed[:_EXPIRED_FACTS_NAMED]
    ]
    rest = lapsed[_EXPIRED_FACTS_NAMED:]
    if rest:
        facts.append(
            f"{len(rest)} more expired suppression(s) ({tool}): "
            + ", ".join(
                f"{s.rule_id} at {suppression_location(s.file_path, s.line)}" for s in rest
            )
        )
    return facts


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
) -> FindingSubmission | None:
    rule_id = str(raw.get("ruleId") or "").strip()
    if not rule_id:
        rule = None
        index = raw.get("ruleIndex")
        if isinstance(index, int):
            ordered = list(rules.values())
            rule = ordered[index] if 0 <= index < len(ordered) else None
        rule_id = str((rule or {}).get("id") or "").strip()
        if not rule_id:
            return None
    else:
        rule = rules.get(rule_id)

    severity, score = _severity_for(raw, rule)
    title, description = _title_and_description(raw, rule)

    locations = raw.get("locations") or []
    physical: dict[str, Any] = {}
    if locations and isinstance(locations[0], dict):
        physical = locations[0].get("physicalLocation") or {}

    artifact = physical.get("artifactLocation") or {}
    raw_uri = str(artifact.get("uri") or "")
    file_path = _clean_uri(raw_uri, context.workspace) or None
    legacy_path = legacy_file_path(raw_uri, context.workspace, file_path)

    region = physical.get("region") or {}
    context_region = physical.get("contextRegion") or {}
    start_line = region.get("startLine")
    end_line = region.get("endLine") or start_line

    resolved = best_snippet(
        context_region_snippet=(context_region.get("snippet") or {}).get("text"),
        region_snippet=(region.get("snippet") or {}).get("text"),
        workspace=context.workspace,
        file_path=file_path,
        start_line=start_line,
        end_line=end_line,
    )

    symbol, v2_symbol = resolved.symbol, resolved.v2_symbol
    v2_snippet = resolved.v2_snippet
    if legacy_path:
        # Stored under Concourse's build directory until TheHub #60734. The
        # predecessor is the id it has in the lake, so resolve it as it was.
        before = best_snippet(
            context_region_snippet=(context_region.get("snippet") or {}).get("text"),
            region_snippet=(region.get("snippet") or {}).get("text"),
            workspace=context.workspace,
            file_path=legacy_path,
            start_line=start_line,
            end_line=end_line,
        )
        v2_symbol, v2_snippet = before.symbol, before.snippet

    # A logical location from the tool beats our heuristic every time — under
    # either identity rule, so it is never a reason for a finding to re-key.
    logical = raw.get("logicalLocations") or []
    if logical and isinstance(logical[0], dict):
        named = logical[0].get("fullyQualifiedName") or logical[0].get("name")
        if named:
            symbol = v2_symbol = str(named)[:500]

    return FindingSubmission(
        rule_id=rule_id[:255],
        title=title,
        description=description,
        severity=severity,
        cvss_score=score,
        file_path=file_path,
        line_start=start_line if isinstance(start_line, int) else None,
        line_end=end_line if isinstance(end_line, int) else None,
        symbol=symbol,
        code_snippet=resolved.snippet,
        cwe_ids=_cwe_ids(rule, raw),
        raw_finding_json=v2_identity(
            raw,
            snippet=resolved.snippet,
            symbol=symbol,
            v2_snippet=v2_snippet,
            v2_symbol=v2_symbol,
            v2_file_path=legacy_path,
        ),
    )
