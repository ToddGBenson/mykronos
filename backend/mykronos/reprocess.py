"""Re-derive findings from archived tool output (spec 05 §5a).

An adapter can be wrong. Three were, in one day: osv-scanner findings carried
absolute runner paths and no package, gitleaks findings pointed at lines in
the current file rather than the commit they came from, and Trivy findings
named neither their package nor their image. Every finding those adapters
produced is now the wrong shape.

Re-running the scans would fix it, and costs CI minutes the repository may not
have. The raw output is already archived (§7) precisely so it does not have to
be. This reads it back, runs the *current* adapter, and ingests the result.

The part that needs care is what happens to the records being replaced.
`finding_id` is derived from the finding's content (§5), so a corrected
adapter produces a different id for the same vulnerability — the old row does
not update, it is orphaned. It must not become `fixed`: that status is the
only input to mean-time-to-fix, and retiring a few hundred mis-identified
findings as fixed would report a mass remediation that never happened. It
becomes `superseded`, which is excluded from both the open counts and the
resolved-work metrics, because it is neither.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from mykronos.adapters.base import AdapterResult, ScanContext
from mykronos.adapters.registry import get_adapter
from mykronos.lake.buffer import WriteAheadBuffer
from mykronos.lake.catalog import Catalog
from mykronos.lake.mutate import locate_findings, update_findings
from mykronos.schemas import FindingStatus, ScanStatus, TriggeredBy, utcnow

logger = logging.getLogger(__name__)


@dataclass
class ScanReprocess:
    scan_run_id: str
    repo_full_name: str
    capability: str
    tool_name: str
    #: Findings the current adapter produced.
    produced: int = 0
    #: Records retired because no current-adapter finding shares their id.
    superseded: int = 0
    #: Records that survived unchanged — the adapter agrees with itself.
    unchanged: int = 0
    error: str = ""


@dataclass
class ReprocessResult:
    scans: list[ScanReprocess] = field(default_factory=list)
    skipped_no_archive: int = 0

    @property
    def produced(self) -> int:
        return sum(s.produced for s in self.scans)

    @property
    def superseded(self) -> int:
        return sum(s.superseded for s in self.scans)

    def summary(self) -> str:
        failed = sum(1 for s in self.scans if s.error)
        return (
            f"reprocessed {len(self.scans) - failed} scan(s), "
            f"produced {self.produced} finding(s), "
            f"superseded {self.superseded} record(s), "
            f"{failed} failed, {self.skipped_no_archive} had no archive"
        )


def _archived_scans(
    catalog: Catalog,
    repo_full_name: str | None,
    capability: str | None,
    all_history: bool,
) -> list[tuple[str, str, str, str, str, str, str, object]]:
    where = ["raw_output_ref IS NOT NULL", "raw_output_ref <> ''"]
    params: list[str] = []
    if repo_full_name:
        where.append("repo_full_name = ?")
        params.append(repo_full_name)
    if capability:
        where.append("capability = ?")
        params.append(capability)

    # Latest scan per repo and capability only, unless asked for all history.
    #
    # Re-deriving every archived scan was the first attempt and it was wrong.
    # Only the most recent scan describes what is true now; the others are
    # history. Re-materialising them resurrects findings that later scans had
    # already resolved, and the absence reconciler then closes each one again
    # with `resolved_at = now` — 282 findings in the first real run, which put
    # a day's worth of imaginary remediation into mean-time-to-fix. The
    # `superseded` status exists to keep exactly that number honest, and this
    # corrupted it from a direction the status could not defend.
    ranked = (
        "SELECT scan_run_id, repo_full_name, capability, tool_name, "
        "       coalesce(tool_version, '') AS tool_version, "
        "       coalesce(commit_sha, '') AS commit_sha, "
        "       coalesce(branch, '') AS branch, "
        "       coalesce(completed_at, started_at) AS observed_at, "
        "       row_number() OVER ("
        "           PARTITION BY repo_full_name, capability "
        "           ORDER BY coalesce(completed_at, started_at) DESC"
        "       ) AS rn "
        "FROM scan_runs "
        f"WHERE {' AND '.join(where)}"
    )
    outer = "" if all_history else "WHERE rn = 1 "
    return catalog.query(
        "SELECT scan_run_id, repo_full_name, capability, tool_name, "
        "       tool_version, commit_sha, branch, observed_at "
        f"FROM ({ranked}) {outer}"
        "ORDER BY observed_at",
        params,
    )


def reprocess(
    catalog: Catalog,
    buffer: WriteAheadBuffer,
    raw_dir: Path,
    *,
    repo_full_name: str | None = None,
    capability: str | None = None,
    dry_run: bool = False,
    all_history: bool = False,
) -> ReprocessResult:
    """Re-derive every archived scan's findings with the current adapters.

    `dry_run` reports what would change and writes nothing, which is what you
    want before retiring several hundred records across an estate.
    """
    result = ReprocessResult()

    for row in _archived_scans(catalog, repo_full_name, capability, all_history):
        scan_run_id, repo, cap, tool, tool_version, commit_sha, branch, seen_at = row
        scan = ScanReprocess(
            scan_run_id=str(scan_run_id),
            repo_full_name=str(repo),
            capability=str(cap),
            tool_name=str(tool),
        )

        derived = derive_scan(catalog, raw_dir, row)
        if derived.no_archive:
            result.skipped_no_archive += 1
            continue
        if derived.error or derived.context is None or derived.parsed is None:
            scan.error = derived.error
            result.scans.append(scan)
            continue
        context, parsed = derived.context, derived.parsed

        fresh_ids = _ingest(
            catalog, buffer, scan_run_id=str(scan_run_id), context=context,
            parsed=parsed, dry_run=dry_run, observed_at=seen_at,
        )
        scan.produced = len(fresh_ids)

        previous = _open_ids_for(catalog, str(scan_run_id))
        scan.unchanged = len(previous & fresh_ids)

        # Retire the replaced records only when the re-derivation actually
        # worked. A truncated or corrupt archive parses to zero findings with
        # a failure status, and treating that as "the adapter no longer
        # reports any of these" would retire the entire scan on the strength
        # of a bad file. Found by the test that asserts it does not.
        if parsed.scan_status is not ScanStatus.SUCCESS:
            scan.error = (
                f"adapter reported {parsed.scan_status.value}; nothing retired"
            )
            result.scans.append(scan)
            continue

        stale = sorted(previous - fresh_ids)
        if stale and not dry_run:
            _mark_superseded(catalog, stale, fresh_ids)
        scan.superseded = len(stale)

        result.scans.append(scan)
        logger.info(
            "Reprocessed %s (%s/%s): %s produced, %s superseded",
            scan_run_id, repo, cap, scan.produced, scan.superseded,
        )

    return result


@dataclass
class DerivedScan:
    """One archived scan run, re-parsed with the current adapter."""

    context: ScanContext | None = None
    parsed: AdapterResult | None = None
    no_archive: bool = False
    error: str = ""


def derive_scan(
    catalog: Catalog,
    raw_dir: Path,
    row: tuple[str, str, str, str, str, str, str, object],
) -> DerivedScan:
    """Re-run the current adapter over everything one scan run archived.

    `row` is a `_archived_scans` row. Shared by `reprocess` and
    `rekey_containers`, which differ only in what they write afterwards.
    """
    scan_run_id, repo, cap, tool, tool_version, commit_sha, branch, _seen_at = row
    try:
        spec = get_adapter(str(cap), str(tool))
    except LookupError as exc:
        return DerivedScan(error=str(exc))

    archives = _archives_for(catalog, raw_dir, str(scan_run_id), spec.pattern)
    if not archives:
        return DerivedScan(no_archive=True)

    context = ScanContext(
        repo_full_name=str(repo),
        capability=str(cap),
        tool_name=str(tool),
        tool_version=str(tool_version),
        commit_sha=str(commit_sha),
        branch=str(branch),
        workflow_run_id="",
        triggered_by=TriggeredBy.PUSH,
        # No workspace: the checkout is long gone. Snippet capture
        # degrades to what the archived output itself carries, which is
        # the same position a scan of a shallow clone is in.
        workspace=None,
    )

    # Every file the scan archived, merged the way `normalize_results` merges
    # them at upload time. One scan run can hold several reports — the
    # containers lane writes one per image — and `raw_output_ref` names only
    # the last one uploaded. Re-deriving from that file alone would reproduce
    # one image and retire every other image's findings as "no longer
    # reported".
    parsed = AdapterResult()
    try:
        for archive in archives:
            part = spec.normalize(archive.read_bytes(), context)
            parsed.findings.extend(part.findings)
            parsed.warnings.extend(part.warnings)
            if part.scan_status is not ScanStatus.SUCCESS:
                parsed.scan_status = part.scan_status
    except Exception as exc:  # noqa: BLE001 — one bad archive is not fatal
        return DerivedScan(error=f"{type(exc).__name__}: {exc}")
    return DerivedScan(context=context, parsed=parsed)


def _archives_for(
    catalog: Catalog, raw_dir: Path, scan_run_id: str, pattern: str
) -> list[Path]:
    """Every archived report for one scan run, in upload order by name.

    The archive endpoint writes each file to `raw/<owner>/<repo>/<scan_run_id>/`
    and the scan row keeps a pointer to one of them. When the pointer's
    directory is that scan's own directory, its siblings matching the
    adapter's pattern are the rest of the same scan; otherwise only the
    pointed-at file is trusted.
    """
    rows = catalog.query(
        "SELECT raw_output_ref FROM scan_runs WHERE scan_run_id = ? LIMIT 1",
        [scan_run_id],
    )
    if not rows or not rows[0][0]:
        return []
    # `raw_output_ref` is relative to the lake root, and `raw_dir` is a
    # directory inside it — resolve against the parent rather than assuming.
    candidate = raw_dir.parent / str(rows[0][0])
    if not candidate.is_file():
        return []
    folder = candidate.parent
    if folder.name != scan_run_id:
        return [candidate]
    siblings = sorted(
        path for path in folder.glob(pattern) if path.is_file() and path.stat().st_size > 0
    )
    return siblings or [candidate]


def _ingest(
    catalog: Catalog,
    buffer: WriteAheadBuffer,
    *,
    scan_run_id: str,
    context: ScanContext,
    parsed: object,
    dry_run: bool,
    observed_at: object = None,
    overrides: dict[str, dict[str, object]] | None = None,
) -> set[str]:
    """Write the re-derived findings and return their ids.

    `overrides` maps a new `finding_id` to columns that replace the defaults
    on its row — how `rekey_containers` carries a disposition and a first
    sighting onto the id that replaces an old one, through this one writer
    rather than a second copy of the row shape.

    `observed_at` is the *scan's* time, not now. Re-derivation produces new
    ids by design, so every row here is an insert rather than an update — and
    stamping them with the reprocess time would record the entire estate as
    first seen today. The triage queue orders by age, so an old critical
    somebody has been ignoring for a month would jump to the bottom of the
    list looking new, and every age-based measure would reset. The finding
    was genuinely first observed by this scan, at this time.
    """
    from mykronos.fingerprint import compute_finding_id, image_of

    moment = observed_at if isinstance(observed_at, datetime) else utcnow()
    rows = []
    ids: set[str] = set()

    # Dispositions already reached on these findings. Re-derivation is not a
    # new observation: re-ingesting a historical scan re-reports findings a
    # *later* scan found gone, and compaction's reopen rule (spec 05 §5) would
    # resurrect every one of them. The first real run reopened 263 records
    # that way. A finding already fixed, dismissed or superseded keeps its
    # disposition and is simply not written again.
    settled = _settled_statuses(catalog, context.repo_full_name, context.capability)

    for finding in getattr(parsed, "findings", []):
        # Exactly the arguments `/api/ingest/findings` passes, in the same
        # order. Identity must be computed one way: `compute_finding_id` keys
        # dependency findings on the package rather than the path, so omitting
        # `package_name` here would give a re-derived finding a different id
        # from the one a real scan produces for the same vulnerability — and
        # the next scan would then insert a third record rather than update
        # this one.
        finding_id, fingerprint_version = compute_finding_id(
            repo_full_name=context.repo_full_name,
            capability=context.capability,
            rule_id=finding.rule_id,
            file_path=finding.file_path,
            symbol=finding.symbol,
            code_snippet=finding.code_snippet,
            line_start=finding.line_start,
            package_name=finding.package_name,
            title=finding.title,
            image=image_of(finding.raw_finding_json),
        )
        ids.add(finding_id)
        if finding_id in settled:
            # Counted as still produced, so it is not retired as stale, but
            # its recorded disposition stands.
            continue
        row: dict[str, object] = {
            "finding_id": finding_id,
            "scan_run_id": scan_run_id,
            # The second writer of findings rows, and the one that made
            # the asset migration bite: `_settled_statuses` reads
            # `asset_id`, so a re-derived row without one is invisible to
            # the guard that stops a fixed finding being reopened. That is
            # D-034 exactly, reintroduced by migrating a reader without
            # its writer.
            "asset_type": "repo",
            "asset_id": context.repo_full_name,
            "repo_full_name": context.repo_full_name,
            "capability": context.capability,
            "rule_id": finding.rule_id,
            "title": finding.title,
            "description": finding.description,
            "severity": finding.severity.value,
            "cvss_score": finding.cvss_score,
            "file_path": finding.file_path,
            "line_start": finding.line_start,
            "line_end": finding.line_end,
            "symbol": finding.symbol,
            "code_snippet": finding.code_snippet,
            "fingerprint_version": fingerprint_version,
            "package_name": finding.package_name,
            "package_version": finding.package_version,
            "status": FindingStatus.OPEN.value,
            "superseded_by": None,
            "first_seen_scan_run_id": scan_run_id,
            "last_seen_scan_run_id": scan_run_id,
            "first_seen_at": moment,
            "last_seen_at": moment,
            "resolved_at": None,
            "raw_finding_json": json.dumps(finding.raw_finding_json or {}),
        }
        if overrides and finding_id in overrides:
            row.update(overrides[finding_id])
        rows.append(row)

    if rows and not dry_run:
        buffer.append("findings", rows)
    return ids


def _settled_statuses(catalog: Catalog, repo_full_name: str, capability: str) -> set[str]:
    """Findings for this repo and capability that already have a disposition."""
    rows = catalog.query(
        "SELECT finding_id FROM findings "
        "WHERE asset_id = ? AND capability = ? AND status <> 'open'",
        [repo_full_name, capability],
    )
    return {str(row[0]) for row in rows}


def _open_ids_for(catalog: Catalog, scan_run_id: str) -> set[str]:
    """Open findings whose latest sighting was this scan run.

    Scoped to the scan run rather than the repository, and that scoping is
    the safety property: reprocessing one scan must never retire a finding
    that a different scan is still reporting. A finding seen by a later run
    has that run's id here and is left alone.

    Read before the re-derived rows are compacted in, so it is the state as
    the old adapter left it.
    """
    rows = catalog.query(
        "SELECT finding_id FROM findings "
        "WHERE last_seen_scan_run_id = ? AND status = 'open'",
        [scan_run_id],
    )
    return {str(row[0]) for row in rows}


def _mark_superseded(
    catalog: Catalog, stale: list[str], fresh_ids: set[str]
) -> None:
    """Retire the replaced records (spec 05 §5a).

    `superseded_by` records one of the replacing ids. One rather than a
    mapping: the relationship is not reliably one-to-one — a corrected adapter
    may merge two mis-identified records or split one — and a pointer into the
    same scan run is enough to follow the trail. Where the scan produced
    nothing at all, it stays null and the status alone says the record was
    withdrawn.

    `superseded_source` names this function as the setter. `superseded_by` was
    never able to: it is null here only when the re-derivation produced
    nothing, and the moment one produces a replacement the row is shaped like
    a carry-forward and means something else entirely (D-124).
    """
    replacement = sorted(fresh_ids)[0] if fresh_ids else None
    located = locate_findings(catalog, stale)
    if not located:
        return
    update_findings(
        catalog,
        located,
        "status = ?, superseded_by = ?, resolved_at = ?, superseded_source = 'reprocess'",
        [FindingStatus.SUPERSEDED.value, replacement, utcnow()],
        only_if_status="open",
    )
