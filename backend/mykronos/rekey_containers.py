"""Give every container finding its image, and keep the decisions (spec 05 §5a).

`v2-package` keyed a container finding on (repo, CVE, package) and nothing
else. One CVE in twenty images was one row, labelled with whichever image the
lake wrote last, and a disposition recorded against one image silently covered
every other image with the same package. Measured on 2026-09-24: 6,673 Trivy
results were stored as 4,875 findings, and 176 of mykronos's 256 container
acceptances also covered an image nobody had looked at.

`FINGERPRINT_CONTAINER` adds the image to the key. Every existing container
finding therefore has a new id, and this is the one-time step that moves the
lake across without losing what people decided.

**The rule for a decision is narrow on purpose.** A disposition moves only to
the image it was recorded against — the image the old row was labelled with,
matched by the location Trivy wrote (`file_path`). Every other image carrying
the same package gets its own finding, open, because nobody ever decided
anything about it; carrying the decision there would re-create exactly the
defect this repairs. Where the old label is a path several images share, the
decision cannot be placed and is reported as stranded rather than guessed.

An acceptance whose stated premise is already false for its image —
`no_vendor_fix` on a finding whose scan names a fixed version — is not
carried either. The front door refuses that acceptance (`dashboard.py`), and
the sweep would reopen it on its next run; writing it across would only put a
known-false premise back in the register for a day.

**First sightings travel on the same lineage.** The image the old row was
labelled with inherits its `first_seen_at`, so the triage queue does not report
a month-old critical as new. Other images do not: the old row's date may come
from a different image entirely, and claiming it would be the same false
precision in the other direction.

Old rows become `superseded` with `superseded_source = 'rekey'`, never
`fixed` — nothing was remediated, and `fixed` feeds mean-time-to-fix.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from mykronos.fingerprint import (
    FINGERPRINT_DEPENDENCY,
    compute_finding_id,
    image_of,
    image_repository,
)
from mykronos.lake.buffer import WriteAheadBuffer
from mykronos.lake.catalog import Catalog
from mykronos.lake.mutate import locate_findings, update_findings
from mykronos.reprocess import _archived_scans, _ingest, derive_scan
from mykronos.schemas import FindingStatus, utcnow

logger = logging.getLogger(__name__)

CAPABILITY = "containers"

#: Statuses a person set. Carried to the lineage image when the premise holds.
DISPOSITIONS = ("accepted_risk", "false_positive", "suppressed")

#: Everything an old row can be in that still means "this is current".
LIVE = ("open", *DISPOSITIONS)


@dataclass
class RepoRekey:
    repo_full_name: str
    scan_run_id: str = ""
    #: Distinct image-keyed findings the latest scan produces.
    produced: int = 0
    #: Old `v2-package` rows retired as superseded.
    superseded: int = 0
    #: Decisions moved onto the image they were recorded against.
    carried: int = 0
    #: `no_vendor_fix` acceptances not carried because the image has a fix.
    premise_false: list[str] = field(default_factory=list)
    #: Decisions whose image could not be told apart, by old finding_id.
    stranded: list[str] = field(default_factory=list)
    #: New findings that inherited an older first sighting.
    dated: int = 0
    error: str = ""


@dataclass
class RekeyResult:
    repos: list[RepoRekey] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"{len(self.repos)} repo(s): produced "
            f"{sum(r.produced for r in self.repos)} image-keyed finding(s), "
            f"superseded {sum(r.superseded for r in self.repos)}, "
            f"carried {sum(r.carried for r in self.repos)} decision(s), "
            f"{sum(len(r.premise_false) for r in self.repos)} not carried "
            "because the image has a fix, "
            f"{sum(len(r.stranded) for r in self.repos)} stranded"
        )


@dataclass
class _Old:
    finding_id: str
    rule_id: str
    package_name: str
    file_path: str
    status: str
    accepted_until: Any
    accepted_reason_code: Any
    resolved_at: Any
    first_seen_at: Any
    first_seen_scan_run_id: Any


@dataclass
class _New:
    finding_id: str
    image: str
    locations: set[str] = field(default_factory=set)
    fixed_version: str = ""


def rekey_containers(
    catalog: Catalog,
    buffer: WriteAheadBuffer,
    raw_dir: Path,
    *,
    repo_full_name: str | None = None,
    dry_run: bool = False,
) -> RekeyResult:
    """Re-key container findings from each repo's latest archived scan.

    Writes the new rows through `reprocess._ingest` (the same writer a
    reprocess uses) and retires the old ones. Run `compact` afterwards, as
    after a reprocess. `dry_run` computes and reports everything and writes
    nothing.
    """
    result = RekeyResult()
    for row in _archived_scans(catalog, repo_full_name, CAPABILITY, all_history=False):
        scan_run_id, repo, *_rest, seen_at = row
        outcome = RepoRekey(repo_full_name=str(repo), scan_run_id=str(scan_run_id))
        result.repos.append(outcome)

        derived = derive_scan(catalog, raw_dir, row)
        if derived.no_archive or derived.error or derived.parsed is None:
            outcome.error = derived.error or "no archived output for the latest scan"
            continue
        if derived.parsed.scan_status.value != "success":
            outcome.error = (
                f"adapter reported {derived.parsed.scan_status.value}; nothing re-keyed"
            )
            continue

        fresh = _group_new(str(repo), derived.parsed.findings)
        if not any(image for items in fresh.values() for image in (n.image for n in items)):
            outcome.error = (
                "the archived reports name no image; re-keying would change nothing"
            )
            continue
        outcome.produced = sum(len(items) for items in fresh.values())

        old_rows = _old_rows(catalog, str(repo))
        overrides: dict[str, dict[str, object]] = {}
        retire: dict[str, list[tuple[str, str | None]]] = defaultdict(list)

        for old in old_rows:
            candidates = fresh.get((old.rule_id, old.package_name), [])
            if not candidates:
                # Not in the latest scan at all, in any image: this row is not
                # being re-keyed, it is gone. The absence reconciler closes it
                # (or the sweep, for a disposition); superseding it here would
                # hide a real remediation from mean-time-to-fix.
                continue
            lineage = [n for n in candidates if old.file_path in n.locations]
            successor = lineage[0] if len({n.image for n in lineage}) == 1 else None

            if successor is not None and _earlier(old.first_seen_at, overrides, successor):
                entry = overrides.setdefault(successor.finding_id, {})
                entry["first_seen_at"] = old.first_seen_at
                entry["first_seen_scan_run_id"] = old.first_seen_scan_run_id
                outcome.dated += 1

            if old.status in DISPOSITIONS:
                if successor is None:
                    outcome.stranded.append(old.finding_id)
                elif (
                    old.status == "accepted_risk"
                    and old.accepted_reason_code == "no_vendor_fix"
                    and successor.fixed_version
                ):
                    outcome.premise_false.append(old.finding_id)
                else:
                    entry = overrides.setdefault(successor.finding_id, {})
                    entry.update(
                        status=old.status,
                        # A `date`, which the write-ahead buffer cannot
                        # serialise; compaction casts the ISO string back.
                        accepted_until=(
                            old.accepted_until.isoformat()
                            if hasattr(old.accepted_until, "isoformat")
                            else old.accepted_until
                        ),
                        accepted_reason_code=old.accepted_reason_code,
                        resolved_at=old.resolved_at,
                    )
                    outcome.carried += 1

            retire[old.status].append(
                (old.finding_id, successor.finding_id if successor else None)
            )

        _ingest(
            catalog,
            buffer,
            scan_run_id=str(scan_run_id),
            context=derived.context,  # type: ignore[arg-type]
            parsed=derived.parsed,
            dry_run=dry_run,
            observed_at=seen_at,
            overrides=overrides,
        )
        outcome.superseded = sum(len(items) for items in retire.values())
        if not dry_run:
            for status, pairs in retire.items():
                _supersede(catalog, pairs, status)

        logger.info(
            "Re-keyed %s: %s produced, %s superseded, %s carried, %s stranded, "
            "%s premise false",
            repo, outcome.produced, outcome.superseded, outcome.carried,
            len(outcome.stranded), len(outcome.premise_false),
        )
    return result


def _group_new(repo: str, findings: list[Any]) -> dict[tuple[str, str], list[_New]]:
    """The re-derived findings, one entry per new id, grouped by (CVE, package).

    Several Trivy results can share one new id — the same `stdlib` CVE in
    twenty binaries of one image — so each entry keeps every location it was
    reported at. The old row's label is one of those locations.
    """
    by_id: dict[str, _New] = {}
    groups: dict[tuple[str, str], list[_New]] = defaultdict(list)
    for finding in findings:
        image = image_of(finding.raw_finding_json)
        if not finding.package_name or not image:
            continue
        finding_id, _version = compute_finding_id(
            repo_full_name=repo,
            capability=CAPABILITY,
            rule_id=finding.rule_id,
            file_path=finding.file_path,
            package_name=finding.package_name,
            title=finding.title,
            image=image,
        )
        entry = by_id.get(finding_id)
        if entry is None:
            entry = _New(finding_id=finding_id, image=image_repository(image))
            by_id[finding_id] = entry
            groups[(finding.rule_id, finding.package_name)].append(entry)
        if finding.file_path:
            entry.locations.add(finding.file_path)
        fixed = (finding.raw_finding_json or {}).get("fixed_version")
        if isinstance(fixed, str) and fixed.strip():
            entry.fixed_version = fixed.strip()
    return groups


def _old_rows(catalog: Catalog, repo: str) -> list[_Old]:
    placeholders = ", ".join("?" for _ in LIVE)
    rows = catalog.query(
        "SELECT finding_id, rule_id, package_name, coalesce(file_path, ''), status, "
        "       accepted_until, accepted_reason_code, resolved_at, "
        "       first_seen_at, first_seen_scan_run_id "
        "FROM findings "
        "WHERE asset_id = ? AND capability = ? AND fingerprint_version = ? "
        f"  AND status IN ({placeholders})",
        [repo, CAPABILITY, FINGERPRINT_DEPENDENCY, *LIVE],
    )
    return [
        _Old(
            finding_id=str(row[0]),
            rule_id=str(row[1]),
            package_name=str(row[2]),
            file_path=str(row[3]),
            status=str(row[4]),
            accepted_until=row[5],
            accepted_reason_code=row[6],
            resolved_at=row[7],
            first_seen_at=row[8],
            first_seen_scan_run_id=row[9],
        )
        for row in rows
    ]


def _earlier(
    candidate: Any, overrides: dict[str, dict[str, object]], successor: _New
) -> bool:
    """Whether `candidate` is an earlier first sighting than one already carried."""
    if not isinstance(candidate, datetime):
        return False
    current = overrides.get(successor.finding_id, {}).get("first_seen_at")
    return not isinstance(current, datetime) or candidate < current


def _supersede(
    catalog: Catalog, pairs: list[tuple[str, str | None]], status: str
) -> None:
    """Retire old rows, each pointing at its own replacement where it has one.

    One `update_findings` call per status, with the pointer chosen per row by
    a CASE: each call rewrites every partition it touches, and a call per
    replacement would rewrite the same partitions thousands of times.
    `only_if_status` is the status the row was read in, so a decision a
    person changes while this runs is not overwritten by it.
    """
    located = locate_findings(catalog, [old_id for old_id, _ in pairs])
    if not located:
        return
    pointed = [(old_id, successor) for old_id, successor in pairs if successor]
    if pointed:
        case = "CASE finding_id " + " ".join("WHEN ? THEN ?" for _ in pointed) + " END"
        case_params: list[object] = [value for pair in pointed for value in pair]
    else:
        case, case_params = "NULL", []
    update_findings(
        catalog,
        located,
        f"status = ?, superseded_by = {case}, resolved_at = ?, "
        "superseded_source = 'rekey'",
        [FindingStatus.SUPERSEDED.value, *case_params, utcnow()],
        only_if_status=status,
    )
