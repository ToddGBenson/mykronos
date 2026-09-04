"""Which fixed vulnerabilities would we notice coming back? (spec 31)

Findings and the Harness have been adjacent tabs with no relationship. A
finding was fixed, the row disappeared, and nothing was left behind in the
repository that would fail if the same mistake were made again next quarter.
Every fix was a one-time event rather than a permanent change in what the
repository will tolerate.

This is the link that changes that, and the number built on it is the first
in this platform that measures a repository getting *structurally* safer
rather than temporarily cleaner.

**Two grades of evidence, never displayed as one.** `asserted` means somebody
said this test covers that finding. `demonstrated` means the platform watched
it fail against the vulnerable code and pass against the fixed code — the only
proof that a test protects anything. A team that proves its tests work should
not be counted the same as a team that says so, which is why `evidence` is a
column rather than a boolean.

**What staleness can and cannot catch.** The JUnit adapter records suite
totals, not case names (D-046) — so this knows when the *lane* last ran green
and cannot know whether one particular test still exists inside it. A deleted
test therefore still counts until its whole lane stops running. That is a real
limit on the number, stated rather than papered over: it is why `stale` is
reported beside the headline instead of folded into it, and closing it means
recording per-test results, which is its own piece of work.

**Fixed findings are the denominator, not all findings.** A vulnerability
never fixed does not need a regression test; it needs a fix. Using every
finding would make the number unimprovable and therefore ignored.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from mykronos.lake.buffer import WriteAheadBuffer
from mykronos.lake.catalog import Catalog
from mykronos.schemas import utcnow

logger = logging.getLogger(__name__)

ASSERTED = "asserted"
DEMONSTRATED = "demonstrated"
EVIDENCE_GRADES = (ASSERTED, DEMONSTRATED)

#: How long a lane may go without a green run before its links are stale.
#: Thirty days: long enough that a quiet month on a mature repository is not
#: an alarm, short enough that a suite somebody switched off is noticed within
#: a release cycle.
STALE_AFTER_DAYS = 30

#: The lanes a regression test can live in (D-046).
TEST_CAPABILITIES = ("unit", "functional", "qa")


class RegressionError(ValueError):
    """Something a person needs to correct."""


def link_id(repo_full_name: str, finding_id: str, test_identifier: str) -> str:
    """Stable, so re-linking the same test to the same finding is one row.

    Keyed on the triple rather than randomly: a fix PR re-parsed on a second
    webhook delivery, or a person re-submitting the form, must not create a
    second link and inflate the count.
    """
    material = f"{repo_full_name}\x00{finding_id}\x00{test_identifier}"
    return hashlib.sha256(material.encode()).hexdigest()


@dataclass(frozen=True)
class Coverage:
    """Regression coverage for one repository (spec 31 §3)."""

    fixed_findings: int = 0
    covered: int = 0
    demonstrated: int = 0
    asserted: int = 0
    stale: int = 0

    @property
    def available(self) -> bool:
        """Whether the number means anything yet.

        A repository with nothing ever fixed has no coverage to report, and
        `0%` would read as a failing grade rather than as an empty
        denominator.
        """
        return self.fixed_findings > 0

    @property
    def ratio(self) -> float | None:
        if not self.available:
            return None
        return round(self.covered / self.fixed_findings, 3)


def record(
    buffer: WriteAheadBuffer,
    *,
    repo_full_name: str,
    finding_id: str,
    test_identifier: str,
    capability: str,
    evidence: str = ASSERTED,
    linked_by: str = "",
    lane_last_green_at: datetime | None = None,
    now: datetime | None = None,
) -> str:
    """Pin a test to a finding. Returns the link id."""
    test_identifier = test_identifier.strip()
    if not test_identifier:
        raise RegressionError("A link needs a test identifier.")
    if capability not in TEST_CAPABILITIES:
        raise RegressionError(
            f"{capability!r} is not a test lane. Expected one of: "
            f"{', '.join(TEST_CAPABILITIES)}."
        )
    if evidence not in EVIDENCE_GRADES:
        raise RegressionError(f"{evidence!r} is not an evidence grade.")

    stamp = now or utcnow()
    identifier = link_id(repo_full_name, finding_id, test_identifier)
    buffer.append(
        "finding_tests",
        [
            {
                "link_id": identifier,
                "finding_id": finding_id,
                "repo_full_name": repo_full_name,
                "test_identifier": test_identifier,
                "capability": capability,
                "evidence": evidence,
                "linked_by": linked_by,
                "linked_at": stamp,
                "lane_last_green_at": lane_last_green_at,
                "updated_at": stamp,
            }
        ],
    )
    return identifier


def _lane_last_green(
    catalog: Catalog, repo_full_name: str | None
) -> dict[tuple[str, str], datetime]:
    """When each `(repo, lane)` pair last completed successfully.

    Keyed on the pair rather than on the lane, because portfolio-wide this is
    asked across every repository at once: a `unit` lane running green in one
    repository would otherwise keep another repository's abandoned links
    alive, and the number would be the opposite of what it claims to measure.
    """
    if not catalog.all_files("scan_runs"):
        return {}
    names = ", ".join(f"'{c}'" for c in TEST_CAPABILITIES)
    where = f"capability IN ({names}) AND scan_status = 'success'"
    params: list[Any] = []
    if repo_full_name is not None:
        where = "repo_full_name = ? AND " + where
        params.append(repo_full_name)
    rows = catalog.query(
        f"""
        SELECT repo_full_name, capability, max(coalesce(completed_at, started_at))
        FROM scan_runs
        WHERE {where}
        GROUP BY 1, 2
        """,
        params,
    )
    return {(str(r), str(c)): when for r, c, when in rows if when is not None}


def coverage(
    catalog: Catalog, repo_full_name: str | None = None, *, now: datetime | None = None
) -> Coverage:
    """Of the findings ever fixed here, how many have a test pinned.

    `repo_full_name=None` is the portfolio (spec 31 §3): the same arithmetic
    over every repository rather than a mean of per-repository ratios. The
    distinction matters — averaging ratios gives a repository with two fixed
    findings the same weight as one with two hundred, so a single well-tested
    corner would carry an estate that has pinned nothing.
    """
    if not catalog.all_files("findings"):
        return Coverage()

    scope = "" if repo_full_name is None else " AND asset_id = ?"
    scoped: list[Any] = [] if repo_full_name is None else [repo_full_name]
    fixed_rows = catalog.query(
        f"SELECT count(*) FROM findings WHERE status = 'fixed'{scope}",
        scoped,
    )
    fixed = int(fixed_rows[0][0]) if fixed_rows else 0
    if not fixed or not catalog.all_files("finding_tests"):
        return Coverage(fixed_findings=fixed)

    moment = now or utcnow()
    green = _lane_last_green(catalog, repo_full_name)
    cutoff = moment - timedelta(days=STALE_AFTER_DAYS)

    link_scope = "" if repo_full_name is None else " AND l.repo_full_name = ?"
    links = catalog.query(
        f"""
        SELECT l.finding_id, l.evidence, l.capability, l.repo_full_name
        FROM finding_tests l
        JOIN findings f ON f.finding_id = l.finding_id
        WHERE f.status = 'fixed'{link_scope}
        """,
        scoped,
    )

    by_finding: dict[str, list[tuple[str, str, str]]] = {}
    for finding_id, evidence, capability, repo in links:
        by_finding.setdefault(str(finding_id), []).append(
            (str(evidence), str(capability), str(repo))
        )

    covered = demonstrated = asserted = stale = 0
    for grades in by_finding.values():
        live = [
            (grade, capability)
            for grade, capability, repo in grades
            if (green.get((repo, capability)) or datetime.min) >= cutoff
        ]
        if not live:
            # Its lane has not run green in a month. A protection nobody runs
            # is a protection that quietly expired, and counting it would make
            # this number one that only ever goes up.
            stale += 1
            continue
        covered += 1
        if any(grade == DEMONSTRATED for grade, _ in live):
            demonstrated += 1
        else:
            asserted += 1

    return Coverage(
        fixed_findings=fixed,
        covered=covered,
        demonstrated=demonstrated,
        asserted=asserted,
        stale=stale,
    )


def as_dict(result: Coverage) -> dict[str, Any]:
    return {
        "available": result.available,
        "fixed_findings": result.fixed_findings,
        "covered": result.covered,
        "demonstrated": result.demonstrated,
        "asserted": result.asserted,
        "stale": result.stale,
        "ratio": result.ratio,
        "note": (
            "Of the findings ever fixed here, how many have a test pinned. "
            "`demonstrated` means the platform watched the test fail against "
            "the vulnerable code and pass against the fixed code; `asserted` "
            "means somebody said so. `stale` counts links whose lane has not "
            "run green in 30 days — which catches a suite that stopped "
            "running and cannot catch one deleted test inside a lane that "
            "still runs, because the JUnit adapter records suite totals "
            "rather than case names."
        ),
    }
