"""Newly disclosed is not introduced (#734).

The commit gate refuses a commit that *introduced* a critical or a high
(D-048), and "introduced" means first seen in a scan of that commit. For code
that is exact: a SAST finding first seen at a commit is in lines that commit
can own. For a container image it is not. The containers lane rescans every
image the repository references on every commit, so a CVE published this
morning against an image nobody touched is first seen by whichever commit
happens to be scanning - and the gate refused `1588e40`, a change to the
briefing, for a libxtst6 CVE inside the ZAP scanner image.

The test here is the image itself. Trivy records each image's `imageID`, the
digest of its config, which changes whenever any layer does. If the scan
before this one saw the same `imageID`, the bytes are identical, every
package in them was already there, and a finding that is new now is new
because the vulnerability database moved - disclosed, not introduced. It is
still an open finding and still scores; it just is not this commit's fault.

**Images the commit rebuilds.** The repository's own images get a new
`imageID` on every commit, so the test above can never clear them - and
8ac4ef8 was refused for openssl CVEs published that morning, on the same
openssl 3.5.7-1~deb13u2 the unchanged postgres and ZAP images carry. The
second test is corroboration: a finding in a changed image is disclosed when
the same CVE, on the same package at the same version, was first seen in the
same scan in an image the first test cleared. That pairing can only happen
when the database learned about a package version both images already had.
A commit that *introduces* a vulnerable version has nothing to pair with -
no unchanged image newly gained that CVE at that moment - so it still counts.

Anything this cannot establish - no archived report, an image named
ambiguously, no earlier scan - answers "introduced". A gate that fails open
on missing evidence is the wrong way round.
"""

from __future__ import annotations

import json
import logging
from functools import lru_cache
from pathlib import Path
from typing import Any, NamedTuple

logger = logging.getLogger(__name__)

#: The only capability where an unchanged artefact can gain findings between
#: two commits without either commit changing it. `atlas` has the same shape
#: in principle, but its artefact is a manifest in the repository, whose
#: unchanged-ness needs the file's content rather than a digest.
CAPABILITY = "containers"


@lru_cache(maxsize=128)
def _report_image(path: str) -> tuple[str, str] | None:
    """`(imageName, imageID)` for one archived Trivy report, or None.

    Cached by path: an archive is written once, under its scan run's own
    directory, and never rewritten - and the ZAP report alone is 14 MB.
    """
    try:
        document = json.loads(Path(path).read_bytes())
    except (OSError, ValueError, UnicodeDecodeError):
        return None
    runs = document.get("runs") if isinstance(document, dict) else None
    if not isinstance(runs, list):
        return None
    pairs = {
        (
            str(run["properties"].get("imageName") or "").strip(),
            str(run["properties"].get("imageID") or "").strip(),
        )
        for run in runs
        if isinstance(run, dict) and isinstance(run.get("properties"), dict)
    }
    # One image per report, named and identified. Anything else cannot say
    # which image a result belongs to, so it says nothing.
    if len(pairs) != 1:
        return None
    ((name, image_id),) = pairs
    return (name, image_id) if name and image_id else None


def _images(catalog: Any, scan_run_id: str) -> dict[str, str]:
    """imageName -> imageID for every report one scan run archived."""
    # Imported here: `reprocess` pulls in the ingest path, and this module is
    # read by the dashboard queries.
    from mykronos.adapters.registry import get_adapter
    from mykronos.reprocess import _archives_for

    pattern = get_adapter(CAPABILITY, "trivy").pattern
    images: dict[str, str] = {}
    for archive in _archives_for(catalog, catalog.root / "raw", scan_run_id, pattern):
        found = _report_image(str(archive))
        if found is not None:
            images[found[0]] = found[1]
    return images


def _previous_scan(catalog: Any, repo_full_name: str, scan_run_id: str) -> str | None:
    """The last successful containers scan of this repository before this one,
    on a different commit."""
    rows = catalog.query(
        """
        SELECT p.scan_run_id
        FROM scan_runs s
        JOIN scan_runs p
          ON p.repo_full_name = s.repo_full_name
         AND p.capability = s.capability
         AND p.scan_status = 'success'
         AND p.started_at < s.started_at
         AND p.commit_sha <> s.commit_sha
        WHERE s.scan_run_id = ? AND s.repo_full_name = ?
        ORDER BY p.started_at DESC
        LIMIT 1
        """,
        [scan_run_id, repo_full_name],
    )
    return str(rows[0][0]) if rows else None


class Candidate(NamedTuple):
    """One open container finding a commit's scans saw first."""

    finding_id: str
    scan: str
    image: str | None
    rule_id: str = ""
    package: str = ""
    version: str = ""


def disclosed_ids(catalog: Any, candidates: list[tuple[Any, ...]]) -> set[str]:
    """Which of these container findings are newly disclosed, not introduced.

    `candidates` are `Candidate`s, or tuples in its field order: `image` is
    the finding's `raw_finding_json.image`. A finding is disclosed when its
    image is byte-identical to the previous scan's, or - for an image this
    commit changed - when the same rule, package and version was disclosed
    that way in the same scan (see the module docstring).
    """
    if not candidates:
        return set()
    rows = [Candidate(*c) for c in candidates]
    repo = _repo_of(catalog, rows[0].scan)
    disclosed: set[str] = set()
    try:
        for scan_run_id in sorted({row.scan for row in rows}):
            previous = _previous_scan(catalog, repo, scan_run_id) if repo else None
            if previous is None:
                continue
            now = _images(catalog, scan_run_id)
            before = set(_images(catalog, previous).values())
            in_scan = [row for row in rows if row.scan == scan_run_id]
            unchanged = {
                row.finding_id
                for row in in_scan
                if row.image and now.get(row.image) in before
            }
            disclosed |= unchanged
            # Corroboration: what the database newly said about a package
            # version, proven on an image that did not change.
            proven = {
                (row.rule_id, row.package, row.version)
                for row in in_scan
                if row.finding_id in unchanged and row.rule_id and row.package and row.version
            }
            for row in in_scan:
                if (row.rule_id, row.package, row.version) in proven:
                    disclosed.add(row.finding_id)
    except Exception:  # noqa: BLE001 - no evidence means "introduced"
        logger.warning(
            "Could not compare container images for disclosure; every "
            "candidate counts as introduced.",
            exc_info=True,
        )
        return set()
    return disclosed


def _repo_of(catalog: Any, scan_run_id: str) -> str | None:
    rows = catalog.query(
        "SELECT repo_full_name FROM scan_runs WHERE scan_run_id = ? LIMIT 1",
        [scan_run_id],
    )
    return str(rows[0][0]) if rows else None
