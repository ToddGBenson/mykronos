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

Anything this cannot establish - no archived report, an image named
ambiguously, no earlier scan - answers "introduced". A gate that fails open
on missing evidence is the wrong way round.
"""

from __future__ import annotations

import json
import logging
from functools import lru_cache
from pathlib import Path
from typing import Any

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


def disclosed_ids(catalog: Any, candidates: list[tuple[str, str, str | None]]) -> set[str]:
    """Which of these container findings are newly disclosed, not introduced.

    `candidates` are `(finding_id, first_seen_scan_run_id, image)` for open
    container findings a commit's scans saw first; `image` is the finding's
    `raw_finding_json.image`. Returns the ids whose image the previous scan
    already saw byte-for-byte.
    """
    if not candidates:
        return set()
    repo = _repo_of(catalog, candidates[0][1])
    disclosed: set[str] = set()
    try:
        for scan_run_id in sorted({scan for _, scan, _ in candidates}):
            previous = _previous_scan(catalog, repo, scan_run_id) if repo else None
            if previous is None:
                continue
            now = _images(catalog, scan_run_id)
            before = set(_images(catalog, previous).values())
            for finding_id, scan, image in candidates:
                if scan == scan_run_id and image and now.get(image) in before:
                    disclosed.add(finding_id)
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
