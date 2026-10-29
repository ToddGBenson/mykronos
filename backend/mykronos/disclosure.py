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

**Tool images (#858).** Policy 1.12 leaves an image a compose file declares
`x-mykronos-role: tool` out of the score (#666), and the floor did not, so
renaming the ZAP scanner image refused `25cd28c` for 87 highs the estate had
carried, and mostly accepted, under its old name. The floor still takes no
policy, and a commit must not be able to lower it by declaring its own image
a tool. So a role counts only as the *previous* scan recorded it, which is
the role declared before this commit:

- a finding in an image the previous scan already recorded as a tool is not
  this commit's to answer for, however the image was rebuilt;
- a finding in a tool image the previous scan never saw is carried over when
  a tool image the previous scan saw is gone from this one and carried the
  same CVE on the same package. That is a rename, which re-keys every finding
  (`v3-package-image`) without adding any of them.

Declaring a service image a tool in the same commit clears nothing, because
the previous scan recorded it as a service. A new image declared a tool
clears only what a vanished tool image already carried.

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

#: The capability whose unchanged artefact is proven by a digest. `atlas` has
#: the same shape, but its artefact is a file in the repository, whose
#: unchanged-ness needs the commit's history - see `atlas_disclosed`.
CAPABILITY = "containers"

#: Dependency findings (TheHub #61063). The runner writes what the checkout
#: knows onto the raw record (`mykronos.atlas_baseline`), and this reads it.
ATLAS = "atlas"


class AtlasCandidate(NamedTuple):
    """One open atlas finding a commit's scans saw first."""

    finding_id: str
    scan: str
    #: `raw_finding_json.baseline_commits`: the ancestors whose copy of the
    #: finding's file already carried this package at this version. None when
    #: the runner could not tell.
    baseline_commits: tuple[str, ...] | None
    #: Whether `raw_finding_json.remediated_by` names a constraint in this
    #: commit's tree that moves the package to the fixed version.
    remediated: bool


def atlas_candidate(
    finding_id: str, scan: str, baseline: Any, remedy: Any
) -> AtlasCandidate:
    """An `AtlasCandidate` from the two raw JSON values the lake returns."""

    def parsed(value: Any) -> Any:
        if isinstance(value, str):
            try:
                return json.loads(value)
            except ValueError:
                return None
        return value

    commits = parsed(baseline)
    remediation = parsed(remedy)
    return AtlasCandidate(
        finding_id=str(finding_id),
        scan=str(scan),
        baseline_commits=(
            tuple(str(c) for c in commits) if isinstance(commits, list) else None
        ),
        remediated=isinstance(remediation, dict) and bool(remediation.get("file")),
    )


def atlas_disclosed(
    catalog: Any, candidates: list[AtlasCandidate]
) -> tuple[set[str], set[str]]:
    """(disclosed, remediated) finding ids among these atlas findings.

    **Newly disclosed** is a component the baseline already had: the commit of
    the previous scan of this repository is among the ancestors whose copy of
    the file carried the package at this version. The advisory moved, not the
    commit.

    **Remediated** is a finding read from an SBOM - a record of what runs -
    while this commit's own manifests move the package to the fixed version.
    TheHub's gate refused 09a6ca31 for three pypdf highs in the committed SBOM
    of the running backend, in the commit that pinned the fix. A commit is
    never charged for what it fixes, so a remediated finding is disclosed too.

    No previous scan, no recorded ancestry, a baseline further back than the
    runner walked: "introduced". Missing evidence never opens the gate.
    """
    disclosed: set[str] = set()
    remediated: set[str] = set()
    if not candidates:
        return disclosed, remediated
    try:
        repo = _repo_of(catalog, candidates[0].scan)
        baselines: dict[str, str | None] = {}
        for row in candidates:
            if row.remediated:
                remediated.add(row.finding_id)
                disclosed.add(row.finding_id)
                continue
            if not row.baseline_commits or repo is None:
                continue
            if row.scan not in baselines:
                baselines[row.scan] = _previous_commit(catalog, repo, row.scan)
            baseline = baselines[row.scan]
            # The runner writes full shas; a scan run may carry a short one.
            if baseline and len(baseline) >= 7 and any(
                commit.startswith(baseline) or baseline.startswith(commit)
                for commit in row.baseline_commits
                if len(commit) >= 7
            ):
                disclosed.add(row.finding_id)
    except Exception:  # noqa: BLE001 - no evidence means "introduced"
        logger.warning(
            "Could not compare atlas findings with their baseline; every "
            "candidate counts as introduced.",
            exc_info=True,
        )
        return set(), set()
    return disclosed, remediated


def _previous_commit(catalog: Any, repo_full_name: str, scan_run_id: str) -> str | None:
    """The commit of the previous successful scan, same capability, different
    commit - the baseline a dependency finding is compared with."""
    previous = _previous_scan(catalog, repo_full_name, scan_run_id)
    if previous is None:
        return None
    rows = catalog.query(
        "SELECT commit_sha FROM scan_runs WHERE scan_run_id = ? LIMIT 1", [previous]
    )
    return str(rows[0][0]) if rows and rows[0][0] else None


class Image(NamedTuple):
    """What one archived report says about the image it scanned."""

    image_id: str
    #: `properties.mykronosRole`, as `estate_images annotate-roles` stamped it
    #: for the commit that scan ran on. Empty means a service.
    role: str = ""


@lru_cache(maxsize=128)
def _report_image(path: str) -> tuple[str, Image] | None:
    """`(imageName, Image)` for one archived Trivy report, or None.

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
            str(run["properties"].get("mykronosRole") or "").strip(),
        )
        for run in runs
        if isinstance(run, dict) and isinstance(run.get("properties"), dict)
    }
    # One image per report, named and identified. Anything else cannot say
    # which image a result belongs to, so it says nothing.
    if len(pairs) != 1:
        return None
    ((name, image_id, role),) = pairs
    return (name, Image(image_id, role)) if name and image_id else None


def _images(catalog: Any, scan_run_id: str) -> dict[str, Image]:
    """imageName -> Image for every report one scan run archived."""
    # Imported here: `reprocess` pulls in the ingest path, and this module is
    # read by the dashboard queries.
    from mykronos.adapters.registry import get_adapter
    from mykronos.reprocess import _archives_for

    pattern = get_adapter(CAPABILITY, "trivy").pattern
    images: dict[str, Image] = {}
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
    that way in the same scan, or when the previous scan's roles make it a
    tool image's finding this commit did not add (see the module docstring).
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
            then = _images(catalog, previous)
            before = {image.image_id for image in then.values()}
            in_scan = [row for row in rows if row.scan == scan_run_id]
            unchanged = {
                row.finding_id
                for row in in_scan
                if row.image and row.image in now and now[row.image].image_id in before
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
            disclosed |= _tool_carry_over(catalog, repo, previous, now, then, in_scan)
    except Exception:  # noqa: BLE001 - no evidence means "introduced"
        logger.warning(
            "Could not compare container images for disclosure; every "
            "candidate counts as introduced.",
            exc_info=True,
        )
        return set()
    return disclosed


def _tool_carry_over(
    catalog: Any,
    repo: str | None,
    previous: str,
    now: dict[str, Image],
    then: dict[str, Image],
    rows: list[Candidate],
) -> set[str]:
    """Findings in tool images that this commit did not add (#858).

    Images are compared by repository, not by name: the repository's own
    images are tagged with the commit, so every build has a new name.
    """
    from mykronos.fingerprint import image_repository

    def tools(images: dict[str, Image]) -> set[str]:
        return {image_repository(name) for name, image in images.items() if image.role == "tool"}

    tools_now, tools_then = tools(now), tools(then)
    seen_then = {image_repository(name) for name in then}
    vanished = tools_then - {image_repository(name) for name in now}
    inherited = _carried_by(catalog, repo, previous, vanished) if vanished and repo else set()
    carried: set[str] = set()
    for row in rows:
        if not row.image:
            continue
        repository = image_repository(row.image)
        if repository not in tools_now:
            continue
        # Already a tool before this commit; or new, and the same CVE on the
        # same package as a tool image this commit removed (a rename).
        if repository in tools_then or (
            repository not in seen_then
            and row.rule_id
            and row.package
            and (row.rule_id, row.package) in inherited
        ):
            carried.add(row.finding_id)
    return carried


def _carried_by(
    catalog: Any, repo: str, scan_run_id: str, repositories: set[str]
) -> set[tuple[str, str]]:
    """(CVE, package) for every finding a scan last saw in these image
    repositories, whatever has been decided about it since.

    The package version is deliberately not compared. A renamed image is
    often rebuilt too, and a CVE that survived the upgrade is the same
    exposure on a newer version, not a new one.
    """
    from mykronos.fingerprint import image_repository

    rows = catalog.query(
        """
        SELECT json_extract_string(raw_finding_json, '$.image'), rule_id, package_name
        FROM findings
        WHERE asset_id = ? AND capability = ? AND last_seen_scan_run_id = ?
        """,
        [repo, CAPABILITY, scan_run_id],
    )
    return {
        (str(rule_id), str(package))
        for image, rule_id, package in rows
        if image and rule_id and package and image_repository(str(image)) in repositories
    }


def _repo_of(catalog: Any, scan_run_id: str) -> str | None:
    rows = catalog.query(
        "SELECT repo_full_name FROM scan_runs WHERE scan_run_id = ? LIMIT 1",
        [scan_run_id],
    )
    return str(rows[0][0]) if rows else None
