"""What an atlas finding was read out of, and how old that is (TheHub #60921).

osv-scanner reads two very different kinds of file and reports both the same
way. A **manifest** -- `requirements.txt`, a lockfile, `package.json` -- is
this commit's own statement of its dependencies. A **committed SBOM document**
-- a CycloneDX or SPDX file somebody generated once and checked in -- is a
statement about whatever it was generated from, on the day it was generated,
and nothing keeps it current.

Observed 2026-10-29: TheHub's open critical PYSEC-2026-4320 (certifi) was
located at `docs/sbom/latest-python.cdx.json`, whose `metadata.timestamp` was
2026-10-21 and which listed certifi 2026.10.18. `backend/requirements.txt` had
changed at least twice since and pinned `certifi>=2026.10.19`. The finding
was right only because production happened to run the same old version, and
nothing on it told a reader whether it described the manifest, a stale
document, or what runs.

So every osv finding records `source_kind` (`manifest`, `sbom_document` or
`other`), and one read out of an SBOM document also records
`source_document`: the document's own date, its age when scanned, and whether
any manifest of the same ecosystem was committed after it. Both live on the
raw record -- facts the runner establishes from the checkout, read back by the
platform -- and neither touches severity or identity.
"""

from __future__ import annotations

import json
import logging
import subprocess
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from mykronos.adapters.base import ScanContext
from mykronos.schemas import FindingSubmission

logger = logging.getLogger(__name__)

SourceKind = Literal["manifest", "sbom_document", "other"]

_SBOM_SUFFIXES = (".cdx.json", ".spdx.json")
_SBOM_NAMES = frozenset({"bom.json", "sbom.json"})

#: The files that declare or resolve each ecosystem's dependencies. A change
#: to any of them after an SBOM document's date means the document may no
#: longer describe this commit.
_ECOSYSTEM_FILES: dict[str, frozenset[str]] = {
    "pypi": frozenset(
        {
            "pyproject.toml",
            "setup.py",
            "setup.cfg",
            "pipfile",
            "pipfile.lock",
            "poetry.lock",
            "pdm.lock",
            "uv.lock",
        }
    ),
    "npm": frozenset({"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"}),
    "golang": frozenset({"go.mod", "go.sum"}),
    "cargo": frozenset({"cargo.toml", "cargo.lock"}),
    "gem": frozenset({"gemfile", "gemfile.lock"}),
    "composer": frozenset({"composer.json", "composer.lock"}),
    "maven": frozenset({"pom.xml", "build.gradle"}),
    "nuget": frozenset({"packages.lock.json"}),
}
_ALL_MANIFESTS = frozenset().union(*_ECOSYSTEM_FILES.values())


def _name(file_path: str) -> str:
    return PurePosixPath(file_path.replace("\\", "/")).name.lower()


def _is_requirements(name: str) -> bool:
    return name.startswith("requirements") and name.endswith(".txt")


def is_sbom(file_path: str) -> bool:
    name = _name(file_path)
    return name in _SBOM_NAMES or name.endswith(_SBOM_SUFFIXES)


def source_kind(file_path: str | None) -> SourceKind:
    """`sbom_document`, `manifest`, or `other` -- read from the file's name,
    which is also how osv-scanner itself decides how to parse it."""
    if not file_path:
        return "other"
    if is_sbom(file_path):
        return "sbom_document"
    name = _name(file_path)
    if name in _ALL_MANIFESTS or _is_requirements(name):
        return "manifest"
    return "other"


def _is_manifest_for(path: str, ecosystems: set[str]) -> bool:
    name = _name(path)
    if is_sbom(path):
        return False
    if not ecosystems:
        return name in _ALL_MANIFESTS or _is_requirements(name)
    if "pypi" in ecosystems and _is_requirements(name):
        return True
    return any(name in _ECOSYSTEM_FILES.get(e, frozenset()) for e in ecosystems)


# -- The document ------------------------------------------------------------


def _timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _walk(components: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for component in components if isinstance(components, list) else []:
        if isinstance(component, dict):
            out.append(component)
            out.extend(_walk(component.get("components")))
    return out


def _purl_type(purl: Any) -> str | None:
    text = str(purl or "")
    if not text.startswith("pkg:") or "/" not in text:
        return None
    return text[4:].split("/", 1)[0].lower() or None


def describe_document(document: Any) -> tuple[str | None, datetime | None, set[str]]:
    """(format, the document's own creation time, the ecosystems it lists).

    CycloneDX dates itself in `metadata.timestamp`, SPDX in
    `creationInfo.created`. Either may be absent, and an absent date is
    recorded as unknown rather than guessed from the file's commit.
    """
    if not isinstance(document, dict):
        return None, None, set()
    ecosystems: set[str] = set()
    if "spdxVersion" in document:
        for package in document.get("packages") or []:
            if not isinstance(package, dict):
                continue
            for ref in package.get("externalRefs") or []:
                if isinstance(ref, dict) and (kind := _purl_type(ref.get("referenceLocator"))):
                    ecosystems.add(kind)
        info = document.get("creationInfo")
        created = _timestamp(info.get("created")) if isinstance(info, dict) else None
        return "spdx", created, ecosystems
    for component in _walk(document.get("components")):
        if kind := _purl_type(component.get("purl")):
            ecosystems.add(kind)
    metadata = document.get("metadata")
    created = _timestamp(metadata.get("timestamp")) if isinstance(metadata, dict) else None
    fmt = "cyclonedx" if str(document.get("bomFormat") or "").lower() == "cyclonedx" else None
    return fmt, created, ecosystems


# -- The checkout ------------------------------------------------------------


def _git(workspace: Path, *args: str) -> str | None:
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            ["git", "-C", str(workspace), *args],  # noqa: S607
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return completed.stdout if completed.returncode == 0 else None


def manifest_changes(
    workspace: Path, since: datetime, ecosystems: set[str]
) -> tuple[bool | None, list[dict[str, str]]]:
    """Whether any manifest of these ecosystems was committed after `since`.

    Returns (answer, the newest such commit per manifest). `None` is "could
    not tell": no git, no manifest to compare with, or a shallow clone whose
    history stops after the document's date and shows no change -- a change
    older than the clone is invisible, and "unchanged" would be a claim.
    """
    listing = _git(workspace, "ls-files", "-z")
    if listing is None:
        return None, []
    manifests = [p for p in listing.split("\0") if p and _is_manifest_for(p, ecosystems)]
    if not manifests:
        return None, []
    log = _git(
        workspace,
        "log",
        "--format=%x01%H %cI",
        "--name-only",
        # Paths relative to the workspace, as ls-files and the finding name
        # them, rather than to the repository root.
        "--relative",
        f"--since={since.isoformat()}",
        "HEAD",
        "--",
        *manifests,
    )
    if log is None:
        return None, []
    newest: dict[str, dict[str, str]] = {}
    commit, committed = "", None
    for line in log.splitlines():
        if line.startswith("\x01"):
            sha, _, stamp = line[1:].partition(" ")
            commit, committed = sha, _timestamp(stamp)
            continue
        path = line.strip()
        if not path or committed is None or committed <= since or path in newest:
            continue
        newest[path] = {
            "file": path,
            "commit": commit,
            "committed_at": committed.astimezone(UTC).isoformat(),
        }
    if newest:
        return True, sorted(newest.values(), key=lambda c: c["file"])
    shallow = _git(workspace, "rev-parse", "--is-shallow-repository")
    if shallow is None or shallow.strip() == "true":
        return None, []
    return False, []


def document_facts(
    workspace: Path, file_path: str, now: datetime
) -> dict[str, Any] | None:
    """`source_document` for one committed SBOM document, or None when the
    file cannot be read from the checkout."""
    path = workspace / file_path
    try:
        document = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None
    fmt, created, ecosystems = describe_document(document)
    facts: dict[str, Any] = {
        "path": file_path,
        "format": fmt,
        "created_at": created.astimezone(UTC).isoformat() if created else None,
        "scanned_at": now.astimezone(UTC).isoformat(),
        "age_days": None,
        "manifests_changed_after": None,
        "manifests_changed": [],
    }
    if created is None:
        return facts
    facts["age_days"] = max(0, (now - created).days)
    changed, changes = manifest_changes(workspace, created, ecosystems)
    facts["manifests_changed_after"] = changed
    facts["manifests_changed"] = changes
    return facts


def _now() -> datetime:
    return datetime.now(UTC)


def annotate(
    findings: list[FindingSubmission], context: ScanContext, *, now: datetime | None = None
) -> None:
    """Write `source_kind` on every finding, and `source_document` on those
    read out of a committed SBOM document. Best effort: what cannot be read
    from the checkout is left absent, never guessed."""
    when = now or _now()
    documents: dict[str, dict[str, Any] | None] = {}
    for finding in findings:
        kind = source_kind(finding.file_path)
        finding.raw_finding_json["source_kind"] = kind
        if kind != "sbom_document" or context.workspace is None or not finding.file_path:
            continue
        if finding.file_path not in documents:
            try:
                documents[finding.file_path] = document_facts(
                    context.workspace, finding.file_path, when
                )
            except Exception:  # noqa: BLE001 - a missing fact is absent, not fatal
                logger.warning(
                    "Could not date the SBOM document %s.", finding.file_path, exc_info=True
                )
                documents[finding.file_path] = None
        facts = documents[finding.file_path]
        if facts is not None:
            finding.raw_finding_json["source_document"] = dict(facts)


# -- Reading it back ---------------------------------------------------------


def _as_dict(value: Any) -> dict[str, Any] | None:
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value:
        try:
            parsed = json.loads(value)
        except ValueError:
            return None
        return parsed if isinstance(parsed, dict) else None
    return None


def note(kind: Any, document: Any) -> str | None:
    """One sentence for a finding read out of a committed SBOM document.

    None for anything else: a manifest finding already says what it is, and
    this exists to stop an SBOM's age going unsaid. Takes the two raw fields
    rather than the whole record so a surface that may not send raw output
    to its reader can still say it.
    """
    if kind != "sbom_document":
        return None
    facts = _as_dict(document) or {}
    created = str(facts.get("created_at") or "")[:10]
    if not created:
        return (
            "From a committed SBOM document with no recorded date, not from this "
            "commit's manifest. Check what runs before acting on it."
        )
    details: list[str] = []
    age = facts.get("age_days")
    if isinstance(age, int):
        details.append(
            "the day of this scan"
            if age == 0
            else f"{age} day{'s' if age != 1 else ''} before this scan"
        )
    changed = facts.get("manifests_changed_after")
    files = [
        str(c.get("file"))
        for c in facts.get("manifests_changed") or []
        if isinstance(c, dict) and c.get("file")
    ]
    if changed is True:
        if len(files) == 1:
            details.append(f"{files[0]} has changed since")
        else:
            details.append(f"{len(files) or 'the'} manifests have changed since")
    elif changed is False:
        details.append("no manifest has changed since")
    suffix = f" ({'; '.join(details)})" if details else ""
    return (
        f"From a committed SBOM document dated {created}{suffix}, not from this "
        "commit's manifest. Check what runs before acting on it."
    )


def note_for(raw: Any) -> str | None:
    """`note` read off a finding's whole raw record."""
    record = _as_dict(raw) or {}
    return note(record.get("source_kind"), record.get("source_document"))


#: What a surface renders when `stale` is True.
STALE_SOURCE = "stale-source"


def stale(kind: Any, document: Any) -> bool | None:
    """The stale-source flag: True when a manifest of the document's ecosystem
    was committed after the document's own date.

    None for anything that is not an SBOM document, and for a document whose
    staleness could not be told (undated, no git, a shallow clone). "Could not
    tell" is not "current", so it is never False.
    """
    if kind != "sbom_document":
        return None
    changed = (_as_dict(document) or {}).get("manifests_changed_after")
    return changed if isinstance(changed, bool) else None


# -- What runs, beside it ----------------------------------------------------
#
# A document's version is a claim about whatever it was generated from. The
# platform sometimes holds a better one: the deployment probe's revision
# (`mykronos.deployments`), or a container scan of an image that names the
# same package. Either, when present, is served beside the finding. Neither
# is folded into severity, and neither is invented when absent.

#: At most this many images are listed. A repository builds a handful.
_MAX_IMAGES = 5


def _short(sha: str) -> str:
    return sha[:7]


# git's default abbreviation. A shorter revision prefix-matches too many
# commits to say that this one is what runs.
_MIN_SHA_PREFIX = 7


def _same_commit(a: str, b: str) -> bool:
    a, b = a.strip().lower(), b.strip().lower()
    if min(len(a), len(b)) < _MIN_SHA_PREFIX:
        return False
    return a.startswith(b) or b.startswith(a)


def _when(value: Any) -> str:
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M UTC")
    return str(value or "")[:16].replace("T", " ")


def _lag_phrase(lag: Any, revision: str) -> str:
    """How far the deployment is behind its branch, from the sweep's stored
    answer -- and only when that answer is about this same revision."""
    data = lag if isinstance(lag, dict) else {}
    if not _same_commit(str(data.get("deployed_revision") or ""), revision):
        return ""
    branch = str(data.get("branch") or "its branch")
    status = str(data.get("status") or "")
    behind = data.get("behind_by")
    if status == "behind" and isinstance(behind, int) and behind > 0:
        return f"{behind} commit{'s' if behind != 1 else ''} behind {branch}"
    if status == "at_head":
        return f"at the head of {branch}"
    if status == "diverged":
        return f"diverged from {branch}"
    return ""


def deployment_observation(onboarding: Any, scanned_commit: str | None) -> dict[str, Any] | None:
    """What the deployment probe last read, when it read one.

    Only a probe whose last sweep answered (`ok`): a revision left over from
    an earlier sweep is what *was* running, and presenting it as what runs is
    the confident wrong answer `mykronos.deployments` exists to prevent.
    """
    if onboarding is None or getattr(onboarding, "deployment_probe_status", "") != "ok":
        return None
    revision = str(getattr(onboarding, "deployed_revision", "") or "").strip()
    if not revision:
        return None
    observed_at = getattr(onboarding, "deployed_revision_at", None)
    matches = _same_commit(revision, scanned_commit) if scanned_commit else None
    details = [f"probe read {_when(observed_at)}"] if observed_at else []
    if lag := _lag_phrase(getattr(onboarding, "deployment_lag", None), revision):
        details.append(lag)
    suffix = f" ({'; '.join(details)})" if details else ""
    if matches is True:
        scan = "the commit this finding was scanned at"
    elif matches is False and scanned_commit:
        scan = f"not {_short(scanned_commit)}, the commit this finding was scanned at"
    else:
        scan = "the scanned commit is not recorded"
    return {
        "kind": "deployment_probe",
        "summary": f"The deployment runs {_short(revision)}{suffix}: {scan}.",
        "observed_at": observed_at,
        "revision": revision,
        "matches_scan": matches,
        "image": None,
        "package_version": None,
        "status": None,
    }


def _scanned_commit(catalog: Any, finding_id: str) -> str | None:
    if not catalog.all_files("scan_runs"):
        return None
    rows = catalog.query(
        "SELECT s.commit_sha FROM findings f "
        "JOIN scan_runs s ON s.scan_run_id = f.last_seen_scan_run_id "
        "WHERE f.finding_id = ? LIMIT 1",
        [finding_id],
    )
    return str(rows[0][0]) if rows and rows[0][0] else None


def image_observations(
    catalog: Any, repo_full_name: str, package_name: str | None
) -> list[dict[str, Any]]:
    """Container scans of this repository's images that name the package.

    The newest report per image. A container lane scans the image in the
    registry, which is not proof of the image that runs, and the sentence
    says so.
    """
    if not package_name or not catalog.all_files("findings"):
        return []
    rows = catalog.query(
        "SELECT json_extract_string(raw_finding_json, '$.image') AS image, "
        "package_version, status, last_seen_at FROM findings "
        "WHERE capability = 'containers' AND repo_full_name = ? "
        "AND lower(package_name) = lower(?) "
        "ORDER BY last_seen_at DESC",
        [repo_full_name, package_name],
    )
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for image, version, status, last_seen in rows:
        name = str(image or "").strip()
        if not name or name in seen:
            continue
        seen.add(name)
        when = f", last seen {_when(last_seen)[:10]}" if last_seen else ""
        out.append(
            {
                "kind": "image_scan",
                "summary": (
                    f"A container scan of {name} in the registry reported "
                    f"{package_name} {version or '(version unreported)'} "
                    f"({status or 'unknown'}{when}). That is the registry's "
                    "image, not necessarily the one running."
                ),
                "observed_at": last_seen,
                "revision": None,
                "matches_scan": None,
                "image": name,
                "package_version": str(version) if version else None,
                "status": str(status) if status else None,
            }
        )
        if len(out) >= _MAX_IMAGES:
            break
    return out


def observations(catalog: Any, onboarding: Any, row: dict[str, Any]) -> list[dict[str, Any]]:
    """Everything observed about what runs, for a finding read out of a
    committed SBOM document. Empty for any other finding, and when nothing
    was observed."""
    if row.get("source_kind") != "sbom_document":
        return []
    finding_id = str(row.get("finding_id") or "")
    out: list[dict[str, Any]] = []
    probe = deployment_observation(onboarding, _scanned_commit(catalog, finding_id))
    if probe is not None:
        out.append(probe)
    out.extend(
        image_observations(
            catalog, str(row.get("repo_full_name") or ""), row.get("package_name")
        )
    )
    return out
