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
