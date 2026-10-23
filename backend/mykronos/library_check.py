"""The library-allowlist check on pull requests (TheHub #60898, epic #60880).

Decided by the operator: **report first, then block per repository**. Every
open pull request head on an onboarded repository gets a `library-allowlist`
check run listing each direct dependency the pull request adds or changes,
and its verdict against the allowlist (`libraries`):

- `approved` and within the entry's version policy, or `tolerated` (already
  in use, not yet vetted): passes;
- not on the allowlist, `approved` but outside its version policy, or
  `banned`: reported, each with a one-click link to request it.

In `report` mode, the default, anything reported makes the check `neutral`:
visible, never blocking. A person may switch a repository to `blocking` only
once its allowlist covers it - every library in its current SBOM has a
recorded `approved` or `tolerated` entry - and the check then concludes
`failure` on anything reported. Coverage is re-read on every check: a
blocking repository whose SBOM has since grown a library nobody recorded
runs in report mode, and the summary says why, rather than blocking on an
allowlist that has stopped describing it.

**What the check reads.** The manifests the pull request changes, at its
head and at its base branch, and the difference between them: `package.json`
dependency sections, `requirements*.txt`, `pyproject.toml` and `go.mod`.
Lockfiles are not read, so transitive changes are outside this check; the
summary says so.
"""

from __future__ import annotations

import json
import logging
import re
import tomllib
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

from sqlalchemy import select
from sqlalchemy.orm import Session

from mykronos import libraries
from mykronos.db.models import AuditLogEntry, LibraryCheck, LibraryRepoPolicy, RepoOnboarding
from mykronos.github import GitHubClient
from mykronos.github.factory import GitHubClientFactory
from mykronos.lake.catalog import Catalog
from mykronos.schemas import utcnow

logger = logging.getLogger(__name__)

CHECK_NAME = "library-allowlist"
MODES = ("report", "blocking")
PASSING = ("approved", "tolerated")

_NPM_SECTIONS = ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies")


@dataclass(frozen=True)
class DependencyChange:
    """One direct dependency a pull request adds or changes."""

    ecosystem: str
    name: str
    spec: str
    manifest: str
    #: added | changed
    change: str


def _manifest_kind(path: str) -> str | None:
    base = path.rsplit("/", 1)[-1]
    if base == "package.json":
        return "npm"
    if base == "pyproject.toml":
        return "pyproject"
    if re.fullmatch(r"requirements[\w.-]*\.txt", base):
        return "requirements"
    if base == "go.mod":
        return "golang"
    return None


_REQUIREMENT = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$")


def _requirement(line: str) -> tuple[str, str] | None:
    line = line.split("#", 1)[0].split(";", 1)[0].strip()
    if not line or line.startswith(("-", "git+", "http:", "https:")):
        return None
    match = _REQUIREMENT.match(line)
    if not match:
        return None
    return match.group(1), match.group(2).strip()


def parse_manifest(kind: str, text: str | None) -> dict[str, str]:
    """name -> version spec for the direct dependencies one manifest declares.

    A manifest that cannot be parsed raises ValueError, and the check reports
    that file as unreadable instead of passing it."""
    if not text:
        return {}
    deps: dict[str, str] = {}
    if kind == "npm":
        try:
            document = json.loads(text)
        except ValueError:
            raise ValueError("package.json is not valid JSON") from None
        for section in _NPM_SECTIONS:
            for name, spec in (document.get(section) or {}).items():
                deps[str(name)] = str(spec)
    elif kind == "requirements":
        for line in text.splitlines():
            parsed = _requirement(line)
            if parsed:
                deps[parsed[0]] = parsed[1]
    elif kind == "pyproject":
        try:
            document = tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            raise ValueError("pyproject.toml is not valid TOML") from None
        project = document.get("project") or {}
        lines = list(project.get("dependencies") or [])
        for extra in (project.get("optional-dependencies") or {}).values():
            lines.extend(extra or [])
        for line in lines:
            parsed = _requirement(str(line))
            if parsed:
                deps[parsed[0]] = parsed[1]
        poetry = ((document.get("tool") or {}).get("poetry") or {}).get("dependencies") or {}
        for name, spec in poetry.items():
            if name.lower() != "python":
                deps[str(name)] = spec if isinstance(spec, str) else str(spec.get("version", ""))
    elif kind == "golang":
        in_block = False
        for raw in text.splitlines():
            line = raw.split("//", 1)[0].strip()
            if line.startswith("require ("):
                in_block = True
                continue
            if in_block and line == ")":
                in_block = False
                continue
            if line.startswith("require "):
                line = line[len("require "):].strip()
            elif not in_block:
                continue
            parts = line.split()
            if len(parts) >= 2:
                deps[parts[0]] = parts[1]
    return deps


def diff_dependencies(
    kind: str, manifest: str, base: dict[str, str], head: dict[str, str]
) -> list[DependencyChange]:
    ecosystem = "pypi" if kind in ("requirements", "pyproject") else kind
    changes: list[DependencyChange] = []
    for name, spec in sorted(head.items()):
        if name not in base:
            changes.append(DependencyChange(ecosystem, name, spec, manifest, "added"))
        elif base[name] != spec:
            changes.append(DependencyChange(ecosystem, name, spec, manifest, "changed"))
    return changes


_MARKDOWN = re.compile(r"([\\`*_\[\]()<>|!#])")


def _md(text: str) -> str:
    """Manifest text as literal Markdown. Names and specs are the pull request
    author's, so unescaped they could forge a table cell or a link."""
    return _MARKDOWN.sub(r"\\\1", " ".join(str(text).split()))


def request_link(dashboard_url: str, change: DependencyChange) -> str:
    """The one-click request: the dashboard's request form, pre-filled."""
    query = urlencode(
        {
            "ecosystem": change.ecosystem,
            "name": change.name,
            "version": libraries.version_from_spec(change.spec),
        }
    )
    base = dashboard_url.rstrip("/")
    return f"{base}/libraries/request?{query}" if base else f"/libraries/request?{query}"


def verdict(
    change: DependencyChange, recorded: dict[tuple[str, str], Any]
) -> tuple[str, str]:
    """(verdict, why) for one dependency against the allowlist."""
    key = (change.ecosystem, libraries.normalise(change.ecosystem, change.name))
    entry = recorded.get(key)
    if entry is None:
        return "unapproved", "not on the allowlist"
    if entry.status == "banned":
        return "banned", "banned"
    if entry.status == "tolerated":
        return "tolerated", "in use already; tolerated, not vetted"
    version = libraries.version_from_spec(change.spec)
    if libraries.version_allowed(entry.version_policy, entry.version_ref, version):
        return "approved", f"approved ({entry.version_policy} {entry.version_ref})".strip()
    return (
        "outside_policy",
        f"approved, but {change.spec or 'this version'} is outside its "
        f"{entry.version_policy} {entry.version_ref} policy",
    )


def coverage(session: Session, catalog: Catalog, repo: str) -> tuple[int, list[str]]:
    """(libraries in the repository's SBOM, the ones with no recorded entry
    that passes). Empty `missing` with a positive total is covered."""
    recorded = libraries.entries(session)
    in_repo = [lib for lib in libraries.in_use(catalog) if repo in lib.repos]
    missing = [
        f"{lib.ecosystem}:{lib.package_name}"
        for lib in in_repo
        if (entry := recorded.get((lib.ecosystem, lib.package_name))) is None
        or entry.status not in PASSING
    ]
    return len(in_repo), missing


def repo_mode(session: Session, repo: str) -> str:
    row = session.execute(
        select(LibraryRepoPolicy).where(LibraryRepoPolicy.repo_full_name == repo)
    ).scalar_one_or_none()
    return row.mode if row else "report"


def set_mode(session: Session, catalog: Catalog, repo: str, mode: str, actor: str) -> str:
    """Switch a repository between report and blocking.

    Blocking is refused until the allowlist covers the repository, which is
    the operator's decision for the epic, and refused for a repository with
    no SBOM at all: nothing is known to be covered there."""
    if mode not in MODES:
        raise libraries.LibraryError(f"mode must be one of {', '.join(MODES)}.")
    if mode == "blocking":
        total, missing = coverage(session, catalog, repo)
        if total == 0:
            raise libraries.LibraryError(
                f"{repo} has no SBOM in the inventory, so nothing shows its dependencies "
                "are covered. It stays in report mode."
            )
        if missing:
            shown = ", ".join(missing[:10]) + (" ..." if len(missing) > 10 else "")
            raise libraries.LibraryError(
                f"{repo} is not covered: {len(missing)} of {total} libraries in use have no "
                f"approved or tolerated entry ({shown}). Record them first; POST "
                "/api/libraries/baseline records every unrecorded one as tolerated."
            )
    row = session.execute(
        select(LibraryRepoPolicy).where(LibraryRepoPolicy.repo_full_name == repo)
    ).scalar_one_or_none()
    previous = row.mode if row else "report"
    if row is None:
        row = LibraryRepoPolicy(repo_full_name=repo)
        session.add(row)
    row.mode = mode
    row.updated_by = actor
    session.add(
        AuditLogEntry(
            actor=actor,
            action="library_check.mode",
            entity_type="repository",
            entity_id=repo,
            detail={"from": previous, "to": mode},
        )
    )
    return mode


async def changes_for(
    github: GitHubClient, repo: str, number: int, head_sha: str, base_branch: str
) -> tuple[list[DependencyChange], list[str]]:
    """The dependency changes in a pull request, and manifests it could not read."""
    files = await github.pull_request_files(repo, number)
    changes: list[DependencyChange] = []
    unreadable: list[str] = []
    for item in files:
        kind = _manifest_kind(item.filename)
        if kind is None or item.status == "removed":
            continue
        try:
            head = parse_manifest(kind, await github.get_file(repo, item.filename, head_sha))
            base_path = item.previous_filename or item.filename
            base = (
                {}
                if item.status == "added"
                else parse_manifest(kind, await github.get_file(repo, base_path, base_branch))
            )
        except ValueError as exc:
            unreadable.append(f"{item.filename}: {exc}")
            continue
        changes.extend(diff_dependencies(kind, item.filename, base, head))
    return changes, unreadable


def evaluate(
    session: Session,
    catalog: Catalog,
    repo: str,
    changes: list[DependencyChange],
    unreadable: list[str],
    *,
    dashboard_url: str = "",
) -> dict[str, Any]:
    """The check's verdict: mode, conclusion, title, summary and per-row results."""
    recorded = libraries.entries(session)
    configured = repo_mode(session, repo)
    mode = configured
    lapsed: list[str] = []
    if configured == "blocking":
        total, lapsed = coverage(session, catalog, repo)
        if lapsed or total == 0:
            mode = "report"
    results: list[dict[str, Any]] = []
    for change in changes:
        outcome, why = verdict(change, recorded)
        results.append(
            {
                "ecosystem": change.ecosystem,
                "name": change.name,
                "spec": change.spec,
                "manifest": change.manifest,
                "change": change.change,
                "verdict": outcome,
                "why": why,
                "request_url": (
                    request_link(dashboard_url, change) if outcome not in PASSING else ""
                ),
            }
        )
    reported = [r for r in results if r["verdict"] not in PASSING]
    problems = bool(reported or unreadable)
    if not problems:
        conclusion = "success"
    elif mode == "blocking":
        conclusion = "failure"
    else:
        conclusion = "neutral"
    if not changes and not unreadable:
        title = "No dependency changes"
    elif problems:
        title = f"{len(reported)} dependenc{'y' if len(reported) == 1 else 'ies'} not allowed"
        if unreadable:
            title += f", {len(unreadable)} manifest(s) unreadable"
    else:
        title = f"{len(results)} dependency change(s), all allowed"

    lines = [f"Mode: **{mode}**."]
    if configured == "blocking" and mode == "report":
        lines.append(
            f"This repository is set to blocking, but its allowlist no longer covers "
            f"its dependencies ({len(lapsed)} unrecorded), so this check only reports."
        )
    if results:
        lines += ["", "| Dependency | Manifest | Verdict | |", "|---|---|---|---|"]
        for r in results:
            link = f"[request it]({r['request_url']})" if r["request_url"] else ""
            lines.append(
                f"| {_md(r['name'])} {_md(r['spec'])} ({r['change']}) | {_md(r['manifest'])} "
                f"| {r['verdict']}: {_md(r['why'])} | {link} |"
            )
    for item in unreadable:
        lines.append(f"- Could not read {_md(item)}")
    lines += [
        "",
        "Reads direct dependencies in package.json, requirements*.txt, pyproject.toml and "
        "go.mod. Lockfiles and transitive dependencies are not checked.",
    ]
    return {
        "mode": mode,
        "conclusion": conclusion,
        "title": title,
        "summary": "\n".join(lines),
        "results": results,
    }


async def check_pull_request(
    db: Any,
    catalog: Catalog,
    github: GitHubClient,
    *,
    repo: str,
    number: int,
    dashboard_url: str = "",
) -> LibraryCheck:
    """Run and post the check for one pull request's current head."""
    pr = await github.get_pull_request(repo, number)
    if pr is None or not pr.head_sha:
        raise libraries.LibraryError(f"{repo}#{number} is not an open pull request.")
    base = pr.base_branch or str((await github.get_repo(repo)).get("default_branch") or "main")
    changes, unreadable = await changes_for(github, repo, number, pr.head_sha, base)
    with db.session() as session:
        outcome = evaluate(
            session, catalog, repo, changes, unreadable, dashboard_url=dashboard_url
        )
    check = LibraryCheck(
        repo_full_name=repo,
        number=number,
        head_sha=pr.head_sha,
        mode=outcome["mode"],
        conclusion=outcome["conclusion"],
        results=outcome["results"],
        created_at=utcnow(),
    )
    try:
        check.external_id = await github.create_check_run(
            repo,
            name=CHECK_NAME,
            head_sha=pr.head_sha,
            conclusion=outcome["conclusion"],
            title=outcome["title"],
            summary=outcome["summary"],
        )
    except Exception as exc:  # noqa: BLE001 - recorded; the sweep retries it
        check.error = f"{type(exc).__name__}: {exc}"[:2000]
        logger.warning("Could not post %s on %s#%s: %s", CHECK_NAME, repo, number, exc)
    with db.session() as session:
        existing = session.execute(
            select(LibraryCheck).where(
                LibraryCheck.repo_full_name == repo, LibraryCheck.head_sha == pr.head_sha
            )
        ).scalar_one_or_none()
        if existing is not None:
            session.delete(existing)
            session.flush()
        session.add(check)
        db.audit(
            session,
            actor="platform",
            action="library_check.posted" if check.error is None else "library_check.failed",
            entity_type="pull_request",
            entity_id=f"{repo}#{number}@{pr.head_sha}",
            mode=check.mode,
            conclusion=check.conclusion,
            error=check.error,
        )
        session.flush()
        session.expunge(check)
    return check


async def sweep(
    db: Any, catalog: Catalog, github_factory: GitHubClientFactory, *, dashboard_url: str = ""
) -> list[str]:
    """The job: every open, non-draft pull request head with no posted check."""
    with db.session() as session:
        repos = [
            (r.github_repo_full_name, r.github_installation_id)
            for r in session.execute(
                select(RepoOnboarding).where(RepoOnboarding.status != "removed")
            ).scalars()
        ]
        done = {
            (c.repo_full_name, c.head_sha)
            for c in session.execute(
                select(LibraryCheck).where(LibraryCheck.error.is_(None))
            ).scalars()
        }
    posted: list[str] = []
    for repo, installation in repos:
        if installation is None:
            continue
        github = github_factory.for_installation(installation)
        try:
            pulls = await github.list_open_pull_requests(repo)
        except Exception as exc:  # noqa: BLE001 - one repository never stops the rest
            logger.warning("Could not list pull requests for %s: %s", repo, exc)
            continue
        for pr in pulls:
            if not pr.head_sha or pr.draft or (repo, pr.head_sha) in done:
                continue
            try:
                check = await check_pull_request(
                    db, catalog, github, repo=repo, number=pr.number, dashboard_url=dashboard_url
                )
            except Exception as exc:  # noqa: BLE001 - one pull request never stops the rest
                logger.warning("Library check failed for %s#%s: %s", repo, pr.number, exc)
                continue
            if check.error is None:
                posted.append(f"{repo}#{pr.number}")
    return posted
