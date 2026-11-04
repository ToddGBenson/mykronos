"""The Ctrl+K jump box: go to a repo, a finding, a CVE or a page (TheHub #60976).

A navigation aid, not a search engine. It answers "where is the thing I can
name" in four shapes and stops:

* **repo** - an onboarded repository whose name contains the text.
* **finding** - a finding whose id starts with the text, the way a person
  pastes the first eight characters of one from a log or a story.
* **cve** - an exact CVE id: one result per repository with an open finding
  that cites it, or, when none does, the incident lookup for it. No affected
  repository is not "not affected" (spec 29 §2), so the box does not say so;
  it sends the reader to the page that names what could not be checked.
* **page** - the dashboard's own routes, from a static list.

**The text is never SQL.** This box sits on an internet-exposed dashboard, so
whatever is typed reaches the lake only as a bound parameter, and only through
functions with no wildcard syntax (`starts_with`, `=`). Repository and page
matching happens in Python against rows already read. A `%`, a quote or a
fragment of a statement matches what contains it literally, which is nothing.

**The answer is capped.** At most `MAX_LIMIT` results, whatever is asked for.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import asdict, dataclass
from typing import Any, Literal
from urllib.parse import quote, urlencode

from sqlalchemy.orm import Session

from mykronos.db.models import RepoOnboarding
from mykronos.lake.catalog import Catalog

Kind = Literal["repo", "finding", "cve", "page"]

#: Shorter than this is not a question; one character matches half the estate.
MIN_QUERY = 2
MAX_QUERY = 200
DEFAULT_LIMIT = 20
#: The ceiling, whatever `limit` asks for.
MAX_LIMIT = 50

_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

#: The dashboard's pages, as the nav rail names them (`frontend/lib/nav.ts`)
#: plus the pages it reaches only through another one. `keywords` are the
#: other words a person types for the same place.
PAGES: tuple[tuple[str, str, str], ...] = (
    ("Approvals", "/approvals", "pending decisions review"),
    ("Portfolio", "/", "home repositories estate"),
    ("Risk", "/risk", "products health gate"),
    ("Triage queue", "/triage", "findings worklist"),
    ("Vulnerability management", "/vulnerability-management", "backlog outstanding"),
    ("Remediate today", "/remediate", "remediation fixes library"),
    ("Product Owner", "/product-owner", "stories sprint backlog"),
    ("Pull requests", "/pull-requests", "open prs"),
    ("Risk policy", "/risk-policy", "decisions scoring oracle"),
    ("MyKronos Health", "/platform-health", "platform jobs lanes"),
    ("Agents", "/agents", "credentials delegations"),
    ("Briefing", "/briefing", "daily overnight"),
    ("Weekly intelligence", "/briefing/weekly", "monday"),
    ("Threat intelligence", "/threat-intel", "kev epss"),
    ("Incident lookup", "/incident", "cve package purl affected"),
    ("Libraries", "/libraries", "packages dependencies"),
    ("Request a library", "/libraries/request", "new dependency"),
    ("Trends", "/trends", "maturity throughput"),
    ("Retros", "/retro", "knowledge retrospective"),
    ("Today", "/today", "run sheet"),
)


class QueryError(ValueError):
    """The text cannot be searched; the message says why."""


@dataclass(frozen=True)
class Result:
    kind: Kind
    title: str
    subtitle: str
    href: str


def clean(query: str) -> str:
    """The text as searched: control characters dropped, trimmed, checked.

    Control characters go first so that `"a\\x00"` is judged as the one
    character it is, not as two.
    """
    text = "".join(ch for ch in query if unicodedata.category(ch)[0] != "C").strip()
    if len(text) < MIN_QUERY:
        raise QueryError(f"Type at least {MIN_QUERY} characters.")
    if len(text) > MAX_QUERY:
        raise QueryError(f"At most {MAX_QUERY} characters.")
    return text


def clamp(limit: int) -> int:
    return max(1, min(limit, MAX_LIMIT))


def _onboarded(session: Session) -> dict[str, str]:
    """owner/repo -> onboarding id, for every repository not removed."""
    return {
        row.github_repo_full_name: str(row.id)
        for row in session.query(RepoOnboarding).filter(RepoOnboarding.status != "removed")
    }


def _worst(severities: list[str]) -> str:
    return min(severities, key=lambda s: _SEVERITY_RANK.get(s, 9), default="")


def _cves(catalog: Catalog, cve_id: str, repos: dict[str, str]) -> list[Result]:
    rows: list[tuple[Any, ...]] = []
    if catalog.all_files("findings"):
        rows = catalog.query(
            """
            SELECT asset_id, lower(severity), count(*)
            FROM findings
            WHERE status = 'open' AND upper(rule_id) = ?
            GROUP BY 1, 2
            """,
            [cve_id],
        )
    per_repo: dict[str, tuple[int, list[str]]] = {}
    for asset, severity, count in rows:
        total, severities = per_repo.get(str(asset), (0, []))
        per_repo[str(asset)] = (total + int(count), [*severities, str(severity or "")])

    results = []
    for asset in sorted(
        per_repo,
        key=lambda a: (_SEVERITY_RANK.get(_worst(per_repo[a][1]), 9), -per_repo[a][0], a),
    ):
        repo_id = repos.get(asset)
        if not repo_id:
            continue
        total, severities = per_repo[asset]
        noun = "finding" if total == 1 else "findings"
        results.append(
            Result(
                kind="cve",
                title=cve_id,
                subtitle=f"{asset} · {total} open {noun} · {_worst(severities) or 'unrated'}",
                href=f"/repos/{quote(repo_id)}?"
                + urlencode({"tab": "findings", "rule_id": cve_id}),
            )
        )
    if not results:
        results.append(
            Result(
                kind="cve",
                title=cve_id,
                subtitle="No open finding cites it. Look it up across every repository.",
                href="/incident?" + urlencode({"q": cve_id}),
            )
        )
    return results


def _findings(
    catalog: Catalog, prefix: str, repos: dict[str, str], limit: int
) -> list[Result]:
    if not catalog.all_files("findings"):
        return []
    rows = catalog.query(
        """
        SELECT finding_id, asset_id, lower(severity), status, title
        FROM findings
        WHERE starts_with(lower(finding_id), ?)
        ORDER BY finding_id
        LIMIT ?
        """,
        [prefix.lower(), limit],
    )
    results = []
    for finding_id, asset, severity, finding_status, title in rows:
        repo_id = repos.get(str(asset))
        if not repo_id:
            continue
        results.append(
            Result(
                kind="finding",
                title=str(title or finding_id),
                subtitle=f"{asset} · {severity or 'unrated'} · {finding_status} · "
                f"{str(finding_id)[:12]}",
                href=f"/repos/{quote(repo_id)}/findings/{quote(str(finding_id))}",
            )
        )
    return results


def _repos(text: str, repos: dict[str, str]) -> list[Result]:
    needle = text.lower()
    names = sorted(
        (name for name in repos if needle in name.lower()),
        # A name that starts with the text, or whose repo half does, first.
        key=lambda n: (
            not n.lower().startswith(needle),
            not n.lower().split("/")[-1].startswith(needle),
            n.lower(),
        ),
    )
    return [
        Result(kind="repo", title=name, subtitle="Repository", href=f"/repos/{quote(repos[name])}")
        for name in names
    ]


def _pages(text: str) -> list[Result]:
    needle = text.lower()
    hits = [
        (title, href)
        for title, href, keywords in PAGES
        if needle in title.lower() or needle in keywords or (len(href) > 1 and needle in href)
    ]
    hits.sort(key=lambda hit: (not hit[0].lower().startswith(needle), hit[0].lower()))
    return [Result(kind="page", title=title, subtitle=href, href=href) for title, href in hits]


def search(catalog: Catalog, session: Session, query: str, limit: int) -> list[Result]:
    """Everything the text names, most specific first, at most `limit`."""
    text = clean(query)
    limit = clamp(limit)
    repos = _onboarded(session)

    results: list[Result] = []
    if _CVE.match(text):
        results.extend(_cves(catalog, text.upper(), repos))
    results.extend(_findings(catalog, text, repos, limit))
    results.extend(_repos(text, repos))
    results.extend(_pages(text))
    return results[:limit]


def as_dicts(results: list[Result]) -> list[dict[str, Any]]:
    return [asdict(result) for result in results]
