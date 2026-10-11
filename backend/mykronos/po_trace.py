"""The delivery trace for one story: story -> commits -> pull requests -> scans
-> deploys (spec 35 §8.5, D-139).

The other direction from Delivery. Delivery lists commits; this opens one
story and shows the chain that delivered it, with the first missing link
named.

**A commit is the story's only when its `Stories:` trailer names it.** Prose
that mentions `#id` (a commit explaining why a story was *not* done, say) is
counted as a mention and never shown as delivery. TheHub's own attribution
falls back to a loose `#id` scan for commits with no trailer, which is why the
commits are read from GitHub and parsed here rather than taken from TheHub's
deploy list.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from mykronos import po_console as pc

#: A `Stories:` trailer line. Case-insensitive on the key, as git trailers
#: are; anchored to a line of its own, so prose saying "Stories: none of
#: these" mid-sentence is not one.
_TRAILER = re.compile(r"(?im)^stories:[ \t]*(.*?)[ \t]*$")
_REF = re.compile(r"#(\d+)\b")
#: GitHub's squash-merge subject suffix: `title (#123)`.
_PR_SUFFIX = re.compile(r"\(#(\d+)\)\s*$")

#: Deploy statuses that mean it went out. `warned` went out with a warning.
DEPLOYED = ("success", "succeeded", "warned", "ok")


def trailer_ids(message: str) -> list[int] | None:
    """The story ids a commit's `Stories:` trailer credits, in order; None
    when the commit has no trailer at all."""
    lines = _TRAILER.findall(message or "")
    if not lines:
        return None
    seen: list[int] = []
    for line in lines:
        for ref in _REF.findall(line):
            if int(ref) not in seen:
                seen.append(int(ref))
    return seen


def credits(message: str, story_id: int) -> bool:
    ids = trailer_ids(message)
    return ids is not None and story_id in ids


def mentions(message: str, story_id: int) -> bool:
    return re.search(rf"#{story_id}\b", message or "") is not None


def subject(message: str) -> str:
    return (message or "").split("\n", 1)[0].strip()


def subject_pr(message: str) -> int | None:
    match = _PR_SUFFIX.search(subject(message))
    return int(match.group(1)) if match else None


@dataclass
class TraceCommit:
    sha: str
    url: str
    subject: str
    committed_at: str | None
    prs: list[dict[str, Any]] = field(default_factory=list)
    scans: list[dict[str, Any]] = field(default_factory=list)
    deploys: list[dict[str, Any]] = field(default_factory=list)
    #: The probe says this commit is running now.
    running: bool = False
    missing: str | None = None


MISSING = {
    "commit": "no commit names this story",
    "pr": "committed, no pull request recorded",
    "scan": "committed, never scanned",
    "deploy": "scanned, never deployed",
}


def _first_missing(has: dict[str, bool]) -> str | None:
    for link in ("commit", "pr", "scan", "deploy"):
        if not has[link]:
            return MISSING[link]
    return None


def build_trace(
    story: dict[str, Any],
    repo_full_name: str,
    commits: list[Any] | None,
    scans: list[dict[str, Any]],
    decisions: list[dict[str, Any]],
    hub_deploys: list[dict[str, Any]] | None,
    running_revision: str | None,
    *,
    github_error: str | None = None,
) -> dict[str, Any]:
    """The chain for one story. `commits` None means GitHub could not be
    read, which is reported as such: it is not "no commit names this story"."""
    sid = int(story["id"])
    credited = [c for c in commits or [] if credits(c.message, sid)]
    prose_only = sum(
        1 for c in commits or [] if not credits(c.message, sid) and mentions(c.message, sid)
    )

    out: list[tuple[TraceCommit, bool]] = []
    for commit in credited:
        prs: dict[int, str] = {}
        for row in scans + decisions:
            if pc.sha_matches(row["sha"], commit.sha) and row["pr_number"] not in (None, 0):
                prs.setdefault(int(row["pr_number"]), "MyKronos scan and decision record")
        suffix = subject_pr(commit.message)
        if suffix is not None:
            prs.setdefault(suffix, "GitHub merge subject")
        commit_scans = [
            {
                "of": "commit",
                "capability": row["capability"],
                "status": row["status"],
                "at": pc.iso(pc.parse_time(row["at"])),
                "run_url": pc.actions_run_url(repo_full_name, row["run_id"]),
            }
            for row in scans
            if pc.sha_matches(row["sha"], commit.sha)
        ]
        pr_scans = [
            {
                "of": f"pull request #{row['pr_number']}",
                "capability": row["capability"],
                "status": row["status"],
                "at": pc.iso(pc.parse_time(row["at"])),
                "run_url": pc.actions_run_url(repo_full_name, row["run_id"]),
            }
            for row in scans
            if row["pr_number"] in prs and not pc.sha_matches(row["sha"], commit.sha)
        ]
        deploys = [
            {
                "source": "TheHub deploy_runs",
                "id": d.get("deploy_id") or d.get("id"),
                "status": d.get("final_status"),
                "at": d.get("started_at"),
                "sha": d.get("sha"),
            }
            for d in hub_deploys or []
            if pc.sha_matches(str(d.get("sha") or ""), commit.sha)
        ]
        running = pc.sha_matches(commit.sha, running_revision)
        went_out = running or any(str(d["status"] or "").lower() in DEPLOYED for d in deploys)
        trace = TraceCommit(
            sha=commit.sha,
            url=commit.url or f"https://github.com/{repo_full_name}/commit/{commit.sha}",
            subject=subject(commit.message)[:200],
            committed_at=pc.iso(pc.parse_time(commit.committed_at)),
            prs=[
                {
                    "number": number,
                    "url": f"https://github.com/{repo_full_name}/pull/{number}",
                    "source": source,
                }
                for number, source in sorted(prs.items())
            ],
            scans=commit_scans + pr_scans,
            deploys=deploys,
            running=running,
        )
        trace.missing = _first_missing(
            {"commit": True, "pr": bool(trace.prs), "scan": bool(trace.scans), "deploy": went_out}
        )
        out.append((trace, went_out))

    links = {
        "commit": bool(out),
        "pr": any(c.prs for c, _ in out),
        "scan": any(c.scans for c, _ in out),
        "deploy": any(went_out for _, went_out in out),
    }
    if commits is None:
        first_missing = "commits could not be read from GitHub"
    else:
        first_missing = _first_missing(links)
    return {
        "story_id": sid,
        "commits": [c for c, _ in out],
        "prose_mentions": prose_only,
        "commits_read": len(commits) if commits is not None else None,
        "links": links,
        "first_missing": first_missing,
        "github_error": github_error,
    }
