"""HTML release notes for every MyKronos production release (TheHub #61703).

Production is deployed in batches, so "what changed" is a range of commits,
and the operator needs to know what to look at after each deploy. deploy.ps1
asks for the notes once the backend confirms it runs the new sha: the commits
from the previous production sha to the new one, along the first-parent line,
grouped by pull request. Each item gets a title, its story ids, a one-line why
and a "what to check" line. The notes also carry the security delta the deploy
gate measured and the rollback command. They are kept one file per release in
the lake, so the history can be browsed, and are never committed: this repository
is public.

A pull request body is untrusted input, for two reasons:

* Markup: nothing from it is rendered as HTML. Every value is reduced to
  plain text and escaped, so a `<script>` or an `on*=` attribute in a body
  is shown as text and never runs. The route that serves the page also
  sends a CSP with no script source at all.
* Hosts and secrets: anything host-like is replaced before rendering. That
  means URLs, IPv4 and IPv6 addresses, and dotted names under a host's
  top-level domain (`triage_packet.redact`, the same rule the triage packet
  uses). Common token shapes are replaced too. A bare one-word host name
  cannot be told from an ordinary word, which is the limit of the rule.
"""

from __future__ import annotations

import html
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from mykronos.schemas import utcnow
from mykronos.triage_packet import redact

#: GitHub's squash and merge subjects: `title (#123)`, `Merge pull request #123 from ...`.
_PR_IN_SUBJECT = re.compile(r"\(#(\d+)\)\s*$|^Merge pull request #(\d+)\b")
_STORY = re.compile(r"TheHub #(\d{4,6})")
_SHA = re.compile(r"^[0-9a-f]{40}$")
#: Credential shapes a pull request body might quote by mistake.
_TOKEN = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}"
    r"|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)\b"
    r"|\b(?:Bearer|token)\s+[A-Za-z0-9._~+/=-]{16,}",
    re.I,
)
_LOCALHOST = re.compile(r"\blocalhost(?::\d+)?\b", re.I)
_MD_LINK = re.compile(r"!?\[([^\]]*)\]\([^)]*\)")
_TAG = re.compile(r"<[^>]*>")
#: Headings whose first line says how to see the change working.
_CHECK_HEADINGS = re.compile(
    r"production check|what to check|verification|how to verify|how to test", re.I
)
_SUMMARY_HEADINGS = re.compile(r"summary|why|what|context", re.I)
MAX_LINE = 280


def clean(text: str, *, max_length: int = MAX_LINE) -> str:
    """Untrusted markdown as one safe line of plain text: markup and links
    dropped, hosts and credential shapes replaced, whitespace folded."""
    out = _MD_LINK.sub(r"\1", text)
    out = _TAG.sub("", out)
    out = _TOKEN.sub("[redacted]", out)
    out = _LOCALHOST.sub("[host]", redact(out))
    # Emphasis and code marks only: `_` and `#` are kept for names like
    # `introduced_blocking` and story ids like `TheHub #61703`.
    out = re.sub(r"[`*|]+|^\s*>+", "", out)
    out = " ".join(out.split())
    if len(out) > max_length:
        out = out[: max_length - 1].rstrip() + "…"
    return out


def _sections(body: str) -> list[tuple[str, list[str]]]:
    """(heading, lines) for each markdown section; the text before the first
    heading is the section ''."""
    out: list[tuple[str, list[str]]] = [("", [])]
    for line in body.replace("\r\n", "\n").split("\n"):
        heading = re.match(r"^\s{0,3}#{1,6}\s+(.*)$", line)
        if heading:
            out.append((heading.group(1).strip(), []))
        else:
            out[-1][1].append(line)
    return out


def _first_sentence(lines: list[str]) -> str:
    for raw in lines:
        line = re.sub(r"^\s*(?:[-*+]|\d+\.)\s+(?:\[[ xX]\]\s+)?", "", raw).strip()
        if not line or line.startswith(("```", "<!--", "|")):
            continue
        sentence = re.split(r"(?<=[.!?])\s+", line, maxsplit=1)[0]
        return clean(sentence)
    return ""


def why_of(body: str) -> str:
    """The first sentence of the summary, or of the body."""
    sections = _sections(body)
    for heading, lines in sections:
        if heading and _SUMMARY_HEADINGS.search(heading):
            found = _first_sentence(lines)
            if found:
                return found
    for _, lines in sections:
        found = _first_sentence(lines)
        if found:
            return found
    return ""


def check_of(body: str) -> str:
    """The first line of the verification section, else the first unticked
    acceptance criterion, else ''."""
    sections = _sections(body)
    for heading, lines in sections:
        if _CHECK_HEADINGS.search(heading):
            found = _first_sentence(lines)
            if found:
                return found
    for _, lines in sections:
        for line in lines:
            unticked = re.match(r"^\s*[-*]\s+\[ \]\s+(.*)$", line)
            if unticked:
                return clean(unticked.group(1))
    return ""


def first_parent(commits: list[Any], head: str) -> list[Any]:
    """The commits on `head`'s first-parent line, oldest first. `commits` is
    a compare listing (`CommitInfo`); without parents it is taken as linear."""
    by_sha = {c.sha: c for c in commits}
    if not any(c.parents for c in commits):
        return list(commits)
    line: list[Any] = []
    sha = head
    while sha in by_sha:
        line.append(by_sha[sha])
        parents = by_sha[sha].parents
        sha = parents[0] if parents else ""
    return list(reversed(line))


@dataclass
class Item:
    pr_number: int | None
    title: str
    stories: list[str]
    why: str
    check: str
    commits: list[str] = field(default_factory=list)


def pr_number_of(message: str) -> int | None:
    subject = message.split("\n", 1)[0].strip()
    match = _PR_IN_SUBJECT.search(subject)
    if not match:
        return None
    return int(match.group(1) or match.group(2))


def build_items(commits: list[Any], pulls: dict[int, Any]) -> list[Item]:
    """One item per pull request, in the order they landed, then one per
    commit that names none. `pulls` maps a number to a `PullRequest`."""
    items: dict[Any, Item] = {}
    for commit in commits:
        number = pr_number_of(commit.message)
        subject = commit.message.split("\n", 1)[0]
        key: Any = number if number is not None else commit.sha
        if key not in items:
            pr = pulls.get(number) if number is not None else None
            title = getattr(pr, "title", "") or subject
            body = getattr(pr, "body", "") or commit.message
            items[key] = Item(
                pr_number=number,
                title=clean(re.sub(r"\s*\(#\d+\)\s*$", "", title)),
                stories=sorted(set(_STORY.findall(f"{title}\n{body}")), key=int),
                why=why_of(body),
                check=check_of(body),
            )
        items[key].commits.append(commit.sha[:8])
    return list(items.values())


@dataclass
class SecurityDelta:
    """What the deploy gate measured before this deploy (one snapshot), and the
    open criticals and highs each commit's own decision recorded."""

    score_before: float | None = None
    score_after: float | None = None
    introduced: dict[str, int] = field(default_factory=dict)
    fixed: dict[str, int] = field(default_factory=dict)
    open_before: dict[str, int] = field(default_factory=dict)
    open_after: dict[str, int] = field(default_factory=dict)
    gate: str = "not asked"


def open_counts(decision_snapshot: str | None) -> dict[str, int]:
    """Open criticals and highs from a stored decision's `findings.*` terms."""
    try:
        terms = json.loads(decision_snapshot or "{}").get("terms") or []
    except (TypeError, ValueError):
        return {}
    out: dict[str, int] = {}
    for term in terms:
        key = str(term.get("key") or "")
        if key in ("findings.critical", "findings.high"):
            out[key.split(".", 1)[1]] = int((term.get("inputs") or {}).get("count") or 0)
    return out


@dataclass
class Release:
    sha: str
    previous_sha: str
    generated_at: str
    items: list[Item]
    security: SecurityDelta
    commit_count: int

    @property
    def rollback(self) -> str:
        return f".\\deploy.ps1 -Tag {self.previous_sha}"

    def meta(self) -> dict[str, Any]:
        return {
            "sha": self.sha,
            "previous_sha": self.previous_sha,
            "generated_at": self.generated_at,
            "commit_count": self.commit_count,
            "pull_requests": [i.pr_number for i in self.items if i.pr_number is not None],
            "stories": sorted({s for i in self.items for s in i.stories}, key=int),
        }


def new_release(
    sha: str, previous_sha: str, commits: list[Any], pulls: dict[int, Any],
    security: SecurityDelta,
) -> Release:
    return Release(
        sha=sha, previous_sha=previous_sha, generated_at=utcnow().isoformat() + "Z",
        items=build_items(commits, pulls), security=security, commit_count=len(commits),
    )


def _count(d: dict[str, int]) -> str:
    return ", ".join(f"{d.get(s, 0)} {s}" for s in ("critical", "high"))


def render(release: Release) -> str:
    """The release as a standalone HTML page. Every value is escaped."""
    e = html.escape
    sec = release.security

    def score(v: float | None) -> str:
        return "not measured" if v is None else f"{v:.2f}"

    rows = []
    for item in release.items:
        ref = f"PR #{item.pr_number}" if item.pr_number is not None else "direct commit"
        stories = ", ".join(f"TheHub #{s}" for s in item.stories) or "no story named"
        rows.append(
            "<li><h3>" + e(item.title) + "</h3>"
            f"<p class=meta>{e(ref)} &middot; {e(stories)} &middot; "
            f"{e(' '.join(item.commits))}</p>"
            f"<p><b>Why:</b> {e(item.why or 'The pull request gives no summary.')}</p>"
            f"<p><b>What to check:</b> {e(item.check or 'No verification step was given.')}</p>"
            "</li>"
        )
    return (
        "<!doctype html><html lang=en><head><meta charset=utf-8>"
        f"<title>MyKronos release {e(release.sha[:8])}</title>"
        "<meta name=viewport content='width=device-width,initial-scale=1'>"
        "<style>body{font:15px/1.5 system-ui,sans-serif;max-width:52rem;margin:2rem auto;"
        "padding:0 1rem;color:#1b1f24;background:#fff}h3{margin:.2rem 0}"
        ".meta{color:#57606a;font-size:13px;margin:0}li{margin:0 0 1.2rem}"
        "code{background:#f3f4f6;padding:.1rem .3rem}"
        "@media(prefers-color-scheme:dark){body{color:#e6edf3;background:#0d1117}"
        ".meta{color:#8b949e}code{background:#161b22}}</style></head><body>"
        f"<h1>MyKronos release {e(release.sha[:8])}</h1>"
        f"<p class=meta>Deployed over {e(release.previous_sha[:8])}; generated "
        f"{e(release.generated_at)}; {release.commit_count} commits, "
        f"{len(release.items)} items.</p>"
        "<h2>Security delta</h2><ul>"
        f"<li>Risk score: {e(score(sec.score_before))} &rarr; {e(score(sec.score_after))} "
        f"(deploy gate: {e(sec.gate)})</li>"
        f"<li>Introduced: {e(_count(sec.introduced))}; fixed: {e(_count(sec.fixed))}</li>"
        f"<li>Open before: {e(_count(sec.open_before))}; open after: "
        f"{e(_count(sec.open_after))} (each commit's own decision)</li></ul>"
        "<h2>What shipped</h2><ol>" + "".join(rows) + "</ol>"
        f"<h2>Rollback</h2><p><code>{e(release.rollback)}</code> "
        "(add <code>-Restore</code> if the backend is down).</p></body></html>"
    )


# -- storage -----------------------------------------------------------------


def releases_dir(datalake_dir: Path) -> Path:
    return datalake_dir / "releases"


def store(datalake_dir: Path, release: Release) -> dict[str, Any]:
    folder = releases_dir(datalake_dir)
    folder.mkdir(parents=True, exist_ok=True)
    meta = release.meta()
    (folder / f"{release.sha}.html").write_text(render(release), encoding="utf-8")
    payload = {**meta, "security": asdict(release.security)}
    (folder / f"{release.sha}.json").write_text(json.dumps(payload), encoding="utf-8")
    return meta


def list_releases(datalake_dir: Path) -> list[dict[str, Any]]:
    """Every stored release's metadata, newest first."""
    folder = releases_dir(datalake_dir)
    out = []
    for path in folder.glob("*.json") if folder.is_dir() else []:
        if not _SHA.match(path.stem):
            continue
        try:
            meta = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        meta.pop("security", None)
        out.append(meta)
    return sorted(out, key=lambda m: str(m.get("generated_at") or ""), reverse=True)


def read_html(datalake_dir: Path, sha: str) -> str | None:
    if not _SHA.match(sha):
        return None
    path = releases_dir(datalake_dir) / f"{sha}.html"
    return path.read_text(encoding="utf-8") if path.is_file() else None
