"""What a repository's static analyser can actually read (B-051).

`keel` recorded 47 successful SAST runs and zero findings, ever. That reads as
a well-kept repository. What happened is that its analyser is CodeQL, CodeQL
implements no shell language at all, and 69% of keel is shell -- so 219 KB has
never been read by anything, and every run over it reported success.

**This is the platform's own thesis one level down.** Mykronos leads with
silent lanes because a lane that reports nothing looks exactly like a clean
repository. A lane that reports nothing *because it cannot read the language*
looks the same and is worse: it reports `success` while doing it, so it does
not appear in the stalled-lane section, does not appear in scan health, and
does not appear as a gap anywhere. It appears as a clean repo.

The information needed to catch it is one API call away. GitHub publishes byte
counts per language for every repository, and this platform already knows which
tool serves each capability.

**Only `sast` is asked this question.** The other capabilities are not
language-blind in the way that matters here: `secrets` greps content and reads
everything, `atlas` reads dependency manifests, `iac` reads configuration,
`containers` reads an image. Asking them about languages would produce a page
of gaps nobody should act on, which is how a real one stops being read.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mykronos.github.client import GitHubClient

#: What each static analyser implements, in GitHub's own language names.
#:
#: Deliberately a declared table rather than something inferred. A tool's
#: language list is a fact about a release, it changes when the tool is
#: upgraded, and guessing it from a finding count would mean a repository with
#: no findings looked identical to a repository nothing could read -- which is
#: the confusion this module exists to end.
SAST_LANGUAGES: dict[str, frozenset[str]] = {
    # CodeQL 2.26.x. No shell of any kind, no PowerShell: that absence is the
    # whole of B-051, so it is written here rather than left to be discovered
    # from an empty result again.
    "codeql": frozenset(
        {
            "C",
            "C++",
            "C#",
            "Go",
            "Java",
            "Kotlin",
            "JavaScript",
            "TypeScript",
            "Python",
            "Ruby",
            "Swift",
        }
    ),
    # ShellCheck reads shell and nothing else, which is exactly why it is
    # worth running *beside* CodeQL rather than instead of it: on `keel` the
    # two together read everything, and either alone reads about a third.
    "shellcheck": frozenset({"Shell"}),
    # PSScriptAnalyzer reads PowerShell and nothing else, which is the whole
    # of `personal-soc`.
    "psscriptanalyzer": frozenset({"PowerShell"}),
    # Semgrep's registry is broader and does cover bash. Named for the day a
    # repository is pointed at it, not because anything uses it here.
    "semgrep": frozenset(
        {
            "C",
            "C++",
            "C#",
            "Go",
            "Java",
            "Kotlin",
            "JavaScript",
            "TypeScript",
            "Python",
            "Ruby",
            "Rust",
            "Scala",
            "PHP",
            "Shell",
        }
    ),
}

#: Languages that are not application source, so their absence from an
#: analyser is not a coverage gap. Two different reasons, kept in one set
#: because the consequence is the same.
#:
#: **Read by another capability.** A Dockerfile is `containers`' job and HCL is
#: `iac`'s, so counting them here would report a gap that is covered
#: elsewhere.
#:
#: **Not code at all.** Documents and markup that no static analyser has an
#: opinion about. `Rich Text Format` is in this list because the first live
#: run over the estate counted 7 KB of it against TheHub as unread source,
#: which is the page-of-gaps failure the module docstring warns about arriving
#: on the first day.
#:
#: **Schema.** Migration DDL - `CREATE TABLE`, `ALTER TABLE`, `CREATE INDEX` -
#: declares a database the way HCL declares infrastructure. It is not the
#: language GitHub names it by, so it arrives here under `SCHEMA` after
#: `classify_sql` has split the SQL bytes by file, and only the files that
#: define procedural code stay counted as source (B-051, D-138).
NOT_SOURCE: frozenset[str] = frozenset(
    {
        # Covered by another capability.
        "Dockerfile",
        "HCL",
        "Jinja",
        # Declarations, not code. Never a GitHub language name: only
        # `classify_sql` produces it.
        "SQL schema",
        # Markup and documents, which no analyser reads and none should.
        "CSS",
        "SCSS",
        "HTML",
        "Makefile",
        "Batchfile",
        "Roff",
        "Vim Script",
        "Rich Text Format",
        "TeX",
        "Markdown",
    }
)

#: The name the DDL share of a repository's SQL is reported under. In
#: `NOT_SOURCE`, so it is never counted as unread.
SCHEMA = "SQL schema"

#: The languages GitHub gives a `.sql` file. Linguist calls a file `PLpgSQL`
#: on markers as weak as a `BEGIN;`, so the language name cannot answer the
#: question and the file content has to. Measured 2026-10-11: GitHub counts
#: 711 KB of TheHub as PLpgSQL, and 34 of its 376 `.sql` files (324 KB)
#: define a function, a procedure or a `DO` block; the rest is DDL.
#: PL/SQL and T-SQL are deliberately absent: their procedural markers are
#: different, and no repository here has either.
SQL_LANGUAGES: frozenset[str] = frozenset({"SQL", "PLpgSQL"})

#: What makes a SQL file code rather than a declaration: a function or
#: procedure body, or an anonymous `DO` block. `CREATE TRIGGER` alone is not
#: here, because a trigger runs a function that one of these defines.
_PROCEDURAL_SQL = re.compile(
    r"\bLANGUAGE\s+'?plpgsql\b"
    r"|\bCREATE\s+(?:OR\s+REPLACE\s+)?(?:FUNCTION|PROCEDURE)\b"
    r"|\bDO\s+(?:LANGUAGE\s+'?\w+'?\s+)?\$",
    re.IGNORECASE,
)

#: Above this many `.sql` files the split is not attempted and the SQL bytes
#: stay counted as before. The files are read a hundred to a GraphQL request
#: (`get_files`, TheHub #60908), so TheHub's few hundred cost a handful of
#: calls; a repository with ten times that is a different cost question, and
#: the safe direction is to keep reporting it.
MAX_SQL_FILES = 1_000


def is_procedural_sql(text: str) -> bool:
    """Whether a SQL file defines code an analyser would need to read."""
    return bool(_PROCEDURAL_SQL.search(text))


def classify_sql(
    languages: Mapping[str, int], sql_files: Mapping[str, str] | None
) -> dict[str, int]:
    """Move the DDL share of a repository's SQL bytes to `SCHEMA`.

    `sql_files` is every `.sql` file's text by path. The procedural files'
    bytes stay source, under `PLpgSQL`; the rest becomes `SCHEMA`. Capped at
    GitHub's own SQL total, so the split can never report more SQL than
    GitHub measured.

    `None` means the files could not be read, and then nothing moves: "we
    could not look" must not read as "it is all schema", which would hide the
    procedural files this exists to keep reporting.
    """
    sql_bytes = sum(languages.get(name, 0) for name in SQL_LANGUAGES)
    if sql_files is None or not sql_bytes:
        return dict(languages)

    procedural = sum(
        len(text.encode("utf-8")) for text in sql_files.values() if is_procedural_sql(text)
    )
    procedural = min(procedural, sql_bytes)

    split = {name: count for name, count in languages.items() if name not in SQL_LANGUAGES}
    if procedural:
        split["PLpgSQL"] = procedural
    if sql_bytes - procedural:
        split[SCHEMA] = sql_bytes - procedural
    return split


async def read_sql_files(client: GitHubClient, repo_full_name: str) -> dict[str, str] | None:
    """Every `.sql` file on the default branch, or None if any could not be read.

    All or nothing, for the reason `list_tree` gives: a partial read would
    classify the unread files as schema by omission.

    Read in batches (`get_files`), not one contents call per file: TheHub's
    migrations made that ~426 GitHub calls per `mykronos briefing`, each
    logged at INFO (TheHub #60908).
    """
    try:
        ref = str((await client.get_repo(repo_full_name)).get("default_branch") or "main")
        paths = await client.list_tree(repo_full_name, ref)
        if paths is None:
            return None
        wanted = [path for path in paths if path.lower().endswith(".sql")]
        if len(wanted) > MAX_SQL_FILES:
            return None
        results = await client.get_files(repo_full_name, wanted, ref)
    except Exception:  # noqa: BLE001 - unknown, never a partial answer
        return None
    texts = {path: results.get(path) for path in wanted}
    if any(text is None for text in texts.values()):
        return None
    return {path: text for path, text in texts.items() if text is not None}


async def read_languages(client: GitHubClient, repo_full_name: str) -> dict[str, int] | None:
    """GitHub's bytes per language, with migration DDL moved to `SCHEMA`.

    The SQL files are read only when GitHub reports SQL at all, so a
    repository with none costs the one call it always did.
    """
    counts = await client.languages(repo_full_name)
    if counts and SQL_LANGUAGES & counts.keys():
        counts = classify_sql(counts, await read_sql_files(client, repo_full_name))
    return counts


#: GitHub's name for a language, where it differs from the analyser's.
_ALIASES: dict[str, str] = {
    "Shell": "Shell",
    "Bash": "Shell",
    "Zsh": "Shell",
    "Fish": "Shell",
    "PowerShell": "PowerShell",
    "TSX": "TypeScript",
    "JSX": "JavaScript",
    "Vue": "JavaScript",
}


@dataclass(frozen=True)
class Readability:
    """How much of a repository its configured analyser can read."""

    repo_full_name: str
    #: Every analyser that reports for this repository, together. Two lanes on
    #: one capability is how "a shell analyser alongside CodeQL" is expressed
    #: here, so readability is a question about the set rather than about one
    #: tool -- and asking it of one tool would report `keel` as 70% unread on
    #: the day it stopped being.
    tools: tuple[str, ...]
    #: Bytes of application source, and how many of them the tools implement.
    source_bytes: int
    analysable_bytes: int
    #: Languages the tool cannot read, largest first, as (name, bytes).
    unread: list[tuple[str, int]]

    @property
    def known(self) -> bool:
        """Whether anything was measured at all.

        An empty language list means GitHub had nothing to say -- a new or
        empty repository -- and that must read as unknown rather than as
        "nothing is analysable", which would report every fresh repository as
        a coverage gap on its first day.
        """
        return self.source_bytes > 0

    @property
    def tool(self) -> str:
        """The analysers, for a sentence. Kept so a caller reading one name
        still gets a true one when there are several."""
        return " + ".join(self.tools) if self.tools else "nothing"

    @property
    def share_unread(self) -> float:
        """0.0 to 1.0 of application source no analyser here can read."""
        if not self.known:
            return 0.0
        return 1 - (self.analysable_bytes / self.source_bytes)

    @property
    def blind(self) -> bool:
        """Is any of it unread at all.

        Any, not a threshold. A percentage invites an argument about where the
        line goes; the honest statement is that some of this code is read by
        nothing, and the share says how much.
        """
        return self.known and bool(self.unread)


def readability(
    repo_full_name: str, languages: dict[str, int], tools: str | Iterable[str]
) -> Readability:
    """Measure one repository against everything analysing it.

    `languages` is GitHub's byte count per language. `tools` is one analyser
    or several: several is the answer B-051 asks for, since a shell analyser
    beside CodeQL is two lanes on one capability rather than a replacement.

    An unknown tool reads nothing, which is the safe direction: a tool this
    platform has no language list for should say so rather than be assumed
    comprehensive.
    """
    names = (tools,) if isinstance(tools, str) else tuple(tools)
    implements: set[str] = set()
    for name in names:
        implements |= SAST_LANGUAGES.get(name, frozenset())

    source = 0
    analysable = 0
    unread: dict[str, int] = {}
    for name, count in languages.items():
        if name in NOT_SOURCE:
            continue
        canonical = _ALIASES.get(name, name)
        source += count
        if canonical in implements:
            analysable += count
        else:
            unread[canonical] = unread.get(canonical, 0) + count

    return Readability(
        repo_full_name=repo_full_name,
        tools=names,
        source_bytes=source,
        analysable_bytes=analysable,
        unread=sorted(unread.items(), key=lambda item: -item[1]),
    )


def describe(reading: Readability) -> str:
    """One sentence a person can act on.

    Names the share and the languages, because "30% analysed" without saying
    *what* the other 70% is leaves the reader unable to choose a tool.
    """
    if not reading.known:
        return f"{reading.repo_full_name}: GitHub reports no languages, so nothing was measured."
    if not reading.unread:
        return f"{reading.repo_full_name}: {reading.tool} reads all of it."

    languages = ", ".join(name for name, _ in reading.unread[:3])
    return (
        f"{reading.repo_full_name}: {reading.share_unread:.0%} of the source is "
        f"{languages}, which {reading.tool} does not implement — those bytes are "
        "read by nothing, and every run over them reports success."
    )
