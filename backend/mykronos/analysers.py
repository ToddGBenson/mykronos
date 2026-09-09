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

from collections.abc import Iterable
from dataclasses import dataclass

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
#: analyser is not a coverage gap. A Dockerfile is read by `containers`,
#: HCL by `iac`, and reporting them as unanalysed source would be the
#: page-of-gaps failure the module docstring warns about.
NOT_SOURCE: frozenset[str] = frozenset(
    {
        "Dockerfile",
        "HCL",
        "Jinja",
        "CSS",
        "SCSS",
        "HTML",
        "Makefile",
        "Batchfile",
        "Roff",
        "Vim Script",
    }
)

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
