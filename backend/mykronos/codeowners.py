"""Who owns this file? (spec 24 §1)

Every finding this platform has ever produced was addressed to everybody,
which is the same as addressed to nobody. This is the smallest thing that
fixes that: the repository already answers the question, in a file its own
team wrote and reviewed, and nothing was reading it.

**The answer is copied, never invented.** A repository with no CODEOWNERS file
gets `unresolved` on every finding — not the org, not the last committer, not
a default that looks like a real assignment. A routing label this platform made
up is one somebody has to disprove before they can hand the work on, and that
costs more than the blank it replaced.

**Last match wins**, per GitHub's own rule. The file is read top to bottom and
the *final* matching pattern owns the path, which is why `_rules` is kept in
file order and matched in reverse rather than sorted by specificity: teams
write these files expecting the bottom of the file to override the top, and a
cleverer resolution order would quietly disagree with the file's own reading.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache

#: Owners are handles (`@user`), teams (`@org/team`), or email addresses.
#: Anything else on the line is not an owner and is dropped rather than stored:
#: a malformed entry that reaches a finding row looks like a routing decision.
_OWNER = re.compile(r"^(?:@[A-Za-z0-9][A-Za-z0-9\-_./]*|[^@\s]+@[^@\s]+\.[^@\s]+)$")


@dataclass(frozen=True)
class Rule:
    """One CODEOWNERS line that parsed into something usable."""

    pattern: str
    owners: tuple[str, ...]
    #: Line number in the source file, for reporting a rule a human can find.
    line: int


def parse(text: str) -> list[Rule]:
    """Parse a CODEOWNERS file into rules, in file order.

    Lines that name a pattern and no owner are dropped. GitHub treats such a
    line as "explicitly nobody owns this", which is a real intent — and it is
    indistinguishable here from `unresolved`, so representing it would add a
    state with no distinct behaviour.
    """
    rules: list[Rule] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        pattern, rest = parts[0], parts[1:]
        owners = tuple(owner for owner in rest if _OWNER.match(owner))
        if not owners:
            continue
        rules.append(Rule(pattern=pattern, owners=owners, line=number))
    return rules


@lru_cache(maxsize=2048)
def _matcher(pattern: str) -> re.Pattern[str]:
    """Translate one CODEOWNERS pattern into an anchored regex.

    Gitignore-shaped, with the subset GitHub actually documents for this file:
    `*` stops at a path separator, `**` crosses them, a trailing `/` means
    "everything under this directory", and a pattern with no separator matches
    by basename at any depth. Deliberately no `!` negation and no character
    ranges — GitHub does not support either here, and accepting them would mean
    resolving an owner this platform's rules agree on and GitHub's do not.
    """
    anchored = "/" in pattern.rstrip("/")
    directory = pattern.endswith("/")
    body = pattern.strip("/")

    out: list[str] = []
    index = 0
    while index < len(body):
        char = body[index]
        if body.startswith("**", index):
            out.append(".*")
            index += 2
            # `**/` should also match zero directories, so `a/**/b` matches
            # `a/b`. Swallowing the separator here is what makes that true.
            if body.startswith("/", index):
                index += 1
                out.append("(?:|.*/)" if not out[-1].endswith("/") else "")
        elif char == "*":
            out.append("[^/]*")
            index += 1
        elif char == "?":
            out.append("[^/]")
            index += 1
        else:
            out.append(re.escape(char))
            index += 1

    core = "".join(out)
    prefix = "" if anchored else "(?:.*/)?"
    suffix = "(?:/.*)?" if not directory else "/.*"
    return re.compile(f"^{prefix}{core}{suffix}$")


def _matches(pattern: str, path: str) -> bool:
    return bool(_matcher(pattern).match(path.lstrip("/")))


def owner_for(path: str, rules: list[Rule]) -> Rule | None:
    """The rule that owns `path`, or None if no pattern matches.

    Reversed rather than sorted: the last matching line in the file wins.
    """
    for rule in reversed(rules):
        if _matches(rule.pattern, path):
            return rule
    return None


def resolve(path: str | None, rules: list[Rule]) -> tuple[str | None, str]:
    """`(owner, owner_source)` for one path.

    The pair, rather than one nullable column, because "nobody owns this" and
    "we never worked out who owns this" are different problems with different
    fixes — and one nullable field would let a reader conclude either.

    Only the first owner on a matching line is stored. A line naming three
    teams means all three review; it does not mean this platform picks one, and
    storing all three in a routing column would make "mine" a substring search.
    The full line stays available in the repository, where it is authoritative.
    """
    if not path or not rules:
        return None, "unresolved"
    rule = owner_for(path, rules)
    if rule is None:
        return None, "unresolved"
    return rule.owners[0], "codeowners"
