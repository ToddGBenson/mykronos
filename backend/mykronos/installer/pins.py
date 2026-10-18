"""Never move a pinned action backwards (#376).

The templates in `workflow-templates/` pin third-party actions to a full SHA
with the release in a trailing comment:

    uses: github/codeql-action/init@6f5948df...  # v3.37.9

The repositories they render into keep their *rendered* copies current with
Dependabot. Nothing keeps the *templates* current, so every install or resync
used to drag a target repository's pin back to whatever the template last
said — on keel, CodeQL went v3.37.9 -> v3.37.6 twice in a week, each time
inside a bot pull request merged for what it was *for*, not for what else it
changed. A slightly older scanner still reports `success`, so nothing was red.

**The rule: keep the target's pin unless the template's is demonstrably
newer, and say so.** Refusing the whole install was the alternative. It was
rejected because the downgrade is almost never the point of the pull request
— a capability is being enabled, a config changed — and failing that because
of an unrelated stale pin blocks real work on a problem the operator cannot
fix from the repository. Keeping the newer pin and naming it in the pull
request body gets the intended change through without the regression, and
the report is the signal that the template needs bumping.

"Demonstrably" is load-bearing. When either side's version cannot be read —
no comment, a pre-release label, a branch name — this does not guess. The
target's pin is kept and reported, because guessing wrong in the
template's favour is exactly the downgrade this exists to stop.

Only template lines in the `owner/repo@<40-hex sha>  # vX.Y.Z` form are
compared. That excludes, on purpose, the upload action: its ref is computed by
the installer from `upload_action_ref` and the `with:` block beside it is
derived from the same string, so keeping an old `uses:` there would split the
action from the package it installs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

_SHA = re.compile(r"^[0-9a-f]{40}$")

#: A `uses:` line. `head` keeps indentation and an optional list dash, so a
#: kept pin is spliced into the template's own layout rather than the
#: target's.
_USES = re.compile(
    r"^(?P<head>[ \t]*(?:-[ \t]+)?uses:[ \t]*)"
    r"(?P<action>[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+)"
    r"@(?P<ref>[^\s#]+)"
    r"(?:[ \t]*#[ \t]*(?P<label>\S+))?"
    r"[^\n]*$",
    re.MULTILINE,
)

_VERSION = re.compile(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?$")


def parse_version(label: str | None) -> tuple[int, int, int] | None:
    """`v3.37.9` -> (3, 37, 9). Anything else, including pre-releases, is None.

    A missing minor or patch reads as zero, so `v4` compares below `v4.0.1`
    and equal to `v4.0.0` — which is what a floating major tag means.
    """
    if not label:
        return None
    match = _VERSION.match(label.strip())
    if match is None:
        return None
    major, minor, patch = match.groups()
    return int(major), int(minor or 0), int(patch or 0)


@dataclass(frozen=True)
class _Pin:
    action: str
    ref: str
    label: str
    #: From `action` to the end of the line, trailing space trimmed: what is
    #: spliced into the template when the target's pin is kept.
    spec: str

    @property
    def version_label(self) -> str:
        """The release this pin claims: the comment, else a version-shaped ref."""
        if self.label:
            return self.label
        return "" if _SHA.match(self.ref) else self.ref

    @property
    def version(self) -> tuple[int, int, int] | None:
        return parse_version(self.version_label)


def _pins(content: str) -> list[tuple[re.Match[str], _Pin]]:
    out = []
    for match in _USES.finditer(content):
        spec = content[match.start("action") : match.end()].rstrip()
        out.append(
            (
                match,
                _Pin(
                    action=match.group("action"),
                    ref=match.group("ref"),
                    label=match.group("label") or "",
                    spec=spec,
                ),
            )
        )
    return out


@dataclass(frozen=True)
class PinDecision:
    """What happened to one pinned action in one rendered workflow."""

    path: str
    action: str
    template_version: str
    target_version: str
    outcome: Literal["kept_target", "upgraded"]
    reason: str

    def describe(self) -> str:
        target = self.target_version or "unversioned pin"
        if self.outcome == "upgraded":
            return (
                f"`{self.action}` in `{self.path}`: {target} -> "
                f"{self.template_version} (template is newer)"
            )
        return (
            f"`{self.action}` in `{self.path}`: kept {target}, template has "
            f"{self.template_version} — {self.reason}"
        )


def reconcile_pins(
    path: str, rendered: str, current: str | None
) -> tuple[str, list[PinDecision]]:
    """`rendered` with no pinned action older than the one in `current`.

    Returns the content to write and a decision for every compared pin whose
    ref differs. A pin the target does not have is a new step, not a
    comparison, and is left as the template says.
    """
    if not current:
        return rendered, []

    target: dict[str, _Pin] = {}
    for _, pin in _pins(current.replace("\r\n", "\n")):
        # First occurrence wins. Every template uses an action at most once
        # per file today (CodeQL's init/autobuild/analyze are three distinct
        # action paths), so this is a tie-break nobody currently hits.
        target.setdefault(pin.action, pin)

    decisions: list[PinDecision] = []
    pieces: list[str] = []
    cursor = 0
    for match, ours in _pins(rendered):
        if not (_SHA.match(ours.ref) and ours.version is not None):
            continue  # Not a SHA + release pin: the installer's own, or unversioned.
        theirs = target.get(ours.action)
        if theirs is None or theirs.ref == ours.ref:
            continue

        ours_v, theirs_v = ours.version, theirs.version
        if theirs_v is None:
            outcome: Literal["kept_target", "upgraded"] = "kept_target"
            reason = (
                "the repository's pin carries no readable version, so whether "
                "the template's is newer cannot be told; not guessing"
            )
        elif ours_v > theirs_v:
            outcome = "upgraded"
            reason = "template is newer"
        elif ours_v == theirs_v:
            outcome = "kept_target"
            reason = "same release, different SHA; the repository's pin is kept"
        else:
            outcome = "kept_target"
            reason = "the repository is newer; the template is stale"

        decisions.append(
            PinDecision(
                path=path,
                action=ours.action,
                template_version=ours.version_label,
                target_version=theirs.version_label,
                outcome=outcome,
                reason=reason,
            )
        )
        if outcome == "kept_target":
            pieces.append(rendered[cursor : match.start("action")])
            pieces.append(theirs.spec)
            cursor = match.end()

    pieces.append(rendered[cursor:])
    return "".join(pieces), decisions


def kept(decisions: list[PinDecision]) -> list[PinDecision]:
    return [d for d in decisions if d.outcome == "kept_target"]
