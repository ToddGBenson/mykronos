"""A second analyser is a second lane, not a second capability (B-051).

CodeQL implements no shell language and no PowerShell, so `keel` recorded 47
successful SAST runs while 69% of it went unread, and `personal-soc` had
nothing examining its 608 lines of PowerShell at all. The answer is to run
ShellCheck or PSScriptAnalyzer *beside* CodeQL rather than instead of it:
swapping the tool would trade one blind spot for another.

**Why this is not modelled as a capability.** The installer requires a
template per capability, so `sast-shell` as a capability would need a grant, a
row in the coverage cross-check, an entry in the maturity model and a place in
every list a person reads — for something that is not a new kind of scanning.
It is the same capability, read by a second tool. A repository should not gain
a new thing to enable by pointing a better analyser at itself.

So the lane is chosen in the capability's own config:

    {"sast": {"extra_analysers": ["shellcheck"]}}

and the installer renders that template alongside the primary one. Both
workflows upload `sast`; `CAPABILITY_BY_JOB` maps both job names to it; the
coverage cross-check sees the capability reporting either way.
"""

from __future__ import annotations

#: tool -> the workflow template that runs it. The keys are the tools a
#: capability's `extra_analysers` may name, and the values are template keys
#: in `workflow-templates/manifest.json`.
#:
#: Keyed on the tool rather than on the language, because that is what the
#: adapter registry is keyed on and what a person configuring this would say.
#: A tool with an adapter and no entry here validates nowhere and installs
#: nothing, which is the honest failure: the platform can read its output and
#: has no way to make it run.
#: The capability each one belongs to is part of the key, not an assumption.
#: Without it, `extra_analysers` on any capability would install a `sast`
#: workflow — an `iac` config could hand a repository a ShellCheck lane
#: uploading a capability its own config never mentioned.
EXTRA_LANES: dict[str, tuple[str, str]] = {
    "shellcheck": ("sast", "sast-shell"),
    "psscriptanalyzer": ("sast", "sast-powershell"),
}


def lanes_for(capability: str, config: dict[str, object] | None) -> list[str]:
    """The extra template keys this capability's config asks for.

    Returns them in a stable order so a re-render of an unchanged
    configuration produces byte-identical files — the property that keeps a
    re-save from showing as churn on somebody's open pull request.
    """
    requested = (config or {}).get("extra_analysers") or []
    if not isinstance(requested, list):
        return []
    return [
        template
        for tool in sorted(dict.fromkeys(requested))
        for owner, template in [EXTRA_LANES.get(str(tool), ("", ""))]
        if owner == capability
    ]
