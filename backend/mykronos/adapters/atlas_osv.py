"""osv-scanner (spec 07 §3).

Thin wrapper over the shared SARIF converter. osv-scanner emits valid SARIF
and needs no bespoke parser, but it puts the one thing that makes a dependency
finding *actionable* — which package, at which version — only in the result
message:

    Package 'js-yaml@4.3.0' is vulnerable to 'GHSA-5p4m-2wfm-xmqj'.

There is no `locations[].logicalLocations` entry, no rule property, nothing
structured. So the first real Atlas scan produced findings whose
`package_name` and `package_version` were both null.

That is not cosmetic. Patchwork's deterministic dependency fixer keys on those
two fields (spec 08 §4): with them null it cannot tell which requirement to
pin, so every dependency finding falls through to `triaged` and no fix is ever
offered. The capability that exists to find vulnerable dependencies was
producing findings the capability that exists to fix them could not read.

Parsing a message is fragile and this one is worth the fragility: it is a
fixed format string in osv-scanner, the pattern is anchored, and a miss leaves
the fields null — exactly where they were before.
"""

from __future__ import annotations

import logging
import re

from mykronos.adapters.base import AdapterResult, ScanContext
from mykronos.adapters.sarif import sarif_to_findings

logger = logging.getLogger(__name__)

#: `Package 'name@version' is vulnerable to 'ID'.`
#:
#: The name may itself contain `@` — npm scoped packages are `@scope/name` —
#: so the version is taken from the *last* `@`, not the first.
_PACKAGE = re.compile(r"Package '(?P<spec>[^']+)' is vulnerable to")


def _split(spec: str) -> tuple[str, str | None]:
    name, separator, version = spec.rpartition("@")
    if not separator or not name:
        # No version, or a scoped name with nothing after it. Better to record
        # the name alone than to invent a version.
        return spec, None
    return name, version or None


def normalize(raw_output: bytes, context: ScanContext) -> AdapterResult:
    outcome = sarif_to_findings(raw_output, context)

    enriched = 0
    for finding in outcome.findings:
        if finding.package_name:
            continue
        match = _PACKAGE.search(finding.description or "") or _PACKAGE.search(
            finding.title or ""
        )
        if not match:
            continue
        finding.package_name, finding.package_version = _split(match.group("spec"))
        enriched += 1

    if outcome.findings and not enriched:
        # Worth a warning rather than silence: it means osv-scanner changed
        # its message format, and the symptom downstream is Patchwork quietly
        # offering no fixes at all.
        outcome.warn(
            "No osv-scanner finding carried a parseable package specifier. "
            "Dependency fixes cannot be generated without one."
        )

    return outcome
