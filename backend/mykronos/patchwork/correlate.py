"""Toxic combinations (spec 08 §2, stage 3; §5).

A set of findings that together represent more risk than any of them alone.
The canonical example is spec 08's own: an unauthenticated endpoint plus a
SQL-injectable query in the same request path. Separately, two medium
findings. Together, an unauthenticated database.

Two design choices worth stating:

**Rules are data, not code.** spec 08 §5 requires admins to be able to add
rules "without code changes", so a rule is a small declarative record — which
capabilities and rule-id patterns must co-occur, and within what scope. The
built-in set is deliberately tiny; a large default set of speculative
combinations would produce noise that discredits the real ones.

**A detected combination stops the individual fixes.** Findings inside a
combination are not fixed in isolation, because fixing one half of a toxic
pair can make the situation *look* resolved while the composite risk remains.
It is also spec 08 §8's conflicting-pull-request case: two fixes touching the
same request path produce two draft PRs that cannot both merge cleanly.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, replace
from typing import Any

from mykronos.threat_intel import extract_cve


@dataclass(frozen=True)
class Requirement:
    """One half of a combination: what to match, and optionally where.

    `capability` exists because the obvious alternative does not work.
    Cross-capability rules need to say "a DAST finding about authentication",
    and a capability cannot be expressed as a pattern over `rule_id` — ZAP
    emits `ZAP-10202-CWE-352` and Trivy emits `CVE-2023-45853`, neither of
    which mentions which scanner produced it. Folding the capability into the
    searched text instead would make the existing `secret|credential` pattern
    match every finding from the `secrets` capability by way of its own name.

    None means any capability, which is what the file-scoped rules want:
    proximity is doing the work there, not provenance.
    """

    pattern: str
    #: One capability, or several that satisfy this half equally (spec 22 §4).
    #: A tuple rather than a second requirement, because `detect` needs a
    #: *distinct* finding per requirement — adding "or atlas" as its own
    #: requirement would stop the rule firing for a repository that has only
    #: the containers half, which is the common case it already covers.
    capability: str | tuple[str, ...] | None = None
    #: Findings below this are ignored for this requirement. Used where a
    #: rule would otherwise fire on nearly every repository: a low-severity
    #: CVE in a reachable service is not a different kind of problem from a
    #: low-severity CVE anywhere else.
    min_severity: str | None = None

    @property
    def capabilities(self) -> tuple[str, ...]:
        """`capability` normalised, so callers never re-derive it.

        Three readings of the same field went out of sync the first time this
        accepted a tuple — `_matches` handled it, two invariant tests did not,
        and they were the tests whose whole job is noticing a rule that cannot
        fire. One accessor, used everywhere.
        """
        if self.capability is None:
            return ()
        if isinstance(self.capability, str):
            return (self.capability,)
        return tuple(self.capability)


@dataclass(frozen=True)
class CombinationRule:
    """One declarative correlation rule (spec 08 §5)."""

    rule_id: str
    name: str
    #: Each requirement must be satisfied by at least one finding for the
    #: combination to fire.
    requires: tuple[Requirement, ...]
    #: `file` means the matches must be in the same file; `repo` means
    #: anywhere in the repository. `file` is the default because proximity is
    #: most of what makes a combination toxic rather than coincidental.
    scope: str = "file"
    explanation: str = ""


@dataclass(frozen=True)
class Combination:
    combination_id: str
    rule_id: str
    finding_ids: frozenset[str]
    rationale: str


#: Small on purpose. Every rule here is one where the composite risk is
#: genuinely different in kind from its parts, not merely larger.
BUILT_IN_RULES: tuple[CombinationRule, ...] = (
    CombinationRule(
        rule_id="unauth-injectable",
        name="Unauthenticated injectable endpoint",
        requires=(
            Requirement(r"CWE-89|sql.?inj", capability="sast"),
            Requirement(r"CWE-306|CWE-287|missing.?auth|unauth", capability="sast"),
        ),
        scope="file",
        explanation=(
            "An injectable query and a missing authentication check in the "
            "same file. Either alone is serious; together they are an "
            "unauthenticated path to the database, and fixing only one of "
            "them leaves that true while making the code look attended to."
        ),
    ),
    CombinationRule(
        rule_id="secret-and-public-surface",
        name="Committed credential on a public surface",
        # Both halves are pinned to a capability because this rule fired in
        # production without it, twice, on a container image. Grouped by
        # `file_path` - which for a container finding is the image name -
        # libcurl's "failure to clear proxy authentication credentials"
        # matched `credential`, libssh2's "publickey attribute allocation"
        # matched `public`, and two unrelated CVEs in one image were reported
        # to an operator as a committed credential on a public surface.
        requires=(
            Requirement(r"generic-api-key|aws-|secret|credential", capability="secrets"),
            Requirement(r"CWE-306|unauth|public", capability="sast"),
        ),
        scope="file",
        explanation=(
            "A committed credential in a file that also has an "
            "unauthenticated surface. The credential is already leaked by "
            "being in git history; the unauthenticated surface is how someone "
            "finds out it is worth using."
        ),
    ),
    # -- cross-capability (spec 08 §5a) -----------------------------------
    #
    # These correlate a *running* application against its *source*, which is
    # the pairing neither scanner can see alone: DAST knows the endpoint
    # answers without credentials but not what the handler contains, and SAST
    # knows the handler is injectable but not whether anything can reach it.
    #
    # Necessarily repo-scoped - a DAST finding's file_path is a URL path or
    # empty - so each pattern is narrow. Repo scope plus a loose pattern is
    # how a correlation engine starts reporting that everything is toxic.
    CombinationRule(
        rule_id="live-unauth-and-injectable-code",
        name="Reachable without credentials, injectable in code",
        requires=(
            Requirement(
                r"auth|401|403|access.?control|idor|session|csrf", capability="dast"
            ),
            Requirement(
                r"CWE-89|CWE-78|CWE-611|sql.?inj|command.?inj", capability="sast"
            ),
        ),
        scope="repo",
        explanation=(
            "DAST reached an endpoint on the running application without "
            "credentials, and SAST found an injectable query or command in "
            "the same codebase. The runtime scan proves reachability that "
            "static analysis has to assume; the static scan proves an impact "
            "the runtime scan only probed for. Each is a medium on its own "
            "and neither is worth an incident; together they are an "
            "unauthenticated path to the database."
        ),
    ),
    CombinationRule(
        rule_id="live-unauth-and-committed-credential",
        name="Reachable without credentials, credential in the repository",
        requires=(
            Requirement(
                r"auth|401|403|access.?control|exposed|disclosure", capability="dast"
            ),
            Requirement(
                r"generic-api-key|aws-|private-key|token|credential",
                capability="secrets",
            ),
        ),
        scope="repo",
        explanation=(
            "An endpoint that answers without credentials, in a repository "
            "that also has a credential committed to it. The credential is "
            "already disclosed by being in git history; an unauthenticated "
            "surface on the same service is how somebody establishes it is "
            "worth using, and against what."
        ),
    ),
    CombinationRule(
        rule_id="public-storage-and-live-exposure",
        name="Publicly reachable service on publicly readable storage",
        requires=(
            Requirement(
                r"public|anonymous|0\.0\.0\.0|unrestricted|world.?readable",
                capability="cloud",
            ),
            Requirement(
                r"auth|exposed|directory|listing|disclosure", capability="dast"
            ),
        ),
        scope="repo",
        explanation=(
            "Cloud posture reports storage or a security group open to the "
            "internet, and DAST reports the application in front of it "
            "answering without credentials. Posture scanning cannot tell "
            "whether anything reachable uses that storage; the runtime scan "
            "can, and does."
        ),
    ),
    # -- network × application (spec 14, spec 08 §5a) ---------------------
    #
    # The pairing the platform could not make until findings had an asset: a
    # network scan sees a port answering and cannot see what is behind it; a
    # web scan sees the application and cannot see what else that host
    # exposes. Neither is wrong alone and neither is the finding that matters.
    CombinationRule(
        rule_id="exposed-admin-port-and-weak-app-auth",
        name="Administrative service exposed beside an app that does not authenticate",
        requires=(
            Requirement(
                r"ssh|rdp|vnc|telnet|winrm|smb|admin|3389|22/tcp|5985",
                capability="network",
            ),
            Requirement(
                r"auth|401|403|access.?control|session|default.?cred",
                capability="dast",
            ),
        ),
        scope="repo",
        explanation=(
            "A management service reachable on the network, and a web "
            "application on the same estate that does not enforce "
            "authentication. The port scan cannot tell whether the service "
            "matters; the web scan cannot tell what else the host runs. "
            "Together they describe a way in and somewhere to go from it."
        ),
    ),
    CombinationRule(
        rule_id="exposed-database-and-committed-credential",
        name="Database port reachable, credential in the repository",
        requires=(
            Requirement(
                r"mysql|postgres|mongo|redis|mssql|elastic|3306|5432|27017|6379",
                capability="network",
            ),
            Requirement(
                r"generic-api-key|password|connection.?string|credential|private-key",
                capability="secrets",
            ),
        ),
        scope="repo",
        explanation=(
            "A database port answering on the network, and a credential "
            "committed to the repository that deploys against it. Neither "
            "finding names the other: the scanner sees a port, the secrets "
            "scan sees a string in git history. The combination is a "
            "reachable database and the means to open it."
        ),
    ),
    CombinationRule(
        rule_id="expired-tls-and-live-endpoint",
        name="Invalid certificate on a service the application depends on",
        requires=(
            Requirement(
                r"expired|self.?signed|weak.?cipher|sslv|tls.?1\.0|certificate",
                capability="network",
            ),
            Requirement(
                r"mixed.?content|cookie|secure.?flag|hsts|transport",
                capability="dast",
            ),
        ),
        scope="repo",
        explanation=(
            "Transport security is failing at both layers: the certificate "
            "or cipher suite on the host is not trustworthy, and the "
            "application is not compensating - cookies without the secure "
            "flag, missing HSTS, or mixed content. Either alone is a hygiene "
            "item; together the session is interceptable in practice rather "
            "than in theory."
        ),
    ),
    CombinationRule(
        rule_id="vulnerable-image-and-live-service",
        name="Exploitable dependency in a running, reachable service",
        requires=(
            # High and above only. Every image carries low-severity CVEs -
            # this repository accepted 243 of them - and without the floor
            # this rule would fire on every repository that runs a web
            # server, which is the definition of a rule nobody reads.
            # Either half of "a known-exploitable component": the built
            # image, or the dependency tree it was built from. Atlas findings
            # are CVE-bearing exactly like container ones — Oracle's KEV boost
            # already reads them generically — so a vulnerable *application*
            # dependency behind a reachable service is the same shape of risk
            # as a vulnerable image layer, and was simply never matched
            # (spec 22 §4).
            Requirement(
                r"CVE-", capability=("containers", "atlas"), min_severity="high"
            ),
            Requirement(
                r"auth|exposed|version|banner|outdated|fingerprint", capability="dast"
            ),
        ),
        scope="repo",
        explanation=(
            "A known-exploitable component in the image or dependency tree, "
            "and a DAST finding showing the service running it is reachable "
            "and disclosing something about itself. A CVE in an image nobody "
            "can reach is backlog; the same CVE behind an endpoint that "
            "answers and names its version is a shortlist."
        ),
    ),
)


#: Ascending, so "at least high" is an index comparison.
_SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")


def _at_least(severity: str, floor: str) -> bool:
    try:
        return _SEVERITY_ORDER.index(severity) >= _SEVERITY_ORDER.index(floor)
    except ValueError:
        # An unrecognised severity is not silently treated as high enough.
        return False


def _matches(requirement: Requirement, finding: dict[str, Any]) -> bool:
    allowed = requirement.capabilities
    if allowed and str(finding.get("capability", "")) not in allowed:
        return False
    if requirement.min_severity is not None and not _at_least(
        str(finding.get("severity", "")), requirement.min_severity
    ):
        return False
    haystack = f"{finding.get('rule_id', '')} {finding.get('title', '')}"
    return re.search(requirement.pattern, haystack, re.IGNORECASE) is not None


def combination_id(rule_id: str, finding_ids: frozenset[str]) -> str:
    """Derived from the rule and its members, so the same combination detected
    twice is the same combination (spec 08 §4)."""
    material = rule_id + "\x00" + "\x00".join(sorted(finding_ids))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def detect(
    findings: list[dict[str, Any]], rules: tuple[CombinationRule, ...] = BUILT_IN_RULES
) -> list[Combination]:
    """Every toxic combination present in this set of findings.

    A finding may appear in at most one combination — the first rule that
    claims it wins, in rule order. Allowing overlap would mean one finding
    generating several draft pull requests, which is the flooding spec 08 §5's
    backpressure exists to prevent, arriving by a different route.
    """
    claimed: set[str] = set()
    combinations: list[Combination] = []

    for rule in rules:
        groups: dict[str, list[dict[str, Any]]] = {}
        for finding in findings:
            if str(finding["finding_id"]) in claimed:
                continue
            key = str(finding.get("file_path") or "") if rule.scope == "file" else "*"
            groups.setdefault(key, []).append(finding)

        for key, group in sorted(groups.items()):
            if rule.scope == "file" and not key:
                continue
            members: set[str] = set()
            for requirement in rule.requires:
                hit = next((f for f in group if _matches(requirement, f)), None)
                if hit is None:
                    members.clear()
                    break
                members.add(str(hit["finding_id"]))
            if len(members) < len(rule.requires):
                continue

            frozen = frozenset(members)
            claimed |= members
            where = f"in `{key}`" if rule.scope == "file" else "in this repository"
            combinations.append(
                Combination(
                    combination_id=combination_id(rule.rule_id, frozen),
                    rule_id=rule.rule_id,
                    finding_ids=frozen,
                    rationale=(
                        f"**{rule.name}** {where}. {rule.explanation} "
                        "Patchwork has not generated a fix: these need to be "
                        "addressed together, and fixing one in isolation would "
                        "close the finding without closing the risk."
                    ),
                )
            )

    return combinations


def kev_boosted(
    combinations: list[Combination],
    findings_by_id: dict[str, dict[str, Any]],
    kev_cve_ids: set[str],
) -> list[Combination]:
    """Prefix a combination's rationale when a member names a KEV-listed CVE
    (spec 17 §5.6).

    Deliberately not a static field on `CombinationRule` — whether *this*
    detected instance involves active exploitation is a fact about the
    findings it matched, not about the rule, and a rule-level flag could not
    say it correctly. `kev_cve_ids` comes from `ThreatIntelMatch` (spec 17
    §4); an empty set (no threat-intel data, or nothing matched) is a no-op,
    so callers with nothing to check pay only the cost of the loop.

    A toxic pair under active exploitation is a different urgency than one
    that merely could be — the prefix says so without changing what rule
    fired or which findings it named.
    """
    if not kev_cve_ids:
        return combinations

    boosted: list[Combination] = []
    for combo in combinations:
        hit_cves: set[str] = set()
        for finding_id in combo.finding_ids:
            finding = findings_by_id.get(finding_id)
            if finding is None:
                continue
            cve_id = extract_cve(
                str(finding.get("rule_id") or ""), str(finding.get("title") or "")
            )
            if cve_id and cve_id in kev_cve_ids:
                hit_cves.add(cve_id)

        if not hit_cves:
            boosted.append(combo)
            continue

        prefix = (
            f"**Actively exploited.** {', '.join(sorted(hit_cves))} — a member "
            "of this combination — is listed in CISA's Known Exploited "
            "Vulnerabilities catalog. "
        )
        boosted.append(replace(combo, rationale=prefix + combo.rationale))

    return boosted
