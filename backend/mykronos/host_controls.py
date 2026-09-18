"""Re-checking a control that lives on the host rather than in a repository.

Every other capability here reads a repository. The control standing between
this estate's deploy registry and an unauthenticated push does not live in one:
`mykronos-registry` runs `registry:2` with no `auth:` block at all, and the only
thing stopping any LAN device from overwriting a tag this host then runs is an
inbound Block rule in Windows Defender Firewall. It was applied once (B-054,
D-109) and nothing has re-read it since.

**The obvious way to re-read it always passes, which is why this module exists.**
The check an operator reaches for is a request to the port:

    $ curl -s http://192.168.0.14:5000/v2/_catalog
    {"repositories":["mykronos-backend","mykronos-frontend","thehub"]}

That reads exactly like an open registry and means nothing at all. Windows
Defender Firewall does not filter traffic from a host to its own addresses, so
that request never touches the rule. It returns the catalog whether the rule is
in force, narrowed, disabled or deleted. The check has three outcomes and looks
like it has two, and the easy one to run is the one that carries no information.

So this module does not probe. It reads the rule: the enabled inbound Block
rules on the port, the address ranges they actually deny, the profiles they
actually apply under, and the prefixes this host is actually on. That is the
difference between a control that is verified and a control that is merely
believed, and it catches every way this control has really been lost —
deletion, disablement, a narrowed remote range, a profile that no longer
matches the interface, and the host moving to a subnet the rule never named.

**Five states, not two.** A check that cannot fail is worth nothing, and so is
a check that cannot say it did not run:

* ``pass`` — read, and the assertion holds.
* ``fail`` — read, and it does not.
* ``unknown`` — the evidence could not be read. Not a pass. `netassess` makes
  the same insistence for the same reason: a NAS that is switched off must not
  read the same as one confirmed closed.
* ``not_evidence`` — the check ran and its result cannot distinguish a pass
  from a failure, **and never could**. The local probe above is the whole
  reason this state exists. It is carried in the report rather than dropped,
  because an operator who does not see it will run it anyway and believe it.
* ``not_measured`` — the check has a subject and could have been established,
  but this run had nothing to establish it against. A `ports.baseline` with no
  recorded baseline is the case: 22 bindings were observed and compared to
  nothing. Unlike ``not_evidence`` this is *fixable*, and the detail says how.

``unknown`` fails a report. ``not_evidence`` and ``not_measured`` neither pass
nor fail one — but a report in which *nothing* is evidence does not pass
either, which is the property that makes "I curled it and it worked" incapable
of producing a green run here.

**Why ``not_measured`` is separate from ``not_evidence`` [#60015].** Collapsing
them loses the only actionable half. ``not_evidence`` is a permanent property
of the check — the local probe will never be evidence no matter how often it is
run, so there is nothing for an operator to do about it. ``not_measured`` is a
property of *this run* — record a baseline and the next run is a comparison. A
report that reads "incomplete" must say which of its checks an operator can
close, and one state cannot say both.

**Completeness is reported separately from correctness, and in the exit code.**
:attr:`Report.ok` answers "did everything I measured hold"; :attr:`Report.complete`
answers "did I measure everything I am supposed to measure". They are different
questions and the defect in #60015 was reporting only the first. The command
exits :data:`EXIT_NOT_MEASURED` when it is ok but not complete, so a control
that inspected nothing cannot be read as one that inspected everything and
found it well.

**Transport is deliberately not here**, exactly as in `netassess`: every
function takes a document already in hand. `deploy/concourse/Get-HostControl
Evidence.ps1` collects it on Windows, because `Get-NetFirewallRule` does not
exist in a Linux container and a container cannot see the host's rules at all.
The judgement is the same however the document arrives.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any, Literal

#: The registry's published port. The control is about this one port; anything
#: else is a different control with a different story.
REGISTRY_PORT = 5000

State = Literal["pass", "fail", "unknown", "not_evidence", "not_measured"]

#: The exit codes this control speaks. Kept as named constants because the
#: whole point of #60015 is that the number carries the verdict: a caller that
#: only knows "0 or not 0" cannot tell a control that passed from one that
#: never ran, and that is the defect. `scripts/bench_grade.py` declares the
#: same four under the same names, and
#: `test_the_two_controls_agree_on_what_the_numbers_mean` fails if they drift.
#:
#: They are duplicated rather than shared because `bench_grade.py` runs as a
#: standalone script inside a pipeline container with no `mykronos` package on
#: the path (`dump_openapi.py` needs a `sys.path` shim to import one). A shared
#: module would buy one definition and cost a runtime import that can fail in
#: the place this most needs to work; a test that pins the two together buys
#: the same guarantee with neither.
EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2
EXIT_NOT_MEASURED = 3

#: Every assertion :func:`assess` is required to produce. This is the floor on
#: what was examined: a report is not allowed to pass by containing fewer
#: checks than it is supposed to. Dropping `firewall.scope` from `assess` and
#: leaving the rest green would otherwise be a passing run, and "the control
#: passed because nobody asked it the hard question" is the failure this module
#: exists to end. [#60015]
EXPECTED_ASSERTIONS = frozenset(
    {
        "firewall.rule_present",
        "firewall.scope",
        "registry.auth",
        "ports.baseline",
        "registry.local_probe",
    }
)

#: `RemoteAddress` values Windows resolves at evaluation time against state this
#: document does not carry. A rule scoped to one of these may or may not cover
#: the prefix in question, and guessing which would be the same mistake as the
#: local probe: an answer that is not derived from anything.
_UNRESOLVABLE_REMOTE = {
    "localsubnet",
    "dns",
    "dhcp",
    "wins",
    "defaultgateway",
    "internet",
    "intranet",
    "playtodevice",
    "remotecorpnetwork",
    "capabilitysid",
}

_ALL_IPV4 = (0, 2**32 - 1)


@dataclass(frozen=True)
class Assertion:
    """One thing said about the host, and how it was established."""

    key: str
    state: State
    detail: str

    @property
    def is_evidence(self) -> bool:
        """Did this assertion establish anything about the host.

        `not_measured` is in here with `not_evidence` [#60015]: a check that had
        nothing to compare against established no more than one that could never
        establish anything. They differ in what an operator can do next, which
        is :attr:`Report.unmeasured`'s job, not this one's.
        """
        return self.state not in ("not_evidence", "not_measured")


@dataclass(frozen=True)
class Report:
    assertions: list[Assertion] = field(default_factory=list)

    @property
    def failures(self) -> list[Assertion]:
        """Everything that is not a pass and is not merely uninformative.

        `unknown` is in here on purpose. A run that could not read the firewall
        is not a run that found it healthy, and the failure mode this whole
        module is about is a check that reports success because it cannot fail.
        """
        return [a for a in self.assertions if a.state in ("fail", "unknown")]

    @property
    def missing_assertions(self) -> list[str]:
        """The floor: checks this report is supposed to contain and does not.

        A report is not allowed to pass by asking fewer questions. Without this,
        deleting an assertion from :func:`assess` turns its subject green rather
        than red — the control keeps reporting, and stops reporting the thing.
        [#60015]
        """
        return sorted(EXPECTED_ASSERTIONS - {a.key for a in self.assertions})

    @property
    def unmeasured(self) -> list[Assertion]:
        """Checks with a subject that this run had nothing to establish against.

        Separate from :attr:`failures` because they are not failures, and
        separate from the permanently-uninformative `not_evidence` because each
        one names something an operator can close. [#60015]
        """
        return [a for a in self.assertions if a.state == "not_measured"]

    @property
    def ok(self) -> bool:
        """Did this run actually verify anything, and did it all hold?

        Three halves now, all load-bearing. A document containing nothing but
        the local probe has no failures at all — and verifies nothing, so it is
        not ok. That is the naive check, and this is the line it cannot cross.
        The floor is the third: a report missing checks it should carry is not
        ok however green what remains is.

        This deliberately does NOT consider :attr:`unmeasured`. "Everything I
        measured held" and "I measured everything" are different claims and
        collapsing them is the #60015 defect in the other direction — see
        :attr:`complete`.
        """
        if self.missing_assertions:
            return False
        if self.failures:
            return False
        return any(a.state == "pass" for a in self.assertions)

    @property
    def complete(self) -> bool:
        """Did this run establish everything it is supposed to establish.

        The question `ok` cannot answer. A run with a green firewall and no
        ports baseline is `ok` and not `complete`, and the whole of #60015 is
        that those two exited with the same number.
        """
        return not self.unmeasured and not self.missing_assertions


def _to_int(address: str) -> int | None:
    try:
        return int(ipaddress.IPv4Address(address.strip()))
    except (ipaddress.AddressValueError, ValueError):
        return None


def parse_remote(spec: str) -> tuple[list[tuple[int, int]], str | None]:
    """One `RemoteAddress` entry as IPv4 spans, or the reason it is not knowable.

    Windows writes this field in at least five shapes and the estate's three
    rules on TCP/5000 already use three of them: `Any`, a dotted-netmask CIDR
    (`192.168.0.0/255.255.255.0`) and a pair of ranges
    (`192.168.0.1-192.168.0.13`, `192.168.0.15-192.168.0.254` — the /24 with
    this host's own `.14` punched out). Parsing only the prefix form would read
    the narrowest of the three as covering nothing and report an exposure that
    is not there.

    An IPv6 entry contributes no IPv4 span and is not an error: it is simply
    not an answer to "is this IPv4 prefix denied". A keyword Windows resolves
    at evaluation time is returned as unresolvable rather than assumed either
    way.
    """
    text = spec.strip()
    if not text:
        return [], "empty RemoteAddress entry"
    if text.lower() == "any":
        return [_ALL_IPV4], None
    if text.lower() in _UNRESOLVABLE_REMOTE:
        return [], f"'{text}' is resolved by Windows at evaluation time"
    if ":" in text:
        # An IPv6 scope. These rules are about an IPv4 LAN; see the module
        # docstring in the collector for why IPv6 is collected but not judged.
        return [], None

    if "-" in text:
        low, _, high = text.partition("-")
        first, last = _to_int(low), _to_int(high)
        if first is None or last is None or first > last:
            return [], f"'{text}' is not an address range this can read"
        return [(first, last)], None

    if "/" in text:
        try:
            network = ipaddress.IPv4Network(text, strict=False)
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
            return [], f"'{text}' is not a network this can read"
        return [(int(network.network_address), int(network.broadcast_address))], None

    single = _to_int(text)
    if single is None:
        return [], f"'{text}' is not an address this can read"
    return [(single, single)], None


def port_matches(spec: str, port: int) -> bool:
    """Does one `LocalPort` entry cover `port`.

    `Any` and `5000-5010` both do, and a rule whose port filter is a service
    keyword (`RPC`) does not name this port.
    """
    text = spec.strip().lower()
    if not text:
        return False
    if text == "any":
        return True
    if "-" in text:
        low, _, high = text.partition("-")
        try:
            return int(low) <= port <= int(high)
        except ValueError:
            return False
    try:
        return int(text) == port
    except ValueError:
        return False


def _subtract(span: tuple[int, int], covered: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """What is left of `span` once every `covered` span is removed."""
    remaining = [span]
    for low, high in covered:
        next_remaining: list[tuple[int, int]] = []
        for start, end in remaining:
            if high < start or low > end:
                next_remaining.append((start, end))
                continue
            if low > start:
                next_remaining.append((start, low - 1))
            if high < end:
                next_remaining.append((high + 1, end))
        remaining = next_remaining
        if not remaining:
            break
    return remaining


def usable_span(network: ipaddress.IPv4Network) -> tuple[int, int]:
    """The addresses a LAN device can actually hold on this prefix.

    The network and broadcast addresses are excluded for anything /30 or wider,
    because no host holds them and no TCP connection arrives from one. It
    matters for the signal rather than for correctness: this estate's older
    `(B-054)` rules deny `.1-.13` and `.15-.254`, and a gap report that listed
    `192.168.0.0`, `192.168.0.14` and `192.168.0.255` buries the one address
    that is a machine somebody could be sitting at among two that are not.
    """
    first, last = int(network.network_address), int(network.broadcast_address)
    if network.prefixlen <= 30:
        return first + 1, last - 1
    return first, last


def _render(spans: list[tuple[int, int]]) -> str:
    out = []
    for low, high in spans:
        first = str(ipaddress.IPv4Address(low))
        out.append(first if low == high else f"{first}-{ipaddress.IPv4Address(high)}")
    return ", ".join(out)


@dataclass(frozen=True)
class Rule:
    """One Windows firewall rule, flattened to what the question needs."""

    display_name: str
    enabled: bool
    direction: str
    action: str
    protocol: str
    local_ports: tuple[str, ...]
    remote_addresses: tuple[str, ...]
    profiles: tuple[str, ...]

    def blocks_port(self, port: int) -> bool:
        return (
            self.enabled
            and self.direction.lower() == "inbound"
            and self.action.lower() == "block"
            and self.protocol.lower() in ("tcp", "any", "6")
            and any(port_matches(entry, port) for entry in self.local_ports)
        )

    def applies_under(self, profile: str) -> bool:
        wanted = profile.strip().lower()
        for entry in self.profiles:
            for part in entry.split(","):
                name = part.strip().lower()
                if name in ("any", wanted):
                    return True
        return False


@dataclass(frozen=True)
class LanAddress:
    """One address this host holds on a real network, and where it sits.

    The profile matters and is easy to lose. This host has `192.168.0.14` on a
    wired interface Windows categorises Private and `192.168.0.19` on wireless
    it categorises Public — one prefix, two profiles. A rule scoped to Private
    alone would cover the first and not the second while reading, in any
    summary that collapsed them, as covering "the LAN".
    """

    prefix: str
    address: str
    interface: str = ""
    profile: str = ""


@dataclass(frozen=True)
class Evidence:
    """A collected document, parsed. Nothing here was inferred."""

    port: int = REGISTRY_PORT
    host: str = ""
    collected_at: str = ""
    lan_addresses: tuple[LanAddress, ...] = ()
    rules: tuple[Rule, ...] = ()
    published_ports: tuple[str, ...] = ()
    registry_auth: dict[str, Any] = field(default_factory=dict)
    local_probe: dict[str, Any] = field(default_factory=dict)
    #: Section name -> why it could not be collected. Every section named here
    #: becomes `unknown`, never a pass.
    errors: dict[str, str] = field(default_factory=dict)


def _strings(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list):
        return tuple(str(item) for item in value)
    return (str(value),)


def parse_evidence(document: dict[str, Any]) -> Evidence:
    """Read a collected document without judging it."""
    addresses = []
    for entry in document.get("lan_addresses") or []:
        addresses.append(
            LanAddress(
                prefix=str(entry.get("prefix", "")),
                address=str(entry.get("address", "")),
                interface=str(entry.get("interface", "") or ""),
                profile=str(entry.get("profile", "") or ""),
            )
        )

    rules = []
    for entry in document.get("firewall_rules") or []:
        rules.append(
            Rule(
                display_name=str(entry.get("display_name", "")),
                enabled=bool(entry.get("enabled", False)),
                direction=str(entry.get("direction", "")),
                action=str(entry.get("action", "")),
                protocol=str(entry.get("protocol", "")),
                local_ports=_strings(entry.get("local_ports")),
                remote_addresses=_strings(entry.get("remote_addresses")),
                profiles=_strings(entry.get("profiles")),
            )
        )

    return Evidence(
        port=int(document.get("port") or REGISTRY_PORT),
        host=str(document.get("host", "") or ""),
        collected_at=str(document.get("collected_at", "") or ""),
        lan_addresses=tuple(addresses),
        rules=tuple(rules),
        published_ports=_strings(document.get("published_ports")),
        registry_auth=dict(document.get("registry_auth") or {}),
        local_probe=dict(document.get("local_probe") or {}),
        errors={str(k): str(v) for k, v in (document.get("errors") or {}).items()},
    )


def assert_rule_present(evidence: Evidence) -> Assertion:
    """Is there an enabled inbound Block rule on the port at all.

    Separate from scope because the two fail for different reasons and want
    different responses: a missing rule is `Set-RegistryScope.ps1 -Remove`, a
    reboot, or an uninstall, and a narrowed one is somebody editing.
    """
    if "firewall_rules" in evidence.errors:
        return Assertion(
            "firewall.rule_present",
            "unknown",
            f"The firewall rules could not be read: {evidence.errors['firewall_rules']}",
        )

    blocking = [rule for rule in evidence.rules if rule.blocks_port(evidence.port)]
    if not blocking:
        disabled = [
            rule.display_name
            for rule in evidence.rules
            if not rule.enabled
            and rule.action.lower() == "block"
            and any(port_matches(entry, evidence.port) for entry in rule.local_ports)
        ]
        detail = (
            f"No enabled inbound Block rule covers TCP/{evidence.port}. The registry "
            "has no auth: block, so nothing else stands between a LAN device and a "
            "write to a tag this host runs (B-054, D-109)."
        )
        if disabled:
            detail += " Disabled rule(s) naming the port: " + ", ".join(sorted(disabled))
        return Assertion("firewall.rule_present", "fail", detail)

    return Assertion(
        "firewall.rule_present",
        "pass",
        f"{len(blocking)} enabled inbound Block rule(s) on TCP/{evidence.port}: "
        + ", ".join(sorted({rule.display_name for rule in blocking})),
    )


def assert_scope(evidence: Evidence) -> Assertion:
    """Is every LAN address this host holds actually inside what is denied.

    Computed per address and per profile, because a rule only applies to the
    profiles it names and only denies the ranges it lists. Windows evaluates
    Block before Allow, so the union of the blocking rules is what is denied
    and the strictest rule is not the one that matters — the widest one is.

    The failure this catches is the one that has actually happened here.
    `Set-RegistryScope.ps1` manages one rule; two older `(B-054)` rules deny
    the /24 with this host's own `.14` carved out. Delete the newest and the
    remaining pair still look like "the LAN is blocked" in any listing, while
    leaving an address uncovered. Nothing but arithmetic on the ranges says so.
    """
    if "firewall_rules" in evidence.errors:
        return Assertion(
            "firewall.scope",
            "unknown",
            f"The firewall rules could not be read: {evidence.errors['firewall_rules']}",
        )
    if "lan_addresses" in evidence.errors:
        return Assertion(
            "firewall.scope",
            "unknown",
            f"This host's own addresses could not be read: {evidence.errors['lan_addresses']}",
        )
    if not evidence.lan_addresses:
        return Assertion(
            "firewall.scope",
            "unknown",
            "No LAN address was collected, so there is no prefix to check the rule "
            "against. A rule denying a subnet this host has left protects nothing "
            "while looking like it does.",
        )

    blocking = [rule for rule in evidence.rules if rule.blocks_port(evidence.port)]
    gaps: list[str] = []
    unknowns: list[str] = []

    for lan in evidence.lan_addresses:
        try:
            network = ipaddress.IPv4Network(lan.prefix, strict=False)
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
            unknowns.append(f"{lan.address}: '{lan.prefix}' is not a prefix this can read")
            continue
        if not lan.profile:
            unknowns.append(
                f"{lan.address} ({lan.interface or 'unknown interface'}): no network "
                "profile, so which rules apply to it cannot be determined"
            )
            continue

        covered: list[tuple[int, int]] = []
        unreadable: list[str] = []
        for rule in blocking:
            if not rule.applies_under(lan.profile):
                continue
            for entry in rule.remote_addresses:
                spans, why = parse_remote(entry)
                covered.extend(spans)
                if why:
                    unreadable.append(f"{rule.display_name}: {why}")

        remaining = _subtract(usable_span(network), covered)
        if remaining and unreadable:
            unknowns.append(
                f"{lan.prefix} under {lan.profile}: {_render(remaining)} is not covered "
                "by any range this could read, and " + "; ".join(sorted(set(unreadable)))
            )
        elif remaining:
            gaps.append(
                f"{lan.prefix} under the {lan.profile} profile "
                f"(this host is {lan.address} on {lan.interface or 'an interface'}): "
                f"{_render(remaining)} is not denied"
            )

    if gaps:
        return Assertion(
            "firewall.scope",
            "fail",
            "The deny rules do not cover the whole LAN this host is on. "
            + " | ".join(gaps),
        )
    if unknowns:
        return Assertion("firewall.scope", "unknown", " | ".join(unknowns))
    return Assertion(
        "firewall.scope",
        "pass",
        "Every LAN address this host holds is inside a denied range under its own "
        "profile: " + ", ".join(f"{lan.address} ({lan.profile})" for lan in evidence.lan_addresses),
    )


def assert_registry_auth(evidence: Evidence) -> Assertion:
    """Is the firewall rule still the only thing holding this up.

    Not a vulnerability check. The registry having no authentication is a
    recorded trade-off — binding to loopback would kill kaniko's push — and the
    consequence is that the scope rule is load-bearing. If the registry ever
    gains an `auth:` block the story changes and the recorded compensating
    control goes stale, which is worth a line either way rather than silence.
    """
    if "registry_auth" in evidence.errors:
        return Assertion(
            "registry.auth",
            "unknown",
            f"The registry's configuration could not be read: {evidence.errors['registry_auth']}",
        )
    if not evidence.registry_auth:
        return Assertion(
            "registry.auth",
            "unknown",
            "Nothing was collected about the registry's authentication, so whether "
            "the firewall rule is still the only control is not established.",
        )

    detail = str(evidence.registry_auth.get("detail", "") or "")
    if evidence.registry_auth.get("configured"):
        return Assertion(
            "registry.auth",
            "fail",
            "The registry now has authentication configured. That is an improvement "
            "and the recorded control is out of date: #268 records firewall scope as "
            "the sole compensating control for a registry with no auth. "
            + detail,
        )
    return Assertion(
        "registry.auth",
        "pass",
        "The registry still has no auth: block, so the firewall rule remains the only "
        "control on it and is worth re-checking. " + detail,
    )


def assert_published_ports(
    evidence: Evidence, baseline: list[str] | None
) -> Assertion:
    """Has the set of things this host publishes to every interface grown.

    A new `0.0.0.0` binding is the event that would need a new rule, and it is
    the one thing on this list that arrives without anybody deciding to expose
    anything — a compose file gains a port mapping and the host gains a service.
    """
    if "published_ports" in evidence.errors:
        return Assertion(
            "ports.baseline",
            "unknown",
            f"The published ports could not be read: {evidence.errors['published_ports']}",
        )
    if baseline is None:
        return Assertion(
            "ports.baseline",
            "not_measured",
            f"No recorded baseline, so this run can neither pass nor fail: "
            f"{len(evidence.published_ports)} binding(s) observed and compared to "
            "nothing. Record this run with --record-ports and the next one "
            "becomes a comparison.",
        )

    added = sorted(set(evidence.published_ports) - set(baseline))
    removed = sorted(set(baseline) - set(evidence.published_ports))
    if added:
        detail = "New binding(s) since the baseline: " + "; ".join(added)
        if removed:
            detail += ". Gone: " + "; ".join(removed)
        return Assertion("ports.baseline", "fail", detail + ". Each needs its own decision.")
    if removed:
        return Assertion(
            "ports.baseline",
            "pass",
            "Nothing new is published. Gone since the baseline: " + "; ".join(removed),
        )
    return Assertion(
        "ports.baseline",
        "pass",
        f"The {len(evidence.published_ports)} published binding(s) match the baseline.",
    )


def assert_local_probe(evidence: Evidence) -> Assertion:
    """The check everybody runs, kept in the report and labelled.

    Always `not_evidence`, whatever it returned. It is here because deleting it
    does not stop anyone running it: an operator who curls the registry from
    this host gets the catalog and a feeling of having checked something. The
    report says, in the same table as the real assertions, that the feeling is
    unearned.
    """
    if not evidence.local_probe:
        return Assertion(
            "registry.local_probe",
            "not_evidence",
            "Not run. It would prove nothing either way: Windows Defender Firewall "
            "does not filter traffic from a host to its own addresses.",
        )
    url = str(evidence.local_probe.get("url", "") or "the registry")
    status = evidence.local_probe.get("status_code")
    outcome = f"answered HTTP {status}" if status else "did not answer"
    return Assertion(
        "registry.local_probe",
        "not_evidence",
        f"{url} {outcome} from this host, and that is the same result the rule "
        "being deleted would give. Windows does not filter host-to-self traffic, so "
        "this request never reaches the rule. Only a request from another LAN host "
        "tests it; firewall.scope reads the rule instead.",
    )


def assess(evidence: Evidence, *, ports_baseline: list[str] | None = None) -> Report:
    """Every assertion, in the order an operator should read them."""
    return Report(
        assertions=[
            assert_rule_present(evidence),
            assert_scope(evidence),
            assert_registry_auth(evidence),
            assert_published_ports(evidence, ports_baseline),
            assert_local_probe(evidence),
        ]
    )


def verdict(report: Report) -> str:
    """The one line an operator reads after the table.

    Five outcomes, because the failure this module exists to end is a check
    with more outcomes than it reports. The order is precedence, most specific
    first: something that failed outranks something that was never asked, and a
    document that establishes nothing at all is described as that rather than as
    a list of the checks it happens to be missing.
    """
    if report.failures:
        return "NOT VERIFIED: " + ", ".join(
            f"{a.key} ({a.state})" for a in report.failures
        )
    if not any(a.is_evidence for a in report.assertions):
        return (
            "NOTHING WAS VERIFIED. This document carries no evidence: every check in "
            "it returns the same answer whether the control holds or not."
        )
    if report.missing_assertions:
        return (
            "INCOMPLETE REPORT: this document is missing "
            + ", ".join(report.missing_assertions)
            + ". It is not a pass and not a failure — it is fewer questions than "
            "this control is defined to ask, so what remains green says nothing "
            "about what is absent."
        )
    if report.unmeasured:
        return (
            "VERIFIED IN PART, AND NOT MEASURED: "
            + ", ".join(a.key for a in report.unmeasured)
            + ". What was read holds. The listed check has a subject and was "
            "compared to nothing, so this run is not a pass for it — see each "
            "detail for what closes it."
        )
    return (
        "VERIFIED. Read from the firewall rule itself, not from a request to "
        "the port — a request from this host would have said this either way."
    )


def summarise(report: Report, evidence: Evidence) -> str:
    """One human-readable block, the way `netassess.summarise` reads."""
    lines = []
    if evidence.host or evidence.collected_at:
        lines.append(
            f"host: {evidence.host or 'unnamed'} "
            f"collected: {evidence.collected_at or '?'}"
        )
    for assertion in report.assertions:
        lines.append(f"{assertion.state:>12}  {assertion.key}")
        lines.append(f"              {assertion.detail}")
    lines.append("")
    lines.append(verdict(report))
    return "\n".join(lines)
