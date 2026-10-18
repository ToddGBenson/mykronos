"""Machine-collected evidence about whether a control holds (TheHub #60826).

**Why this exists.** Everything the threat model holds is declared: a person
says an entry point is `internal`, a person says a gate stands in front of an
API. The environmental CVSS work (epic #60822) wants to lower scores on facts
like those, and D-106 already says what lowering on a person's word costs. So
the scorer is only allowed to lower on *observations* - a row here, written by
a collector that names where it stood (`vantage`), what it ran (`tool`), when
(`collected_at`) and what it saw (`state`).

**The vocabulary is closed.** Seven assertions, five states, three vantages.
A register where one collector writes `port_open` and another `published` can
not be queried, and an assertion the scorer has no rule for is noise it would
have to learn to ignore.

**Five states, and only two are evidence.** `host_controls` defines them and
the reasons carry over unchanged: `pass` / `fail` say the assertion was read
and does or does not hold; `unknown` says it could not be read; `not_evidence`
and `not_measured` say the check cannot, or this run did not, establish it.
`pass` means *the assertion is true*, not *the result is good*: a
`port_published` that passes means the port IS published.

**A run that resolves nothing records `unknown`, never `pass`.** Every
translator below emits an `unknown` row for a section it could not read, or
read and found empty, rather than emitting nothing - "nothing was recorded"
and "nothing is published" must not look the same.

**Linking.** When a collector does not name a surface, `record` links the
observation to the most specific surface whose `selectors` (TheHub #60825,
`surface_match`) cover its subject - `hostnames` for a hostname, `addresses`
for `host:port`, and for a tunnel rule also the local service it routes to -
and to the one control guarding that surface whose kind the assertion speaks
to (`ASSERTION_CONTROL_KINDS`).

**Contradiction.** `surfaces.CONTRADICTED_BY` names what can contradict an
`internal` or `local` declaration - `network` (a port reachable from outside)
and `published_ingress` (a tunnel or proxy config naming it). `contradictions`
below is the reader of that table. A surface is matched by its `selectors`;
only a surface with no `addresses` or `hostnames` selector falls back to its
text - a hostname it names, or a port (`tcp/8002`, `:8002`) for address
subjects and tunnel services.
"""

from __future__ import annotations

import ipaddress
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

import yaml
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from mykronos import host_controls, surface_match, surfaces
from mykronos.db.models import ControlObservation, RepoControl, RepoSurface
from mykronos.schemas import utcnow

#: What a collector may assert. Closed: adding one is a code change with a
#: reason, not a payload a collector invents.
ASSERTIONS = (
    "port_published",
    "anonymous_401",
    "header_csp",
    "header_hsts",
    "bound_loopback",
    "firewall_scope",
    "ingress_published",
)

#: `host_controls`' five states, in the order an operator reads them.
STATES: tuple[str, ...] = ("pass", "fail", "unknown", "not_evidence", "not_measured")

#: The only states that establish anything.
EVIDENCE_STATES = ("pass", "fail")

#: Where the collector stood. `internet`: outside, through public DNS (the
#: exposure sweep). `lan`: another host on the network (nmap from the Windows
#: host). `host`: on the machine itself (docker, cloudflared, the firewall).
VANTAGES = ("internet", "lan", "host")

#: An observation older than this lowers nothing and contradicts nothing (the
#: S5 core rule, "observation fresh <= 14 days").
FRESH_DAYS = 14

#: How far into the future a `collected_at` may be before it is refused - a
#: little clock skew between a collector and this host is normal.
_FUTURE_SKEW = timedelta(minutes=10)

_SUBJECT_CHARS = re.compile(r"^[A-Za-z0-9._\-\[\]:/%]+$")
_ID_CHARS = re.compile(r"^[A-Za-z0-9\-]{1,36}$")


class ObservationError(ValueError):
    """An observation the register will not accept."""


@dataclass(frozen=True)
class Subject:
    """What an observation is about, parsed."""

    raw: str
    surface_id: str | None = None
    control_id: str | None = None
    host: str | None = None
    port: int | None = None


def parse_subject(subject: str) -> Subject:
    """`surface:<id>` | `control:<id>` | `host:port` | `hostname`.

    Hostnames are lower-cased; DNS is case-insensitive and a matcher that
    compares `Demo.example.net` to `demo.example.net` must not miss.
    """
    text = (subject or "").strip()
    if not text or len(text) > 255:
        raise ObservationError("A subject is 1-255 characters.")
    for prefix in ("surface:", "control:"):
        if text.startswith(prefix):
            ident = text[len(prefix) :]
            if not _ID_CHARS.match(ident):
                raise ObservationError(f"{text!r}: {prefix[:-1]} id is not an id.")
            if prefix == "surface:":
                return Subject(raw=text, surface_id=ident)
            return Subject(raw=text, control_id=ident)
    if not _SUBJECT_CHARS.match(text):
        raise ObservationError(
            f"{text!r} is not a subject: expected surface:<id>, control:<id>, "
            "host:port or a hostname."
        )
    lowered = text.lower()
    bracketed = re.match(r"^\[([0-9a-f:.%]+)\](?::(\d+))?$", lowered)
    if bracketed:
        return Subject(raw=lowered, host=bracketed.group(1), port=_port(bracketed.group(2)))
    if lowered.count(":") == 1:
        host, _, port = lowered.partition(":")
        if not host:
            raise ObservationError(f"{text!r} has a port and no host.")
        return Subject(raw=lowered, host=host, port=_port(port))
    return Subject(raw=lowered, host=lowered)


def _port(text: str | None) -> int | None:
    if text is None:
        return None
    if not text.isdigit() or not 0 < int(text) <= 65535:
        raise ObservationError(f"{text!r} is not a port.")
    return int(text)


@dataclass
class Observed:
    """One observation before it is stored. Collectors build these."""

    subject: str
    assertion: str
    state: str
    vantage: str
    tool: str = ""
    tool_version: str = ""
    collected_at: datetime | None = None
    raw_ref: str = ""
    detail: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    surface_id: str | None = None
    control_id: str | None = None


def _naive_utc(when: datetime | None) -> datetime:
    if when is None:
        return utcnow()
    if when.tzinfo is not None:
        return when.astimezone(UTC).replace(tzinfo=None)
    return when


def _parse_when(text: Any) -> datetime | None:
    if not text:
        return None
    try:
        return _naive_utc(datetime.fromisoformat(str(text).replace("Z", "+00:00")))
    except ValueError:
        return None


def validate(observed: Observed) -> Subject:
    """Refuse anything outside the vocabulary, before anything is written."""
    if observed.assertion not in ASSERTIONS:
        raise ObservationError(
            f"{observed.assertion!r} is not an assertion. Expected one of: {', '.join(ASSERTIONS)}."
        )
    if observed.state not in STATES:
        raise ObservationError(
            f"{observed.state!r} is not a state. Expected one of: {', '.join(STATES)}."
        )
    if observed.vantage not in VANTAGES:
        raise ObservationError(
            f"{observed.vantage!r} is not a vantage. Expected one of: {', '.join(VANTAGES)}."
        )
    when = _naive_utc(observed.collected_at)
    if when > utcnow() + _FUTURE_SKEW:
        raise ObservationError(
            f"collected_at {when.isoformat()} is in the future; check the collector's clock."
        )
    return parse_subject(observed.subject)


def record(
    session: Session, repo_full_name: str, batch: list[Observed], *, collector: str
) -> list[ControlObservation]:
    """Validate the whole batch, then store it. All or nothing.

    A `surface:` / `control:` subject, or an explicit link, must name a row of
    this repository - an id from elsewhere cannot reach across, the rule
    `surfaces.remove` keeps for the same reason.
    """
    rows: list[ControlObservation] = []
    linker = _Linker(session, repo_full_name)
    for observed in batch:
        subject = validate(observed)
        surface_id = observed.surface_id or subject.surface_id
        control_id = observed.control_id or subject.control_id
        if surface_id is None and control_id is None and subject.host:
            surface_id = linker.surface_for(subject, observed.evidence)
            if surface_id is not None:
                control_id = linker.control_for(surface_id, observed.assertion)
        if surface_id is not None:
            surface = session.get(RepoSurface, surface_id)
            if surface is None or surface.repo_full_name != repo_full_name:
                raise ObservationError(f"No surface {surface_id!r} in {repo_full_name}.")
        if control_id is not None:
            control = session.get(RepoControl, control_id)
            if control is None or control.repo_full_name != repo_full_name:
                raise ObservationError(f"No control {control_id!r} in {repo_full_name}.")
        rows.append(
            ControlObservation(
                repo_full_name=repo_full_name,
                subject=subject.raw,
                surface_id=surface_id,
                control_id=control_id,
                assertion=observed.assertion,
                state=observed.state,
                vantage=observed.vantage,
                tool=observed.tool[:64],
                tool_version=observed.tool_version[:64],
                collected_at=_naive_utc(observed.collected_at),
                raw_ref=observed.raw_ref[:512],
                collector=collector[:255],
                detail=observed.detail[:4000],
                evidence=dict(observed.evidence),
            )
        )
    session.add_all(rows)
    session.flush()
    return rows


#: The control kinds (controls.CONTROL_KINDS) an assertion is evidence about.
#: An observation is linked to a control only when exactly one control of
#: these kinds guards the matched surface: two candidates is a guess.
ASSERTION_CONTROL_KINDS: dict[str, tuple[str, ...]] = {
    "anonymous_401": ("perimeter_gate",),
    "header_csp": ("security_headers",),
    "header_hsts": ("security_headers",),
    "firewall_scope": ("network_segmentation",),
    "bound_loopback": ("network_segmentation", "container_hardening"),
}


def _probes(subject: Subject, evidence: dict[str, Any] | None) -> list[dict[str, Any]]:
    """The subject as `surface_match` network findings.

    A hostname is matched against `hostnames` (and, with a port, `addresses`);
    a tunnel rule also as the local service it routes to, so a surface located
    at `127.0.0.1:8002` or `*:8002` is the one a tunnel to localhost:8002
    publishes.
    """
    host = subject.host or ""
    is_ip = _is_address(host)
    probes: list[dict[str, Any]] = [
        {
            "address": host,
            "port": subject.port,
            "raw_finding_json": {} if is_ip else {"hostname": host},
        }
    ]
    service = str((evidence or {}).get("service") or "")
    service_port = (evidence or {}).get("service_port")
    if service and isinstance(service_port, int):
        try:
            service_host = urlsplit(service).hostname or ""
        except ValueError:
            service_host = ""
        if service_host:
            probes.append(
                {"address": service_host, "port": service_port, "raw_finding_json": {}}
            )
    return probes


def _selector_matches(subject: Subject, evidence: dict[str, Any] | None, declared: Any) -> Any:
    best: Any = None
    for probe in _probes(subject, evidence):
        for match in surface_match.matches(probe, declared, capability="network"):
            if best is None or match.specificity > best.specificity:
                best = match
    return best


def _locates_network(surface: RepoSurface) -> bool:
    selectors = surface.selectors if isinstance(surface.selectors, dict) else {}
    return bool(selectors.get("addresses") or selectors.get("hostnames"))


class _Linker:
    """Finds, once per batch, the surface and control a subject belongs to."""

    def __init__(self, session: Session, repo_full_name: str) -> None:
        self.session = session
        self.repo_full_name = repo_full_name
        self._surfaces: list[RepoSurface] | None = None

    def surface_for(self, subject: Subject, evidence: dict[str, Any]) -> str | None:
        if self._surfaces is None:
            self._surfaces = list(
                self.session.scalars(
                    select(RepoSurface).where(RepoSurface.repo_full_name == self.repo_full_name)
                ).all()
            )
        best = _selector_matches(subject, evidence, self._surfaces)
        return str(best.surface.id) if best is not None else None

    def control_for(self, surface_id: str, assertion: str) -> str | None:
        kinds = ASSERTION_CONTROL_KINDS.get(assertion)
        if not kinds:
            return None
        found = self.session.scalars(
            select(RepoControl.id).where(
                RepoControl.repo_full_name == self.repo_full_name,
                RepoControl.applies_to_surface_id == surface_id,
                RepoControl.kind.in_(kinds),
            )
        ).all()
        return str(found[0]) if len(found) == 1 else None


def by_state(rows: list[ControlObservation]) -> dict[str, int]:
    return dict(Counter(r.state for r in rows))


def latest(session: Session, repo_full_name: str) -> list[ControlObservation]:
    """The newest observation per (subject, assertion) for one repository."""
    newest = (
        select(
            ControlObservation.subject,
            ControlObservation.assertion,
            func.max(ControlObservation.collected_at).label("at"),
        )
        .where(ControlObservation.repo_full_name == repo_full_name)
        .group_by(ControlObservation.subject, ControlObservation.assertion)
        .subquery()
    )
    rows = session.scalars(
        select(ControlObservation)
        .join(
            newest,
            (ControlObservation.subject == newest.c.subject)
            & (ControlObservation.assertion == newest.c.assertion)
            & (ControlObservation.collected_at == newest.c.at),
        )
        .where(ControlObservation.repo_full_name == repo_full_name)
        .order_by(ControlObservation.subject, ControlObservation.assertion)
    ).all()
    # Two rows collected in the same instant (one batch) keep the later write.
    out: dict[tuple[str, str], ControlObservation] = {}
    for row in rows:
        key = (row.subject, row.assertion)
        if key not in out or row.received_at >= out[key].received_at:
            out[key] = row
    return list(out.values())


def is_fresh(row: ControlObservation, now: datetime | None = None) -> bool:
    return row.collected_at >= (now or utcnow()) - timedelta(days=FRESH_DAYS)


# ---------------------------------------------------------------------------
# The host collector's document (deploy/concourse/Publish-ControlObservations.ps1)
# ---------------------------------------------------------------------------

HOST_DOCUMENT_SCHEMA = "mykronos.host-observations/1"
HOST_TOOL = "Publish-ControlObservations.ps1"


def from_host_document(document: dict[str, Any]) -> list[Observed]:
    """Translate what the host collector read into observations.

    The collector reads; this judges - the split `host_controls` already
    makes, for the same reason: the judgement is here, in Python, under test,
    and the PowerShell stays a reader that cannot quietly pass anything.
    """
    host = str(document.get("host") or "host").strip().lower() or "host"
    errors = {str(k): str(v) for k, v in (document.get("errors") or {}).items()}
    when = _parse_when(document.get("collected_at")) or utcnow()
    version = str(document.get("collector_version") or "")

    def make(subject: str, assertion: str, state: str, detail: str, **evidence: Any) -> Observed:
        return Observed(
            subject=subject,
            assertion=assertion,
            state=state,
            vantage="host",
            tool=HOST_TOOL,
            tool_version=version,
            collected_at=when,
            detail=detail,
            evidence=evidence,
        )

    out: list[Observed] = []
    out += _docker(document.get("docker"), errors.get("docker"), host, make)
    out += _cloudflared(document.get("cloudflared"), errors.get("cloudflared"), host, make)
    out += _firewall(document.get("host_controls"), errors.get("host_controls"), host, when)
    return out


def _docker(section: Any, error: str | None, host: str, make: Any) -> list[Observed]:
    if error or not isinstance(section, dict):
        why = (
            f"docker could not be read: {error}"
            if error
            else "docker was not collected by this run"
        )
        return [
            make(host, "port_published", "unknown", why),
            make(host, "bound_loopback", "unknown", why),
        ]

    # Host port -> every binding docker reports for it. Docker lists 0.0.0.0
    # and :: separately for one mapping; they are one port, and it is bound to
    # loopback only if every binding is.
    bindings: dict[int, list[dict[str, str]]] = {}
    for container in section.get("containers") or []:
        name = str(container.get("name") or "")
        for container_port, mapped in (container.get("ports") or {}).items():
            for binding in mapped or []:
                host_port = str(binding.get("HostPort") or "")
                if not host_port.isdigit():
                    continue
                bindings.setdefault(int(host_port), []).append(
                    {
                        "container": name,
                        "container_port": str(container_port),
                        "host_ip": str(binding.get("HostIp") or ""),
                    }
                )

    if not bindings:
        return [
            make(
                host,
                "port_published",
                "unknown",
                "docker was read and publishes no port to any interface; nothing resolved "
                "to a subject, which is recorded rather than passed.",
            )
        ]

    out: list[Observed] = []
    for port, found in sorted(bindings.items()):
        subject = f"{host}:{port}"
        addresses = sorted({b["host_ip"] for b in found})
        loopback = all(_is_loopback(a) for a in addresses)
        evidence = {
            "container": found[0]["container"],
            "container_port": found[0]["container_port"],
            "host_ips": addresses,
        }
        out.append(
            make(
                subject,
                "port_published",
                "pass",
                f"{found[0]['container']} publishes {found[0]['container_port']} on "
                f"{', '.join(a or '*' for a in addresses)}:{port}",
                **evidence,
            )
        )
        out.append(
            make(
                subject,
                "bound_loopback",
                "pass" if loopback else "fail",
                (
                    f"bound to loopback only ({', '.join(addresses)})"
                    if loopback
                    else f"bound beyond loopback ({', '.join(a or '*' for a in addresses)})"
                ),
                **evidence,
            )
        )
    return out


def _is_loopback(address: str) -> bool:
    try:
        return ipaddress.ip_address(address).is_loopback
    except ValueError:
        return False


def parse_ingress(config_text: str) -> list[tuple[str, str]]:
    """`(hostname, service)` for every hostname rule in a cloudflared config.

    Raises ValueError for a config that is not the YAML cloudflared reads.
    The catch-all rule (no hostname) publishes nothing by name and is skipped.
    """
    try:
        config = yaml.safe_load(config_text)
    except yaml.YAMLError as exc:
        raise ValueError(f"not YAML: {exc}") from exc
    if not isinstance(config, dict):
        raise ValueError("not a cloudflared config (no mapping at the top)")
    rules = config.get("ingress")
    if not isinstance(rules, list):
        raise ValueError("no ingress: list")
    out = []
    for rule in rules:
        if isinstance(rule, dict) and rule.get("hostname"):
            out.append((str(rule["hostname"]).strip().lower(), str(rule.get("service") or "")))
    return out


def _service_port(service: str) -> int | None:
    parts = urlsplit(service)
    if parts.scheme not in ("http", "https", "tcp", "ssh", "rdp", "unix") or not parts.hostname:
        return None
    try:
        if parts.port is not None:
            return parts.port
    except ValueError:
        return None
    return {"http": 80, "https": 443, "ssh": 22, "rdp": 3389}.get(parts.scheme)


def _cloudflared(section: Any, error: str | None, host: str, make: Any) -> list[Observed]:
    if error or not isinstance(section, dict):
        why = (
            f"the cloudflared config could not be read: {error}"
            if error
            else "no cloudflared config was collected by this run"
        )
        return [make(host, "ingress_published", "unknown", why)]
    path = str(section.get("path") or "")
    try:
        rules = parse_ingress(str(section.get("config_text") or ""))
    except ValueError as exc:
        return [
            make(
                host,
                "ingress_published",
                "unknown",
                f"{path or 'the cloudflared config'} could not be read as one: {exc}",
                config_path=path,
            )
        ]
    if not rules:
        return [
            make(
                host,
                "ingress_published",
                "unknown",
                f"{path or 'the cloudflared config'} names no hostname; nothing resolved.",
                config_path=path,
            )
        ]
    return [
        make(
            hostname,
            "ingress_published",
            "pass",
            f"cloudflared routes {hostname} to {service or '(no service)'}",
            service=service,
            service_port=_service_port(service),
            config_path=path,
        )
        for hostname, service in rules
    ]


def _firewall(section: Any, error: str | None, host: str, when: datetime) -> list[Observed]:
    """The registry's LAN scope, judged by `host_controls.assert_scope`."""
    if error or not isinstance(section, dict):
        why = (
            f"the firewall evidence could not be collected: {error}"
            if error
            else "no firewall evidence was collected by this run"
        )
        return [
            Observed(
                subject=host,
                assertion="firewall_scope",
                state="unknown",
                vantage="host",
                tool="host_controls",
                collected_at=when,
                detail=why,
            )
        ]
    evidence = host_controls.parse_evidence(section)
    judged = host_controls.assert_scope(evidence)
    return [
        Observed(
            subject=f"{(evidence.host or host).lower()}:{evidence.port}",
            assertion="firewall_scope",
            state=judged.state,
            vantage="host",
            tool="host_controls",
            collected_at=_parse_when(evidence.collected_at) or when,
            detail=judged.detail,
            evidence={"port": evidence.port},
        )
    ]


# ---------------------------------------------------------------------------
# Contradiction
# ---------------------------------------------------------------------------

#: Which observation stands for each `surfaces.CONTRADICTED_BY` source.
SOURCE_ASSERTIONS = {"network": "port_published", "published_ingress": "ingress_published"}

_PORT_IN_TEXT = re.compile(r"(?:\btcp/|\budp/|:|\bport\s+)(\d{1,5})\b", re.IGNORECASE)


@dataclass(frozen=True)
class Contradiction:
    """One fresh observation that says a surface's exposure claim is wrong."""

    surface_id: str
    source: str
    assertion: str
    subject: str
    vantage: str
    state: str
    tool: str
    collector: str
    collected_at: datetime
    detail: str


def _source(row: ControlObservation, exposure: str) -> str | None:
    """Which `CONTRADICTED_BY` source this row is, for a claim of `exposure`.

    `port_published` from the internet contradicts both claims. From the LAN
    it contradicts only `local`: `internal` *means* reachable on the LAN, so a
    LAN scan finding the port open is the claim holding. From the host itself
    it contradicts nothing - every published port answers its own host.
    """
    if row.assertion == "ingress_published":
        return "published_ingress"
    if row.assertion == "port_published":
        if row.vantage == "internet":
            return "network"
        if row.vantage == "lan" and exposure == "local":
            return "network"
    return None


def _surface_ports(text: str) -> set[int]:
    return {int(m) for m in _PORT_IN_TEXT.findall(text) if 0 < int(m) <= 65535}


def _names_host(text: str, host: str) -> bool:
    pattern = r"(?<![a-z0-9.\-])" + re.escape(host) + r"(?![a-z0-9\-]|\.[a-z0-9])"
    return re.search(pattern, text) is not None


def _is_address(host: str) -> bool:
    try:
        ipaddress.ip_network(host, strict=False)
    except ValueError:
        return False
    return True


def _matches(surface: RepoSurface, row: ControlObservation) -> bool:
    if row.surface_id is not None:
        return row.surface_id == surface.id
    try:
        subject = parse_subject(row.subject)
    except ObservationError:
        return False
    if subject.surface_id or subject.control_id:
        return False
    if _locates_network(surface):
        # Located: the selectors decide, and the text is not consulted.
        return _selector_matches(subject, row.evidence, [surface]) is not None
    text = " ".join(
        part for part in (surface.name, surface.description, surface.evidence_ref) if part
    ).lower()
    host = subject.host or ""
    if host and not _is_address(host) and _names_host(text, host):
        return True
    # A port match only where the port is the identity: an address subject
    # (a LAN scan), or the local service a tunnel routes to. A public
    # hostname's :443 says nothing about every surface that mentions 443.
    ports: set[int] = set()
    if host and _is_address(host) and subject.port is not None:
        ports.add(subject.port)
    service_port = (row.evidence or {}).get("service_port")
    if isinstance(service_port, int):
        ports.add(service_port)
    return bool(ports & _surface_ports(text))


def contradictions(
    declared: list[RepoSurface],
    rows: list[ControlObservation],
    now: datetime | None = None,
) -> dict[str, list[Contradiction]]:
    """Surface id -> the fresh observations contradicting its exposure claim.

    Reads `surfaces.CONTRADICTED_BY` rather than restating it: `internet` and
    `unknown` have no key there, so nothing contradicts them here either.
    Only a `pass` counts - `port_published` passing is the port being
    published - and only within `FRESH_DAYS`.
    """
    now = now or utcnow()
    found: dict[str, list[Contradiction]] = {}
    for surface in declared:
        sources = surfaces.CONTRADICTED_BY.get(surface.exposure)
        if not sources:
            continue
        for row in rows:
            if row.state != "pass" or not is_fresh(row, now):
                continue
            source = _source(row, surface.exposure)
            if source is None or source not in sources:
                continue
            if not _matches(surface, row):
                continue
            found.setdefault(surface.id, []).append(
                Contradiction(
                    surface_id=surface.id,
                    source=source,
                    assertion=row.assertion,
                    subject=row.subject,
                    vantage=row.vantage,
                    state=row.state,
                    tool=row.tool,
                    collector=row.collector,
                    collected_at=row.collected_at,
                    detail=row.detail,
                )
            )
    return found


def contradictions_for_repo(
    session: Session, repo_full_name: str, declared: list[RepoSurface]
) -> dict[str, list[Contradiction]]:
    return contradictions(declared, latest(session, repo_full_name))


__all__ = [
    "ASSERTIONS",
    "EVIDENCE_STATES",
    "FRESH_DAYS",
    "STATES",
    "VANTAGES",
    "Contradiction",
    "ObservationError",
    "Observed",
    "contradictions",
    "from_host_document",
    "latest",
    "parse_subject",
    "record",
]
