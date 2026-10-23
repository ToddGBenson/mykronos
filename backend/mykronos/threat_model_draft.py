"""A threat model drafted from what MyKronos already knows (TheHub #60899,
epic #60881).

`.sdlc/threat-model.yaml` (TheHub #60825) made the repository's own file the
source of truth, and every row in it was written by a person reading the host.
Most of what that person read, MyKronos had already recorded: which hostnames
answer from the internet, which routes DAST walked, which images the compose
files run, what the SBOM lists, which ports are published and which controls a
collector saw hold. This module turns those records into a draft of the same
file, so a person reviews a proposal rather than starting from a blank page.

**Every element cites its evidence.** An element is drafted only from records,
each kept as an `Evidence` with its source, what it said and when, and the
element's `evidence_ref` is the first of them that can be cited the way the
schema allows - a path in the repository or an https URL. A candidate whose
evidence cannot be cited that way (a port seen only by a collector, an image
seen only by the containers lane) is not drafted: it is listed in `uncited`
with its evidence, because an element that cites nothing is a guess written in
the shape of a declaration.

**The draft is the strict schema.** `Draft.manifest()` builds the same
`ThreatModelManifest` the sync parses, and `Draft.render()` is text that
`threat_model_manifest.parse_manifest` reads back as `valid`. Findings mapped
CWE -> STRIDE (`stride-map-v1.yaml`) are carried as `threats`: schema v1 has no
section for them, so they are rendered as comments under the element they land
in and never become keys the strict parser would refuse.

**Pure, apart from `gather`.** `draft()` takes an `EvidenceBundle` of plain
rows; `gather()` is the one function that reads the stores, and a source it
could not read is named in `unread` - never an empty list, because "could not
look" and "found nothing" must not draft the same file (B-058).
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from types import SimpleNamespace
from typing import Any, Literal
from urllib.parse import urlsplit

import yaml

from mykronos import surface_match
from mykronos.estate_images import COMPOSE_GLOBS, PRUNED_DIRS, services_from_compose
from mykronos.fingerprint import image_repository
from mykronos.logsafe import scrub
from mykronos.threat_model_manifest import (
    MANIFEST_PATH,
    ThreatModelManifest,
    _evidence,
)

logger = logging.getLogger(__name__)

Section = Literal["assets", "entry_points", "trust_boundaries", "controls"]
SECTIONS: tuple[Section, ...] = ("assets", "entry_points", "trust_boundaries", "controls")

#: The schema's kind for each surface section.
SURFACE_KIND: dict[str, str] = {
    "assets": "asset",
    "entry_points": "entry_point",
    "trust_boundaries": "trust_boundary",
}

#: The sources an `Evidence` may name. Closed, so a PR body can say what each
#: one means and a reviewer can tell a probe from a declaration.
EvidenceSource = Literal[
    "exposure",
    "dast",
    "compose",
    "containers",
    "sbom",
    "iac",
    "observation",
    "finding",
]

#: Which collector assertions are controls when they hold, and which kind
#: (`control_observations.ASSERTION_CONTROL_KINDS`, first kind). `pass` means
#: the assertion is true: an `anonymous_401` that passes is a gate that
#: answered 401, which is the control. `port_published` and
#: `ingress_published` are exposure facts, not controls.
CONTROL_ASSERTIONS: dict[str, str] = {
    "anonymous_401": "perimeter_gate",
    "header_csp": "security_headers",
    "header_hsts": "security_headers",
    "firewall_scope": "network_segmentation",
    "bound_loopback": "network_segmentation",
}

#: Manifest files whose presence names a dependency set, by SBOM ecosystem
#: (Syft's purl type). Only the file name is compared.
MANIFESTS: dict[str, tuple[str, ...]] = {
    "pypi": ("pyproject.toml", "requirements.txt", "poetry.lock", "uv.lock", "Pipfile.lock"),
    "npm": ("package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock"),
    "golang": ("go.mod", "go.sum"),
    "cargo": ("Cargo.toml", "Cargo.lock"),
    "maven": ("pom.xml",),
    "gem": ("Gemfile", "Gemfile.lock"),
    "nuget": ("packages.lock.json",),
}

#: Files that define infrastructure, by name or suffix.
IAC_NAMES = ("Dockerfile",)
IAC_SUFFIXES = (".tf", ".bicep", ".dockerfile")

#: Bounds that keep a draft reviewable. A selector list is capped by the
#: schema (`surface_match.MAX_SELECTORS`); threats are grouped and capped so a
#: repository with four hundred findings drafts a file, not a dump.
MAX_THREATS = 60
MAX_ROUTES_SHOWN = 5
MAX_ELEMENTS_PER_SECTION = 200

_KEY_BAD = re.compile(r"[^a-z0-9_.-]+")
_COMMENT_BAD = re.compile(r"[\r\n\t]+")


# --------------------------------------------------------------------------
# Data
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Evidence:
    """One record an element was drafted from."""

    source: EvidenceSource
    #: What the record said, in one line.
    detail: str
    #: A path in the repository or an https URL, or "" when the record has no
    #: reference the schema can cite.
    ref: str = ""
    observed_at: datetime | None = None


@dataclass
class DraftElement:
    section: Section
    #: The manifest fields, exactly as the schema names them.
    body: dict[str, Any]
    evidence: list[Evidence] = field(default_factory=list)

    @property
    def id(self) -> str:
        return str(self.body["id"])

    def selectors(self) -> dict[str, list[str]]:
        raw = self.body.get("selectors") or {}
        return {key: list(raw.get(key) or []) for key in surface_match.SELECTOR_KEYS}


@dataclass(frozen=True)
class Threat:
    """Open findings of one weakness, placed in the draft (spec 28 §2)."""

    stride: tuple[str, ...]
    #: `cwe` when `stride-map-v1.yaml` placed it, `capability` otherwise.
    resolution: Literal["cwe", "capability"]
    weakness: str
    title: str
    capability: str
    severity: str
    findings: int
    #: The draft element it lands in, or None when no element's selectors
    #: cover it.
    element_id: str | None
    ref: str = ""


@dataclass
class EvidenceBundle:
    """Everything `draft` reads, as plain rows. `None` = could not read."""

    repo_full_name: str
    #: `PublicEndpoint` rows for this repository: url, label, last_status,
    #: last_probed_at.
    endpoints: list[dict[str, Any]] | None = field(default_factory=list)
    #: Open lake findings: finding_id, capability, rule_id, title, severity,
    #: file_path, package_name, raw_finding_json, cwe_ids_json, last_seen_at.
    findings: list[dict[str, Any]] | None = field(default_factory=list)
    #: The newest, fresh `ControlObservation` per (subject, assertion):
    #: subject, assertion, state, vantage, tool, collected_at, raw_ref.
    observations: list[dict[str, Any]] | None = field(default_factory=list)
    #: SBOM components per ecosystem: ecosystem, components, observed_at.
    sbom: list[dict[str, Any]] | None = field(default_factory=list)
    #: Every path on the default branch.
    tree: list[str] | None = field(default_factory=list)
    #: Compose files on the default branch, path -> text.
    compose: dict[str, str] | None = field(default_factory=dict)

    def unread(self) -> list[str]:
        return [
            name
            for name in ("endpoints", "findings", "observations", "sbom", "tree", "compose")
            if getattr(self, name) is None
        ]


@dataclass
class Draft:
    repo_full_name: str
    elements: list[DraftElement] = field(default_factory=list)
    threats: list[Threat] = field(default_factory=list)
    #: Candidates not drafted because none of their evidence is citable:
    #: (description, evidence).
    uncited: list[tuple[str, list[Evidence]]] = field(default_factory=list)
    #: Sources `gather` could not read.
    unread: list[str] = field(default_factory=list)
    generated_at: datetime | None = None

    def section(self, name: Section) -> list[DraftElement]:
        return [e for e in self.elements if e.section == name]

    def element(self, element_id: str) -> DraftElement | None:
        return next((e for e in self.elements if e.id == element_id), None)

    def manifest(self) -> ThreatModelManifest:
        """The draft as the strict schema; raises if it is not one."""
        document: dict[str, Any] = {"version": 1}
        for name in SECTIONS:
            document[name] = [dict(e.body) for e in self.section(name)]
        return ThreatModelManifest.model_validate(document)

    def render(self) -> str:
        return render(self)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def citable(ref: str) -> bool:
    """Whether the schema accepts `ref` as an `evidence_ref`."""
    if not ref or len(ref) > 512:
        return False
    try:
        return bool(_evidence(ref))
    except ValueError:
        return False


def _slug(*parts: str) -> str:
    text = "-".join(p for p in parts if p).lower()
    text = _KEY_BAD.sub("-", text).strip("-._")
    return (text or "x")[:100]


def _unique(key: str, taken: set[str]) -> str:
    candidate, n = key, 2
    while candidate in taken:
        candidate = f"{key}-{n}"
        n += 1
    taken.add(candidate)
    return candidate


def _one_line(text: str, limit: int = 200) -> str:
    flat = _COMMENT_BAD.sub(" ", str(text)).strip()
    return flat if len(flat) <= limit else flat[: limit - 3] + "..."


def _when(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None
    return None


def _raw(row: dict[str, Any]) -> dict[str, Any]:
    raw = row.get("raw_finding_json")
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw:
        try:
            parsed = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _cwes(row: dict[str, Any]) -> list[str]:
    raw = row.get("cwe_ids_json")
    if not raw:
        return []
    try:
        values = json.loads(str(raw))
    except (json.JSONDecodeError, TypeError):
        return []
    return [str(v).upper() for v in values if str(v).strip()] if isinstance(values, list) else []


def _hostname(text: str) -> str | None:
    host = (text or "").strip().lower().rstrip(".")
    if not host or ":" in host or "/" in host:
        return None
    try:
        surface_match.normalize_selectors({"hostnames": [host]})
    except surface_match.SelectorError:
        return None
    return host


def _is_loopback(address: str) -> bool:
    if address in ("localhost",):
        return True
    try:
        return ipaddress.ip_address(address.strip("[]")).is_loopback
    except ValueError:
        return False


def _is_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


# --------------------------------------------------------------------------
# Compose
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class PublishedPort:
    compose_path: str
    service: str
    host_ip: str
    host_port: int
    container_port: str
    image: str


def _published(entry: Any) -> tuple[str, int, str] | None:
    """`(host_ip, host_port, container_port)` for one `ports:` entry, or None
    when the host side is not a fixed number (an unpublished or ranged or
    interpolated port is not something to draft an entry point from)."""
    if isinstance(entry, dict):
        published = str(entry.get("published") or "").strip()
        target = str(entry.get("target") or "").strip()
        host_ip = str(entry.get("host_ip") or "").strip()
        if not published.isdigit():
            return None
        return host_ip, int(published), target
    text = str(entry).strip().strip('"').split("/", 1)[0]
    if not text:
        return None
    if text.startswith("["):
        bracket, _, rest = text[1:].partition("]")
        host_ip, parts = bracket, rest.lstrip(":").split(":")
    else:
        parts = text.split(":")
        host_ip = parts.pop(0) if len(parts) == 3 else ""
    if len(parts) != 2 or not parts[0].isdigit():
        return None
    return host_ip, int(parts[0]), parts[1]


def compose_ports(path: str, text: str) -> list[PublishedPort]:
    """Every fixed host port a compose file publishes."""
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError:
        return []
    services = document.get("services") if isinstance(document, dict) else None
    if not isinstance(services, dict):
        return []
    out: list[PublishedPort] = []
    for name, definition in services.items():
        if not isinstance(definition, dict):
            continue
        image = str(definition.get("image") or "").strip()
        for entry in definition.get("ports") or []:
            parsed = _published(entry)
            if parsed is None or not 0 < parsed[1] <= 65535:
                continue
            out.append(PublishedPort(path, str(name), parsed[0], parsed[1], parsed[2], image))
    return out


def is_compose_file(path: str) -> bool:
    parts = path.split("/")
    if any(part in PRUNED_DIRS for part in parts[:-1]):
        return False
    return any(surface_match.glob_match(pattern, parts[-1]) for pattern in COMPOSE_GLOBS)


def _is_iac(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    parts = path.split("/")
    if any(part in PRUNED_DIRS for part in parts[:-1]):
        return False
    return (
        name in IAC_NAMES
        or name.startswith("Dockerfile.")
        or name.endswith(IAC_SUFFIXES)
        or is_compose_file(path)
    )


# --------------------------------------------------------------------------
# Drafting
# --------------------------------------------------------------------------


class _Builder:
    def __init__(self, repo_full_name: str) -> None:
        self.draft = Draft(repo_full_name=repo_full_name)
        self.taken: set[str] = set()

    def add(
        self,
        section: Section,
        key: str,
        body: dict[str, Any],
        evidence: list[Evidence],
        *,
        label: str,
    ) -> DraftElement | None:
        """Add an element if any evidence is citable; otherwise record it as
        uncited. The first citable evidence is its `evidence_ref`."""
        cited = next((e.ref for e in evidence if citable(e.ref)), "")
        if not cited:
            self.draft.uncited.append((label, list(evidence)))
            return None
        if len(self.draft.section(section)) >= MAX_ELEMENTS_PER_SECTION:
            self.draft.uncited.append((f"{label} (section full)", list(evidence)))
            return None
        element = DraftElement(
            section=section,
            body={"id": _unique(key, self.taken), **body, "evidence_ref": cited},
            evidence=list(evidence),
        )
        self.draft.elements.append(element)
        return element


def draft(bundle: EvidenceBundle, *, now: datetime | None = None) -> Draft:
    """Draft `.sdlc/threat-model.yaml` from `bundle`. Pure."""
    from mykronos.dashboard import STRIDE_BY_CAPABILITY, stride_by_cwe

    builder = _Builder(bundle.repo_full_name)
    builder.draft.generated_at = now
    builder.draft.unread = bundle.unread()

    endpoints = bundle.endpoints or []
    findings = bundle.findings or []
    observations = [o for o in bundle.observations or [] if o.get("state") == "pass"]
    compose = bundle.compose or {}
    tree = bundle.tree or []

    # -- entry points: public hostnames -----------------------------------
    hosts: dict[str, list[Evidence]] = {}
    internet: set[str] = set()
    for row in endpoints:
        url = str(row.get("url") or "")
        host = _hostname(urlsplit(url).hostname or "")
        if host is None:
            continue
        internet.add(host)
        status = str(row.get("last_status") or "not_probed")
        hosts.setdefault(host, []).append(
            Evidence(
                "exposure",
                f"registered public endpoint {url}; last anonymous probe: {status}",
                ref=url if url.startswith("https://") else "",
                observed_at=_when(row.get("last_probed_at")),
            )
        )
    routes: dict[str, set[str]] = {}
    schemes: dict[str, str] = {}
    for row in findings:
        if row.get("capability") != "dast":
            continue
        instance = _raw(row).get("instance")
        uri = instance.get("uri") if isinstance(instance, dict) else None
        if not isinstance(uri, str) or not uri:
            continue
        parts = urlsplit(uri)
        host = _hostname(parts.hostname or "")
        if host is None:
            continue
        routes.setdefault(host, set()).add(parts.path or "/")
        if parts.scheme == "https" or host not in schemes:
            schemes[host] = parts.scheme
    for host, paths in sorted(routes.items()):
        shown = sorted(paths)[:MAX_ROUTES_SHOWN]
        more = len(paths) - len(shown)
        hosts.setdefault(host, []).append(
            Evidence(
                "dast",
                f"DAST reported on {len(paths)} route(s): {', '.join(shown)}"
                + (f" and {more} more" if more > 0 else ""),
                ref=f"https://{host}/" if schemes.get(host) == "https" else "",
            )
        )
    for row in observations:
        if row.get("assertion") != "ingress_published":
            continue
        host = _hostname(str(row.get("subject") or ""))
        if host is None:
            continue
        internet.add(host)
        hosts.setdefault(host, []).append(
            Evidence(
                "observation",
                f"ingress_published holds ({row.get('vantage')}, {row.get('tool') or 'collector'})",
                ref=f"https://{host}/",
                observed_at=_when(row.get("collected_at")),
            )
        )
    entry_for_host: dict[str, str] = {}
    for host in sorted(hosts):
        element = builder.add(
            "entry_points",
            _slug("ep", host),
            {
                "name": f"Web entry point at {host}",
                "description": "Drafted from MyKronos evidence; review before merging.",
                "exposure": "internet" if host in internet else "unknown",
                "selectors": {"hostnames": [host]},
            },
            hosts[host],
            label=f"entry point at {host}",
        )
        if element is not None:
            entry_for_host[host] = element.id

    # -- entry points: published ports ------------------------------------
    port_observations: dict[int, list[dict[str, Any]]] = {}
    for row in bundle.observations or []:
        subject = str(row.get("subject") or "")
        host, sep, port = subject.rpartition(":")
        if sep and port.isdigit():
            port_observations.setdefault(int(port), []).append(row)
    entry_for_port: dict[int, str] = {}
    lan_ports: list[tuple[int, str]] = []
    for path in sorted(compose):
        for published in compose_ports(path, compose[path]):
            if published.host_port in entry_for_port:
                continue
            loopback = bool(published.host_ip) and _is_loopback(published.host_ip)
            exposure = "local" if loopback else "internal"
            evidence = [
                Evidence(
                    "compose",
                    f"{published.service} publishes "
                    f"{published.host_ip or '0.0.0.0'}:{published.host_port} -> "
                    f"{published.container_port}",
                    ref=path,
                )
            ]
            for row in port_observations.get(published.host_port, []):
                if row.get("state") not in ("pass", "fail"):
                    continue
                evidence.append(
                    Evidence(
                        "observation",
                        f"{row.get('assertion')} {row.get('state')} on {row.get('subject')} "
                        f"({row.get('vantage')}, {row.get('tool') or 'collector'})",
                        ref=str(row.get("raw_ref") or "") if citable(
                            str(row.get("raw_ref") or "")
                        ) else "",
                        observed_at=_when(row.get("collected_at")),
                    )
                )
                if (
                    row.get("assertion") == "port_published"
                    and row.get("state") == "pass"
                    and row.get("vantage") == "internet"
                ):
                    exposure = "internet"
            selectors: dict[str, list[str]] = {"addresses": [f"*:{published.host_port}"]}
            if published.image and "$" not in published.image:
                try:
                    selectors["images"] = [image_repository(published.image)]
                    surface_match.normalize_selectors(selectors)
                except (surface_match.SelectorError, ValueError):
                    selectors.pop("images", None)
            element = builder.add(
                "entry_points",
                _slug("ep", published.service, str(published.host_port)),
                {
                    "name": f"{published.service} on port {published.host_port}",
                    "description": "Drafted from MyKronos evidence; review before merging.",
                    "exposure": exposure,
                    "selectors": selectors,
                },
                evidence,
                label=f"{published.service} on port {published.host_port}",
            )
            if element is not None:
                entry_for_port[published.host_port] = element.id
                if exposure != "local":
                    lan_ports.append((published.host_port, path))

    # -- trust boundaries ---------------------------------------------------
    edge_hosts = sorted(h for h in internet if h in entry_for_host)
    if edge_hosts:
        builder.add(
            "trust_boundaries",
            "tb-internet-edge",
            {
                "name": "Internet edge",
                "description": (
                    "Where requests from the internet enter: the hostnames MyKronos "
                    "has registered or observed as public."
                ),
                "exposure": "internet",
                "selectors": {"hostnames": edge_hosts[: surface_match.MAX_SELECTORS]},
            },
            [e for h in edge_hosts for e in hosts[h] if e.source in ("exposure", "observation")],
            label="internet edge",
        )
    if lan_ports:
        builder.add(
            "trust_boundaries",
            "tb-host-network",
            {
                "name": "Host network edge",
                "description": (
                    "Ports compose publishes on every interface, reachable from the "
                    "network the host is on unless a firewall says otherwise."
                ),
                "exposure": "internal",
                "selectors": {
                    "addresses": [f"*:{p}" for p, _ in lan_ports][: surface_match.MAX_SELECTORS]
                },
            },
            [
                Evidence("compose", f"port {port} published on all interfaces", ref=path)
                for port, path in lan_ports
            ],
            label="host network edge",
        )

    # -- assets: images ----------------------------------------------------
    image_evidence: dict[str, list[Evidence]] = {}
    for path in sorted(compose):
        services, _ = services_from_compose(compose[path], path)
        for service in services:
            if not service.reference or service.unresolved_vars:
                continue
            repository = image_repository(service.reference)
            image_evidence.setdefault(repository, []).append(
                Evidence(
                    "compose",
                    f"{path} runs service {service.service} from {service.reference}",
                    ref=service.build_dockerfile or path,
                )
            )
    container_counts: dict[str, int] = {}
    for row in findings:
        if row.get("capability") != "containers":
            continue
        image = _raw(row).get("image")
        if isinstance(image, str) and image.strip():
            repo_name = image_repository(image)
            container_counts[repo_name] = container_counts.get(repo_name, 0) + 1
    for repository, count in sorted(container_counts.items()):
        image_evidence.setdefault(repository, []).append(
            Evidence("containers", f"containers lane: {count} open finding(s) in this image")
        )
    for repository in sorted(image_evidence):
        try:
            surface_match.normalize_selectors({"images": [repository]})
        except surface_match.SelectorError:
            continue
        builder.add(
            "assets",
            _slug("img", repository.rsplit("/", 1)[-1]),
            {
                "name": f"Container image {repository}",
                "description": "Drafted from MyKronos evidence; review before merging.",
                "selectors": {"images": [repository]},
            },
            image_evidence[repository],
            label=f"container image {repository}",
        )

    # -- assets: dependency sets (SBOM) ------------------------------------
    for row in sorted(bundle.sbom or [], key=lambda r: str(r.get("ecosystem") or "")):
        ecosystem = str(row.get("ecosystem") or "").lower()
        names = MANIFESTS.get(ecosystem, ())
        manifests = sorted(p for p in tree if p.rsplit("/", 1)[-1] in names)[
            : surface_match.MAX_SELECTORS
        ]
        evidence = [
            Evidence(
                "sbom",
                f"SBOM lists {row.get('components')} {ecosystem} component(s)",
                observed_at=_when(row.get("observed_at")),
            ),
            *(Evidence("sbom", f"{ecosystem} manifest", ref=p) for p in manifests),
        ]
        builder.add(
            "assets",
            _slug("deps", ecosystem),
            {
                "name": f"{ecosystem} dependency set",
                "description": (
                    "Third-party code this repository ships; drafted from the SBOM."
                ),
                "sensitivity": "source",
                "selectors": {"paths": manifests},
            },
            evidence,
            label=f"{ecosystem} dependency set",
        )

    # -- assets: infrastructure as code -------------------------------------
    iac_paths = sorted({p for p in tree if _is_iac(p)})
    iac_findings: dict[str, int] = {}
    for row in findings:
        if row.get("capability") == "iac" and row.get("file_path"):
            path = str(row["file_path"])
            iac_findings[path] = iac_findings.get(path, 0) + 1
            if path not in iac_paths and citable(path):
                iac_paths.append(path)
    if iac_paths:
        shown = sorted(iac_paths)[: surface_match.MAX_SELECTORS]
        builder.add(
            "assets",
            "iac-definitions",
            {
                "name": "Infrastructure definitions",
                "description": (
                    "The files that say what runs and how: compose, Dockerfiles and "
                    "other infrastructure as code. A change here changes the deployment."
                ),
                "sensitivity": "source",
                "selectors": {"paths": shown},
            },
            [
                Evidence(
                    "iac",
                    f"infrastructure file ({iac_findings[p]} open IaC finding(s))"
                    if p in iac_findings
                    else "infrastructure file",
                    ref=p,
                )
                for p in shown
            ],
            label="infrastructure definitions",
        )

    # -- controls -----------------------------------------------------------
    for row in observations:
        assertion = str(row.get("assertion") or "")
        kind = CONTROL_ASSERTIONS.get(assertion)
        if kind is None:
            continue
        subject = str(row.get("subject") or "")
        host = _hostname(subject)
        applies_to: str | None = None
        ref = ""
        if host is not None and not _is_address(host):
            applies_to = entry_for_host.get(host)
            ref = f"https://{host}/"
        else:
            _, sep, port = subject.rpartition(":")
            if sep and port.isdigit():
                applies_to = entry_for_port.get(int(port))
                element = builder.draft.element(applies_to) if applies_to else None
                ref = element.body["evidence_ref"] if element else ""
        raw_ref = str(row.get("raw_ref") or "")
        evidence = [
            Evidence(
                "observation",
                f"{assertion} holds on {subject} "
                f"({row.get('vantage')}, {row.get('tool') or 'collector'})",
                ref=raw_ref if citable(raw_ref) else ref,
                observed_at=_when(row.get("collected_at")),
            )
        ]
        body: dict[str, Any] = {
            "kind": kind,
            "description": _one_line(
                f"Observed: {assertion} holds on {subject}. Drafted from a "
                "collector's observation; review before merging.",
                500,
            ),
        }
        if applies_to:
            body["applies_to"] = applies_to
        builder.add(
            "controls",
            _slug("ctl", assertion, applies_to or subject),
            body,
            evidence,
            label=f"{kind} ({assertion} on {subject})",
        )

    # -- threats: findings mapped CWE -> STRIDE ------------------------------
    cwe_map = stride_by_cwe()
    surfaces = [
        SimpleNamespace(
            id=e.id, kind=SURFACE_KIND[e.section], name=e.body["name"], selectors=e.selectors()
        )
        for e in builder.draft.elements
        if e.section in SURFACE_KIND
    ]
    groups: dict[tuple[str, str | None], dict[str, Any]] = {}
    for row in findings:
        capability = str(row.get("capability") or "")
        cwes = _cwes(row)
        mapped = sorted({c for cwe in cwes for c in cwe_map.get(cwe, ())})
        weakness = next((c for c in cwes if c in cwe_map), cwes[0] if cwes else "")
        if mapped:
            stride, resolution = tuple(mapped), "cwe"
        else:
            stride = tuple(STRIDE_BY_CAPABILITY.get(capability, ()))
            resolution = "capability"
        if not stride:
            continue
        found = surface_match.matches(row, surfaces)
        element_id = found[0].surface.id if found else None
        key = (weakness or f"{capability}:{row.get('rule_id')}", element_id)
        group = groups.get(key)
        if group is None:
            path = str(row.get("file_path") or "")
            group = groups[key] = {
                "stride": stride,
                "resolution": resolution,
                "weakness": weakness or str(row.get("rule_id") or capability),
                "title": _one_line(str(row.get("title") or ""), 120),
                "capability": capability,
                "severity": str(row.get("severity") or ""),
                "findings": 0,
                "element_id": element_id,
                "ref": path
                if capability in surface_match.PATH_CAPABILITIES and citable(path)
                else "",
            }
        group["findings"] += 1
    ranked = sorted(
        groups.values(),
        key=lambda g: (-_SEVERITY.get(g["severity"], 0), -g["findings"], g["weakness"]),
    )
    builder.draft.threats = [Threat(**g) for g in ranked[:MAX_THREATS]]
    return builder.draft


_SEVERITY = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------


def _evidence_comment(evidence: Evidence, indent: str) -> str:
    when = f" ({evidence.observed_at:%Y-%m-%d})" if evidence.observed_at else ""
    ref = f" [{evidence.ref}]" if evidence.ref else ""
    return f"{indent}# evidence ({evidence.source}): {_one_line(evidence.detail)}{ref}{when}"


def render_element(element: DraftElement, draft: Draft | None = None) -> str:
    """One element as YAML list-item text at the manifest's indent, with its
    evidence (and any threats placed in it) as comments above it."""
    lines = [_evidence_comment(e, "  ") for e in element.evidence]
    for threat in (draft.threats if draft else []):
        if threat.element_id == element.id:
            lines.append(
                f"  # threat ({'/'.join(threat.stride)}, {threat.resolution}): "
                f"{threat.weakness} x{threat.findings} {threat.severity} - "
                f"{_one_line(threat.title, 100)}"
            )
    dumped = yaml.safe_dump(
        [element.body], sort_keys=False, default_flow_style=False, allow_unicode=True, width=100
    )
    lines += ["  " + line if line else line for line in dumped.rstrip("\n").split("\n")]
    return "\n".join(lines)


def render(draft: Draft) -> str:
    """The draft as `.sdlc/threat-model.yaml` text, comments included."""
    stamp = f"{draft.generated_at:%Y-%m-%d %H:%M} UTC" if draft.generated_at else "now"
    out = [
        f"# {draft.repo_full_name}'s threat model, drafted by MyKronos from its own",
        f"# evidence on {stamp} (TheHub #60899). Every element below names the",
        "# records it was drafted from as `# evidence` comments; `evidence_ref` is",
        "# the first one that is a path in this repository or an https URL.",
        "#",
        "# A draft, not a declaration: read each element, correct what is wrong,",
        "# delete what does not belong, and merge. Once merged this file is the",
        "# source of truth, and the threat-model-sync job loads it (spec 28 §8).",
    ]
    if draft.unread:
        out.append(
            "# Not read while drafting (so absent here, not proven absent): "
            + ", ".join(draft.unread)
            + "."
        )
    out += ["", "version: 1"]
    for name in SECTIONS:
        elements = draft.section(name)
        out.append("")
        if not elements:
            out.append(f"{name}: []")
            continue
        out.append(f"{name}:")
        for index, element in enumerate(elements):
            if index:
                out.append("")
            out.append(render_element(element, draft))
    unplaced = [t for t in draft.threats if t.element_id is None]
    if unplaced:
        out += ["", "# Threats no drafted element covers (findings mapped CWE -> STRIDE):"]
        out += [
            f"#   {'/'.join(t.stride)} ({t.resolution}): {t.weakness} x{t.findings} "
            f"{t.severity} - {_one_line(t.title, 100)}"
            + (f" [{t.ref}]" if t.ref else "")
            for t in unplaced
        ]
    if draft.uncited:
        out += ["", "# Seen but not drafted, because no evidence could be cited as a path"]
        out.append("# or an https URL:")
        out += [f"#   {_one_line(label, 150)}" for label, _ in draft.uncited]
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------
# Gathering
# --------------------------------------------------------------------------

_FINDING_COLUMNS = (
    "finding_id",
    "capability",
    "rule_id",
    "title",
    "severity",
    "file_path",
    "package_name",
    "raw_finding_json",
    "cwe_ids_json",
    "last_seen_at",
)


def _read_findings(catalog: Any, repo_full_name: str) -> list[dict[str, Any]] | None:
    try:
        if not catalog.all_files("findings"):
            return []
        rows = catalog.query(
            f"SELECT {', '.join(_FINDING_COLUMNS)} FROM findings "
            "WHERE asset_id = ? AND status = 'open'",
            [repo_full_name],
        )
    except Exception as exc:  # noqa: BLE001 - an unreadable lake is `unread`, not a crash
        logger.warning("Threat-model draft: findings unreadable: %s", scrub(str(exc)))
        return None
    return [dict(zip(_FINDING_COLUMNS, row, strict=True)) for row in rows]


def _read_sbom(catalog: Any, repo_full_name: str) -> list[dict[str, Any]] | None:
    try:
        if not catalog.all_files("sbom_components"):
            return []
        rows = catalog.query(
            "SELECT ecosystem, count(DISTINCT component_id), max(observed_at) "
            "FROM sbom_components WHERE repo_full_name = ? GROUP BY ecosystem",
            [repo_full_name],
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Threat-model draft: SBOM unreadable: %s", scrub(str(exc)))
        return None
    return [
        {"ecosystem": e, "components": int(n), "observed_at": at}
        for e, n, at in rows
        if e
    ]


def _read_operational(
    db: Any, repo_full_name: str
) -> tuple[list[dict[str, Any]] | None, list[dict[str, Any]] | None]:
    from mykronos import control_observations, exposure

    try:
        endpoints = [
            {
                "url": e.url,
                "label": e.label,
                "last_status": e.last_status,
                "last_probed_at": e.last_probed_at,
            }
            for e in exposure.endpoints(db)
            if e.repo_full_name == repo_full_name
        ]
    except Exception as exc:  # noqa: BLE001
        logger.warning("Threat-model draft: endpoints unreadable: %s", scrub(str(exc)))
        endpoints = None
    try:
        with db.session() as session:
            observations: list[dict[str, Any]] | None = [
                {
                    "subject": row.subject,
                    "assertion": row.assertion,
                    "state": row.state,
                    "vantage": row.vantage,
                    "tool": row.tool,
                    "collected_at": row.collected_at,
                    "raw_ref": row.raw_ref,
                }
                for row in control_observations.latest(session, repo_full_name)
                if control_observations.is_fresh(row)
            ]
    except Exception as exc:  # noqa: BLE001
        logger.warning("Threat-model draft: observations unreadable: %s", scrub(str(exc)))
        observations = None
    return endpoints, observations


async def gather(
    db: Any, catalog: Any, github: Any, repo_full_name: str, branch: str
) -> EvidenceBundle:
    """Read every source `draft` uses. A source that fails is `None`."""
    import asyncio

    endpoints, observations = await asyncio.to_thread(_read_operational, db, repo_full_name)
    findings = await asyncio.to_thread(_read_findings, catalog, repo_full_name)
    sbom = await asyncio.to_thread(_read_sbom, catalog, repo_full_name)
    tree: list[str] | None
    compose: dict[str, str] | None
    try:
        tree = await github.list_tree(repo_full_name, branch)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Threat-model draft: tree unreadable: %s", scrub(str(exc)))
        tree = None
    if tree is None:
        compose = None
    else:
        paths = [p for p in tree if is_compose_file(p)][:50]
        try:
            files = await github.get_files(repo_full_name, paths, branch) if paths else {}
            compose = {p: t for p, t in files.items() if t is not None}
        except Exception as exc:  # noqa: BLE001
            logger.warning("Threat-model draft: compose unreadable: %s", scrub(str(exc)))
            compose = None
    return EvidenceBundle(
        repo_full_name=repo_full_name,
        endpoints=endpoints,
        findings=findings,
        observations=observations,
        sbom=sbom,
        tree=tree,
        compose=compose,
    )


def evidence_sources(elements: Iterable[DraftElement]) -> dict[str, int]:
    """How many elements each source contributed to - for a PR body."""
    counts: dict[str, int] = {}
    for element in elements:
        for source in {e.source for e in element.evidence}:
            counts[source] = counts.get(source, 0) + 1
    return dict(sorted(counts.items()))


__all__ = [
    "MANIFEST_PATH",
    "Draft",
    "DraftElement",
    "Evidence",
    "EvidenceBundle",
    "Threat",
    "citable",
    "compose_ports",
    "draft",
    "gather",
    "render",
    "render_element",
]
