"""Which declared surface a finding is in (TheHub #60825, epic #60822).

A `RepoSurface` said *what* is at stake and never *where*: "the cardholder
database" was a name, and no finding could be placed inside it. Environmental
CVSS rescoring (S5) needs exactly that placement — a CR of H belongs to the
findings in the asset holding credentials, not to every finding in the
repository — so a surface now carries `selectors`, and this module answers the
one question they exist for.

**One shape per capability, because each capability locates its findings
differently**, and reading the wrong field is worse than reading none:

* `sast`, `secrets`, `iac`, `atlas` (SCA), `ai`: `file_path`, against `paths`
  globs. A repository-relative path.
* `containers`: `raw_finding_json["image"]` — the image the Trivy adapter
  stamps onto every result — against `images`, both in `image_repository`
  form, so a tag or a LAN registry host never decides a match.
* `network`: `address` and `port` against `addresses` (`host:port`), and the
  raw record's `hostname` against `hostnames`.
* `dast`: the probed URL, `raw_finding_json["instance"]["uri"]`, by host
  against `hostnames` and by host and port against `addresses`. Never
  `file_path`: for DAST that is the route (`/admin`), and matching it against
  a path glob would place a web finding in a source directory of the same
  name.

**No match is an answer, not an error.** `surface_for` returns `None` and the
caller falls back to repository-level facts (the design's core rule: lowering
then needs observed evidence). Guessing the closest surface would put a
finding inside an asset nobody located it in.

Pure: no session, no I/O. A surface is anything with `id`, `kind`, `name` and
`selectors`, so the ORM row and a test double both work.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlsplit

from mykronos.fingerprint import image_repository

#: The four ways a surface can be located. A closed list for the reason
#: `controls.CONTROL_KINDS` is one: a selector type nothing reads is a claim
#: that silently matches nothing.
SELECTOR_KEYS: tuple[str, ...] = ("paths", "images", "addresses", "hostnames")

#: CVSS 3.1 Security Requirement values a surface may override to.
REQUIREMENT_LEVELS: tuple[str, ...] = ("H", "M", "L")

#: Per selector type. Generous for a real repository, small enough that a
#: pasted file listing is refused rather than stored.
MAX_SELECTORS = 50
MAX_SELECTOR_LENGTH = 255

#: Capabilities whose findings are located by a repository path.
PATH_CAPABILITIES = frozenset({"sast", "secrets", "iac", "atlas", "ai"})

_HOSTNAME = re.compile(
    r"^(\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
_GLOB_CHARS = re.compile(r"^[A-Za-z0-9_.*?/\-\[\]{}@+~ ]+$")
_IMAGE_CHARS = re.compile(r"^[a-z0-9][a-z0-9._/:@\-]*$")


class SelectorError(ValueError):
    """A selector the register will not accept, said so a person can fix it."""


class SurfaceLike(Protocol):
    id: str
    kind: str
    name: str
    selectors: Any


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------


def normalize_selectors(raw: Mapping[str, Any] | None) -> dict[str, list[str]]:
    """Validate and normalise; every key present, de-duplicated, in order.

    Normalising at the door is what lets matching stay dumb: a path loses its
    leading `./` or `/`, an image becomes its repository, a hostname is
    lowercased. Two people writing `postgres:15` and `library/postgres` have
    declared the same thing and are stored as the same thing.
    """
    if raw is None:
        raw = {}
    if not isinstance(raw, Mapping):
        raise SelectorError("Selectors must be a mapping of selector type to a list.")
    unknown = sorted(set(raw) - set(SELECTOR_KEYS))
    if unknown:
        raise SelectorError(
            f"Unknown selector type(s): {', '.join(unknown)}. "
            f"Expected any of: {', '.join(SELECTOR_KEYS)}."
        )

    out: dict[str, list[str]] = {}
    for key in SELECTOR_KEYS:
        values = raw.get(key) or []
        if isinstance(values, str) or not isinstance(values, Sequence):
            raise SelectorError(f"`{key}` must be a list.")
        if len(values) > MAX_SELECTORS:
            raise SelectorError(f"`{key}` holds {len(values)}; at most {MAX_SELECTORS}.")
        normalised: list[str] = []
        for value in values:
            if not isinstance(value, str) or not value.strip():
                raise SelectorError(f"`{key}` entries must be non-empty strings.")
            if len(value) > MAX_SELECTOR_LENGTH:
                raise SelectorError(
                    f"`{key}` entry is longer than {MAX_SELECTOR_LENGTH} characters."
                )
            item = _NORMALISERS[key](value.strip())
            if item not in normalised:
                normalised.append(item)
        out[key] = normalised
    return out


def _normalise_path(value: str) -> str:
    path = value.replace("\\", "/")
    if "://" in path or path.startswith("~"):
        raise SelectorError(f"Path selector {value!r} must be a repository-relative glob.")
    while path.startswith("./"):
        path = path[2:]
    path = path.lstrip("/")
    if not path or ".." in path.split("/"):
        raise SelectorError(f"Path selector {value!r} must stay inside the repository.")
    if not _GLOB_CHARS.match(path):
        raise SelectorError(f"Path selector {value!r} has characters a path glob cannot.")
    return path


def _normalise_image(value: str) -> str:
    lowered = value.lower()
    if "://" in lowered or not _IMAGE_CHARS.match(lowered):
        raise SelectorError(f"Image selector {value!r} is not an image reference.")
    repository = image_repository(lowered)
    if not repository:
        raise SelectorError(f"Image selector {value!r} names no repository.")
    return repository


def _normalise_address(value: str) -> str:
    host, port = _split_host_port(value.lower())
    if host is None or port is None:
        raise SelectorError(
            f"Address selector {value!r} must be host:port — e.g. 10.0.0.5:5433, "
            "[::1]:8080, db.internal:5432, or *:22 for that port on any host."
        )
    if host != "*" and not _is_ip(host) and not _HOSTNAME.match(host):
        raise SelectorError(f"Address selector {value!r} names no host.")
    if port != "*":
        number = int(port)
        if not 0 < number <= 65535:
            raise SelectorError(f"Address selector {value!r} has no valid port.")
        port = str(number)
    shown = f"[{host}]" if ":" in host else host
    return f"{shown}:{port}"


def _normalise_hostname(value: str) -> str:
    host = value.lower().rstrip(".")
    if "://" in host or "/" in host or ":" in host or not _HOSTNAME.match(host):
        raise SelectorError(
            f"Hostname selector {value!r} must be a DNS name, optionally *.example.net."
        )
    return host


_NORMALISERS = {
    "paths": _normalise_path,
    "images": _normalise_image,
    "addresses": _normalise_address,
    "hostnames": _normalise_hostname,
}


def _split_host_port(value: str) -> tuple[str | None, str | None]:
    if value.startswith("["):
        host, _, rest = value[1:].partition("]")
        if not rest.startswith(":"):
            return None, None
        port = rest[1:]
    else:
        host, sep, port = value.rpartition(":")
        if not sep:
            return None, None
    if not host or not (port == "*" or port.isdigit()):
        return None, None
    return host, port


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def validate_requirement(value: str | None, metric: str) -> str | None:
    """`H`/`M`/`L`, case-insensitive, or None for "not overridden"."""
    if value is None or value == "":
        return None
    level = value.strip().upper()
    if level not in REQUIREMENT_LEVELS:
        raise SelectorError(
            f"{metric.upper()} must be one of {', '.join(REQUIREMENT_LEVELS)}, not {value!r}."
        )
    return level


# --------------------------------------------------------------------------
# Matching
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Match:
    """One surface a finding is in, and how tightly."""

    surface: Any
    selector_type: str
    selector: str
    #: Higher is more specific. A literal path beats `src/**`; an exact host
    #: beats `*.example.net`; `10.0.0.5:5433` beats `*:5433`.
    specificity: int


#: Tie-break between equally specific matches. An asset first, because the
#: question S5 asks most is "what is at stake here", then the way in.
_KIND_ORDER = {"asset": 0, "entry_point": 1, "trust_boundary": 2}


def surface_for(
    finding: Any, surfaces: Sequence[SurfaceLike], *, capability: str | None = None
) -> Any | None:
    """The single most specific surface this finding is in, or None."""
    found = matches(finding, surfaces, capability=capability)
    return found[0].surface if found else None


def matches(
    finding: Any, surfaces: Sequence[SurfaceLike], *, capability: str | None = None
) -> list[Match]:
    """Every surface the finding is in, most specific first.

    `finding` is a lake row (a mapping) or an adapter's `FindingSubmission`;
    the latter carries no capability, so pass `capability` for it. Without
    either, the shape decides: an address means network, a raw image means
    containers, a raw DAST instance means dast, and otherwise the file path.
    """
    cap = (capability or _field(finding, "capability") or _infer_capability(finding)).lower()
    raw = _raw(finding)

    candidates: list[Match] = []
    for surface in surfaces:
        selectors = surface.selectors if isinstance(surface.selectors, Mapping) else {}
        best = _best(cap, finding, raw, selectors, surface)
        if best is not None:
            candidates.append(best)

    candidates.sort(
        key=lambda m: (
            -m.specificity,
            _KIND_ORDER.get(m.surface.kind, 9),
            m.surface.name,
            m.surface.id,
        )
    )
    return candidates


def _best(
    cap: str, finding: Any, raw: dict[str, Any], selectors: Mapping[str, Any], surface: Any
) -> Match | None:
    hits: list[Match] = []

    if cap in PATH_CAPABILITIES:
        path = _clean_path(_field(finding, "file_path"))
        if path:
            for pattern in selectors.get("paths") or []:
                if glob_match(pattern, path):
                    hits.append(Match(surface, "paths", pattern, _path_specificity(pattern)))

    elif cap == "containers":
        image = raw.get("image")
        if isinstance(image, str) and image.strip():
            repository = image_repository(image)
            for selector in selectors.get("images") or []:
                if selector == repository:
                    hits.append(Match(surface, "images", selector, 1000))

    elif cap == "network":
        address = _field(finding, "address") or raw.get("address")
        port = _field(finding, "port") or raw.get("port")
        hits += _address_hits(surface, selectors, address, port)
        hostname = raw.get("hostname")
        hits += _hostname_hits(surface, selectors, hostname)

    elif cap == "dast":
        instance = raw.get("instance")
        uri = instance.get("uri") if isinstance(instance, Mapping) else None
        if isinstance(uri, str) and uri:
            host, port = _host_port_of(uri)
            hits += _hostname_hits(surface, selectors, host)
            hits += _address_hits(surface, selectors, host, port)

    return max(hits, key=lambda m: m.specificity) if hits else None


def _address_hits(
    surface: Any, selectors: Mapping[str, Any], address: Any, port: Any
) -> list[Match]:
    if not address or port in (None, ""):
        return []
    host = str(address).strip().lower().strip("[]")
    port_text = str(port)
    hits = []
    for selector in selectors.get("addresses") or []:
        s_host, s_port = _split_host_port(selector)
        if s_host is None or s_port is None:
            continue
        if s_port not in ("*", port_text):
            continue
        if s_host == "*":
            hits.append(Match(surface, "addresses", selector, 200 if s_port != "*" else 50))
        elif s_host == host:
            hits.append(Match(surface, "addresses", selector, 900 if s_port != "*" else 600))
    return hits


def _hostname_hits(surface: Any, selectors: Mapping[str, Any], hostname: Any) -> list[Match]:
    if not isinstance(hostname, str) or not hostname:
        return []
    host = hostname.lower().rstrip(".")
    hits = []
    for selector in selectors.get("hostnames") or []:
        if selector == host:
            hits.append(Match(surface, "hostnames", selector, 800))
        elif selector.startswith("*.") and host.endswith(selector[1:]):
            # One label or more under the wildcard; never the apex itself.
            hits.append(Match(surface, "hostnames", selector, 300 + len(selector)))
    return hits


def glob_match(pattern: str, path: str) -> bool:
    """Repository glob: `*` within a segment, `**` across segments, `?` one
    character. A pattern ending in `/` is a directory and matches everything
    beneath it."""
    return _compile(pattern).fullmatch(path) is not None


_COMPILED: dict[str, re.Pattern[str]] = {}


def _compile(pattern: str) -> re.Pattern[str]:
    cached = _COMPILED.get(pattern)
    if cached is not None:
        return cached
    source = pattern + "**" if pattern.endswith("/") else pattern
    out = []
    i = 0
    while i < len(source):
        if source.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif source.startswith("**", i):
            out.append(".*")
            i += 2
        elif source[i] == "*":
            out.append("[^/]*")
            i += 1
        elif source[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(source[i]))
            i += 1
    compiled = re.compile("".join(out))
    _COMPILED[pattern] = compiled
    return compiled


def _path_specificity(pattern: str) -> int:
    """Literal characters before the first wildcard, so `backend/api/**` beats
    `backend/**`, and a pattern with no wildcard at all beats both."""
    first = min((pattern.find(c) for c in "*?[" if c in pattern), default=-1)
    if first == -1:
        return 1000 + len(pattern)
    return first


def _clean_path(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    path = value.replace("\\", "/")
    if path.startswith("file://"):
        path = path[len("file://") :]
    while path.startswith("./"):
        path = path[2:]
    return path.lstrip("/")


def _host_port_of(uri: str) -> tuple[str | None, int | None]:
    try:
        parts = urlsplit(uri)
        port = parts.port
    except ValueError:
        return None, None
    if port is None:
        port = {"https": 443, "http": 80}.get(parts.scheme.lower())
    return parts.hostname, port


def _field(finding: Any, name: str) -> Any:
    if isinstance(finding, Mapping):
        return finding.get(name)
    return getattr(finding, name, None)


def _raw(finding: Any) -> dict[str, Any]:
    """The tool's record. The lake stores it as JSON text; an adapter hands
    it over as a dict."""
    raw = _field(finding, "raw_finding_json")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            return {}
    return raw if isinstance(raw, dict) else {}


def _infer_capability(finding: Any) -> str:
    if _field(finding, "address"):
        return "network"
    raw = _raw(finding)
    if isinstance(raw.get("image"), str):
        return "containers"
    if isinstance(raw.get("instance"), Mapping):
        return "dast"
    return "sast"
