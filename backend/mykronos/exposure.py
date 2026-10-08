"""What a public endpoint shows anyone who asks (observed, not declared).

THE GAP THIS CLOSES. On 2026-10-01 two services were on the public internet
through a Cloudflare tunnel, and the platform said nothing about either:

- ``demo.toddbenson.net`` served TheHub's demo with its gate disabled - the
  full API schema, 1,766 operations, 891 of them writes, to anyone - while
  holding the production AI keys;
- ``blog.toddbenson.net`` served *Concourse*: every pipeline's job list and
  build logs, a private repository's included, readable without logging in.

Both were declared ``internal`` in the threat model (``surfaces.py``) because
the declarations came from a LAN port scan, which cannot see a tunnel. A
declaration is a person's claim; this module is the observation that can
contradict it.

WHAT IS ASKED, AND WHAT IS NOT. Each probe is a handful of plain GETs a browser
would make - ``/openapi.json``, ``/docs``, ``/api/v1/info`` - against a URL the
operator registered as public. No credentials, no writes, no fuzzing, no
following of what the answers point to. The question is only "what does an
anonymous visitor get", which is the question exposure is about.

WHAT IS CLAIMED. An observation is a fact about one response ("the schema was
served without credentials, with N write operations"), and the severity says
how much that fact matters. It does not claim the API *executes* those writes
anonymously - only that it publishes them to anyone, which on a gated
deployment it does not (production answers 401 to the same request).
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import socket
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urlsplit

import httpx2
from sqlalchemy import select

from mykronos.logsafe import scrub
from mykronos.schemas import utcnow

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 15.0

#: The anonymous requests a probe makes, and nothing else.
PATHS = ("/openapi.json", "/docs", "/api/v1/info", "/api/v1/teams/main/pipelines")

WRITE_METHODS = ("post", "put", "patch", "delete")

#: Probe outcomes for the endpoint as a whole.
NOT_PROBED = "not_probed"
PROBED = "probed"
UNREACHABLE = "unreachable"
#: The hostname resolves, from where the probe runs, only to loopback or
#: private addresses - a hosts-file entry or split DNS. A request would reach
#: the local service, not the internet path, so nothing is probed: reporting
#: that as "unreachable" or as clean would both be wrong.
RESOLVES_LOCALLY = "resolves_locally"


def _local_only(host: str) -> list[str] | None:
    """The addresses `host` resolves to here, if every one is loopback,
    private or link-local; None if any is public or it does not resolve."""
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return None
    addresses = sorted({str(info[4][0]) for info in infos})
    if not addresses:
        return None
    for address in addresses:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
        if not (ip.is_loopback or ip.is_private or ip.is_link_local):
            return None
    return addresses


@dataclass
class Observation:
    """One thing an anonymous visitor can get, and how much it matters."""

    kind: str
    severity: str
    title: str
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class Answer:
    """What one GET returned. `body` is capped; nothing here needs more."""

    status: int | None
    content_type: str = ""
    body: str = ""
    error: str = ""


def _json(answer: Answer | None) -> Any:
    if answer is None or answer.status != 200:
        return None
    try:
        return json.loads(answer.body)
    except ValueError:
        return None


def classify(answers: dict[str, Answer]) -> list[Observation]:
    """Turn the probe's answers into observations. Pure: no network.

    Each rule reads only what it names. An answer that is not what a rule
    expects is not stretched to fit it - a 200 HTML page at /openapi.json is a
    catch-all route, not a published schema.
    """
    found: list[Observation] = []

    schema = _json(answers.get("/openapi.json"))
    if isinstance(schema, dict) and isinstance(schema.get("paths"), dict):
        ops = [
            (method.lower(), path)
            for path, item in schema["paths"].items()
            if isinstance(item, dict)
            for method in item
            if method.lower() in ("get", *WRITE_METHODS)
        ]
        writes = [op for op in ops if op[0] in WRITE_METHODS]
        admin = sorted({p for m, p in writes if "/admin" in p})[:5]
        found.append(
            Observation(
                kind="api_schema_public",
                severity="high" if writes else "medium",
                title=(
                    f"API schema served without credentials: {len(ops)} operations, "
                    f"{len(writes)} of them writes"
                ),
                detail=(
                    "Anyone can read the full API description. On a gated deployment "
                    "this request is refused; served here, it is either an ungated API "
                    "or a published map of a gated one."
                    + (f" Admin write routes listed: {', '.join(admin)}." if admin else "")
                ),
                evidence={"operations": len(ops), "writes": len(writes), "admin_writes": admin},
            )
        )

    docs = answers.get("/docs")
    if docs is not None and docs.status == 200 and "swagger" in docs.body.lower():
        found.append(
            Observation(
                kind="api_docs_public",
                severity="medium",
                title="Interactive API docs served without credentials",
                detail=(
                    "/docs renders a Swagger UI that can send requests to the API "
                    "from the visitor's browser."
                ),
            )
        )

    info = _json(answers.get("/api/v1/info"))
    if isinstance(info, dict) and "worker_version" in info:
        pipelines = _json(answers.get("/api/v1/teams/main/pipelines"))
        public = (
            sorted(
                str(p.get("name"))
                for p in pipelines
                if isinstance(p, dict) and p.get("public")
            )
            if isinstance(pipelines, list)
            else []
        )
        found.append(
            Observation(
                kind="ci_public",
                severity="high" if public else "medium",
                title=(
                    f"CI server (Concourse {info.get('version', '?')}) answers anonymously"
                    + (f"; {len(public)} public pipeline(s)" if public else "")
                ),
                detail=(
                    "The CI API is reachable without logging in. Public pipelines expose "
                    "their job lists and build logs to anyone, and the login page is "
                    "open to password guessing."
                    + (f" Public: {', '.join(public)}." if public else "")
                ),
                evidence={"version": info.get("version"), "public_pipelines": public},
            )
        )
    return found


async def probe_endpoint(
    url: str, *, timeout: float = DEFAULT_TIMEOUT_SECONDS
) -> tuple[str, dict[str, Answer], str]:
    """GET each of `PATHS` under `url`, anonymously. Returns `(status, answers, detail)`."""
    base = url.rstrip("/")
    host = urlsplit(base).hostname or ""
    local = await asyncio.to_thread(_local_only, host) if host else None
    if local is not None:
        return (
            RESOLVES_LOCALLY,
            {},
            f"{host} resolves to {', '.join(local)} from where the probe runs (a hosts-file "
            "entry or split DNS), so a request would reach the local service rather than the "
            "internet path. Not probed; probe it from outside, or remove the local override.",
        )
    answers: dict[str, Answer] = {}
    errors: list[str] = []
    async with httpx2.AsyncClient(timeout=timeout, follow_redirects=False) as http:
        for path in PATHS:
            try:
                response = await http.get(base + path)
            except Exception as exc:  # noqa: BLE001 - one unreachable path is data
                answers[path] = Answer(status=None, error=str(exc))
                errors.append(f"{path}: {scrub(str(exc))}")
                continue
            answers[path] = Answer(
                status=response.status_code,
                content_type=str(response.headers.get("content-type", "")),
                body=response.text[:4_000_000],
            )
    if all(a.status is None for a in answers.values()):
        return UNREACHABLE, answers, f"{scrub(url)} could not be reached: " + "; ".join(errors[:2])
    return PROBED, answers, ""


def validate_url(url: str) -> str:
    """An absolute http(s) URL with a host, and nothing else."""
    parts = urlsplit(url.strip())
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ValueError("A public endpoint is an absolute http(s) URL, e.g. https://demo.example.com")
    if parts.query or parts.fragment:
        raise ValueError("Register the base URL only; the probe chooses the paths it asks for.")
    return f"{parts.scheme}://{parts.netloc}{parts.path.rstrip('/')}"


def endpoints(db: Any) -> list[Any]:
    from mykronos.db.models import PublicEndpoint

    with db.session() as session:
        rows = session.scalars(select(PublicEndpoint).order_by(PublicEndpoint.url)).all()
        for row in rows:
            session.expunge(row)
        return list(rows)


def record(
    db: Any, endpoint_id: str, status: str, observations: list[Observation], detail: str
) -> None:
    """Store the latest answer, and audit when what is exposed changes."""
    from mykronos.db.models import PublicEndpoint

    now = utcnow()
    with db.session() as session:
        row = session.get(PublicEndpoint, endpoint_id)
        if row is None:
            return
        before = sorted(o.get("kind", "") for o in (row.observations or []))
        after = sorted(o.kind for o in observations)
        row.last_status = status
        row.last_probed_at = now
        row.last_detail = detail
        # An unreachable probe is not evidence the exposure went away: keep
        # the last observations rather than reporting the endpoint clean.
        if status == PROBED:
            row.observations = [asdict(o) for o in observations]
            if before != after:
                db.audit(
                    session,
                    actor="job:exposure",
                    action="exposure.changed",
                    entity_type="public_endpoint",
                    entity_id=row.id,
                    url=row.url,
                    before=before,
                    after=after,
                )
        session.commit()


async def run_sweep(db: Any, *, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> list[dict[str, Any]]:
    """The scheduled job: probe every registered endpoint and record what it saw."""
    results: list[dict[str, Any]] = []
    for row in endpoints(db):
        try:
            status, answers, detail = await probe_endpoint(row.url, timeout=timeout)
        except Exception as exc:  # noqa: BLE001 - one endpoint must not stop the sweep
            status, answers, detail = UNREACHABLE, {}, scrub(str(exc))
        observations = classify(answers) if status == PROBED else []
        record(db, row.id, status, observations, detail)
        if any(o.severity in ("critical", "high") for o in observations):
            logger.warning(
                "Public endpoint %s exposes: %s",
                scrub(row.url),
                "; ".join(o.title for o in observations),
            )
        results.append(
            {"url": row.url, "status": status, "observations": [asdict(o) for o in observations]}
        )
    return results


def summary(db: Any) -> list[dict[str, Any]]:
    """Every registered endpoint with its last observations, worst first."""
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    out = []
    for row in endpoints(db):
        obs = list(row.observations or [])
        worst = min((order.get(o.get("severity", ""), 9) for o in obs), default=9)
        out.append(
            {
                "id": row.id,
                "url": row.url,
                "repo_full_name": row.repo_full_name,
                "label": row.label,
                "last_status": row.last_status,
                "last_probed_at": row.last_probed_at.isoformat() if row.last_probed_at else None,
                "last_detail": row.last_detail,
                "observations": obs,
                "_worst": worst,
            }
        )
    out.sort(key=lambda e: (e["_worst"], e["url"]))
    for e in out:
        e.pop("_worst")
    return out


__all__ = [
    "Answer",
    "Observation",
    "classify",
    "probe_endpoint",
    "run_sweep",
    "summary",
    "validate_url",
]
