"""Safe validation against the demo environment (TheHub #60892, Triage T5).

Epic #60879 decided that validation is *evidence plus safe tests on the demo
only, never production*. This module is that rule, and the record it leaves.

**Where a request may go.** Exactly one origin: `validation_demo_origin`, set
by the operator. Empty, nothing is sent (`not_configured`). An origin is
compared as scheme, lower-cased host and port with the scheme's default port
filled in, so `HTTPS://Prod.Example:443/` is the same origin as
`https://prod.example`. The demo is refused (`demo_is_production`) when it
matches a configured production origin, or when the finding itself is from
the `prod` DAST lane (D-155) and was recorded *at* the demo origin, which
means the "demo" served production. Three layers keep a request on the demo:

1. a ZAP finding's recorded URL is never used as the target - only its path
   and query, re-based onto the demo origin, so a finding recorded against
   production is replayed at the demo;
2. the re-based URL is checked again after it is built;
3. the HTTP client refuses, in a request hook, anything whose origin is not
   the demo, and never follows a redirect (a 3xx is recorded, not chased).

**What may be sent.** One GET or HEAD, as the scanner recorded it, with no
credentials. A recorded POST/PUT/PATCH/DELETE is refused (`unsafe_method`):
replaying a write is not a safe test even on the demo.

**Nuclei.** Templates run elsewhere (the backend has no nuclei) and their
result is reported here. The report is refused when its target is a
production origin (`production`) or any origin but the demo (`not_demo`), or
when the template carries a tag nuclei uses for destructive or noisy checks
(`unsafe_template`).

**The verdict** is one of `validated`, `not_validated` or `inconclusive`, and
it is never applied: a validation changes no finding. A ZAP replay is
`validated` when the evidence ZAP recorded appears in the response's headers
or body; `not_validated` when the demo answered (2xx, 404, 410) without it;
and `inconclusive` when there was nothing recorded to look for, the demo did
not answer, or it answered with something that is not the page (a redirect,
a gate's 401/403, a 429 or a 5xx). The request sent and the response received
are kept with the verdict - the response bounded and with cookies and
credentials redacted - so the reader sees what was observed.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import httpx2
from sqlalchemy import select
from sqlalchemy.orm import Session

from mykronos.db.models import FindingValidation
from mykronos.logsafe import scrub

logger = logging.getLogger(__name__)

VALIDATED = "validated"
NOT_VALIDATED = "not_validated"
INCONCLUSIVE = "inconclusive"
VERDICTS = (VALIDATED, NOT_VALIDATED, INCONCLUSIVE)

ZAP_REPLAY = "zap_replay"
NUCLEI = "nuclei"

ENVIRONMENT = "demo"
PROD_LANE = "prod"

SAFE_METHODS = frozenset({"GET", "HEAD"})

#: Nuclei tags for checks that change state, flood, or guess - never run
#: against anything, demo included, under the name "validation".
UNSAFE_TEMPLATE_TAGS = frozenset(
    {"intrusive", "dos", "fuzz", "fuzzing", "bruteforce", "brute-force", "destructive"}
)

#: What of a response body is kept on the record.
BODY_KEPT_BYTES = 8_192
#: A reported nuclei request or response is kept up to this many characters.
RAW_KEPT_CHARS = 16_384
REDACTED = "[redacted]"
_REDACTED_HEADERS = frozenset(
    {"set-cookie", "cookie", "authorization", "proxy-authorization", "x-api-key"}
)

USER_AGENT = "mykronos-validation"

#: Statuses where the demo answered with the page (or that it is gone): an
#: absent piece of evidence there is a real "not reproduced".
_ANSWERED = frozenset({404, 410})

_DEFAULT_PORTS = {"http": 80, "https": 443}


class RefusedError(Exception):
    """A validation that may not run. Nothing was sent."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def origin_of(url: str) -> str | None:
    """`scheme://host[:port]`, normalised, or None if `url` has no http(s) origin."""
    try:
        parts = urlsplit(url.strip())
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if scheme not in _DEFAULT_PORTS or not host:
        return None
    if ":" in host:
        host = f"[{host}]"
    if port is None or port == _DEFAULT_PORTS[scheme]:
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


@dataclass(frozen=True)
class TargetPolicy:
    """Where a validation may go: the demo origin, and what is production."""

    demo_origin: str
    production_origins: tuple[str, ...] | list[str] = ()

    @classmethod
    def from_settings(cls, settings: Any) -> TargetPolicy:
        return cls(
            demo_origin=str(getattr(settings, "validation_demo_origin", "") or ""),
            production_origins=tuple(getattr(settings, "validation_production_origins", ()) or ()),
        )

    @property
    def production(self) -> frozenset[str]:
        return frozenset(o for o in (origin_of(p) for p in self.production_origins) if o)

    def demo(self) -> str:
        """The normalised demo origin, or `RefusedError` if it is unset or production."""
        if not self.demo_origin.strip():
            raise RefusedError(
                "not_configured",
                "No demo origin is configured (validation_demo_origin), so nothing is sent.",
            )
        demo = origin_of(self.demo_origin)
        if demo is None:
            raise RefusedError(
                "not_configured", "The configured demo origin is not an http(s) origin."
            )
        if demo in self.production:
            raise RefusedError(
                "demo_is_production",
                "The configured demo origin is a production origin; validation never "
                "targets production.",
            )
        return demo

    def check(self, url: str) -> str:
        """`url`'s origin if it is the demo; `RefusedError` otherwise."""
        demo = self.demo()
        origin = origin_of(url)
        if origin is not None and origin in self.production:
            raise RefusedError("production", "The target is a production origin.")
        if origin != demo:
            raise RefusedError("not_demo", "The target is not the demo origin.")
        return demo


@dataclass(frozen=True)
class ReplayPlan:
    method: str
    url: str
    evidence: str
    recorded_uri: str
    template_id: str = ""


@dataclass
class Result:
    verdict: str
    reason: str
    target_origin: str
    request: dict[str, Any] = field(default_factory=dict)
    response: dict[str, Any] = field(default_factory=dict)


def _raw(finding: Mapping[str, Any]) -> dict[str, Any]:
    raw = finding.get("raw_finding_json")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            return {}
    return raw if isinstance(raw, dict) else {}


def replay_plan(finding: Mapping[str, Any], policy: TargetPolicy) -> ReplayPlan:
    """The one request a ZAP finding's replay would send, or `RefusedError`."""
    demo = policy.demo()
    raw = _raw(finding)
    instance = raw.get("instance")
    uri = instance.get("uri") if isinstance(instance, Mapping) else None
    if finding.get("capability") != "dast" or not isinstance(uri, str) or not uri:
        raise RefusedError(
            "no_replay", "Only a DAST finding with a recorded request can be replayed."
        )
    assert isinstance(instance, Mapping)
    method = str(instance.get("method") or "GET").upper()
    if method not in SAFE_METHODS:
        raise RefusedError(
            "unsafe_method",
            f"The recorded request is a {method}; only GET and HEAD are replayed.",
        )
    if str(finding.get("symbol") or "") == PROD_LANE and origin_of(uri) == demo:
        raise RefusedError(
            "demo_is_production",
            "This production-lane finding was recorded at the demo origin, so the "
            "demo origin serves production.",
        )
    try:
        parts = urlsplit(uri)
    except ValueError as exc:
        raise RefusedError("no_replay", "The recorded request URL does not parse.") from exc
    # Only the path and query travel. A path that starts with `//` would read
    # as a host to the next parser, so it is collapsed to one slash.
    path = "/" + (parts.path or "/").lstrip("/")
    url = demo + path + (f"?{parts.query}" if parts.query else "")
    policy.check(url)
    return ReplayPlan(
        method=method,
        url=url,
        evidence=str(instance.get("evidence") or ""),
        recorded_uri=uri,
        template_id=str(raw.get("alertRef") or finding.get("rule_id") or ""),
    )


def _headers(headers: Iterable[tuple[str, str]]) -> dict[str, str]:
    kept: dict[str, str] = {}
    for name, value in headers:
        key = name.lower()
        value = REDACTED if key in _REDACTED_HEADERS else value
        kept[key] = f"{kept[key]}, {value}" if key in kept else value
    return kept


def _verdict(evidence: str, status: int, headers: httpx2.Headers, body: str) -> tuple[str, str]:
    if not evidence:
        return INCONCLUSIVE, "The finding records no evidence to look for in the response."
    # Header names are case-insensitive, and the client lower-cases them.
    header_text = "\n".join(f"{k}: {v}" for k, v in headers.items()).lower()
    if evidence.lower() in header_text or evidence in body:
        return VALIDATED, f"The demo's response contains the recorded evidence {evidence!r}."
    if 200 <= status < 300 or status in _ANSWERED:
        return (
            NOT_VALIDATED,
            f"The demo answered {status} without the recorded evidence {evidence!r}.",
        )
    return (
        INCONCLUSIVE,
        f"The demo answered {status}, which is not the page the finding was recorded on.",
    )


async def replay(
    plan: ReplayPlan,
    policy: TargetPolicy,
    *,
    timeout: float = 15.0,
    transport: httpx2.AsyncBaseTransport | None = None,
) -> Result:
    """Send `plan`'s one request to the demo and judge the answer."""
    demo = policy.check(plan.url)

    async def on_the_demo(request: httpx2.Request) -> None:
        policy.check(str(request.url))

    headers = {"User-Agent": USER_AGENT}
    sent = {
        "method": plan.method,
        "url": plan.url,
        "headers": headers,
        "recorded_uri": plan.recorded_uri,
        "evidence_sought": plan.evidence,
    }
    async with httpx2.AsyncClient(
        timeout=timeout,
        follow_redirects=False,
        transport=transport,
        event_hooks={"request": [on_the_demo]},
        trust_env=False,
    ) as http:
        try:
            response = await http.request(plan.method, plan.url, headers=headers)
        except RefusedError:
            raise
        except httpx2.HTTPError as exc:
            return Result(
                verdict=INCONCLUSIVE,
                reason="The demo did not answer.",
                target_origin=demo,
                request=sent,
                response={"error": f"{type(exc).__name__}: {scrub(str(exc))}"[:500]},
            )
        content = response.content or b""
    body = content[:BODY_KEPT_BYTES].decode("utf-8", errors="replace")[:BODY_KEPT_BYTES]
    verdict, reason = _verdict(
        plan.evidence, response.status_code, response.headers, content.decode("utf-8", "replace")
    )
    return Result(
        verdict=verdict,
        reason=reason,
        target_origin=demo,
        request=sent,
        response={
            "status": response.status_code,
            "headers": _headers(response.headers.multi_items()),
            "body": body,
            "body_truncated": len(content) > BODY_KEPT_BYTES,
        },
    )


def check_nuclei(policy: TargetPolicy, *, target_url: str, template_tags: Iterable[str]) -> str:
    """The demo origin if a reported nuclei run may be recorded; `RefusedError` if not."""
    demo = policy.check(target_url)
    unsafe = sorted({t.strip().lower() for t in template_tags} & UNSAFE_TEMPLATE_TAGS)
    if unsafe:
        raise RefusedError(
            "unsafe_template",
            f"The template is tagged {', '.join(unsafe)}; validation runs only "
            "non-destructive templates.",
        )
    return demo


NUCLEI_VERDICTS = {"matched": VALIDATED, "not_matched": NOT_VALIDATED, "error": INCONCLUSIVE}


def nuclei_result(
    *,
    demo: str,
    template_id: str,
    template_tags: Iterable[str],
    target_url: str,
    outcome: str,
    request: str,
    response: str,
) -> Result:
    verdict = NUCLEI_VERDICTS[outcome]
    reason = {
        VALIDATED: f"Nuclei template {template_id} matched on the demo.",
        NOT_VALIDATED: f"Nuclei template {template_id} ran on the demo and did not match.",
        INCONCLUSIVE: f"Nuclei template {template_id} did not complete on the demo.",
    }[verdict]
    return Result(
        verdict=verdict,
        reason=reason,
        target_origin=demo,
        request={
            "url": target_url,
            "template_tags": sorted({t.strip().lower() for t in template_tags if t.strip()}),
            "raw": request[:RAW_KEPT_CHARS],
        },
        response={"raw": response[:RAW_KEPT_CHARS], "truncated": len(response) > RAW_KEPT_CHARS},
    )


def record(
    session: Session,
    finding: Mapping[str, Any],
    result: Result,
    *,
    source: str,
    template_id: str,
    requested_by: str,
    actor_kind: str,
) -> FindingValidation:
    row = FindingValidation(
        finding_id=str(finding.get("finding_id") or ""),
        repo_full_name=str(finding.get("repo_full_name") or ""),
        source=source,
        template_id=template_id[:255],
        environment=ENVIRONMENT,
        target_origin=result.target_origin,
        verdict=result.verdict,
        reason=result.reason,
        request=result.request,
        response=result.response,
        requested_by=requested_by,
        actor_kind=actor_kind,
    )
    session.add(row)
    session.flush()
    logger.info(
        "Validation of %s on the demo: %s (%s)",
        scrub(row.finding_id[:12]),
        result.verdict,
        source,
    )
    return row


def history(session: Session, finding_id: str) -> list[FindingValidation]:
    """Every validation of one finding, newest first."""
    return list(
        session.scalars(
            select(FindingValidation)
            .where(FindingValidation.finding_id == finding_id)
            .order_by(FindingValidation.created_at.desc(), FindingValidation.id)
        )
    )
