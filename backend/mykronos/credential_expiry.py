"""One place that knows when each credential expires (TheHub #61104).

On 2026-10-30 an agent credential with a seven-day lifetime lapsed mid-task and
review requests failed with "Token is not valid". Nothing had said it was
coming. This module answers "what expires soon?" from two kinds of source:

* **Observed**: MyKronos's own database. Agent credentials and repo read
  tokens carry `expires_at`; an active ingestion token carries `rotate_after`
  (the rotate-by date) and a superseded one carries `expires_at`.
* **Declared**: `credential-expiry-v1.yaml`, for credentials MyKronos cannot
  see (the CI token, an OAuth grant, the GitHub App key, a secrets-store
  token). A person wrote that date down; every row says so (`source`).

**Metadata only.** Rows hold a name, a kind, an owner, a date and a renewal
step. The token tables are read for those columns; their hash column is never
selected into a row, so there is nothing secret to leak (and the API test
proves it).

**The clock is a parameter.** Every function takes `now`. A window that reads
the real date makes fixed-date tests fail days later (#1034).

**Expired is listed, up to a point.** A credential that has lapsed and not been
renewed is the most useful row, so it is listed. An observed one stops being
listed after `EXPIRED_LOOKBACK_DAYS`, and when its holder has a live
replacement, otherwise a week-old agent credential would crowd the list for
ever. Revoked credentials are never listed: revoking is a decision, not a lapse.

There is deliberately no incident filing here: MyKronos has no hook that opens
a Hub incident, and the story's incident step needs one (see the pull request).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

import yaml
from sqlalchemy import select

from mykronos.db.models import AgentCredential, IngestionToken, RepoReadToken

#: How long after lapsing an observed credential stays on the list.
EXPIRED_LOOKBACK_DAYS = 7

Source = Literal["observed", "declared"]

#: The only keys a declared entry may carry. Anything else is refused, which is
#: what keeps a pasted token from riding in under a field nobody reviewed.
DECLARED_FIELDS = frozenset(
    {"name", "kind", "owner", "expires_at", "rotate_by", "renewal_step"}
)


@dataclass(frozen=True)
class Credential:
    name: str
    kind: str
    owner: str
    #: Naive UTC, like every timestamp in the database.
    expires_at: datetime | None
    renewal_step: str
    source: Source

    def hours_left(self, now: datetime) -> float | None:
        if self.expires_at is None:
            return None
        return round((self.expires_at - now).total_seconds() / 3600, 1)


class CredentialFileError(ValueError):
    """The declared file is unreadable or carries something it should not."""


def _naive_utc(value: Any, where: str) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        moment = value
    elif isinstance(value, date):
        moment = datetime(value.year, value.month, value.day, tzinfo=UTC)
    elif isinstance(value, str):
        try:
            moment = datetime.fromisoformat(value)
        except ValueError as exc:
            raise CredentialFileError(f"{where}: {value!r} is not an ISO date") from exc
    else:
        raise CredentialFileError(f"{where}: {value!r} is not a date")
    if moment.tzinfo is not None:
        moment = moment.astimezone(UTC).replace(tzinfo=None)
    return moment


def load_declared(path: Path | None) -> list[Credential]:
    """The declared credentials. A missing file is an empty list; a malformed
    one raises, because silently dropping an entry hides a credential."""
    if path is None or not path.exists():
        return []
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise CredentialFileError(f"{path.name}: not valid YAML") from exc
    entries = document.get("credentials") or []
    out: list[Credential] = []
    seen: set[str] = set()
    for index, entry in enumerate(entries):
        where = f"{path.name} entry {index}"
        if not isinstance(entry, dict):
            raise CredentialFileError(f"{where}: not a mapping")
        extra = set(entry) - DECLARED_FIELDS
        if extra:
            raise CredentialFileError(f"{where}: unknown field(s) {sorted(extra)}")
        for required in ("name", "kind", "owner", "renewal_step"):
            if not str(entry.get(required) or "").strip():
                raise CredentialFileError(f"{where}: {required} is required")
        name = str(entry["name"])
        if name in seen:
            raise CredentialFileError(f"{where}: duplicate name {name!r}")
        seen.add(name)
        when = _naive_utc(entry.get("expires_at"), where) or _naive_utc(
            entry.get("rotate_by"), where
        )
        out.append(
            Credential(
                name=name,
                kind=str(entry["kind"]),
                owner=str(entry["owner"]),
                expires_at=when,
                renewal_step=str(entry["renewal_step"]),
                source="declared",
            )
        )
    return out


# -- observed sources -------------------------------------------------------


def agent_credentials(session: Any, now: datetime) -> list[Credential]:
    floor = now - timedelta(days=EXPIRED_LOOKBACK_DAYS)
    rows = session.execute(
        select(
            AgentCredential.actor,
            AgentCredential.instance,
            AgentCredential.on_behalf_of,
            AgentCredential.expires_at,
        ).where(AgentCredential.revoked_at.is_(None), AgentCredential.expires_at > floor)
    ).all()
    live_actors = {r.actor for r in rows if r.expires_at > now}
    out = []
    for r in rows:
        if r.expires_at <= now and r.actor in live_actors:
            continue  # already replaced
        out.append(
            Credential(
                name=f"{r.actor} ({r.instance[:8]})",
                kind="agent-credential",
                owner=r.on_behalf_of or "operator",
                expires_at=r.expires_at,
                renewal_step=(
                    "Mint a replacement agent credential (POST /api/agents/credentials) "
                    "and give it to the agent."
                ),
                source="observed",
            )
        )
    return out


def read_tokens(session: Any, now: datetime) -> list[Credential]:
    floor = now - timedelta(days=EXPIRED_LOOKBACK_DAYS)
    rows = session.execute(
        select(
            RepoReadToken.repo_full_name,
            RepoReadToken.token_id,
            RepoReadToken.minted_by,
            RepoReadToken.expires_at,
        ).where(RepoReadToken.revoked_at.is_(None), RepoReadToken.expires_at > floor)
    ).all()
    return [
        Credential(
            name=f"repo-read token {r.repo_full_name} ({r.token_id[:8]})",
            kind="repo-read-token",
            owner=r.minted_by or "operator",
            expires_at=r.expires_at,
            renewal_step=(
                "Mint a new repo read token (POST /api/repo-read/tokens) and replace the "
                "caller's copy, then revoke the old one."
            ),
            source="observed",
        )
        for r in rows
    ]


def ingestion_tokens(session: Any, now: datetime) -> list[Credential]:
    floor = now - timedelta(days=EXPIRED_LOOKBACK_DAYS)
    out = []
    rows = session.execute(
        select(
            IngestionToken.repo_full_name,
            IngestionToken.status,
            IngestionToken.rotate_after,
            IngestionToken.expires_at,
        ).where(IngestionToken.status.in_(("active", "superseded")))
    ).all()
    for r in rows:
        if r.status == "superseded":
            # The old token stops working at expires_at: the repo's CI breaks
            # then unless it already holds the replacement.
            when = r.expires_at
            kind = "ingestion-token-overlap"
            step = "Confirm the repo's CI holds the new ingestion token before the overlap ends."
        else:
            when = r.rotate_after
            kind = "ingestion-token"
            step = f"Run `mykronos rotate-token {r.repo_full_name}` and sync the new secret."
        if when is None or when <= floor:
            continue
        out.append(
            Credential(
                name=f"ingestion token {r.repo_full_name}",
                kind=kind,
                owner="operator",
                expires_at=when,
                renewal_step=step,
                source="observed",
            )
        )
    return out


# -- the list ---------------------------------------------------------------


def collect(session: Any, declared: list[Credential], now: datetime) -> list[Credential]:
    return [
        *agent_credentials(session, now),
        *read_tokens(session, now),
        *ingestion_tokens(session, now),
        *declared,
    ]


def expiring(
    credentials: list[Credential], now: datetime, within_hours: float
) -> list[dict[str, Any]]:
    """Credentials already expired or expiring inside the window, soonest first."""
    horizon = now + timedelta(hours=within_hours)
    rows = []
    for c in credentials:
        if c.expires_at is None or c.expires_at > horizon:
            continue
        row = asdict(c)
        row["hours_left"] = c.hours_left(now)
        row["expired"] = c.expires_at <= now
        rows.append(row)
    rows.sort(key=lambda r: (r["expires_at"], r["name"]))
    return rows


def undated(credentials: list[Credential]) -> list[str]:
    return sorted(c.name for c in credentials if c.expires_at is None)
