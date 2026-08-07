"""GitHub App authentication (spec 02 §2, spec 12 §2).

Two credentials, with very different lifetimes:

- The **App private key** is the only long-lived secret in the system. It is
  read from a secret manager or KMS, never the database, never a log, never a
  repo (spec 12 §4.2). It is used only to sign short-lived JWTs.
- **Installation access tokens** last about an hour and are minted on demand
  per installation. They are held in memory and never persisted (spec 12 §2).

The blast radius of the private key is documented in spec 12 §6.1 and is the
reason for both of those rules.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

import jwt

from mykronos.schemas import utcnow

#: GitHub rejects a JWT more than 10 minutes in the future. Eight, combined
#: with the 60s backdated `iat` below, keeps *both* readings of that limit
#: satisfied — `exp - now` is 480s and `exp - iat` is 540s, so it does not
#: matter which one a given validator applies. Nine minutes put `exp - iat`
#: exactly on 600 and depended on the interpretation going our way.
JWT_TTL_SECONDS = 8 * 60

#: Re-mint an installation token this long before it actually expires, so a
#: request never starts with a credential that dies mid-flight.
TOKEN_REFRESH_MARGIN = timedelta(minutes=5)


@dataclass(frozen=True)
class AppCredentials:
    """The registered GitHub App's identity."""

    app_id: str
    private_key_pem: str
    #: Verifies webhook payload signatures (spec 02 §4).
    webhook_secret: str = ""

    @classmethod
    def from_file(cls, app_id: str, key_path: Path, webhook_secret: str = "") -> AppCredentials:
        return cls(
            app_id=app_id,
            private_key_pem=key_path.read_text(encoding="utf-8"),
            webhook_secret=webhook_secret,
        )

    def app_jwt(self, now: int | None = None) -> str:
        """Sign a short-lived JWT proving we are the App.

        `iat` is backdated by 60s: GitHub rejects tokens issued in the future,
        and a slightly fast local clock is a common and otherwise baffling
        cause of 401s here.
        """
        issued = int(now if now is not None else time.time())
        payload = {
            "iat": issued - 60,
            "exp": issued + JWT_TTL_SECONDS,
            "iss": self.app_id,
        }
        return jwt.encode(payload, self.private_key_pem, algorithm="RS256")


@dataclass
class _CachedToken:
    token: str
    expires_at: datetime

    def usable(self, as_of: datetime) -> bool:
        return as_of + TOKEN_REFRESH_MARGIN < self.expires_at


class InstallationTokenCache:
    """In-memory cache of installation access tokens, keyed by installation id.

    Deliberately in memory only. Persisting these would create a second
    long-lived credential store for tokens whose whole security value is that
    they expire in an hour and live nowhere (spec 12 §2).
    """

    def __init__(self) -> None:
        self._tokens: dict[int, _CachedToken] = {}

    def get(self, installation_id: int, as_of: datetime | None = None) -> str | None:
        moment = as_of or utcnow()
        cached = self._tokens.get(installation_id)
        if cached is None or not cached.usable(moment):
            return None
        return cached.token

    def put(self, installation_id: int, token: str, expires_at: datetime) -> None:
        self._tokens[installation_id] = _CachedToken(token=token, expires_at=expires_at)

    def invalidate(self, installation_id: int) -> None:
        """Drop a token, e.g. after a 401 suggests it was revoked early."""
        self._tokens.pop(installation_id, None)

    def clear(self) -> None:
        self._tokens.clear()

    def __len__(self) -> int:
        return len(self._tokens)
