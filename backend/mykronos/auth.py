"""Ingestion token auth (spec 05 §4, spec 12 §2).

A token is scoped to exactly one `(repo_full_name, capability)` pair. That
scoping is the blast-radius control for the whole platform: a compromised CI
runner can pollute its own repo's own capability and nothing else — it cannot
read or write another repo's data, and it cannot reach the GitHub App key.

Only the SHA-256 of a token is ever persisted. Issuance returns the plaintext
exactly once; after that the platform genuinely cannot recover it.

Phase 0 stores the registry as a local JSON file. Phase 1 moves issuance
behind the Workflow Installer, which seals tokens into GitHub Actions repo
secrets (spec 03 §4a) — the validation path below does not change.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

TOKEN_BYTES = 32
ROTATION_DAYS = 90  # spec 05 §4


def hash_token(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


@dataclass
class TokenScope:
    token_sha256: str
    repo_full_name: str
    capability: str
    issued_at: str
    rotate_after: str
    revoked: bool = False
    label: str = ""

    def permits(self, repo_full_name: str, capability: str) -> bool:
        return (
            not self.revoked
            and self.repo_full_name == repo_full_name
            and self.capability == capability
        )


class TokenRegistry:
    """Token hashes and their scopes, persisted as JSON."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._scopes: dict[str, TokenScope] = {}
        self.reload()

    def reload(self) -> None:
        if not self.path.is_file():
            self._scopes = {}
            return
        raw = json.loads(self.path.read_text(encoding="utf-8") or "{}")
        self._scopes = {
            digest: TokenScope(**payload) for digest, payload in raw.get("tokens", {}).items()
        }

    def _persist(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"tokens": {digest: asdict(s) for digest, s in self._scopes.items()}}
        pending = self.path.with_suffix(".json.tmp")
        pending.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        pending.replace(self.path)

    def issue(self, repo_full_name: str, capability: str, label: str = "") -> str:
        """Mint a token and return its plaintext — the only time it exists."""
        plaintext = secrets.token_urlsafe(TOKEN_BYTES)
        now = datetime.now(UTC)
        scope = TokenScope(
            token_sha256=hash_token(plaintext),
            repo_full_name=repo_full_name,
            capability=capability,
            issued_at=now.isoformat(),
            rotate_after=(now + timedelta(days=ROTATION_DAYS)).isoformat(),
            label=label,
        )
        self._scopes[scope.token_sha256] = scope
        self._persist()
        return plaintext

    def revoke(self, repo_full_name: str, capability: str) -> int:
        """Revoke every token for a (repo, capability) pair.

        Called when a capability is disabled (spec 03 §5). Takes effect on the
        next request, with no grace period — spec 05 §9 requires it.
        """
        count = 0
        for scope in self._scopes.values():
            if (
                scope.repo_full_name == repo_full_name
                and scope.capability == capability
                and not scope.revoked
            ):
                scope.revoked = True
                count += 1
        if count:
            self._persist()
        return count

    def resolve(self, plaintext: str) -> TokenScope | None:
        """Return the scope for a presented token, or None."""
        scope = self._scopes.get(hash_token(plaintext))
        if scope is None or scope.revoked:
            return None
        return scope

    def list_scopes(self) -> list[TokenScope]:
        return list(self._scopes.values())
