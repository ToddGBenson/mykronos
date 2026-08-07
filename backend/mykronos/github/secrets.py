"""Actions secret sealing (spec 03 §4a, spec 12 §4.4).

GitHub requires repository secrets to be encrypted client-side with a
libsodium sealed box against the repo's own public key. A plaintext secret
value never crosses the wire — not to GitHub, and not into any log or request
trace along the way.

This is also the reason `secrets: write` is safe to hold (spec 12 §6): the
API takes ciphertext we produced and never hands any secret value back.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass

from nacl import encoding, public


@dataclass(frozen=True)
class RepoPublicKey:
    """The repo's Actions public key, from `GET /repos/{o}/{r}/actions/secrets/public-key`."""

    key_id: str
    key_base64: str


def seal_secret(public_key_base64: str, plaintext: str) -> str:
    """Return the base64 sealed-box ciphertext GitHub's Secrets API expects.

    Sealed boxes are anonymous and one-way: we can encrypt to the repo's
    public key but cannot decrypt what we produced, and neither can anyone
    who intercepts it without the repo's private key, which only GitHub holds.
    """
    key = public.PublicKey(public_key_base64.encode("utf-8"), encoding.Base64Encoder)
    sealed = public.SealedBox(key).encrypt(plaintext.encode("utf-8"))
    return base64.b64encode(sealed).decode("utf-8")
