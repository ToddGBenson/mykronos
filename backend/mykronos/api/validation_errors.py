"""A 422 that can always be rendered.

FastAPI's default handler echoes each offending value back under `input`.
Python's `json` module accepts `NaN`, `Infinity` and `1e400` (which parses to
infinity), so a body carrying one of those in a constrained float — a
finding's `cvss_score`, say — fails validation correctly and then fails
*again* rendering the 422, because Starlette refuses to serialise a
non-finite float. The caller saw a 500 for what spec 05 §4 says is a 422.

The fallback drops `input` (and `ctx`, which can carry the same value as a
bound) rather than rewriting it: the location and message still say exactly
what was wrong, and the caller already holds what it sent.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

_ECHOED = ("input", "ctx")


async def _render(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, RequestValidationError)
    errors: list[Any] = list(exc.errors())
    try:
        return JSONResponse(status_code=422, content={"detail": jsonable_encoder(errors)})
    except (ValueError, RecursionError):
        bare = [
            {key: value for key, value in error.items() if key not in _ECHOED}
            if isinstance(error, dict)
            else str(error)
            for error in errors
        ]
        return JSONResponse(status_code=422, content={"detail": jsonable_encoder(bare)})


def install(app: FastAPI) -> None:
    app.add_exception_handler(RequestValidationError, _render)
