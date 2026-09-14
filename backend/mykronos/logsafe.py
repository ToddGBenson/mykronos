"""Keeping untrusted text out of the shape of a log line (spec 12 §8).

Log injection is not about what an attacker can make a log *say*. It is about
what they can make it *look like*. A newline in a value that reaches a log
message ends the record early and starts one the reader has no reason to
doubt — same file, same format, same timestamp column. The forged line can
claim any actor, any outcome, any repository, and nothing downstream can tell
it from a real one. Audit trails are the control that makes every other
control reviewable, so this is worth closing even where the reachable input is
semi-trusted.

Two layers, deliberately:

`scrub()` at the call sites where a value crosses a trust boundary — a webhook
header, an actor, an exception message from a remote service. Explicit, so a
reader can see which values were considered untrusted and so static analysis
can follow the sanitizer.

`ControlCharacterFilter` on the root logger as a backstop, because the first
layer only protects the call sites somebody remembered. Every future log
statement is covered without anyone having to know this module exists.
"""

from __future__ import annotations

import logging
from typing import Any

_logger = logging.getLogger(__name__)

#: Long enough for a repository name, a rule id, or a GitHub delivery uuid
#: with room to spare; short enough that a hostile value cannot push the rest
#: of a record off the end of a viewer's screen.
MAX_LENGTH = 256

#: Everything below 0x20 plus DEL. Covers CR and LF, which forge records, and
#: also the terminal escapes that let a value rewrite what a reader sees when
#: logs are tailed in a console.
_CONTROL = {c: None for c in range(0x20)}
_CONTROL[0x7F] = None


def scrub(value: Any, *, max_length: int = MAX_LENGTH) -> str:
    """Render `value` safe to interpolate into a log message.

    Control characters are replaced rather than dropped: a value that arrives
    with a newline in it is itself worth noticing, and silently closing the gap
    would hide that. `\\n` in the output is a visible artefact of a hostile or
    malformed input.
    """
    text = value if isinstance(value, str) else str(value)
    text = text.replace("\r\n", "\\n").replace("\n", "\\n").replace("\r", "\\r")
    text = text.translate(_CONTROL)
    if len(text) > max_length:
        text = text[: max_length - 1] + "…"
    return text


class ControlCharacterFilter(logging.Filter):
    """Scrub the formatted message of every record passing through.

    Applied to the root logger's handlers, so it catches log statements this
    module's authors never saw — including third-party libraries logging
    request data. It does not replace `scrub()` at the boundary: this runs
    after formatting, so it cannot distinguish a value from the message around
    it, and a filter is easy to omit when a new handler is added.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # noqa: BLE001 — a bad format string must not kill logging
            return True
        cleaned = scrub(message, max_length=4096)
        if cleaned != message:
            record.msg = cleaned
            record.args = ()
        return True


def _attach(target: logging.Logger) -> int:
    """Add the filter to any of `target`'s own handlers that lack it."""
    attached = 0
    for handler in target.handlers:
        if not any(isinstance(f, ControlCharacterFilter) for f in handler.filters):
            handler.addFilter(ControlCharacterFilter())
            attached += 1
    return attached


def install(logger: logging.Logger | None = None) -> int:
    """Attach the backstop filter to every handler that will emit a record.

    On the handlers rather than the loggers: a filter on a logger does not see
    records propagated up from its children, which is most of them.

    Root is not enough, and assuming it was made this a no-op in production for
    its whole life (#364). Under uvicorn the root logger has **zero** handlers:
    uvicorn configures the named loggers `uvicorn` and `uvicorn.access` with
    their own handlers and `propagate: False`, so nothing reaches root and the
    original loop body never executed. Measured inside the running image, after
    `lifespan` had called this function:

        root             handlers=0  ControlCharacterFilter=False
        uvicorn          handlers=1  ControlCharacterFilter=False
        uvicorn.access   handlers=1  ControlCharacterFilter=False

    `uvicorn.access` is exactly the logger that writes attacker-influenced
    request lines, so the one logger this was described as covering was the one
    it could never reach.

    Every logger with handlers of its own is therefore walked, via the stdlib's
    own registry rather than by naming uvicorn: a `propagate: False` logger is
    a terminal sink wherever it comes from, and the next library to configure
    one should not need this function edited.

    Returns the number of handlers newly filtered, so a caller can tell
    "already installed" from "covered nothing" — the two states this could not
    previously distinguish, and the reason a silent no-op survived.
    """
    if logger is not None:
        return _attach(logger)

    root = logging.getLogger()
    attached = _attach(root)
    covered = len(root.handlers)

    # `loggerDict` holds PlaceHolder entries for intermediate names that were
    # never configured; only real Loggers have handlers.
    for existing in list(logging.root.manager.loggerDict.values()):
        if isinstance(existing, logging.Logger) and existing.handlers:
            attached += _attach(existing)
            covered += len(existing.handlers)

    if not covered:
        # Not an exception: logging is not worth crashing a deployment over.
        # But a backstop protecting nothing must not look identical to one that
        # is doing its job, which is the whole defect this docstring describes.
        #
        # Resolved through the module attribute rather than inline, so this
        # branch is reachable from a test: the only way to reach it is to leave
        # the process with no handlers anywhere, which also removes the ones a
        # test would use to observe it.
        _logger.warning(
            "logsafe.install() found no log handlers to filter; untrusted text "
            "is protected only at the call sites that scrub explicitly."
        )
    return attached
