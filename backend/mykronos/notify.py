"""Slack notification for the events worth interrupting somebody over.

Mykronos is the system of record for findings, decisions and scan runs, and it
cannot tell which CI produced any of them (spec 15 §4). That makes it the right
place to alert *from*: one notifier serves the GitHub Actions workflows in
onboarded repositories and both Concourse pipelines, and adding a third CI
would need no change here.

**What it deliberately cannot see.** A lane that dies before it uploads never
reaches this module — "the scan never ran" and "the scan ran and found nothing"
are distinguishable in the lake only when the runner got far enough to say so.
That gap is covered from the other side, by the pipelines' own `on_failure`
hooks, and the two are not redundant: this alerts on what arrived, and those
alert on what did not.

**Three rules, each of which is a way this could otherwise make things worse.**

1. *A notification failure is never an ingestion failure.* Every send is
   wrapped, and the worst outcome of Slack being down is a logged warning. A
   security platform that stops accepting findings because a chat service is
   unreachable has inverted its own priorities.
2. *One message per batch, never per finding.* A scan that uploads four hundred
   criticals is one event a person needs to know about, not four hundred. The
   summary names the count; the dashboard has the detail.
3. *Nothing untrusted reaches Slack unscrubbed.* Finding titles come from
   scanner output, which comes from repository content. `logsafe.scrub` is
   applied on the way out for the same reason it is applied on the way to a
   log.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import httpx2

from mykronos.logsafe import scrub

logger = logging.getLogger(__name__)

#: Slack renders a long message badly and truncates it silently. Well inside
#: the documented 40,000-character ceiling, because the useful part of any of
#: these is the first two lines.
MAX_TEXT = 2_500


@dataclass(frozen=True)
class Notification:
    """One thing worth telling somebody about.

    `repo_full_name` is separate from `detail` so a future router can send a
    repository's alerts to that team's channel without parsing prose.
    """

    title: str
    detail: str
    repo_full_name: str
    #: Drives the leading emoji only. Deliberately not a severity enum from
    #: `schemas`: this is about how loud the message looks, and a `Finding`
    #: severity and "how much does this interrupt someone" are different
    #: questions that would drift if one field answered both.
    level: str = "warning"

    def render(self) -> str:
        icon = {"critical": ":rotating_light:", "warning": ":warning:", "info": ":information_source:"}.get(
            self.level, ":warning:"
        )
        text = (
            f"{icon} *{scrub(self.title)}*\n"
            f"`{scrub(self.repo_full_name)}`\n"
            f"{scrub(self.detail)}"
        )
        return text[:MAX_TEXT]


class SlackNotifier:
    """Posts to a Slack incoming webhook, or does nothing at all.

    The disabled case is the common one — no webhook configured — and it is a
    first-class state rather than an error. There is deliberately no default
    webhook: a deployment that changed no configuration must not be posting
    anywhere (the same rule spec 12 §5.2 applies to the AI classifier).
    """

    def __init__(self, webhook_url: str = "", timeout: float = 10.0) -> None:
        self._webhook_url = webhook_url.strip()
        self._timeout = timeout

    @property
    def enabled(self) -> bool:
        return bool(self._webhook_url)

    async def send(self, note: Notification) -> bool:
        """Post one notification. Returns whether it was delivered.

        Never raises. Callers are ingestion endpoints on the hot path, and the
        return value exists for tests rather than for branching: there is
        nothing useful an ingestion handler could do about a failed post.
        """
        if not self.enabled:
            return False

        try:
            async with httpx2.AsyncClient(timeout=self._timeout) as http:
                response = await http.post(
                    self._webhook_url, json={"text": note.render()}
                )
            if response.status_code >= 400:
                # The webhook URL is a bearer credential; it is not logged, and
                # the response body is Slack's own text rather than ours.
                logger.warning(
                    "Slack rejected a notification: %s %s",
                    response.status_code,
                    scrub(response.text)[:200],
                )
                return False
            return True
        except Exception as exc:  # noqa: BLE001 - see the class docstring
            logger.warning("Could not post to Slack: %s", scrub(str(exc)))
            return False
