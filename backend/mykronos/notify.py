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
from typing import Any, Protocol

import httpx2

from mykronos.logsafe import scrub

logger = logging.getLogger(__name__)

#: Slack renders a long message badly and truncates it silently. Well inside
#: the documented 40,000-character ceiling, because the useful part of any of
#: these is the first two lines.
MAX_TEXT = 2_500

_ICONS = {
    "critical": ":rotating_light:",
    "warning": ":warning:",
    "info": ":information_source:",
}


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
        icon = _ICONS.get(self.level, ":warning:")
        text = (
            f"{icon} *{scrub(self.title)}*\n"
            f"`{scrub(self.repo_full_name)}`\n"
            f"{scrub(self.detail)}"
        )
        return text[:MAX_TEXT]


class Notifier(Protocol):
    """What a caller may assume about a notifier.

    It exists because `send` is a coroutine and nothing said so at a call
    site typed `Any`. `digest.send_all` took that `Any`, called `send`
    without awaiting it, and logged that a digest had gone out — for a
    fortnightly job that had never delivered anything and could not have.
    A test double with a *synchronous* `send` agreed with it.

    One line of type, and mypy answers the question the double could not.
    """

    @property
    def enabled(self) -> bool:
        """Whether anything sent here reaches a person."""

    async def send(self, note: Notification) -> bool:
        """Post one notification. Returns whether it was delivered."""


#: Slack's own endpoint for posting as a bot. Named here rather than made
#: configurable: a "Slack notifier" pointed at an arbitrary host is a
#: findings exfiltration path with a reassuring name.
CHAT_POST_MESSAGE = "https://slack.com/api/chat.postMessage"


class SlackNotifier:
    """Posts to Slack as a bot, or to an incoming webhook, or nowhere.

    The disabled case is the common one and is a first-class state rather than
    an error. There is deliberately no default endpoint of either kind: a
    deployment that changed no configuration must not be posting anywhere (the
    same rule spec 12 §5.2 applies to the AI classifier).

    **Two transports, because this estate already chose one and this module
    could not speak it.** The Concourse pipelines post with a bot token
    against `chat.postMessage`, and say why in the `slack_alert` anchor: a
    webhook's secret lives in the URL path of the endpoint being called, so
    whatever holds the URL holds the credential, while a bot token lives in an
    `Authorization:` header that Vault can substitute at egress. That was PS-9
    on this host, and thehub and personal-soc already resolve the same
    credential at team scope — one Slack identity rather than three.

    This module accepted only a webhook, so configuring notification (B-035)
    meant minting a second Slack identity of the kind the pipelines had
    already argued against. It now takes either, and prefers the bot token
    when both are set.

    **`ok: false` arrives with a 200.** Slack answers `chat.postMessage` with
    HTTP 200 and `{"ok": false, "error": "channel_not_found"}` for a bad
    channel, a revoked token or a bot that was never invited. A status-code
    check alone reports every one of those as delivered, which is the failure
    this platform exists to report: a green result for something that did not
    happen. The webhook transport keeps its status-code check, because that is
    how incoming webhooks actually signal refusal.
    """

    def __init__(
        self,
        webhook_url: str = "",
        timeout: float = 10.0,
        *,
        bot_token: str = "",
        channel: str = "",
    ) -> None:
        self._webhook_url = webhook_url.strip()
        self._bot_token = bot_token.strip()
        self._channel = channel.strip()
        self._timeout = timeout

    @property
    def enabled(self) -> bool:
        return bool(self._bot_token and self._channel) or bool(self._webhook_url)

    @property
    def transport(self) -> str:
        """`bot`, `webhook` or `none`. For operators reading a health page.

        A half-configured bot — a token and no channel, which is the shape of
        a copied-and-truncated deployment — reports `webhook` if a webhook is
        also set and `none` otherwise. It never reports `bot`, because a bot
        that cannot name a channel posts nothing.
        """
        if self._bot_token and self._channel:
            return "bot"
        return "webhook" if self._webhook_url else "none"

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
                if self.transport == "bot":
                    return self._read_bot_response(
                        await http.post(
                            CHAT_POST_MESSAGE,
                            headers={"Authorization": f"Bearer {self._bot_token}"},
                            json={"channel": self._channel, "text": note.render()},
                        )
                    )
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

    def _read_bot_response(self, response: Any) -> bool:
        """Whether `chat.postMessage` actually posted.

        Both halves matter. A 200 can carry `ok: false`, and a body that is
        not JSON at all — a proxy's error page, which is what a blocked egress
        looks like from in here — must not be read as success just because it
        arrived.
        """
        if response.status_code >= 400:
            logger.warning(
                "Slack rejected a notification: %s %s",
                response.status_code,
                scrub(response.text)[:200],
            )
            return False
        try:
            body = response.json()
        except ValueError:
            logger.warning(
                "Slack answered %s with a body that is not JSON.", response.status_code
            )
            return False
        if not body.get("ok"):
            # `error` is Slack's own enum — `channel_not_found`,
            # `invalid_auth`, `not_in_channel`. Each names a different thing
            # for an operator to go and fix, so it is said rather than
            # flattened into "failed".
            logger.warning(
                "Slack refused a notification: %s", scrub(str(body.get("error")))
            )
            return False
        return True
