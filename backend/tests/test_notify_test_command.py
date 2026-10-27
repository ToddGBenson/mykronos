"""`mykronos notify-test`: one message the operator can look for (TheHub #60573).

B-035 is configured (D-137): the running backend holds a bot token and a
channel from Vault, and logs no refusal. What no machine can check is that a
message actually lands where a person reads it, and there was no way to make
the running backend post one on demand. This is that way. It must never print
the token or the channel, and must say plainly when nothing was delivered.
"""

from __future__ import annotations

from typing import Any

import pytest

import mykronos.cli as cli
from mykronos.config import Settings
from mykronos.notify import Notification, SlackNotifier

TOKEN = "xoxb-not-a-real-token-0000"
CHANNEL = "C0NOTREAL1"


def _with(settings: Settings, monkeypatch: pytest.MonkeyPatch, **kw: Any) -> None:
    for name, value in kw.items():
        setattr(settings, name, value)
    monkeypatch.setattr(cli, "get_settings", lambda: settings)


def _capture(monkeypatch: pytest.MonkeyPatch, delivered: bool) -> list[Notification]:
    sent: list[Notification] = []

    async def send(self: SlackNotifier, note: Notification) -> bool:
        sent.append(note)
        return delivered

    monkeypatch.setattr(SlackNotifier, "send", send)
    return sent


def test_it_posts_one_test_message_and_names_only_the_transport(
    settings: Settings, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _with(settings, monkeypatch, slack_bot_token=TOKEN, slack_channel=CHANNEL)
    sent = _capture(monkeypatch, delivered=True)

    assert cli.main(["notify-test"]) == 0

    [note] = sent
    assert "test" in note.title.lower()
    # No repository: the message must not render an empty `` line.
    assert "``" not in note.render()
    out = capsys.readouterr()
    assert "bot" in out.out and "confirm" in out.out.lower()
    for secret in (TOKEN, CHANNEL):
        assert secret not in out.out + out.err


def test_an_unaddressed_notifier_says_so_and_sends_nothing(
    settings: Settings, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _with(settings, monkeypatch, slack_bot_token="", slack_channel="", slack_webhook_url="")
    sent = _capture(monkeypatch, delivered=True)

    assert cli.main(["notify-test"]) == 1

    assert sent == []
    assert "MYKRONOS_SLACK_BOT_TOKEN" in capsys.readouterr().out


def test_a_refused_post_is_not_reported_as_delivered(
    settings: Settings, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _with(settings, monkeypatch, slack_bot_token=TOKEN, slack_channel=CHANNEL)
    _capture(monkeypatch, delivered=False)

    assert cli.main(["notify-test"]) == 1

    out = capsys.readouterr().out
    assert "not delivered" in out.lower()
    assert TOKEN not in out and CHANNEL not in out
