"""Settings an operator is meant to change must reach the container.

Compose interpolates only the names its `environment:` block lists. A setting
absent from that list cannot be configured in the deployed stack no matter
what `backend/.env` says — and it fails silently, reading as its code default.

The compose file already carried this lesson for Slack: "a notifier that is
wired everywhere except the one process that runs is worse than no notifier:
it looks configured." `routing_enabled` was then set in `.env`, deployed, and
read `False` in the container for exactly the same reason. Hence a test rather
than a third comment.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

COMPOSE = (
    Path(__file__).resolve().parents[2] / "deploy" / "mykronos" / "docker-compose.yml"
)

#: Settings that change behaviour and that a deployment is expected to set.
#: Not every field on `Settings` — paths and URLs with sane defaults do not
#: belong here. These are the ones where the code default and the operator's
#: intent can differ, and where being wrong is silent.
MUST_BE_PASSABLE = (
    "MYKRONOS_ROUTING_ENABLED",
    "MYKRONOS_SLACK_WEBHOOK_URL",
    "MYKRONOS_SLACK_BOT_TOKEN",
    "MYKRONOS_SLACK_CHANNEL",
    "MYKRONOS_GITHUB_APP_ID",
    "MYKRONOS_VIEWER_TOKEN",
    "MYKRONOS_CONCOURSE_URL",
)


@pytest.fixture(scope="module")
def backend_environment() -> dict:
    document = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    return document["services"]["backend"]["environment"]


@pytest.mark.parametrize("name", MUST_BE_PASSABLE)
def test_the_setting_is_passed_into_the_container(name, backend_environment) -> None:
    assert name in backend_environment, (
        f"{name} is not in the compose environment block, so setting it in "
        "backend/.env does nothing and the container silently uses the code "
        "default"
    )


@pytest.mark.parametrize("name", MUST_BE_PASSABLE)
def test_it_interpolates_rather_than_hardcoding(name, backend_environment) -> None:
    """A hardcoded value would be worse than an absent one: it would override
    whatever the operator set, rather than merely ignoring it."""
    assert str(backend_environment[name]).startswith("${"), (
        f"{name} is hardcoded in compose, so backend/.env cannot change it"
    )


def test_routing_defaults_to_off_in_compose() -> None:
    """Turning it on is a per-deployment decision — it opens issues in
    somebody's tracker. A compose file that defaulted it to true would make
    that decision for everyone who pulls."""
    document = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    value = str(document["services"]["backend"]["environment"]["MYKRONOS_ROUTING_ENABLED"])

    assert value.endswith(":-false}"), value


def test_every_name_here_is_a_real_setting() -> None:
    """A guard over a misspelled setting name passes forever and guards
    nothing."""
    from mykronos.config import Settings

    fields = {f"MYKRONOS_{name.upper()}" for name in Settings.model_fields}
    unknown = set(MUST_BE_PASSABLE) - fields

    assert not unknown, f"{sorted(unknown)} are not fields on Settings"


def test_the_app_key_mount_has_no_silent_default() -> None:
    """A missing App key must stop the stack, not start it credential-less.

    The mount used to read:

        ${MYKRONOS_GITHUB_APP_KEY_HOST_PATH:-/dev/null}:/secrets/github-app.pem:ro

    so a recreate without that variable exported bind-mounted an empty file.
    The container started, the healthcheck went green, and the platform ran
    with no GitHub credential — which is the exact failure mode this file's
    docstring is about, applied to the one secret that cannot be regenerated
    from inside the platform.

    It happened on 2026-09-18 and left /dev/null mounted for six minutes,
    reporting Healthy throughout.

    `MYKRONOS_ADMIN_TOKEN` already used `:?` in the same file. This asserts the
    App key does too, and that nobody restores the convenience.
    """
    raw = COMPOSE.read_text(encoding="utf-8")

    mounts = [
        line.strip()
        for line in raw.splitlines()
        if "/secrets/github-app.pem" in line and "MYKRONOS_GITHUB_APP_KEY_HOST_PATH" in line
    ]
    assert mounts, "no bind mount for the App private key — has it moved?"

    for line in mounts:
        assert "/dev/null" not in line, (
            f"the App key mount falls back to /dev/null, which starts the "
            f"platform with no GitHub credential and a green healthcheck: {line}"
        )
        assert ":?" in line, (
            f"the App key mount has no `:?` guard, so an unset variable will "
            f"substitute something rather than refusing to start: {line}"
        )


def test_the_app_key_variable_is_documented_for_an_operator() -> None:
    """It is read by compose and not by the application, so it appears in no
    `Settings` field and is easy to omit. `.env.example` is the only place an
    operator would find it."""
    example = (
        Path(__file__).resolve().parents[2] / "backend" / ".env.example"
    ).read_text(encoding="utf-8")

    assert "MYKRONOS_GITHUB_APP_KEY_HOST_PATH" in example, (
        "compose refuses to start without this variable and nothing tells an "
        "operator it exists"
    )


def test_every_variable_compose_interpolates_is_documented() -> None:
    """The general form of the three point-fixes that preceded it.

    `MYKRONOS_GITHUB_APP_KEY_HOST_PATH` (#664) and the five Slack variables
    (#412) were each found the same way: by reading the compose file against a
    running container, because nothing else recorded that they existed. Twelve
    of the eighteen variables compose interpolates were undocumented when this
    test was written.

    A variable reaching the container through compose is not necessarily a
    `Settings` field, so reading the code does not find it either. `.env.example`
    is the only place an operator has to look, which makes "compose references
    it" the right trigger rather than "the application reads it".
    """
    compose = COMPOSE.read_text(encoding="utf-8")
    example = (
        Path(__file__).resolve().parents[2] / "backend" / ".env.example"
    ).read_text(encoding="utf-8")

    referenced = set(re.findall(r"\$\{(MYKRONOS_[A-Z0-9_]+)", compose))
    documented = set(re.findall(r"^(MYKRONOS_[A-Z0-9_]+)=", example, re.MULTILINE))

    undocumented = sorted(referenced - documented)

    assert not undocumented, (
        "compose interpolates these and `backend/.env.example` does not "
        "mention them, so an operator has no way to know they exist: "
        + ", ".join(undocumented)
    )
