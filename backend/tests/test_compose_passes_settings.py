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
