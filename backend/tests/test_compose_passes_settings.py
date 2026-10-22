"""Settings an operator is meant to change must reach the container.

Compose interpolates only the names its `environment:` block lists. A setting
absent from that list cannot be configured in the deployed stack no matter
what `backend/.env` says — and it fails silently, reading as its code default.

The compose file already carried this lesson for Slack: "a notifier that is
wired everywhere except the one process that runs is worse than no notifier:
it looks configured." `routing_enabled` (since retired, D-161) was then set in
`.env`, deployed, and read `False` in the container for exactly the same
reason. Hence a test rather than a third comment.
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
    "MYKRONOS_SLACK_WEBHOOK_URL",
    "MYKRONOS_SLACK_BOT_TOKEN",
    "MYKRONOS_SLACK_CHANNEL",
    "MYKRONOS_GITHUB_APP_ID",
    "MYKRONOS_VIEWER_TOKEN",
    "MYKRONOS_CONCOURSE_URL",
    "MYKRONOS_HUB_API_URL",
    "MYKRONOS_HUB_API_TOKEN",
    # D-149: the reviewer could not be switched live, or given a key, in the
    # deployed stack - none of the three was listed.
    "MYKRONOS_REVIEWER_MODE",
    "MYKRONOS_REVIEWER_MODEL",
    "MYKRONOS_REVIEWER_API_KEY",
    # #60754: OPERATOR-TASKS.md tells the operator to set the first in
    # backend/.env, and none of these reached the container - the digest could
    # not be switched on under Docker at all.
    "MYKRONOS_DIGEST_ENABLED",
    "MYKRONOS_WEEKLY_DIGEST_INTERVAL_SECONDS",
    "MYKRONOS_CONCOURSE_API_TOKEN",
    "MYKRONOS_GITHUB_BOT_LOGINS",
    # TheHub #60864: the briefing DM's target and link. Unpassed, the job
    # would read them empty in the container and skip every morning.
    "MYKRONOS_BRIEFING_DM_CHANNEL",
    "MYKRONOS_BRIEFING_DM_TIME",
    "MYKRONOS_BRIEFING_DM_TIMEZONE",
    "MYKRONOS_DASHBOARD_URL",
)

EXAMPLE = Path(__file__).resolve().parents[1] / ".env.example"

#: The phrase that marks a `.env.example` block as deliberately NOT passed into
#: the deployed container. The block has to say why; this only checks it says so.
NOT_PASSED = "Not passed by deploy/mykronos/docker-compose.yml"

#: Compose fallbacks that differ from the code default on purpose: the code's
#: default is right for a laptop, and these describe this deployment.
DEPLOYMENT_DEFAULTS = {
    "MYKRONOS_INGESTION_API_URL",
    "MYKRONOS_CONCOURSE_URL",
    "MYKRONOS_CONCOURSE_EXTERNAL_URL",
    "MYKRONOS_VAULT_URL",
    "MYKRONOS_HUB_API_URL",
    "MYKRONOS_PATCHWORK_IMAGE_REGISTRY",
}


def _documented_settings() -> tuple[set[str], set[str]]:
    """Settings `.env.example` tells an operator to set, split into the ones
    it says compose passes and the ones it marks as not passed.

    Blocks are separated by blank lines, so a marker covers the comment and
    assignments it sits with. Commented-out assignments count: `# NAME=value`
    is still an instruction that NAME can be set.
    """
    from mykronos.config import Settings

    fields = {f"MYKRONOS_{name.upper()}" for name in Settings.model_fields}
    passed: set[str] = set()
    exempt: set[str] = set()
    for block in re.split(r"\n\s*\n", EXAMPLE.read_text(encoding="utf-8")):
        names = set(re.findall(r"^#?\s*(MYKRONOS_[A-Z0-9_]+)=", block, re.MULTILINE))
        (exempt if NOT_PASSED in block else passed).update(names & fields)
    return passed - exempt, exempt


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


def test_the_reviewer_defaults_to_shadow_in_compose() -> None:
    """Live is the operator's decision, made with a delegation in place
    (D-149). A compose default of `live` would make it on every recreate; an
    empty default would fail the setting's own pattern and stop the backend."""
    document = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    value = str(document["services"]["backend"]["environment"]["MYKRONOS_REVIEWER_MODE"])

    assert value.endswith(":-shadow}"), value


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


def test_the_deploy_reads_the_slack_pair_from_the_pipelines_vault_paths() -> None:
    """D-137: passing the names through compose is half of it. The deploy has
    to supply them, and from the same Vault paths the Concourse pipelines
    resolve `((slack-bot-token))` and `((slack-alert-channel))` from - so the
    platform posts as the host's one Slack bot, to the channel the pipeline
    alerts already go to, and nothing is pasted into `backend/.env`.

    A text check, because no test here runs PowerShell. It pins the
    name-to-path pairing, which is the part a rename would break silently.
    """
    deploy = (COMPOSE.parent / "deploy.ps1").read_text(encoding="utf-8")
    pipeline = (
        COMPOSE.parents[1] / "concourse" / "pipelines" / "thehub.yml"
    ).read_text(encoding="utf-8")

    for name, var in (
        ("MYKRONOS_SLACK_BOT_TOKEN", "slack-bot-token"),
        ("MYKRONOS_SLACK_CHANNEL", "slack-alert-channel"),
    ):
        assert f"(({var}))" in pipeline, f"the pipeline no longer resolves (({var}))"
        assert re.search(
            rf'"{name}"\s*=\s*"concourse/main/{var}"', deploy
        ), f"deploy.ps1 does not read {name} from concourse/main/{var}"


def test_every_setting_the_docs_say_to_set_reaches_the_container(backend_environment) -> None:
    """#60754, generally. MUST_BE_PASSABLE is a list somebody has to remember
    to extend, and the digest, the Concourse API token and the bot logins were
    each documented as settable and never added to it - so setting them in
    backend/.env did nothing to the deployed backend, silently.

    This diffs what `.env.example` tells an operator to set against what the
    compose environment passes. A setting that genuinely cannot be configured
    under compose (a path the image fixes, a pin that lives in code) stays out
    of the list, and its `.env.example` block says so in words.
    """
    documented, _ = _documented_settings()
    missing = sorted(documented - set(backend_environment))

    assert not missing, (
        "backend/.env.example tells an operator to set these, and the compose "
        "environment does not pass them, so the deployed backend silently uses "
        "the code default. Pass them in deploy/mykronos/docker-compose.yml, or "
        f"mark their block in .env.example with {NOT_PASSED!r} and say why: "
        + ", ".join(missing)
    )


def test_a_setting_marked_not_passed_really_is_not_passed(backend_environment) -> None:
    """The marker is a claim, and a stale one misleads in the other direction:
    an operator who reads "not configurable" never tries."""
    _, exempt = _documented_settings()
    contradicted = sorted(
        name for name in exempt if str(backend_environment.get(name, "")).startswith("${")
    )
    assert not contradicted, f"marked {NOT_PASSED!r} but compose passes: {contradicted}"


def test_a_passed_setting_left_unset_reads_as_the_code_default(
    backend_environment, monkeypatch
) -> None:
    """Passing a setting must not change it for an operator who never set it.

    `${NAME:-}` hands the container an empty string, which is not a default:
    for a bool or a list it is a validation error and the backend does not
    start. So each newly passed setting's compose fallback must parse to the
    same value as leaving the variable out altogether.
    """
    from mykronos.config import Settings

    baseline = Settings(_env_file=None)
    documented, _ = _documented_settings()
    differs = []
    for name in sorted(documented - DEPLOYMENT_DEFAULTS):
        match = re.fullmatch(r"\$\{" + name + r":-(.*)\}", str(backend_environment[name]))
        if not match:
            continue  # `:?` (must be set) or a fixed value - not a fallback
        monkeypatch.setenv(name, match.group(1))
        field = name.removeprefix("MYKRONOS_").lower()
        try:
            if getattr(Settings(_env_file=None), field) != getattr(baseline, field):
                differs.append(name)
        except ValueError:
            differs.append(f"{name} (does not parse)")
        monkeypatch.delenv(name)

    assert not differs, f"compose's fallback is not the code default for: {differs}"


def test_the_example_file_is_a_valid_configuration() -> None:
    """It says "copy to .env and adjust", and `MYKRONOS_DIGEST_ENABLED=` - an
    empty value - failed validation, so a straight copy did not start."""
    from mykronos.config import Settings

    Settings(_env_file=EXAMPLE)
