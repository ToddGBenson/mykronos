"""#60474: the Vault probe was configured to be incapable of reporting an outage.

`/v1/sys/health` takes query parameters that OVERRIDE its status code per
state. The healthcheck passed `sealedcode=200&uninitcode=200`, which instructs
Vault to answer 200 while sealed and while uninitialised — the two states in
which it cannot serve a single secret.

The consequence, measured rather than supposed: Vault sealed on 2026-09-19 at
a Docker-engine recreate and stayed sealed until 2026-09-23. Throughout those
four days `docker inspect mykronos-vault` reported `health=healthy` with
`failingStreak=0`, while 20 of keel's 26 jobs errored in three seconds each on
"Code: 503 ... Vault is sealed", and `thehub` and `personal-soc` — which
resolve ((vars)) from the same Vault — were equally dead.

The probe answered "is the process up". It was never able to answer "can it
serve a secret", which is the only question a credential manager's healthcheck
is for.

The comment that justified the override said reporting it unhealthy "would
make compose restart it forever". That is not what Docker does: a healthcheck
result drives `State.Health` only. `restart:` acts on process EXIT. A sealed
Vault has not exited, so nothing restarts it — the crash loop the override was
protecting against could not have happened.

These are static assertions over the compose file. The probe's runtime
behaviour was demonstrated separately against a throwaway Vault container; see
the commit for #60474.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
COMPOSE = REPO_ROOT / "deploy" / "concourse" / "docker-compose.yml"

#: Vault's health endpoint names its status-code overrides `<state>code`.
#: Setting any of them to 200 declares that state healthy. Only `activecode`
#: may be 200, because an active unsealed node IS healthy — that is the state
#: the probe exists to confirm.
MASKABLE = ("sealedcode", "uninitcode", "standbycode", "drsecondarycode",
            "performancestandbycode")


@pytest.fixture(scope="module")
def probe_url() -> str:
    document = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    test = document["services"]["vault"]["healthcheck"]["test"]

    urls = [part for part in test if isinstance(part, str) and "/v1/sys/health" in part]
    assert urls, f"the vault healthcheck no longer probes /v1/sys/health: {test}"
    return urls[0]


@pytest.mark.parametrize("parameter", MASKABLE)
def test_no_unserviceable_state_is_declared_healthy(parameter, probe_url) -> None:
    query = parse_qs(urlsplit(probe_url).query)
    value = query.get(parameter, [None])[0]

    assert value != "200", (
        f"the vault healthcheck passes {parameter}=200, which tells Vault to "
        f"answer HTTP 200 in a state where it cannot serve a secret. Docker "
        f"then reports the container healthy through a total outage — which "
        f"is exactly how #60474 stayed invisible for four days."
    )


def test_a_sealed_vault_is_left_to_answer_503(probe_url) -> None:
    """Absent means default, and the default is the true answer: 503 sealed,
    501 uninitialised. Naming the parameter at all is what went wrong, so the
    fix is to stop naming it rather than to give it a different number."""
    query = parse_qs(urlsplit(probe_url).query)

    assert "sealedcode" not in query, (
        "sealedcode is set at all. Leave it off: Vault's own default for a "
        "sealed node is 503, and wget exits non-zero on it."
    )
    assert "uninitcode" not in query, (
        "uninitcode is set at all. An uninitialised Vault is not serving "
        "either, and its default is 501."
    )


def test_an_unsealed_vault_still_passes(probe_url) -> None:
    """The failure mode of over-correcting: a probe that reds on the healthy
    state trades one wrong answer for another.

    `standbyok=true` is the only override that belongs here. It maps a standby
    node — which IS serving, via request forwarding — onto 200. Without it a
    single-node Vault is unaffected, but with it the probe stays correct if a
    second node is ever added, and it cannot mask a seal.
    """
    query = parse_qs(urlsplit(probe_url).query)

    assert query.get("standbyok", ["false"])[0] == "true", (
        "standbyok was dropped along with the sealed overrides. A standby "
        "node serves requests and must not read unhealthy."
    )

    unexpected = set(query) - {"standbyok", "perfstandbyok"}
    assert not unexpected, (
        f"unreviewed query parameters on the health probe: {sorted(unexpected)}. "
        "Every parameter this endpoint takes changes which states count as "
        "healthy, so each one needs a reason here."
    )


def test_the_probe_fails_the_container_rather_than_swallowing_the_status(probe_url) -> None:
    """`wget -q` exits non-zero on an HTTP error status, which is what turns a
    503 into an unhealthy container. A pipe into something forgiving, or a
    trailing `|| true`, would restore the blind spot with different syntax."""
    document = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    test = document["services"]["vault"]["healthcheck"]["test"]
    joined = " ".join(str(part) for part in test)

    assert "|| true" not in joined and "|| exit 0" not in joined, (
        f"the vault probe swallows its own failure: {joined}"
    )


def test_the_unseal_is_automated_rather_than_waiting_for_somebody(probe_url) -> None:
    """The probe makes a seal VISIBLE; it does not stop it happening.

    A file-storage Vault comes back sealed after every Docker recreate, and
    recreates are routine on this host — 2026-09-19 and 2026-09-07 were both
    recreates, not reboots. Without something that runs the unseal, the fix is
    a faster alarm attached to the same four-day manual recovery.
    """
    installer = REPO_ROOT / "deploy" / "concourse" / "Install-VaultUnsealTask.ps1"
    assert installer.is_file(), (
        f"{installer.name} is missing, so nothing runs vault-unseal.ps1 and "
        "every recreate still needs an operator who happens to be looking."
    )

    text = installer.read_text(encoding="utf-8")

    assert "vault-unseal.ps1" in text, (
        "the installer does not invoke vault-unseal.ps1 — a second unseal "
        "implementation is a second thing to keep correct."
    )
    assert "RepetitionInterval" in text, (
        "the task is triggered at boot only. A Docker recreate is not a boot: "
        "the engine restarted under a running session on 2026-09-19 and the "
        "host stayed up. A repeating idempotent check is what covers that."
    )
