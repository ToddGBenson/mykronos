"""A fresh host can bring Concourse up, and the errors on the way name real things.

#60753. `deploy/concourse/docker-compose.yml` refuses to start without
`CONCOURSE_VAULT_TOKEN`, and its error said `see vault-init`. Nothing by that
name existed, `setup.ps1` never wrote the token, and no script initialised
Vault - so the first `up` on a new host failed and sent the operator nowhere.

Text checks, because no test here runs PowerShell (see
test_compose_passes_settings.py). They pin the wiring a rename or a reorder
would break silently: the name in the error, the script it names, and the
order `setup.ps1` runs things in.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

CONCOURSE = Path(__file__).resolve().parents[2] / "deploy" / "concourse"
COMPOSE = CONCOURSE / "docker-compose.yml"
SETUP = CONCOURSE / "setup.ps1"
VAULT_INIT = CONCOURSE / "vault-init.ps1"


def _required_variable_messages() -> list[tuple[str, str]]:
    """Every `${NAME:?message}` in the Concourse compose file."""
    raw = COMPOSE.read_text(encoding="utf-8")
    return re.findall(r"\$\{([A-Z0-9_]+):\?([^}]*)\}", raw)


def test_every_script_an_error_points_to_exists() -> None:
    """`see vault-init` named a file that was never written. An error message
    that sends the operator to something absent is worse than a bare one: it
    reads as though the fix is documented, and the time goes on looking."""
    pointers = [
        (name, target)
        for name, message in _required_variable_messages()
        for target in re.findall(r"see ([\w./-]+)", message)
    ]
    assert pointers, "no `see <script>` pointers left - has the message moved?"

    for name, target in pointers:
        assert (CONCOURSE / target).is_file(), (
            f"{name}'s error says `see {target}`, and deploy/concourse/{target} "
            "does not exist"
        )


def test_the_vault_token_error_names_the_init_script() -> None:
    messages = dict(_required_variable_messages())
    assert "vault-init.ps1" in messages["CONCOURSE_VAULT_TOKEN"]


def test_setup_initialises_vault_before_starting_the_stack() -> None:
    """The token comes out of Vault, so Vault has to be initialised before the
    `up` that needs it. Running it after would fail exactly as before."""
    setup = SETUP.read_text(encoding="utf-8")

    init_at = setup.find("vault-init.ps1")
    assert init_at != -1, "setup.ps1 never runs vault-init.ps1"

    up_at = setup.find("docker compose up -d\n")
    assert up_at != -1, "setup.ps1 no longer starts the full stack - has it moved?"
    assert init_at < up_at, "setup.ps1 starts the stack before Vault is initialised"


def test_the_init_script_writes_the_token_compose_requires() -> None:
    script = VAULT_INIT.read_text(encoding="utf-8")

    assert "CONCOURSE_VAULT_TOKEN" in script
    # The two mounts and the policy VAULT.md describes, by name.
    for needle in ("concourse/", "personal/", "kv-v2", '"read", "list"'):
        assert needle in script, f"vault-init.ps1 does not set up {needle!r}"


def test_the_init_script_never_overwrites_key_material() -> None:
    """`vault/init.json` holds the only unseal key. Overwriting it on a re-run
    would make every secret in the store unrecoverable (VAULT.md)."""
    script = VAULT_INIT.read_text(encoding="utf-8")
    assert re.search(r"Test-Path\s+\$InitFile", script), (
        "vault-init.ps1 does not check for an existing init file before writing one"
    )


def test_starting_vault_alone_does_not_trip_the_token_guard() -> None:
    """Compose interpolates the whole file even for `up -d vault`, so the
    `:?` guard on the token fires before Vault - which is what mints the token
    - can start. The init script supplies a placeholder in its own process
    environment for that one call; the concourse service is not created by it.
    """
    script = VAULT_INIT.read_text(encoding="utf-8")
    assert re.search(r"up['\"]?,\s*['\"]-d['\"],\s*['\"]vault['\"]", script) or (
        "up -d vault" in script
    ), "vault-init.ps1 does not start the vault service on its own"
    assert "$env:CONCOURSE_VAULT_TOKEN" in script


@pytest.mark.parametrize("doc", ["README.md", "docs/GUIDE.md"])
def test_standing_it_up_starts_with_the_concourse_setup(doc) -> None:
    """The platform joins Concourse's network as `external`, so the Concourse
    stack has to exist first - and neither document said how to create it."""
    text = (CONCOURSE.parents[1] / doc).read_text(encoding="utf-8")
    assert "deploy/concourse/setup.ps1" in text or "setup.ps1" in text


def test_the_vault_service_still_exists_under_that_name() -> None:
    document = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    assert document["services"]["vault"]["container_name"] == "mykronos-vault"
