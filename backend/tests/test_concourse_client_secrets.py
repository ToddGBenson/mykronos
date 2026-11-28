"""Concourse web sets its own client secrets (TheHub #62376, GHSA-9x27-gfq9-5qx8).

With no `--client-secret` / `--tsa-client-secret`, Concourse up to 8.3.3
derives both from the public modulus of the session signing key, which
`/sky/issuer/keys` serves to anyone. The derived secret exchanges for a
system-level token: register, land, retire and delete workers. 8.3.4 stops
deriving them; setting both closes it on any version. This holds the pieces
together: 8.3.4 by digest everywhere Concourse runs, both secrets read from
the host's gitignored .env with a guard that refuses to start without them,
setup.ps1 generating them into an existing .env as well as a fresh one, and
no value anywhere in the repository.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any, cast

import pytest
import yaml

from tests.test_linux_concourse_worker import (
    ADD,
    COMPOSE,
    CONCOURSE,
    INSTALL,
    ROOT,
    SETUP,
    WORKER_COMPOSE,
    _functions_of,
    _pwsh,
    needs_pwsh,
)

VERSION = "8.3.4"
#: The 8.3.4 OCI image index on Docker Hub, read from the registry API
#: (Docker-Content-Digest) on 2026-11-28.
DIGEST = "sha256:a5362362e0b40b2713b08598f44c12fcd61ca9b6e31bc990cb17dcf82c962f10"
IMAGE = f"concourse/concourse:{VERSION}@{DIGEST}"
#: GitHub's digests of the v8.3.4 release assets; amd64 also recomputed from
#: the downloaded file and checked against the release's .sha1 sidecar.
SHA256 = {
    "amd64": "1fdeda7affb67b0e572761d8045913f0c3124a73159ac53f97122292844b2b84",
    "arm64": "8adca30ec41fd6a1b4892c177fb2676bc541342743afcf82831cf902d20e7cf2",
}
SECRETS = ("CONCOURSE_CLIENT_SECRET", "CONCOURSE_TSA_CLIENT_SECRET")


def _yaml(path: Path) -> dict[str, Any]:
    return cast("dict[str, Any]", yaml.safe_load(path.read_text(encoding="utf-8")))


class TestEveryConcourseRunsThePatchedRelease:
    def test_the_web_node_and_the_worker_anchor_pin_the_8_3_4_digest(self) -> None:
        compose = _yaml(COMPOSE)
        for name, block in (("web", compose["services"]["concourse"]),
                            ("x-worker", compose["x-worker"])):
            assert block["image"] == IMAGE, name
            build = block["x-mykronos-build"]
            assert build["base"] == IMAGE, name
            assert build["publish"] == f"concourse/concourse:{VERSION}", name

    def test_every_compose_worker_uses_the_anchor_image(self) -> None:
        compose = _yaml(COMPOSE)
        workers = {n: s for n, s in compose["services"].items() if s.get("command") == "worker"}
        assert workers, "no compose worker found"
        for name, service in workers.items():
            assert service["image"] == IMAGE, name

    def test_no_concourse_image_in_the_stack_is_older(self) -> None:
        for path in (COMPOSE, WORKER_COMPOSE, SETUP, ADD):
            text = path.read_text(encoding="utf-8")
            versions = set(re.findall(r"concourse/concourse:(\d+\.\d+\.\d+)", text))
            assert versions == {VERSION}, (path.name, versions)

    def test_the_linux_worker_compose_pins_the_digest(self) -> None:
        services = _yaml(WORKER_COMPOSE)["services"]
        assert services
        for name, service in services.items():
            assert service["image"] == IMAGE, name

    def test_the_install_script_fetches_8_3_4_with_its_checksums(self) -> None:
        text = INSTALL.read_text(encoding="utf-8")
        assert re.search(rf'^CONCOURSE_VERSION="{re.escape(VERSION)}"$', text, re.M)
        for arch, digest in SHA256.items():
            assert re.search(rf'^SHA256_{arch}="{digest}"$', text, re.M), arch


class TestTheWebNodeSetsBothClientSecrets:
    @pytest.mark.parametrize("name", SECRETS)
    def test_from_env_with_a_guard_that_refuses_to_start_without_it(self, name: str) -> None:
        env = _yaml(COMPOSE)["services"]["concourse"]["environment"]
        value = str(env.get(name, ""))
        assert re.fullmatch(rf"\$\{{{name}:\?[^}}]+\}}", value), (name, value)

    def test_the_web_node_has_no_env_file_that_could_shadow_them(self) -> None:
        assert "env_file" not in _yaml(COMPOSE)["services"]["concourse"]

    def test_no_tracked_file_holds_a_value_for_either(self) -> None:
        tracked = subprocess.run(
            ["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True
        ).stdout.decode().split("\0")
        assigned = re.compile(
            r"(CONCOURSE_(?:TSA_)?CLIENT_SECRET|--(?:tsa-)?client-secret)[ \t]*[:=][ \t]*(\S*)"
        )
        found = []
        this = Path(__file__).resolve()
        for rel in filter(None, tracked):
            path = ROOT / rel
            if path.resolve() == this:
                continue  # its own fixture writes a placeholder into a temp .env
            if not path.is_file() or path.suffix in {".png", ".jpg", ".ico", ".parquet"}:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            for match in assigned.finditer(text):
                value = match.group(2).strip("'\"")
                if value and not value.startswith(("${", "$(", "$")):
                    found.append((rel, match.group(1)))
        assert found == []

    def test_the_example_env_names_both_without_values(self) -> None:
        example = (CONCOURSE / ".env.example").read_text(encoding="utf-8")
        for name in SECRETS:
            assert re.search(rf"^{name}=\s*$", example, re.M), name


class TestSetupGeneratesThemIfAbsent:
    def test_a_fresh_env_gets_both_at_32_bytes(self) -> None:
        text = SETUP.read_text(encoding="utf-8")
        for name in SECRETS:
            assert f'"{name}=$(New-Secret 32)"' in text, name

    def test_an_existing_env_is_given_what_it_lacks_before_vault_and_compose(self) -> None:
        text = SETUP.read_text(encoding="utf-8")
        call = re.search(r"^Add-MissingSecret -EnvFile \$EnvFile -Name (.+)$", text, re.M)
        assert call, "setup.ps1 never adds a missing secret to an existing .env"
        for name in SECRETS:
            assert f"'{name}'" in call.group(1), name
        assert call.start() < text.index('& (Join-Path $PSScriptRoot "vault-init.ps1")')
        assert call.start() < text.index("\n    docker compose up -d\n")

    @needs_pwsh
    def test_adds_only_the_missing_ones_and_keeps_existing_values(self, tmp_path: Path) -> None:
        env = tmp_path / ".env"
        env.write_text("CONCOURSE_LOCAL_USER=mykronos\nCONCOURSE_CLIENT_SECRET=keep-me\n",
                       encoding="utf-8")
        path = str(env).replace("'", "''")
        script = (
            _functions_of(SETUP)
            + f"Add-MissingSecret -EnvFile '{path}' -Name "
            + ", ".join(f"'{n}'" for n in SECRETS)
            + " 6>&1 | Out-String | Set-Variable said; "
            "ConvertTo-Json -Compress @{ said = $said }"
        )
        said = _pwsh(script)["said"]
        lines = env.read_text(encoding="utf-8").splitlines()
        values = dict(line.split("=", 1) for line in lines if "=" in line)
        assert values["CONCOURSE_CLIENT_SECRET"] == "keep-me"
        assert values["CONCOURSE_LOCAL_USER"] == "mykronos"
        tsa = values["CONCOURSE_TSA_CLIENT_SECRET"]
        assert re.fullmatch(r"[A-Za-z0-9_-]{43}", tsa), "32 random bytes, URL-safe"
        assert not tsa.startswith("-")
        assert tsa not in said, "the value was printed"
        assert "CONCOURSE_TSA_CLIENT_SECRET" in said
        assert sum(1 for line in lines if line.startswith("CONCOURSE_CLIENT_SECRET=")) == 1

    @needs_pwsh
    def test_a_second_run_changes_nothing(self, tmp_path: Path) -> None:
        env = tmp_path / ".env"
        env.write_text("CONCOURSE_LOCAL_USER=mykronos\n", encoding="utf-8")
        path = str(env).replace("'", "''")
        call = (
            f"Add-MissingSecret -EnvFile '{path}' -Name "
            + ", ".join(f"'{n}'" for n in SECRETS)
            + " | Out-Null; "
        )
        _pwsh(_functions_of(SETUP) + call + "ConvertTo-Json -Compress @{ ok = $true }")
        first = env.read_bytes()
        for name in SECRETS:
            assert f"\n{name}=".encode() in first, name
        _pwsh(_functions_of(SETUP) + call + "ConvertTo-Json -Compress @{ ok = $true }")
        assert env.read_bytes() == first

