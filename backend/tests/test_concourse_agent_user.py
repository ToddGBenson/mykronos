"""D-182: agents log in to Concourse as their own user, holding pipeline-operator.

A YAML and text read, no containers, as test_concourse_bootstrap.py: these pin
the shape a rename or a reorder would break silently. The one that matters
most is the owner. The web node rewrites the main team's auth from the team
config on every start, and Concourse does not require that config to name an
owner (atc.TeamAuth.Validate), so a config that drops the operator locks the
operator out at the next recreate and nothing refuses it.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
CONCOURSE = ROOT / "deploy" / "concourse"
COMPOSE = CONCOURSE / "docker-compose.yml"
SETUP = CONCOURSE / "setup.ps1"
HELPER = CONCOURSE / "Connect-AgentFly.ps1"
OPERATOR_TASKS = ROOT / "docs" / "OPERATOR-TASKS.md"

OWNER = "CONCOURSE_LOCAL_USER"
AGENT = "CONCOURSE_AGENT_USER"


def _compose() -> dict:
    return yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))


def _web_env() -> dict:
    return _compose()["services"]["concourse"]["environment"]


def _resolve(text: str, env: dict[str, str]) -> str:
    """`${NAME}`, `${NAME:?msg}` and `${NAME:-default}` the way compose reads
    them, with every name present in `env`."""
    return re.sub(r"\$\{(\w+)(?::[?-][^}]*)?\}", lambda m: env[m.group(1)], text)


DUMMY = {
    OWNER: "operator-name",
    "CONCOURSE_LOCAL_PASSWORD": "owner-pass",
    AGENT: "agent-name",
    "CONCOURSE_AGENT_PASSWORD": "agent-pass",
}


def _team_config() -> dict:
    content = _compose()["configs"]["concourse-main-team"]["content"]
    return yaml.safe_load(_resolve(content, DUMMY))


def _role_users(name: str) -> list[str]:
    roles = {r["name"]: r for r in _team_config()["roles"]}
    return roles[name]["local"]["users"]


def test_both_users_are_added_and_both_are_required() -> None:
    raw = _web_env()["CONCOURSE_ADD_LOCAL_USER"]
    for name in (OWNER, "CONCOURSE_LOCAL_PASSWORD", AGENT, "CONCOURSE_AGENT_PASSWORD"):
        assert re.search(rf"\$\{{{name}:\?[^}}]+\}}", raw), (
            f"{name} is not a required (`:?`) variable in CONCOURSE_ADD_LOCAL_USER"
        )
    # Comma-separated USER:PASSWORD pairs, owner first.
    assert _resolve(raw, DUMMY) == "operator-name:owner-pass,agent-name:agent-pass"


def test_the_main_team_is_configured_by_the_mounted_file() -> None:
    service = _compose()["services"]["concourse"]
    path = _web_env()["CONCOURSE_MAIN_TEAM_CONFIG"]
    mounts = [c for c in service["configs"] if c["source"] == "concourse-main-team"]
    assert len(mounts) == 1 and mounts[0]["target"] == path


def test_the_ignored_owner_flag_is_gone() -> None:
    """With a config file, skycmd.AuthTeamFlags.Format reads only the file;
    --main-team-local-user would read as a second grant that does not exist."""
    assert "CONCOURSE_MAIN_TEAM_LOCAL_USER" not in _web_env()


def test_the_operator_keeps_owner() -> None:
    assert _role_users("owner") == [DUMMY[OWNER]]


def test_the_agent_is_pipeline_operator_and_nothing_more() -> None:
    names = [r["name"] for r in _team_config()["roles"]]
    assert sorted(names) == ["owner", "pipeline-operator"]
    assert _role_users("pipeline-operator") == [DUMMY[AGENT]]
    assert DUMMY[AGENT] not in _role_users("owner")


def test_every_role_user_is_a_user_who_can_log_in() -> None:
    """A name in a role but not in CONCOURSE_ADD_LOCAL_USER is a grant to
    nobody, and the login that was meant to use it fails as a bad password."""
    added = {
        pair.split(":", 1)[0]
        for pair in _resolve(_web_env()["CONCOURSE_ADD_LOCAL_USER"], DUMMY).split(",")
    }
    for role in _team_config()["roles"]:
        assert set(role["local"]["users"]) <= added, role["name"]


def test_a_fresh_env_has_the_agent_pair() -> None:
    """Both are required, so a .env that setup.ps1 writes without them fails
    the first `up` on a new host - before vault-init can even start Vault."""
    setup = SETUP.read_text(encoding="utf-8")
    assert f'"{AGENT}=' in setup
    assert '"CONCOURSE_AGENT_PASSWORD=$(New-Secret)"' in setup


def test_the_helper_logs_the_agent_target_in_from_env() -> None:
    script = HELPER.read_text(encoding="utf-8")
    assert '[string]$Target = "mykronos-agent"' in script
    assert re.search(r'Read-EnvValue \$EnvFile "CONCOURSE_AGENT_PASSWORD"', script)
    assert '--username $user "--password=$password"' in script
    # It checks the role Concourse granted rather than trusting the config.
    assert "userinfo --json" in script and '"pipeline-operator"' in script


def test_the_helper_never_prints_the_password() -> None:
    script = HELPER.read_text(encoding="utf-8")
    for n, line in enumerate(script.splitlines(), 1):
        if re.search(r"Write-(Host|Output|Verbose|Information|Warning|Error)|\bthrow\b", line):
            assert "$password" not in line, f"line {n} prints the password: {line}"


# `--password $x` (or `--password (...)`) as two arguments. fly parses flags
# with go-flags, which refuses a separate value that starts with '-' and
# repeats that value in its error on stderr: the password, printed in full.
_PASSWORD_AS_TWO_ARGS = re.compile(r"--password\s+[$(]")


def test_every_fly_login_passes_the_password_as_one_argument() -> None:
    scripts = sorted(CONCOURSE.glob("*.ps1"))
    hits = [
        f"{s.name}:{n}: {line.strip()}"
        for s in scripts
        for n, line in enumerate(s.read_text(encoding="utf-8").splitlines(), 1)
        if _PASSWORD_AS_TWO_ARGS.search(line) and not line.lstrip().startswith("#")
    ]
    assert hits == []
    logins = [s.name for s in scripts if '"--password=$' in s.read_text(encoding="utf-8")]
    assert {
        "Connect-AgentFly.ps1",
        "set-pipeline.ps1",
        "set-personal-soc-pipeline.ps1",
        "set-thehub-pipeline.ps1",
    } <= set(logins)


def test_the_two_argument_pattern_catches_what_it_is_for() -> None:
    assert _PASSWORD_AS_TWO_ARGS.search("--username $user --password $password")
    assert _PASSWORD_AS_TWO_ARGS.search('--password (Read-EnvValue $e "X") `')
    assert not _PASSWORD_AS_TWO_ARGS.search('--username $user "--password=$password"')


def test_no_generated_secret_starts_with_a_dash() -> None:
    for script in (HELPER, SETUP):
        text = script.read_text(encoding="utf-8")
        body = text.split("function New-Secret", 1)[1].split("\n}", 1)[0]
        assert "while ($secret.StartsWith('-'))" in body, script.name


def test_the_helper_refuses_the_owner_as_the_agent() -> None:
    """Both at -Provision, before anything is written, and at login. A shared
    name would put the agents' login in the owner role."""
    script = HELPER.read_text(encoding="utf-8")
    provision = script.split("if ($Provision) {", 1)[1].split("Set-Content", 1)[0]
    assert "ToLowerInvariant() -eq $agentName.ToLowerInvariant()" in provision
    assert "$ownerName = Read-EnvValue $EnvFile \"CONCOURSE_LOCAL_USER\"" in provision
    assert "$owner.ToLowerInvariant() -eq $user.ToLowerInvariant()" in script


def test_provision_accepts_only_plain_names() -> None:
    script = HELPER.read_text(encoding="utf-8")
    provision = script.split("if ($Provision) {", 1)[1].split("Set-Content", 1)[0]
    assert "-cnotmatch '^[a-z0-9][a-z0-9_-]*$'" in provision


def test_the_helper_requires_pwsh() -> None:
    """RandomNumberGenerator.Fill is missing in 5.1, and 5.1 turns fly's
    stderr into a terminating error under Stop."""
    first = HELPER.read_text(encoding="utf-8").splitlines()[0]
    assert first == "#Requires -Version 7"


def test_the_helper_says_agents_never_pause() -> None:
    header = HELPER.read_text(encoding="utf-8").split("#>", 1)[0]
    assert "pipeline-operator" in header
    assert "AGENTS NEVER PAUSE" in header
    flat = " ".join(header.split())
    assert "never pause, pin, unpin or disable a resource version" in flat
    assert "never clear a cache" in flat
    assert "abort only builds they started" in flat


def test_the_helper_is_ascii() -> None:
    """Windows PowerShell 5.1 reads a BOM-less file as CP1252 (setup.ps1)."""
    HELPER.read_bytes().decode("ascii")


def test_the_operator_steps_name_the_values_and_the_recreate() -> None:
    text = OPERATOR_TASKS.read_text(encoding="utf-8")
    section = text.split("D-182", 1)[1]
    for needle in (AGENT, "CONCOURSE_AGENT_PASSWORD", "docker compose up -d --no-deps concourse"):
        assert needle in section, needle
    assert "PowerShell 7 (`pwsh`)" in section


def test_the_operator_steps_update_the_checkout_before_provisioning() -> None:
    """-Provision is in the change itself, so it cannot run before the
    checkout has it; then it runs before any compose call."""
    section = OPERATOR_TASKS.read_text(encoding="utf-8").split("## 11 ", 1)[1]
    section = section.split("\n---", 1)[0]
    update = section.index("Update the checkout")
    provision = section.index(r".\Connect-AgentFly.ps1 -Provision")
    recreate = section.index("docker compose up -d --no-deps concourse\n")
    assert update < provision < recreate
