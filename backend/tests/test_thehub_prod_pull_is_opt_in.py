"""The registry-pull agent leaves production alone unless told otherwise (TheHub #364).

`deploy-prod` was retired on 2026-09-18 (#59990) and production follows
TheHub's own deploy.sh (TheHub ADR 0072), but `Invoke-RegistryPullDeploy.ps1`
still polled `prod.requested` by default, and the Scheduled Task passes no
`-Environments`. A listener for a delivery path nobody chose. Production is
now opt-in, and when it is opted into, `Invoke-TheHubDeploy.ps1` recreates the
backend alone, never builds, never follows dependencies, and runs the digest
rather than the tag.

Text assertions, like test_thehub_deploy_collation_guard.py: running either
script would deploy.
"""

from __future__ import annotations

import re
from pathlib import Path

HERE = Path(__file__).resolve()
THEHUB = next(
    p / "deploy" / "thehub" for p in HERE.parents if (p / "deploy" / "thehub").is_dir()
)
POLLER = THEHUB / "Invoke-RegistryPullDeploy.ps1"
DEPLOYER = THEHUB / "Invoke-TheHubDeploy.ps1"


def _src(path: Path) -> str:
    return path.read_text(encoding="ascii")


def test_the_poller_defaults_to_demo_only():
    m = re.search(r'\[string\[\]\]\$Environments\s*=\s*@\(([^)]*)\)', _src(POLLER))
    assert m, "the -Environments default has moved"
    assert [s.strip().strip('"') for s in m.group(1).split(",")] == ["demo"]


def test_prod_can_still_be_opted_into():
    src = _src(POLLER)
    assert '[ValidateSet("demo", "prod")]' in src
    assert "-Environments demo,prod" in src, "the opt-in must be documented"


def _compose_up(src: str) -> str:
    start = src.index("function Invoke-ComposeUp {")
    return src[start:src.index("\nfunction ", start + 1)]


def test_prod_recreates_one_service_without_deps_or_a_build():
    body = _compose_up(_src(DEPLOYER))
    prod = body[body.index('if ($Environment -eq "prod") {'):body.index("return")]
    assert "up -d --no-deps --no-build $service" in prod
    assert "--remove-orphans" not in prod


def test_prod_runs_the_digest_not_the_tag():
    body = _compose_up(_src(DEPLOYER))
    prod = body[body.index('if ($Environment -eq "prod") {'):body.index("return")]
    assert "$pinned = Resolve-DigestRef -ImageRef $ImageRef" in prod
    assert "$env:THEHUB_IMAGE = $pinned" in prod
    assert "Assert-RunningImage -Expected $expected -ImageRef $pinned" in prod
    # The pin's limit is said out loud, not discovered at the next deploy.sh.
    assert "NOT PERSISTENT" in prod


def test_a_tag_without_a_digest_is_refused():
    src = _src(DEPLOYER)
    fn = src[src.index("function Resolve-DigestRef {"):src.index("function Invoke-ComposeUp {")]
    assert "throw" in fn and "refusing to run production on a tag" in fn


def test_demo_is_unchanged():
    body = _compose_up(_src(DEPLOYER))
    demo = body[body.index("return"):]
    assert "$env:THEHUB_IMAGE = $ImageRef" in demo
    assert "up -d --remove-orphans" in demo


def test_the_wipe_is_still_demo_only():
    src = _src(DEPLOYER)
    assert 'if ($Environment -ne "demo") {' in src[src.index("function Invoke-Wipe {"):]


def test_scripts_stay_ascii():
    for path in (POLLER, DEPLOYER):
        path.read_bytes().decode("ascii")
