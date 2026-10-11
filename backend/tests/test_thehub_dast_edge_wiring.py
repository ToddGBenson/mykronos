"""`dast-edge` scans TheHub through Cloudflare and reports as its own lane (TheHub #60708, D-154).

`dast-prod` scans the origin on the LAN, so the edge's headers and TLS and the
tunnel's path allowlist were outside every scan. `dast-edge` is the same
passive baseline pointed at the public hostname, with three things around it:
proof that the request went through Cloudflare, an unauthenticated perimeter
check, and a refusal to report a crawl Cloudflare challenged as a clean scan.

The task script is EXECUTED as it stands in the pipeline, with curl, ZAP, pip,
python3 and git stubbed to record what they were asked to do, rather than
grepped for words. The one textual change is `/zap/wrk`, ZAP's hardcoded report
directory, which is pointed at a temporary directory.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
PIPELINE = ROOT / "deploy" / "concourse" / "pipelines" / "thehub.yml"
VARS = ROOT / "deploy" / "concourse" / "vars" / "thehub.yml"
JOB = "dast-edge"
TASK = "zap-baseline-edge"
SHA = "0123456789abcdef0123456789abcdef01234567"
HUB = "https://hub.example.net"
SIBLING = "https://mk.example.net"


def _doc() -> dict[str, Any]:
    return yaml.safe_load(PIPELINE.read_text(encoding="utf-8"))


def _jobs() -> dict[str, dict[str, Any]]:
    return {job["name"]: job for job in _doc()["jobs"]}


def _task(job: str, name: str) -> dict[str, Any]:
    return next(step for step in _jobs()[job]["plan"] if step.get("task") == name)


def _script(job: str = JOB, task: str = TASK) -> str:
    return _task(job, task)["config"]["run"]["args"][-1]


# -- shape --------------------------------------------------------------------


def test_it_runs_on_the_daily_clock_like_dast_prod() -> None:
    """Same cadence, same serialisation, same ceiling: no extra load on prod."""
    edge, prod = _jobs()[JOB], _jobs()["dast-prod"]
    triggers = [s["get"] for s in edge["plan"] if s.get("trigger")]

    assert triggers == ["daily"]
    assert not any(s.get("passed") for s in edge["plan"])
    assert edge["serial_groups"] == prod["serial_groups"]
    assert _task(JOB, TASK)["timeout"] == _task("dast-prod", "zap-baseline")["timeout"]


def test_it_is_in_the_prod_group() -> None:
    """Concourse hides a job that is in no group."""
    groups = {g["name"]: g["jobs"] for g in _doc()["groups"]}
    assert JOB in groups["prod"]


def test_the_scan_profile_is_dast_prods() -> None:
    """Baseline, passive, 5-minute spider. Not an active scan through Cloudflare."""
    profile = re.compile(r"zap-baseline\.py [^\n|]*")
    assert profile.findall(_script()) == profile.findall(_script("dast-prod", "zap-baseline"))
    assert "zap-full-scan" not in _script()
    assert "zap-api-scan" not in _script()


def test_it_targets_the_public_hostnames_over_https() -> None:
    params = _task(JOB, TASK)["config"]["params"]
    committed = yaml.safe_load(VARS.read_text(encoding="utf-8"))

    assert params["TARGET_URL"] == "((thehub-public-url))"
    assert params["SIBLING_URL"] == "((mykronos-public-url))"
    assert committed["thehub-public-url"] == "https://hub.toddbenson.net"
    assert committed["mykronos-public-url"] == "https://mykronos.toddbenson.net"
    assert committed["thehub-public-url"] != committed["thehub-prod-url"]


def test_it_uses_this_pipelines_token_and_never_mykronoss() -> None:
    """mykronos's ingestion token must never resolve in thehub's scope."""
    params = _task(JOB, TASK)["config"]["params"]
    assert params["MYKRONOS_TOKEN"] == "((thehub-ingestion-token))"
    assert "mykronos-ingestion-token" not in yaml.safe_dump(_jobs()[JOB])


def test_it_reports_to_thehub_under_its_own_target() -> None:
    """Distinguishable from `dast-prod` in TheHub's lifecycle, too."""
    edge = yaml.safe_dump(_jobs()[JOB])
    assert "TARGET_ENV: prod-edge" in edge
    assert "TARGET_ENV: prod\n" not in edge


def test_the_perimeter_checks_stay_under_thehubs_brute_force_threshold() -> None:
    """TheHub's IPS files `brute_force` at five 401s in five minutes."""
    hub_401s = re.findall(r'^\s*expect "\$TARGET_URL[^"]*"\s+401', _script(), re.M)
    assert 0 < len(hub_401s) < 5


# -- the script, executed -----------------------------------------------------

_STUBS = r"""
curl() {
  local url="" hdr="" wfmt="" prev="" a code h
  for a in "$@"; do
    case "$prev" in -D) hdr="$a" ;; -w) wfmt="$a" ;; esac
    case "$a" in http://*|https://*) url="$a" ;; esac
    prev="$a"
  done
  printf '%s %s\n' "$url" "$*" >> "$WORK/curl.calls"
  code=$(awk -v u="$url" '$1 == u { print $2 }' "$WORK/table" | tail -n 1)
  [ -n "$code" ] || code=200
  h="HTTP/1.1 $code X\r\n"
  [ -n "${NO_CF:-}" ] || h="${h}server: cloudflare\r\ncf-ray: 8f00-LAX\r\n"
  if [ -n "${CHALLENGE:-}" ] || [ -f "$WORK/challenged" ]; then
    h="${h}cf-mitigated: challenge\r\n"
  fi
  h="${h}strict-transport-security: max-age=31536000\r\n"
  if [ "$hdr" = "-" ]; then printf "$h"; elif [ -n "$hdr" ]; then printf "$h" > "$hdr"; fi
  [ -z "$wfmt" ] || printf '%s' "$code"
  case " $* " in *" --tls-max "*) return "${TLS_OLD_RC:-35}" ;; esac
  return 0
}
zap-baseline.py() {
  printf '%s\n' "$@" > "$WORK/zap.args"
  if [ -n "${ZAP_EMPTY:-}" ]; then
    printf '{"site": []}' > "$ZAPWRK/zap.json"
  else
    printf '{"site": [{"@name": "x", "alerts": [{"alert": "A"}]}]}' > "$ZAPWRK/zap.json"
  fi
  if [ -n "${CHALLENGE_DURING_SCAN:-}" ]; then : > "$WORK/challenged"; fi
  return "${ZAP_RC:-2}"
}
pip() { return 0; }
python3() {
  if [ "$1" = "-c" ]; then return "${ADAPTER_RC:-0}"; fi
  printf '%s\n' "$@" > "$WORK/upload.args"
  return 0
}
git() {
  case "$*" in *rev-parse*) echo "$SHA" ;; esac
  return 0
}
"""


def _run(
    tmp_path: Path, codes: dict[str, int] | None = None, **env: str
) -> subprocess.CompletedProcess[str]:
    bash = shutil.which("bash")
    assert bash, "bash is required to execute the dast-edge script"
    zapwrk = tmp_path / "zapwrk"
    zapwrk.mkdir()
    table = {
        f"{HUB}/": 200,
        f"{HUB}/api/auth/me": 401,
        f"{HUB}/api/dev/stories": 401,
        f"{HUB}/docs": 401,
        f"{HUB}/openapi.json": 401,
        f"{SIBLING}/": 404,
        f"{SIBLING}/api/health": 401,
        f"{SIBLING}/docs": 401,
        f"{SIBLING}/healthz": 200,
        **(codes or {}),
    }
    (tmp_path / "table").write_text(
        "".join(f"{url} {code}\n" for url, code in table.items()), encoding="utf-8"
    )
    script = _script().replace("/zap/wrk", zapwrk.as_posix())
    full_env = {
        **os.environ,
        "WORK": tmp_path.as_posix(),
        "ZAPWRK": zapwrk.as_posix(),
        "SHA": SHA,
        "TARGET_URL": HUB,
        "SIBLING_URL": SIBLING,
        "MYKRONOS_URL": "http://mykronos.test",
        "MYKRONOS_TOKEN": "tok",
        "MYKRONOS_REF": "v99",
        "SCANNED_BRANCH": "develop",
        **env,
    }
    (tmp_path / "source").mkdir()
    # On stdin, not as `-c`'s argument: the script is longer than a Windows
    # command line, which truncates it silently and runs the remainder.
    # `-e` as the pipeline's `bash -ec` sets it.
    return subprocess.run(
        [bash, "-e", "-s"], input=_STUBS + script, env=full_env, cwd=tmp_path,
        capture_output=True, text=True, timeout=60,
    )


def _uploaded(tmp_path: Path) -> list[str] | None:
    path = tmp_path / "upload.args"
    return path.read_text(encoding="utf-8").split("\n") if path.exists() else None


def _scanned(tmp_path: Path) -> bool:
    return (tmp_path / "zap.args").exists()


def test_a_clean_edge_is_scanned_and_uploaded_as_zap_edge(tmp_path: Path) -> None:
    r = _run(tmp_path)

    assert r.returncode == 0, r.stdout + r.stderr
    zap = (tmp_path / "zap.args").read_text(encoding="utf-8").split("\n")
    assert zap[:2] == ["-t", HUB]
    args = _uploaded(tmp_path)
    assert args is not None
    assert args[args.index("--tool") + 1] == "zap-edge"
    assert args[args.index("--capability") + 1] == "dast"
    assert args[args.index("--repo") + 1] == "ToddGBenson/TheHub"
    assert args[args.index("--commit-sha") + 1] == SHA
    assert "via Cloudflare" in r.stdout


def test_every_probe_goes_over_ipv4(tmp_path: Path) -> None:
    """The host's IPv6 route is dead (#59976); ZAP's JVM prefers IPv4."""
    _run(tmp_path)
    calls = (tmp_path / "curl.calls").read_text(encoding="utf-8").splitlines()
    assert calls
    assert all(" -4 " in f" {call} " for call in calls), calls


def test_a_response_without_cloudflare_is_not_an_edge_scan(tmp_path: Path) -> None:
    """A resolver that hands back the LAN address would make this a second dast-prod."""
    r = _run(tmp_path, NO_CF="1")

    assert r.returncode != 0
    assert "did not traverse the edge" in r.stdout
    assert not _scanned(tmp_path)
    assert _uploaded(tmp_path) is None


def test_a_challenge_fails_and_names_the_operator_fix(tmp_path: Path) -> None:
    r = _run(tmp_path, CHALLENGE="1")

    assert r.returncode != 0
    assert "Cloudflare challenged the scanner" in r.stdout
    assert "WAF" in r.stdout and "egress address" in r.stdout
    assert not _scanned(tmp_path)
    assert _uploaded(tmp_path) is None


def test_a_challenge_that_starts_mid_crawl_is_not_uploaded(tmp_path: Path) -> None:
    r = _run(tmp_path, CHALLENGE_DURING_SCAN="1")

    assert r.returncode != 0
    assert "after the scan" in r.stdout
    assert _uploaded(tmp_path) is None


@pytest.mark.parametrize(
    ("url", "code"),
    [
        (f"{HUB}/api/auth/me", 200),
        (f"{HUB}/openapi.json", 200),
        (f"{SIBLING}/", 200),
        (f"{SIBLING}/api/health", 200),
    ],
    ids=["hub-api-open", "hub-schema-open", "tunnel-allowlist-open", "perimeter-gate-open"],
)
def test_an_open_perimeter_fails_before_any_scan(tmp_path: Path, url: str, code: int) -> None:
    r = _run(tmp_path, {url: code})

    assert r.returncode != 0
    assert f"{url} answered {code}" in r.stdout
    assert not _scanned(tmp_path)
    assert _uploaded(tmp_path) is None


def test_old_tls_is_a_warning_not_a_failure(tmp_path: Path) -> None:
    """Cloudflare's minimum TLS version is unmeasured and operator-owned."""
    r = _run(tmp_path, TLS_OLD_RC="0")

    assert r.returncode == 0, r.stdout + r.stderr
    assert "::warning::" in r.stdout and "accepts TLS 1.0" in r.stdout


def test_a_report_with_no_alerts_is_not_reported_as_clean(tmp_path: Path) -> None:
    r = _run(tmp_path, ZAP_EMPTY="1")

    assert r.returncode != 0
    assert "Refusing to report it as clean" in r.stdout
    assert _uploaded(tmp_path) is None


def test_a_scanner_failure_is_not_a_result(tmp_path: Path) -> None:
    r = _run(tmp_path, ZAP_RC="3")

    assert r.returncode == 3
    assert _uploaded(tmp_path) is None


def test_an_uploader_without_the_adapter_names_the_pin(tmp_path: Path) -> None:
    """`mykronos-ref` at a tag that predates D-154 fails loudly, before uploading."""
    r = _run(tmp_path, ADAPTER_RC="1")

    assert r.returncode != 0
    assert "no zap-edge adapter" in r.stdout and "mykronos-ref" in r.stdout
    assert _uploaded(tmp_path) is None
