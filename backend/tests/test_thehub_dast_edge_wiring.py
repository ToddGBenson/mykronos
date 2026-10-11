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

import hashlib
import hmac
import json
import os
import re
import shutil
import subprocess
import sys
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
    """Baseline, passive, 5-minute spider. Not an active scan through Cloudflare.

    The one addition is `--hook`, which loads the request signer (#60724) and
    changes no rule, no spider budget and no scan mode.
    """
    profile = re.compile(r"zap-baseline\.py [^\n|]*")
    edge = [re.sub(r' --hook="[^"]*"', "", line) for line in profile.findall(_script())]
    assert edge == profile.findall(_script("dast-prod", "zap-baseline"))
    assert '--hook="$SIGNER_DIR/hook.py"' in _script()
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


def test_the_scanner_token_comes_from_vault_with_an_apply_fallback() -> None:
    """TheHub #60724. `Add-Secret` probes Vault, then TheHub's .env."""
    params = _task(JOB, TASK)["config"]["params"]
    script = (ROOT / "deploy" / "concourse" / "set-thehub-pipeline.ps1").read_text(
        encoding="utf-8"
    )
    assert params["HUB_SCANNER_TOKEN"] == "((hub-scanner-token))"
    assert re.search(r'^Add-Secret -Name "hub-scanner-token"', script, re.M)
    assert '"HUB_SCANNER_TOKEN" -Optional' in script
    assert "hub-scanner-token" not in yaml.safe_load(VARS.read_text(encoding="utf-8"))


def test_the_signer_files_stay_out_of_the_results_directory() -> None:
    """Every *.json in /zap/wrk is parsed as a ZAP report by the upload."""
    script = _script()
    assert 'HUB_SCANNER_SCRIPT="$SIGNER_DIR/' in script
    assert 'cat > "$SIGNER_DIR/hook.py"' in script
    assert not re.search(r"cat > \S*/zap/wrk", script)


# -- the signature: a known vector, three implementations -----------------------
#
# TheHub's verifier (services/scanner_identity.py at ffe23ede) computes
# hmac.new(key.encode(), f"{ts}{path}".encode(), hashlib.sha256).hexdigest().
# The job signs in two places -- python3 for its own probes, a ZAP script for
# the crawl -- and both must agree with that byte for byte.

VECTOR_KEY = "unit-test-scanner-token"
VECTOR_TS = "1700000000"
VECTOR_PATH = "/api/auth/me"
VECTOR_HEX = "e19a5a679c9f45e5e99e69c7f2d8b987cf461f316d227b2b333bd0ee0d55669c"


def test_the_vector_is_thehubs_formula() -> None:
    mac = hmac.new(
        VECTOR_KEY.encode(), f"{VECTOR_TS}{VECTOR_PATH}".encode(), hashlib.sha256
    ).hexdigest()
    assert mac == VECTOR_HEX


def _heredoc(tag: str) -> str:
    match = re.search(rf"<<'{tag}'\n(.*?)\n{tag}\n", _script(), re.S)
    assert match, f"no <<'{tag}' heredoc in the {TASK} script"
    return match.group(1)


#: Just enough of GraalJS's `Java.type` for the sender script, backed by node's
#: crypto. Bytes come back signed, as Java's do, so `& 0xff` is exercised.
_JAVA_SHIM = r"""
const crypto = require('crypto');
const ENV = JSON.parse(process.env.SHIM_ENV);
const Java = { type(name) {
  if (name === 'java.lang.String') {
    return function (s) { this.getBytes = () => Buffer.from(String(s), 'utf8'); };
  }
  if (name === 'java.nio.charset.StandardCharsets') return { UTF_8: 'UTF-8' };
  if (name === 'java.lang.System') return { getenv: (k) => (k in ENV ? ENV[k] : null) };
  if (name === 'javax.crypto.spec.SecretKeySpec') return function (key) { this.key = key; };
  if (name === 'javax.crypto.Mac') return { getInstance() {
    let h; return { init(spec) { h = crypto.createHmac('sha256', spec.key); },
                    doFinal(data) { return Int8Array.from(h.update(data).digest()); } };
  } };
  throw new Error('unshimmed ' + name);
} };
"""

_JS_DRIVER = r"""
const out = { vector: hubScannerSignature(ENV.KEY, ENV.TS, ENV.PATH), headers: {} };
for (const [host, path] of [['hub.example.net', '/api/auth/me'], ['mk.example.net', '/api/health'],
                            ['HUB.example.net', '']]) {
  const set = {};
  const msg = { getRequestHeader: () => ({
    getURI: () => ({ getHost: () => host, getPath: () => path }),
    setHeader: (k, v) => { set[k] = v; } }) };
  sendingRequest(msg, 1, null);
  out.headers[host + (path || '<empty>')] = set['X-Hub-Scanner'] || null;
}
console.log(JSON.stringify(out));
"""


def _run_js(env: dict[str, str]) -> dict[str, Any]:
    node = shutil.which("node")
    if not node:
        pytest.skip("node is needed to execute the ZAP sender script")
    source = _JAVA_SHIM + _heredoc("JS") + _JS_DRIVER
    r = subprocess.run(
        [node, "-e", source], env={**os.environ, "SHIM_ENV": json.dumps(env)},
        capture_output=True, text=True, timeout=30,
    )
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def test_the_zap_sender_script_signs_the_known_vector() -> None:
    out = _run_js({"KEY": VECTOR_KEY, "TS": VECTOR_TS, "PATH": VECTOR_PATH})
    assert out["vector"] == f"{VECTOR_TS}.{VECTOR_HEX}"


def test_the_zap_sender_script_signs_hubs_host_only() -> None:
    out = _run_js({
        "KEY": VECTOR_KEY, "TS": VECTOR_TS, "PATH": VECTOR_PATH,
        "HUB_SCANNER_TOKEN": VECTOR_KEY, "HUB_SCANNER_HOST": "hub.example.net",
    })
    signed = out["headers"]["hub.example.net/api/auth/me"]
    ts, _, mac = signed.partition(".")
    expected = hmac.new(
        VECTOR_KEY.encode(), f"{ts}/api/auth/me".encode(), hashlib.sha256
    ).hexdigest()
    assert mac == expected
    assert out["headers"]["mk.example.net/api/health"] is None
    # Host compared case-insensitively; an empty path is signed as "/".
    root = out["headers"]["HUB.example.net<empty>"]
    ts, _, mac = root.partition(".")
    assert mac == hmac.new(VECTOR_KEY.encode(), f"{ts}/".encode(), hashlib.sha256).hexdigest()


def test_the_zap_sender_script_does_nothing_without_a_token() -> None:
    out = _run_js({
        "KEY": VECTOR_KEY, "TS": VECTOR_TS, "PATH": VECTOR_PATH,
        "HUB_SCANNER_HOST": "hub.example.net",
    })
    assert set(out["headers"].values()) == {None}


# -- the hook that loads it -------------------------------------------------------


class _FakeScript:
    def __init__(self, engines: list[str], accepts: str | None) -> None:
        self.list_engines = engines
        self.accepts = accepts
        self.loaded: list[tuple[str, ...]] = []
        self.enabled: list[str] = []

    def load(self, *args: str) -> str:
        self.loaded.append(args)
        if args[2] != self.accepts:
            raise RuntimeError("no such engine")
        return "OK"

    def enable(self, name: str) -> str:
        self.enabled.append(name)
        return "OK"


class _FakeZap:
    def __init__(self, engines: list[str], accepts: str | None) -> None:
        self.script = _FakeScript(engines, accepts)


def _hook(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, token: str) -> dict[str, Any]:
    namespace: dict[str, Any] = {}
    exec(compile(_heredoc("PY"), "hook.py", "exec"), namespace)  # noqa: S102 - our own heredoc
    monkeypatch.setenv("HUB_SCANNER_STATUS", str(tmp_path / "status"))
    monkeypatch.setenv("HUB_SCANNER_SCRIPT", "/s/hub-scanner-sign.js")
    monkeypatch.setenv("HUB_SCANNER_TOKEN", token)
    return namespace


def test_the_hook_loads_and_enables_an_httpsender_script(tmp_path, monkeypatch) -> None:
    hook = _hook(tmp_path, monkeypatch, "k")
    zap = _FakeZap(["Zest : Mozilla Zest", "ECMAScript : Graal.js"], accepts="Graal.js")

    hook["zap_started"](zap, "https://hub.example.net")

    assert zap.script.loaded[-1] == (
        "hub-scanner-sign", "httpsender", "Graal.js", "/s/hub-scanner-sign.js",
    )
    assert zap.script.enabled == ["hub-scanner-sign"]
    assert (tmp_path / "status").read_text(encoding="utf-8") == "signed"


def test_the_hook_fails_loudly_when_no_engine_takes_the_script(tmp_path, monkeypatch) -> None:
    hook = _hook(tmp_path, monkeypatch, "k")
    zap = _FakeZap(["Zest : Mozilla Zest"], accepts=None)

    with pytest.raises(RuntimeError):
        hook["zap_started"](zap, "https://hub.example.net")

    assert (tmp_path / "status").read_text(encoding="utf-8").startswith("failed")
    assert zap.script.enabled == []


def test_the_hook_loads_nothing_without_a_token(tmp_path, monkeypatch) -> None:
    hook = _hook(tmp_path, monkeypatch, "")
    zap = _FakeZap(["ECMAScript : Graal.js"], accepts="Graal.js")

    hook["zap_started"](zap, "https://hub.example.net")

    assert zap.script.loaded == []
    assert (tmp_path / "status").read_text(encoding="utf-8") == "unsigned"


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
  # Stands in for the hook (tested on its own above): what it would record.
  if [ -z "${HUB_SCANNER_TOKEN:-}" ]; then printf unsigned > "$HUB_SCANNER_STATUS"
  elif [ -n "${SIGNER_FAILS:-}" ]; then printf 'failed: test' > "$HUB_SCANNER_STATUS"
  else printf signed > "$HUB_SCANNER_STATUS"; fi
  return "${ZAP_RC:-2}"
}
pip() { return 0; }
python3() {
  if [ "$1" = "-c" ]; then
    # The signer and the host lookup run for real; the adapter probe is stubbed.
    case "$2" in *get_adapter*) return "${ADAPTER_RC:-0}" ;; esac
    "$REAL_PY" "$@"
    return $?
  fi
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
    inherited = {k: v for k, v in os.environ.items() if k != "HUB_SCANNER_TOKEN"}
    full_env = {
        **inherited,
        "REAL_PY": Path(sys.executable).as_posix(),
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


# -- signing, executed ----------------------------------------------------------

_SIGNED = re.compile(r"-H X-Hub-Scanner: (\d+)\.([0-9a-f]{64})")


def _calls(tmp_path: Path) -> list[str]:
    return (tmp_path / "curl.calls").read_text(encoding="utf-8").splitlines()


def test_the_probes_sign_the_known_vector(tmp_path: Path) -> None:
    """The job's own 401 probes sign too, so they do not count toward brute force."""
    r = _run(tmp_path, HUB_SCANNER_TOKEN=VECTOR_KEY, SIGN_TS=VECTOR_TS)

    assert r.returncode == 0, r.stdout + r.stderr
    me = next(c for c in _calls(tmp_path) if c.startswith(f"{HUB}/api/auth/me "))
    assert f"-H X-Hub-Scanner: {VECTOR_TS}.{VECTOR_HEX}" in me


def test_every_hub_probe_is_signed_and_no_sibling_probe_is(tmp_path: Path) -> None:
    r = _run(tmp_path, HUB_SCANNER_TOKEN=VECTOR_KEY)

    assert r.returncode == 0, r.stdout + r.stderr
    for call in _calls(tmp_path):
        url = call.split(" ", 1)[0]
        match = _SIGNED.search(call)
        if url.startswith(SIBLING):
            assert match is None, call
        elif url.startswith(HUB) and "--tls" not in call and " -D - " not in call:
            assert match, call
            path = url[len(HUB):] or "/"
            expected = hmac.new(
                VECTOR_KEY.encode(), f"{match.group(1)}{path}".encode(), hashlib.sha256
            ).hexdigest()
            assert match.group(2) == expected, call
    assert "X-Hub-Scanner: signed." in r.stdout


def test_the_token_is_never_printed(tmp_path: Path) -> None:
    secret = "sentinel-scanner-token-must-not-appear"
    r = _run(tmp_path, HUB_SCANNER_TOKEN=secret)

    assert r.returncode == 0, r.stdout + r.stderr
    assert secret not in r.stdout + r.stderr
    assert not any(secret in p.read_text(encoding="utf-8", errors="replace")
                   for p in (tmp_path / "zapwrk").iterdir())


def test_an_empty_token_scans_unsigned_and_warns(tmp_path: Path) -> None:
    r = _run(tmp_path, HUB_SCANNER_TOKEN="")

    assert r.returncode == 0, r.stdout + r.stderr
    assert "UNSIGNED" in r.stdout and "brute_force" in r.stdout
    assert not any(_SIGNED.search(c) for c in _calls(tmp_path))
    assert _uploaded(tmp_path) is not None


def test_a_token_with_a_broken_signer_is_not_uploaded(tmp_path: Path) -> None:
    """A token and an unsigned crawl means the signer broke, not 'no token'."""
    r = _run(tmp_path, HUB_SCANNER_TOKEN=VECTOR_KEY, SIGNER_FAILS="1")

    assert r.returncode != 0
    assert "did not sign its requests" in r.stdout
    assert _uploaded(tmp_path) is None
