"""`dast-demo` authenticates through Cloudflare Access with a service token (TheHub #60803).

demo.toddbenson.net goes behind a Cloudflare Access application (option A),
and the demo lane scans it there, through Cloudflare, presenting the Access
service token. The failure this guards against is quiet: without the token
every request meets Access's login page, and a crawl of a login page reads as
a clean demo. So an empty token, a token Access does not admit, and a report
that never reached the demo each fail the job; requests that met the login
page mid-crawl are dropped and the run is marked partial.

As in `test_thehub_dast_edge_wiring.py`, the task script is EXECUTED as it
stands in the pipeline, with curl, ZAP, pip, python3 and git stubbed to
record what they were asked to do. The one textual change is `/zap/wrk`.
"""

from __future__ import annotations

import json
import os
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
APPLIER = ROOT / "deploy" / "concourse" / "set-thehub-pipeline.ps1"
JOB = "dast-demo"
TASK = "zap-baseline"
SHA = "0123456789abcdef0123456789abcdef01234567"
DEMO = "https://demo.example.net"
CLIENT_ID = "sentinel-client-id.access"
CLIENT_SECRET = "sentinel-client-secret-must-not-appear"
LOGIN = "https://team.cloudflareaccess.com/cdn-cgi/access/login/demo.example.net"


def _task() -> dict[str, Any]:
    doc = yaml.safe_load(PIPELINE.read_text(encoding="utf-8"))
    job = next(j for j in doc["jobs"] if j["name"] == JOB)
    return next(step for step in job["plan"] if step.get("task") == TASK)


def _script() -> str:
    return str(_task()["config"]["run"]["args"][-1])


# -- shape --------------------------------------------------------------------


def test_it_targets_the_public_demo_with_the_token_from_vault() -> None:
    params = _task()["config"]["params"]
    assert params["TARGET_URL"] == "((thehub-demo-public-url))"
    assert params["CF_ACCESS_CLIENT_ID"] == "((cf-access-demo-client-id))"
    assert params["CF_ACCESS_CLIENT_SECRET"] == "((cf-access-demo-client-secret))"


def test_the_public_url_is_in_the_committed_vars_and_the_applier() -> None:
    """Self-apply reads vars/thehub.yml; set-thehub-pipeline.ps1 writes its own."""
    assert yaml.safe_load(VARS.read_text(encoding="utf-8"))["thehub-demo-public-url"] == (
        "https://demo.toddbenson.net"
    )
    applier = APPLIER.read_text(encoding="utf-8")
    assert '"thehub-demo-public-url: $DemoPublicUrl"' in applier


def test_the_token_is_a_secret_never_a_committed_var() -> None:
    names = set(yaml.safe_load(VARS.read_text(encoding="utf-8")))
    assert not {"cf-access-demo-client-id", "cf-access-demo-client-secret"} & names
    applier = APPLIER.read_text(encoding="utf-8")
    for name in ("cf-access-demo-client-id", "cf-access-demo-client-secret"):
        assert f'Add-Secret -Name "{name}"' in applier


def test_it_still_uploads_as_zap_demo_under_its_own_job() -> None:
    script = _script()
    assert "MYKRONOS_JOB=dast-demo python3 -m mykronos.upload" in script
    assert "--tool zap-demo" in script


# -- the script, executed -----------------------------------------------------

_STUBS = r"""
curl() {
  local url="" hdr="" wfmt="" prev="" a code loc h who=without
  for a in "$@"; do
    case "$prev" in -D) hdr="$a" ;; -w) wfmt="$a" ;; esac
    if [ "$prev" = -H ]; then
      case "$a" in @*) who=with; cp "${a#@}" "$WORK/headers.seen" ;; esac
    fi
    case "$a" in http://*|https://*) url="$a" ;; esac
    prev="$a"
  done
  printf '%s %s %s\n' "$who" "$url" "$*" >> "$WORK/curl.calls"
  if [ "$who" = with ] && [ -f "$WORK/token-revoked" ]; then who=without; fi
  code=$(awk -v u="$url" -v w="$who" '$1 == w && $2 == u { print $3 }' "$WORK/table" | tail -n 1)
  loc=$(awk -v u="$url" -v w="$who" '$1 == w && $2 == u { print $4 }' "$WORK/table" | tail -n 1)
  [ -n "$code" ] || code=200
  h="HTTP/1.1 $code X\r\n"
  [ -n "${NO_CF:-}" ] || h="${h}server: cloudflare\r\ncf-ray: 8f00-LAX\r\n"
  [ -z "$loc" ] || [ "$loc" = "-" ] || h="${h}location: $loc\r\n"
  if [ -n "$hdr" ]; then printf "$h" > "$hdr"; fi
  [ -z "$wfmt" ] || printf '%s' "$code"
  return 0
}
zap-baseline.py() {
  printf '%s\n' "$@" > "$WORK/zap.args"
  cp "$WORK/report.json" "$ZAPWRK/zap.json"
  if [ -n "${REVOKE_DURING_SCAN:-}" ]; then : > "$WORK/token-revoked"; fi
  # Stands in for the hook: what it would record.
  if [ -n "${HOOK_FAILS:-}" ]; then printf 'failed: test' > "$ACCESS_STATUS"
  else printf presented > "$ACCESS_STATUS"; fi
  return "${ZAP_RC:-2}"
}
pip() { return 0; }
python3() {
  if [ "$1" = "-c" ] || [ "$1" = "-" ]; then
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

#: Access in front: admitted with the token, sent to the login without it.
ACCESS_ON = {
    ("with", f"{DEMO}/"): (200, "-"),
    ("without", f"{DEMO}/"): (302, LOGIN),
}


def _site(name: str, alerts: int = 1, uri: str | None = None) -> dict[str, Any]:
    return {
        "@name": name,
        "alerts": [
            {"alert": f"A{i}", "instances": [{"uri": uri or f"{name}/p{i}", "method": "GET"}]}
            for i in range(alerts)
        ],
    }


def _run(
    tmp_path: Path,
    table: dict[tuple[str, str], tuple[int, str]] | None = None,
    report: dict[str, Any] | None = None,
    **env: str,
) -> subprocess.CompletedProcess[str]:
    bash = shutil.which("bash")
    assert bash, "bash is required to execute the dast-demo script"
    zapwrk = tmp_path / "zapwrk"
    zapwrk.mkdir()
    rows = {**ACCESS_ON, **(table or {})}
    (tmp_path / "table").write_text(
        "".join(f"{who} {url} {code} {loc}\n" for (who, url), (code, loc) in rows.items()),
        encoding="utf-8",
    )
    (tmp_path / "report.json").write_text(
        json.dumps(report if report is not None else {"site": [_site(DEMO, 2)]}),
        encoding="utf-8",
    )
    script = _script().replace("/zap/wrk", zapwrk.as_posix())
    inherited = {
        k: v for k, v in os.environ.items() if not k.startswith("CF_ACCESS_CLIENT")
    }
    full_env = {
        **inherited,
        "REAL_PY": Path(sys.executable).as_posix(),
        "WORK": tmp_path.as_posix(),
        "ZAPWRK": zapwrk.as_posix(),
        "SHA": SHA,
        "TARGET_URL": DEMO,
        "CF_ACCESS_CLIENT_ID": CLIENT_ID,
        "CF_ACCESS_CLIENT_SECRET": CLIENT_SECRET,
        "MYKRONOS_URL": "http://mykronos.test",
        "MYKRONOS_TOKEN": "tok",
        "MYKRONOS_REF": "v99",
        "SCANNED_BRANCH": "develop",
        **env,
    }
    (tmp_path / "source").mkdir()
    return subprocess.run(
        [bash, "-e", "-s"], input=_STUBS + script, env=full_env, cwd=tmp_path,
        capture_output=True, text=True, timeout=60,
    )


def _uploaded(tmp_path: Path) -> list[str] | None:
    path = tmp_path / "upload.args"
    return path.read_text(encoding="utf-8").split("\n") if path.exists() else None


def _scanned(tmp_path: Path) -> bool:
    return (tmp_path / "zap.args").exists()


def test_an_admitted_scan_is_uploaded_as_zap_demo(tmp_path: Path) -> None:
    r = _run(tmp_path)

    assert r.returncode == 0, r.stdout + r.stderr
    zap = (tmp_path / "zap.args").read_text(encoding="utf-8").split("\n")
    assert zap[:2] == ["-t", DEMO]
    assert any(a.startswith("--hook=") for a in zap)
    args = _uploaded(tmp_path)
    assert args is not None
    assert args[args.index("--tool") + 1] == "zap-demo"
    assert args[args.index("--repo") + 1] == "ToddGBenson/TheHub"
    assert "Access admitted the service token" in r.stdout
    assert "Access is enforcing" in r.stdout
    assert not (tmp_path / "zapwrk" / "zap-incomplete.json").exists()


def test_the_probes_present_both_headers(tmp_path: Path) -> None:
    r = _run(tmp_path)

    assert r.returncode == 0, r.stdout + r.stderr
    seen = (tmp_path / "headers.seen").read_text(encoding="utf-8")
    assert f"CF-Access-Client-Id: {CLIENT_ID}" in seen
    assert f"CF-Access-Client-Secret: {CLIENT_SECRET}" in seen


@pytest.mark.parametrize("empty", ["CF_ACCESS_CLIENT_ID", "CF_ACCESS_CLIENT_SECRET"])
def test_an_empty_token_fails_before_anything_runs(tmp_path: Path, empty: str) -> None:
    r = _run(tmp_path, **{empty: ""})

    assert r.returncode != 0
    assert "cf-access-demo-client" in r.stdout and "#60875" in r.stdout
    assert "vault-secret.ps1 set" in r.stdout
    assert not (tmp_path / "curl.calls").exists()
    assert not _scanned(tmp_path) and _uploaded(tmp_path) is None


@pytest.mark.parametrize(
    "answer",
    [(302, LOGIN), (302, f"{DEMO}/cdn-cgi/access/login/demo.example.net"), (403, "-")],
)
def test_a_token_access_does_not_admit_is_not_scanned(
    tmp_path: Path, answer: tuple[int, str]
) -> None:
    r = _run(tmp_path, {("with", f"{DEMO}/"): answer})

    assert r.returncode != 0
    assert "did not admit the service token" in r.stdout
    assert not _scanned(tmp_path) and _uploaded(tmp_path) is None


def test_a_response_without_cloudflare_is_refused(tmp_path: Path) -> None:
    r = _run(tmp_path, NO_CF="1")

    assert r.returncode != 0
    assert "without Cloudflare's headers" in r.stdout
    assert not _scanned(tmp_path)


def test_access_not_enforcing_warns_and_still_scans(tmp_path: Path) -> None:
    r = _run(tmp_path, {("without", f"{DEMO}/"): (200, "-")})

    assert r.returncode == 0, r.stdout + r.stderr
    assert "not" in r.stdout and "enforcing" in r.stdout and "::warning::" in r.stdout
    assert _uploaded(tmp_path) is not None


def test_a_report_with_only_the_login_page_fails(tmp_path: Path) -> None:
    report = {"site": [_site("https://team.cloudflareaccess.com", 3)]}
    r = _run(tmp_path, report=report)

    assert r.returncode != 0
    assert "no site on demo.example.net" in r.stdout
    assert _uploaded(tmp_path) is None


def test_login_page_hits_mid_crawl_are_dropped_and_marked_partial(tmp_path: Path) -> None:
    report = {
        "site": [
            {
                "@name": DEMO,
                "alerts": [
                    {"alert": "Real", "instances": [{"uri": f"{DEMO}/api/x"}]},
                    {
                        "alert": "Login",
                        "instances": [{"uri": f"{DEMO}/cdn-cgi/access/login/demo.example.net"}],
                    },
                ],
            },
            _site("https://team.cloudflareaccess.com", 1),
        ]
    }
    r = _run(tmp_path, report=report)

    assert r.returncode == 0, r.stdout + r.stderr
    marker = (tmp_path / "zapwrk" / "zap-incomplete.json").read_text(encoding="utf-8")
    assert marker.startswith("MYKRONOS-INCOMPLETE:")
    kept = json.loads((tmp_path / "zapwrk" / "zap.json").read_text(encoding="utf-8"))
    assert [s["@name"] for s in kept["site"]] == [DEMO]
    assert [a["alert"] for a in kept["site"][0]["alerts"]] == ["Real"]
    assert _uploaded(tmp_path) is not None


def test_a_token_refused_by_the_end_of_the_scan_is_not_uploaded(tmp_path: Path) -> None:
    r = _run(tmp_path, REVOKE_DURING_SCAN="1")

    assert r.returncode != 0
    assert "no longer admits the service token" in r.stdout
    assert _uploaded(tmp_path) is None


def test_a_hook_that_did_not_load_is_not_uploaded(tmp_path: Path) -> None:
    r = _run(tmp_path, HOOK_FAILS="1")

    assert r.returncode != 0
    assert "did not present the Access service token" in r.stdout
    assert _uploaded(tmp_path) is None


def test_a_report_with_no_alerts_is_not_clean(tmp_path: Path) -> None:
    r = _run(tmp_path, report={"site": [{"@name": DEMO, "alerts": []}]})

    assert r.returncode != 0
    assert "no alerts at all" in r.stdout
    assert _uploaded(tmp_path) is None


def test_a_scanner_failure_is_not_a_result(tmp_path: Path) -> None:
    r = _run(tmp_path, ZAP_RC="3")

    assert r.returncode == 3
    assert _uploaded(tmp_path) is None


def test_the_token_is_never_printed_or_left_behind(tmp_path: Path) -> None:
    r = _run(tmp_path)

    assert r.returncode == 0, r.stdout + r.stderr
    for secret in (CLIENT_ID, CLIENT_SECRET):
        assert secret not in r.stdout + r.stderr
        assert not any(
            secret in p.read_text(encoding="utf-8", errors="replace")
            for p in (tmp_path / "zapwrk").iterdir()
        )
        calls = (tmp_path / "curl.calls").read_text(encoding="utf-8")
        assert secret not in calls  # never on a command line


# -- the ZAP sender script ----------------------------------------------------


def _embedded(marker: str) -> str:
    """The heredoc body that follows `cat > ... <<'<marker>'`."""
    lines = _script().splitlines()
    start = next(i for i, line in enumerate(lines) if line.endswith(f"<<'{marker}'"))
    end = next(i for i in range(start + 1, len(lines)) if lines[i] == marker)
    return "\n".join(lines[start + 1 : end])


def test_the_sender_script_sets_both_headers_for_the_demo_host_only() -> None:
    js = _embedded("JS")
    assert "setHeader('CF-Access-Client-Id'" in js
    assert "setHeader('CF-Access-Client-Secret'" in js
    assert "System.getenv('TARGET_HOST')" in js
    assert "!== String(host).toLowerCase()" in js


def test_the_hook_loads_and_enables_an_httpsender_script(tmp_path, monkeypatch) -> None:
    namespace: dict[str, Any] = {}
    exec(compile(_embedded("PY"), "hook.py", "exec"), namespace)  # noqa: S102 - the pipeline's own hook

    class Script:
        list_engines = ["Graal.js : Graal.js"]

        def __init__(self) -> None:
            self.loaded: list[tuple[str, ...]] = []
            self.enabled: list[str] = []

        def load(self, name: str, kind: str, engine: str, path: str) -> str:
            self.loaded.append((name, kind, engine, path))
            return "OK"

        def enable(self, name: str) -> None:
            self.enabled.append(name)

    class Zap:
        script = Script()

    monkeypatch.setenv("ACCESS_STATUS", str(tmp_path / "status"))
    monkeypatch.setenv("ACCESS_SCRIPT", str(tmp_path / "s.js"))
    namespace["zap_started"](Zap, DEMO)
    assert Zap.script.loaded[0][1] == "httpsender"
    assert Zap.script.enabled == ["cf-access-headers"]
    assert (tmp_path / "status").read_text(encoding="utf-8") == "presented"
