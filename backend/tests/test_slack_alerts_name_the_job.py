"""Pipeline Slack alerts name the job and link to it.

Every alert in #alerts from 2026-10-08 to 10-10 read

    *TheHub*: job `` failed (build ) - it ran and the answer was bad...
    http://localhost:8080/teams//pipelines//jobs//builds/

The notify task built its text and link from BUILD_JOB_NAME / BUILD_NAME /
BUILD_TEAM_NAME / BUILD_PIPELINE_NAME, which Concourse gives to RESOURCES, not
to tasks, so all of them were empty in every alert ever sent. Each hook now
passes JOB, and the slack_params anchor carries the static pipeline, team and
URL.

These EXECUTE the notify script as it stands in each pipeline -- with the
params a real hook resolves to, and curl stubbed to capture the payload --
rather than asserting that words are present.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

PIPELINES = ("thehub", "personal-soc", "mykronos")


def _pipeline_dir() -> Path:
    for parent in Path(__file__).resolve().parents:
        d = parent / "deploy" / "concourse" / "pipelines"
        if (d / "thehub.yml").is_file():
            return d
    pytest.fail("deploy/concourse/pipelines not found above this test")


def _hooks(name: str) -> list[tuple[str, dict]]:
    doc = yaml.safe_load((_pipeline_dir() / f"{name}.yml").read_text(encoding="utf-8"))
    found: list[tuple[str, dict]] = []

    def walk(node, job):
        if isinstance(node, dict):
            if node.get("task") == "notify-slack":
                found.append((job, node))
            for v in node.values():
                walk(v, job)
        elif isinstance(node, list):
            for v in node:
                walk(v, job)

    for job in doc["jobs"]:
        walk(job, job["name"])
    assert found, f"{name}: no notify-slack hooks found"
    return found


_CURL_STUB = """curl() {
  for a in "$@"; do
    case "$a" in @*) cp "${a#@}" "$CAPTURE" ;; esac
  done
  echo '{"ok":true}'
}
"""


def _render(hook: dict, tmp_path: Path, **overrides) -> dict:
    sh = shutil.which("sh")
    assert sh, "sh is required to execute the notify script"
    script = hook["config"]["run"]["args"][-1]
    # The hook writes a fixed /tmp/payload.json -- right in a Concourse
    # container, where nothing runs beside it, but under pytest-xdist every
    # case on the host shares that one file and they race. Each case gets its
    # own path, substituted here; the pipeline itself is unchanged.
    assert "/tmp/payload.json" in script, "the hook no longer writes /tmp/payload.json"
    script = script.replace("/tmp/payload.json", (tmp_path / "sent.json").as_posix())
    params = {k: str(v) for k, v in (hook.get("params") or {}).items()}
    # The real token/channel are Vault refs; any non-empty value enables posting.
    params.update(SLACK_BOT_TOKEN="xoxb-test", SLACK_CHANNEL="C0TEST")
    params.update({k: v for k, v in overrides.items() if v is not None})
    for k, v in overrides.items():
        if v is None:
            params.pop(k, None)
    capture = tmp_path / "payload.json"
    # The FULL environment, not just PATH: on a Windows host Git's sh finds
    # `sed` (the script's escaping step) only through its own PATH translation.
    env = {**os.environ, "CAPTURE": str(capture), **params}
    for k, v in overrides.items():
        if v is None:
            env.pop(k, None)
    # On stdin, not `sh -c <script>`: on Windows the -c argument goes through
    # command-line quoting, which halves backslashes next to quotes and turned
    # the script's own sed escaping into an unterminated `s` command.
    r = subprocess.run([sh, "-s"], input=_CURL_STUB + script, env=env,
                       cwd=tmp_path, capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    assert capture.exists(), f"nothing was posted: {r.stdout}{r.stderr}"
    # Slack rejects a body that is not JSON, so parse it as Slack would.
    return json.loads(capture.read_text(encoding="utf-8"))


@pytest.mark.parametrize("name", PIPELINES)
def test_every_hook_passes_its_own_job_name_and_the_static_metadata(name):
    for job, hook in _hooks(name):
        p = hook.get("params") or {}
        assert p.get("JOB") == job, f"{name}: a hook in {job} passes JOB={p.get('JOB')!r}"
        assert p.get("PIPELINE") == name and p.get("TEAM") == "main"
        # TheHub #60941: never a loopback link; "" sends none.
        url = str(p.get("CONCOURSE_URL", ""))
        assert url == "" or url.startswith("http"), url
        for loopback in LOOPBACK:
            assert loopback not in url, f"{name}/{job}: CONCOURSE_URL={url!r}"
        assert "SLACK_BOT_TOKEN" in p and "SLACK_CHANNEL" in p, (
            f"{name}/{job}: step params replaced the credentials instead of merging"
        )


#: Hosts a phone reading Slack cannot reach: they name the Concourse host itself.
LOOPBACK = ("localhost", "127.0.0.1", "[::1]", "0.0.0.0")


@pytest.mark.parametrize("name", PIPELINES)
@pytest.mark.parametrize("outcome", [None, "errored"])
def test_the_posted_alert_names_the_job_and_links_to_it(name, outcome, tmp_path):
    job, hook = _hooks(name)[0]
    payload = _render(hook, tmp_path, OUTCOME=outcome, CONCOURSE_URL="http://ci.example.net:8080/")
    text = payload["text"]
    assert f"`{job}`" in text, text
    assert f"\nhttp://ci.example.net:8080/teams/main/pipelines/{name}/jobs/{job}" in text, text
    for empty in ("``", "(build )", "teams//", "pipelines//", "jobs//", "8080//"):
        assert empty not in text, f"{empty!r} in {text!r}"
    assert ("ERRORED" in text) == (outcome == "errored")


@pytest.mark.parametrize("name", PIPELINES)
def test_the_alert_as_the_pipeline_ships_carries_no_link_it_cannot_open(name, tmp_path):
    """TheHub #60941: as applied, every alert linked to http://localhost:8080."""
    job, hook = _hooks(name)[0]
    text = _render(hook, tmp_path)["text"]
    assert f"`{job}`" in text, text
    assert "http" not in text and "/teams/" not in text, text
    assert not text.endswith("\n"), "an empty link line was still sent"


@pytest.mark.parametrize("name", PIPELINES)
@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:8080",
        "http://localhost",
        "http://127.0.0.1:8080/",
        "http://[::1]:8080",
        "http://0.0.0.0:8080",
    ],
)
def test_a_loopback_concourse_url_is_refused(name, url, tmp_path):
    """Matching #988: a loopback URL set by hand is left out, not linked."""
    job, hook = _hooks(name)[0]
    text = _render(hook, tmp_path, CONCOURSE_URL=url)["text"]
    assert f"`{job}`" in text, text
    for loopback in LOOPBACK:
        assert loopback not in text, f"{loopback!r} in {text!r}"
    assert "/teams/" not in text, text


def test_a_hook_that_forgot_job_says_so_rather_than_posting_an_empty_name(tmp_path):
    job, hook = _hooks("thehub")[0]
    text = _render(hook, tmp_path, JOB=None)["text"]
    assert "``" not in text
    assert "passed no JOB" in text
