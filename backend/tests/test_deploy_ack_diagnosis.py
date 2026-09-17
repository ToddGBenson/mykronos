"""The deploy gate's timeout message has to describe what it read — TheHub#343.

`deploy-demo` and `deploy-prod` publish a pointer to MinIO and then wait for the
deploy host to acknowledge it. When the wait runs out the job has, on disk, the
very object that would explain why: `<env>.deployed`. It used to ignore that and
print a fixed sentence instead —

    The pointer is published and still stands. This means the
    host-side poller is not running, or it failed and rolled back:
    Scheduled Task 'TheHub Registry Pull Deploy' on the deploy host.

— which for `deploy-demo` #82 through #88 was false in every clause. The poller
ran on each five-minute cycle, deployed, and wrote the acknowledgement; only the
comparison could not read it, because the acknowledgement carried a CR (#388).

The cost of the wrong sentence is the point. It named the demo host as the place
to look, so TheHub#343 was filed against the demo container's build stamp and two
further days went into that container — while the object that disproves the
sentence sat in the build's own working directory, two bytes longer than the SHA
it was compared against.

So these tests do not assert on the wording. They run the script, with `mc` stubbed
to produce each of the two states, and assert that the job's own output tells them
apart: an acknowledgement that exists and names another commit is a different
failure, needing a different action, from no acknowledgement at all.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

PIPELINES = Path(__file__).resolve().parents[2] / "deploy" / "concourse" / "pipelines"

REQUESTED = "a284852f75cc7cd1bb403321e65bf1b7174455f8"
OTHER = "4385e6a2c6030860b2fcf0f92874975d6f4b7e6b"


def deploy_script(job_name: str) -> str:
    """The wait-for-acknowledgement task body, from the pipeline itself.

    Located by what it does rather than by an index, the way `test_thehub_gate`
    finds the oracle-gate body: a step added ahead of it should not silently
    move this test onto a different script.
    """
    document = yaml.safe_load((PIPELINES / "thehub.yml").read_text(encoding="utf-8"))
    for job in document["jobs"]:
        if job["name"] != job_name:
            continue
        for step in job.get("plan", []):
            run = (step.get("config") or {}).get("run") or {}
            if run.get("path") == "bash" and "RELEASE_BUCKET" in str(run.get("args")):
                return run["args"][-1]
    raise AssertionError(f"no MinIO deploy-pointer task in job {job_name}")


# The script's first lines install `mc` and talk to a real MinIO. Every command
# that reaches outside the working directory is replaced by a shell function,
# which bash resolves ahead of anything on PATH. `mc` is the only interesting
# one: it decides which of the two states the test is exercising.
PRELUDE = """
set +e
apt-get()   { return 0; }
sha256sum() { return 0; }
chmod()     { return 0; }
curl()      { return 0; }
git()       { printf '%s\\n' "$WANT_SHA"; }
mc() {
  for a in "$@"; do
    case "$a" in
      *.deployed)
        if [ "$ACK" = "none" ]; then return 1; fi
        # Written the way the PowerShell poller writes it, CR and all.
        printf '%s\\r\\n' "$ACK" > deployed
        return 0
        ;;
    esac
  done
  return 0
}
export -f apt-get sha256sum chmod curl git mc 2>/dev/null || true
"""


def run_deploy_task(script: str, tmp_path: Path, ack: str, env_name: str):
    """Run the task body to its deadline, with the acknowledgement in `ack`.

    DEPLOY_TIMEOUT_MINUTES=0 puts the deadline in the past, so the wait loop
    reaches its timeout branch on the first pass instead of after 25 minutes.
    """
    bash = shutil.which("bash")
    if not bash:
        pytest.skip("bash is not available in this environment")
    return subprocess.run(
        [bash, "-c", PRELUDE + script],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        timeout=120,
        env={
            "PATH": "/usr/bin:/bin:/usr/local/bin",
            "WANT_SHA": REQUESTED,
            "ACK": ack,
            "ENVIRONMENT": env_name,
            "RELEASE_BUCKET": "thehub-releases",
            "DEPLOY_TIMEOUT_MINUTES": "0",
            "MINIO_ENDPOINT": "http://127.0.0.1:9000",
            "MINIO_ACCESS_KEY": "k",
            "MINIO_SECRET_KEY": "s",
            "TARGET_URL": "http://127.0.0.1:8002/health",
            "MC_RELEASE": "unused",
            "MC_SHA256": "unused",
        },
    )


@pytest.mark.parametrize(
    ("job_name", "env_name"), [("deploy-demo", "demo"), ("deploy-prod", "prod")]
)
class TestTheTimeoutSaysWhatItRead:
    def test_the_script_is_valid_shell(self, job_name: str, env_name: str) -> None:
        result = subprocess.run(
            ["bash", "-n"], input=deploy_script(job_name), text=True, capture_output=True
        )
        assert result.returncode == 0, result.stderr

    def test_an_acknowledgement_for_another_commit_is_reported_as_such(
        self, job_name: str, env_name: str, tmp_path: Path
    ) -> None:
        """The state that cost five days: the host is acknowledging, just not
        this commit. The job holds the object and must quote it."""
        result = run_deploy_task(deploy_script(job_name), tmp_path, OTHER, env_name)
        out = result.stdout + result.stderr

        assert result.returncode != 0, out
        assert OTHER in out, (
            "the timeout did not report the acknowledgement it had already "
            f"fetched; it said only:\n{out}"
        )
        assert "not running" not in out, (
            "the timeout claimed the poller is not running while holding an "
            f"acknowledgement the poller wrote:\n{out}"
        )

    def test_no_acknowledgement_at_all_is_a_different_report(
        self, job_name: str, env_name: str, tmp_path: Path
    ) -> None:
        """And the opposite state still points at the scheduled task — the two
        need different actions, so one message for both is one too few."""
        result = run_deploy_task(deploy_script(job_name), tmp_path, "none", env_name)
        out = result.stdout + result.stderr

        assert result.returncode != 0, out
        assert "TheHub Registry Pull Deploy" in out, out
        assert OTHER not in out

    def test_the_comparison_still_tolerates_line_endings(
        self, job_name: str, env_name: str, tmp_path: Path
    ) -> None:
        """Guard for #388. The stub writes the acknowledgement with CRLF, as the
        PowerShell poller does; a comparison that reads it raw matches nothing,
        and this job would then time out on a deploy that had succeeded."""
        result = run_deploy_task(deploy_script(job_name), tmp_path, REQUESTED, env_name)
        out = result.stdout + result.stderr

        assert f"Host reports {env_name} at {REQUESTED}" in out, out
