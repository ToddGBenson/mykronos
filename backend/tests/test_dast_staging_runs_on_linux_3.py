"""dast-staging scans staging on the linux-3 worker, and reports from the host (TheHub #62099).

TheHub staging moved off the host (incident 37414: restarting it there would put
the Docker VM under its 4 GB floor) onto the laptop that runs the `linux-3`
worker, the only worker tagged `small`. The operator's decision: no firewall
change and no LAN listener. So the scan reaches staging over that laptop's
docker bridge, which only a task ON linux-3 can do, and the upload to Mykronos,
which only the host can reach, happens in a separate host task.

What has to hold for that to be safe, and is asserted here:

* `zap-baseline` is tagged `small` and nothing else in the job is: the hooks
  report to the Hub, and `report-dast` uploads to Mykronos, from the host.
* No credential reaches the remote task. Its params are the target and nothing
  else; the ingestion and Hub tokens stay on the host steps.
* `zap-baseline` runs as root (so it can write a report into a root-owned
  output), never privileged.
* The verdict is unchanged: the upload runs only after the scan task, in the
  same `do` chain, so a refusing or failing scan stops the job before anything
  reports, and an empty report is refused by both tasks.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
PIPELINE = ROOT / "deploy" / "concourse" / "pipelines" / "thehub.yml"
VARS = ROOT / "deploy" / "concourse" / "vars" / "thehub.yml"
APPLY = ROOT / "deploy" / "concourse" / "set-thehub-pipeline.ps1"
WORKER = ROOT / "deploy" / "concourse" / "linux-worker"


def _job() -> dict[str, Any]:
    doc = yaml.safe_load(PIPELINE.read_text(encoding="utf-8"))
    return next(j for j in doc["jobs"] if j["name"] == "dast-staging")


def _tasks(steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for step in steps:
        if "task" in step:
            out.append(step)
        for key in ("do", "in_parallel", "aggregate"):
            inner = step.get(key)
            if isinstance(inner, dict):
                inner = inner.get("steps")
            if isinstance(inner, list):
                out.extend(_tasks(inner))
    return out


def _plan_task(name: str) -> dict[str, Any]:
    found = [t for t in _tasks(_job()["plan"]) if t["task"] == name]
    assert len(found) == 1, f"dast-staging has {len(found)} {name!r} tasks, expected 1"
    return found[0]


def test_only_the_scan_runs_on_linux_3() -> None:
    tagged = {t["task"]: t.get("tags") for t in _tasks(_job()["plan"]) if t.get("tags")}
    assert tagged == {"linux-worker-probe": ["small"], "zap-baseline": ["small"]}, (
        "dast-staging's ZAP scan must run on linux-3 (tag `small`, the only worker that "
        f"can reach laptop-hosted staging), and nothing else in the job may: {tagged}"
    )
    for hook in ("on_success", "on_failure", "on_error", "on_abort"):
        hook_text = yaml.safe_dump(_job().get(hook) or {})
        assert "tags" not in hook_text, f"{hook} must report from the host"


def test_the_remote_task_carries_no_credential() -> None:
    zap = _plan_task("zap-baseline")
    assert "params" not in zap, "zap-baseline takes no step-level params"
    params = zap["config"].get("params") or {}
    assert set(params) == {"TARGET_URL"}, (
        f"zap-baseline's params must be the target only: {sorted(params)}"
    )
    text = yaml.safe_dump(zap, width=10_000)
    for needle in ("MYKRONOS_TOKEN", "thehub-ingestion-token", "mykronos-url", "mykronos.upload"):
        assert needle not in text, f"{needle!r} reaches the linux-3 task"


def test_the_scan_runs_as_root_and_never_privileged() -> None:
    zap = _plan_task("zap-baseline")
    assert zap["config"]["run"].get("user") == "root"
    steps = [_job(), *_tasks(_job()["plan"])]
    assert not any("privileged" in step for step in steps), "nothing in dast-staging is privileged"
    outputs = [o["name"] for o in zap["config"].get("outputs") or []]
    assert outputs == ["dast", "ran"], outputs
    script = zap["config"]["run"]["args"][-1]
    assert "chmod -R a+rX dast" in script, "the report must be readable by the host task"


def test_the_host_uploads_after_the_scan_and_refuses_an_empty_report() -> None:
    names = [t["task"] for t in _tasks(_job()["plan"])]
    assert names.index("zap-baseline") < names.index("report-dast"), names
    report = _plan_task("report-dast")
    assert "tags" not in report
    assert {i["name"] for i in report["config"]["inputs"]} == {"source", "dast"}
    script = report["config"]["run"]["args"][-1]
    assert "--capability dast --tool zap-staging" in script
    assert "test -s dast/zap.json" in script, "report-dast must refuse an empty report too"
    assert "attempts" not in report, "a retried upload would retry a refusal away"


def test_the_refusals_stay_in_the_scan() -> None:
    script = _plan_task("zap-baseline")["config"]["run"]["args"][-1]
    for refusal in (
        "Refusing to report an empty scan as clean",
        "ZAP wrote no report",
        "The target is not serving the commit this scan would record",
    ):
        assert refusal in script, f"zap-baseline lost the refusal {refusal!r}"


# -- Review of #1215: a tagged step waits for its worker forever ---------------
#
# A task's own `timeout:` starts only once a worker is chosen, so with linux-3
# off a bare `tags: [small]` step held serial group `dast` -- and dast-prod,
# dast-demo and the rest of the lane -- indefinitely, reporting nothing. Each
# tagged step now sits in a `do:` whose `timeout:` includes that wait, behind
# a short probe, and `linux_absent` on both hooks turns "never ran" into
# errored (nothing judged), never failed and never green.


def _wrappers() -> list[dict[str, Any]]:
    return [s for s in _job()["plan"] if isinstance(s.get("do"), list)]


def _wrapper_of(task: str) -> dict[str, Any]:
    found = [w for w in _wrappers() if any(t.get("task") == task for t in w["do"])]
    assert len(found) == 1, f"{task!r} is not inside exactly one `do:` wrapper"
    return found[0]


def _minutes(value: str) -> int:
    assert value.endswith("m"), value
    return int(value[:-1])


def test_a_probe_asks_for_linux_3_first_and_bounds_the_wait() -> None:
    probe = _wrapper_of("linux-worker-probe")
    assert probe["do"][0].get("tags") == ["small"], "the probe must ask for linux-3"
    assert _minutes(probe["timeout"]) <= 5
    for hook in ("on_failure", "on_error"):
        assert probe[hook]["task"] == "linux-worker-absent", f"the probe has no {hook} linux_absent"
        assert probe[hook].get("input_mapping") == {"ran": "probed"}
    plan = _job()["plan"]
    assert plan.index(probe) < plan.index(_wrapper_of("zap-baseline")), "the probe must come first"


def test_the_scan_waits_inside_a_timed_wrapper() -> None:
    wrapper = _wrapper_of("zap-baseline")
    zap = next(t for t in wrapper["do"] if t.get("task") == "zap-baseline")
    assert _minutes(wrapper["timeout"]) >= _minutes(zap["timeout"]), (
        "the wrapper must outlast the task"
    )
    for hook in ("on_failure", "on_error"):
        assert wrapper[hook]["task"] == "linux-worker-absent", (
            f"the scan's wrapper has no {hook} linux_absent"
        )
    # A scan that RAN keeps its verdict: it writes ran/rc from an EXIT trap,
    # so linux_absent re-labels only a scan that never started.
    assert {"name": "ran"} in zap["config"]["outputs"]
    assert "> ran/rc' EXIT" in zap["config"]["run"]["args"][-1]


def test_report_dast_needs_no_package_install() -> None:
    """Review nit: an apt failure after a finished scan lost the scan."""
    report = _plan_task("report-dast")
    script = report["config"]["run"]["args"][-1]
    assert "apt-get" not in script
    assert report["image"] == "zap", "the job's own zap image ships git and pip"


# -- dast-staging #82-#86: the right worker, this host's address (TheHub #62099) --
#
# Every nightly run from 11-21 to 11-28 ran `zap-baseline` on linux-3 (the
# build's selected-worker events name it) and refused with "not answering".
# The worker was right. The target was not: `((thehub-staging-url))` came from
# vars/thehub.yml, which is this host's view of the estate (the registry,
# Mykronos and TheHub are all reached through this host's Docker gateway), and
# that address does not exist on linux-3. So no address from either copy of
# this host's vars may reach a task on linux-3. The target is staging as a
# linux-3 task reaches it: an address on that laptop, which this public repo
# never holds and Vault does.


def _vars_in(node: object) -> set[str]:
    return set(re.findall(r"\(\(([A-Za-z0-9_.-]+)\)\)", yaml.safe_dump(node, width=10_000)))


def _committed_vars() -> dict[str, Any]:
    loaded: dict[str, Any] = yaml.safe_load(VARS.read_text(encoding="utf-8"))
    return loaded


def test_no_address_from_this_hosts_vars_reaches_linux_3() -> None:
    committed = _committed_vars()
    for task in _tasks(_job()["plan"]):
        if not task.get("tags"):
            continue
        hosts_view = sorted(
            name
            for name in _vars_in(task)
            if name in committed and re.search(r"://|:\d+$", str(committed[name]))
        )
        assert not hosts_view, (
            f"{task['task']} runs on linux-3 but reads {hosts_view} from vars/thehub.yml, "
            "an address as THIS host reaches it; linux-3 cannot route to it (dast-staging #86)"
        )


def test_the_target_is_one_store_var_that_neither_apply_path_writes() -> None:
    target = str(_plan_task("zap-baseline")["config"]["params"]["TARGET_URL"])
    match = re.fullmatch(r"\(\(([a-z0-9-]+)\)\)", target)
    assert match, f"TARGET_URL must be one store var, never a literal address: {target!r}"
    name = match.group(1)
    assert name.endswith("-on-linux-3"), (
        f"{name}: the name must say whose view of staging it is, so nobody fills it "
        "with this host's address again"
    )
    assert name not in _committed_vars(), f"vars/thehub.yml must not carry {name}"
    script = APPLY.read_text(encoding="utf-8")
    assert f'"{name}:' not in script, f"set-thehub-pipeline.ps1 must not write {name}"
    # The old name, which a stale checkout's apply script would still bake in
    # with this host's address, must not be what the scan reads.
    assert "thehub-staging-url" not in _committed_vars()
    assert '"thehub-staging-url:' not in script


def test_the_scan_never_asks_for_the_shared_linux_tag() -> None:
    """GUARD (passes on main too): linux-1 and linux-2 carry `linux`, and so
    does linux-3; only linux-3 carries `small`. A bare `linux` would let the
    scan land on a laptop with no staging stack."""
    for task in ("linux-worker-probe", "zap-baseline"):
        assert _plan_task(task).get("tags") == ["small"], task


def test_an_absent_linux_3_names_linux_3_and_the_store_var() -> None:
    """The default re-run hint says linux-1 or linux-2, which cannot take a
    `small` step: for this job it was the wrong advice."""
    for wrapper in (_wrapper_of("linux-worker-probe"), _wrapper_of("zap-baseline")):
        for hook in ("on_failure", "on_error"):
            when = str(wrapper[hook]["params"].get("LINUX_RERUN_WHEN", ""))
            assert "linux-3" in when and "linux-1" not in when and "linux-2" not in when, when
            assert "thehub-staging-url-on-linux-3" in when, when
            assert "((" not in when, "a hint must name the var, never interpolate it"
    anchors = yaml.safe_load(PIPELINE.read_text(encoding="utf-8"))["anchors"]
    script = anchors["linux_absent"]["config"]["run"]["args"][-1]
    assert "${LINUX_RERUN_WHEN:-fly workers lists linux-1 or linux-2 as running}" in script, (
        "every other job keeps the default hint"
    )


def test_the_reference_worker_compose_can_carry_the_staging_tag() -> None:
    """linux-3 carries `linux,small`. A reference compose that hard-codes
    `linux` would drop `small` the day linux-3 is aligned to it (#62067), and
    the scan would then wait for a worker that no longer exists."""
    compose = yaml.safe_load((WORKER / "docker-compose.yml").read_text(encoding="utf-8"))
    assert compose["x-worker-env"]["CONCOURSE_TAG"] == "${WORKER_TAGS:-linux}"
    example = (WORKER / ".env.example").read_text(encoding="utf-8")
    assert re.search(r"^WORKER_TAGS=linux$", example, re.MULTILINE), example
    assert "small" in example and "linux-3" in example and "dast-staging" in example
