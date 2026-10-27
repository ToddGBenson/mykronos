## D-174 — Concourse workers yield to production; task limits are CPU shares only

**2026-10-26.** **Status:** Decided, awaiting merge, apply and measurement
**Story:** TheHub #61009 (follow-up to TheHub #61001) · Refs D-055, D-172

**The problem.** TheHub's Concourse tasks run on the same Docker VM as
`thehub-backend` (14 CPUs, 11.68 GiB). On 2026-10-23 test load on that VM
starved production's uvicorn workers into a restart storm (71 deaths in two
hours; swap at 52-67%, #36488), and D-172's three lanes allow three heavy task
containers at once. No task in `pipelines/thehub.yml` declared
`container_limits`.

**What was measured, not assumed.** A disposable copy of the workers' own
image, running `gdn` with the live workers' exact flags on the same cgroup v2
VM, gave:

| Task setting | Result |
|---|---|
| `container_limits.cpu: 512` | applied: the task's `cpu.weight` is 59 |
| `container_limits.memory: 2g` | **container creation fails**: "cannot enter cgroupv2 /sys/fs/cgroup/garden with domain controllers -- it is in threaded mode" |

The worker keeps its own processes in its cgroup root, so the memory controller
cannot be delegated below it. A task memory limit therefore fails that task on
every run, and `CONCOURSE_DEFAULT_TASK_MEMORY_LIMIT` (a web-node flag, not a
worker one) would fail every task in every pipeline. The live workers' `garden`
cgroup confirms it: controllers `cpuset cpu pids`, no `memory.max` anywhere.

The CPU weight that does apply is nested inside the worker container, so it
ranks a task only against its sibling tasks and resource checks. It cannot rank
a task against `thehub-backend`, which is a sibling of the worker, not the task.

Both workers had also peaked at their full 6g (worker-2 with two OOM kills),
so CI alone could claim 12 GiB of an 11.68 GiB VM, plus as much swap again.

**The decision.**

- Every task step in `thehub.yml` declares `container_limits: {cpu: 512}`, and
  none declares `memory`.
- Production's precedence is set on the worker containers in
  `docker-compose.yml`: `cpu_shares: 256` (`cpu.weight` 35 against
  production's 100, or 174 with TheHub #539's `cpu_shares: 2048`),
  `oom_score_adj: 500` (inherited by every task process, since garden sets none
  of its own, so the VM's OOM killer takes a test run before a uvicorn worker),
  and `mem_limit`/`memswap_limit` 5g each, so the two workers together stay
  under the VM's memory and add no swap.

CPU weight is work-conserving: on an idle VM CI still gets all six CPUs per
worker. It decides only who waits when CPUs are contended.

**Not chosen.** `CONCOURSE_DEFAULT_TASK_CPU_LIMIT` on the web node: also shares,
so no more reach than the per-task setting, and it would change every other
pipeline. A memory limit per task: see above. Moving the workers to the
containerd runtime, which may delegate memory properly, is its own change (the
compose file records why guardian is stated).

**How it is held.** `backend/tests/test_thehub_task_limits.py` fails when a task
with a `run` lacks `container_limits`, sets CPU shares at or above 1024, or sets
`memory`, and when a worker loses its `cpu_shares`, `oom_score_adj`, swap cap,
or the workers' memory adds up to more than the VM.

**What it does not prove.** The OOM ordering and CPU precedence are read off
the kernel's settings, not observed under load. The acceptance measurement is a
full Concourse `unit` run alongside production with zero uvicorn worker deaths
(`Child process [N] died` in `docker logs thehub-backend`, or TheHub's
`hub_ops/worker_restarts` capability once #539 is deployed). If the lower memory
cap makes the unit tier OOM inside a worker, the lever is `mem_limit` back to
6g; keep `memswap_limit` equal to it and keep `oom_score_adj`.
