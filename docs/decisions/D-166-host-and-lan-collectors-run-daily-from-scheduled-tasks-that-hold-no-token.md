## D-166 — The host and LAN collectors run daily from Scheduled Tasks that hold no token

**2026-10-20.** **Status:** Decided, implemented
**Story:** TheHub #60834 (S11b) · follows TheHub #60826 (S4) · Refs D-097, spec 14 §3

**The rule.** Each of the three control-observation collectors runs on a
schedule well inside the 14-day freshness window (`FRESH_DAYS`):

- `internet` is the backend's `exposure` job, every 6 hours. It was already
  scheduled, and a test now pins it.
- `host` is `Publish-ControlObservations.ps1`, run daily at 05:00 by a
  Scheduled Task, one per repository.
- `lan` is `python -m mykronos.lan_scan`, run daily at 05:30 by a Scheduled
  Task. It is registered only when the operator supplies both the ranges and a
  standing authorization reference.

`Register-ControlObservationTasks.ps1` registers the tasks, and each task runs
`Invoke-ControlObservationCollector.ps1`. The task's arguments name the
`backend\.env` key that holds each token (`MYKRONOS_CONCOURSE_TOKEN`,
`MYKRONOS_GATE_TOKEN`) and never its value. The collector reads the values
when it fires and passes them to the collector through its own process
environment.

**Why read `backend\.env` at run time, and not a DPAPI copy like the backup
tasks.** The backup secrets are set once and never rotate. An ingestion token
rotates, and `repair-ingestion-token.ps1` delivers the new value to its
readers. For mykronos and TheHub, one of those readers is `backend\.env`. A
copy kept anywhere else would be a reader the repair script does not know
about. That is D-097 again: the copy would work until 24 hours after the next
rotation, when the overlap window ends, and then the task would 401 every day
while the lowerings lapsed. Reading the key the rotation already writes leaves
nothing to forget. The file is plaintext readable by the operator's account,
which was already true. The task adds no new copy.

**Why daily.** The window is 14 days. Daily keeps every lowering live through
thirteen consecutive missed runs: a week away with the machine off, or Docker
Desktop down. What the host publishes changes on a deploy or a tunnel edit,
not by the hour. The LAN scan is `nmap -sV --top-ports 1000` against named
`/32` hosts, which is light enough to run daily.

**Why LogonType Interactive.** The host collector reads Docker Desktop, which
runs only while the operator is logged on, so a task that could run while they
are logged off would collect `unknown`. Interactive needs no stored Windows
password. StartWhenAvailable runs a missed day at the next logon.

**Why the LAN task needs an explicit range and authorization.** Spec 14 §3:
no scan without an authorization reference, and no default range. Scheduling a
scan makes the authorization a standing one. So the operator writes it once,
it is visible in the task, and `lan_scan` records it in the audit log on every
run.

**Not chosen.**
- A Concourse `time` job for the host collector. It would run in a container
  behind Docker Desktop's NAT, which sees neither the host's firewall nor its
  LAN segment (`lan_scan.py`, `publish-netassess-run.ps1`).
- Passing tokens as task arguments: they would be readable in Task Scheduler
  and in the process list.
- An in-app "observations stopped arriving" warning. It is follow-up work.
  Today a lapse shows as `stale: last observed N days ago` on the environmental
  view.
