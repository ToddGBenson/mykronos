# A Concourse worker on a Linux host

TheHub #61659, decision D-181. The estate's CI is one web node and two
workers in Docker on the Windows host (`../docker-compose.yml`). The workers
share the Docker VM with production and have run it out of memory. A worker
on a Linux box takes compute steps off that VM. It registers to the same web
node over the TSA, Concourse's SSH endpoint on port 2222, with a key pair of
its own and a tag so that only steps which name the tag land on it.

## What you run

Three steps, one script each, in this order.

1. **Windows, from `deploy\concourse`, in an elevated prompt:**

   ```powershell
   .\Add-LinuxWorker.ps1 -LinuxIp <the Linux box's LAN address> -WhatIf
   .\Add-LinuxWorker.ps1 -LinuxIp <the Linux box's LAN address>
   ```

   In this order: it first makes sure a firewall block rule denies 2222 to
   every LAN address but the Linux box (an existing block rule that already
   does that, such as `Mykronos app ports - deny the LAN` once it lists 2222
   and excludes the box, is reused; otherwise it adds its own). Then it
   generates the worker key pair straight into `bundles\linux-1-bundle\`,
   copies only the `.pub` to `keys\linux-1_key.pub` and lists it in
   `authorized_worker_keys`, writes `CONCOURSE_TSA_BIND_IP` to `.env`,
   recreates the web node so it publishes 2222 on this host's LAN address,
   and finishes the bundle. Un-elevated it stops before the first change and
   prints the command to run elevated; `-IUnderstandLanExposure` overrides
   that and leaves 2222 open to the whole LAN (key-gated) until the rule
   exists. It is safe to re-run from any partial state.

2. **Copy the bundle, run the installer on the Linux box, delete the bundle:**

   ```powershell
   scp -r .\bundles\linux-1-bundle user@<linux-ip>:~/
   ssh user@<linux-ip> 'sudo bash ~/linux-1-bundle/install-concourse-worker.sh'
   Remove-Item -Recurse .\bundles\linux-1-bundle    # it holds the worker's private key
   ```

   The bundle is the only copy of the private key on Windows: `keys\` is
   mounted into the web node and both compose workers, so the key never goes
   there. After the `scp`, delete the bundle (and `~/linux-1-bundle` on the
   Linux box once the installer has run; it copies the key to
   `/etc/concourse/worker_key`).

   The installer downloads Concourse 8.3.3 (about 950 MB, pinned by sha256),
   installs it under `/usr/local/concourse`, writes `/etc/concourse/`, and
   starts `concourse-worker.service`. It waits for the worker's own health
   endpoint and prints the last log lines if that fails.

3. **Verify, on Windows:**

   ```powershell
   fly -t mykronos workers
   ```

   The new worker is listed by name with tag `linux` and state `running`.

## What the worker can and cannot run

Only steps that say `tags: [linux]` run on it, and it runs nothing else:
a tagged worker is outside the default placement. Resource checks, `get`
and `put` steps and every untagged task keep running on the Windows
workers, and Concourse streams inputs and outputs between workers.

The pipelines reach SILO, the registry and the MyKronos backend through
Docker Desktop's host gateway address, which exists only inside the Windows
Docker VM, and those ports are published on loopback there. A task on the
Linux worker therefore cannot upload a result, push an image or call the
backend. It can run anything whose only network is the public internet:
test suites, static analysers, builds that leave their output in an output
directory for an untagged step to upload. Routing steps to the worker is a
pipeline change with its own review (see D-181); this directory only adds
the worker.

The tasks routed here are listed in `REMOTE_COMPUTE` in
`backend/tests/test_concourse_worker_tags.py` (TheHub #61659), which also
checks each one is compute only: no credential, no host address, no
pipeline var but the non-secret ones it lists, no registry read or push, a
public image, not privileged. The result leaves in an output, and a task on
this host checks it and uploads it.

**A tagged step never falls back to an untagged worker.** While no `linux`
worker is registered, a tagged step waits for one. A task's own `timeout:`
does not cover that wait (in 8.3.3 it starts only once a worker is chosen),
so each routed task sits in a `do:` or `try:` whose `timeout:` bounds the
wait too, and the test checks it. An offline remote host then costs one of
two things:

- the scans and long suites (mykronos `sast`, `dependencies`, `coverage`,
  `time-travel`; thehub's `pr-gates`, `post-merge`, `container-tiers`) ask
  for a remote worker first and ERROR within 5m when none answers, so
  nothing behind them is judged until it is back (operator decision
  2026-11-16);
- mykronos's gating lanes `unit` and `frontend` (TheHub #61951) prefer a
  remote worker and run on this host when none finishes them, so an offline
  laptop costs a slower build, never a stopped risk gate. This host runs
  the lane when no worker was up (the probe times out), when the run hit
  its cap (the SIGTERM leaves no `ran/rc`), when setup failed on the laptop
  (`ran/rc` is written only after it), and when the worker was lost
  mid-run (`linux-finished` errors reading its outputs, and its `on_error`
  runs the copy; read from the Concourse 8.3.3 source, not yet seen on a
  real build). A worker that drops after the probe makes the remote task
  wait out its cap first. See "The gating lanes" in
  `deploy/concourse/pipelines/mykronos.yml`.

Still on this host: mykronos `lint-and-types`, `qa-spec-links`, `secrets`,
`ai` and `iac` (the next slice of #61951), and the jobs that need this
host's Docker engine, registry or MyKronos API: `build`, `publish-*`,
`promote`, `demo-and-dast`, `oracle-gate`. `fly workers` shows whether a
`linux` worker is registered; a build's `selected-worker` events name the
worker each step ran on.

## Where things are on the Linux box

| What | Where |
|---|---|
| Binaries | `/usr/local/concourse` -> `/usr/local/concourse-8.3.3` |
| Config and keys | `/etc/concourse/worker.env`, `worker_key` (0600), `tsa_host_key.pub` |
| Builds and volumes | `/opt/concourse/worker` |
| Unit | `/etc/systemd/system/concourse-worker.service` |
| Logs | `journalctl -u concourse-worker -f` |
| Health | `curl http://127.0.0.1:8888/` |
| Release cache | `/var/cache/concourse/` |

Task containers resolve names through 8.8.8.8 and 1.1.1.1, in that order, the same
resolvers the compose workers hand theirs (a host on systemd-resolved would
otherwise give them 127.0.0.53, which a container cannot reach). Change
them with `--dns <a,b>` or `DNS_SERVERS=` in `worker.conf`, or edit
`CONCOURSE_CONTAINERD_DNS_SERVER` in `/etc/concourse/worker.env` and restart
the unit; a re-run of the installer keeps the value it finds there.
8.8.8.8 comes first because on this LAN UDP/53 to 1.1.1.1 timed out from one
Linux box (2026-11-16) while 8.8.8.8 and the router answered: a first
resolver that times out makes every lookup wait before trying the second. A
worker installed before that keeps `1.1.1.1,8.8.8.8` until its
`worker.env` is edited.

The unit stops the worker with SIGUSR2 and `KillMode=mixed`: the signal
retires the worker (the web node forgets it), and only the worker process
gets it, not containerd or the task processes.

`sudo bash install-concourse-worker.sh --uninstall` stops the unit and
removes the install and the config. The work dir is kept unless
`--remove-work-dir` is given too. `--help` lists the flags; `--runtime
guardian` is there for a kernel that containerd's runtime refuses.

## Running the worker in Docker instead of the installer

The installer is the supported path. A worker can also run as the
`concourse/concourse` image under Docker on the Linux box (linux-1 and
linux-2 did, from 2026-11-14). Three things the installer gets right by
construction then have to be set by hand, and all three fail quietly. The
first and third are handled by `cgroup-wrapper.sh` beside this README: mount
it read-only and set `entrypoint: ["dumb-init", "/cgroup-wrapper.sh"]`.

Rollout, as of 2026-11-18: no worker mounts this file yet. linux-3 mounts a
hand-kept copy, `~/concourse-worker/cgroup-wrapper.sh` on its host, whose
commands match this file up to 2026-11-18 (the stale-state clear was added
there by hand that day). linux-1 and linux-2 run their own hand-kept copies
with the cgroup delegation only, so they are not yet protected from the
stale-state loop below. Each host's compose file has to mount this file in
place of its copy.

- **cgroup v2 delegation.** The image's entrypoint moves only PID 1 out of
  the container's root cgroup. The root keeps processes, so it cannot hand
  `cpu`/`memory` to `garden/`, and every job container fails with
  `openat2 /sys/fs/cgroup/garden/<id>/cpu.weight: no such file or directory`.
  Wrap the entrypoint so it moves every process into a child cgroup and
  enables all controllers on the root before running the image's
  `entrypoint.sh`. Keep the cgroup namespace private (not `cgroup: host`),
  so the container's `mem_limit`/`cpus` still bound its jobs.
- **DNS for task containers.** Inside a Docker container `/etc/resolv.conf`
  names Docker's embedded resolver, 127.0.0.11, which answers only on that
  container's loopback. The containerd runtime hands task containers the
  worker's own address instead, and nothing answers there: every `get`
  fails, and git reports it as `fatal: Could not read from remote
  repository`, which looks like a key or port problem. Set either
  `CONCOURSE_CONTAINERD_DNS_SERVER` (explicit resolvers, as the installer
  and `../docker-compose.yml` do) or
  `CONCOURSE_CONTAINERD_DNS_PROXY_ENABLE=true` (the worker answers on its
  address and forwards to Docker's resolver). linux-1 and linux-2 use the
  proxy since 2026-11-16.
- **Stale containerd state across a restart.** In the container `/run` is
  the writable layer, not a tmpfs, so `/run/containerd` survives a container
  restart and a host reboot. The tasks it records died with the previous
  start; containerd tries to restore them and never listens, garden exits on
  `dial unix /run/containerd/containerd.sock: connect: connection refused`,
  and the worker restart-loops without ever running a job (linux-3: 1775
  restarts in 30 h after an abrupt shutdown, 2026-11-16/17). The wrapper
  removes `/run/containerd` before the image's entrypoint runs (or empties
  it, if something is mounted exactly there), and leaves it alone if a
  containerd is already running, so running it by hand in a live worker
  deletes nothing. Without it, `docker compose up -d --force-recreate`
  recovers a looping worker once.

To check a worker, enter a running job container's network namespace from
inside the worker (`nsenter -t <pid> -n`, the pid from
`/sys/fs/cgroup/garden/<id>/cgroup.procs`) and send a DNS query to the
`nameserver` in `/worker-state/networkmounts/<id>/resolv.conf`.

## Why the Windows side looks like it does

- 2222 is published as `${CONCOURSE_TSA_BIND_IP:-127.0.0.1}:2222:2222`:
  loopback until `.env` names the LAN address, and Docker Desktop honours
  a LAN-address bind (measured 2026-11-13: a throwaway publish on the
  host's LAN address answered there and was refused on 127.0.0.1).
- The firewall rule comes before the `.env` line, so no run of the script
  publishes 2222 to an unscoped LAN unless told to.
- The firewall rule is a block, not an allow, because `Docker Desktop
  Backend` already allows every port from every address and block beats
  allow. The rule denies the on-link LAN prefix (this host's address and
  prefix length) in two ranges with the Linux box's address as the gap
  between them. An address routed in from another subnet is outside that
  prefix and is not denied; on a flat home LAN there is none.
- The TSA is an SSH server that admits only the keys in
  `authorized_worker_keys`, so the port is key-gated behind the firewall.
- `setup.ps1` now assembles `authorized_worker_keys` from every `*_key.pub`
  but the TSA host key and the session signing key, so re-running it keeps
  the Linux worker's key.
