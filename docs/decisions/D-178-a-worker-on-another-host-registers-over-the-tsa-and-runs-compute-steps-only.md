## D-178 — A worker on another host registers over the TSA on the LAN address and runs compute steps only

**2026-11-13.** **Status:** Decided; the worker joins the pool, routing is a
follow-up
**Story:** TheHub #61659 · Refs D-174, TheHub #61607 (worker tags), TheHub #60841 (loopback publishes)

**The problem.** Both Concourse workers run in the Docker VM on the Windows
host beside production. At 3 GiB each they have SIGKILLed each other's unit
lanes (TheHub #61607), and on the night of 2026-11-13 the host's free memory
fell to 815 MB with three builders and a reviewer running tests. The Windows
host is the velocity limit. The operator has a Linux box on the LAN.

**The decision.**

1. **A Linux worker registers to the existing web node over the TSA.** The
   TSA is Concourse's SSH endpoint on 2222; a worker needs only that one port,
   because the web node reaches the worker's garden and baggageclaim back
   through the same SSH connection. The worker carries its own key pair,
   generated with the same `generate-key` as the compose workers', and its
   `.pub` is listed in `authorized_worker_keys`. `setup.ps1` now assembles
   that file from every `*_key.pub` but the TSA host key, so a re-run keeps
   the new worker instead of silently dropping it.
2. **2222 is published on the LAN address, scoped by a block rule.** The
   compose header promises "nothing is published to 0.0.0.0", and it still
   holds: the publish is `${CONCOURSE_TSA_BIND_IP:-127.0.0.1}:2222:2222`,
   loopback until `.env` names the LAN address. Measured 2026-11-13 on this
   host: Docker Desktop honours a LAN-address bind (a throwaway publish on
   192.168.0.14 answered 200 there and refused on 127.0.0.1). Because the
   `Docker Desktop Backend` firewall rule allows every port from every
   address, the scope is a block rule on 2222 for the LAN prefix in two
   ranges with the Linux box's address as the gap, the same block-beats-allow
   reasoning as `Set-AppPortScope.ps1`. Behind it the TSA admits listed keys
   only.
3. **The worker is tagged (`linux`) and runs compute steps only.** A tagged
   worker takes only steps that name its tag, so adding it changes no
   placement until a pipeline says `tags: [linux]`. And it cannot take every
   step: since TheHub #60841 the pipelines reach SILO, the registry and the
   MyKronos backend through Docker Desktop's host gateway, 192.168.65.254,
   which exists only inside the Windows Docker VM, and those ports are
   published on loopback there. From the Linux box that address is
   unroutable and the ports are closed. So a task that uploads a result,
   pushes an image or posts a check run stays on a Windows worker; a task
   whose only network is the public internet (pytest, semgrep, a build that
   leaves its output in an output directory) can move. Resource checks,
   `get` and `put` steps stay untagged on worker-1 and Concourse streams the
   volumes.
4. **One script per side, bundled.** `Add-LinuxWorker.ps1` does the four
   Windows changes and writes `keys\<name>-bundle\` (private key, TSA host
   `.pub`, `worker.conf`, the install script); the operator copies it with
   `scp` and runs `install-concourse-worker.sh` as root. The installer pins
   8.3.3 by sha256 (the compose workers' version; the web node is being moved
   to it by the same recreate), installs a systemd unit that retires the
   worker on stop (`KillSignal=SIGUSR2`, so a reboot leaves no stalled
   entry), uses containerd (Concourse 8's default on bare Linux) with
   explicit public resolvers like the compose workers, and binds its
   healthcheck to loopback.

**What is not decided here.** Which steps say `tags: [linux]`.
`backend/tests/test_concourse_worker_tags.py` models placement per job
(every task of a heavy job carries its pipeline's tag set) and that model
has no room for a worker that may take some of a job's tasks and not others.
Routing is its own story: a per-task placement model, the list of compute
tasks that qualify under point 3, their memory budgets measured on the Linux
box, and the TheHub pipeline mirror re-exported (TheHub #61639). Until then
the Linux worker idles in the pool, which costs nothing.

**Why not alternatives.**

- *Move the `thehub` tag to the Linux box.* TheHub's tagged tasks include
  the check-run reporter and the gates, which call MyKronos through the host
  gateway; they would fail from the Linux box (point 3).
- *Publish SILO, the registry and the backend on the LAN too.* That undoes
  TheHub #60841 for every LAN device to make three services reachable from
  one; a VPN or an SSH tunnel for those is a later decision if the compute
  steps turn out not to be the bottleneck.
- *The official worker container with `--privileged` instead of the tarball.*
  The container needs Docker on the Linux box and nests the runtime one
  level deeper; the tarball is what Concourse documents for a Linux worker
  and runs under systemd with cgroup delegation.
- *Allow rule for the Linux box instead of a block.* Already allowed: the
  Docker Desktop rule admits everything. Only a block narrows it.
