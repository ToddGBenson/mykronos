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

Task containers resolve names through 1.1.1.1 and 8.8.8.8, the same
resolvers the compose workers hand theirs (a host on systemd-resolved would
otherwise give them 127.0.0.53, which a container cannot reach). Change
them with `--dns <a,b>` or `DNS_SERVERS=` in `worker.conf`, or edit
`CONCOURSE_CONTAINERD_DNS_SERVER` in `/etc/concourse/worker.env` and restart
the unit; a re-run of the installer keeps the value it finds there.

The unit stops the worker with SIGUSR2 and `KillMode=mixed`: the signal
retires the worker (the web node forgets it), and only the worker process
gets it, not containerd or the task processes.

`sudo bash install-concourse-worker.sh --uninstall` stops the unit and
removes the install and the config. The work dir is kept unless
`--remove-work-dir` is given too. `--help` lists the flags; `--runtime
guardian` is there for a kernel that containerd's runtime refuses.

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
