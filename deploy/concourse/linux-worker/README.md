# A Concourse worker on a Linux host

TheHub #61659, decision D-178. The estate's CI is one web node and two
workers in Docker on the Windows host (`../docker-compose.yml`). The workers
share the Docker VM with production and have run it out of memory. A worker
on a Linux box takes compute steps off that VM. It registers to the same web
node over the TSA, Concourse's SSH endpoint on port 2222, with a key pair of
its own and a tag so that only steps which name the tag land on it.

## What you run

Three steps, one script each, in this order.

1. **Windows, from `deploy\concourse`:**

   ```powershell
   .\Add-LinuxWorker.ps1 -LinuxIp <the Linux box's LAN address>
   ```

   It generates `keys\linux-1_key`, lists its `.pub` in
   `authorized_worker_keys`, writes `CONCOURSE_TSA_BIND_IP` to `.env`,
   recreates the web node so it publishes 2222 on this host's LAN address,
   adds a firewall rule that denies 2222 to every LAN address but the Linux
   box, and writes `keys\linux-1-bundle\`. The firewall rule needs an
   elevated prompt; without one the script does everything else and prints
   the elevated command to run. `-WhatIf` shows the plan first.

2. **Copy the bundle and run the installer on the Linux box:**

   ```powershell
   scp -r .\keys\linux-1-bundle user@<linux-ip>:~/
   ssh user@<linux-ip> 'sudo bash ~/linux-1-bundle/install-concourse-worker.sh'
   Remove-Item -Recurse .\keys\linux-1-bundle    # it holds the worker's private key
   ```

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
pipeline change with its own review (see D-178); this directory only adds
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

`sudo bash install-concourse-worker.sh --uninstall` stops the unit (SIGUSR2
retires the worker, so the web node forgets it) and removes the install,
the config and the work dir. `--help` lists the flags; `--runtime guardian`
is there for a kernel that containerd's runtime refuses.

## Why the Windows side looks like it does

- 2222 is published as `${CONCOURSE_TSA_BIND_IP:-127.0.0.1}:2222:2222`:
  loopback until `.env` names the LAN address, and Docker Desktop honours
  a LAN-address bind (measured 2026-11-13: a throwaway publish on
  192.168.0.14 answered there and refused on 127.0.0.1).
- The firewall rule is a block, not an allow, because `Docker Desktop
  Backend` already allows every port from every address and block beats
  allow. The rule denies the LAN prefix in two ranges with the Linux box's
  address as the gap between them.
- The TSA is an SSH server that admits only the keys in
  `authorized_worker_keys`, so the port is key-gated behind the firewall.
- `setup.ps1` now assembles `authorized_worker_keys` from every `*_key.pub`
  but the TSA host key, so re-running it keeps the Linux worker's key.
