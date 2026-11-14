# A remote Concourse worker (D-180, TheHub #61659)

## Purpose

The two workers in `docker-compose.yml` share one Docker Desktop VM with
TheHub's production backend. They are capped at 3g each and cannot grow
(see the `mem_limit` comment there). A Linux box on the LAN (a named runner
host, 8 CPU, 15 GiB) can take heavy, credential-free work off that VM by
running a third worker that registers with the existing web node. The worker
is tagged `linux`. A tagged worker runs only steps that name its tag, so the
worker changes nothing until a job is tagged. Tagging is a second PR, made
after the worker has been proven with `fly workers`.

This file explains how a task reaches host services today, what a remote
worker needs, which jobs can move to it, and how the worker joins and leaves.

## How a task reaches the host today

- Garden task containers resolve names through `1.1.1.1` and `8.8.8.8`
  (`CONCOURSE_GARDEN_DNS_SERVER`). They cannot resolve Docker service names
  like `minio` or `registry`, or `host.docker.internal`. The worker
  container's `extra_hosts` entry is visible only to the worker process,
  not to tasks.
- So every host service is addressed by IP, through a pipeline var:
  `((registry))`, `((minio-endpoint))`, `((mykronos-url))`,
  `((thehub-url))` and the `thehub-*-url` vars. Their committed values
  (`vars/*.yml`, written by `set-*-pipeline.ps1`) all name
  `192.168.65.254`. That is Docker Desktop's host gateway, and it lands on
  the Windows host's loopback. This is why 5000, 9000, 8100 and the TheHub
  ports can publish on `127.0.0.1` and stay off the LAN (TheHub #60841;
  measured on 2026-10-18 from a worker's network namespace).
- The pipeline YAML itself names no host address.
  `test_remote_worker.py::test_no_pipeline_hard_codes_a_host_only_address`
  enforces this. `fly get-pipeline` (and TheHub's mirror export) shows the
  interpolated value because `fly set-pipeline --load-vars-from`
  interpolates on the client side.
- Vault is never contacted by a worker. The web node resolves every
  credential `((var))` from Vault (`CONCOURSE_VAULT_URL: http://vault:8200`
  on the compose network) and hands the value to the task. "A job that
  reads Vault" therefore means a job whose plan or resources use a var that
  is not in `vars/<pipeline>.yml`. Its value is shipped into a container on
  whichever worker runs the step.

## What a remote worker changes

The `192.168.65.254` gateway does not exist on another machine. A remote
worker reaches the host only on the host's LAN address, and only on ports
that are published beyond loopback and admitted by the firewall.

| port | service | needed by a remote worker | default bind |
|---|---|---|---|
| 2222 | TSA (web node) | yes, to register | `${CONCOURSE_TSA_BIND_IP:-127.0.0.1}` (PR #1167; unpublished on main until it merges) |
| 5000 | registry | yes, for jobs that pull or push images | `${REGISTRY_BIND:-127.0.0.1}` (this PR) |
| 8080 | Concourse web | no. The worker's garden and baggageclaim are forwarded back over the TSA's SSH connection, so the web node needs no inbound port on the worker. | `${CONCOURSE_BIND:-127.0.0.1}` (#1166) |
| 9000 | MinIO (SILO) | no, for the jobs listed below (none uses `((minio-endpoint))`) | `127.0.0.1`, unchanged |
| 8200 | Vault | no. Workers never contact Vault, and Vault-reading jobs stay local. | `127.0.0.1`, unchanged |

Every default stays on loopback, so this change opens nothing by itself. The
firewall rule that admits only the named runner host is the LAN lock
(D-178). The operator runs it, and it is out of scope here. The registry has
no `auth:` block, so never set `REGISTRY_BIND` to `0.0.0.0` without that
rule. The TSA authenticates by key, but it should not face the whole LAN
either.

### The registry address a remote job sees

`((registry))` is the worker-visible registry variable. Every image pull,
kaniko push, crane tag and trivy scan of the local registry goes through
it. Its committed value stays `192.168.65.254:5000`, so the rendered
pipelines and the local workers are unchanged. A pipeline var has one value
for every worker, though, and the remote worker cannot reach that one.
Before the second PR tags a job, choose one of these:

1. **A second var, only in tagged jobs (recommended).** Tagged steps use
   something like `((remote-registry))`, the host's LAN address and port
   5000, held in Vault at `concourse/main/remote-registry` so the LAN
   address never enters this public repository. Local jobs keep
   `((registry))` exactly as today. Both names point at the same registry,
   so an image one job pushes is the image the other pulls.
2. **One value for both.** Set `registry` to the host's LAN address. This
   works only if a local worker's task can reach the LAN address once 5000
   binds wide. That held before #60841 (D-109's kaniko pushed to the LAN
   address), but it has not been measured since. The change also moves
   every rendered thehub pipeline line and would commit the LAN address, so
   the value would have to move out of `vars/` as well.

MinIO does not need an `((artifact-host))` for this list, because no
candidate job uses `((minio-endpoint))`. A job that does use it reads MinIO
credentials from Vault, which keeps it local anyway.

## Which jobs can go remote

A job is a candidate when its plan and the resources it gets or puts use no
Vault-resolved var and no host address except `((registry))`. Nothing is
tagged in this PR. `test_remote_worker.py` derives the list below from the
pipelines and fails if this table drifts from it. It also fails if a
`linux`-tagged step ever belongs to a job outside the list.

<!-- remote-candidates:begin -->
| pipeline | job | why it can go | note |
|---|---|---|---|
| `mykronos` | `set-pipeline` | gets `pipelines` and `source` (public, no key); `set_pipeline` itself runs on the web node | little to gain: it is light |
| `mykronos` | `promote` | crane retag on `((registry))` | needs the registry address decided above |
| `mykronos` | `publish-backend` | kaniko build and push to `((registry))` | the best candidate: CPU-heavy, no credential |
| `mykronos` | `publish-frontend` | kaniko build and push to `((registry))` | the best candidate: CPU-heavy, no credential |
| `mykronos` | `image-refresh` | rebuilds and trivy-compares estate images on `((registry))` | heavy; nightly |
| `personal-soc` | `set-pipeline` | as mykronos's | light |
| `personal-soc` | `doc-drift` | reads the checkout only | light |
<!-- remote-candidates:end -->

Everything else stays on the local workers. Why, by pipeline:

- **mykronos**: every scanning and test lane (`pin-check`, `unit`,
  `coverage`, `bench`, `lint-and-types`, `qa-spec-links`, `frontend`,
  `secrets`, `ai`, `sast`, `insider`, `iac`, `oracle-gate`, `containers`,
  `remediate`, `demo-and-dast`) uploads to `((mykronos-url))` with the
  Vault-held `mykronos-ingestion-token` and `mykronos-gate-token`.
  `dependencies` and `build` use the MinIO credentials. `time-travel`
  files to `((thehub-url))` with `hub-story-token`.
- **thehub**: no job qualifies. Every job gets `source` with the Vault-held
  `source-deploy-key` and reports to `((thehub-url))` with
  `hub-deploy-token`. Most also upload with `thehub-ingestion-token`, and the
  DAST, cloud and model lanes add their own credentials. The heavy jobs stay
  on worker-2 (`tags: [thehub]`, TheHub #61607).
- **personal-soc**: every lane except `doc-drift` and `set-pipeline`
  uploads with `personal-soc-ingestion-token`. `package` and the
  `netassess-*` jobs use the MinIO credentials. `skill-integrity` reads
  `anthropic-api-key`.

A job is placed by tagging every step in its plan (gets and tasks), so that
the step outputs stay on one worker. The second PR must also teach
`test_concourse_worker_tags.py` that `linux` is a worker tag. That worker is
not in this compose file.

## Joining

PR #1167 automates these steps. `Add-LinuxWorker.ps1` handles the Windows
side and `linux-worker/install-concourse-worker.sh` (systemd, containerd)
handles the runner host, and its README is authoritative once it merges.
The manual steps below are the same mechanism done by hand. Use them to
understand what those scripts do, or to run the worker under compose instead.

### On the runner host

1. Generate the worker's key pair. `generate-key -t ssh` is the same command
   `setup.ps1` uses for `worker_key`. It writes an RSA private key in PEM
   form and an OpenSSH public key beside it:

   ```sh
   mkdir -p keys
   docker run --rm -v "$PWD/keys:/keys" concourse/concourse:8.3.3 \
     generate-key -t ssh -f /keys/worker_key
   ```

   The private key never leaves this machine.
2. Copy the web node's **public** TSA key, `deploy/concourse/keys/tsa_host_key.pub`,
   from the Windows host into `keys/`. The worker pins it, which is how it
   knows it reached the real TSA.
3. Write `docker-compose.yml`. Pin the same image digest as the web node,
   because web and workers move together:

   ```yaml
   name: concourse-remote-worker
   services:
     worker:
       image: concourse/concourse:8.3.3@sha256:5d3a30f336b063b9ed0bb2b963044b5782dc06d8efd1161e85202d60de26e923
       command: worker
       privileged: true
       restart: unless-stopped
       cpus: 6            # of 8: leave the host room to stay reachable
       mem_limit: 6g      # of 15 GiB; a runaway backstop, as on the host
       memswap_limit: 6g
       environment:
         CONCOURSE_NAME: linux-1
         CONCOURSE_TAG: linux
         CONCOURSE_TSA_HOST: <host-lan-address>:2222
         CONCOURSE_TSA_PUBLIC_KEY: /keys/tsa_host_key.pub
         CONCOURSE_TSA_WORKER_PRIVATE_KEY: /keys/worker_key
         CONCOURSE_WORK_DIR: /worker-state
         CONCOURSE_BAGGAGECLAIM_DRIVER: overlay
         # containerd, not guardian: a plain Linux host has no reason to
         # carry the guardian workaround, and containerd takes its DNS from
         # CONCOURSE_CONTAINERD_DNS_* (the CONCOURSE_GARDEN_* names are ignored).
         CONCOURSE_RUNTIME: containerd
         CONCOURSE_CONTAINERD_DNS_SERVER: "1.1.1.1,8.8.8.8"
         CONCOURSE_LOG_LEVEL: info
       volumes:
         - ./keys:/keys:ro
         - worker-state:/worker-state
   volumes:
     worker-state:
   ```

   Do not start it yet.

### On the Windows host (operator)

1. Append the worker's **public** key (`keys/worker_key.pub` from the
   runner host) as one line to `deploy/concourse/keys/authorized_worker_keys`.
   Do not replace the file: worker-1's and worker-2's lines must stay.
2. Make the web node read the file again. Concourse 8.3.3 reloads
   `authorized_worker_keys` on **SIGHUP** and at no other time. It does not
   watch the file or poll it. This was read in the v8.3.3 source
   (`tsa/tsacmd/command.go`: a goroutine on `syscall.SIGHUP` calls
   `AuthorizedKeys.Reload()` and rebuilds the SSH server config). This
   change did not exercise it. PR #1167 reports the live web node logging
   `tsa.reloading-config` on the signal. The image's entrypoint is
   `dumb-init`, which forwards the signal:

   ```powershell
   docker kill --signal=HUP mykronos-concourse
   docker logs --since 1m mykronos-concourse 2>&1 | Select-String 'reloading-config'
   ```

   If no `reloading-config` line appears, restart the web node in a
   lane-free window instead. A restart keeps every session, because the
   session signing key is pinned.
3. The two one-time steps that open the ports:
   - In `deploy/concourse/.env`, set `REGISTRY_BIND=0.0.0.0` (this
     change) and the TSA bind (`CONCOURSE_TSA_BIND_IP`, PR #1167). Do this
     only after the firewall rule that admits the runner host alone is in
     place. `setup.ps1 -Rotate` rewrites `.env` without these lines, which
     falls back to loopback (fails safe), so re-add them after a rotate.
   - In a lane-free window (no running builds; `fly -t mykronos builds`),
     recreate the two services so they pick up the binds:
     `docker compose up -d concourse registry` from `deploy/concourse`.
     Neither depends on Vault, so Vault is not recreated and stays unsealed.
     The registry serves its own image, so it restarts only from the local
     Docker store. If that image was pruned, follow the boot steps in the
     registry's comment in `docker-compose.yml`.

### Start and verify

On the runner host, run `docker compose up -d`. Then, from the host:

```powershell
fly -t mykronos workers
```

`linux-1` should be listed `running`, with tag `linux` and platform
`linux`. A worker that stays absent or shows `stalled` means the key line,
the SIGHUP, the bind or the firewall is wrong. The worker's own log
(`docker logs` on the runner host) names which: a handshake error points at
keys, and a dial timeout points at the bind or the firewall.

Nothing runs on it until the second PR tags a job. That is the point: it
can be watched idle first.

## Leaving

1. Retire it cleanly, so no running build loses its containers:
   `fly -t mykronos land-worker -w linux-1`, then wait until `fly workers`
   no longer lists it.
2. Stop it on the runner host: `docker compose down`.
3. If it was stopped without landing and shows `stalled`, remove it with
   `fly -t mykronos prune-worker -w linux-1`.
4. To revoke it for good, delete its line from `authorized_worker_keys` and
   SIGHUP the web node again. Set the two binds back to `127.0.0.1` and
   recreate `concourse` and `registry` in a lane-free window if no other
   remote worker remains.
5. Any job tagged `linux` hangs with "no workers" while the worker is gone.
   Untag first, or accept the wait.
