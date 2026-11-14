## D-180 — Pipelines address the registry through a worker-visible variable; a remote worker joins by tag and public key; Vault-reading jobs stay on local workers

**2026-11-14.** **Status:** Decided, partly implemented (TheHub #61659)
**Story:** TheHub #61659

**The decision.** A Linux runner host joins Concourse as a third worker. It
registers with the existing web node's TSA and is tagged `linux`.

- **Addressing.** Pipelines name no host address. The image registry is
  `((registry))`, the worker-visible registry variable, and every other host
  service also comes through a var. The committed value stays the Docker
  Desktop gateway, so the local workers and the rendered pipelines are
  unchanged. A test holds the pipelines free of literal host-only addresses.
  The registry publishes on `${REGISTRY_BIND:-127.0.0.1}`. It is loopback by
  default, and the firewall rule that admits the one runner host is the LAN
  lock (D-178).
- **Joining.** A remote worker joins by tag and public key. It has its own
  key pair, and the operator appends the public half as one line to
  `keys/authorized_worker_keys` and SIGHUPs the web node. PR #1167 carries
  the TSA publish and the scripts on both sides.
- **Placement.** Jobs that read Vault stay on local workers. Workers never
  contact Vault, because the web node resolves credentials. A credential's
  value still lands in the task container, so it lands on whichever machine
  runs the step. A job may carry `tags: [linux]` only when its plan and its
  resources use no Vault-resolved var and no host address except the
  registry's. The candidate list is derived and checked
  (`deploy/concourse/REMOTE-WORKER.md`). In this change nothing is tagged.

**Why.** The two local workers share a Docker VM with production and cannot
grow (D-174, TheHub #61607). The CPU-heavy, credential-free work, mainly the
kaniko image builds, can run elsewhere. Using a tag means the new worker
takes nothing until a job opts in, so the worker can be proven idle first.
Keeping credentialed jobs local keeps every Vault secret on the host it was
issued to. The few jobs that qualify are the ones that benefit most.

**Not yet decided.** The address a tagged job uses for the registry. One
option is a second var that only tagged jobs use, held in Vault so the LAN
address never enters this public repository (recommended). The other is
moving `((registry))` itself to the LAN address once it is measured to work
from a local worker. The second PR, which tags the first job, makes that
choice.

**Rollout.** The operator sets `REGISTRY_BIND=0.0.0.0` in
`deploy/concourse/.env` after the firewall rule is in place, then recreates
`registry` in a lane-free window. Tagging the first job comes after that.
