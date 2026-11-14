## D-178 — The estate APIs stay loopback-bound by default; the firewall rule, not the binding, is the LAN lock

**2026-11-14.** **Status:** Decided, implemented (TheHub #61659)
**Story:** TheHub #61659

**The decision (operator, 2026-11-14).** The estate APIs stay loopback-bound by
default. A host may bind them to all interfaces only when its firewall admits a
single named runner host. The firewall rule, not the binding, is the LAN lock.

**What changes.** The published ports in `deploy/mykronos/docker-compose.yml`
(backend 8100, frontend 3100) and the Concourse web port 8080 in
`deploy/concourse/docker-compose.yml` take their bind address from
`${MYKRONOS_BIND:-127.0.0.1}` and `${CONCOURSE_BIND:-127.0.0.1}`. The committed
default is unchanged. The TSA, workers, database and every other service are
untouched, and 2222 is not published.

**Why.** A Linux runner host is being added to run CI workers and builders, and
it must reach the backend and Concourse web over the network. A hard-coded
`127.0.0.1` publish cannot be reached from another machine, so the binding has
to be a host choice. Making the committed default permissive would expose every
checkout, so the default stays loopback and a host opts in. Binding wide is
safe only because the host firewall limits those ports to the one runner;
relying on the bind address alone was never a LAN lock either, since a firewall
rule is what actually decides who connects.

**Rollout.** Takes effect when the containers are next recreated (MyKronos
deploy; Concourse web restart in a lane-free window).
