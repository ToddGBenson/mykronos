#!/bin/sh
# Entrypoint wrapper for a Concourse worker run as the concourse/concourse
# image under Docker (README: "Running the worker in Docker instead of the
# installer"). Mount it read-only and run it in place of the image's own:
#
#   entrypoint: ["dumb-init", "/cgroup-wrapper.sh"]
#   volumes:    ["./cgroup-wrapper.sh:/cgroup-wrapper.sh:ro"]
#
# It does two things before handing over to the image's entrypoint.sh, and
# says on stderr when either cannot be done rather than exiting silently.
set -eu

warn() { echo "cgroup-wrapper: $*" >&2; }

# 1. cgroup v2 delegation (TheHub #61894). The image's entrypoint moves only
#    PID 1 out of the container's root cgroup. A root that still holds
#    processes cannot hand cpu/memory to garden/, and every job container then
#    fails with ".../garden/<id>/cpu.weight: no such file or directory". Move
#    every process into a child cgroup, then enable every controller.
if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
  mkdir -p /sys/fs/cgroup/init
  for i in 1 2 3 4 5; do
    for p in $(cat /sys/fs/cgroup/cgroup.procs); do
      echo "$p" > /sys/fs/cgroup/init/cgroup.procs 2>/dev/null || true
    done
    [ -z "$(cat /sys/fs/cgroup/cgroup.procs)" ] && break
  done
  if [ -n "$(cat /sys/fs/cgroup/cgroup.procs)" ]; then
    warn "the root cgroup still holds pids $(tr '\n' ' ' < /sys/fs/cgroup/cgroup.procs)after 5 passes;" \
      "enabling controllers will fail and job containers will get no cpu/memory"
  fi
  controllers="$(cat /sys/fs/cgroup/cgroup.controllers)"
  if [ -z "$controllers" ]; then
    warn "cgroup.controllers is empty: nothing to delegate (is the cgroup namespace private?)"
  else
    echo "$controllers" | sed -e 's/ / +/g' -e 's/^/+/' > /sys/fs/cgroup/cgroup.subtree_control
    echo "cgroup-wrapper: subtree_control = $(cat /sys/fs/cgroup/cgroup.subtree_control)"
  fi
fi

# 2. Stale containerd state (TheHub #62024). /run here is the container's
#    writable layer, not a tmpfs, so it outlives a container restart and a
#    host reboot. Every task it describes died with the previous start, but
#    containerd tries to restore them and never starts listening; garden then
#    exits on "dial unix /run/containerd/containerd.sock: connect: connection
#    refused" and the worker restart-loops (linux-3: 1775 restarts in 30 h
#    after an abrupt shutdown, 2026-11-16/17).
#    Only at container start: a containerd already running means this was run
#    by hand in a live worker, where the state is real.
running_containerd() {
  for c in /proc/[0-9]*/comm; do
    [ "$(cat "$c" 2>/dev/null)" = containerd ] && return 0
  done
  return 1
}
if running_containerd; then
  warn "containerd is running: not clearing /run/containerd (run me only as the entrypoint)"
elif grep -qs ' /run/containerd ' /proc/self/mounts; then
  # A mountpoint cannot be removed (EBUSY); empty it instead.
  find /run/containerd -mindepth 1 -maxdepth 1 -exec rm -rf {} + \
    || warn "could not empty the /run/containerd mount; containerd may not start"
  echo "cgroup-wrapper: emptied /run/containerd (a mountpoint)"
else
  rm -rf /run/containerd || warn "could not remove /run/containerd; containerd may not start"
  echo "cgroup-wrapper: cleared /run/containerd"
fi

exec /usr/local/bin/entrypoint.sh "$@"
