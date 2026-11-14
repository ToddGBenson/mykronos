#!/usr/bin/env bash
# Install a Concourse worker on a Linux host and register it to the MyKronos
# web node on the Windows host (TheHub #61659, D-181).
#
# One script, run once as root on the Linux box, from the bundle that
# deploy/concourse/Add-LinuxWorker.ps1 wrote on the Windows side:
#
#     sudo bash ./install-concourse-worker.sh
#
# The bundle directory beside this script holds `worker.conf` (the TSA host,
# the worker's name and tag), `worker_key` (this worker's private key, whose
# .pub the web node already lists) and `tsa_host_key.pub` (the web node's
# host key, so the worker refuses an impostor TSA). Nothing here is read from
# the network except the release tarball, and that is pinned by sha256.
#
# What it does, in order, each step idempotent:
#   1. checks root, architecture, distribution and kernel;
#   2. installs ca-certificates, curl and iptables (CNI's firewall plugin
#      shells out to iptables);
#   3. downloads concourse-$CONCOURSE_VERSION-linux-$ARCH.tgz into /var/cache/concourse
#      (resumable) and verifies its sha256 against the value pinned below;
#   4. unpacks it to /usr/local/concourse-$CONCOURSE_VERSION and points
#      /usr/local/concourse at it;
#   5. writes /etc/concourse/{worker.env,worker_key,tsa_host_key.pub};
#   6. installs and starts concourse-worker.service, then waits for the
#      worker's own healthcheck on 127.0.0.1:8888.
#
# Verify from the Windows host:  fly -t mykronos workers   (the worker is
# listed by name with its tag, state `running`).
#
# Flags override worker.conf, which overrides the defaults:
#   --tsa-host IP:2222     the Windows host's LAN address and the TSA port
#   --name NAME            worker name as fly shows it (default: hostname)
#   --tag TAG              placement tag; steps that say `tags: [TAG]` run here
#                          and nothing else does (default: linux)
#   --work-dir DIR         builds and volumes (default /opt/concourse/worker)
#   --keys-dir DIR         where worker_key and tsa_host_key.pub are
#                          (default: beside this script)
#   --tarball PATH         an already-downloaded release tarball (still verified)
#   --runtime NAME         containerd (Concourse 8's default) or guardian
#   --memory-max SIZE      systemd MemoryMax for the whole worker, e.g. 6G
#   --dns A,B              resolvers handed to task containers (default
#                          1.1.1.1,8.8.8.8, or what /etc/concourse/worker.env
#                          already names on a re-run)
#   --no-systemd           install everything but the unit; print the
#                          foreground command instead
#   --foreground           --no-systemd, then run the worker in this shell
#                          (how the script is tested in a container)
#   --uninstall            stop and remove the unit, the install and the
#                          config; the work dir is kept
#   --remove-work-dir      with --uninstall, also delete the work dir (and
#                          every build cache and volume in it)
set -euo pipefail

CONCOURSE_VERSION="8.3.3"
# sha256 of the GitHub release assets, v8.3.3 (2026-11-03). The amd64 value was
# computed from the downloaded file on 2026-11-13 and matched GitHub's digest
# and the release's .sha1 sidecar; arm64 is GitHub's digest for that asset.
SHA256_amd64="6b7699a3d3d1066b15011833dfb2712af5ca94b1f49090d035596f1c5fa82ba8"
SHA256_arm64="fa459cf89446559cdb12e9b4f7bd191f5138ce50dbc25b349e48c7f7077258c5"
RELEASES="https://github.com/concourse/concourse/releases/download"
# Task containers get these resolvers, as the compose workers do: on a host
# running systemd-resolved they would otherwise inherit 127.0.0.53, which is
# unreachable from inside a container.
DEFAULT_DNS="1.1.1.1,8.8.8.8"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF_DIR="/etc/concourse"
UNIT="/etc/systemd/system/concourse-worker.service"
CACHE_DIR="/var/cache/concourse"
HEALTH_PORT="8888"

# Defaults, then worker.conf, then flags.
TSA_HOST=""
WORKER_NAME="$(hostname -s 2>/dev/null || hostname)"
TAG="linux"
WORK_DIR="/opt/concourse/worker"
KEYS_DIR="$SCRIPT_DIR"
TARBALL=""
RUNTIME="containerd"
MEMORY_MAX=""
DNS_SERVERS=""
MODE="systemd"
UNINSTALL="no"
REMOVE_WORK_DIR="no"

say()  { printf '\n==> %s\n' "$*"; }
fail() { printf 'error: %s\n' "$*" >&2; exit 1; }

read_conf() {
    # KEY=VALUE lines; `tr -d '\r'` because the bundle may be written on Windows.
    local conf="$SCRIPT_DIR/worker.conf" line key value
    [ -f "$conf" ] || return 0
    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%%#*}"; line="$(printf '%s' "$line" | tr -d '\r' | sed 's/[[:space:]]*$//')"
        [ -z "$line" ] && continue
        key="${line%%=*}"; value="${line#*=}"
        case "$key" in
            TSA_HOST)    TSA_HOST="$value" ;;
            WORKER_NAME) WORKER_NAME="$value" ;;
            TAG)         TAG="$value" ;;
            WORK_DIR)    WORK_DIR="$value" ;;
            RUNTIME)     RUNTIME="$value" ;;
            MEMORY_MAX)  MEMORY_MAX="$value" ;;
            DNS_SERVERS) DNS_SERVERS="$value" ;;
            *) fail "worker.conf: unknown key '$key'" ;;
        esac
    done < "$conf"
}

read_conf
while [ $# -gt 0 ]; do
    case "$1" in
        --tsa-host)   TSA_HOST="$2"; shift 2 ;;
        --name)       WORKER_NAME="$2"; shift 2 ;;
        --tag)        TAG="$2"; shift 2 ;;
        --work-dir)   WORK_DIR="$2"; shift 2 ;;
        --keys-dir)   KEYS_DIR="$2"; shift 2 ;;
        --tarball)    TARBALL="$2"; shift 2 ;;
        --runtime)    RUNTIME="$2"; shift 2 ;;
        --memory-max) MEMORY_MAX="$2"; shift 2 ;;
        --dns)        DNS_SERVERS="$2"; shift 2 ;;
        --no-systemd) MODE="none"; shift ;;
        --foreground) MODE="foreground"; shift ;;
        --uninstall)  UNINSTALL="yes"; shift ;;
        --remove-work-dir) REMOVE_WORK_DIR="yes"; shift ;;
        -h|--help)    sed -n '2,52p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) fail "unknown argument '$1' (see --help)" ;;
    esac
done

[ "$(id -u)" -eq 0 ] || fail "run as root: the worker orchestrates containers (sudo bash $0)"

if [ "$UNINSTALL" = "yes" ]; then
    say "Uninstalling the Concourse worker"
    if command -v systemctl >/dev/null 2>&1 && [ -f "$UNIT" ]; then
        # SIGUSR2 (the unit's KillSignal) retires the worker: it tells the web
        # node to forget it, so `fly workers` does not keep a stalled entry.
        systemctl disable --now concourse-worker.service || true
        rm -f "$UNIT"; systemctl daemon-reload
    fi
    rm -rf /usr/local/concourse "/usr/local/concourse-$CONCOURSE_VERSION" "$CONF_DIR"
    if [ "$REMOVE_WORK_DIR" = "yes" ]; then
        rm -rf "$WORK_DIR"
        echo "removed the unit, /usr/local/concourse*, $CONF_DIR and $WORK_DIR; $CACHE_DIR kept"
    else
        echo "removed the unit, /usr/local/concourse* and $CONF_DIR; $WORK_DIR and $CACHE_DIR kept (--remove-work-dir deletes the work dir)"
    fi
    exit 0
fi

# ── 1. host checks ────────────────────────────────────────────────────────
say "Checking this host"
case "$(uname -m)" in
    x86_64)  ARCH="amd64"; WANT="$SHA256_amd64" ;;
    aarch64) ARCH="arm64"; WANT="$SHA256_arm64" ;;
    *) fail "unsupported architecture $(uname -m); Concourse ships linux amd64 and arm64" ;;
esac
# Read in a subshell: os-release defines CONCOURSE_VERSION, ID and NAME, and sourcing it
# here once overwrote this script's CONCOURSE_VERSION with "24.04.5 LTS (Noble Numbat)"
# (found by the container test on 2026-11-13).
# shellcheck source=/dev/null
OS_ID="$(. /etc/os-release 2>/dev/null && echo "${ID:-}")"
# shellcheck source=/dev/null
OS_NAME="$(. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-}")"
case "$OS_ID" in
    ubuntu|debian) ;;
    *) echo "warning: ${OS_NAME:-unknown distribution}; Concourse tests Ubuntu 22.04/24.04, apt is assumed" ;;
esac
KERNEL="$(uname -r | cut -d. -f1,2)"
if [ "$(printf '%s\n5.15\n' "$KERNEL" | sort -V | head -1)" != "5.15" ]; then
    echo "warning: kernel $KERNEL is older than the 5.15 Concourse tests against"
fi
[ -n "$TSA_HOST" ] || fail "no TSA host: pass --tsa-host <windows-lan-ip>:2222 or put TSA_HOST=... in worker.conf"
[[ "$TSA_HOST" == *:* ]] || TSA_HOST="$TSA_HOST:2222"
[[ "$WORKER_NAME" =~ ^[a-z0-9][a-z0-9-]*$ ]] || fail "worker name '$WORKER_NAME' must be lowercase letters, digits and hyphens"
[[ "$TAG" =~ ^[a-z0-9][a-z0-9,-]*$ ]] || fail "tag '$TAG' must be lowercase letters, digits, hyphens (comma-separated for several)"
case "$RUNTIME" in containerd|guardian) ;; *) fail "runtime must be containerd or guardian" ;; esac
if [ -z "$DNS_SERVERS" ] && [ -f "$CONF_DIR/worker.env" ]; then
    # A re-run keeps resolvers the operator set by hand in worker.env.
    DNS_SERVERS="$(sed -n 's/^CONCOURSE_\(CONTAINERD\|GARDEN\)_DNS_SERVER=//p' "$CONF_DIR/worker.env" | head -1)"
fi
DNS_SERVERS="${DNS_SERVERS:-$DEFAULT_DNS}"
[[ "$DNS_SERVERS" =~ ^[0-9a-fA-F.:]+(,[0-9a-fA-F.:]+)*$ ]] || fail "--dns '$DNS_SERVERS' must be comma-separated IP addresses"
# A bundle copied again after the Windows side deleted its private key (as
# the README says to) has no worker_key; the one already installed is reused.
[ -f "$KEYS_DIR/worker_key" ] || [ -f "$CONF_DIR/worker_key" ] || fail "$KEYS_DIR/worker_key missing: copy the whole bundle Add-LinuxWorker.ps1 wrote"
[ -f "$KEYS_DIR/tsa_host_key.pub" ] || fail "$KEYS_DIR/tsa_host_key.pub missing: copy the whole bundle Add-LinuxWorker.ps1 wrote"
echo "arch $ARCH, ${OS_NAME:-linux}, kernel $(uname -r); worker '$WORKER_NAME' tag '$TAG' -> TSA $TSA_HOST"

# ── 2. packages ───────────────────────────────────────────────────────────
say "Installing ca-certificates, curl and iptables"
if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends ca-certificates curl iptables >/dev/null
else
    for bin in curl iptables; do command -v "$bin" >/dev/null 2>&1 || fail "$bin is not installed and this is not an apt system"; done
fi

# ── 3 and 4. the release, pinned, unpacked ────────────────────────────────
# A box that already has this version installed fetches and hashes nothing:
# a re-run must not pull a gigabyte to confirm what is on disk.
INSTALL_DIR="/usr/local/concourse-$CONCOURSE_VERSION"
if [ -x "$INSTALL_DIR/bin/concourse" ]; then
    say "Concourse $CONCOURSE_VERSION is already installed in $INSTALL_DIR"
else
    say "Fetching Concourse $CONCOURSE_VERSION for linux/$ARCH"
    mkdir -p "$CACHE_DIR"
    ASSET="concourse-$CONCOURSE_VERSION-linux-$ARCH.tgz"
    if [ -n "$TARBALL" ]; then
        [ -f "$TARBALL" ] || fail "--tarball $TARBALL does not exist"
    else
        TARBALL="$CACHE_DIR/$ASSET"
        if [ ! -f "$TARBALL" ] || ! sha256sum -c --status <<<"$WANT  $TARBALL"; then
            # About 950 MB; -C - resumes a partial file from an earlier attempt.
            curl -fL --retry 3 -C - -o "$TARBALL" "$RELEASES/v$CONCOURSE_VERSION/$ASSET"
        fi
    fi
    GOT="$(sha256sum "$TARBALL" | cut -d' ' -f1)"
    [ "$GOT" = "$WANT" ] || fail "sha256 mismatch for $TARBALL: got $GOT, pinned $WANT (delete it and re-run, or check the release)"
    echo "sha256 verified: $GOT"

    say "Installing to $INSTALL_DIR"
    rm -rf "$INSTALL_DIR.partial"
    mkdir -p "$INSTALL_DIR.partial"
    tar -xzf "$TARBALL" -C "$INSTALL_DIR.partial" --strip-components=1
    rm -rf "$INSTALL_DIR.partial/fly-assets"
    mv "$INSTALL_DIR.partial" "$INSTALL_DIR"
fi
ln -sfn "$INSTALL_DIR" /usr/local/concourse
/usr/local/concourse/bin/concourse --version 2>/dev/null || echo "concourse $CONCOURSE_VERSION"

# ── 5. configuration ──────────────────────────────────────────────────────
say "Writing $CONF_DIR"
install -d -m 0700 "$CONF_DIR"
if [ -f "$KEYS_DIR/worker_key" ]; then
    install -m 0600 "$KEYS_DIR/worker_key" "$CONF_DIR/worker_key"
else
    echo "no worker_key in the bundle; keeping the installed $CONF_DIR/worker_key"
fi
install -m 0644 "$KEYS_DIR/tsa_host_key.pub" "$CONF_DIR/tsa_host_key.pub"
mkdir -p "$WORK_DIR"
# The overlay volume driver below needs a real filesystem under the work dir.
# On overlayfs or tmpfs every task fails with "failed to create volume" and
# nothing names the cause (seen in the container test, 2026-11-13).
WORK_FS="$(stat -f -c %T "$WORK_DIR")"
case "$WORK_FS" in
    overlayfs|tmpfs|fuseblk|9p|virtiofs|fuse*)
        fail "$WORK_DIR is on $WORK_FS; Concourse's overlay volumes need ext4 or xfs there - pass --work-dir <a directory on a local disk>" ;;
esac
# The same shape as the two workers in deploy/concourse/docker-compose.yml:
# explicit resolvers for task containers ($DNS_SERVERS, see DEFAULT_DNS),
# overlay volumes, a modest sweeper, and the healthcheck on loopback rather
# than every interface.
{
    echo "CONCOURSE_NAME=$WORKER_NAME"
    echo "CONCOURSE_TAG=$TAG"
    echo "CONCOURSE_WORK_DIR=$WORK_DIR"
    echo "CONCOURSE_TSA_HOST=$TSA_HOST"
    echo "CONCOURSE_TSA_PUBLIC_KEY=$CONF_DIR/tsa_host_key.pub"
    echo "CONCOURSE_TSA_WORKER_PRIVATE_KEY=$CONF_DIR/worker_key"
    echo "CONCOURSE_RUNTIME=$RUNTIME"
    if [ "$RUNTIME" = "containerd" ]; then
        echo "CONCOURSE_CONTAINERD_DNS_SERVER=$DNS_SERVERS"
    else
        echo "CONCOURSE_GARDEN_DNS_SERVER=$DNS_SERVERS"
    fi
    echo "CONCOURSE_BAGGAGECLAIM_DRIVER=overlay"
    echo "CONCOURSE_BAGGAGECLAIM_VOLUME_SWEEPER_MAX_IN_FLIGHT=5"
    echo "CONCOURSE_HEALTHCHECK_BIND_IP=127.0.0.1"
    echo "CONCOURSE_HEALTHCHECK_BIND_PORT=$HEALTH_PORT"
    echo "CONCOURSE_LOG_LEVEL=info"
} > "$CONF_DIR/worker.env"
chmod 0600 "$CONF_DIR/worker.env"
echo "worker.env written (no secrets in it; the private key is $CONF_DIR/worker_key, mode 0600)"

# ── 6. systemd ────────────────────────────────────────────────────────────
if [ "$MODE" != "systemd" ]; then
    say "Skipping systemd ($MODE)"
    echo "foreground command:"
    echo "  set -a; . $CONF_DIR/worker.env; set +a; exec /usr/local/concourse/bin/concourse worker"
    if [ "$MODE" = "foreground" ]; then
        set -a
        # shellcheck source=/dev/null
        . "$CONF_DIR/worker.env"
        set +a
        export PATH="/usr/local/concourse/bin:$PATH"
        exec /usr/local/concourse/bin/concourse worker
    fi
    exit 0
fi

say "Installing concourse-worker.service"
command -v systemctl >/dev/null 2>&1 || fail "no systemctl; re-run with --no-systemd and supervise the printed command yourself"
{
    echo "[Unit]"
    echo "Description=Concourse worker '$WORKER_NAME' (tag $TAG) for the MyKronos web node at $TSA_HOST"
    echo "Documentation=https://concourse-ci.org/docs/install/running-worker/"
    echo "After=network-online.target"
    echo "Wants=network-online.target"
    echo ""
    echo "[Service]"
    echo "Type=simple"
    echo "EnvironmentFile=$CONF_DIR/worker.env"
    echo "Environment=PATH=/usr/local/concourse/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    echo "ExecStart=/usr/local/concourse/bin/concourse worker"
    echo "# SIGUSR2 retires the worker: it finishes nothing new, tells the web node"
    echo "# to forget it, and exits - so a stop or a reboot leaves no stalled entry."
    echo "KillSignal=SIGUSR2"
    echo "# mixed: SIGUSR2 goes to the worker process alone. The default"
    echo "# (control-group) would send it to containerd and every task process"
    echo "# too, whose default action on SIGUSR2 is to terminate."
    echo "KillMode=mixed"
    echo "TimeoutStopSec=300"
    echo "Restart=on-failure"
    echo "RestartSec=10"
    echo "# The worker manages its own cgroup subtree for task containers."
    echo "Delegate=yes"
    echo "TasksMax=infinity"
    echo "LimitNOFILE=1048576"
    if [ -n "$MEMORY_MAX" ]; then
        echo "# The whole worker, tasks included: a cap here protects the host, not a task."
        echo "MemoryMax=$MEMORY_MAX"
    fi
    echo ""
    echo "[Install]"
    echo "WantedBy=multi-user.target"
} > "$UNIT"
systemctl daemon-reload
systemctl enable --now concourse-worker.service
systemctl restart concourse-worker.service

say "Waiting for the worker to report healthy on 127.0.0.1:$HEALTH_PORT"
for _ in $(seq 1 30); do
    if curl -fsS "http://127.0.0.1:$HEALTH_PORT/" >/dev/null 2>&1; then
        echo "healthy"
        break
    fi
    sleep 2
done
if ! curl -fsS "http://127.0.0.1:$HEALTH_PORT/" >/dev/null 2>&1; then
    echo "not healthy after 60 s; the last log lines:"
    journalctl -u concourse-worker.service --no-pager -n 30 || true
    fail "the worker did not come up - the usual causes: $TSA_HOST unreachable (firewall or port not published on the Windows side), or this worker's .pub missing from authorized_worker_keys there"
fi

say "Done"
echo "Verify from the Windows host:   fly -t mykronos workers      ('$WORKER_NAME' with tag '$TAG', state running)"
echo "Logs here:                      journalctl -u concourse-worker -f"
echo "Remove:                         sudo bash $0 --uninstall"
