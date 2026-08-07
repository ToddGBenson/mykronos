# Spec 14 — Network Scanning

**Status:** Approved for build
**Depends on:** [04 — Scanner Workflows](04-scanner-workflows.md), [05 — Data Lake](05-datalake.md), [12 — Security](12-security-and-secrets-management.md)

---

## 1. Purpose

Add an eleventh capability: **active scanning of networks the operator owns**
— host discovery, exposed services, TLS posture, and templated vulnerability
checks against what is found.

Every capability in specs 04–09 examines a *codebase*. This one examines
*running infrastructure*, which makes it the first capability that is not
scoped to a repository and the first that cannot run on a GitHub-hosted
runner. Both consequences are load-bearing and are dealt with in §4 and §5.

The motivation is completeness of posture: a repo can pass every SAST, SCA
and IaC check and still deploy onto a host with an exposed admin port and an
expired certificate. Mykronos claims to be the control plane for security
posture; posture that stops at the repo boundary is a partial claim.

## 2. Scope (v1)

| Function | Description | Default tool |
|---|---|---|
| **Host discovery** | Which addresses in an authorised range are alive | `nmap -sn` |
| **Port & service detection** | Open TCP/UDP ports, service names, version banners | `nmap -sV` |
| **TLS posture** | Protocol versions, cipher suites, certificate expiry and chain validity on discovered TLS services | `sslyze` |
| **Templated vulnerability checks** | Known-CVE and misconfiguration probes against discovered services | `nuclei` |

Explicitly **out of scope for v1**: credentialed/authenticated host scanning,
agent-based endpoint inventory, exploitation of any kind, wireless scanning,
and anything that writes to a scanned host. v1 observes; it does not touch.

Deep authenticated vulnerability scanning (Greenbone/OpenVAS) is a plausible
v2 addition. It is excluded here because it needs credential management per
host, which is a larger design problem than the rest of this spec combined.

## 3. Authorization model

Active network scanning is dual-use. Scanning infrastructure you own is
ordinary security practice; the same tool pointed elsewhere is not. The
authorization boundary is therefore enforced in code, not documented as an
expectation.

1. **Explicit ranges only.** A network scan target is a list of CIDR blocks
   declared in `CapabilityConfig`. There is no discovery outside declared
   ranges, no "scan whatever the host can reach", and no default range. An
   empty config scans nothing and is not an error.
2. **Ranges are validated before every run**, not only at save time — config
   could have been edited between scheduling and execution.
3. **Non-private ranges require explicit acknowledgement.** A CIDR outside
   RFC1918 / RFC4193 / loopback is rejected unless the config also carries
   `external_scan_acknowledged: true` and a non-empty
   `authorization_reference`. This is a deliberate speed bump against the
   most likely serious mistake: a typo'd CIDR aimed at the public internet.
4. **`authorization_reference` is mandatory and free-text** — a ticket, a
   change record, a note naming who authorised the scan and when. It is
   stored on every `NetworkScanTarget` row and every resulting finding's
   provenance. Standard practice for authorised testing, and the field an
   auditor will ask for.
5. **Every run is audited** (spec 12 §7) with the operator identity, the
   resolved CIDR list, the tool set, and the authorization reference.
6. **Intensity is bounded.** Scans run at a configurable rate ceiling with a
   default well below tool maximums. A security tool that knocks a device
   over has caused an incident, not prevented one.

## 4. Where it runs

**Not in GitHub Actions.** A GitHub-hosted runner sits in Microsoft's cloud
and cannot see `192.168.0.0/16`. This is not a limitation to work around; it
is a fact that determines the execution model.

Network scans are therefore **orchestrated by the Mykronos backend directly**:
a scheduled job runs the scanner in a local container, on a host inside the
network being scanned, and writes results through the normal Ingestion API.

This makes network scanning the first capability with a second execution
model, and it is worth being precise about why that is acceptable rather than
a crack in the architecture:

- The **ingestion contract is unchanged** (spec 05 §4). The lake, Oracle, the
  dashboard and the Knowledge Store cannot tell where a finding was produced,
  and must not care. That seam is exactly what makes a second execution model
  cheap.
- The **repo-based model stays the default** for all ten existing
  capabilities. This is not a migration; it is one capability using the
  execution path its subject requires.
- Self-hosted GitHub Actions runners were considered and rejected. They would
  work, but wiring a LAN scanner to a *public* repo's workflow means a fork
  pull request can execute code on a host inside the network being scanned.
  That is a worse security posture than the problem being solved.

### Container isolation (spec 12)

The scanner runs in a throwaway container per scan with: no host filesystem
mounts beyond its output directory, a non-root user, dropped capabilities
except `NET_RAW` and `NET_ADMIN` where the scanner genuinely requires them, a
hard timeout, and egress restricted to the declared CIDR ranges plus the
Ingestion API. The container is destroyed after each run.

## 5. Data model — the scope problem

Every finding today carries a mandatory `repo_full_name` (spec 05 §3). A host
on a network has no repository. This is the first real strain on that model
and it has to be resolved deliberately rather than by convention.

### Decision: generalise the subject to an **Asset**

A repository is an asset. A network segment is an asset. `Finding` gains:

| Field | Type | Notes |
|---|---|---|
| `asset_type` | enum | `repo`, `network` |
| `asset_id` | string | `owner/repo` for repos; the network's declared name (e.g. `home-lab`) for networks |

`repo_full_name` is **retired** in favour of `asset_id`, not kept alongside
it: two columns meaning the same thing is how a data model rots.

Rejected alternative: registering networks as pseudo-repos so that
`repo_full_name` could hold `network/home-lab`. It requires no migration,
which is its only merit. It also means the column that stores your network is
called `repo_full_name` forever, every repo-scoped query silently matches
networks, and the ingestion token scoping in D-009 becomes incoherent.

**Migration timing.** Nothing needs this until the network capability is
actually built. The rename touches the finding schema, compaction, the
ingestion API and the token grant model, and its cost grows with the
codebase — so it is done as the *first* task of whichever phase builds this
capability, not deferred inside it. See `docs/DECISIONS.md` D-011.

### `NetworkAsset`

| Field | Type | Notes |
|---|---|---|
| `asset_id` | string | PK — operator-chosen name, e.g. `home-lab` |
| `cidr_ranges` | list | Authorised ranges. The scan boundary (§3) |
| `authorization_reference` | string | Who authorised this, and where it is recorded |
| `external_scan_acknowledged` | bool | Required for any non-private range |
| `enabled` | bool | |
| `created_at` / `last_scanned_at` | datetime | |

### `NetworkHost` (inventory, one row per discovered host per scan)

| Field | Type | Notes |
|---|---|---|
| `host_id` | string | PK — hash of (asset_id, address) |
| `asset_id` | string | |
| `address` | string | IP |
| `hostname` | string, nullable | Reverse DNS where available |
| `mac_address` / `vendor` | string, nullable | Where the scan is on the same L2 segment |
| `open_ports` | JSON | port → {protocol, service, version} |
| `first_seen_at` / `last_seen_at` | datetime | A host that appears and disappears is itself a signal |

Individual issues — an exposed service, an expired certificate, a Nuclei hit —
are written as ordinary `Finding` rows with `capability = "network"`, so they
appear in the same portfolio views as everything else. `NetworkHost` is the
inventory record; `Finding` rows are the detail, mirroring how Atlas splits
`SscsEvidence` from its findings (spec 07 §3).

### Finding identity for network findings

The fingerprint rule (spec 05 §5) gains a fourth kind:

| Kind | Condition | Fingerprint inputs |
|---|---|---|
| **Network** | `asset_type = network` | `asset_id`, `capability`, `rule_id`, `address`, `port` |

Deliberately keyed on address and port rather than hostname, which is often
absent, and not on the service banner, which changes on every patch and would
churn identity on exactly the events that should instead resolve the finding.

**Known weakness:** on DHCP, a host that changes address becomes a new finding
and the old one ages out as fixed. Mitigating that properly needs stable host
identity (MAC, or a machine ID), which v1 records but does not yet key on.
Documented rather than hidden — for a home or lab network with reservations it
is a minor issue; on a large dynamic network it would need addressing first.

## 6. Configuration (`CapabilityConfig` for `network`)

| Field | Type | Default | Notes |
|---|---|---|---|
| `cidr_ranges` | list | `[]` | Empty scans nothing. There is no default range |
| `authorization_reference` | string | — | **Required.** Non-empty, else the scan refuses to run |
| `external_scan_acknowledged` | bool | `false` | Required `true` for any non-private CIDR |
| `enabled_tools` | list | `["nmap", "sslyze", "nuclei"]` | |
| `schedule_cron` | string | `0 3 * * 0` | Weekly. Active scanning is not a per-commit activity |
| `max_rate_pps` | int | `1000` | Packets/sec ceiling |
| `port_scope` | enum | `top-1000` | `top-100`, `top-1000`, `all` |
| `timeout_minutes` | int | `60` | Hard kill |
| `severity_threshold` | enum | `low` | Shared pattern, spec 04 §5 |
| `blocking` | bool | `false` | Network findings never gate a PR by default — a PR did not cause them |

## 7. Oracle integration

Network findings feed Oracle's **portfolio** decision type (spec 09 §2) but
**not** PR-gate decisions. Blocking a pull request because an unrelated host
on the network has an open port would be incoherent — the PR did not cause it
and merging it does not change it.

This is the first case of a finding that legitimately affects posture without
affecting any specific change, and Oracle's inputs table (spec 09 §4) should
record it as such rather than folding it into the PR-gate weighted sum.

## 8. Acceptance criteria

- A scan of an authorised range produces one `NetworkHost` row per live host
  and `Finding` rows for each issue, all queryable from the lake.
- A CIDR outside the declared ranges is **never** contacted. Asserted by test
  against the range-resolution function, not by inspecting traffic.
- A non-private CIDR without `external_scan_acknowledged` refuses to run and
  says why.
- A missing or empty `authorization_reference` refuses to run.
- Every run appears in the audit log with operator, ranges and authorization
  reference.
- A host that disappears between scans has its findings resolved by the normal
  absence-reconciliation path (spec 05 §5), not deleted.
- Re-scanning an unchanged host produces no new `Finding` rows — only updated
  `last_seen_at`.

## 9. Edge cases

- **Scanner needs raw sockets.** `nmap -sS` requires `NET_RAW`. Where the
  deployment cannot grant it, fall back to TCP connect scanning and record the
  degraded mode on the scan run, rather than silently producing thinner
  results that look like a clean network.
- **A range is unreachable** (VLAN not routed from the scanning host) — record
  `scan_status: partial_failure` with the unreachable ranges named. "Nothing
  found" and "could not look" must not be indistinguishable (spec 04 §6).
- **Scan overlaps its own schedule** on a large range — skip the new run and
  record the skip, rather than stacking concurrent scans that will contend
  for the same rate budget.
- **A device is knocked over by the scan.** Rate limits reduce this risk but
  cannot eliminate it for fragile embedded devices. The per-asset config
  should support an exclusion list of addresses to skip.

## 10. Dependencies

- Spec 05 for the ingestion contract, and for the `asset_id` migration (§5).
- Spec 12 for container isolation and the audit requirement.
- Spec 09 for portfolio-decision integration.
- Spec 10 for a network view in the dashboard — inventory plus findings.
