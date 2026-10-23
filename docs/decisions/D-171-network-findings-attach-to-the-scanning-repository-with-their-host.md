## D-171 — Network findings attach to the scanning repository, with their host in address and port

**2026-10-21.** **Status:** Decided, implemented
**Story:** TheHub #60813 (option A, decided by Todd 2026-10-21) · Refs D-046, B-062, [spec 14 §5](../../specs/14-network-scanning.md), [spec 05 §5](../../specs/05-datalake.md)

**The problem.** personal-soc's `external-exposure`, `netassess-ingest` and
`netassess-freshness` judged the WAN edge, the LAN and the scan's cadence, went
red on what they found, and uploaded nothing. The findings model keys on a
repository - the token is scoped to one, and `finding_id` is derived from it -
and the NAS, the household's public IP and an open access point are not
repositories.

**The decision (option A).** A network finding is filed against the repository
that scanned for it: ToddGBenson/personal-soc. Which host it is about is the
finding's `address` (host or IP; `wifi:<SSID>` for an access point, which has
no address the scan can see) and `port` where one applies. Both columns already
existed for nmap (spec 14 §5) and are already part of a network finding's
identity, so nothing about fingerprinting changes. `asset_label()` spells them
as one string, and the finding detail, the triage row (and cluster members),
the repository's Findings tab and an acceptance's covered findings all show it.

The alternative - a non-repository asset with its own token scope - was not
chosen: it needs a second identity model for a handful of findings that one
operator owns, and the repository that runs the scan is a truthful owner.

**`unknown` stays its own state.** A check that did not run is never clean:

- `netassess`: a check whose verdict begins `unknown`, or that is missing from
  `network-status.md`, makes the run `partial_failure`. Its findings are kept;
  reconciliation counts only `success` and `no_applicable_targets` as evidence,
  so nothing the run did not look at closes.
- `shodan-internetdb`: a lookup that never happened (`{"check": "unknown"}`) is
  a failed run. InternetDB's 404 (`{"indexed": false}`) is a real, empty edge
  and succeeds.
- `netassess-freshness`: files no findings - a stale scanner is lane health, not
  a vulnerability on a host - and a stale, empty or unreadable bucket is a failed
  `network` run.

**Three tools, not one.** Reconciliation partitions on the tool, so the WAN
view's silence says nothing about the NAS and the freshness check's empty result
says nothing about either.

**Refused is not never-sent.** `api.refusals` notified on a capability refusal
(B-062) and kept nothing, so a lane being turned away left the same absence of
scan runs as a lane that never ran. `IngestRefusal` now records every refusal
per (repository, capability), and the portfolio's capability state carries
`refused` and `last_refused_at`; the grid draws a `refused` cell, which wins
over "not enabled" because a refused capability is, by construction, never
enabled.

**Operator steps.** Grant `network` to personal-soc
(`mykronos grant ToddGBenson/personal-soc network`), cut a tag carrying the new
adapters and move `mykronos-ref` to it (`pin-check` is red until then), then
`set-pipeline` personal-soc.
