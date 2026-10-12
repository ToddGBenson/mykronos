## D-155 — Each DAST environment is its own lane and its own identity

**2026-10-11.** **Status:** Decided, implemented (TheHub #60723)
**Spec:** [05 §5, §5b](../../specs/05-datalake.md) ·
uses [D-139](../DECISIONS.md)'s exact link ·
found by D-154 (TheHub #60708, PR #781)

**The rule.** TheHub's three LAN DAST lanes upload under one tool each:
`dast-demo` as `zap-demo`, `dast-prod` as `zap-prod`, `dast-staging` as
`zap-staging` (`fingerprint.DAST_ENVIRONMENT_TOOLS`). All three use the ZAP
adapter. It reads the environment from the tool name and makes it the finding's
`symbol`, with the route left as the location. These findings are stamped
`v3-route-env`: the same `code` digest as before, with the environment as one
more input. Plain `zap`, which `mykronos.yml` still uploads under, is
unchanged.

**Why.** The ZAP adapter keys a finding on the route alone (#274). Absence
reconciliation, carry-forward and the stranding sweep all partition on
`(repo, capability, branch, tool)`. With all three lanes uploading as `zap`,
the estate had one identity space and one cleanup lane for three environments.
A route that only staging serves was closed `fixed` by two prod or demo runs
and reopened by the next staging run. A test against `origin/main` reproduces
this: the staging-only finding ends `fixed`.

**Why per-environment tools, and not the host in the identity.** These are
two separate problems, and only the tool fixes both.

- **The cleanup lane.** It is keyed on the tool, and `scan_runs` records no
  target. Putting the host in the identity alone would leave the three lanes
  in one cleanup lane. Each lane's runs would then close every other lane's
  findings, since their identities would never match. Partitioning on the
  host would need a new `scan_runs` column, and every partitioned query would
  have to learn it. The tool name is already in every one of them, so
  separate tools give separate lanes. This is #781's reasoning for `zap-edge`.
- **The identity.** It is keyed on the environment, not the host.
  `http://192.168.0.14:8081` is an address the application happens to have.
  WinNAT reservations have moved these ports before, and the LAN address is a
  DHCP lease. #274 is the rule: do not key on something the target changes
  for reasons unrelated to the finding. The edge lane (D-154) keeps the host
  for the opposite reason. There, the public hostname is the asset under test.

So this does not build on `zap-edge`, and it does not wait for #781. The two
touch the same three files, in neighbouring lines.

**Measured before building, read-only, inside `mykronos-backend` on
2026-10-11.** TheHub has 126 `dast` scan runs: 119 on `develop` and 7 on
`main`. Classified by the port in each archived raw report, the `develop`
runs are 69 demo, 22 prod and 28 staging. There are **48 live findings** (8
`open`, 36 `false_positive`, 4 `accepted_risk`). For each live finding, the
newest `develop` report from each lane was checked for it:

| reported by | open | false_positive | accepted_risk |
|---|---|---|---|
| demo only | 5 | 2 | |
| staging only | | 2 | |
| demo + prod | 1 | | |
| demo + staging | 2 | 8 | |
| demo + prod + staging | | 2 | 4 |
| no current report | | 22 | |

So 17 live findings are one row shared by two or three environments, and none
is reported by prod alone. The 22 unreported rows are dismissals that no
current rule and route produce. They were orphaned before this change and are
not affected by it.

The branch's adapter was then run over the same reports. Each of the 26
reported live findings resolves to its own row through `v2_predecessor_id`.
No new id collides with an existing one. 15 findings in the current reports
have no live predecessor. Their old row was closed `fixed`, which is this
defect at work, so they reappear `open` in the environment that still serves
them. ToddGBenson/mykronos's own `zap` lane (33 live dismissals) keeps its
tool and its identities.

**How the decisions carry.** D-139's mechanism is used unchanged where it
fits:

- **At ingestion** (`carry_forward.inherit_decisions`). The adapter records
  `{"rule": "v3-route-env", "v2_symbol": null}` under `mykronos_identity`.
  The API hashes that back into the id the finding had as `zap`, and the new
  row is written carrying that finding's `first_seen_*` and any human
  disposition. Each lane uploads separately, so each batch holds one claimant
  per old row. Every environment that reports a shared route therefore
  inherits the decision about it. The decision was made about the route
  without knowing which environment served it, so it applies to all of them.
- **In `carry_forward`**, through a new pass. A finding left in the old `zap`
  lane can never meet D-139's condition, "its lane has scanned without it",
  because that lane never scans again. Its claimants are also in other lanes,
  and the matcher never looks across lanes. `fingerprint.LANE_SUCCESSORS`
  names the lanes that replaced `zap`. The old row is withdrawn as
  `superseded` (`superseded_source = 'carry_forward'`) only once **every**
  successor lane on its branch has completed a run after it was last seen.
  That gives every environment its chance to inherit at ingestion first. A
  lane that has not scanned since might still claim the row, and it can only
  inherit from a row that is still live. The row is paired with each
  claimant, and `superseded_by` names the first by tool name. Two claimants
  from one lane would be two findings that the old identity had merged into
  one, and they are refused, as in D-139.

The ordinary matcher keeps the tool in its grouping. Merging the three
successor lanes there would let a staging finding that disappeared hand its
dismissal to the prod finding on the same route. That would be the bleed this
decision removes, coming back by another path.

**Merge and apply order.** The order is the same as #781's: merge, cut a tag,
bump `mykronos-ref`, then apply. `check_pinned_ref.py` requires the three new
adapters, so pin-check stays red until the bump. Applying the pipeline before
the bump would leave all three lanes failing their uploads with "No adapter".

**Not done.**
- An `open` row left in the `zap` lane that no environment claims would stay
  open, because nothing reconciles a lane that never scans again. None exists
  today: every live `open` finding is in a current report.
- TheHub's `main`-branch `zap` rows (last run 2026-09-04) are unaffected. No
  successor lane scans `main`.

**Rejected.**
- *Host in the identity, one tool.* It splits identities but leaves one
  cleanup lane, which makes the closing worse.
- *Environment as a file-path prefix* (`staging:/admin`). This would split
  the identity just as well. But it changes the location that every view and
  owner lookup reads, and it puts the environment into the route, which #274
  defines.
- *Re-key the lake server-side, like `rekey_containers`.* The server cannot
  tell which environments saw a shared row. Only the next upload from each
  lane knows, so the link has to be made at ingestion.
