## D-154 — The public edge is scanned as its own DAST tool, `zap-edge`

**2026-10-11.** **Status:** Decided, implemented. It is live once a tag carries
it and `mykronos-ref` points at that tag.
**Story:** TheHub #60708 · found by TheHub #60652 (`docs/runbooks/internet-exposure.md`, finding 5)

**The rule.** `thehub.yml`'s `dast-edge` job scans `https://hub.toddbenson.net`
through Cloudflare and uploads its findings as `--capability dast --tool
zap-edge`. The `zap-edge` adapter is the `zap` adapter with one change: a
finding's location keeps the scheme and host (`https://hub.toddbenson.net/`),
where `zap` keeps only the route (`/`).

**Why a separate tool and not the same `zap` upload.** Every DAST lane in the
TheHub pipeline uploads as `zap` under `ToddGBenson/TheHub` on `develop`. Two
facts about that, both read from the code:

- **Identity has no host.** `dast_zap.normalize` makes the route the
  `file_path` and `"METHOD route"` the snippet. `compute_finding_id` hashes
  repo, capability, rule, `file_path` and snippet. So the edge and the origin
  reporting the same rule on `/` would be one `finding_id`. Each lane's upload
  would re-describe the other's row. That is wrong for the edge in particular,
  because Cloudflare can add, strip or rewrite headers. A disagreement between
  edge and origin about one route is the result this lane exists to produce.
- **Reconciliation partitions on `(repo, capability, branch, tool)`.** With
  one tool name, two edge scans that do not see an origin-only finding would
  count as two confirming absences, and the finding would close as `fixed`.

`zap-edge` fixes both. Its identities can never equal an origin lane's,
because the host is in the hashed inputs. `reconcile`, `carry_forward` and the
stranding sweep already partition on `tool_name`, so the edge's silence is
never evidence about the origin. No identity changes for any existing
finding: `zap` is untouched, which `test_the_origin_lane_is_unchanged`
asserts.

**Rejected.**
- *A `--target` flag on the uploader.* That needs a new `scan_runs` column, or
  a tool name that only some readers parse. The tool name is what the
  readers already partition on.
- *Adding the host to `zap`'s identity.* That would re-key every existing DAST
  finding and destroy `first_seen_at` across the estate, which is #274's
  defect introduced on purpose.
- *Uploading `mykronos.toddbenson.net` from this job.* That host is MyKronos's
  asset. Its ingestion token must not resolve in `thehub`'s Vault scope
  (`Import-EnvSecretsToVault.ps1`). The job checks that host's perimeter
  (the tunnel's 404, PerimeterGate's 401, `/healthz`) without a token, and
  uploads nothing for it. A ZAP scan of it belongs in `mykronos.yml`.

**Found while doing this, and not fixed here.** The three origin lanes,
`dast-demo`, `dast-prod` and `dast-staging`, already share one identity space
and one reconciliation lane. Staging lacks headers that prod sends
(`dast-staging`'s own comment says so). A staging-only finding can therefore
be closed by two prod or demo runs and reopened by the next staging run. That
is the flapping spec 05 §5's two-scan rule exists to prevent. Giving each
origin lane its own tool name would fix it, but it changes what existing
findings were last seen by, so it is a separate decision.

**Rollout.** `scripts/check_pinned_ref.py` lists `("dast", "zap-edge")`, so
`pin-check` stays red until `mykronos-ref` names a tag that has the adapter.
Until then the job fails before uploading and names the pin. It does not fail
on a `LookupError` partway through.
