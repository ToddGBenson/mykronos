## D-160 — A Concourse build-dir path is stripped, and the findings stored under it are re-keyed, not fixed

**2026-10-12.** **Status:** Decided, implemented
**Story:** TheHub #60734 · uses [D-139](../DECISIONS.md)'s exact link ·
spec [05 §5, §5b](../../specs/05-datalake.md)

**The rule.** The shared path normaliser (`adapters/sarif.py::_clean_uri`)
strips Concourse's `/tmp/build/<hex handle>/source/` prefix, with or without
the leading slash, the way it already stripped GitHub's
`/home/runner/work/<repo>/<repo>/`. Only the input name `source` is matched:
every pipeline here names its checkout that, and a wider pattern would be a
guess about paths nobody has seen.

When the prefix was stripped, the adapter records the path the finding used
to be stored under as `v2_file_path` in its identity marker, alongside the
snippet and symbol that resolving *that* path gives. That is how the
finding's current id was built. `fingerprint.v2_predecessor_id` hashes those
inputs into the old id. From there, D-139's machinery runs unchanged.
Ingestion's `inherit_decisions` gives the new row the old row's first
sighting and any decision. `carry_forward` withdraws the old row as
`superseded` (`superseded_source = 'carry_forward'`) once its lane has
scanned without it. Both PSScriptAnalyzer's JSON adapter and the SARIF
converter do this.

`carry_forward` now matches exact links across the whole lane
(`repo, capability, rule, branch, tool`), not within a single file. It also
reads the raw record of a `v1-line` row when that record names a
`v2_file_path`, so a successor whose file could not be read still links.

**Why.** All 116 PSScriptAnalyzer findings in the lake (48 open in mykronos,
68 in personal-soc, measured 2026-10-12) were stored as
`tmp/build/e542859e/source/...`. The path is not one in the repository, so no
snippet could be read, and every one of them is `v1-line`. A line-keyed
identity moves with any edit above the finding.

Fixing the path changes every one of those ids. Left to the normal paths,
absence reconciliation would close 116 findings as `fixed`. Those `fixed`
rows would feed the Oracle's posture credits and mean-time-to-fix. The same
116 findings would arrive as new work, first seen today. Nothing was
remediated and nothing was introduced, so both halves would be false. An
exact link is available because the adapter has both paths in hand. Using it
avoids any similarity judgement.

Checked against the live lake before this change: for every one of the 116
rows, the predecessor id the new adapter computes equals the stored
`finding_id`.

**Not chosen.**
- *A one-off re-key command, like `rekey_containers`.* The new id depends on
  the snippet read from the checkout, and only the uploader has the
  checkout. A command run against the lake would compute a third identity,
  `v1-line` on the clean path, which the next real scan would re-key again.
- *Rewrite `file_path` in place.* Same problem: the id is a hash of the
  path, and the path alone does not give the id the next scan will submit.
- *Match any input name, not just `source`.* No pipeline uses another name,
  and stripping two path components on a guess could truncate a real path.

**Effect on deploy.** The re-key happens on the first PSScriptAnalyzer scan
after both the API (ingest and `carry_forward`) and the uploader the lane
pins (`MYKRONOS_REF`) carry this change.
