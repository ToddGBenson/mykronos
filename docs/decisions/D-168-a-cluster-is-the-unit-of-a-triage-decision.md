## D-168 — A cluster is the unit of a triage decision, and its rules are deterministic

**2026-10-21.** **Status:** Decided, implemented
**Story:** TheHub #60887 (Triage T1) · Refs D-001, D-124, D-149, #280, #713, [spec 05 §5](../../specs/05-datalake.md), [spec 27 §3](../../specs/27-the-worklist.md), [spec 34](../../specs/34-duties-delegation-and-independent-approval.md)

**The rule.** `finding_id` stays the identity of a record. A *cluster* is the
set of open findings one human judgement covers, built by
`backend/mykronos/clusters.py` from fields already on each row, with no score
and no model. Three rules, in order, each finding in exactly one cluster:

1. **advisory**: a dependency or container finding, keyed on the advisory (the
   CVE its rule id or title names, else the rule id) and the package name. One
   CVE in twenty images of three repositories is one cluster.
2. **location**: a code finding, keyed on repository, weakness (the sorted CWE
   set when the scanner gave one, else the rule id), normalised file path, and
   place (enclosing symbol, else line, else the file). The CWE is what lets two
   scanners' differently-named rules for one defect meet.
3. **single**: anything else, keyed on its own `finding_id`.

A Debian `TEMP-` finding folds into the CVE cluster on the same repository,
capability, package and version **only when exactly one CVE is open there**. With
two or more there is no pairing to infer (#280: four placeholders became six
CVEs) and the cluster says so instead.

A cluster id is `cl_` plus a SHA-256 prefix of the rule and its key, never of
its members, so a rescan that moves lines or adds an image keeps the id.

**The queue.** `GET /api/dashboard/triage/clusters` takes the queue's filters,
and they choose which clusters are listed - one appears when any member
matches - but never trim a cluster's members, because the disposition beside
it covers all of them. A person filtering to `high` still sees the mediums the
decision would close.

**The disposition.** `POST /api/dashboard/triage/clusters/{id}/disposition`
runs the status route's own path once per member (`apply_finding_status`), so
every member gets its own `finding.status` audit entry carrying the cluster id,
plus one `triage.cluster_disposition` summary entry. Optional `member_ids` makes
it refuse (409) when the cluster changed since the caller looked. When the
caller is an agent and any member is critical or high (the #713 rule), nothing
applies: **one** `finding_disposition` approval request covers the cluster,
tiered by its worst governed member, with every member's row and raw record in
the evidence; on approval each still-open member is dispositioned with its own
audit entry naming the approval and the cluster.

**Why not reuse `(rule_id, package)` grouping from the findings page.** That
grouping is per repository and for display. A decision crosses repositories
and images, and needs a stable id and a sentence saying why, which a display
grouping never had to provide.

**Not done here.** Clusters are computed per request over at most
`CORRELATION_CEILING` open findings (`pool_truncated` says when that cap was
hit); nothing is stored. Auto-applying anything on the strength of a cluster is
D-169's business, not this one's.
