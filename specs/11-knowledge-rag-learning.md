# Spec 11 — Knowledge Store & RAG Learning

**Status:** Approved for build
**Depends on:** [05 — Data Lake](05-datalake.md), [09 — Oracle](09-oracle-risk-decision-engine.md)

---

## 1. Purpose

Capture what humans actually do in response to findings and decisions
(dismiss as false positive, override a risk decision, approve/reject a
Patchwork fix) as durable, retrievable "learnings," so the rest of the
system gets measurably better over time: fewer repeat false positives,
retro reports that surface real patterns, and process-change proposals
generated from evidence rather than guesswork. This mirrors a proven
internal pattern (a JSONL-backed knowledge store with a vector index and a
retrieval-augmented synthesizer), applied here across every onboarded repo
rather than a single project.

## 2. Trust tiers

Every learning entry is tagged with a trust tier, mirroring the proven
internal model:

| Tier | Meaning | Example |
|---|---|---|
| `personal` | Observed for one specific repo/finding only | "This rule_id is always a false positive in repo X because of its generated-code directory" |
| `team` | Promoted after being observed independently across multiple repos owned by the same team/org unit | "Rule_id CKV_AWS_123 has an 80% false-positive rate across the payments team's repos" |
| `org` | Promoted from `team` after cross-team confirmation — becomes an input to org-wide policy (spec 09 §5 `false_positive_dampening`) | "Rule_id X should be globally dampened in the Oracle policy" |

Promotion between tiers is **never automatic.** A scheduled job identifies
entries that independently recur across ≥ N repos at ≥ some confidence and
records them as *promotion proposals* awaiting human approval; nothing is
written to the target tier until a person approves.

**Where the approval happens depends on what is being promoted**, and an
earlier draft of this spec conflated the two:

- **`personal → team` and `team → org`** move an entry between JSONL files on
  the Mykronos server's local disk (§8). There is no git repository to open a
  pull request against, so the proposal is a record in the operational store,
  approved or rejected in the dashboard, and the decision is audit-logged.
  A draft PR here was never implementable as specified.
- **`org` tier → the Oracle policy** is a different act: it changes
  `oracle-policy-v1.yaml`, which *is* checked into the Mykronos repository.
  That one is a draft PR (§7), and it is the step that actually needs to be,
  because it changes how every repository is scored.

The distinction matters beyond mechanics. Moving an entry between tiers is a
statement about what we have observed; changing the policy is a decision about
what we will do. Only the second deserves the weight of a pull request, and
pretending the first also got one would have been ceremony rather than
control.

`restricted` entries (§3) are never promoted beyond their originating tier,
whatever their confidence or recurrence.

## 3. Data model

### `KnowledgeEntry` (JSONL file per tier, or one JSONL with a `tier` field)
| Field | Type | Notes |
|---|---|---|
| `entry_id` | string | **Derived, not random**: SHA-256 over `tier` + `repo_full_name` + `source_type` + `subject`. §5's reconfirmation is an *update* — same pattern, seen again — so a random id would append a second row instead of resetting decay, and the confidence model would never work. Same reasoning as `finding_id` (spec 05 §5) |
| `tier` | enum | `personal, team, org` |
| `repo_full_name` | string, nullable | null for org-tier entries not tied to one repo |
| `source_type` | enum | `finding_dismissal, decision_override, remediation_outcome, retro_note` |
| `subject` | string | What the learning is *about*, and the thing that recurs: `rule_id` for a dismissal, the recommendation for an override. Distinct from `source_ref`, which is one instance of it |
| `source_ref` | string | `finding_id` / `decision_id` / `event_id` that most recently produced this entry. Overwritten on reconfirmation — the full history lives in the audit log, which is append-only |
| `observations` | int | How many times this pattern has been seen and handled the same way. Starts at 1 and increments on reconfirmation. §6's dampening needs it: a rate of 1/1 is not evidence of anything |
| `text` | string | the learning itself, normalized to plain text (this is what gets embedded for retrieval) |
| `reasons` | list[string] | Every human-supplied reason given for this pattern, newest first, capped. Kept rather than collapsed into `text` because two people dismissing the same rule for *different* stated reasons is the §11 contradiction case, and a single overwritten string would hide it |
| `confidence` | float (0–1) | starts based on source signal strength, decays over time if unconfirmed (see §5) |
| `sensitivity` | enum | `public` (safe to share/promote), `restricted` (repo/team-confidential, never promoted beyond its tier) |
| `created_at` | datetime | |
| `last_confirmed_at` | datetime | updated whenever a similar signal recurs, resetting decay |
| `embedding` | vector | computed at write time, stored in the local vector index (not necessarily inline in the JSONL row) |

## 4. Ingestion — what generates a `KnowledgeEntry`

| Trigger | `source_type` | Example `text` |
|---|---|---|
| Dashboard "mark as false positive" action (spec 10 §2.2) | `finding_dismissal` | "rule_id=CKV_AWS_123, repo=payments-api: dismissed as false positive — reason: '<admin-provided free text>'" |
| Oracle decision override (spec 09 §6) | `decision_override` | "decision_id=..., repo=..., overrode no_go recommendation — reason: '<free text>'" |
| Patchwork fix PR merged vs. closed-unmerged (spec 08 §4) | `remediation_outcome` | "finding rule_id=..., auto-fix PR merged as-is" or "...closed without merging, human fixed differently: <diff summary>" |
| Manual retro note (dashboard or CLI) | `retro_note` | free-text entry from a scheduled retro session |

Every ingestion path requires the human-provided free-text reason where
applicable (dismissals/overrides) — a bare "false positive" click with no
reason is still recorded but flagged `confidence: low` and excluded from
promotion eligibility until a reason is provided (reasons are what make
learnings actionable, not just statistics).

## 5. Confidence decay

- `confidence` decays over time if an entry is not "reconfirmed" (i.e., the
  same pattern recurring and being handled the same way again).
- Decay function: exponential per a configurable half-life (default 180
  days) — an entry with no reconfirmation in that window drops to roughly
  half its original confidence, floor at 0.05.
- **Decayed entries are never deleted by decay.** They drop out of active
  retrieval and become ineligible for promotion, and they stay on disk for
  audit: "we knew this and stopped believing it" is a different fact from
  "we never knew it", and only one of them is recoverable.
- `purge_expired()` (§9) therefore does **not** delete on confidence. It
  removes entries whose *source no longer exists* — a repo that has been
  offboarded and had its data deleted (spec 02 §6). An entry about a repo
  Mykronos no longer holds data for cannot be reconfirmed, cannot be
  audited against anything, and would otherwise outlive the deletion request
  that removed everything else.

  Named `purge_expired` because that is the interface §9 fixes; what expires
  is the entry's *subject*, not its confidence.
- Reconfirmation (the same `rule_id`+repo combination dismissed again with
  a consistent reason) resets `last_confirmed_at` and boosts confidence
  back up (capped at 1.0).

## 6. Retrieval (RAG) — where learnings get used

| Consumer | How it's used |
|---|---|
| **Patchwork triage** (spec 08 §2) | Before classifying a finding, retrieve top-k similar past `KnowledgeEntry` rows (by embedding similarity on `text`, filtered to entries relevant to this repo's tier + team/org tiers) and include them as context so triage doesn't repeat a previously-corrected mistake |
| **Oracle false-positive dampening** (spec 09 §4) | A statistical rollup, not a per-decision RAG call. See §6.1 for the rate's definition, which this spec previously left open |
| **Retro report synthesis** (§7) | Retrieves clusters of similar entries to identify recurring themes worth a written retro finding |

Retrieval failures (empty store, index unavailable) must never block the
consuming process — always fall back to the no-retrieval-augmentation
behavior (matches the proven internal pattern: optional `store` parameter,
graceful degradation).

### 6.1 The false-positive rate, defined

An earlier draft said "aggregate dismissals into a historical false-positive
rate" without saying what the denominator was or how many observations were
needed. Both omissions matter, and the second is a live footgun: with the
policy's `threshold: 0.5` and no minimum, **one dismissal of a rule seen once
is a 100% false-positive rate**, and a single click would dampen that rule for
the whole repository.

    false_positive_rate(rule_id, repo) =
        findings dismissed as false_positive
        ÷ all findings for that rule_id in that repo, any status

- The denominator is the **lake**, not the Knowledge Store. Findings are the
  ground truth for how often a rule fired; the Knowledge Store records what
  humans concluded about it.
- Dampening requires **at least `min_observations` reasoned dismissals**
  (default 3) *and* a rate at or above the policy threshold. A dismissal with
  no reason (§4) counts toward neither — reasons are what make a learning
  actionable, which is the whole premise of this spec.
- Dampening is applied at the entry's own tier: a `personal` entry dampens one
  repository, an `org` entry dampens everywhere. This is why promotion is
  gated by a human (§2) — automatic promotion would let three clicks in one
  repo quieten a rule across the estate.
- The dampened weight is `severity_weight × (1 - dampening_factor)`, and the
  dampening term must appear in `inputs_snapshot` with the rate and the
  observation count that justified it (spec 09 §5). A weight that quietly
  halved is exactly the kind of hidden input spec 09 exists to prevent.

## 7. Retro & trend reports

- A scheduled job (e.g., end of each sprint/period, configurable cadence)
  synthesizes a **retro report**: new entries created this period, entries
  promoted between tiers, entries flagged for decay review, and any
  proposed process/policy changes (e.g., "propose adding rule_id X to the
  Oracle policy's dampening list org-wide" — opened as a draft PR against
  `oracle-policy-v1.yaml`, spec 09 §5, never auto-applied).
- A **trend report**, aggregating ≥ N periods (default 4) of retro data,
  surfaces longer-arc patterns: repeat false-positive categories, override
  rate trends, mean time-to-fix trends. Requires the minimum period count
  before producing a trend report, to avoid misleading conclusions from too
  little data.
- Both reports are written to the dashboard's Retro view (spec 10 §2.4) and
  optionally as committed markdown files (for teams that want them in
  version control / linked from PRs), mirroring the proven internal
  retro-report pattern.

## 8. Storage & tech

- JSONL file per tier (or a single file with a `tier` column, partitioned
  logically) on local disk, alongside a local vector index (e.g., FAISS)
  for `retrieve_similar(query, k)` semantic search — same proven pattern as
  the internal reference implementation, not a new design.
- Embeddings computed via a pluggable embedding function (configurable
  provider, e.g., the org's approved AI gateway) — the store's public
  interface accepts an injectable `embed_fn` so the embedding backend can
  be swapped without changing storage logic.
- **With no `embed_fn` configured, retrieval still works.** The default is a
  local lexical retriever — term-frequency scoring over the entry text, no
  network call, no model download. It finds fewer things than a semantic
  index would and it says so: results carry the retrieval mode that produced
  them, so a caller is never told "nothing similar" when what happened is
  "nothing lexically similar".

  A default that required an external embedding service would mean the
  learning loop silently did nothing in any deployment that had not wired one
  up, which is the same failure mode as a scanner that skips silently
  (spec 01 §6). It would also make every dismissal reason leave the host,
  which is a decision an operator should make deliberately — the same rule as
  Aegis's classifier (spec 12 §5.2).
- Physically colocated with, but logically separate from, the main data
  lake (spec 05) — the Knowledge Store is text/learnings, not raw scan
  data; kept as its own component so its retention/promotion rules (which
  differ from `Finding` retention) don't get tangled with data lake
  compaction logic.

## 9. Public interface (for the developer implementing this)

```python
class KnowledgeStore:
    def __init__(self, store_dir: Path, tier: str, embed_fn: Callable[[str], np.ndarray] | None = None): ...
    def add_entry(self, entry: KnowledgeEntry) -> AddResult: ...
    def list_entries(self, filter_tags: dict | None = None) -> list[KnowledgeEntry]: ...
    def retrieve_similar(self, query: str, k: int = 5) -> list[KnowledgeEntry]: ...
    def rebuild_index(self) -> int: ...
    def decayed_confidence(self, entry: KnowledgeEntry, as_of: datetime) -> float: ...
    def purge_expired(self) -> PurgeResult: ...

def find_cross_project_candidates(
    store_path: Path, min_projects: int = 2, min_confidence: float = 0.7
) -> list[PromotionCandidate]: ...

def record_promotion_proposals(candidates: list[PromotionCandidate]) -> int:
    """Record tier-promotion proposals for human approval in the dashboard.
    Writes nothing to the target tier. Returns the number recorded."""

def propose_policy_change(candidates: list[PromotionCandidate]) -> str | None:
    """Opens a draft PR against oracle-policy-v1.yaml for org-tier entries
    that should be dampened estate-wide. Returns the PR URL, or None if there
    was nothing to propose. Never auto-applies."""
```

`retrieve_similar` returns entries alongside the retrieval mode that found
them (`lexical` or `semantic`), so a caller can tell a genuinely empty result
from the limits of the configured backend.

## 10. Acceptance criteria

- Every finding dismissal and decision override produces exactly one
  `KnowledgeEntry`.
- `retrieve_similar` degrades gracefully (returns `[]`, never raises) when
  the store is empty or the index is corrupted.
- Confidence decay is computed deterministically from `last_confirmed_at`
  and the configured half-life — reproducible for any `as_of` timestamp.
- Tier promotion never writes directly to the target tier — always via a
  recorded proposal requiring human approval (§2), and an org-tier entry
  reaching the Oracle policy always via a draft PR requiring human merge.
- A rule is never dampened on fewer than `min_observations` reasoned
  dismissals, whatever its rate (§6.1).
- Retrieval works with no embedding backend configured, and reports which
  mode produced the results.
- A trend report cannot be generated with fewer than the configured
  minimum number of periods of data (raises a clear error rather than
  producing a misleading report).

## 11. Edge cases

- Same underlying issue dismissed with contradictory reasons across
  different repos (one admin says false positive, another confirms it as
  real in a different repo) — entries remain repo-scoped (`personal`/
  `team` tier) until/unless a promotion review explicitly reconciles the
  conflict; the system does not auto-resolve contradictions.
- Very high entry volume (thousands of dismissals) causing vector index
  rebuild cost — `rebuild_index()` should be incremental where the
  underlying index library supports it, or run as an async background job
  rather than blocking the ingestion path.

## 12. Dependencies

- Spec 05 for the `Finding`/`RiskDecision`/`RemediationEvent` records that
  trigger entries.
- Spec 08 for remediation-outcome ingestion.
- Spec 09 for the false-positive dampening consumer and policy-proposal
  target file.
- Spec 10 for the Retro/Trend dashboard view.
