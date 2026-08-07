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

Promotion between tiers is **never automatic to `org`** without a
reviewable draft PR (mirrors the internal "org-proposal" pattern) — a
scheduled job identifies `team`-level entries that independently recur in
≥ N repos at ≥ some confidence, and opens a PR appending them to the
org-level store for human approval. `personal → team` promotion is
similarly proposal-based, not automatic, but may use a lower confirmation
bar (configurable).

## 3. Data model

### `KnowledgeEntry` (JSONL file per tier, or one JSONL with a `tier` field)
| Field | Type | Notes |
|---|---|---|
| `entry_id` | UUID | |
| `tier` | enum | `personal, team, org` |
| `repo_full_name` | string, nullable | null for org-tier entries not tied to one repo |
| `source_type` | enum | `finding_dismissal, decision_override, remediation_outcome, retro_note` |
| `source_ref` | string | `finding_id` / `decision_id` / `event_id` this entry originated from |
| `text` | string | the learning itself, normalized to plain text (this is what gets embedded for retrieval) |
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
- Decay function: simple linear or exponential decay per a configurable
  half-life (default 180 days) — an entry with no reconfirmation in that
  window drops to roughly half its original confidence, floor at 0.05
  (never fully deleted automatically; expired-confidence entries are
  excluded from active retrieval/promotion but retained for audit).
- Reconfirmation (the same `rule_id`+repo combination dismissed again with
  a consistent reason) resets `last_confirmed_at` and boosts confidence
  back up (capped at 1.0).

## 6. Retrieval (RAG) — where learnings get used

| Consumer | How it's used |
|---|---|
| **Patchwork triage** (spec 08 §2) | Before classifying a finding, retrieve top-k similar past `KnowledgeEntry` rows (by embedding similarity on `text`, filtered to entries relevant to this repo's tier + team/org tiers) and include them as context so triage doesn't repeat a previously-corrected mistake |
| **Oracle false-positive dampening** (spec 09 §4) | Aggregate confirmed `finding_dismissal` entries per `rule_id` per repo into a historical false-positive rate, feeding the policy's dampening term directly (this is a statistical rollup, not a per-decision RAG call) |
| **Retro report synthesis** (§7) | Retrieves clusters of similar entries to identify recurring themes worth a written retro finding |

Retrieval failures (empty store, index unavailable) must never block the
consuming process — always fall back to the no-retrieval-augmentation
behavior (matches the proven internal pattern: optional `store` parameter,
graceful degradation).

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

def generate_promotion_proposal(candidates: list[PromotionCandidate]) -> str | None:
    """Opens a draft PR appending candidates to the next tier's store. Returns
    the PR URL, or None if there was nothing to propose. Never auto-applies."""
```

## 10. Acceptance criteria

- Every finding dismissal and decision override produces exactly one
  `KnowledgeEntry`.
- `retrieve_similar` degrades gracefully (returns `[]`, never raises) when
  the store is empty or the index is corrupted.
- Confidence decay is computed deterministically from `last_confirmed_at`
  and the configured half-life — reproducible for any `as_of` timestamp.
- Tier promotion never writes directly to the target tier — always via a
  draft PR requiring human merge.
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
