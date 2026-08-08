# Spec 06 — Aegis Integration (Insider Risk)

**Status:** Approved for build
**Depends on:** [04 — Scanner Workflows](04-scanner-workflows.md), [05 — Data Lake](05-datalake.md)

---

## 1. Purpose

Add an **insider-risk and AI-authorship PR gate** capability, modeled on the
existing internal "Aegis Guard" GitHub Action pattern: on every pull
request, assess signals that indicate insider threat risk or undisclosed
AI-generated authorship, and produce a go/no-go recommendation attached to
the PR — feeding into Oracle (spec 09) as one input among several, not a
final verdict on its own.

## 2. Scope of "insider risk" signals (v1)

Aegis evaluates a PR and computes a set of signals, each independently
scored, then combined into an `insider_risk_score` (0–100, higher = riskier):

| Signal | Description | Data source |
|---|---|---|
| **Author baseline deviation** | Commit timing, volume, and file-touch patterns vs. that author's own historical baseline for this repo | Git history via GitHub API |
| **Sensitive path touch** | PR modifies paths flagged as sensitive (auth, secrets config, CI/CD config, access-control code) — configurable glob list per repo | Repo config (`CapabilityConfig`) |
| **AI-authorship likelihood** | Heuristic/LLM-based estimate of whether code was AI-generated and, if so, whether the PR description discloses it | Diff content passed to an LLM classifier. **Off unless an endpoint is configured** — see §5 |
| **Access anomaly** | Author has write access but has never contributed to this repo before | Repo contributor history |
| **Rapid privilege-adjacent change** | PR modifies permission/role definitions (IAM policies, RBAC configs) shortly before or after a personnel-sensitive event, *if such an event feed is configured* (optional integration, off by default — no HR system integration in v1) | Optional external signal, disabled by default |

**v1 explicitly does NOT integrate with HR/personnel systems.** The
"rapid privilege-adjacent change" signal only activates if a deployment
operator configures an external event feed; out of the box, insider-risk
scoring uses only Git/GitHub-native signals.

**AI-authorship classification is also off by default.** It is the only
signal that sends repository content off the runner, and a deployment
without a configured classifier endpoint must not silently post diffs
anywhere. With no endpoint set, Aegis scores the deterministic signals and
records `ai_authorship_flag = null` — the same path as §7's gateway-outage
case, because "we did not look" is the same fact either way.

## 3. Data model — `InsiderRiskSignal` (data lake table)

| Field | Type | Notes |
|---|---|---|
| `signal_id` | string | PK. **Derived, not random**: SHA-256 over `repo_full_name` + `pr_number` + `commit_sha`, so re-running the workflow on the same head commit upserts rather than appending a duplicate. Same reasoning as `finding_id` (spec 05 §5) |
| `repo_full_name` | string | |
| `pr_number` | int | |
| `commit_sha` | string | head commit evaluated |
| `author_login` | string | The GitHub login whose PR was scored. **Required** — see §9. A score about a person that does not record which person is unauditable: you cannot check calibration, you cannot answer a challenge, and you cannot delete it on request |
| `insider_risk_score` | int (0–100) | combined score |
| `signal_breakdown` | JSON | per-signal sub-scores + short human-readable rationale for each (never just a number — must be explainable, matching architecture constraint spec 01 §6) |
| `ai_authorship_flag` | bool, **nullable** | true if AI-authorship likely and undisclosed; false if evaluated and not AI; **null if not evaluated** (§7). The three states are distinct and collapsing null into false would report "we checked, it is human" when nothing checked |
| `recommendation` | enum | `pass, review_recommended, block_recommended` |
| `evaluated_at` | datetime | |
| `github_check_run_id` | string, nullable | if a GitHub Check Run was posted |

## 4. Workflow behavior

- Template: `workflow-templates/aegis.yml.j2`, triggered on `pull_request`
  (opened, synchronize, reopened).
- Steps: checkout PR diff → run Aegis scorer (calls an LLM via the
  org's approved AI gateway, using only the diff + PR metadata, never the
  full repo contents unless the sensitive-path signal requires reading
  surrounding context) → post a GitHub Check Run summarizing the
  recommendation and top contributing signals → call
  `POST /api/ingest/aegis` (per the shared upload contract, spec 04 §2) to
  write the `InsiderRiskSignal` row.
- `recommendation: block_recommended` does **not** auto-block the PR merge
  by itself — it surfaces a failing Check Run if `CapabilityConfig.blocking`
  is `true` for Aegis on that repo (same blocking config pattern as spec 04
  §5); otherwise it's advisory only. Either way, human review of the PR is
  still required before merge (architecture constraint, spec 01 §6).

## 5. Configuration (`CapabilityConfig` for `aegis`)

| Field | Type | Default | Notes |
|---|---|---|---|
| `sensitive_paths` | glob list | `["**/auth/**", "**/*secret*", "**/.github/workflows/**", "**/iam/**"]` | |
| `blocking` | bool | `false` | |
| `block_threshold` | int | `80` | `insider_risk_score` at/above this triggers `block_recommended` when `blocking=true` |
| `ai_disclosure_required` | bool | `true` | if true, undisclosed AI-authorship raises the score even if the code itself looks fine |
| `ai_classifier_url` | string, nullable | `null` | Endpoint for the AI-authorship classifier. **Null disables the signal entirely** — no diff leaves the runner. There is no default endpoint, deliberately: a deployment must name where it is willing to send code |
| `retention_days` | int | `90` | How long `InsiderRiskSignal` rows are kept before the purge job deletes them (§9) |

## 6. Acceptance criteria

- Every evaluated head commit on a repo with Aegis enabled produces exactly
  one `InsiderRiskSignal` row and one GitHub Check Run. **Per commit, not per
  PR**: the workflow triggers on `synchronize`, so an active PR is scored many
  times, and each score is about the code as it then stood. Re-running the
  workflow on an unchanged head commit upserts the existing row rather than
  adding a second.
- `signal_breakdown` always contains a rationale string for every
  sub-signal that contributed non-zero score — no opaque numeric-only
  output.
- Aegis never merges, closes, or force-pushes a PR — read/comment/check
  permissions only.

## 7. Edge cases

- LLM/AI gateway unavailable — Aegis falls back to non-AI signals only
  (author baseline, sensitive path, access anomaly), sets
  `ai_authorship_flag = null` (not `false`, to distinguish "not evaluated"
  from "evaluated, not AI"), and still ingests a signal row rather than
  failing the whole workflow.
- First-ever PR from a repo (no baseline history) — author baseline
  deviation signal is skipped (insufficient data) rather than defaulting
  to a false-positive-prone extreme score.

## 8. Dependencies

- Spec 05 for ingestion contract and table schema.
- Spec 09 (Oracle) consumes `InsiderRiskSignal.insider_risk_score` as one
  weighted input to its overall risk decision.
- Spec 11 (Knowledge Store) — human overrides of an Aegis recommendation
  (e.g., admin dismisses a `block_recommended` as a false positive) are
  captured as retro signals to improve future scoring calibration.

## 9. Data governance

Every other capability in Mykronos scores *code*. Aegis scores a **pull
request by a named person**, and the difference is not cosmetic: an
`insider_risk_score` attached to a GitHub login is personal data, and a table
of them accumulating indefinitely is a dossier on your colleagues whatever the
intent behind it.

This section is normative, not advisory. An implementation that skips it is
not compliant with this spec.

**Purpose limitation.** An `InsiderRiskSignal` is a *review prompt about a
change*, not a rating of a person. It says "this PR touches auth config and
its author has not contributed here before, so look properly" — it does not
say "this person is a risk". Nothing in Mykronos aggregates these scores per
author, ranks contributors, or trends an individual over time, and adding such
a view is a spec change, not a feature request.

**Access.** Insider-risk rows are **admin-only**, at the query layer rather
than hidden in the UI — the same rule and the same reason as raw tool output
(spec 12 §5). Viewers see that Aegis ran and what it recommended for a PR;
they do not see the breakdown or the author's baseline comparison.

**Retention.** Rows are purged after `retention_days` (default **90**). The
signal's value is in reviewing the pull request it is about, which is over in
days; after that it is only a record of somebody having been suspected. The
purge is a scheduled job, not a documented intention — an unenforced retention
policy is just a sentence.

**Right of reply.** `signal_breakdown` must carry a rationale for every
non-zero sub-signal (§6), so a person challenged by this can see exactly what
was said about them and dispute a specific claim rather than a number. An
admin dismissal is recorded as a retro signal (§8) and is the primary
calibration input.

**Never automated.** Aegis cannot merge, close, or force-push (§6), and
`block_recommended` never blocks on its own (§4). Human review is required
before merge regardless (spec 01 §6). A person's access is never changed by
this system.

**Deletion.** Because `author_login` is recorded, a deletion request can
actually be honoured. If the author were omitted "for privacy", the rows would
still be personal data — trivially re-identified via `repo_full_name` and
`pr_number` — but no longer findable, which is the worst of both.
