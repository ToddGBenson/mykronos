# Spec 35 — The Product Owner Tab: Each Repository's Declared Process, Backlog and Sprint

**Status:** Approved for build, phase 1 (Product Owner decision 2026-10-11)
**Depends on:** [17 — Harness, Threat Intel and i2i Grooming](17-harness-threat-intel-and-i2i.md) for "dev-ready", [34 — Independent Approval](34-duties-delegation-and-independent-approval.md) for who may change a process
**I2I record:** TheHub oplan #11537 (problem, options, KPIs). Design canvas: three directions, **C chosen**.

---

## 0. What this spec is against

Every repository in the estate has a development process, and almost none of them can be seen. Measured
2026-10-11:

1. **TheHub defines its process in at least four overlapping places**: `config/lifecycle_pipelines.yaml`,
   `config/pipeline_phases.yaml`, `docs/lifecycle-reference.md` and the root `CLAUDE.md`. Its 8 story gates
   × 4 buckets, the 8-step Dev Process and about 20 deploy gates live in prose and code. One of them,
   the inception gate, is declared in code and switched off in the running `.env`, and nothing shows it.
2. **keel has the clearest model**: six gates (G0–G5), each a checklist with the evidence every item needs
   and a named recommender and approver, plus `automation-policy.yml`. It is visible only to someone who
   reads `process/gates/*.md`.
3. **MyKronos itself has no process document.** Spec 16 records that TheHub's I2I funnel was not followed for
   MyKronos work, and its backlog is `docs/BACKLOG.md` markdown.
4. **personal-soc and six other repositories declare nothing at all.**

The Product Owner, a single operator, runs sprints in TheHub's Mission Control, the MyKronos backlog in
markdown, and keel in GitHub Issues. There is no one place that answers "what is this repository's process,
what is ready, what is in the sprint, and what is waiting on me?"

## 1. Decisions (Product Owner, 2026-10-11; recorded as D-132 – D-135)

| # | Question | Decision |
|---|---|---|
| D-132 | Where is a repository's process defined? | **A manifest in the repository**: `.sdlc/process.yaml`. It is changed by pull request, so its history is in git and its changes get independent review (spec 34). MyKronos reads it; it never stores a second copy. |
| D-133 | Where do work items live? | **TheHub `dev_stories` is the system of record** for every repository. MyKronos reads and moves stories through the Hub API. A story belongs to a repository through a `repo:<name>` tag; the manifest says whether untagged stories count as its own (TheHub's do). |
| D-134 | One state model or many? | **Each repository's own gates, mapped onto a shared spine**: Idea · Ready · Building · Verifying · Shipping · Done. The tab shows the repository's real gate names. The spine makes repositories comparable and gives a repository with no manifest a default. |
| D-135 | Layout | **A Product Owner console**: one `product-owner` tab with sub-views, chosen over a process-map page (A) and a board-first page (B). It is the one that scales to the later phases without crowding a single screen. |

## 2. The manifest — `.sdlc/process.yaml`, version 1

```yaml
version: 1
name: keel-style            # free text; shown in the header
spine_map:                  # this repo's gate id -> spine step
  G0: idea
  G1: ready
  G2: building
  G3: building
  G4: verifying
  G5: shipping
gates:
  - id: G1
    name: Ready
    recommends: Product Owner
    approves: Delivery Lead
    doc: process/gates/g1-ready.md
    story_gates: [clarified, designed]       # TheHub dev_stories.gate values this gate covers
    checklist:
      - id: ac-binary
        text: Acceptance criteria are binary and observable
        evidence: acceptance_criteria        # a known evidence key (§2.2), or omitted = manual
backlog:
  source: thehub                             # phase 1: thehub only
  tag: repo:keel
  include_untagged: false
delivery:
  summary: PR to main, required governance check, human merge, Concourse after merge
  steps: [pr, governance-check, human-merge, concourse, authorize-release]
automation_policy:
  - id: P1
    text: Credential is the CLI login
    met: true
docs:
  - {label: Roles, path: docs/01-roles.md}
```

### 2.1 Validation

The manifest is parsed with a strict pydantic model. Unknown top-level keys are an error, so a typo is not
silently ignored. An invalid manifest is **shown as invalid, with the reason**. The tab never falls back to
a default and presents it as the repository's declared process.

### 2.2 Evidence keys (phase 1)

These are checked against the Hub story: `acceptance_criteria` (≥1), `detail_500` (detail ≥ 500 characters),
`sized` (a `size` value), `threat_model` (an `inception_draft.threat_model_md` key) and `sprint` (bucket = sprint).
An item without an `evidence` key is shown as **manual**: neither passed nor failed.

### 2.3 Absent manifest

If the default branch has no `.sdlc/process.yaml`, the tab says so plainly ("This repository declares no
process") and shows the spine as a default, labelled as a default. Offering a template pull request is
phase 2.

## 3. What the tab shows (phase 1)

Route: `/repos/[repoId]?tab=product-owner&view=<overview|backlog|sprint|process>`.

- **Overview**:
  - **Needs a human**, first, as keel's `dashboard.py` does. It lists sprint stories that fail a gate
    check, stories at Ready with a manual checklist item, and an invalid manifest.
  - Counts per spine step.
  - Sprint progress (done / committed).
  - The Oracle decision for the repository, from data MyKronos already holds.
- **Backlog**: the repository's `bucket=backlog` stories in the Product Owner's rank order, then unranked
  ones by gate and age. Each row shows its gate check (passed / total). Writes: **rank** (move up or down)
  and **Pull into sprint**.
- **Sprint**: `bucket=sprint` stories grouped by spine step. Write: **Back to backlog**.
- **Process**: the manifest rendered. It shows each gate with its checklist, recommender, approver and doc
  link; the delivery steps; the automation-policy preconditions; and the doc links. Each links to the file
  on GitHub at the default branch.

## 4. Writes, and why they are safe

| Action | Hub call | Guard |
|---|---|---|
| Pull into sprint | `POST /api/devops/autonomy/stories/{id}/toggle-autonomy {autonomy_disabled: true}`, **then** `POST /api/dev/stories/{id}/move {bucket: sprint}` | A sprint move arms autonomous dispatch in TheHub. Autonomy is switched off **first**, so a failure between the two calls leaves the story in the backlog with autonomy off, never in the sprint with autonomy armed. |
| Back to backlog | `POST /api/dev/stories/{id}/move {bucket: backlog}` | — |
| Rank | none — MyKronos `po_backlog_rank` table | TheHub has no rank field. Rank is the Product Owner's ordering, stored in MyKronos, keyed by (repo id, story id). Moving rank into TheHub is follow-up B-068. |

- All writes need the **admin** token. A viewer sees the tab read-only. Every write is recorded in `audit_log`
  with the actor, repository, story id and action.
- The Hub refuses moves its own rules forbid; for example, a sprint pull needs acceptance criteria and
  gate ≥ clarified. Its refusal is shown verbatim (the Hub writes those messages) and never retried.
- MyKronos never edits story content. Title, acceptance criteria and gates stay with TheHub, which owns them
  (D-133).

### 4.1 The Hub credential

MyKronos calls TheHub with `X-Hub-Token: <gate_token>`. `gate_token` is already, by its own definition
(config.py), the same value as the Hub's `HUB_API_TOKEN`. No new credential is introduced. The Hub base URL is
a new setting, `hub_api_url` (default `http://host.docker.internal:8000`). It is empty-disables: with no URL or
no token, the tab says "TheHub is not connected" and shows the manifest only.

> **Amended during the build (D-133).** The premise above is wrong: D-131 records that `gate_token` and the
> Hub's `HUB_API_TOKEN` are different values (checked 2026-10-08). Reusing `gate_token` would be refused by
> the Hub, and would send MyKronos's perimeter secret to another service. The client reads a setting of its
> own, `hub_api_token`, holding the Hub's existing token. No new credential is minted. Like `hub_api_url`, it is
> empty-disables.

## 5. Out of scope for phase 1 (backlog entries)

- B-068: rank stored in TheHub (a migration, which ships alone).
- B-069: a template pull request for a repository with no manifest.
- B-070: **declared-vs-observed drift findings**. For example, the manifest declares required review but
  branch protection is off, or it declares the inception gate but the flag is off.
- B-071: sub-views for Delivery, Approvals inbox, Roles & agents, and a generated retro.
- B-072: a keel GitHub-Issues adapter (`backlog.source: github_issues`).

## 6. Tests

`backend/tests/test_product_owner.py`:
- **Manifest validation:**
  - a valid manifest parses;
  - an unknown key is refused;
  - an absent manifest yields `state=absent` and the default spine.
- **Gate checks:** evidence keys pass or fail against a story, and an item with no evidence key is manual.
- **Repository membership:** by tag, and with `include_untagged`.
- **Sprint pull order:** the autonomy toggle runs before the move. If the toggle fails, no move happens. If the
  move fails, autonomy stays off and the Hub's refusal is surfaced.
- **Auth:** a viewer cannot write, and every write is audit-logged.
- **Rank:** rank persists and orders the backlog.
