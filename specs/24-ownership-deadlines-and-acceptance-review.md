# Spec 24 — Ownership, Deadlines, and the Acceptance Review Cycle

**Status:** Draft for review
**Depends on:** [05 — Data Lake](05-datalake.md), [09 — Oracle](09-oracle-risk-decision-engine.md),
[10 — JDED Dashboard](10-jded-dashboard.md), [11 — Knowledge Store & RAG](11-knowledge-rag-learning.md),
[17 — Harness, Threat Intel, i2i](17-harness-threat-intel-and-i2i.md)

---

## 0. What this spec is against

A platform review of the eight repo-page subsystems found twenty-two gaps. Six of them were the same
gap wearing different clothes — the forward pass is built and the return path is not — and three of
those six live in `Finding` itself:

1. **No finding has an owner.** There is no assignee, no team, and no CODEOWNERS resolution anywhere
   in the schema or the API. `CODEOWNERS` appears exactly once in this codebase, in a comment in
   `api/patchwork.py` explaining that draft PRs go through review and CODEOWNERS "which is the point
   of them". Every finding is therefore addressed to everybody, which is the same as addressed to
   nobody.
2. **The one externally-authored deadline in the platform is discarded.** CISA KEV ships a `dueDate`.
   `threat_intel.py` parses it, `ThreatIntelEntry.kev_due_date` stores it, and the `/threat-intel`
   endpoint renders it. `_attach_threat_intel` stamps `cve_id`, `in_kev` and `epss_score` onto finding
   groups and **not** the due date. The only date anybody outside this organisation has committed to
   never reaches the work.
3. **Accepted risk never expires.** `api/dashboard.py`'s own docstring records the state plainly:
   *"this repository is currently carrying 243 acceptances that each said exactly that"* — that no
   vendor fix exists. That claim stops being true the day a vendor ships one. Atlas learns the fixed
   version on the next scan. The two facts never meet, and nothing re-opens the decision.

None of these is a missing subsystem. Each is a column and the thing that populates it. They are
first because everything else in the review's roadmap — routing, digests, throughput, burn-down,
overdue escalation — is undefined until a finding can be addressed to a person and carry a date.

## 0a. Implementation status

| Item | Status |
|---|---|
| `owner` on `Finding`, resolved from CODEOWNERS at ingest (§1) | **Built** |
| `due_at` on `Finding`, from KEV or from policy (§2) | **Built** |
| Overdue as a filter, a portfolio tile, and an Oracle term (§2.4) | Filter built; tile and Oracle term not started |
| Acceptance expiry and automatic re-open (§3) | **Built** |
| "Mine" across Findings and Triage (§4) | Not started |

## 1. Ownership

### 1.1 Current state

`FindingRecord` carries identity, location, severity, status and timestamps. It carries nothing about
who should act. The dashboard's queues are portfolio-wide and unfiltered by person; the i2i grooming
path creates a GitHub issue with no assignee.

### 1.2 What ships

- **`Finding.owner`** — a string, nullable, holding a GitHub handle or team slug (`@org/team`), and
  **`owner_source`** — `codeowners` | `profile` | `manual` | `unresolved`. Two columns because
  "nobody owns this" and "we never worked out who owns this" are different problems with different
  fixes, and one nullable column would conflate them exactly as spec 09 §9 warns about elsewhere.
- **Resolution at ingest.** The server reads `CODEOWNERS` for the repository (the existing
  `GitHubClient.get_file` is the whole client surface needed — no new permission, no new operation)
  and matches the finding's `file_path` against its patterns, last-match-wins per the CODEOWNERS
  specification. The resolved owner is stored on the finding.
- **Resolution is cached per repository and commit**, not per finding: a scan producing four hundred
  findings reads the file once.
- **A finding with no `file_path`** — a dependency finding, a container layer — falls back to the
  repository owner on the risk profile (spec 21 §1), stored as `owner_source: profile` so nobody
  reads it as something the team wrote in their own file. Failing that, `unresolved`.
- **No manifest is guessed.** The obvious extra step — match `package.json` or `requirements.txt`
  against CODEOWNERS — is not taken. A dependency finding names a package and not the file that
  declares it, so choosing between those two paths would be this platform inventing a location and
  then routing real work by it. The profile answer is weaker and true; the manifest answer would be
  specific and made up.
- **Manual override.** `PATCH /api/findings/{finding_id}/owner` sets `owner` with
  `owner_source: manual`. A later scan does not overwrite a manual assignment — a person reassigning
  a finding is making a decision, and a re-scan is not new information about who should fix it.

### 1.3 What does not ship

No user accounts, no notion of a person inside this platform, and no mapping from a GitHub handle to
an employee. The owner is a routing label copied from a file in the repository, which is what makes
it defensible: the answer is authored by the team, in their repo, under review.

No auto-assignment of GitHub issues to the owner. Grooming creates the issue; who it lands on is
GitHub's business, and an assignment this platform makes is one nobody agreed to.

## 2. Deadlines

### 2.1 Current state

`age_days` exists and Oracle escalates on it (spec 09 §5's age term). Age is not a deadline: it says
how long something has been open, never how long it may remain so. `kev_due_date` is parsed, stored
and rendered on the threat-intel page, and consumed by nothing.

### 2.2 What ships

- **`Finding.due_at`** (timestamp, nullable) and **`due_source`** — `kev` | `policy` | `manual`.
- **KEV wins.** If the finding's CVE is in KEV, `due_at` is the KEV due date, `due_source: kev`. That
  date is authored outside this organisation, and a locally-computed date that disagreed with it
  would be the platform quietly negotiating with CISA.
- **Otherwise policy.** `oracle-policy-v1.yaml` gains a `remediation_targets` block — days per
  severity, admin-authored and reviewed in a pull request like every other policy value:

```yaml
remediation_targets:          # days from first_seen_at
  critical: 7
  high: 30
  medium: 90
  low: 180
  info: null                  # null means no target — info findings are not work
```

- **`due_at` is computed from `first_seen_at`**, not from the most recent scan. A finding that has
  been open for sixty days does not get a fresh thirty because somebody re-ran the scanner.
- **Manual extension** requires a reason, is captured to the Knowledge Store like every other reasoned
  human verdict (spec 11 §4), and is visible on the finding.

### 2.3 What does not ship

No notifications in this spec — §4 names the digest as follow-on work, and a deadline nobody is told
about is still better than no deadline, while a notifier built before ownership is a notifier that
mails everybody.

### 2.4 Overdue as a first-class state

- A `due` filter on `open_findings()` and `triage_queue()`: `overdue` | `due_soon` (inside 7 days) |
  `on_track` | `no_target`.
- A portfolio tile counting overdue findings, beside the existing critical/high tiles.
- **An Oracle term.** `overdue_findings` is additive and small, and — importantly — it is *not* a
  second age term. Age already escalates continuously; this fires once, on a date the organisation
  set for itself. A repository whose criticals are inside their window scores no worse for having
  them, which is the behaviour the current age curve cannot express.

## 3. The acceptance review cycle

### 3.1 Current state

`FindingStatus.ACCEPTED_RISK` is terminal. `capture_dismissal` deliberately does not learn from it —
correctly, per spec 11: an acceptance is a statement about appetite, not about detection quality.
What nothing does is revisit it. The reason text is free-form, so "no vendor fix" is prose rather
than a condition anything can re-evaluate.

### 3.2 What ships

- **`accepted_until`** (date, nullable) on the finding, set when a person accepts the risk. The
  disposition form requires either a date or an explicit "indefinite" choice with its own reason —
  the second is rarer than people expect once the first exists.
- **`accepted_reason_code`** alongside the free text: `no_vendor_fix` | `not_exploitable_here` |
  `compensating_control` | `cost_exceeds_risk` | `other`. The free text stays and is still required;
  the code is what makes an acceptance machine-revisitable.
- **Automatic re-open on evidence, for one code only.** When a later scan reports a fixed version for
  a finding accepted as `no_vendor_fix`, the finding returns to `open` with a note naming the version
  that contradicted it. This is the one code where the platform can *know* the premise expired.
  The others expire on their date and are never auto-reopened, because no scan can tell you that a
  compensating control was removed.
- **Expiry sweep.** A daily job returns findings past `accepted_until` to `open`, preserving
  `first_seen_at` — an acceptance that ran out is not a new discovery, and letting it reset the clock
  would hand every ageing finding a way to look young.

### 3.3 What does not ship

Bulk expiry of the existing 243 acceptances. They are re-dispositioned by a person, on a schedule the
operator picks, with the reason-code field newly available. A migration that assigned every one of
them a synthetic date would manufacture 243 decisions nobody took — and the review that found this
gap found it by reading the docstring that counts them, which is exactly the evidence trail a
mass-update would destroy.

## 4. Where these surface

- **Findings tab**: owner and due state as columns; a "mine" filter driven by a handle the viewer
  types once and the browser remembers.
- **Triage queue**: the same two filters, plus overdue-first as an available ordering (the ranked
  ordering itself is spec 27).
- **Risk Decision tab**: the `overdue_findings` term in the existing breakdown table, like every
  other term.

A weekly per-owner digest is named here as follow-on work and specified in spec 27 §4, where the
worklist it summarises is defined.

## 5. Acceptance criteria

- A finding whose `file_path` matches a CODEOWNERS pattern carries that owner, and one that matches
  none carries `owner_source: unresolved` — never a default that looks like a real assignment.
- Re-running a scan does not overwrite a manually assigned owner.
- A KEV-listed finding's `due_at` equals the KEV due date exactly, and `due_source` says `kev`.
- A finding accepted as `no_vendor_fix` re-opens automatically when a scan reports a fixed version,
  with `first_seen_at` unchanged and a note naming the version.
- An acceptance reaching `accepted_until` returns to `open` with `first_seen_at` unchanged.
- The `overdue_findings` Oracle term contributes zero for a repository whose findings are all inside
  their targets, and the `inputs_snapshot` reports the category `available: True` for any repository
  where `remediation_targets` is configured.
- Changing `remediation_targets` in policy bumps the policy version, exactly as any other policy edit
  does.

## 6. Edge cases

- **A repository with no CODEOWNERS file.** Every finding resolves `unresolved`; the tab says so
  once, at the top, with a link to GitHub's documentation — rather than four hundred rows each
  quietly blank.
- **A CODEOWNERS pattern naming a team that no longer exists.** Stored as written. This platform does
  not validate GitHub's membership graph, and a finding routed to a dead team is a fact worth seeing.
- **A finding whose file moves.** Ownership is re-resolved on the next scan; a manual assignment
  survives, per §1.2.
- **A KEV due date in the past at first ingest** — common, since KEV back-dates. The finding is
  overdue on arrival. Correct, and it must not be softened into a fresh window.
- **A finding that is both overdue and accepted.** Acceptance suppresses the overdue state while it
  is live; expiry restores it. The two must not double-count in the Oracle term.
- **Clock skew across a daily sweep.** Expiry is evaluated in UTC against `accepted_until` as a date,
  not a timestamp, so a finding does not flip status twice in one day at a timezone boundary.

## 7. Dependencies

Spec 05 (lake columns and the rule that the server derives status and timestamps, which is why
`due_at` is computed server-side and never submitted), spec 09 and `oracle-policy-v1.yaml` (the new
`remediation_targets` block and the additive term), spec 10 §6 (every number traceable — owner and
due date are both stored, never derived at render time), spec 11 §4 (reasoned verdicts captured),
spec 17 §4 (the KEV data this reuses), spec 21 §1 (the risk profile's default owner).
