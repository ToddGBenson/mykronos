# Spec 21 — Oracle Depth: Risk Profile, Fleet Analytics, and the Missing Override Button

**Status:** Draft for review
**Depends on:** [09 — Oracle](09-oracle-risk-decision-engine.md), [10 — JDED Dashboard](10-jded-dashboard.md),
[18 — Repo Page Rework](18-repo-page-rework-threat-model-and-remediation.md)

---

## 0. What this spec is against

Oracle's engine is the most complete system this platform has — six honestly-gated input categories,
immutable decisions, shadow-mode measurement, an audited override path. What a full read turned up is
not a missing engine but three real gaps: the portfolio trend line is quietly computing the wrong
thing, there is no way to act on an override from the UI that already displays one, and Oracle knows
nothing about the *asset* it is scoring — every input is derived from what was found, none of them
from what the thing actually is. A repo that is an internal build tool and a repo that is a
public-facing payments API can carry an identical finding and get an identical score, because Oracle
has no way to know they are not the same kind of risk.

This spec adds asset context as a new, first-class Oracle input — the risk profile — and closes the
three other gaps found alongside it. It does not touch per-repo policy variation, which stays out of
scope for the reason spec 09 and `OracleConfig` already state: one global, comparable policy. The risk
profile is *data*, read by that one policy the same way every other input is; it is not a mechanism
for a repo to opt into different scoring rules.

## 0a. Implementation status

| Item | Status |
|---|---|
| Risk profile: data model, admin-authored, per repo | Done |
| Risk profile: editor on the Risk Decision tab | Done |
| Risk profile: new Oracle input category | Done — policy bumped to 1.1 |
| Portfolio-wide trend: real aggregation, not "most recent decision" | Planned |
| Fleet analytics: which policy terms drive `no_go` across the portfolio | Planned |
| Override: a UI button, not API-only | Planned |
| Policy version history/diff | Planned |

## 1. Risk profile

### 1.1 What it is

A small, admin-authored set of facts about a repository as an asset — not derived from any scan,
because nothing a scanner sees can tell you whether an application is internet-facing or what data it
handles. An unset profile is `available: false`, exactly like every other Oracle input before its
source exists — never defaulted to "internal, low criticality," which would be a guess dressed as a
fact.

Fields, chosen to be answerable by a person who owns the application without specialist knowledge, and
each independently `null`-able (a partially-filled profile is still useful; Oracle scores what is
known and marks the rest unknown, not the whole category unavailable for one missing field):

| Field | Values | What it means |
|---|---|---|
| `internet_facing` | `bool \| null` | Does this application accept traffic from the public internet |
| `data_classification` | `public \| internal \| confidential \| regulated \| null` | The most sensitive data class this application handles |
| `business_criticality` | `low \| medium \| high \| critical \| null` | Cost of this application being down or breached |
| `compliance_scope` | `list[str]` | Regulatory regimes this asset falls under (`pci`, `hipaa`, `soc2`, `gdpr`, ...) — empty list is a real fact ("none"), distinct from `null` ("not yet asked") |
| `owner` | `str \| null` | Free text — a team or person, for context. Never scored. |
| `notes` | `str \| null` | Free text, never scored — the "why" behind the choices above, for the next admin who edits this. |

### 1.2 Data model

New operational-DB table, `risk_profiles`, one row per `RepoOnboarding` (1:1, unlike
`CapabilityConfig`'s per-capability rows), following that table's own shape (typed columns for the
fields Oracle reads, not an opaque JSON blob — an input Oracle scores has to be a schema Oracle can
validate, the same reasoning every other typed capability config already follows):

```
risk_profiles
  id                    string, pk
  repo_onboarding_id    fk -> repo_onboardings.id, unique
  internet_facing       bool, nullable
  data_classification   string, nullable
  business_criticality  string, nullable
  compliance_scope      json (list[str]), default []
  owner                 string, nullable
  notes                 string, nullable
  updated_by            string          -- actor, audit trail
  updated_at            datetime
```

### 1.3 API

`GET /api/repos/{repo_id}/risk-profile` — any authenticated principal (read access matches every
other repo-detail read; nothing here is more sensitive than a capability config).

`PUT /api/repos/{repo_id}/risk-profile` — admin-only (`may_write`), full replace (not a patch — a risk
profile is a small, complete statement of fact, and a partial-update endpoint invites a profile that
drifts field by field with no one ever looking at the whole thing). Every write is audit-logged
(`db.audit`, same pattern as the Oracle override) and stamps `updated_by`/`updated_at`.

### 1.4 Oracle input

A new modifier category, `risk_profile`, following the established shape exactly
(`MODIFIER_CATEGORIES`, `_build_snapshot`, always present, `available` gated):

- `available: false`, reason `"no risk profile recorded for this repository"` — when no row exists.
- `available: true` once a row exists, **even if every field inside it is still null** — a profile
  that exists and says "we don't know yet" is a different, auditable fact from no profile at all, and
  the per-field contributions below are each independently zero for a null field rather than the
  whole category being unavailable.
- Additive, one `Term` per non-null field that has a nonzero weight — matching `finding_age`'s flat-
  points style, not `sscs_trust`'s single-scalar style, because each field is an independent fact
  worth naming separately in `render_reasoning`, not a single number that obscures which one mattered.

New `oracle-policy-v1.yaml` block:

```yaml
  # Risk profile (spec 21). Asset context, not a finding — arrives once an
  # admin has recorded a profile; null until then, exactly like every other
  # modifier here before its source exists.
  risk_profile:
    internet_facing_points: 10
    data_classification_points:
      public: 0
      internal: 3
      confidential: 10
      regulated: 15
    business_criticality_points:
      low: 0
      medium: 3
      high: 8
      critical: 15
    compliance_scope_points_per_entry: 3   # each named regime adds this, unbounded by design —
                                            # an asset in four regimes really does carry four
                                            # kinds of exposure, and capping would hide that
```

`render_reasoning` names each contributing field by its own sentence ("internet-facing: +10",
"regulated data: +15", "PCI, HIPAA in scope: +6") — an admin reading a decision should be able to see
exactly which facts about the asset moved the score, the same standard every other category is held to.

### 1.5 Frontend

A new editable card on the Risk Decision tab (`decisions.tsx`) — the tab already explains "why this
score," and the risk profile is now one of the things a score is computed from, so it belongs beside
the term breakdown it feeds rather than on a separate page. Read-only for a viewer; a form for an
admin, `PUT`-backed through a proxy route, same shape as every other admin edit in this app. Shows
`updated_by`/`updated_at` so "who last said this repo is internet-facing" is never a mystery.

## 2. Portfolio-wide trend: fix the aggregation bug

`trend_series(catalog, repo_full_name=None, ...)` scoped to the whole portfolio has no repo filter and
no aggregation — it returns whichever single repo's `portfolio`-type decision happens to be most
recent before each timestamp, not a fleet aggregate. This has been rendering as "portfolio risk over
time" and has never been that.

**Fix:** when `repo_full_name` is `None`, aggregate every active repo's most-recent-as-of-that-instant
`raw_score` (D-018's unclamped value — ranking survives repos pinned at the clamp) into a **mean**
per time bucket, computed the same way the existing per-repo series already buckets by day. `median`
is available as a second series in the same response — a mean can be dragged by one very bad repo, a
median cannot, and showing both rather than picking one avoids re-introducing a different silent
misrepresentation in place of the one this fixes.

## 3. Fleet-wide term analytics

Nothing today aggregates `inputs_snapshot.terms` across repos to answer "what's actually driving
`no_go` across the portfolio this month — is it aging findings, KEV boosts, insider risk, or the new
risk-profile weights."

**New endpoint**, `GET /api/oracle/term-analytics` — for each active repo's latest `portfolio`
decision, sums each term's contribution by category across the fleet, returns a ranked breakdown
("finding_age: 340 total points across 12 repos, risk_profile: 210 points across 8 repos, ..."). Read
from data every decision already stores (`inputs_snapshot`); no new computation at decision time, a
new aggregate query at read time — matching how every other fleet-wide view in this app (portfolio
summary, shadow-mode) is a read-time aggregate over decisions already made, never a new write path.

Surfaced on the `/decisions` portfolio page as a new section below the standing-score table.

## 4. Override: a button, not a Postman collection

`POST /decisions/{id}/override` works, is audited, requires a reason — and has no UI. A person
overriding a decision today has to know the endpoint exists.

**Fix:** `decisions.tsx` gains an "override" action on any decision without one already — a small
form (accepted recommendation, reason, required) calling the existing endpoint through a proxy route.
No change to the endpoint's own contract (one-shot, 409 if already overridden, reason mandatory) —
this section is a UI addition over an API that was already complete.

## 5. Policy version history

`version` is a hand-bumped string in `oracle-policy-v1.yaml` with nothing to compare against. Add
`GET /api/oracle/policy/history` — reads git history on `oracle-policy-v1.yaml` (the file is already
checked in and PR-reviewed per D-0xx's promotion-to-policy-change flow) via the GitHub API, rendering
each version bump as a diff. Read-only, no new storage — the file's own commit history is already the
record; this endpoint makes it queryable from the platform instead of requiring a clone.

## 6. Acceptance criteria

- A repo with no risk profile shows `risk_profile: {available: false}` in every decision's
  `inputs_snapshot`, identical in shape to `reachability`'s permanent `unavailable` state.
- A repo with `internet_facing: true, data_classification: regulated` and nothing else set shows
  exactly two named `Term`s under `risk_profile`, worth `internet_facing_points +
  data_classification_points.regulated` from the shipped policy — reproducible by hand from the YAML.
- Editing a risk profile is admin-only; a viewer's `PUT` attempt is refused with the same 403 shape
  `PATCH /findings/{id}/status` already uses.
- The portfolio trend endpoint returns both a mean and a median series when `repo_full_name` is
  omitted, and an unchanged single-repo series when it is supplied.
- `GET /api/oracle/term-analytics` returns a ranked list summing at least `risk_profile`,
  `finding_age`, and `exploitability` contributions across every active repo with a `portfolio`
  decision.
- Clicking "override" on a decision with no existing override opens a form; submitting it calls the
  existing `POST /decisions/{id}/override` and the result renders identically to today's read-only
  override display.

## 7. Edge cases

- A risk profile edited *after* a decision was made does not retroactively change that decision
  (D-019's immutability) — only the next evaluation sees the new profile.
- `compliance_scope` as an empty list (explicitly "none") is `available: true` for the category and
  contributes zero from that field — distinct from the whole category being unavailable.
- The portfolio trend's mean/median for a bucket with zero active repos (a data gap, not a zero-risk
  day) is `null` for that bucket, not zero — same "absence is not a value" standard as everything else.
- `GET /api/oracle/policy/history` degrades to "unavailable" rather than erroring when the GitHub App
  cannot read the Mykronos repository itself (the same "different installation" caveat spec 11's
  policy-proposal PR path already documents).

## 8. Dependencies

Spec 02 (`RepoOnboarding` — the FK target for `risk_profiles`), spec 09 (Oracle — the input-category
pattern, `MODIFIER_CATEGORIES`, D-018's clamp/raw distinction, D-019's immutability), spec 10
(portfolio/trend query layer), spec 18 (Risk Decision tab, where the profile editor and override
button land).
