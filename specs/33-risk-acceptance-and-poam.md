# Spec 33 — Risk Acceptance as a Governed Decision: Authority, POA&M, and Premise Monitoring (NIST SP 800-53 Rev. 5)

**Status:** Draft for review
**Depends on:** [09 — Oracle](09-oracle-risk-decision-engine.md), [11 — Knowledge Store](11-knowledge-rag-learning.md),
[17 — Harness, Threat Intel, i2i](17-harness-threat-intel-and-i2i.md),
[24 — Ownership, Deadlines, and the Acceptance Review Cycle](24-ownership-deadlines-and-acceptance-review.md),
[27 — The Worklist](27-the-worklist.md)
**Uses:** [34 — Duties, Delegation, and Independent Approval](34-duties-delegation-and-independent-approval.md) for every approval
**Decisions:** D-127 (per-image container identity) is a prerequisite

---

## 0. What this spec is against

Spec 24 made an acceptance expire. `docs/acceptance-checklist.md` made one hard to write badly: a
reason code, words for critical and high, a review window scaled to severity, and a refusal of
`no_vendor_fix` when a fix is already visible. **Everything this platform does about an acceptance
happens at the moment it is written, or on the day it lapses. Nothing happens in between.**

Measured on 2026-09-26, mykronos carries 4,228 acceptances:

1. **No one approves anything.** Any `admin` credential writes an acceptance. The person who wants
   the finding gone is the person who decides it may stay. There is no approver role and no notion
   of authority scaled to severity. Six criticals were accepted by the same actor who requested it.
2. **No one owns them.** All 4,228 carry one owner: the repository-owner fallback (spec 24 §1.2),
   not a person who agreed to the risk.
3. **Nothing tracks the way out.** An acceptance is not linked to the work that would end it:
   an upgrade, a rebuild, a vendor release to watch for. Issue routing handles only *open* findings,
   and is switched off anyway since #663.
4. **Premises are prose.** "The database publishes no host port" and "ZAP runs in daemon mode, so
   its GUI never starts" are true today and checkable by machine. Nothing checks them. If port 5432
   is published tomorrow, the acceptance stays valid until its date.
5. **Expiry is silent.** `sweep_acceptances` returns a lapsed finding to `open` with no
   notification, no audit entry, and no record that a decision ran out rather than being renewed.
6. **The scope is a status on a row.** An acceptance is `status = accepted_risk` on each finding, so
   "one decision about a vendor's image" is written 3,647 times and cannot be reviewed, renewed or
   revoked as the one thing it is.

None of this is a missing scanner. Each is a missing *record* — the decision itself — and the
machinery that keeps that record honest.

## 0a. What "compliance with 800-53" means here

This platform cannot make an organisation compliant with NIST SP 800-53; controls are implemented by
organisations, and several below are organisational by nature (who the authorizing official is, what
the risk tolerance is). What it can do is **implement the technical portions of the controls, hold
the organisation-defined parameters as reviewed policy, and produce the evidence an assessor asks
for.** Every section below names the control it serves, and §11 is the mapping in one table.

The model follows 800-53 Rev. 5 and SP 800-37 Rev. 2 (the RMF): a finding is a weakness; the
response to it is a **risk response** (RA-7); a response other than remediation is a **risk
acceptance** that only an **authorizing official** may take (CA-6, PM-9, PM-10); every weakness not
yet remediated is tracked on a **Plan of Action and Milestones** (CA-5, PM-4); and the premise the
acceptance rests on is **continuously monitored** (CA-7, CA-7(4)). Where FedRAMP has operationalised
the same controls — deviation request types, vendor-dependency check-ins — this spec borrows the
shape, and says so.

## 1. The risk acceptance record

### 1.1 What ships

A new entity, **`RiskAcceptance`**, in the relational store beside `RepoOnboarding`. It is the unit
of decision. Findings point at it; it does not live on them.

| field | purpose | control |
|---|---|---|
| `id` | stable identifier, referenced from findings and POA&M items | CA-5 |
| `repo_full_name` | the system boundary the decision is about | CA-6 |
| `scope` | what the decision covers (§1.2) | RA-7 |
| `response` | `accept` \| `mitigate` \| `transfer` \| `avoid` (§1.3) | RA-7 |
| `deviation_type` | `vendor_dependency` \| `risk_adjustment` \| `operational_requirement` (§1.3) | RA-7, CA-5 |
| `justification` | the words — why this is true *here* | RA-7 |
| `residual_likelihood`, `residual_impact` | the risk that remains, after controls, on the RA-3 scale | RA-3 |
| `residual_severity` | derived; drives authority (§2) and scoring (§8) | RA-3, PM-9 |
| `premises[]` | the facts the decision rests on, each monitorable (§4) | CA-7(4) |
| `compensating_controls[]` | each names a control ID, where it is implemented, and its monitor (§4) | PL-2, CA-2 |
| `milestones[]` | the POA&M plan out (§3) | CA-5 |
| `risk_owner` | a named person who answers for it — never a fallback | PM-9, RA-7 |
| `requested_by`, `approved_by` | two identities; §2 governs when they may be one | AC-5, CA-6 |
| `status` | lifecycle (§1.4) | CA-5 |
| `effective_at`, `review_by`, `expires_at` | review is before expiry, not at it | CA-7 |
| `renewal_count`, `first_effective_at` | a renewed decision is still the same exposure | SI-2(3) |
| `tracking_ref` | the private work item that ends it (§5) | PM-4 |

`findings.accepted_risk_id` references it. `status = accepted_risk`, `accepted_until` and
`accepted_reason_code` on the finding become **derived** from the linked record, so the Oracle, the
sweep and the dashboard keep working unchanged during migration.

### 1.2 Scope: one decision, many findings, never more than it names

A scope is a **predicate over finding identity**, stored as data and evaluated, not a list of IDs:

```yaml
scope:
  capability: containers
  image: ghcr.io/zaproxy/zaproxy        # image repository (D-127), required for containers
  rule_ids: ["*"]                        # or an explicit list
  severities: [critical, high, medium, low]
  fixed_version: absent                  # only findings with no published fix
```

- **A finding enters scope only if the predicate says so when the finding is first seen.** A new
  CVE in an accepted image does not inherit the acceptance by default; it lands in a *scope-drift*
  queue for the risk owner (§4.3). This is exactly the leak D-127 removed at the identity layer —
  a decision about one thing silently covering another — and it must not come back at the decision
  layer.
- `image` is required for container scopes. `file_path` and `rule_id` are required for code scopes.
  A scope that would match every finding in a repository is refused.

### 1.3 Responses and deviation types (RA-7)

RA-7 names four responses. Only `accept` produces an acceptance; the others are recorded so that the
register can show *why* a weakness is not being remediated on its default timeline.

| response | meaning | produces |
|---|---|---|
| `mitigate` | remediate — the default | a POA&M item with a fix milestone; no acceptance |
| `accept` | carry the residual risk for a stated period | acceptance + POA&M item |
| `transfer` | another party carries it (a vendor under contract, an insurer) | acceptance with a named counterparty |
| `avoid` | remove the component or capability | POA&M item whose milestone is removal |

Accepted risks carry a **deviation type**, borrowed from FedRAMP's deviation-request categories
because they correspond to different evidence and different re-checks:

| deviation type | today's reason code | what must be true | re-check |
|---|---|---|---|
| `vendor_dependency` | `no_vendor_fix` | no fix exists upstream | every scan (a fix appears → reopen); vendor check-in milestone every 30 days |
| `risk_adjustment` | `not_exploitable_here`, `compensating_control` | residual severity is lower than scanner severity, for a stated, checkable reason | the premise monitors in §4 |
| `operational_requirement` | `cost_exceeds_risk` | the fix would break something the mission needs | review at every milestone; never for critical residual |

`false_positive` stays a separate disposition. It is not a risk response and never produces an
acceptance: a finding that is not real has nothing to accept.

### 1.4 Lifecycle

```
draft ─► pending_approval ─► active ─► review_due ─► renewed ─► active …
                │                │           │
                ▼                ▼           ▼
             rejected     premise_failed   expired ─► (findings reopen)
                          revoked
                          closed  (all findings remediated — the good ending)
```

- `review_due` opens at `review_by` (default: 14 days before `expires_at`). It is a working state,
  not a lapse: the risk owner re-attests, updates evidence, and either renews, closes or lets it
  expire.
- `premise_failed` is entered automatically (§4) and reopens every finding in scope immediately. It
  is not a date-driven expiry: the decision was wrong from the moment the monitor failed.
- **Every transition is an audited event** (§7), including the sweep's. Today's sweep is silent.

## 2. Authority and separation of duties (CA-6, PM-9, PM-10, AC-5)

### 2.1 What ships

- **Approval is a spec 34 duty.** Who may approve an acceptance, how many approvals it needs, and
  whether an agent other than the requester may be the independent approver are the
  `risk_acceptance` duty's tiers in `approval-policy-v1.yaml` (spec 34 §3), tiered by residual
  severity. This spec does not define its own roles or approval rules; it is the first consumer of
  that engine. The default tiers: critical is human-only with a cooling-off; high, medium and low
  accept a human or, **only under a delegation the operator has granted**, an independent agent
  (spec 34 §2, §5).
- `risk_owner` is a field on the record — the person who answers for the risk — not an approval role.
- **The acceptance limits stay here**, as the organisation-defined parameters PM-9 asks for,
  reviewed in a pull request like every other policy value:

```yaml
risk_acceptance:
  max_duration_days:         # unchanged from spec 24 / the checklist
    critical: 30
    high: 90
    medium: 180
    low: 365
  max_renewals:              # beyond this, the answer is remediation, avoidance or re-architecture
    critical: 1
    high: 2
    medium: 4
    low: null
  review_lead_days: 14
  refuse:
    kev_listed: true         # an actively exploited CVE is not accepted, only mitigated (§2.2)
    critical_operational_requirement: true
  risk_tolerance:            # PM-9 / PM-28: the most residual risk a system may carry
    max_residual_score: 30   # Oracle points (§8); exceeding it blocks new acceptances
```

### 2.2 Refusals the platform enforces

- **KEV-listed CVEs are not accepted.** A CISA KEV entry is evidence of active exploitation with an
  externally set due date (spec 24 §2). The response is `mitigate` or `avoid`, never `accept`.
  An acceptance whose CVE *joins* KEV while active is moved to `premise_failed` (§4.2) — the threat
  premise it rested on no longer holds (SI-5).
- **Residual critical cannot be `operational_requirement`** (today's `cost_exceeds_risk` rule,
  kept).
- **An acceptance beyond `max_renewals` is refused.** A critical renewed twice is not a decision
  with a premise; it is an unfunded remediation, and the register should say so as an overdue
  POA&M item instead.
- **Beyond the risk tolerance, new acceptances are refused** until residual risk comes down. This is
  what stops "accept everything" from being a strategy (§8 makes the tolerance reachable).

### 2.3 Separation of duties, including on a single-operator estate

AC-5 wants the requester and the approver to be different parties. Spec 34 enforces that for every
tier — the requester is never an approver — and widens what "different party" can mean: an agent
the operator has chosen to trust, running independently of the requester, can be the second party
for the tiers where a delegation allows it (spec 34 §5). Most acceptances an agent proposes can
therefore get a genuine independent check without waiting on the one human.

**What remains is the case where the human is both sides:** the operator requests, and a
human-only tier (critical, by default) needs a human approver. This estate has one human. Enforcing
two-person approval there would make every critical acceptance impossible, which in practice means
they would be written as `false_positive` instead — the worst outcome. So for that case AC-5 is met
the way small systems legitimately meet it, and the platform records that it is being met this way
rather than pretending:

- `separation_of_duties: single_operator` in policy, which the SSP export (§9) states verbatim
  as a documented deviation from AC-5 with its compensating measures;
- a **cooling-off interval** (default 24 hours for critical, 4 for high) between request and
  approval by the same person, so an acceptance is never written in the same breath as the
  frustration that prompted it;
- approval requires re-stating the premise in the approver's own words, captured separately from
  the request;
- every same-person approval is flagged in the audit trail and counted on the governance page.

## 3. Plan of Action and Milestones (CA-5, PM-4)

### 3.1 What ships

Every weakness that is not remediated inside its spec 24 target, and every active acceptance, has a
**POA&M item**. This is the register an assessor asks for first.

- One item per acceptance (not per finding), plus one per open finding group past its `due_at`.
- **Milestones are required**, with dates, and at least one must end the weakness:
  `vendor_dependency` → "check vendor for fix" every 30 days and "apply fix within N days of
  release"; `operational_requirement` → the change that would remove the constraint;
  `risk_adjustment` → the date the compensating control is re-assessed (CA-2).
- **A missed milestone is overdue**, surfaced like an overdue finding (spec 24 §2.4) and scored
  (§8). A POA&M item whose milestones are all in the past is the register saying the plan failed.
- **Automated currency (CA-5(1)).** Milestones close themselves when evidence arrives: a vendor
  check-in closes when the scan shows a fixed version; a remediation milestone closes when the
  findings in scope close.

### 3.2 Export

- **OSCAL** `plan-of-action-and-milestones` JSON (NIST OSCAL 1.1), one document per system, with
  each item's `related-observations` pointing at the findings and `risks` carrying the acceptance.
- A FedRAMP-template-shaped CSV for teams that need the spreadsheet.
- Both generated on demand and on a monthly schedule, and archived with a content hash (§7).

## 4. Premise monitoring (CA-7, CA-7(4), CA-2)

### 4.1 What ships

A premise is a **typed, checkable assertion** with a monitor. Free text stays for the justification;
premises are what the platform re-evaluates.

| premise type | asserts | evidence source (exists today) |
|---|---|---|
| `no_fixed_version` | the scan names no fix | every containers / Atlas scan |
| `port_not_published` | a container publishes no host port / binds loopback only | `docker inspect` via host-controls evidence |
| `firewall_scope` | a host firewall rule restricts a port to named ranges | `Get-HostControlEvidence.ps1` (it exists for the registry, D-109) |
| `image_role` | the image is a `tool`, not a `service` | `estate_images` compose role (x-mykronos-role) |
| `container_command` | the running command matches (e.g. `zap.sh -daemon`) | `docker inspect` |
| `not_internet_facing` | the service is not published through the tunnel | tunnel ingress config |
| `not_kev_listed` | the CVE is not in CISA KEV | threat-intel refresh |
| `epss_below` | EPSS stays under a threshold | threat-intel refresh |
| `path_unreachable` | the vulnerable function is not reachable | Atlas reachability, where it can answer |

Each compensating control names its **800-53 control ID** (e.g. `SC-7` for a firewall scope,
`CM-7` for least functionality) and one or more premises as its monitor. "A control nobody can point
at cannot be checked when it is removed" — the checklist's own words — becomes a requirement: a
`risk_adjustment` without at least one monitorable premise is refused.

### 4.2 On failure

- Monitors run daily and after every relevant scan. A failing premise moves the acceptance to
  `premise_failed`, reopens every finding in scope with a note naming the failed premise, notifies
  the risk owner and the approver, and opens (or reopens) the tracking item.
- **A monitor that cannot run is not a pass.** "Could not evaluate" is its own state, surfaced on
  the governance page and counted in the score — the same rule D-126 applied to the deploy gate
  (fail open, but loudly, and never silently equal to success).

### 4.3 Scope drift

A new finding that matches an accepted scope's image and rule pattern but was not in scope when
approved is **not** auto-covered. It enters a drift queue for the risk owner, who either extends the
acceptance (which counts as a change requiring the same authority) or lets the finding stand open.

## 5. Follow-up work items (PM-4)

- Every POA&M item links a **tracking issue in a private tracker**. Never the public mykronos
  repository: #663 is the record of what an estate-wide CVE inventory looks like when it is filed
  publicly.
- **One issue per acceptance**, not per finding, with the milestones as a checklist and the scope
  summarised — 3,647 ZAP findings are one issue, not 3,647.
- Filing is **rate-limited and capped** per sweep (the #663 lesson), and the router refuses any
  target repository whose visibility is public.
- Closing the issue does not close the acceptance; evidence does (§3.1). The issue is where the
  human work is discussed, not where the state lives.

## 6. Notification and escalation (CA-7, PM-4)

| event | who | when |
|---|---|---|
| request awaiting approval | approver | on request; daily digest while pending |
| review due | risk owner | `review_by`, then 7 days and 1 day before expiry |
| premise failed / monitor cannot run | risk owner + approver | immediately |
| CVE in scope joins KEV | risk owner + approver | immediately (it will already be `premise_failed`) |
| milestone overdue | risk owner; approver after 7 days | daily |
| acceptance expired unrenewed | risk owner + approver | on expiry, with the reopened count |
| scope drift | risk owner | daily digest |

Delivered through the existing notifier. A notifier with no transport configured is reported at
startup as the digest already is (#412), not left to fail silently.

## 7. Audit and evidence (AU-2, AU-3, AU-6, AU-9, AU-10, AU-11)

- **Every lifecycle transition and every monitor result is an audit event** (AU-2), with actor,
  role used, before/after state, the premise evaluated and its evidence (AU-3). Today the expiry
  sweep writes none; after this spec it writes one per acceptance it expires.
- **Append-only and tamper-evident (AU-9, AU-10).** Acceptance events are hash-chained — each
  event carries the hash of the previous one for the same acceptance — so an edited history is
  detectable. Approvals carry the approver's re-statement of the premise, which is what makes
  non-repudiation more than a username in a column.
- **Evidence snapshots** (the `docker inspect` output, the firewall rule, the scan that showed no
  fix) are stored with a content hash against the event that used them.
- **Retention (AU-11)** is an organisation-defined parameter in policy; the default is the life of
  the system plus three years, because an assessor asks what was accepted and why long after the
  finding is gone.
- **Review (AU-6).** A monthly acceptance-review report: new, renewed, expired, failed, same-person
  approvals, and acceptances past `max_renewals`.

## 8. Scoring (Oracle)

The residual term (spec 09, `modifiers.accepted_risk.residual`) keeps its shape and changes three
things, because the audit on 2026-09-26 showed accepted risk could never move a verdict:

1. **The residual cap reaches the review threshold.** `residual_cap` rises from 15 to 30, and the
   risk tolerance (§2.1) is expressed in the same points, so "too much accepted risk" becomes a
   state the gate can report.
2. **Weight by deviation type and evidence.** A `risk_adjustment` whose premises are all passing
   costs the base residual weight. `vendor_dependency` costs 1.5×, since it is unmitigated by
   construction. `operational_requirement` costs 2×. A premise that cannot be evaluated costs the
   finding's full *open* weight until it can.
3. **Weight by image role.** Findings in an image whose compose role is `tool` (§4.1) cost 0.25× —
   a throwaway scanner container is not the production backend — and the role is itself a premise,
   so reclassifying a service as a tool to lower the score fails its own monitor.

Overdue milestones add a term alongside spec 24's `overdue_findings`.

## 9. Reporting

- **SSP fragment** (PL-2): the risk acceptance procedure, the authority matrix, the risk tolerance,
  and the AC-5 deviation from §2.3, rendered from policy — so the document cannot drift from what
  the platform enforces.
- **POA&M** (CA-5): §3.2.
- **Governance page**: acceptances by state, deviation type and residual severity; approvals by
  same-person flag; premises failing or not evaluable; time-in-acceptance and renewal counts
  (SI-2(3)'s benchmarks, measured from `first_effective_at`, so renewal does not reset the clock).
- **Unsupported components (SA-22).** An image whose upstream is archived or unmaintained — MinIO on
  2026-09-25 — cannot be accepted as `vendor_dependency`: there is no vendor to depend on. The
  response is `avoid` (replace it) with a milestone, which is what D-129 did by hand.

## 10. Migration of the existing 4,228 acceptances

Not bulk-converted into approved decisions — that would manufacture approvals nobody gave, the same
objection spec 24 §3.3 made to synthetic dates.

1. **Group** the current acceptances into proposed `RiskAcceptance` records by
   (repository, image or file, deviation type, justification text). Today's register collapses to a
   few dozen groups: ZAP no-fix, postgres no-fix, the upgraded-image dependency groups, the
   own-image Debian groups, and so on.
2. Create each as **`pending_approval`** with `status: legacy`, the original acceptance's dates
   preserved, and its prose justification carried over. Proposed premises are attached where the
   platform can infer them (`no_fixed_version`, `port_not_published`), for the approver to confirm.
3. Findings keep their current `accepted_risk` status until their existing `accepted_until`, so no
   finding reopens because of the migration itself.
4. A legacy record not approved by its original expiry lapses normally and its findings reopen —
   the same outcome as today, now with a notification and an audit event.

## 11. Control mapping

| Control | Title (Rev. 5) | Implemented by | Organisation-defined parameters |
|---|---|---|---|
| **RA-3** | Risk Assessment | residual likelihood × impact per acceptance (§1.1) | scale |
| **RA-5** | Vulnerability Monitoring and Scanning | the existing lanes; scope drift (§4.3) | — |
| **RA-7** | Risk Response | response + deviation type (§1.3) | — |
| **CA-2** | Control Assessments | compensating-control re-assessment milestones (§3.1, §4) | assessment frequency |
| **CA-5** | Plan of Action and Milestones | POA&M items (§3) | update frequency |
| **CA-5(1)** | Automation Support for Accuracy and Currency | evidence-driven milestone closure (§3.1) | — |
| **CA-6** | Authorization | the `risk_acceptance` duty's human tiers; delegated agent approval under spec 34 §5 (§2) | who the AO is; which tiers are delegable |
| **CA-7**, **CA-7(4)** | Continuous Monitoring; Risk Monitoring | premise monitors (§4), notifications (§6) | monitoring frequency |
| **PM-4** | Plan of Action and Milestones Process | tracking items and escalation (§5, §6) | — |
| **PM-9**, **PM-28** | Risk Management Strategy; Risk Framing | authority matrix, risk tolerance (§2.1) | tolerance, authority |
| **PM-10** | Authorization Process | approval workflow (§1.4, §2) | — |
| **PL-2** | System Security and Privacy Plans | SSP fragment (§9) | — |
| **SI-2**, **SI-2(3)** | Flaw Remediation; Time to Remediate | spec 24 targets; time-in-acceptance (§9) | benchmarks |
| **SI-5** | Security Alerts, Advisories, and Directives | KEV/EPSS premises (§2.2, §4.1) | — |
| **SA-22** | Unsupported System Components | refusal of `vendor_dependency` for abandoned upstreams (§9) | — |
| **AC-5** | Separation of Duties | requester ≠ approver, or the documented single-operator deviation (§2.3) | which duties separate |
| **AU-2, AU-3, AU-6, AU-9, AU-10, AU-11** | Event Logging; Content; Review; Protection; Non-repudiation; Retention | §7 | retention period, review frequency |
| **CM-8** | System Component Inventory | per-image scope requires the derived estate inventory (D-127, #502) | — |

## 12. Phasing

1. **Record and authority.** `RiskAcceptance`, scopes, approval through spec 34's engine (its
   phases 1–2 are a prerequisite), the single-operator deviation, audited transitions including the
   sweep. Migration §10 steps 1–2.
2. **POA&M and follow-up.** Milestones, overdue state, private tracking issues, OSCAL/CSV export.
3. **Premise monitoring.** The premise types in §4.1, starting with the four whose evidence already
   exists (`no_fixed_version`, `port_not_published`, `image_role`, `not_kev_listed`); failure and
   "cannot evaluate" handling; scope drift.
4. **Notification, scoring, reporting.** §6, §8, §9.

Phase 1 alone closes gaps 1, 2, 5 and 6 from §0. Phases 2 and 3 close 3 and 4.

## 13. Acceptance criteria

- An acceptance cannot be created without a named risk owner, a deviation type, a residual
  severity, at least one milestone that ends the weakness, and — for `risk_adjustment` — at least one
  monitorable premise.
- No acceptance can be approved by its requester (spec 34). A tier that allows delegated agent
  approval accepts it only from an agent independent of the requester under an active delegation;
  a human-only tier approved by the same human who requested it is refused before the cooling-off
  interval elapses and is flagged in the audit trail.
- A CVE listed in KEV cannot be accepted; an accepted CVE that joins KEV moves its acceptance to
  `premise_failed` and reopens its findings within one threat-intel refresh.
- Publishing a host port on a container whose acceptance rests on `port_not_published` reopens that
  acceptance's findings within one monitor cycle, with the failed premise named.
- A premise monitor that cannot run is reported as "not evaluated", never as passing, and the
  acceptance is scored at the findings' open weight until it runs.
- A new CVE in an accepted image does not inherit the acceptance; it appears in the drift queue.
- Every lifecycle transition, including an expiry by the sweep, produces a hash-chained audit event;
  altering a stored event breaks verification of every later one.
- The POA&M export validates against the OSCAL 1.1 POA&M schema and includes every active
  acceptance and every open weakness past its due date.
- Tracking issues are filed only to private repositories, at most one per acceptance, and never more
  than the configured cap per sweep.
- An acceptance renewed beyond `max_renewals` is refused, and time-in-acceptance is measured from
  `first_effective_at` across renewals.

## 14. Out of scope

- Deciding who the authorizing official is, or what the risk tolerance should be. These are
  organisation-defined parameters; the platform enforces whatever policy says and reports it.
- Inheriting controls from a cloud provider or common-control provider (CA-6(2) and friends). There
  is no inherited boundary in this estate today.
- Replacing the Knowledge Store's learning from `false_positive` (spec 11). An acceptance still
  teaches nothing about a rule, and this spec does not change that.
