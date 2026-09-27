# Approvals: how to use them

Specs 33 and 34 made risk acceptance and pull request merge **governed
duties**: someone independent of the requester approves, the platform records
who, and the approval is of exactly the evidence the platform froze. This page
is the operator's runbook. The specs say why.

All calls go to the backend on `127.0.0.1:8100` with the perimeter header
`X-Hub-Token` and a bearer credential. A person uses the admin token; an agent
uses its own `mka_` credential (`POST /api/agents/credentials`).

## Who can approve what

`approval-policy-v1.yaml` is the only source. In short:

| Duty | Tier | Approver |
|---|---|---|
| `risk_acceptance` | critical | a person |
| | high | a person, or a delegated agent of a *different* model family |
| | medium, low | a person, or a delegated agent |
| `pull_request_merge` | governance | a person |
| | production, routine | a person, or a delegated agent |
| `delegation_grant` | any | a person, requested by a person |

The requester never approves their own request. An agent's sub-agents are in
its lineage and cannot approve for it either. Under `single_operator` a person
may approve their own request after the tier's cooling-off; every such
decision is flagged `same_person`.

## Deciding a request

```
GET  /api/approvals?state=pending          what is waiting
GET  /api/approvals/{id}/evidence          the frozen bundle and its digest
POST /api/approvals/{id}/decisions         {"verdict", "rationale", "evidence_digest"}
GET  /api/approvals/{id}/chain             the hash-chained history, verified
```

`verdict` is `approve`, `reject` or `needs_info`. A rationale is required. The
digest must be the one from the evidence call: a decision about anything else
is refused. Requests expire after `request_ttl_hours` (7 days).

## Risk acceptances

`POST /api/risk-acceptances` proposes a record and opens its approval request
in one call; the tier comes from the record's residual severity. Nothing about
the findings changes until the request is approved. A rejected or expired
request closes the record as `not_approved` on the next sweep and releases its
findings.

Legacy row-level acceptances migrate as proposed records:
`POST /api/risk-acceptances/migrate-legacy` with `dry_run` (default true) and
`severities` to stage it.

## Pull requests

`POST /api/approvals/pull-requests` with `{repo, number, statement}`. The
platform reads the diff itself, computes the tier from the files touched
(`change_classes` in the policy), and posts an `independent-review` check run
on the head commit: in progress, then success or failure. The approval covers
that commit only; a new push needs a new request.

The check's summary names the requesting and approving principals. That is
the record an audit cites, because every GitHub action reads as one shared
account.

## Letting an agent approve

1. A person proposes a delegation: `POST /api/approvals/delegations` with the
   duty, tiers, model families and an expiry (at most 90 days).
2. A person approves that request after its one-hour cooling-off.
3. `POST /api/approvals/{id}/independent-review` then starts a
   platform-started reviewer for a request the delegation covers. It needs
   `MYKRONOS_REVIEWER_API_KEY`; without one it answers 503 and the request
   waits for a person.

A share of delegated decisions is sampled for you to review afterwards
(`GET /api/approvals/samples`, `POST /api/approvals/samples/{decision_id}`).
A delegation is suspended when your agreement drops below 90% of recent
samples, or when samples sit unreviewed past 14 days.
