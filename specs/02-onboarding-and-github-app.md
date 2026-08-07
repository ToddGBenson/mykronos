# Spec 02 — Onboarding & GitHub App

**Status:** Approved for build
**Depends on:** [01 — Architecture](01-architecture.md)

---

## 1. Purpose

Allow a security admin to register one or more GitHub repositories with
Mykronos, and give Mykronos the minimum necessary, auditable, short-lived
access to those repos to install workflows and read results — without ever
storing a long-lived Personal Access Token.

## 2. Why a GitHub App (not PATs)

- A GitHub App's permissions are scoped and explicit (e.g., `contents:write`,
  `pull_requests:write`, `checks:write`, `actions:write`) and reviewable by
  the repo owner at install time.
- Access tokens minted from a GitHub App installation expire in ~1 hour —
  nothing long-lived is stored per repo.
- Installations can be revoked per-repo by the repo owner at any time,
  independent of Mykronos.
- One private key (the App's) is the only long-lived secret in the entire
  system — see spec 12 for its handling.

## 3. Data model

### `Organization`
| Field | Type | Notes |
|---|---|---|
| `id` | UUID | PK |
| `github_org_login` | string | e.g. `example-org` |
| `created_at` | datetime | |

### `RepoOnboarding`
| Field | Type | Notes |
|---|---|---|
| `id` | UUID | PK |
| `org_id` | UUID | FK → Organization |
| `github_repo_full_name` | string | `owner/repo` |
| `github_installation_id` | integer | GitHub App installation id covering this repo |
| `status` | enum | `pending_install`, `active`, `suspended`, `removed` |
| `enabled_capabilities` | JSON array of enums | subset of `sast, dast, secrets, containers, iac, cloud, aegis, atlas, patchwork, oracle` |
| `default_branch` | string | cached from GitHub, used by the workflow installer |
| `onboarded_by` | string | admin's identity (email or GitHub login) |
| `onboarded_at` | datetime | |
| `last_synced_at` | datetime | last time Mykronos confirmed installation is still active |

### `CapabilityConfig`
Per-repo, per-capability configuration overrides (e.g., which branches to
scan, severity thresholds, tool-specific flags). Stored as JSON keyed by
capability name; schema for each capability's config block is owned by that
capability's spec (04, 06, 07, 08, 09).

| Field | Type | Notes |
|---|---|---|
| `id` | UUID | PK |
| `repo_onboarding_id` | UUID | FK |
| `capability` | enum | |
| `config_json` | JSON | validated against a per-capability JSON Schema |
| `updated_at` | datetime | |

## 4. GitHub App registration (one-time, manual, by platform operator)

1. Create a GitHub App in the `example-org` GitHub organization (or the relevant
   org) named e.g. `mykronos-platform`.
2. Required permissions:
   - Repository contents: **Read & write** (to open workflow-install PRs)
   - Pull requests: **Read & write** (to open/comment on PRs)
   - Checks: **Read & write** (for Aegis/Oracle to post check runs)
   - Actions: **Read & write** (to enable/monitor workflow runs)
   - Metadata: **Read-only** (mandatory baseline)
   - Secrets: **No access** — Mykronos never reads or writes repo secrets
     directly; workflow-level secrets needed by scanners (e.g., a Snyk token)
     remain the repo owner's responsibility to configure, or are proxied
     through the ingestion API pattern in spec 05 §4.
3. Webhook URL → Mykronos backend `/webhooks/github`.
4. Subscribe to events: `installation`, `installation_repositories`,
   `pull_request`, `workflow_run`, `check_run`.
5. Generate a private key; store per spec 12. Note the App ID and Client ID.

## 5. Onboarding flow (per repo)

1. Admin clicks "Onboard a repo" in the frontend.
2. Frontend redirects to GitHub's App installation URL
   (`https://github.com/apps/mykronos-platform/installations/new`),
   scoped to the admin's account/org, letting them pick specific repos.
3. GitHub redirects back to Mykronos with an `installation_id` and
   `setup_action=install`.
4. Backend's `/webhooks/github` receives the `installation` (or
   `installation_repositories`) event, and/or the setup callback handles
   the redirect synchronously. Either path calls
   `POST /api/repos/onboard` (see §7) to create/update `RepoOnboarding`
   rows for each newly installed repo, with `status=pending_install`.
5. Admin is shown the capability grid (checkboxes for each of the 10
   capabilities) for the repo and saves selections →
   `enabled_capabilities` updated, `status` stays `pending_install` until
   the workflow-install PR (spec 03) is opened, then flips to `active`
   once merged (detected via the `pull_request.closed` webhook + merged
   flag, matched by PR branch naming convention `mykronos/enable-workflows`).
6. Backend periodically (daily) re-validates each `RepoOnboarding` by
   calling `GET /app/installations/{id}` — if GitHub reports the
   installation was removed, set `status=removed` and stop all
   scheduled activity for that repo.

## 6. Removing/suspending a repo

- Admin can disable a capability at any time → triggers a follow-up PR
  from the Workflow Installer removing/disabling that capability's
  workflow file(s) (spec 03 §5).
- Admin can fully offboard a repo → sets `status=removed`, stops
  Oracle/Dashboard from including it in new computations, but **does not
  delete historical data lake rows** (needed for audit trail) unless the
  admin explicitly requests data deletion (a separate, logged, confirmed
  action — data retention policy is deployment-configurable).
- If the repo owner uninstalls the GitHub App from GitHub's side directly,
  the `installation_repositories` (`removed` action) webhook sets
  `status=removed` automatically.

## 7. API endpoints (backend)

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/repos/onboard` | Idempotently create/update a `RepoOnboarding` from a GitHub installation event or manual admin action |
| `GET` | `/api/repos` | List onboarded repos with status + enabled capabilities |
| `GET` | `/api/repos/{id}` | Detail view of one onboarded repo |
| `PATCH` | `/api/repos/{id}/capabilities` | Update `enabled_capabilities` and trigger the Workflow Installer |
| `DELETE` | `/api/repos/{id}` | Offboard a repo (sets `status=removed`) |
| `POST` | `/webhooks/github` | GitHub App webhook receiver (installation, PR, workflow_run, check_run events) |

All endpoints require an authenticated admin session (see spec 12 §3 for
admin auth — out of scope of GitHub App auth, which is service-to-service).

## 8. Acceptance criteria

- Installing the GitHub App on a new repo results in a `RepoOnboarding` row
  within 60 seconds (via webhook), with `status=pending_install`.
- Selecting capabilities and saving triggers exactly one workflow-install PR
  per save action (no duplicate PRs on repeated saves — see spec 03 §4 for
  idempotency rules).
- Uninstalling the App from GitHub's side is reflected as `status=removed`
  in Mykronos within 24 hours (webhook-driven, with daily reconciliation as
  a fallback).
- No GitHub PAT is ever stored in the Mykronos database or logs.

## 9. Edge cases

- Admin selects a capability for a repo whose language/stack doesn't support
  it (e.g., enabling "Containers" scan for a repo with no Dockerfile) — the
  Workflow Installer PR is still opened; the workflow will simply find
  nothing to scan and no-op successfully (not a hard failure). This is a
  product decision to keep onboarding simple; see spec 04 §6 for per-scanner
  no-op behavior.
- GitHub installation is suspended (not removed) by an org owner — treat
  identically to `removed` for scheduling purposes, but keep
  `status=suspended` distinct in the data model so the dashboard can show
  "temporarily paused" rather than "gone."
- Same repo is installed under two different GitHub orgs (e.g., forked) —
  `github_repo_full_name` + `org_id` together are the uniqueness constraint,
  so this is modeled as two independent `RepoOnboarding` rows.

## 10. Dependencies

- GitHub App must be registered before any onboarding can occur (§4, manual
  one-time setup).
- Spec 03 (Workflow Installer) for what happens after capabilities are saved.
- Spec 12 (Security) for private key storage and admin authentication.
