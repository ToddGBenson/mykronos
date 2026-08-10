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
   - Repository contents: **Read & write** (to create branches and commit
     non-workflow files)
   - Workflows: **Write** (to commit and delete files under
     `.github/workflows/`) — see the note below; this is **not** covered by
     `contents: write`
   - Pull requests: **Read & write** (to open/comment on PRs)
   - Checks: **Read & write** (for Aegis/Oracle to post check runs)
   - Actions: **Read & write** (to enable/monitor workflow runs)
   - Metadata: **Read-only** (mandatory baseline)
   - Secrets: **Write** (to create and update the ingestion token secret it
     manages, spec 05 §4) — see the note below. Mykronos never *reads* a repo
     secret's value, and GitHub's API makes that structural rather than a
     promise. Workflow-level secrets needed by scanners (e.g. a Snyk token)
     remain the repo owner's responsibility to configure.
   > **Why `workflows: write` is listed separately.** GitHub treats files under
   > `.github/workflows/` as privileged and gates them behind their own
   > permission. An installation token holding only `contents: write` is
   > refused when it tries to create, update or delete a workflow file — the
   > Contents API rejects the write outright. Since committing workflow YAML is
   > the Workflow Installer's entire purpose (spec 03), the App is inoperable
   > without this permission: onboarding would complete, capabilities would
   > save, and every install PR would then fail at the commit step.
   >
   > The permission is write-only in GitHub's model (there is no
   > `workflows: read`); reading workflow files is covered by `contents: read`.

   > **Why `secrets: write` cannot be avoided.** An earlier draft of this spec
   > claimed the App could create named secrets with "no access" to Secrets,
   > on the reasoning that it only needed to *write* the ones it manages. That
   > is not how the permission is shaped: the Actions Secrets API requires
   > `secrets: write` for any create-or-update, and GitHub grants Secrets as a
   > single permission with no create-only tier.
   >
   > The security *intent* of that draft still holds, but for a better reason
   > than withholding the permission. GitHub's Secrets API never returns a
   > secret's value to anyone — `GET .../actions/secrets/{name}` returns the
   > name and timestamps only. So `secrets: write` genuinely does not confer
   > read: Mykronos cannot exfiltrate a repo's existing secrets even holding
   > it. Values are also libsodium-sealed against the repo's public key before
   > upload (spec 03 §4a), so plaintext never crosses the wire.
   >
   > What the permission *does* confer is the ability to overwrite any named
   > secret in an onboarded repo. See spec 12 §6 for the resulting blast
   > radius, which is the honest reason the App private key is handled the way
   > spec 12 §2 requires.

3. Webhook URL → Mykronos backend `/webhooks/github`.
4. Subscribe to events: `installation`, `installation_repositories`,
   `pull_request`, `workflow_run`, `check_run`, `push`.
5. Set a webhook secret and record it as `MYKRONOS_GITHUB_WEBHOOK_SECRET`.
   GitHub treats this as optional and the App works without it right up until
   the first delivery, which `/webhooks/github` then rejects unsigned. The
   failure reads as a broken tunnel rather than a missing field, so it is
   worth setting at registration and not later.
6. Generate a private key; store per spec 12. Note the App ID and Client ID.

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
| `POST` | `/api/repos` | Idempotently create/update a `RepoOnboarding` from a GitHub installation event or manual admin action |
| `GET` | `/api/repos` | List onboarded repos with status + enabled capabilities |
| `GET` | `/api/repos/{id}` | Detail view of one onboarded repo |
| `PATCH` | `/api/repos/{id}/capabilities` | Update `enabled_capabilities` and trigger the Workflow Installer |
| `DELETE` | `/api/repos/{id}` | Offboard a repo (sets `status=removed`) |
| `POST` | `/webhooks/github` | GitHub App webhook receiver (installation, PR, workflow_run, check_run, push events) |

> **Why `POST /api/repos` and not `/api/repos/onboard`.** An earlier draft of
> this table named the creating call `/api/repos/onboard`, and the first real
> onboarding attempt got a `405` for it — the implementation had always
> mounted create on the collection, alongside the `GET` that lists it. The
> code is the one that is right. A verb in the path buys nothing here when
> the method already carries it, and the split form invites a second question
> nobody wants to answer: whether `POST /api/repos` means something *else*.
>
> The `push` subscription is likewise a correction rather than an addition.
> Spec 08 §3 requires Patchwork to stand down when a person commits to one of
> its fix branches, and `push` is the only event that reveals it —
> `pull_request` does not fire for a commit to an existing branch. Without the
> subscription the guarantee silently does not hold.

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
- **Permission smoke test.** Before any other Phase 1 work is accepted, the
  registered App must be shown to commit a workflow file to a scratch repo and
  create an Actions secret on it, using nothing but an installation token.
  Both operations depend on permissions this spec previously omitted (§4), and
  both fail late and confusingly — at PR-commit time, per repo — if the App is
  registered with the wrong set. Verifying the grant directly is cheaper than
  diagnosing it through the installer.

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
