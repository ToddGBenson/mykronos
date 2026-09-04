# Spec 03 — Workflow Installer

**Status:** Approved for build
**Depends on:** [02 — Onboarding & GitHub App](02-onboarding-and-github-app.md)

---

## 1. Purpose

Translate a repo's `enabled_capabilities` selection into actual GitHub
Actions YAML files committed to that repo, via a pull request, so a human
always reviews and merges the change that turns scanning on.

## 2. Workflow template library

A directory `workflow-templates/` in the Mykronos repo holds one Jinja2 (or
equivalent) template per capability that maps to a GitHub Actions workflow:

```
workflow-templates/
├── sast.yml.j2
├── dast.yml.j2
├── secrets.yml.j2
├── containers.yml.j2
├── iac.yml.j2
├── cloud.yml.j2
├── aegis.yml.j2
├── atlas.yml.j2
├── patchwork.yml.j2
└── oracle-gate.yml.j2       # PR-time call into Oracle for a go/no-go check
```

Each template renders to `.github/workflows/mykronos-<capability>.yml` in the
target repo. Templates are parameterized with:

- `${INGESTION_API_URL}` — Mykronos backend ingestion endpoint (spec 05)
- `${REPO_TOKEN_SECRET_NAME}` — name of the repo secret holding the repo's
  ingestion token (see spec 05 §4), fixed at `MYKRONOS_INGESTION_TOKEN`. Every
  capability's workflow references the same secret; the Workflow Installer
  creates it once, on first onboarding. Parameterised rather than hardcoded
  only so a deployment can avoid a name collision with an existing secret.
- Capability-specific config values pulled from `CapabilityConfig.config_json`
  (spec 02 §3), e.g. branch triggers, severity thresholds, tool version pins

## 3. Rendering & PR flow

1. Backend receives a capability-change request (from
   `PATCH /api/repos/{id}/capabilities`, spec 02 §7).
2. For each **newly enabled** capability: render its template, compute the
   target file path, and stage it for the PR.
3. For each **newly disabled** capability: stage a deletion of that
   capability's workflow file (or set it to `if: false` at the job level and
   leave the file, depending on the `--soft-disable` deployment setting —
   default is delete the file so the Actions tab stays clean).
4. Using an installation access token (spec 02 §5), the Workflow Installer:
   a. Ensures the repo's single ingestion secret
      (`MYKRONOS_INGESTION_TOKEN`, spec 05 §4) exists, creating it via the
      GitHub Secrets API on first onboarding only (values are
      libsodium-sealed client-side per GitHub's API requirement — never sent
      in plaintext). Enabling further capabilities adds a **grant** in the
      token registry and touches no secret, so a capability change involves
      no GitHub Secrets call at all and cannot half-apply.
   b. Creates a branch `mykronos/enable-workflows-<timestamp>` off the
      repo's `default_branch`.
   c. Commits the staged file additions/deletions to that branch. Because the
      staged paths are all under `.github/workflows/`, this step requires the
      App's `workflows: write` permission (spec 02 §4) — `contents: write`
      alone is refused by GitHub for these paths, and the failure surfaces
      here rather than at install time.
   d. Opens a PR titled `Mykronos: update security workflows` with a body
      listing exactly which capabilities were added/removed and links to
      this spec set for context.
5. PR is left for a human (repo maintainer or admin) to review and merge.
   Auto-merge is available as an opt-in, per-repo setting
   (`RepoOnboarding.auto_merge_workflow_prs: bool`, default `false`).
6. On webhook `pull_request.closed` with `merged=true` and a head branch
   matching `mykronos/enable-workflows-*`, backend sets
   `RepoOnboarding.status = active` (if it was `pending_install`) and logs
   the change in an audit table (`WorkflowInstallEvent`).

## 3a. Not every repository is scanned by Actions

This spec was written when GitHub Actions was the only way a scan happened, so
"enable a capability" and "install a workflow" were the same act. They are no
longer. Concourse now scans three repositories, and this one has no
`.github/workflows/` at all (spec 16 §4, D-039).

That left the model saying something untrue. `enabled_capabilities` is
documented as "capabilities whose workflow-install PR has actually merged" —
for a Concourse-scanned repository no such PR exists or ever will, and the
capability is enabled all the same.

**Two answers, and it took both (the second added 2026-08-15).** `scanned_by`
below records who scans; and for any repo not scanned by Actions, the
dashboard derives enablement from the capability *grants*, unioned with the
installer's ledger. What may write is what is enabled. Before the union, the
portfolio showed three capabilities per repo while eleven were reporting —
the ledger was never going to move, and every view that read it alone was
wrong the same way.

**A repository declares what scans it: `scanned_by`.**

| Value | Meaning |
|---|---|
| `github_actions` | The installer renders workflows and opens a pull request, exactly as §3 describes |
| `concourse` | A pipeline covers this repository. Enabling a capability grants ingestion and installs nothing |
| `none` | Onboarded and not scanned yet. Findings can still be uploaded by hand |

**`concourse` is the default for new repositories**, because it is what is
true here now. A default that installs Actions workflows into a repository
whose Actions were deliberately removed is a default that undoes a decision.

**What this does *not* do is decide whether a capability is covered.**
`scanned_by` records intent — which system is supposed to scan. Whether it
actually does is a different question with a different answer, and spec 15
§4a.1 already answers it by comparing the pipeline's jobs against what reached
the lake. A repository can declare `concourse`, enable `dast`, and have no
DAST job; that is exactly the `no_job` state, and it stays visible rather
than being papered over by a field that says the intent was good. (Aegis,
Oracle and Patchwork are the exception: they never produce a ScanRun from a
pipeline lane, so they read `event_driven` rather than `no_job` — a working
capability is not a coverage gap.)

The two are worth keeping apart. Intent is what an operator asked for; the
cross-check is what happened. A model that only records the first reports
coverage it does not have, which is the failure this platform exists to
catch.

## 4. Idempotency

- Before rendering, compare the requested `enabled_capabilities` set against
  the **last successfully merged** set for that repo (tracked in
  `RepoOnboarding.enabled_capabilities` only after merge, plus a separate
  `RepoOnboarding.pending_capabilities` field tracking what's been requested
  but not yet merged).
- If a capability-change PR is already open (unmerged) for a repo, a new
  request **updates the existing branch/PR** (force-push the recomputed
  diff) rather than opening a second PR. Store the open PR number on
  `RepoOnboarding.pending_pr_number`.
- If the requested set is identical to the currently active set, no-op
  (return success without opening a PR).

## 5. Disabling a capability

Same PR mechanism as enabling (§3), but the diff removes the workflow file —
for an Actions-scanned repository. For everything else, disabling is the same
one-click grant sync as enabling (§3a): the dashboard's CapabilityManager
PATCHes the capability set and no PR is involved, because there is no
workflow file to remove.

Revocation is decoupled from the PR and happens **immediately**, not on merge:
the capability's grant is removed from the token registry as soon as the admin
disables it (spec 05 §4). The repo's `MYKRONOS_INGESTION_TOKEN` secret is left
in place, since the repo's other capabilities still use it — it is deleted
only on full offboarding.

Decoupling matters: an unmerged removal PR must not leave a capability able to
keep writing findings for days. Conversely a still-installed workflow whose
grant is gone fails loudly with `403` rather than writing quietly, which is
the correct signal that the PR is outstanding.

Historical data lake rows for that capability are retained.

### 5.1 Auto-merge is refused by design

Mykronos does not merge the pull requests it opens — not the install and
removal PRs above, and not the fix PRs of spec 08. There is no setting for it,
and the absence is structural rather than a default: spec 08 §3 gives
`GitHubClient` no merge method, and a test asserts no method whose name
contains "merge" exists on the interface or on either implementation.

This is stated here because an `auto_merge_workflow_prs` option was once
stored on the onboarding record and returned by the API. Nothing consumed it
and nothing could, so setting it changed only what an operator believed. It
was removed in D-095; the column is retired on start by
`Database.drop_retired_columns`.

Re-introducing auto-merge is a design change that has to reverse D-095 and
spec 08 §3 first. It is not a configuration gap.

## 6. Updating templates (versioning)

- Every rendered workflow file includes a header comment:
  `# Generated by Mykronos Workflow Installer — template version: <semver>`.
- When a template's semver bumps (e.g., a scanner's action version is
  updated org-wide), the backend can run a **bulk resync** job: for every
  active repo with that capability enabled, re-render and open an update PR
  if the rendered content differs from what's currently in the repo
  (detected by comparing file content via the GitHub Contents API, not by
  trusting the stored version string alone, in case someone hand-edited the
  file).
- This bulk-resync pattern is directly modeled on the "downstream repo
  sync" mechanism already proven internally (a manifest of repos + a
  scheduled job that opens sync PRs on each).

## 7. Acceptance criteria

- Enabling a capability for a repo results in exactly one open PR containing
  exactly the new workflow file(s) and the corresponding repo secret being
  created, within 2 minutes of the API call.
- Re-requesting the same capability set with no changes does not open a
  duplicate PR.
- Merging the PR flips `RepoOnboarding.status` to `active` within 60 seconds
  (webhook-driven).
- Disabling a capability removes its workflow file and revokes its secret
  once the corresponding PR is merged, without touching other capabilities'
  files/secrets in the same repo.
- A template version bump can be bulk-applied across all repos with that
  capability enabled via one admin action, producing one PR per affected
  repo.

## 8. Edge cases

- Target repo has branch protection requiring status checks the new
  workflow itself provides (chicken-and-egg on first run) — document this
  in the PR body; not automatically resolved by Mykronos (admin/maintainer
  responsibility, standard GitHub behavior).
- Target repo already has a hand-written workflow file at the same path
  Mykronos would use — Workflow Installer must detect a path collision
  before staging and abort with a clear error surfaced to the admin,
  rather than silently overwriting a human's file.
- GitHub API rate limits during a bulk resync — Workflow Installer must
  queue and throttle PR creation (see spec 05 §6 for the shared rate-limit
  handling pattern used across all GitHub API callers).

## 9. Dependencies

- Spec 02 for installation tokens and `RepoOnboarding` data model.
- Spec 05 §4 for how per-repo ingestion secrets are provisioned.
- Spec 04, 06, 07, 08, 09 for the actual content of each capability's
  workflow template.
