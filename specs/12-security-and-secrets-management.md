# Spec 12 — Security & Secrets Management

**Status:** Approved for build
**Depends on:** [02 — Onboarding & GitHub App](02-onboarding-and-github-app.md), [05 — Data Lake](05-datalake.md)

---

## 1. Purpose

Define the security requirements that apply across the whole platform —
who can authenticate as what, how every secret is stored, and what the
blast radius of any single credential compromise is. Every other spec's
security-relevant details point back here as the source of truth.

## 2. Identities in the system

| Identity | Used for | Lifetime | Storage |
|---|---|---|---|
| **GitHub App private key** | Minting installation access tokens (spec 02 §4) | Long-lived (rotated on a schedule, e.g. annually, or immediately on suspected compromise) | Deployment secret manager / KMS — **never** in the database, never in logs, never in a repo |
| **GitHub App installation access tokens** | All GitHub API calls the platform makes on behalf of an onboarded repo (opening PRs, creating secrets, posting checks) | ~1 hour, minted on demand | In-memory only, never persisted |
| **Per-repo ingestion token** (one per repo, carrying capability grants) | Workflow → Ingestion API auth (spec 05 §4) | 90-day rotation, with a 24h dual-validity overlap so in-flight workflows are not broken | Stored **only** as a GitHub Actions repo secret (encrypted by GitHub, readable by that repo's workflows); the platform stores the token's SHA-256 and metadata, never the plaintext, after issuance |
| **Admin/human user sessions** | Dashboard/admin UI access | Session-length (SSO-backed, see §3) | Standard session/JWT handling; no long-lived admin API keys in v1 |
| **AI gateway credentials** (for Aegis/Patchwork/RAG embeddings) | LLM calls | Deployment-managed, org-provided | Deployment secret manager, injected as environment variables to the backend service only — never exposed to onboarded-repo workflows directly |

## 3. Human user authentication

- Admin/dashboard access uses the organization's existing SSO (SAML/OIDC)
  — Mykronos does not implement its own username/password system.
- Role-based access control (RBAC): `admin`, `viewer`, and optional
  `repo-scoped` roles (spec 10 §5). Role assignment is managed by existing
  org identity groups where possible (e.g., map an SSO group to the
  `admin` role) rather than a bespoke per-user permission UI, to avoid
  building a second identity system to maintain.

## 4. Secret storage principles

1. **No long-lived GitHub PAT is ever created or stored anywhere in this
   system.** (Restated from spec 02 — this is a hard requirement, not a
   preference.)
2. Every secret that must be stored long-term (GitHub App private key, AI
   gateway credentials) lives in a dedicated secret manager (deployment
   choice: HashiCorp Vault, cloud KMS + Secrets Manager, or equivalent) —
   never in application config files, environment variable dumps in logs,
   or the application database.
3. The ingestion token (spec 05 §4) is the **only** secret Mykronos ever
   places inside a customer/onboarded repo, one per repo, bound to that repo.
   Compromise of one repo's CI cannot read or write another repo's data and
   cannot reach the GitHub App's own credentials.

   Note what this deliberately does *not* claim. Scoping below the repo — a
   separate token per capability — would be decorative, because GitHub
   Actions repository secrets are readable by every workflow in the repo: a
   compromised runner holds all of that repo's secrets whatever they were
   provisioned for. The repo is the smallest boundary GitHub actually
   enforces, so it is the boundary the design uses. Capability granularity is
   retained where it *is* enforceable — server-side grants, revocable
   independently (spec 05 §4).
4. All secrets in transit use TLS; the Ingestion API and admin API are
   never exposed without TLS termination.
5. Secret rotation is automatic and does not require manual intervention
   for the 90-day ingestion token cycle (spec 05 §4) — manual intervention
   is reserved for the rare GitHub App key rotation. Automatic also means
   *non-disruptive*: rotation uses a dual-validity overlap window so a
   workflow that read the old secret before the swap still completes. A
   rotation scheme that reddens CI is one operators will disable.

## 5. Data handling & privacy

- No client/production data is ever required for Mykronos to function —
  it processes security tool output (findings), not application data
  itself. Scanners should be configured (per each capability's own
  documentation) to avoid capturing sensitive payload data in finding
  descriptions where avoidable (e.g., DAST findings should redact request
  bodies containing potential PII where the tool supports it).
- `raw_finding_json` (spec 05 §3) and raw tool output (spec 05 §7) may
  still incidentally contain sensitive strings (e.g., a secret detected by
  the Secrets scanner necessarily includes some context) — access to raw
  output is restricted to `admin` role only in the dashboard (§3), never
  shown to `viewer`/`repo-scoped` roles by default.
- Data retention (spec 05 §7) and the right to request deletion of a
  repo's historical data (spec 02 §6) must be honored as explicit,
  logged, admin-only actions.

## 6. Least privilege — GitHub App permission review

Restated from spec 02 §4 for completeness: the App requests
`contents: write`, `workflows: write`, `pull_requests: write`,
`checks: write`, `actions: write`, `metadata: read`.

`workflows: write` is required because GitHub gates files under
`.github/workflows/` behind their own permission — `contents: write` is
refused for those paths. Committing workflow YAML is the Workflow Installer's
entire purpose, so this is not an optional addition (spec 02 §4, spec 03 §3).

`secrets: write` is required to provision the ingestion token secret (spec 05
§4). An earlier draft of this section asserted the App could do that with no
Secrets permission; it cannot — the Actions Secrets API requires
`secrets: write` for any create-or-update, and GitHub offers no create-only
tier. The claim that Mykronos never reads repo secrets is still true, but it
is guaranteed by GitHub rather than by the permission grant: the Secrets API
never returns a value to any caller, so `write` here does not imply read.

### 6.1 Blast radius of the App private key

Stating this plainly because §2 calls the App private key the only long-lived
secret in the system, and the permission set above determines what its
compromise actually costs.

An attacker holding the App private key can mint installation tokens for every
onboarded repo, and with them:

| Can | Cannot |
|---|---|
| Commit arbitrary workflow files to any onboarded repo (`workflows: write`) | Read any existing repo secret's value — the API does not return them |
| Overwrite any named Actions secret, including ones Mykronos does not manage (`secrets: write`) | Merge a pull request, or administer the repo |
| Commit arbitrary non-workflow code (`contents: write`) | Reach the data lake's contents — ingestion tokens are write-only and per-repo |
| Open PRs and post checks | Act on a repo that has not installed the App |

The first row is the serious one, and the combination is worse than either
alone: an attacker who can write a workflow can run arbitrary code in that
repo's CI, and code running in CI *can* read that repo's secrets. So while
Mykronos cannot read secrets through the API, a compromised App key can reach
them indirectly, in any onboarded repo, by writing a workflow that does.

Three consequences, all already required elsewhere and restated here as the
reasons they exist rather than as house style:

1. The private key lives in a secret manager or KMS and never in the database,
   application config, or logs (§4.2). Rotation on suspected compromise is
   immediate, not scheduled (§2).
2. Every installation-token mint is logged with the repo and the operation it
   was minted for, so anomalous minting is detectable in the audit log (§7).
   Tokens themselves stay in memory and are never persisted (§2).
3. Repo owners retain unilateral revocation: uninstalling the App from
   GitHub's side cuts access immediately and independently of Mykronos
   (spec 02 §6). This is a real control, not a formality — it is the only one
   that works if the platform itself is the thing compromised.

This blast radius is inherent to any tool that installs CI workflows into
other people's repositories. It is not a reason to reject the design, but it
must be stated accurately rather than understated, or the key handling in §2
reads as bureaucratic instead of load-bearing.

## 7. Auditability

- Every write to `RepoOnboarding`, `CapabilityConfig`, `RiskDecision`
  (especially overrides), and `WorkflowInstallEvent` is logged with actor
  identity and timestamp in an append-only audit log table, separate from
  the operational tables, retained per the organization's compliance
  requirements (default: indefinitely, or per deployment policy).
- The audit log itself is read-only via the API (no update/delete
  endpoints) — corrections are additive (a new log entry), never
  destructive edits to history.

## 8. Acceptance criteria

- A code/config review confirms no PAT-shaped credential exists anywhere
  in the codebase, database schema, or default configuration.
- No code path calls the Actions Secrets API for anything other than
  creating, updating or deleting a secret whose name Mykronos owns — asserted
  by test, since `secrets: write` grants the ability to overwrite any named
  secret in an onboarded repo (§6.1) and nothing in the grant itself prevents
  a future change from doing so by accident.
- Revoking a single repo's ingestion token (via disabling its capability,
  spec 03 §5) immediately prevents further writes from that repo/capability
  pair, without affecting any other repo.
- All secrets required for local development are documented in a
  `.env.example`-style file with clearly fake placeholder values — no real
  secret ever committed, including in test fixtures.
- An admin action log entry exists for every `RiskDecision` override and
  every capability enable/disable.

## 9. Dependencies

- Spec 02 for GitHub App identity and installation token lifecycle.
- Spec 05 for ingestion token issuance/rotation mechanics.
- Spec 10 for RBAC enforcement in the dashboard.
