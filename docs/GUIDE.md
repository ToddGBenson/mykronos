# Using and implementing Mykronos

Two audiences, and they want different things. **Part one** is for somebody who
reads the dashboard and has to decide what to work on. **Part two** is for
somebody standing the platform up, onboarding a repository, or teaching a new
scanner to report into it.

Neither part repeats the specs. Those are the design record; this is how the
thing behaves.

---

# Part one — using it

## The daily loop

Three views, in this order, and the order is the point.

**1. `mykronos briefing`, or Remediate today.** Start here, always. It leads
with the lanes that *cannot close findings*, because while one is silent none of
your other numbers mean anything — a lane that reports nothing looks exactly
like a repository with nothing wrong. Everything below that is ordered by what
it costs you, cheapest first: findings closing on their own, then one change
that closes seven, then the ones needing a person.

A critical nobody can close today belongs below zero findings that close for
free. That ordering is deliberate and it is not severity.

**2. Triage queue.** What to work on next, ranked. Read the line under the order
control before you trust the ranking: it names what the rank consulted and what
it could not. On an estate with no risk profiles it says so out loud — the order
is severity and threat intelligence, not business risk.

**3. The repository, when something needs deciding.** Findings tab for the
backlog, the finding record for one item, Risk Decision for the standing score
and what drives it.

## Reading a finding

Open the full record from any occurrence. Four questions, in the order people
ask them:

| Block | Answers |
|---|---|
| Header | What is it |
| Does this matter here | Severity, EPSS, KEV, reachability, exposure — **and what could not be consulted** |
| What to do about it | The change that closes it, how many others it closes, and how to verify |
| Can it close? | Whether the lane is reporting. **Read this before fixing anything** |

**"Can it close?" is the one people skip.** A finding closes only after two
consecutive successful scans stop seeing it. If the lane is dead, a perfect fix
changes nothing on the page and the natural conclusion — "my fix did not work" —
is wrong. The record says which it is.

## Deciding not to fix something

Accepting a risk is a first-class outcome and is reported separately from
resolved. It is never counted as fixed.

**Record grounds and a review date.** An acceptance with neither is not a
decision, it is ignoring the finding with extra steps, and the risk score now
says so: `accepted.unqualified` contributes, and an acceptance whose review date
has passed contributes more. An acceptance *with* grounds and a future date
costs exactly nothing, which is the whole point.

A dismissal with a written reason also teaches the classifier — that rule gets
quietened on this repository next time. A dismissal without one teaches it
nothing, deliberately: click counts are not evidence.

## What the check on your pull request means

`Mykronos / risk decision` leads with **what your change introduced** — the
findings whose first sighting was a scan of your commit. A finding your branch
merely reproduces is not counted against you.

The score below that describes the repository's *whole* open backlog, which is
a different question and is labelled as one. On a repository with 300 open
findings it barely moves between commits; the list above it is the part you can
act on.

The gate is **advisory**. It does not block, by decision (D-102), and the check
says so.

---

# Part two — implementing it

## Standing it up

```bash
cd deploy/mykronos
export MYKRONOS_GITHUB_APP_KEY_HOST_PATH=/absolute/path/to/app.pem
docker compose --env-file ../../backend/.env up -d
```

**The trap, and it is silent.** The GitHub App private key is bind-mounted from
the host and the compose file defaults it to `/dev/null`. Call compose without
that variable and the container starts, reports healthy, serves every page — and
every GitHub operation fails with `InvalidKeyError: Could not parse the provided
public key`. Recreating *any* service can recreate the backend as a dependency,
so this bites when you meant to touch only the frontend.

Check it landed:

```bash
docker inspect mykronos-backend --format '{{range .Mounts}}{{.Source}}{{println}}{{end}}' | grep -i pem
```

**Vault seals on every restart.** Concourse resolves `((vars))` through it, so
after a reboot run `deploy/concourse/vault-unseal.ps1`. Jobs that failed while
it was sealed do not retry on their own.

## Onboarding a repository

1. **Register it.** `POST /api/repos` with `github_repo_full_name`. Idempotent.
2. **Enable capabilities.** `PATCH /api/repos/{id}/capabilities`. For an
   Actions-scanned repository this opens an install pull request that adds the
   generated workflows; the capability is *pending* until it merges, and the
   platform distinguishes "nothing enabled" from "waiting on an install PR".
3. **Mint an ingestion token.** `mykronos mint-token owner/repo --capability sast`.
   Shown once, only its hash is stored. This is what CI authenticates with.
4. **Fill in the risk profile.** The Risk Decision tab proposes what it can
   evidence and, for the rest, says exactly what would settle each field. Until
   it exists, scoring is severity and threat intelligence and the platform says
   so rather than pretending otherwise.
5. **Add CODEOWNERS.** Without one, ownership falls to the account that owns the
   repository — true, weak, and labelled `repo_owner` so nobody mistakes it for
   a decision somebody made.

## Teaching a scanner to report

Two calls, in order. A scan run first, then its findings.

```http
POST /api/ingest/scan-run
Authorization: Bearer <ingestion token>

{ "scan_run_id": "...", "repo_full_name": "owner/repo", "capability": "sast",
  "tool_name": "semgrep", "commit_sha": "...", "pr_number": 42,
  "scan_status": "success", "finding_count": 3 }
```

```http
POST /api/ingest/findings

{ "scan_run_id": "...", "capability": "sast",
  "findings": [ { "rule_id": "...", "title": "...", "severity": "high",
                  "file_path": "app/db.py", "line_start": 40,
                  "code_snippet": "...", "cwe_ids": ["CWE-89"] } ] }
```

Four things that decide whether the data is any good:

**Report a failed scan.** `scan_status: "failure"` is not an error to swallow —
it is the difference between "nothing was found" and "nothing was looked at",
and the closure rule depends on knowing which. A lane that uploads nothing on
failure freezes every finding it owns.

**Send a `code_snippet` where one exists.** Findings without one fall back to
positional identity and churn whenever unrelated lines shift above them.

**Send `commit_sha` and `pr_number`.** Attribution — "what did this change
introduce" — is computed from the scan run that *first* saw a finding. Omit
them and the finding still lands, but nobody can be told they added it.

**Send `cwe_ids` if your tool emits them.** The threat model is only as
structured as its inputs.

## Operating it

| Task | How |
|---|---|
| After every deploy | `mykronos briefing` — it leads with what is broken |
| A lane went silent | The briefing names it and gives the re-run route |
| Ownership looks wrong | `POST /api/dashboard/repos/{id}/reown?dry_run=true` re-derives it. Manual assignments are never overwritten |
| Component inventory looks thin | `POST /api/dashboard/inventory/reindex?dry_run=true` rebuilds from archived SBOMs |
| Are we affected by this CVE? | Threat intelligence → look it up. Repositories with no SBOM report as *not checked*, which is not the same as clear |

## Things that will surprise you

**Nothing runs before `git push`.** No pre-commit hook, no local scan. That is
a decision (D-101), not an omission: this is a control plane, and the cost — a
committed credential is found *after* it is committed, so rotation comes before
removal — is stated in the guidance rather than hidden.

**Auto-remediation cannot merge.** Not by policy: the GitHub client exposes no
merge operation and a test asserts the method does not exist.

**A finding inside a toxic combination is not fixed in isolation.** Repairing
half a toxic pair makes it look resolved while the composite risk remains, so
the pipeline stops and says so.

**Empty is not clean.** A repository with no SBOM is absent from the library
view. A capability with no findings because it never ran is not a passing
capability. The interface distinguishes these everywhere it can, and where it
cannot it says which one it is showing.
