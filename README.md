# Mykronos

**An AppSec control plane: it reads what your scanners report and tells you what
is actually true.**

Mykronos is not a scanner. Scanners are a commodity; knowing which of four
hundred findings can close this afternoon, which are frozen behind a lane that
quietly stopped reporting, and which single change closes seven of them is not.
It onboards a GitHub repository, installs a standard set of checks, collects
every result into a local data lake, scores it, and answers the questions the
scanners cannot.

## What it does that other tools do not

**It knows when a scanner has stopped.** A lane that reports nothing looks
exactly like a clean repository. Mykronos treats a silent lane as the leading
item on the page — ahead of severity — because while one is silent, none of
your numbers mean anything.

**It refuses to close a finding on one clean scan.** Closure requires two
consecutive *successful* scans that no longer see it. The cost is stated out
loud: a broken lane freezes its findings open, and the platform tells you that
is what happened rather than letting a failed scan launder into good news.

**It groups remediation by the change, not the finding.** One response header
that answers seven findings appears once, with its blast radius and the step
that verifies it landed — including checking the header on the wire rather than
in the config, which is where that fix usually fails.

**It says when it does not know.** "0 of 430 are auto-fixable." "This ranking is
severity and threat intelligence, not business risk, because no risk profile
exists." "DAST reached a deployment, which is not the same as internet-facing —
that lane runs inside CI against an ephemeral stack." A number you cannot check
is a number people stop believing.

## Status

Running in production against four repositories — one scanned by Concourse,
three by GitHub Actions — with ten capabilities reporting.

| | |
|---|---|
| Open findings | 430, every one owned and dated or visibly not |
| Successful scan runs recorded | 2,581 |
| Findings ever recorded | 2,964 |
| Capabilities reporting | 10 of 15 |
| Risk gate | Advisory. It would have refused 0 of the last 30 merges (D-102) |

Known gaps, stated rather than implied:

| Area | State |
|---|---|
| Network scanning | **Not started.** The authorization model and the ingest path exist; no scanner does, so no CIDR would be scanned if one were authorized |
| Cloud posture | Enabled on one repository and structurally unable to run — no Azure principal (B-018) |
| ZAP active scanning | Paused. It measured 548% CPU and 7 GiB on the shared host and took production down while it ran (D-053). Passive DAST still runs |
| Notifications | The notifier is built, the severity threshold is set, and no webhook URL is configured — so everything is pull (B-035) |
| Risk profiles | 0 of 4 repositories have one, so scoring degrades to severity and threat intelligence. The interface says so at the point of ranking (B-033) |
| Local / pre-commit | Deliberately absent. This is a control plane, not a scanner, and the loop starts at push (D-101) |

## How it decides

Three processes worth understanding before reading the code:

**Triage.** Every finding lands in exactly one of `true_positive`,
`likely_false_positive` or `needs_human_judgment`, and every classification
carries a written reason — an unexplained verdict is treated as a bug. A rule
this repository has dismissed *with a written reason* is quietened; a rule
dismissed without one is not, because click counts are not evidence. One
classifier serves both the dashboard and auto-remediation, so the platform
cannot call something a false positive on one page and generate a fix for it on
another.

**Toxic combinations.** A set of findings that together carry more risk than any
of them alone — an unauthenticated endpoint beside a SQL-injectable query is one
unauthenticated database. Rules are data rather than code, so they can be added
without a release. Detecting one *stops* the individual fixes: repairing half a
toxic pair makes the situation look resolved while the composite risk remains.

**Remediation.** Six stages, and every finding produces exactly one event —
including the ones where nothing happened, because "we looked at this and could
not fix it" is useful and a finding that silently never appears is not. Fix
generation is narrow by construction, and the platform structurally cannot merge
its own work: the GitHub client exposes no merge operation and a test asserts
the method does not exist.

## Running it

```bash
# The stack: API, dashboard, Vault, Concourse, ZAP.
cd deploy/mykronos
docker compose --env-file ../../backend/.env up -d

# The one thing that is not obvious: the GitHub App key is bind-mounted from
# the host, and compose defaults it to /dev/null. deploy.ps1 resolves it; if
# you call compose directly, export it first or GitHub auth fails silently.
export MYKRONOS_GITHUB_APP_KEY_HOST_PATH=/path/to/app.pem
```

```bash
# What to run first, and after every deploy: it leads with the lanes that
# cannot close findings, which is the thing most likely to be wrong.
mykronos briefing
```

New to it? [`docs/GUIDE.md`](docs/GUIDE.md) is the shortest path to being
useful — part one for reading the dashboard and deciding what to work on, part
two for standing it up, onboarding a repository, and teaching a scanner to
report into it.

Implementation decisions the specs do not settle — and the ones that became
spec changes — are logged in [`docs/DECISIONS.md`](docs/DECISIONS.md).
Operational lessons worth carrying between projects are promoted to
[`docs/lessons/`](docs/lessons/), incident-scale days get a retro in
[`docs/retros/`](docs/retros/), and work that is known and not yet done —
including gaps where a spec claims more than the code delivers — is in
[`docs/BACKLOG.md`](docs/BACKLOG.md).

## Start here

Read the specs in this order:

| # | Spec | What it covers |
|---|---|---|
| 00 | [Overview & Glossary](specs/00-overview-and-glossary.md) | Business context, goals, non-goals, glossary of all project codenames |
| 01 | [Architecture](specs/01-architecture.md) | System components, data flow, tech stack |
| 02 | [Onboarding & GitHub App](specs/02-onboarding-and-github-app.md) | Registering repos, GitHub App auth |
| 03 | [Workflow Installer](specs/03-workflow-installer.md) | How GH Actions get installed/configured per repo |
| 04 | [Scanner Workflows](specs/04-scanner-workflows.md) | SAST/DAST/Secrets/Containers/IaC/Cloud contracts |
| 05 | [Data Lake](specs/05-datalake.md) | Local storage of every scan/agent result |
| 06 | [Aegis Integration (Insider Risk)](specs/06-aegis-integration.md) | Insider threat + AI-authorship PR gate |
| 07 | [Atlas Integration (SSCS/SCA)](specs/07-atlas-integration.md) | Supply-chain security signals |
| 08 | [Patchwork Integration (Auto-Remediation)](specs/08-patchwork-integration.md) | Automated fix-PR generation |
| 09 | [Oracle — Risk Decision Engine](specs/09-oracle-risk-decision-engine.md) | New component: risk-based go/no-go decisions |
| 10 | [JDED Unified Dashboard](specs/10-jded-dashboard.md) | Portfolio views, scoring, drill-down UI |
| 11 | [Knowledge Store & RAG Learning](specs/11-knowledge-rag-learning.md) | Cross-repo retro learning |
| 12 | [Security & Secrets Management](specs/12-security-and-secrets-management.md) | Token handling, encryption, least privilege |
| 13 | [Build Roadmap](specs/13-build-roadmap.md) | Phased delivery plan |
| 14 | [Network Scanning](specs/14-network-scanning.md) | Active scanning of operator-owned networks; the Asset model |
| 15 | [Concourse Pipeline](specs/15-concourse-pipeline.md) | The self-hosted second execution environment: quality, security, gate, build, deploy |
| 16 | [TheHub Delivery Pipeline](specs/16-thehub-delivery-pipeline.md) | Delivery to demo, DAST, a manual gate before prod, and the retirement of this repo's GitHub Actions |
| 17 | [Harness Promotion, Threat Intel, i2i](specs/17-harness-threat-intel-and-i2i.md) | Harness/Findings as real tabs, KEV/EPSS threat intelligence, and the (not-yet-built) issue-to-implementation grooming process |
| 18 | [Repo Page Rework](specs/18-repo-page-rework-threat-model-and-remediation.md) | Eight tabs, a real test harness, a STRIDE threat model, and remediation from a finding |
| 19 | [Harness, Triage and Remediation Depth](specs/19-harness-triage-and-remediation-depth.md) | Flaky-test flagging, blast radius, import reachability, partial fixes, auto-routing |
| 20 | [Aegis Depth](specs/20-aegis-depth.md) | The AI-authorship classifier call, `privilege_adjacent`, and stating whether Aegis blocks |
| 21 | [Oracle Depth & Risk Profile](specs/21-oracle-depth-and-risk-profile.md) | Asset context as an input, real portfolio aggregation, fleet term analytics, the override button |
| 22 | [Atlas (SCA) Depth](specs/22-atlas-sca-depth.md) | License compliance, a real freshness signal, package/license denylists |
| 23 | [Agentic Source Code Review](specs/23-agentic-source-code-review.md) | A detector benchmark, an attack-surface inventory, and why the bug-finding agents come last |
| 24 | [Ownership, Deadlines & Acceptance Review](specs/24-ownership-deadlines-and-acceptance-review.md) | An owner and a due date on every finding, and acceptances that expire |
| 25 | [Fix Efficacy & Verification](specs/25-fix-efficacy-and-verification.md) | Re-scan on merge, attribute the closure, and learn from a rejected fix |
| 26 | [Oracle as Adviser](specs/26-oracle-as-adviser.md) | Path to green, terms that reward, and a shadow report before the gate goes on |
| 27 | [The Worklist](specs/27-the-worklist.md) | Ranked triage, claimable rows, and a weekly digest per owner |
| 28 | [Threat Model Resolution](specs/28-threat-model-resolution.md) | CWE out of SARIF, a controls register, and clean vs unscanned vs unmitigated |
| 29 | [Component Inventory & Incident Mode](specs/29-component-inventory-and-incident-mode.md) | Who uses this package, answered in one screen — plus provenance signals |
| 30 | [Change-Governance Posture](specs/30-change-governance-posture.md) | The review controls that would catch a bad change, not just the changes that looked odd |
| 31 | [Regression Coverage](specs/31-regression-coverage.md) | Pin a test to every finding you fix, so a regression is noticed |
| 32 | [GitHub Actions Delivery](specs/32-github-actions-delivery.md) | Move mykronos, keel and personal-soc off Concourse onto Actions, controlled by Mykronos. TheHub stays |

Specs 18–22 close a round of depth work: each began as a full read of a
subsystem, and each is a list of things that were *named* in an earlier spec —
a capped signal, a scoring term, a snapshot category — and never wired to
anything. Their status tables record what shipped and what was deliberately
left, with the reasoning in `docs/DECISIONS.md`.

The specs are the design record, not the current state. Where a spec and the
running system disagree, the system is right and `docs/BACKLOG.md` says so —
that gap is tracked rather than tidied away, because a spec that quietly
describes something nobody built is worse than one that is visibly out of date.

## Provenance

Mykronos is a **from-scratch build** informed by, but not copy-pasted from, several
existing internal projects. Where a spec says "mirrors the behavior of Project X,"
that is a design reference for the developer to consult if source access is available —
it is not a dependency.
