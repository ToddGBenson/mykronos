# Project Mykronos

**Unified AppSec onboarding, scanning, risk-decision, and dashboard platform.**

Mykronos lets a security team register ("onboard") any GitHub repository, run a standard
set of fifteen security and quality checks against it — through GitHub Actions workflows
it installs, or through a Concourse pipeline the repository already has — collect every
scan's results into a local data lake, run those results through a risk-decision engine,
and view everything, across every onboarded repo, in one unified dashboard. A
learning/RAG layer captures retro feedback over time so the whole system gets smarter
about false positives, recurring issues, and process changes.

Build order and milestones are in [`specs/13-build-roadmap.md`](specs/13-build-roadmap.md).
The specs are written for a developer with no prior context on any of the source
projects referenced below.

## Status

All seven roadmap phases are built and in production, serving four onboarded
repositories through three Concourse pipelines plus GitHub Actions. Work since the
roadmap closed is tracked as decisions and retros rather than phases:

| Area | State |
|---|---|
| Phases 0–7 (lake → dashboard → Oracle → Aegis/Atlas → Knowledge → Patchwork → trends) | **Done** — every dashboard tab renders from real data |
| The standard set: 15 checks per repo, icons, one-click enable/disable, coverage cross-check | **Done** — spec 10 §2.1, spec 15 §4a |
| Concourse as the primary execution environment (spec 15/16); Actions retained for Actions-scanned repos | **Done** — uploader pinned at `v2` (D-051) |
| Quality lanes as ScanRuns: unit, functional, QA docs (D-046); AI checks (D-047) | **Done** |
| Network scanning (spec 14) | Built; awaiting an authorized CIDR to scan |
| DAST | Paused platform-wide until the scan has a resource budget (D-053) |
| Harness/Findings as real tabs, threat intelligence (KEV/EPSS) (spec 17) | **Done** — the reachability/exploitability wiring, on-demand scan, `ai` capability's default tool, and the i2i grooming process are speced but not yet built (D-057) |

Implementation decisions the specs do not settle — and the ones that became spec
changes — are logged in [`docs/DECISIONS.md`](docs/DECISIONS.md). Operational
lessons worth carrying between projects are promoted to [`docs/lessons/`](docs/lessons/),
and incident-scale days get a retro in [`docs/retros/`](docs/retros/).

Spec changes land as their own commits before the code that depends on them. Where an
outage forced code first, the spec sync is called out in the retro that covers it.

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

## Provenance

Mykronos is a **from-scratch build** informed by, but not copy-pasted from, several
existing internal projects. Where a spec says "mirrors the behavior of Project X,"
that is a design reference for the developer to consult if source access is available —
it is not a dependency.
