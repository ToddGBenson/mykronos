# Project Mykronos

**Unified AppSec onboarding, scanning, risk-decision, and dashboard platform.**

Mykronos lets a security team register ("onboard") any GitHub repository, automatically
install and configure a standard set of security-scanning GitHub Actions on it, collect
every scan's results into a local data lake, run those results through a risk-decision
engine, and view everything — across every onboarded repo — in one unified dashboard.
A learning/RAG layer captures retro feedback over time so the whole system gets smarter
about false positives, recurring issues, and process changes.

Build order and milestones are in [`specs/13-build-roadmap.md`](specs/13-build-roadmap.md).
The specs are written for a developer with no prior context on any of the source
projects referenced below.

## Status

| Phase | Scope | State |
|---|---|---|
| 0 | Data lake + Ingestion API | **Done** — see [`backend/`](backend/README.md) |
| 1 | Onboarding, GitHub App, workflow installer, SAST | Not started |
| 2 | Remaining five scanners + first dashboard views | Not started |
| 3 | Oracle v1 (deterministic policy) | Not started |
| 4 | Aegis + Atlas | Not started |
| 5 | Knowledge Store + RAG | Not started |
| 6 | Patchwork | Not started |
| 7 | Trend/retro reporting, maturity view, hardening | Not started |

Implementation decisions the specs do not settle — and the ones that should
become spec changes — are logged in [`docs/DECISIONS.md`](docs/DECISIONS.md).
Five open questions carried from the spec review are listed there too; items
1–3 block Phase 1.

Spec changes land as their own commits before the code that depends on them.
`specs/05-datalake.md` §3/§5/§9 have been amended once so far (D-001).

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

## Provenance

Mykronos is a **from-scratch build** informed by, but not copy-pasted from, several
existing internal projects. Where a spec says "mirrors the behavior of Project X,"
that is a design reference for the developer to consult if source access is available —
it is not a dependency.
