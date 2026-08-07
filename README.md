# Project Mykronos

**Unified AppSec onboarding, scanning, risk-decision, and dashboard platform.**

Mykronos lets a security team register ("onboard") any GitHub repository, automatically
install and configure a standard set of security-scanning GitHub Actions on it, collect
every scan's results into a local data lake, run those results through a risk-decision
engine, and view everything — across every onboarded repo — in one unified dashboard.
A learning/RAG layer captures retro feedback over time so the whole system gets smarter
about false positives, recurring issues, and process changes.

This repository contains **specifications only** — no prior implementation exists.
It is written for a developer with no prior context on any of the source projects
referenced below. Build order and milestones are in
[`specs/13-build-roadmap.md`](specs/13-build-roadmap.md).

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

## Provenance

Mykronos is a **from-scratch build** informed by, but not copy-pasted from, several
existing internal projects. Where a spec says "mirrors the behavior of Project X,"
that is a design reference for the developer to consult if source access is available —
it is not a dependency.
