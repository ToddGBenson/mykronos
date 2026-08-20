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
| Harness/Findings tabs, threat intel (KEV/EPSS), exploitability in Oracle, scan-now dispatch, `ai` capability's first tool, i2i grooming, Triage-queue KEV badges / `min_epss`/`kev_only` filters (spec 17) | **Done** — no reachability engine; honestly `unknown` in Oracle, real call-graph analysis is separate work (D-057, D-058, D-059, #15) |
| 8-tab repo page (Dashboard = capability manager/scan health/jobs, Findings, Harness = a real unit/functional/qa test runner, Threat Model, Supply chain, Insider Threat, Risk Decision, Remediation), portfolio/Findings count-mismatch fix, `triage`/Found-By filters, per-finding remediation preview + on-demand PR, SBOM download (spec 18) | **Done** — Threat Model is capability-level, not CWE-level (no `Finding` carries a structured CWE); its narrative layer is honest plumbing, no LLM wired. Harness's "run tests" reaches Concourse-scanned repos only — no GitHub Actions workflow template exists yet for unit/functional/qa (D-061, D-062, D-063) |

Implementation decisions the specs do not settle — and the ones that became spec
changes — are logged in [`docs/DECISIONS.md`](docs/DECISIONS.md). Operational
lessons worth carrying between projects are promoted to [`docs/lessons/`](docs/lessons/),
and incident-scale days get a retro in [`docs/retros/`](docs/retros/).

The shape every Concourse pipeline conforms to — eleven numbered rules, the
failure each one prevents, and a per-capability conformance table for both
pipelines — is [`docs/pipeline-standard.md`](docs/pipeline-standard.md).
Comments in the pipeline YAML cite it by rule number (D-078).

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
| 18 | [Repo Page Rework](specs/18-repo-page-rework-threat-model-and-remediation.md) | Eight tabs, a real test harness, a STRIDE threat model, and remediation from a finding |
| 19 | [Harness, Triage and Remediation Depth](specs/19-harness-triage-and-remediation-depth.md) | Flaky-test flagging, blast radius, import reachability, partial fixes, auto-routing |
| 20 | [Aegis Depth](specs/20-aegis-depth.md) | The AI-authorship classifier call, `privilege_adjacent`, and stating whether Aegis blocks |
| 21 | [Oracle Depth & Risk Profile](specs/21-oracle-depth-and-risk-profile.md) | Asset context as an input, real portfolio aggregation, fleet term analytics, the override button |
| 22 | [Atlas (SCA) Depth](specs/22-atlas-sca-depth.md) | License compliance, a real freshness signal, package/license denylists |

Specs 18–22 close a round of depth work: each began as a full read of a
subsystem, and each is a list of things that were *named* in an earlier spec —
a capped signal, a scoring term, a snapshot category — and never wired to
anything. Their status tables record what shipped and what was deliberately
left, with the reasoning in `docs/DECISIONS.md`.

## Provenance

Mykronos is a **from-scratch build** informed by, but not copy-pasted from, several
existing internal projects. Where a spec says "mirrors the behavior of Project X,"
that is a design reference for the developer to consult if source access is available —
it is not a dependency.
