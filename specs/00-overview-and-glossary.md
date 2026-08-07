# Spec 00 — Overview & Glossary

**Status:** Approved for build
**Audience:** A developer with zero prior context on this system or any related project.

---

## 1. Problem statement

Security teams typically manage application security tooling one repo at a time:
someone manually adds a SAST workflow here, a container scan there, nobody
normalizes the output, and there is no single place to see risk across a whole
portfolio of repositories. Findings pile up in disconnected tool UIs, risk
decisions ("is this PR/release safe to ship?") are made ad hoc, and nothing is
learned from past mistakes or false positives.

Mykronos solves this by being the **control plane** for a repo's entire security
posture:

1. A team **onboards** a repo (or many) by installing a GitHub App.
2. Mykronos **installs and configures** a standard suite of GitHub Actions
   workflows on that repo covering every major security capability.
3. Every workflow run **uploads its results** to a central, local data lake in a
   normalized format.
4. A **risk decision engine ("Oracle")** continuously evaluates the data lake
   and produces risk-based go/no-go recommendations per repo/PR/release.
5. A **unified dashboard ("JDED")** shows portfolio-wide and per-repo risk,
   findings, trends, and decisions.
6. A **knowledge/RAG layer** captures what humans do with findings (dismiss as
   false positive, override a decision, fix a certain way) and feeds that back
   into future scans/decisions, plus produces periodic retro reports.

## 2. Goals

- One-click(ish) onboarding: give Mykronos a repo, get a full security posture
  pipeline running on it within minutes.
- Every security signal, from every capability, lands in one normalized,
  queryable local data lake — no cloud SaaS dependency, no vendor lock-in for
  storage.
- A single dashboard shows risk at the portfolio level and drills down to the
  individual finding.
- Risk decisions are explainable: Oracle must show its inputs and reasoning,
  not just a score.
- The system learns: false-positive corrections and retro insights measurably
  reduce noise and repeat mistakes over time.
- Everything defaults to **human-in-the-loop** — no capability auto-merges or
  auto-applies changes to a customer repo without human approval, except where
  explicitly scoped as automatic (see spec 08, Patchwork).

## 3. Non-goals (out of scope for v1)

- Building a general-purpose SIEM or replacing existing enterprise GRC tools.
- Real-time streaming analytics — data lake ingestion is per-workflow-run
  (batch), not sub-second.
- Multi-cloud/multi-region high availability — v1 targets a single
  organization's on-prem or single-cloud-account deployment.
- Supporting source control systems other than GitHub (GitHub.com and GitHub
  Enterprise Server only).

## 4. Glossary

| Term | Meaning |
|---|---|
| **Mykronos** | This platform — the whole system described by these specs. |
| **Onboarded repo** | A GitHub repository that has installed the Mykronos GitHub App and has one or more capabilities enabled. |
| **Asset** | The subject a finding belongs to. A repository is an asset; so is a network segment (spec 14). Introduced because network scanning examines running infrastructure rather than a codebase. |
| **Network scanning** | Active scanning of operator-owned networks: host discovery, exposed services, TLS posture, templated vulnerability checks. The only capability that cannot run on a GitHub-hosted runner. See spec 14. |
| **Capability** | One security function that can be enabled per asset: SAST, DAST, Secrets, Containers, IaC, Cloud, Network, Insider Risk (Aegis), SSCS/SCA (Atlas), Auto-Remediation (Patchwork), Risk Decisions (Oracle). |
| **Finding** | A single normalized security issue detected by any capability (e.g., one SAST vulnerability, one exposed secret, one risky dependency). |
| **Signal** | Any normalized data point ingested into the data lake — broader than "Finding"; includes decisions, remediation outcomes, insider-risk scores, retro entries. |
| **Data lake** | The local, central store of all raw and normalized capability output. See spec 05. |
| **Aegis** | The insider-risk / AI-authorship / PR go-no-go capability. Modeled on the existing internal "Project Aegis" ("Aegis Guard") GitHub Action. See spec 06. |
| **Atlas** | The software supply chain security (SSCS) and software composition analysis (SCA) capability — SBOM, provenance, dependency risk. Modeled on the existing internal "Project Atlas." See spec 07. |
| **Patchwork** | The auto-remediation capability — scans a PR, triages findings, opens draft fix PRs. Modeled on the existing internal "Project Patchwork." See spec 08. |
| **Oracle** | The risk-decision engine. **This does not exist yet anywhere — it is a new component specified in full in spec 09.** It consumes the data lake and produces explainable risk decisions. |
| **JDED** | The unified dashboard — portfolio scorecards, per-app risk, drill-down, maturity view. See spec 10. |
| **Knowledge Store / RAG** | The retro-learning subsystem: stores lessons learned (personal → team → org tiers) and uses retrieval-augmented generation to surface relevant prior learnings during triage and retros. See spec 11. |
| **GitHub App** | The single GitHub identity Mykronos uses to authenticate to onboarded repos (see spec 02) — preferred over per-repo Personal Access Tokens for security reasons (see spec 12). |
| **Workflow installer** | The subsystem that renders and opens a PR containing GitHub Actions YAML files into an onboarded repo, per its enabled capabilities. See spec 03. |
| **SSCS** | Software Supply Chain Security — provenance, SBOM, dependency trust. |
| **SCA** | Software Composition Analysis — identifying and assessing risk in open-source/third-party dependencies. A subset of SSCS in this system. |
| **IaC** | Infrastructure as Code (e.g., Terraform, CloudFormation) — scanned for misconfiguration. |
| **SARIF** | Static Analysis Results Interchange Format — the standard JSON format most security tools emit; used where possible as the wire format between scanners and the data lake. |

## 5. Actors

- **Security admin** — onboards repos, enables/disables capabilities, manages the GitHub App installation, reviews organization-wide dashboards.
- **Repo maintainer / developer** — receives PRs from the workflow installer and from Patchwork, sees inline PR comments from Aegis/Oracle, is the approver for all human-in-the-loop actions.
- **Mykronos platform** — the automated system itself (backend services, workflows, agents).
- **Auditor / compliance reviewer** — read-only consumer of the dashboard and data lake for evidence during audits.

## 6. Document conventions used in the rest of this spec set

Each numbered spec (01–13) generally follows this structure where applicable:
Purpose → Scope → Data Model → Interfaces/API → Data Flow → Constraints →
Acceptance Criteria → Edge Cases → Dependencies. Specs describing UI or
process (e.g., roadmap) deviate where a different structure is clearer.
