/**
 * Server-side data fetching.
 *
 * These run on the Next server, so they hold the admin token and the browser
 * never does. Each returns data or a reason it could not — the dashboard's
 * most likely failure by far is "the backend is not running", and that should
 * render as a clear message rather than a stack trace or an empty table that
 * looks like a clean portfolio.
 */

import "server-only";

import {
  BackendUnavailable,
  backendClient,
  type CiPage,
  type Finding,
  type FindingsPage,
  type GovernancePosture,
  type InsiderRiskPage,
  type MaturityReport,
  type OpenFindingsPage,
  type Portfolio,
  type PullRequestsPage,
  type RemediationPage,
  type RepoDetail,
  type RetroReport,
  type RiskDecision,
  type RiskProfile,
  type ScanHealth,
  type ScanRunTrend,
  type ShadowModeReport,
  type SscsPage,
  type ThreatIntelEntry,
  type ThreatModelPage,
  type TrendReport,
  type TrendSeries,
  type TriageQueue,
  type Briefing,
  type RepoGuidance,
  type RepoSurfaces,
  type SupplyChainPackages,
  type VulnerabilityManagement,
  type WorkflowsPage,
} from "./api";
import type { paths } from "./api-types";

export type Result<T> = { ok: true; data: T } | { ok: false; error: string };

function failure(error: unknown): { ok: false; error: string } {
  if (error instanceof BackendUnavailable) return { ok: false, error: error.detail };
  const message = error instanceof Error ? error.message : String(error);
  if (/fetch failed|ECONNREFUSED|ENOTFOUND/i.test(message)) {
    return {
      ok: false,
      error:
        "Cannot reach the Mykronos API. Start the backend " +
        "(uvicorn mykronos.main:app) or set MYKRONOS_API_URL.",
    };
  }
  return { ok: false, error: message };
}

function describe(response: Response | undefined, fallback: string): string {
  if (!response) return fallback;
  if (response.status === 401 || response.status === 503) {
    return (
      "The API rejected this request. Set MYKRONOS_ADMIN_TOKEN on the " +
      "frontend to the backend's admin token."
    );
  }
  return `${fallback} (HTTP ${response.status})`;
}

export async function getPortfolio(
  includeRemoved = false,
): Promise<Result<Portfolio>> {
  try {
    const { data, response } = await backendClient().GET("/api/dashboard/portfolio", {
      params: { query: { include_removed: includeRemoved } },
      cache: "no-store",
    });
    if (!data) return { ok: false, error: describe(response, "Could not load the portfolio") };
    return { ok: true, data };
  } catch (error) {
    return failure(error);
  }
}

export async function getRepo(repoId: string): Promise<Result<RepoDetail>> {
  try {
    const { data, response } = await backendClient().GET("/api/repos/{repo_id}", {
      params: { path: { repo_id: repoId } },
      cache: "no-store",
    });
    if (!data) return { ok: false, error: describe(response, "Could not load the repository") };
    return { ok: true, data };
  } catch (error) {
    return failure(error);
  }
}

/**
 * The flat record: every row, one per report, any status.
 *
 * No page renders this — the dashboard reads `getOpenFindings`, which groups
 * and triages. Kept because the record and the view are different things and
 * the endpoint is the documented one (spec 10 §4); a caller that wants the
 * rows exactly as the lake holds them should not have to rebuild this.
 */
export async function getFindings(
  repoId: string,
  query: { capability?: string; severity?: string; finding_status?: string; offset?: number },
): Promise<Result<FindingsPage>> {
  try {
    const { data, response } = await backendClient().GET(
      "/api/dashboard/repos/{repo_id}/findings",
      {
        params: {
          path: { repo_id: repoId },
          query: {
            capability: query.capability as never,
            severity: query.severity as never,
            finding_status: query.finding_status as never,
            limit: 100,
            offset: query.offset ?? 0,
          },
        },
        cache: "no-store",
      },
    );
    if (!data) return { ok: false, error: describe(response, "Could not load findings") };
    return { ok: true, data: data };
  } catch (error) {
    return failure(error);
  }
}

/**
 * The findings view the dashboard actually renders: open only, deduplicated,
 * triaged, and with toxic combinations named. `getFindings` remains the flat
 * record, and the detail pane still reads from it — a disposition is recorded
 * against one finding, not against a group.
 */
export async function getOpenFindings(
  repoId: string,
  query: {
    capability?: string;
    severity?: string;
    finding_status?: string;
    rule_id?: string;
    kev_only?: boolean;
    min_epss?: number;
    triage?: string;
    fixable?: boolean;
  },
): Promise<Result<OpenFindingsPage>> {
  try {
    const { data, response } = await backendClient().GET(
      "/api/dashboard/repos/{repo_id}/open-findings",
      {
        params: {
          path: { repo_id: repoId },
          query: {
            capability: query.capability as never,
            severity: query.severity as never,
            finding_status: (query.finding_status ?? "open") as never,
            rule_id: query.rule_id as never,
            kev_only: query.kev_only as never,
            min_epss: query.min_epss as never,
            triage: query.triage as never,
            fixable: query.fixable as never,
          },
        },
        cache: "no-store",
      },
    );
    if (!data) return { ok: false, error: describe(response, "Could not load open findings") };
    return { ok: true, data };
  } catch (error) {
    return failure(error);
  }
}

/**
 * One finding, by id.
 *
 * The dashboard groups occurrences, so the one somebody clicked is routinely
 * not in the first page of the flat list — fetching it by id is the difference
 * between a detail pane that always works and one that works for the first
 * hundred findings.
 */
export type FindingRecord =
  paths["/api/dashboard/findings/{finding_id}/record"]["get"]["responses"]["200"]["content"]["application/json"];

/** Everything the platform knows about one finding, in one call (B-032). */
export async function getFindingRecord(
  findingId: string,
): Promise<Result<FindingRecord>> {
  try {
    const { data, response } = await backendClient().GET(
      "/api/dashboard/findings/{finding_id}/record",
      { params: { path: { finding_id: findingId } }, cache: "no-store" },
    );
    if (!data) return { ok: false, error: describe(response, "Could not load the record") };
    return { ok: true, data: data as FindingRecord };
  } catch (error) {
    return failure(error);
  }
}

export type EstateLibraries =
  paths["/api/dashboard/libraries"]["get"]["responses"]["200"]["content"]["application/json"];

/** Every library the estate carries, and where — the consolidation view. */
export async function getLibraries(
  ecosystem?: string,
): Promise<Result<EstateLibraries>> {
  try {
    const { data, response } = await backendClient().GET("/api/dashboard/libraries", {
      cache: "no-store",
      ...(ecosystem ? { params: { query: { ecosystem } } } : {}),
    });
    if (!data) return { ok: false, error: describe(response, "Could not load libraries") };
    return { ok: true, data: data as EstateLibraries };
  } catch (error) {
    return failure(error);
  }
}

export async function getFinding(findingId: string): Promise<Result<Finding>> {
  try {
    const { data, response } = await backendClient().GET(
      "/api/dashboard/findings/{finding_id}",
      { params: { path: { finding_id: findingId } }, cache: "no-store" },
    );
    if (!data) return { ok: false, error: describe(response, "Could not load the finding") };
    return { ok: true, data: data as Finding };
  } catch (error) {
    return failure(error);
  }
}

export async function getTriage(query: {
  severity?: string;
  capability?: string;
  rule_id?: string;
  kev_only?: boolean;
  min_epss?: number;
  owner?: string;
  order?: string;
  triage?: string;
}): Promise<Result<TriageQueue>> {
  try {
    const { data, response } = await backendClient().GET("/api/dashboard/triage", {
      params: {
        query: {
          severity: query.severity as never,
          capability: query.capability as never,
          rule_id: query.rule_id as never,
          kev_only: query.kev_only as never,
          min_epss: query.min_epss as never,
          owner: query.owner as never,
          order: query.order as never,
          triage: query.triage as never,
          limit: 100,
        },
      },
      cache: "no-store",
    });
    if (!data) return { ok: false, error: describe(response, "Could not load the queue") };
    return { ok: true, data };
  } catch (error) {
    return failure(error);
  }
}

export async function getDecisions(
  repoId: string,
): Promise<Result<{ repo_full_name: string; decisions: RiskDecision[] }>> {
  try {
    const { data, response } = await backendClient().GET(
      "/api/oracle/decisions/{repo_id}",
      { params: { path: { repo_id: repoId } }, cache: "no-store" },
    );
    if (!data) return { ok: false, error: describe(response, "Could not load decisions") };
    return {
      ok: true,
      data: data as { repo_full_name: string; decisions: RiskDecision[] },
    };
  } catch (error) {
    return failure(error);
  }
}

export async function getShadowMode(): Promise<Result<ShadowModeReport>> {
  try {
    const { data, response } = await backendClient().GET("/api/oracle/shadow-mode", {
      cache: "no-store",
    });
    if (!data) {
      return { ok: false, error: describe(response, "Could not load the shadow-mode report") };
    }
    return { ok: true, data: data as ShadowModeReport };
  } catch (error) {
    return failure(error);
  }
}

export type TermAnalytics = {
  window_days: number;
  repos_considered: number;
  no_go_repos: number;
  terms: {
    key: string;
    label: string;
    total_contribution: number;
    repos: number;
    no_go_repos: number;
  }[];
  note: string;
};

/**
 * What is driving risk across the fleet, term by term (spec 21 §3). A
 * read-time aggregate over snapshots every decision already stores — the
 * portfolio table says *which* repos are worst, this says *why*.
 */
export async function getTermAnalytics(): Promise<Result<TermAnalytics>> {
  try {
    const { data, response } = await backendClient().GET("/api/oracle/term-analytics", {
      cache: "no-store",
    });
    if (!data) {
      return { ok: false, error: describe(response, "Could not load term analytics") };
    }
    return { ok: true, data: data as TermAnalytics };
  } catch (error) {
    return failure(error);
  }
}

export type PolicyHistory = {
  current_version: string;
  versions: {
    version: string;
    decisions: number;
    first_used: string | null;
    last_used: string | null;
    no_go_decisions: number;
    repos: number;
    current: boolean;
  }[];
  note: string;
};

/**
 * Which policy version scored what (spec 21 §5). Derived from the decisions,
 * not from the policy file's commit history — see the endpoint's own note for
 * why, and for the part that is still missing.
 */
export async function getPolicyHistory(): Promise<Result<PolicyHistory>> {
  try {
    const { data, response } = await backendClient().GET("/api/oracle/policy/history", {
      cache: "no-store",
    });
    if (!data) {
      return { ok: false, error: describe(response, "Could not load policy history") };
    }
    return { ok: true, data: data as PolicyHistory };
  } catch (error) {
    return failure(error);
  }
}

/**
 * `source` is the parsed policy document, not the YAML text — the endpoint
 * serves the structure so machine consumers do not have to parse it, and the
 * UI re-serialises it for display.
 */
export async function getPolicy(): Promise<
  Result<{ version: string; source: unknown; note: string }>
> {
  try {
    const { data, response } = await backendClient().GET("/api/oracle/policy", {
      cache: "no-store",
    });
    if (!data) return { ok: false, error: describe(response, "Could not load the policy") };
    return { ok: true, data: data as { version: string; source: unknown; note: string } };
  } catch (error) {
    return failure(error);
  }
}

export async function getInsiderRisk(
  repoId: string,
): Promise<Result<InsiderRiskPage>> {
  try {
    const { data, response } = await backendClient().GET(
      "/api/dashboard/repos/{repo_id}/insider-risk",
      { params: { path: { repo_id: repoId } }, cache: "no-store" },
    );
    if (!data) {
      return { ok: false, error: describe(response, "Could not load insider risk") };
    }
    return { ok: true, data };
  } catch (error) {
    return failure(error);
  }
}

/**
 * Which packages are vulnerable and which of them have somewhere to go
 * (B-027). Separate from `getSscs` on purpose: the trust score is a summary
 * that renders instantly, and this joins two lake tables per repository.
 */
export async function getVulnerablePackages(
  repoId: string,
): Promise<Result<SupplyChainPackages>> {
  try {
    const { data, response } = await backendClient().GET(
      "/api/dashboard/repos/{repo_id}/sscs/packages",
      { params: { path: { repo_id: repoId } }, cache: "no-store" },
    );
    if (!data) {
      return { ok: false, error: describe(response, "Could not load vulnerable packages") };
    }
    return { ok: true, data };
  } catch (error) {
    return failure(error);
  }
}

/** What this repository is, so the threat model can say what is at stake. */
/** The scanners' own remediation for one repository (B-030). */
export async function getRepoGuidance(repoId: string): Promise<Result<RepoGuidance>> {
  try {
    const { data, response } = await backendClient().GET(
      "/api/dashboard/repos/{repo_id}/guidance",
      { params: { path: { repo_id: repoId } }, cache: "no-store" },
    );
    if (!data) {
      return { ok: false, error: describe(response, "Could not load remediation guidance") };
    }
    return { ok: true, data };
  } catch (error) {
    return failure(error);
  }
}

export async function getSurfaces(repoId: string): Promise<Result<RepoSurfaces>> {
  try {
    const { data, response } = await backendClient().GET(
      "/api/dashboard/repos/{repo_id}/surfaces",
      { params: { path: { repo_id: repoId } }, cache: "no-store" },
    );
    if (!data) {
      return { ok: false, error: describe(response, "Could not load the surface register") };
    }
    return { ok: true, data };
  } catch (error) {
    return failure(error);
  }
}

export async function getSscs(repoId: string): Promise<Result<SscsPage>> {
  try {
    const { data, response } = await backendClient().GET(
      "/api/dashboard/repos/{repo_id}/sscs",
      { params: { path: { repo_id: repoId } }, cache: "no-store" },
    );
    if (!data) {
      return { ok: false, error: describe(response, "Could not load supply-chain evidence") };
    }
    return { ok: true, data };
  } catch (error) {
    return failure(error);
  }
}

export async function getWorkflows(repoId: string): Promise<Result<WorkflowsPage>> {
  try {
    const { data, response } = await backendClient().GET(
      "/api/repos/{repo_id}/workflows",
      { params: { path: { repo_id: repoId } }, cache: "no-store" },
    );
    if (!data) {
      return { ok: false, error: describe(response, "Could not load workflow state") };
    }
    return { ok: true, data };
  } catch (error) {
    return failure(error);
  }
}

export async function getThreatModel(repoId: string): Promise<Result<ThreatModelPage>> {
  try {
    const { data, response } = await backendClient().GET(
      "/api/dashboard/repos/{repo_id}/threat-model",
      { params: { path: { repo_id: repoId } }, cache: "no-store" },
    );
    if (!data) {
      return { ok: false, error: describe(response, "Could not load the threat model") };
    }
    return { ok: true, data };
  } catch (error) {
    return failure(error);
  }
}

export async function getRetro(
  periodDays = 14,
): Promise<Result<RetroReport>> {
  try {
    const { data, response } = await backendClient().GET("/api/knowledge/retro", {
      params: { query: { period_days: periodDays } },
      cache: "no-store",
    });
    if (!data) return { ok: false, error: describe(response, "Could not load the retro") };
    return { ok: true, data: data as RetroReport };
  } catch (error) {
    return failure(error);
  }
}

/**
 * A 422 here is the *expected* answer for a young deployment, not a fault:
 * spec 11 §10 requires the report to refuse rather than render a shape into
 * too few points. The detail message explains why, so it is surfaced as
 * content rather than as an error panel.
 */
export async function getTrend(): Promise<
  Result<TrendReport> | { ok: false; notEnoughHistory: string }
> {
  try {
    const { data, response, error } = await backendClient().GET(
      "/api/knowledge/trend",
      { cache: "no-store" },
    );
    if (response?.status === 422) {
      const detail = (error as { detail?: string } | undefined)?.detail;
      return {
        ok: false,
        notEnoughHistory: detail ?? "Not enough history for a trend yet.",
      };
    }
    if (!data) return { ok: false, error: describe(response, "Could not load the trend") };
    return { ok: true, data: data as TrendReport };
  } catch (err) {
    return failure(err);
  }
}

export async function getRemediation(
  repoId: string,
): Promise<Result<RemediationPage>> {
  try {
    const { data, response } = await backendClient().GET(
      "/api/patchwork/repos/{repo_id}",
      { params: { path: { repo_id: repoId } }, cache: "no-store" },
    );
    if (!data) {
      return { ok: false, error: describe(response, "Could not load remediation") };
    }
    return { ok: true, data };
  } catch (error) {
    return failure(error);
  }
}

export async function getTrends(
  repoId?: string,
): Promise<Result<TrendSeries>> {
  try {
    const { data, response } = await backendClient().GET("/api/dashboard/trends", {
      params: { query: { repo_id: repoId, days: 90, points: 12 } },
      cache: "no-store",
    });
    if (!data) return { ok: false, error: describe(response, "Could not load trends") };
    return { ok: true, data: data as TrendSeries };
  } catch (error) {
    return failure(error);
  }
}

export async function getMaturity(): Promise<Result<MaturityReport>> {
  try {
    const { data, response } = await backendClient().GET("/api/dashboard/maturity", {
      cache: "no-store",
    });
    if (!data) return { ok: false, error: describe(response, "Could not load maturity") };
    return { ok: true, data: data as MaturityReport };
  } catch (error) {
    return failure(error);
  }
}

export async function getVulnerabilityManagement(): Promise<
  Result<VulnerabilityManagement>
> {
  try {
    const { data, response } = await backendClient().GET(
      "/api/dashboard/vulnerability-management",
      { cache: "no-store" },
    );
    if (!data) {
      return {
        ok: false,
        error: describe(response, "Could not load vulnerability management"),
      };
    }
    return { ok: true, data: data as VulnerabilityManagement };
  } catch (error) {
    return failure(error);
  }
}

/**
 * The post-deployment briefing (D-098).
 *
 * Its first section is why it exists: a finding closes only after two
 * consecutive *successful* scans see it gone, so a lane that is failing — or
 * that quietly stopped running — freezes its findings open however thoroughly
 * the defect was fixed. On 2026-09-01 that was 431 of 475 open findings, and
 * every other surface reported them as work somebody was neglecting.
 */
/** `repoId` narrows every section to one repository; omit it for the estate. */
export async function getBriefing(repoId?: string): Promise<Result<Briefing>> {
  try {
    const { data, response } = await backendClient().GET("/api/dashboard/briefing", {
      cache: "no-store",
      ...(repoId ? { params: { query: { repo_id: repoId } } } : {}),
    });
    if (!data) {
      return { ok: false, error: describe(response, "Could not load the briefing") };
    }
    return { ok: true, data: data as Briefing };
  } catch (error) {
    return failure(error);
  }
}

export async function getCi(repoId: string): Promise<Result<CiPage>> {
  try {
    const { data, response } = await backendClient().GET(
      "/api/dashboard/repos/{repo_id}/ci",
      { params: { path: { repo_id: repoId } }, cache: "no-store" },
    );
    if (!data) return { ok: false, error: describe(response, "Could not load pipeline links") };
    return { ok: true, data };
  } catch (error) {
    return failure(error);
  }
}

/** Every CVE currently matched to an open finding, KEV first (spec 17 §4.4). */
export async function getThreatIntel(): Promise<Result<ThreatIntelEntry[]>> {
  try {
    const { data, response } = await backendClient().GET("/api/dashboard/threat-intel", {
      cache: "no-store",
    });
    if (!data) {
      return { ok: false, error: describe(response, "Could not load threat intelligence") };
    }
    return { ok: true, data };
  } catch (error) {
    return failure(error);
  }
}

export async function getScanHealth(repoId: string): Promise<Result<ScanHealth>> {
  try {
    const { data, response } = await backendClient().GET(
      "/api/dashboard/repos/{repo_id}/scan-health",
      { params: { path: { repo_id: repoId } }, cache: "no-store" },
    );
    if (!data) return { ok: false, error: describe(response, "Could not load scan health") };
    return { ok: true, data: data as ScanHealth };
  } catch (error) {
    return failure(error);
  }
}

export async function getRiskProfile(repoId: string): Promise<Result<RiskProfile>> {
  try {
    const { data, response } = await backendClient().GET(
      "/api/repos/{repo_id}/risk-profile",
      { params: { path: { repo_id: repoId } }, cache: "no-store" },
    );
    if (!data) {
      return { ok: false, error: describe(response, "Could not load the risk profile") };
    }
    return { ok: true, data };
  } catch (error) {
    return failure(error);
  }
}

export async function getScanRunTrend(
  repoId: string,
  capability: string,
): Promise<Result<ScanRunTrend>> {
  try {
    const { data, response } = await backendClient().GET(
      "/api/dashboard/repos/{repo_id}/scan-runs/trend",
      {
        params: { path: { repo_id: repoId }, query: { capability } },
        cache: "no-store",
      },
    );
    if (!data) return { ok: false, error: describe(response, "Could not load the trend") };
    return { ok: true, data: data as ScanRunTrend };
  } catch (error) {
    return failure(error);
  }
}

export async function getPullRequests(): Promise<Result<PullRequestsPage>> {
  try {
    const { data, response } = await backendClient().GET(
      "/api/dashboard/pull-requests",
      { cache: "no-store" },
    );
    if (!data) {
      return { ok: false, error: describe(response, "Could not load pull requests") };
    }
    return { ok: true, data: data as PullRequestsPage };
  } catch (error) {
    return failure(error);
  }
}

export type RemediationDigest =
  paths["/api/patchwork/digest"]["get"]["responses"]["200"]["content"]["application/json"];

/**
 * The same fix, everywhere it is open (spec 19 §3.4). Grouped for the
 * reviewer — never merged into one pull request, which would break per-repo
 * review and CODEOWNERS.
 */
export async function getRemediationDigest(): Promise<Result<RemediationDigest>> {
  try {
    const { data, response } = await backendClient().GET("/api/patchwork/digest", {
      cache: "no-store",
    });
    if (!data) {
      return { ok: false, error: describe(response, "Could not load the digest") };
    }
    return { ok: true, data };
  } catch (error) {
    return failure(error);
  }
}

export type FixEfficacy =
  paths["/api/patchwork/efficacy"]["get"]["responses"]["200"]["content"]["application/json"];

export async function getFixEfficacy(): Promise<Result<FixEfficacy>> {
  try {
    const { data, response } = await backendClient().GET("/api/patchwork/efficacy", {
      cache: "no-store",
    });
    if (!data) {
      return { ok: false, error: describe(response, "Could not load fix efficacy") };
    }
    return { ok: true, data };
  } catch (error) {
    return failure(error);
  }
}

/**
 * The controls that would catch a bad change (spec 30).
 *
 * Read live on every render rather than from a snapshot: branch protection is
 * configuration somebody can change in the GitHub UI in ten seconds, and a
 * panel still reporting two required reviews after they were turned off would
 * be worse than no panel.
 */
export async function getGovernance(
  repoId: string,
): Promise<Result<GovernancePosture>> {
  try {
    const { data, response } = await backendClient().GET(
      "/api/dashboard/repos/{repo_id}/governance",
      { params: { path: { repo_id: repoId } }, cache: "no-store" },
    );
    if (!data) {
      return { ok: false, error: describe(response, "Could not read the controls") };
    }
    return { ok: true, data };
  } catch (error) {
    return failure(error);
  }
}

export type IncidentView =
  paths["/api/dashboard/incident"]["get"]["responses"]["200"]["content"]["application/json"];

/**
 * Are we affected by this? (spec 29 §2)
 *
 * Read under time pressure by somebody who has just been paged, so nothing
 * here is fetched lazily and nothing is cached: an answer from ten minutes ago
 * is exactly the kind of thing that gets somebody to stand down early.
 */
export async function getIncident(query: string): Promise<Result<IncidentView>> {
  try {
    const { data, response } = await backendClient().GET("/api/dashboard/incident", {
      params: { query: { q: query } },
      cache: "no-store",
    });
    if (!data) {
      return { ok: false, error: describe(response, "Could not run the lookup") };
    }
    return { ok: true, data };
  } catch (error) {
    return failure(error);
  }
}

export type Reachability =
  paths["/api/repos/{repo_id}/reachability"]["get"]["responses"]["200"]["content"]["application/json"];

/**
 * The stored import analysis (spec 19 §2.1). `analysed: false` means nothing
 * has looked — a different answer from having looked and found nothing, and
 * the card renders them differently.
 */
export async function getReachability(repoId: string): Promise<Result<Reachability>> {
  try {
    const { data, response } = await backendClient().GET(
      "/api/repos/{repo_id}/reachability",
      { params: { path: { repo_id: repoId } }, cache: "no-store" },
    );
    if (!data) {
      return { ok: false, error: describe(response, "Could not load the import analysis") };
    }
    return { ok: true, data };
  } catch (error) {
    return failure(error);
  }
}
