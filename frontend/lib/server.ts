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
  type FindingsPage,
  type InsiderRiskPage,
  type MaturityReport,
  type Portfolio,
  type PullRequestsPage,
  type RemediationPage,
  type RepoDetail,
  type RetroReport,
  type RiskDecision,
  type ScanHealth,
  type ShadowModeReport,
  type SscsPage,
  type TrendReport,
  type TrendSeries,
  type TriageQueue,
} from "./api";

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

export async function getTriage(query: {
  severity?: string;
  capability?: string;
}): Promise<Result<TriageQueue>> {
  try {
    const { data, response } = await backendClient().GET("/api/dashboard/triage", {
      params: {
        query: {
          severity: query.severity as never,
          capability: query.capability as never,
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
