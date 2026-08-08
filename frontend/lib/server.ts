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
  type FindingsPage,
  type Portfolio,
  type RepoDetail,
  type ScanHealth,
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
