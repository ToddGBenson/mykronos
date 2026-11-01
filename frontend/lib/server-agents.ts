/**
 * Server-side reads for the agents and delegations view (TheHub #61144).
 *
 * A file of its own rather than more of `server.ts`, so this page's reads do
 * not collide with the other pages being rebuilt alongside it. Same contract
 * as `server.ts`: data or a reason, never a throw.
 */

import "server-only";

import { BackendUnavailable, backendClient } from "./api";
import type { AgentCredential, Agreement, DelegationRow } from "./agents";

export type Result<T> = { ok: true; data: T } | { ok: false; error: string };

/** One sampled agent decision waiting for a person (`sampling.sample_queue`). */
export type SampleRow = {
  decision_id: string;
  request_id: string;
  duty: string;
  tier: string;
  subject_ref: string;
  approver: string;
  family: string | null;
  verdict: string;
  rationale: string;
  delegation_id: string | null;
  decided_at: string;
};

/** The parts of `sampling.delegation_stats` this page shows. */
export type DelegationStats = {
  delegation_id: string;
  decisions: number;
  by_verdict: Record<string, number>;
  sampled: number;
  sample_queue: number;
  agreement: Agreement;
};

function failure(error: unknown): { ok: false; error: string } {
  if (error instanceof BackendUnavailable) return { ok: false, error: error.detail };
  const message = error instanceof Error ? error.message : String(error);
  if (/fetch failed|ECONNREFUSED|ENOTFOUND/i.test(message)) {
    return { ok: false, error: "Cannot reach the Mykronos API." };
  }
  return { ok: false, error: message };
}

function refused(response: Response | undefined, what: string): { ok: false; error: string } {
  if (response && (response.status === 401 || response.status === 503)) {
    return {
      ok: false,
      error:
        "The API rejected this request. Set MYKRONOS_ADMIN_TOKEN on the " +
        "frontend to the backend's admin token.",
    };
  }
  return { ok: false, error: `Could not load ${what}${response ? ` (HTTP ${response.status})` : ""}` };
}

export async function getAgentCredentials(): Promise<Result<AgentCredential[]>> {
  try {
    const { data, response } = await backendClient().GET("/api/agents/credentials", {
      params: { query: { include_inactive: true } },
      cache: "no-store",
    });
    if (!data) return refused(response, "agent credentials");
    return { ok: true, data };
  } catch (error) {
    return failure(error);
  }
}

export async function getDelegations(): Promise<Result<DelegationRow[]>> {
  try {
    const { data, response } = await backendClient().GET("/api/approvals/delegations", {
      cache: "no-store",
    });
    if (!data) return refused(response, "delegations");
    return { ok: true, data };
  } catch (error) {
    return failure(error);
  }
}

export async function getDelegationStats(id: string): Promise<Result<DelegationStats>> {
  try {
    const { data, response } = await backendClient().GET(
      "/api/approvals/delegations/{delegation_id}/stats",
      { params: { path: { delegation_id: id } }, cache: "no-store" },
    );
    if (!data) return refused(response, "delegation stats");
    return { ok: true, data: data as unknown as DelegationStats };
  } catch (error) {
    return failure(error);
  }
}

export async function getSampleQueue(): Promise<Result<SampleRow[]>> {
  try {
    const { data, response } = await backendClient().GET("/api/approvals/samples", {
      cache: "no-store",
    });
    if (!data) return refused(response, "the sampling queue");
    return { ok: true, data: data as unknown as SampleRow[] };
  } catch (error) {
    return failure(error);
  }
}
