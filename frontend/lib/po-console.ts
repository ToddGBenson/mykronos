/**
 * Server-side reads for the Product Owner console's phase 2 views (spec 35 §8).
 *
 * Kept apart from `server.ts` so these views can grow without touching the
 * phase 1 reads. Same contract: each returns data or a sentence saying why it
 * could not, and the admin token never leaves this server.
 */

import "server-only";

import { BackendUnavailable, backendClient } from "./api";
import type { paths } from "./api-types";
import type { Result } from "./server";

type Json<P extends keyof paths> = paths[P] extends {
  get: { responses: { 200: { content: { "application/json": infer T } } } };
}
  ? T
  : never;

export type PoDelivery = Json<"/api/dashboard/repos/{repo_id}/product-owner/delivery">;
export type PoDeliveryRow = PoDelivery["shipped"][number];
export type PoInbox = Json<"/api/dashboard/repos/{repo_id}/product-owner/approvals">;
export type PoInboxItem = PoInbox["pending"][number];
export type PoRoles = Json<"/api/dashboard/repos/{repo_id}/product-owner/roles">;
export type PoRetro = Json<"/api/dashboard/repos/{repo_id}/product-owner/retro">;
export type PoGateFailure = PoRetro["failures"][number];

function failure(error: unknown, fallback: string): { ok: false; error: string } {
  if (error instanceof BackendUnavailable) return { ok: false, error: error.detail };
  const message = error instanceof Error ? error.message : String(error);
  if (/fetch failed|ECONNREFUSED|ENOTFOUND/i.test(message)) {
    return { ok: false, error: "Cannot reach the Mykronos API." };
  }
  return { ok: false, error: fallback };
}

function refused(response: Response | undefined, fallback: string): string {
  if (!response) return fallback;
  if (response.status === 401 || response.status === 503) {
    return (
      "The API rejected this request. Set MYKRONOS_ADMIN_TOKEN on the frontend to the " +
      "backend's admin token."
    );
  }
  return `${fallback} (HTTP ${response.status})`;
}

/** A window in days from the query string, or the view's default. */
export function windowDays(raw: string | undefined, fallback: number, max: number): number {
  const value = Number(raw);
  return Number.isInteger(value) && value >= 1 && value <= max ? value : fallback;
}

export async function getPoDelivery(repoId: string, days: number): Promise<Result<PoDelivery>> {
  try {
    const { data, response } = await backendClient().GET(
      "/api/dashboard/repos/{repo_id}/product-owner/delivery",
      { params: { path: { repo_id: repoId }, query: { days } }, cache: "no-store" },
    );
    return data
      ? { ok: true, data }
      : { ok: false, error: refused(response, "Could not load Delivery") };
  } catch (error) {
    return failure(error, "Could not load Delivery");
  }
}

export async function getPoApprovals(repoId: string): Promise<Result<PoInbox>> {
  try {
    const { data, response } = await backendClient().GET(
      "/api/dashboard/repos/{repo_id}/product-owner/approvals",
      { params: { path: { repo_id: repoId } }, cache: "no-store" },
    );
    return data
      ? { ok: true, data }
      : { ok: false, error: refused(response, "Could not load the approvals inbox") };
  } catch (error) {
    return failure(error, "Could not load the approvals inbox");
  }
}

export async function getPoRoles(repoId: string): Promise<Result<PoRoles>> {
  try {
    const { data, response } = await backendClient().GET(
      "/api/dashboard/repos/{repo_id}/product-owner/roles",
      { params: { path: { repo_id: repoId } }, cache: "no-store" },
    );
    return data
      ? { ok: true, data }
      : { ok: false, error: refused(response, "Could not load Roles & agents") };
  } catch (error) {
    return failure(error, "Could not load Roles & agents");
  }
}

export async function getPoRetro(repoId: string, days: number): Promise<Result<PoRetro>> {
  try {
    const { data, response } = await backendClient().GET(
      "/api/dashboard/repos/{repo_id}/product-owner/retro",
      { params: { path: { repo_id: repoId }, query: { days } }, cache: "no-store" },
    );
    return data
      ? { ok: true, data }
      : { ok: false, error: refused(response, "Could not load the retro") };
  } catch (error) {
    return failure(error, "Could not load the retro");
  }
}

export type PoTraceView = Json<"/api/dashboard/repos/{repo_id}/product-owner/trace">;
export type PoTrace = NonNullable<PoTraceView["trace"]>;

export async function getPoTrace(
  repoId: string,
  storyId: number | undefined,
): Promise<Result<PoTraceView>> {
  try {
    const { data, response } = await backendClient().GET(
      "/api/dashboard/repos/{repo_id}/product-owner/trace",
      {
        params: { path: { repo_id: repoId }, query: storyId ? { story_id: storyId } : {} },
        cache: "no-store",
      },
    );
    return data
      ? { ok: true, data }
      : { ok: false, error: refused(response, "Could not load the delivery trace") };
  } catch (error) {
    return failure(error, "Could not load the delivery trace");
  }
}
