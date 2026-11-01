/**
 * Server-side read for the Today run sheet (TheHub #61141). Its own file so
 * this page's read does not collide with the pages rebuilt alongside it.
 */

import "server-only";

import { BackendUnavailable, backendClient } from "./api";
import type { RunSheet } from "./today";

export type Result<T> = { ok: true; data: T } | { ok: false; error: string };

export async function getRunSheet(): Promise<Result<RunSheet>> {
  try {
    const { data, response } = await backendClient().GET("/api/dashboard/today", {
      cache: "no-store",
    });
    if (!data) {
      return {
        ok: false,
        error:
          response.status === 401 || response.status === 503
            ? "The API rejected this request. Set MYKRONOS_ADMIN_TOKEN on the frontend."
            : `Could not load the run sheet (HTTP ${response.status})`,
      };
    }
    return { ok: true, data };
  } catch (error) {
    if (error instanceof BackendUnavailable) return { ok: false, error: error.detail };
    return { ok: false, error: "Cannot reach the Mykronos API." };
  }
}
