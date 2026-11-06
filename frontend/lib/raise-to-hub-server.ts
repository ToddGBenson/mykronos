/** Server-side read of what has been raised from a page's rows (TheHub #60911). */

import "server-only";

import { backendClient } from "./api";
import type { RaiseKind, RaisedRead } from "./raise-to-hub";

export async function getRaised(kind: RaiseKind, subjects: string[]): Promise<RaisedRead> {
  if (subjects.length === 0) return { ok: true, data: { links: [] } };
  try {
    const { data, response } = await backendClient().GET("/api/dashboard/raised", {
      params: { query: { kind, subject: subjects } },
      cache: "no-store",
    });
    return data ? { ok: true, data } : { ok: false, error: `HTTP ${response.status}` };
  } catch {
    return { ok: false, error: "Cannot reach the Mykronos API." };
  }
}
