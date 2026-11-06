/**
 * The Today run sheet's actions (TheHub #61142): Merge in order, Deploy and
 * the Decide drawer. Pure, so the vitest suite runs it.
 *
 * Shipped switched off (operator decision 2026-11-04; on after 11-08 at the
 * earliest). Two switches, both on the server: `MYKRONOS_RUNSHEET_ACTIONS=on`
 * in the Next server's environment, which no browser can set, and the
 * backend's `runsheet_actions_enabled`, which the run sheet reports as
 * `actions_enabled`. With either off, /today renders as it did before and the
 * proxy routes answer 404.
 *
 * Neither action merges or deploys from the server. Each re-checks and queues
 * a request for the host runner, which keeps Start-Here's rules: one batch,
 * TheHub first, `--match-head-commit`, stop at the first failure, and never
 * move an approved head.
 */
import type { components } from "@/lib/api-types";
import type { ItemLike } from "@/lib/today";

export const ACTIONS_ENV = "MYKRONOS_RUNSHEET_ACTIONS";
export const MERGE_ROUTE = "/api/today/merge";
export const DEPLOY_ROUTE = "/api/today/deploy";
/** Start-Here's batch limit (operator decision 2026-11-03). */
export const MAX_BATCH = 5;
/** Start-Here merges TheHub first. */
const FIRST = new Set(["ToddGBenson/TheHub"]);

export type MergeAsk = components["schemas"]["MergeAskIn"];
export type MergeOutcome = components["schemas"]["MergeOutcomeOut"];

type Env = Record<string, string | undefined>;

/** Exactly `on`: a typo, `true` or `1` leaves the actions off. */
export function actionsOn(env: Env): boolean {
  return env[ACTIONS_ENV] === "on";
}

/** Render the actions only when both the Next server and the backend say on. */
export function showActions(env: Env, backendEnabled: boolean | undefined): boolean {
  return actionsOn(env) && backendEnabled === true;
}

const PR_REF = /^([\w.-]+\/[\w.-]+)#(\d+)$/;

/** The Merge step's ready lines as one batch: TheHub first, at most five. */
export function mergeBatch(items: readonly ItemLike[]): { batch: MergeAsk[]; left: number } {
  const ready: MergeAsk[] = [];
  for (const item of items) {
    const match = PR_REF.exec(item.ref ?? "");
    if (item.state !== "ready" || !match || !item.sha) continue;
    ready.push({ repo_full_name: match[1], number: Number(match[2]), head_sha: item.sha });
  }
  ready.sort(
    (a, b) =>
      Number(!FIRST.has(a.repo_full_name)) - Number(!FIRST.has(b.repo_full_name)) ||
      a.repo_full_name.localeCompare(b.repo_full_name) ||
      a.number - b.number,
  );
  return { batch: ready.slice(0, MAX_BATCH), left: Math.max(0, ready.length - MAX_BATCH) };
}

/** A decide line opens its packet in the drawer, on the same page. */
export function decideHref(requestId: string): string {
  return `/today?decide=${encodeURIComponent(requestId)}`;
}

/** Where "Record" goes from the drawer: the next pending request's drawer, then Today. */
export function drawerNext(
  pendingIds: readonly string[],
  current: string,
): { href: string; label: string } {
  const at = pendingIds.indexOf(current);
  const next = at < 0 ? pendingIds[0] : pendingIds[at + 1];
  if (!next || next === current) return { href: "/today", label: "return to Today" };
  return {
    href: decideHref(next),
    label: `go to ${pendingIds.indexOf(next) + 1} of ${pendingIds.length}`,
  };
}

/**
 * Why a browser request may not reach an action, or null (TheHub #61142).
 *
 * The gate's cookie is SameSite=Lax, which stops a cross-site form but not a
 * page on a sibling subdomain of the same site. So the action routes take only
 * JSON (a cross-origin JSON POST needs a CORS preflight nobody answers), and
 * refuse a request the browser marks as not same-origin, or whose Origin is
 * another host.
 */
export function crossOriginRefusal(headers: Headers): string | null {
  const type = headers.get("content-type") ?? "";
  if (!type.toLowerCase().startsWith("application/json")) return "Send JSON.";
  const site = headers.get("sec-fetch-site");
  if (site && site !== "same-origin") return "Cross-origin requests are refused.";
  const origin = headers.get("origin");
  const host = headers.get("x-forwarded-host") ?? headers.get("host");
  if (origin) {
    let originHost = "";
    try {
      originHost = new URL(origin).host;
    } catch {
      return "Cross-origin requests are refused.";
    }
    if (!host || originHost !== host) return "Cross-origin requests are refused.";
  }
  return null;
}
