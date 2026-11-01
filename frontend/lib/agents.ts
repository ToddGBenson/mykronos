/**
 * The agents and delegations view (TheHub #61144, spec 34 §5.2).
 *
 * Two things were invisible before this page. A credential minted with the
 * 12-hour default lapses partway through a long run, and the agent then sees
 * a 401 that reads like a stale token; listing every credential with its
 * lifetime makes the default visible before it bites. And a standing
 * delegation's scope (which duty, which tiers, which model families, how much
 * is sampled) was readable only as JSON from `/api/approvals/delegations`.
 *
 * Everything here is pure, so the page's sentences are tested rather than
 * read. Anything that depends on the current time takes `now` as an argument:
 * the server render must not read the clock (see `relative-time.tsx`).
 */

import type { components } from "./api-types";

export type AgentCredential = components["schemas"]["AgentOut"];
export type DelegationRow = components["schemas"]["DelegationOut"];

/** `mykronos.agents.DEFAULT_TTL_HOURS`. */
export const DEFAULT_TTL_HOURS = 12;

/** Timestamps from the backend are naive UTC (spec 01 §6). */
export function utcMs(value: string): number {
  return Date.parse(/[zZ]|[+-]\d\d:\d\d$/.test(value) ? value : `${value}Z`);
}

export function ttlHours(c: AgentCredential): number {
  return (utcMs(c.expires_at) - utcMs(c.minted_at)) / 3_600_000;
}

/** "20m lifetime", "12h lifetime", "7d lifetime": minutes under an hour,
 *  so a short-lived credential never reads as "0h". */
export function lifetimeLabel(c: AgentCredential): string {
  const hours = ttlHours(c);
  if (hours < 1) return `${Math.max(1, Math.round(hours * 60))}m lifetime`;
  if (hours < 48) return `${Math.round(hours)}h lifetime`;
  return `${Math.round(hours / 24)}d lifetime`;
}

export function isDefaultTtl(c: AgentCredential): boolean {
  return Math.abs(ttlHours(c) - DEFAULT_TTL_HOURS) < 0.05;
}

export type CredentialState = "active" | "expired" | "revoked";

export function credentialState(c: AgentCredential): CredentialState {
  if (c.revoked_at) return "revoked";
  return c.active ? "active" : "expired";
}

/** The one sentence a row needs beyond its fields, or null when it needs none. */
export function credentialNote(c: AgentCredential): string | null {
  const state = credentialState(c);
  if (state === "revoked") return "Revoked. Its sub-agents were revoked with it.";
  if (!isDefaultTtl(c)) return null;
  if (state === "expired") {
    return (
      "Lapsed on the 12-hour default. A run that was still using it got 401s " +
      "that look like a stale token."
    );
  }
  return (
    "Minted with the 12-hour default, so a long run stops when it lapses. " +
    "Mint with ttl_hours (up to 168) for work that runs overnight."
  );
}

/**
 * Live credentials soonest-to-lapse first, because that is the next thing to
 * go wrong; ended ones newest first, capped, because the history is long and
 * only the recent end of it explains a failure someone is looking at.
 */
export function orderCredentials(
  rows: AgentCredential[],
  endedLimit = 20,
): { live: AgentCredential[]; ended: AgentCredential[]; endedHidden: number } {
  const live = rows
    .filter((c) => credentialState(c) === "active")
    .sort((a, b) => utcMs(a.expires_at) - utcMs(b.expires_at));
  const allEnded = rows
    .filter((c) => credentialState(c) !== "active")
    .sort((a, b) => utcMs(b.revoked_at ?? b.expires_at) - utcMs(a.revoked_at ?? a.expires_at));
  return {
    live,
    ended: allEnded.slice(0, endedLimit),
    endedHidden: Math.max(0, allEnded.length - endedLimit),
  };
}

/** The live sub-agents a revocation of `instance` takes with it. */
export function descendants(instance: string, rows: AgentCredential[]): string[] {
  return rows
    .filter((c) => c.instance !== instance && c.active && !c.revoked_at)
    .filter((c) => c.lineage.includes(instance))
    .map((c) => c.instance);
}

function span(ms: number): string {
  const minutes = Math.round(ms / 60_000);
  if (minutes < 90) return `${minutes}m`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours}h`;
  return `${Math.round(hours / 24)}d`;
}

export function countdown(expiresAt: string, now: number): string {
  const delta = utcMs(expiresAt) - now;
  return delta > 0 ? `lapses in ${span(delta)}` : `lapsed ${span(-delta)} ago`;
}

export type DelegationState = "active" | "suspended" | "expired" | "revoked";

export function delegationState(d: DelegationRow): DelegationState {
  if (d.revoked_at) return "revoked";
  if (d.suspended_at) return "suspended";
  return d.active ? "active" : "expired";
}

function list(items: string[], joiner: "and" | "or"): string {
  if (items.length <= 1) return items.join("");
  return `${items.slice(0, -1).join(", ")} ${joiner} ${items[items.length - 1]}`;
}

function samplingPhrase(rate: number): string {
  if (rate <= 0) return "no decision is sampled for your review";
  if (rate >= 1) return "every decision is sampled for your review";
  const inverse = 1 / rate;
  if (Math.abs(inverse - Math.round(inverse)) < 1e-9) {
    return `1 in ${Math.round(inverse)} decisions is sampled for your review`;
  }
  return `${Math.round(rate * 100)}% of decisions are sampled for your review`;
}

/** What the delegated agent may decide, as a sentence rather than JSON. */
export function delegationScope(d: DelegationRow): string {
  const duty = d.duty.replace(/_/g, " ");
  const families = d.approver_families.length ? list(d.approver_families, "or") : "any family";
  return `${duty} at ${list(d.tiers, "and")}, by ${families}; ${samplingPhrase(d.sampling)}`;
}

export type Agreement = { agreed: number; reviewed: number; window: number; threshold: number };

export function agreementNote(a: Agreement): string {
  const threshold = `${Math.round(a.threshold * 100)}%`;
  if (a.reviewed === 0) {
    return `No sampled decision has been reviewed yet. It suspends if agreement falls below ${threshold}.`;
  }
  const rate = Math.round((a.agreed / a.reviewed) * 100);
  return (
    `You agreed with ${a.agreed} of the last ${a.reviewed} sampled decisions (${rate}%). ` +
    `It suspends below ${threshold}.`
  );
}
