/**
 * A check's run history (TheHub #60819). Pure, so the vitest suite runs it.
 *
 * A "check" is a capability on a repository — the tile on the repo
 * Dashboard tab and the cell in the portfolio's capability column. Clicking
 * one opens `/repos/{repoId}/checks/{capability}`: every run of that check,
 * newest first, each linking to its full report. Where a capability has
 * several tools or jobs (`dast-demo` and `dast-staging`, #449) the page
 * narrows by `?tool=` or `?job=`.
 */

/** How many runs one page of the history shows. */
export const HISTORY_PAGE_SIZE = 50;

export type HistoryFilter = {
  tool?: string | null;
  job?: string | null;
  offset?: number;
};

/** A lane under one capability, as the backend's `lanes` lists it. */
export type CheckLane = {
  tool_name: string | null;
  job: string | null;
  runs: number;
  last_run_at: string | null;
  /**
   * current | stale | retired (TheHub #60816). A lane that stopped reads
   * stale or retired, never current. Optional so an older backend still types.
   */
  state?: LaneState;
  /** config | operator (retired), age | never_finished (stale), "" (current). */
  state_basis?: string;
  state_reason?: string;
  retired_by?: string | null;
  retired_at?: string | null;
  reported_since_retired?: boolean;
};

export type LaneState = "current" | "stale" | "retired";

/** Green only when current: a stale lane is amber, a retired one grey. */
export function laneTone(state: string | undefined): "pass" | "warn" | "muted" {
  if (state === "current") return "pass";
  if (state === "retired") return "muted";
  return "warn";
}

/** Which operator control a lane offers: retire, restore, or none. */
export function laneControl(lane: Pick<CheckLane, "state" | "state_basis">): "retire" | "restore" | null {
  if (lane.state === "retired") return lane.state_basis === "operator" ? "restore" : null;
  return "retire";
}

/** The body the retire/restore routes take for this lane. */
export function laneActionBody(
  lane: Pick<CheckLane, "tool_name" | "job">,
  reason: string,
): { ok: true; body: { tool_name: string | null; job: string | null; reason: string } } | {
  ok: false;
  error: string;
} {
  const text = reason.trim();
  if (!text) return { ok: false, error: "Say why: the reason is audited with the change." };
  if (text.length > 2000) return { ok: false, error: "Keep the reason under 2000 characters." };
  return { ok: true, body: { tool_name: lane.tool_name, job: lane.job, reason: text } };
}

/** The run-history page for one check, optionally narrowed and paged. */
export function checkHref(repoId: string, capability: string, filter: HistoryFilter = {}): string {
  const query = new URLSearchParams();
  if (filter.tool) query.set("tool", filter.tool);
  if (filter.job) query.set("job", filter.job);
  if (filter.offset && filter.offset > 0) query.set("offset", String(Math.floor(filter.offset)));
  const qs = query.toString();
  return `/repos/${encodeURIComponent(repoId)}/checks/${encodeURIComponent(capability)}${qs ? `?${qs}` : ""}`;
}

/** One run's full report. */
export function scanRunHref(repoId: string, scanRunId: string): string {
  return `/repos/${encodeURIComponent(repoId)}/scan-runs/${encodeURIComponent(scanRunId)}`;
}

function first(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

/**
 * The history page's search params, read defensively: a hand-edited URL with
 * `offset=-3` or `offset=abc` reads as the first page rather than an error,
 * and an empty `tool=` reads as no filter.
 */
export function parseHistoryFilter(
  params: Record<string, string | string[] | undefined>,
): Required<HistoryFilter> {
  const tool = first(params.tool)?.trim() || null;
  const job = first(params.job)?.trim() || null;
  const raw = Number(first(params.offset));
  const offset = Number.isFinite(raw) && raw > 0 ? Math.floor(raw) : 0;
  return { tool, job, offset };
}

/** How a lane is named: its job if it has one (the more specific), else its tool. */
export function laneLabel(lane: Pick<CheckLane, "tool_name" | "job">): string {
  if (lane.job && lane.tool_name) return `${lane.job} (${lane.tool_name})`;
  return lane.job ?? lane.tool_name ?? "unnamed";
}

/** A lane is worth offering as a filter only when there is more than one. */
export function lanesToOffer(lanes: CheckLane[]): CheckLane[] {
  return lanes.length > 1 ? lanes : [];
}

/** The first 7 characters, the length GitHub shows; anything shorter is shown whole. */
export function shortSha(sha: string | null | undefined): string | null {
  if (!sha) return null;
  return sha.length > 7 ? sha.slice(0, 7) : sha;
}

/**
 * How long a run took, from its start and finish. Null when either is
 * missing (a run still going, or one that never said it finished), or when
 * the clock went backwards — a duration nobody can believe is worse than none.
 */
export function runDuration(
  startedAt: string | null | undefined,
  completedAt: string | null | undefined,
): string | null {
  if (!startedAt || !completedAt) return null;
  const ms = Date.parse(asUtc(completedAt)) - Date.parse(asUtc(startedAt));
  if (!Number.isFinite(ms) || ms < 0) return null;
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s % 60}s`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
}

/**
 * The lake stores naive UTC timestamps (`_naive_utc` in schemas.py). Parsed
 * as-is, a browser reads them as local time; this pins them to UTC.
 */
export function asUtc(timestamp: string): string {
  return /([zZ]|[+-]\d{2}:?\d{2})$/.test(timestamp) ? timestamp : `${timestamp}Z`;
}

/** An absolute timestamp, in UTC, to the second: what a report should say exactly. */
export function exactTime(timestamp: string | null | undefined): string | null {
  if (!timestamp) return null;
  const parsed = Date.parse(asUtc(timestamp));
  if (!Number.isFinite(parsed)) return timestamp;
  return `${new Date(parsed).toISOString().slice(0, 19).replace("T", " ")} UTC`;
}

/** Coverage as a percentage, or null when not reported (a different fact from 0%). */
export function percent(rate: number | null | undefined): string | null {
  if (rate === null || rate === undefined) return null;
  return `${Math.round(rate * 1000) / 10}%`;
}
