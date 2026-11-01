/**
 * The Portfolio status board (TheHub #61138, design v2 P4 and P6).
 *
 * Each product is a band of twelve tiles, one per capability or lane. A tile
 * is in one of six states, and it shows the age of its last run, its count of
 * accepted findings, or its overdue count and the oldest one's age. Pure, so
 * the vitest suite runs it; the page and the tile component only draw it.
 *
 * Built from existing endpoints: the portfolio's `capability_states` give
 * the run state, and the open-findings endpoint gives the overdue and
 * accepted counts per capability (`getBoardCounts`).
 */

import type { CapabilityRun } from "./capability-cell";
import { asUtc } from "./checks";

export type TileState = "healthy" | "failing" | "stale" | "never" | "accepted" | "overdue";

/**
 * The twelve tiles, in pipeline-stage order. The portfolio measures fifteen
 * capabilities. Network (ingest only, no scanner), AI checks and
 * auto-remediation are not tiles here. They have no lane of their own to
 * judge, and the repository page still shows all fifteen.
 */
export const BOARD_CAPABILITIES = [
  { capability: "unit", short: "Unit", label: "Unit tests" },
  { capability: "qa", short: "Lint", label: "QA / docs quality" },
  { capability: "sast", short: "SAST", label: "Static analysis (SAST)" },
  { capability: "secrets", short: "Secrets", label: "Secret scanning" },
  { capability: "atlas", short: "SCA", label: "Dependencies (SCA)" },
  { capability: "containers", short: "Container", label: "Container scanning" },
  { capability: "iac", short: "IaC", label: "Infrastructure as code" },
  { capability: "functional", short: "Func", label: "Functional tests" },
  { capability: "dast", short: "DAST", label: "Dynamic analysis (DAST)" },
  { capability: "cloud", short: "Cloud", label: "Cloud posture" },
  { capability: "aegis", short: "Insider", label: "Insider risk" },
  { capability: "oracle", short: "Gate", label: "Risk decisions" },
] as const;

/** The words for each state, as the legend, the summary and the tile's
 *  accessible name say them. Colour is never the only carrier. */
export const TILE_WORD: Record<TileState, string> = {
  healthy: "healthy",
  failing: "failing",
  stale: "stale or silent",
  never: "never scanned",
  accepted: "accepted risk",
  overdue: "overdue",
};

/** Legend and summary order: the problems first. */
export const TILE_ORDER: TileState[] = [
  "failing",
  "overdue",
  "stale",
  "never",
  "accepted",
  "healthy",
];

/** The board's legend reads in the design's order. */
export const LEGEND: TileState[] = ["healthy", "failing", "stale", "never", "accepted", "overdue"];

/** States that put a tile, and its band, in front of somebody. */
const PROBLEM: TileState[] = ["failing", "overdue", "stale"];

const STALE_MS = 7 * 24 * 3600_000;

export type OverdueCount = { count: number; oldestDays: number | null };

/** Per-capability finding counts for one repository. */
export type BoardCounts = {
  accepted: Record<string, number>;
  overdue: Record<string, OverdueCount>;
};

export type Tile = {
  state: TileState;
  /** When the state began to be true: the last run, or the failure. */
  since: string | null;
  count?: number;
  oldestDays?: number | null;
};

const LANE_FAILED = new Set(["failed", "errored"]);

function parse(timestamp: string | null | undefined): number | null {
  if (!timestamp) return null;
  const at = Date.parse(asUtc(timestamp));
  return Number.isFinite(at) ? at : null;
}

/**
 * Which of the six states a tile is in. A failure outranks everything,
 * because nothing else on the tile can be trusted while the check is broken.
 * Overdue comes next, because a deadline has passed. A stale or silent check
 * outranks accepted risk, because the acceptance cannot be re-checked by a
 * scan that is not running.
 */
export function tileState(
  {
    enabled,
    pending,
    run,
    accepted = 0,
    overdue,
  }: {
    enabled: boolean;
    pending: boolean;
    run?: CapabilityRun;
    accepted?: number;
    overdue?: OverdueCount;
  },
  now: number = Date.now(),
): Tile {
  void pending; // An install PR that has not merged is still not scanning.
  if (run?.refused) return { state: "failing", since: run.last_refused_at ?? null };
  if (enabled && run?.last_run_failed) {
    // From the lane's failed build when the lane is what failed (or its state
    // is unknown); from the scan when only the scan failed.
    const laneFailed = !run.lane_status || LANE_FAILED.has(run.lane_status);
    const since = (laneFailed ? run.lane_finished_at : null) ?? run.last_scan_at ?? null;
    return { state: "failing", since };
  }
  if (overdue && overdue.count > 0) {
    return {
      state: "overdue",
      since: run?.last_scan_at ?? null,
      count: overdue.count,
      oldestDays: overdue.oldestDays,
    };
  }
  if (!enabled) return { state: "never", since: null };
  if (!run?.has_scanned) return { state: "stale", since: null };
  const last = parse(run.last_scan_at);
  if (last !== null && now - last > STALE_MS) {
    return { state: "stale", since: run.last_scan_at ?? null };
  }
  if (accepted > 0) return { state: "accepted", since: run.last_scan_at ?? null, count: accepted };
  return { state: "healthy", since: run.last_scan_at ?? null };
}

/** `15m`, `3h`, `47h`, `9d`: hours until two days, then days. */
export function ageLabel(timestamp: string | null | undefined, now: number = Date.now()): string {
  const at = parse(timestamp);
  if (at === null) return "—";
  const minutes = Math.max(0, Math.floor((now - at) / 60_000));
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return `${hours}h`;
  return `${Math.floor(hours / 24)}d`;
}

/** What the tile prints under its name. */
export function tileValue(tile: Tile, now: number = Date.now()): string {
  if (tile.state === "never") return "—";
  if (tile.state === "accepted") return `${tile.count ?? 0}`;
  if (tile.state === "overdue") {
    const oldest = typeof tile.oldestDays === "number" ? `·${tile.oldestDays}d` : "";
    return `${tile.count ?? 0}${oldest}`;
  }
  return ageLabel(tile.since, now);
}

/** The tile's state in words, for its accessible name and hover. */
export function tileWords(tile: Tile, now: number = Date.now()): string {
  const word = TILE_WORD[tile.state];
  if (tile.state === "never") return word;
  if (tile.state === "accepted") {
    return `${word}, ${tile.count} finding${tile.count === 1 ? "" : "s"}`;
  }
  if (tile.state === "overdue") {
    const oldest = typeof tile.oldestDays === "number" ? `, the oldest ${tile.oldestDays} days old` : "";
    return `${word}, ${tile.count} finding${tile.count === 1 ? "" : "s"} past target${oldest}`;
  }
  if (!tile.since) return `${word}, never reported`;
  const age = ageLabel(tile.since, now);
  return tile.state === "failing" ? `${word} for ${age}` : `${word}, last run ${age} ago`;
}

/** The fields of a portfolio row the board reads. */
export type BoardRepo = {
  repo_id: string;
  repo_full_name: string;
  enabled_capabilities: string[];
  pending_capabilities?: string[] | null;
  capability_states: CapabilityRun[];
};

/** A band's twelve tiles. */
export function bandTiles(
  repo: BoardRepo,
  now: number = Date.now(),
  counts?: BoardCounts | null,
): { capability: string; short: string; label: string; tile: Tile }[] {
  return BOARD_CAPABILITIES.map(({ capability, short, label }) => ({
    capability,
    short,
    label,
    tile: tileState(
      {
        enabled: repo.enabled_capabilities.includes(capability),
        pending: (repo.pending_capabilities ?? []).includes(capability),
        run: repo.capability_states.find((s) => s.capability === capability),
        accepted: counts?.accepted[capability] ?? 0,
        overdue: counts?.overdue[capability],
      },
      now,
    ),
  }));
}

function emptyCounts(): Record<TileState, number> {
  return { healthy: 0, failing: 0, stale: 0, never: 0, accepted: 0, overdue: 0 };
}

/** How many tiles of a band are in each state. */
export function bandCounts(
  repo: BoardRepo,
  now: number = Date.now(),
  counts?: BoardCounts | null,
): Record<TileState, number> {
  const out = emptyCounts();
  for (const { tile } of bandTiles(repo, now, counts)) out[tile.state] += 1;
  return out;
}

/** Tiles that need a look: failing, overdue, stale or silent. */
export function problemCount(states: Record<TileState, number>): number {
  return PROBLEM.reduce((sum, state) => sum + states[state], 0);
}

/** The whole board's tiles by state, for the line under the title. */
export function bandSummary(
  repos: BoardRepo[],
  now: number = Date.now(),
  counts: Record<string, BoardCounts | null | undefined> = {},
): Record<TileState, number> {
  const out = emptyCounts();
  for (const repo of repos) {
    const band = bandCounts(repo, now, counts[repo.repo_id]);
    for (const state of TILE_ORDER) out[state] += band[state];
  }
  return out;
}

export type BoardSort = "problems" | "az";

/**
 * Problems first: more failing tiles, then more overdue, then more stale or
 * silent, and A to Z among equals. `az` is A to Z only.
 */
export function sortBands<T extends BoardRepo>(
  repos: T[],
  sort: BoardSort,
  now: number = Date.now(),
  counts: Record<string, BoardCounts | null | undefined> = {},
): T[] {
  const byName = (a: T, b: T) => a.repo_full_name.localeCompare(b.repo_full_name);
  if (sort === "az") return [...repos].sort(byName);
  const keyed = repos.map((repo) => ({ repo, states: bandCounts(repo, now, counts[repo.repo_id]) }));
  keyed.sort((a, b) => {
    for (const state of PROBLEM) {
      const diff = b.states[state] - a.states[state];
      if (diff) return diff;
    }
    return byName(a.repo, b.repo);
  });
  return keyed.map((k) => k.repo);
}

/**
 * Everything the page draws, read against one clock: the bands in order,
 * each with its tiles and how many need a look, and the whole board's
 * counts by state.
 */
export function buildBoard<T extends BoardRepo>(
  repos: T[],
  sort: BoardSort,
  counts: Record<string, BoardCounts | null | undefined> = {},
  now: number = Date.now(),
) {
  const bands = sortBands(repos, sort, now, counts).map((repo) => {
    const tiles = bandTiles(repo, now, counts[repo.repo_id]);
    const states = emptyCounts();
    for (const { tile } of tiles) states[tile.state] += 1;
    return { repo, tiles, needs: problemCount(states) };
  });
  return { now, bands, summary: bandSummary(repos, now, counts) };
}

/** "1 crit · 7 high". */
export function severityLine(counts: Record<string, number> | null | undefined): string {
  return `${counts?.critical ?? 0} crit · ${counts?.high ?? 0} high`;
}
