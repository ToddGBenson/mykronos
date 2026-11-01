import { prerender } from "react-dom/static";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ageLabel, bandSummary, sortBands, tileState } from "../lib/portfolio-board";

/**
 * The Portfolio status board (TheHub #61138, v2 P4 and P6): each product a
 * band of tiles, one per capability, coloured by state, each with an icon, a
 * word and the age of its last run, each linking to that check's history.
 * Bands with problems sort first. It replaces the 15px capability cells.
 */

const getPortfolio = vi.fn();
vi.mock("@/lib/server", () => ({ getPortfolio }));

const NOW = Date.parse("2026-10-31T12:00:00Z");
const hoursAgo = (h: number) => new Date(NOW - h * 3600_000).toISOString();

describe("tileState", () => {
  const run = (over: Record<string, unknown> = {}) => ({
    capability: "sast",
    has_scanned: true,
    last_run_failed: false,
    last_scan_at: hoursAgo(3),
    ...over,
  });

  it("is healthy when the last run worked within the week", () => {
    expect(tileState({ enabled: true, pending: false, run: run() }, NOW)).toEqual({
      state: "healthy",
      since: hoursAgo(3),
    });
  });

  it("is failing when the last scan or its lane failed, from when it failed", () => {
    const failed = run({ last_run_failed: true, lane_finished_at: hoursAgo(1) });
    expect(tileState({ enabled: true, pending: false, run: failed }, NOW)).toEqual({
      state: "failing",
      since: hoursAgo(1),
    });
  });

  it("is failing when uploads are refused, even if not enabled", () => {
    const refused = run({ refused: true, last_refused_at: hoursAgo(2) });
    expect(tileState({ enabled: false, pending: false, run: refused }, NOW).state).toBe("failing");
  });

  it("is stale when the last good run is more than seven days old", () => {
    const old = run({ last_scan_at: hoursAgo(8 * 24) });
    expect(tileState({ enabled: true, pending: false, run: old }, NOW).state).toBe("stale");
  });

  it("is stale (silent) when enabled and never reported", () => {
    const silent = run({ has_scanned: false, last_scan_at: null });
    expect(tileState({ enabled: true, pending: false, run: silent }, NOW)).toEqual({
      state: "stale",
      since: null,
    });
  });

  it("is never scanned when not enabled, or only pending", () => {
    expect(tileState({ enabled: false, pending: false }, NOW).state).toBe("never");
    expect(tileState({ enabled: false, pending: true }, NOW).state).toBe("never");
  });
});

describe("ageLabel", () => {
  it("reads minutes, hours, then days", () => {
    expect(ageLabel(hoursAgo(0.25), NOW)).toBe("15m");
    expect(ageLabel(hoursAgo(3), NOW)).toBe("3h");
    expect(ageLabel(hoursAgo(47), NOW)).toBe("47h");
    expect(ageLabel(hoursAgo(9 * 24), NOW)).toBe("9d");
    expect(ageLabel(null, NOW)).toBe("—");
  });
});

const ROW = {
  status: "active",
  github_url: "https://github.com/example-org/x",
  pipeline_url: null,
  synthetic: false,
  pending_capabilities: [],
  severity_counts: { critical: 0, high: 0 },
  total_open: 0,
  last_scan_at: hoursAgo(1),
  awaiting_first_scan: false,
  is_stale: false,
  risk_score: null,
  recommendation: "go",
  raw_risk_score: null,
  risk_assessed_at: null,
  deploy_lag: null,
};

function repo(id: string, name: string, over: Record<string, unknown> = {}) {
  return {
    ...ROW,
    repo_id: id,
    repo_full_name: name,
    enabled_capabilities: ["sast", "secrets"],
    capability_states: [
      { capability: "sast", has_scanned: true, enabled: true, last_scan_at: hoursAgo(2) },
      { capability: "secrets", has_scanned: true, enabled: true, last_scan_at: hoursAgo(2) },
    ],
    ...over,
  };
}

const healthy = repo("r-a", "example-org/alpha");
const broken = repo("r-z", "example-org/zulu", {
  severity_counts: { critical: 1, high: 7 },
  recommendation: "no_go",
  capability_states: [
    {
      capability: "sast",
      has_scanned: true,
      enabled: true,
      last_run_failed: true,
      last_scan_at: hoursAgo(3),
      lane_status: "failed",
      lane_finished_at: hoursAgo(3),
    },
    { capability: "secrets", has_scanned: false, enabled: true },
  ],
});
const bench = repo("r-b", "example-org/bench", { synthetic: true });

describe("sortBands", () => {
  it("puts bands with problems first, then A to Z", () => {
    const sorted = sortBands([healthy, broken] as never, "problems", NOW);
    expect(sorted.map((r) => r.repo_full_name)).toEqual(["example-org/zulu", "example-org/alpha"]);
    const az = sortBands([broken, healthy] as never, "az", NOW);
    expect(az.map((r) => r.repo_full_name)).toEqual(["example-org/alpha", "example-org/zulu"]);
  });
});

describe("bandSummary", () => {
  it("counts the states across the board", () => {
    const counts = bandSummary([healthy, broken] as never, NOW);
    expect(counts.failing).toBe(1);
    expect(counts.stale).toBe(1);
    expect(counts.healthy).toBe(4 - 2);
    expect(counts.never).toBe(2 * 15 - 4);
  });
});

describe("the Portfolio page", () => {
  beforeEach(() => {
    vi.useFakeTimers({ now: NOW, toFake: ["Date"] });
    getPortfolio.mockResolvedValue({
      ok: true,
      data: {
        summary: {
          active_repos: 3,
          open_critical: 1,
          open_high: 7,
          repos_no_go: 1,
          repos_not_assessed: 0,
          repos_awaiting_first_scan: 0,
          repos_with_stale_scans: 0,
          overdue_findings: 0,
        },
        repos: [healthy, broken, bench],
      },
    });
  });

  async function render(query: Record<string, string> = {}) {
    const { default: PortfolioPage } = await import("../app/page");
    const { prelude } = await prerender(
      await PortfolioPage({ searchParams: Promise.resolve(query) }),
    );
    return new Response(prelude).text();
  }

  it("draws a band per product, problems first, each named by a link to its page", async () => {
    const html = await render();
    expect(html.indexOf("example-org/zulu")).toBeLessThan(html.indexOf("example-org/alpha"));
    expect(html).toContain('href="/repos/r-z"');
    expect(html).toContain('href="/repos/r-a"');
  });

  it("draws every capability as a tile that links to its run history", async () => {
    const html = await render();
    expect(html).toContain('href="/repos/r-z/checks/sast"');
    const tiles = html.match(/<a [^>]*data-tile="[a-z]+"[^>]*>/g) ?? [];
    expect(tiles.length).toBe(2 * 15);
    for (const tile of tiles) expect(tile).toMatch(/min-h-11/);
    for (const tile of tiles) expect(tile).toMatch(/sm:min-h-14/);
  });

  it("names each tile's state in words, not by colour alone", async () => {
    const html = await render();
    expect(html).toMatch(/aria-label="Static analysis \(SAST\): failing[^"]*3h/);
    expect(html).toMatch(/aria-label="Secret scanning: stale or silent/);
    expect(html).toMatch(/aria-label="Dynamic analysis \(DAST\): never scanned/);
  });

  it("says what is wrong on the board at the top", async () => {
    const html = await render();
    expect(html).toContain("1 failing");
    expect(html).toContain("1 stale or silent");
  });

  it("hides the benchmark corpus unless asked", async () => {
    expect(await render()).not.toContain("example-org/bench");
    expect(await render({ benchmark: "1" })).toContain("example-org/bench");
  });

  it("carries the gate verdict and the severity counts on the band", async () => {
    const html = await render();
    expect(html).toContain("1 crit · 7 high");
  });

  it("has a legend with the icon and word for each state", async () => {
    const html = await render();
    for (const word of ["healthy", "failing", "stale or silent", "never scanned"]) {
      expect(html).toContain(word);
    }
  });
});
