/**
 * A check's run history (TheHub #60819), run rather than read: the links a
 * tile opens, the filters a hand-edited URL can carry, and the small
 * formatting a run row depends on.
 */
import { describe, expect, it } from "vitest";

import {
  asUtc,
  checkHref,
  exactTime,
  laneActionBody,
  laneControl,
  laneLabel,
  laneTone,
  lanesToOffer,
  parseHistoryFilter,
  percent,
  runDuration,
  scanRunHref,
  shortSha,
} from "../lib/checks";

describe("checkHref", () => {
  it("opens a check's history on its repository", () => {
    expect(checkHref("42", "sast")).toBe("/repos/42/checks/sast");
  });

  it("narrows by tool or job, and pages by offset", () => {
    expect(checkHref("42", "dast", { job: "dast-staging" })).toBe(
      "/repos/42/checks/dast?job=dast-staging",
    );
    expect(checkHref("42", "sast", { tool: "codeql", offset: 50 })).toBe(
      "/repos/42/checks/sast?tool=codeql&offset=50",
    );
  });

  it("leaves out empty filters and the first page's offset", () => {
    expect(checkHref("42", "sast", { tool: null, job: "", offset: 0 })).toBe(
      "/repos/42/checks/sast",
    );
  });

  it("encodes what it puts in the path and the query", () => {
    expect(checkHref("a/b", "x y", { job: "a&b" })).toBe("/repos/a%2Fb/checks/x%20y?job=a%26b");
  });
});

describe("scanRunHref", () => {
  it("links a run to its full report", () => {
    expect(scanRunHref("42", "run 1")).toBe("/repos/42/scan-runs/run%201");
  });
});

describe("parseHistoryFilter", () => {
  it("reads tool, job and offset", () => {
    expect(parseHistoryFilter({ tool: "zap", job: "dast-demo", offset: "50" })).toEqual({
      tool: "zap",
      job: "dast-demo",
      offset: 50,
    });
  });

  it("reads a bad offset as the first page rather than an error", () => {
    for (const offset of ["-3", "abc", "", undefined]) {
      expect(parseHistoryFilter({ offset }).offset).toBe(0);
    }
    expect(parseHistoryFilter({ offset: "12.7" }).offset).toBe(12);
  });

  it("reads an empty filter as none, and a repeated one by its first value", () => {
    expect(parseHistoryFilter({ tool: "  ", job: ["a", "b"] })).toEqual({
      tool: null,
      job: "a",
      offset: 0,
    });
  });
});

describe("lanes", () => {
  const lane = (tool_name: string | null, job: string | null) => ({
    tool_name,
    job,
    runs: 1,
    last_run_at: null,
  });

  it("names a lane by its job, with the tool beside it", () => {
    expect(laneLabel(lane("zap", "dast-staging"))).toBe("dast-staging (zap)");
    expect(laneLabel(lane("codeql", null))).toBe("codeql");
    expect(laneLabel(lane(null, null))).toBe("unnamed");
  });

  it("offers lanes as filters only when a capability has more than one", () => {
    expect(lanesToOffer([lane("codeql", null)])).toEqual([]);
    expect(lanesToOffer([lane("zap", "a"), lane("zap", "b")])).toHaveLength(2);
  });
});

describe("shortSha", () => {
  it("shortens to GitHub's seven characters", () => {
    expect(shortSha("a91f2c7e0b1d")).toBe("a91f2c7");
    expect(shortSha("abc")).toBe("abc");
    expect(shortSha(null)).toBeNull();
  });
});

describe("runDuration", () => {
  it("says how long a run took", () => {
    expect(runDuration("2026-10-17T10:00:00", "2026-10-17T10:00:42")).toBe("42s");
    expect(runDuration("2026-10-17T10:00:00", "2026-10-17T10:03:05")).toBe("3m 5s");
    expect(runDuration("2026-10-17T10:00:00", "2026-10-17T12:10:00")).toBe("2h 10m");
  });

  it("says nothing for an unfinished run or a clock that went backwards", () => {
    expect(runDuration("2026-10-17T10:00:00", null)).toBeNull();
    expect(runDuration("2026-10-17T10:00:10", "2026-10-17T10:00:00")).toBeNull();
    expect(runDuration("not a time", "2026-10-17T10:00:00")).toBeNull();
  });
});

describe("timestamps", () => {
  it("reads the lake's naive timestamps as UTC", () => {
    expect(asUtc("2026-10-17T10:00:00")).toBe("2026-10-17T10:00:00Z");
    expect(asUtc("2026-10-17T10:00:00Z")).toBe("2026-10-17T10:00:00Z");
    expect(asUtc("2026-10-17T10:00:00+02:00")).toBe("2026-10-17T10:00:00+02:00");
  });

  it("prints an exact time to the second, in UTC", () => {
    expect(exactTime("2026-10-17T10:00:00.123456")).toBe("2026-10-17 10:00:00 UTC");
    expect(exactTime(null)).toBeNull();
  });
});

describe("percent", () => {
  it("keeps 'not reported' apart from 0%", () => {
    expect(percent(null)).toBeNull();
    expect(percent(0)).toBe("0%");
    expect(percent(0.8125)).toBe("81.3%");
  });
});

describe("lane state (TheHub #60816)", () => {
  it("is green only when current", () => {
    expect(laneTone("current")).toBe("pass");
    expect(laneTone("stale")).toBe("warn");
    expect(laneTone("retired")).toBe("muted");
    expect(laneTone(undefined)).toBe("warn");
  });
  it("offers retire on a live lane and restore only on an operator's retirement", () => {
    expect(laneControl({ state: "current", state_basis: "" })).toBe("retire");
    expect(laneControl({ state: "stale", state_basis: "age" })).toBe("retire");
    expect(laneControl({ state: "retired", state_basis: "operator" })).toBe("restore");
    // Retired because the configuration dropped it: the fix is the config.
    expect(laneControl({ state: "retired", state_basis: "config" })).toBeNull();
  });
  it("needs a reason, and names the lane by tool and job", () => {
    expect(laneActionBody({ tool_name: "zap", job: "dast-demo" }, "  ").ok).toBe(false);
    expect(laneActionBody({ tool_name: "zap", job: "dast-demo" }, " gone ")).toEqual({
      ok: true,
      body: { tool_name: "zap", job: "dast-demo", reason: "gone" },
    });
  });
});
