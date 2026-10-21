/**
 * The portfolio grid's cell colour: green only when the latest run worked,
 * red when the last scan or the lane that produces it failed.
 */
import { describe, expect, it } from "vitest";

import {
  CELL_MEANING,
  CELL_SKIN,
  LEGEND_ORDER,
  cellState,
  cellStateText,
  failureReason,
  laneName,
  type CapabilityRun,
} from "../lib/capability-cell";

const ok: CapabilityRun = {
  capability: "sast",
  has_scanned: true,
  last_run_failed: false,
  last_scan_at: "2026-10-20T13:00:00",
  last_scan_status: "success",
  lane_ci: "concourse",
  lane_pipeline: "thehub",
  lane_job: "sast",
  lane_status: "succeeded",
  lane_build_name: "335",
  lane_finished_at: "2026-10-20T13:01:00Z",
};

const laneFailed: CapabilityRun = {
  ...ok,
  last_run_failed: true,
  lane_job: "unit",
  lane_status: "failed",
  lane_build_name: "336",
  lane_finished_at: "2026-10-20T14:03:27Z",
};

describe("cellState", () => {
  it("is green only when the latest run succeeded", () => {
    expect(cellState({ enabled: true, pending: false, run: ok })).toBe("reporting");
  });

  it("is red when the last run failed, even though the capability has scanned", () => {
    expect(cellState({ enabled: true, pending: false, run: laneFailed })).toBe("failed");
  });

  it("is red for an enabled capability whose lane failed before it ever reported", () => {
    const run = { ...laneFailed, has_scanned: false, last_scan_status: null };
    expect(cellState({ enabled: true, pending: false, run })).toBe("failed");
  });

  it("keeps the existing states", () => {
    const silent = { capability: "sast", has_scanned: false };
    expect(cellState({ enabled: true, pending: false, run: silent })).toBe("silent");
    expect(cellState({ enabled: false, pending: true, run: silent })).toBe("pending");
    expect(cellState({ enabled: false, pending: false })).toBe("off");
  });

  it("does not paint a capability nobody enabled red", () => {
    expect(cellState({ enabled: false, pending: false, run: laneFailed })).toBe("off");
  });

  it("draws failure in the critical tone and success in the pass tone", () => {
    expect(CELL_SKIN.failed).toContain("bg-critical");
    expect(CELL_SKIN.reporting).toContain("bg-pass");
    expect(CELL_SKIN.failed).not.toContain("pass");
  });
});

describe("why a cell is red", () => {
  it("names the failed Concourse build", () => {
    expect(failureReason(laneFailed)).toBe(
      "last run failed 2026-10-20 14:03 UTC (Concourse thehub/unit #336)",
    );
  });

  it("names a GitHub Actions run without a pipeline", () => {
    const run = { ...laneFailed, lane_ci: "github_actions" as const, lane_job: "sast" };
    expect(laneName(run)).toBe("GitHub Actions sast #336");
  });

  it("says errored when the lane errored", () => {
    expect(failureReason({ ...laneFailed, lane_status: "errored" })).toMatch(/^last run errored /);
  });

  it("names a failed scan when the lane is green or unknown", () => {
    const run: CapabilityRun = {
      capability: "sast",
      has_scanned: true,
      last_run_failed: true,
      last_scan_at: "2026-10-20T09:15:00",
      last_scan_status: "failure",
    };
    expect(failureReason(run)).toBe("last scan failed 2026-10-20 09:15 UTC");
  });

  it("names both when both failed", () => {
    const run = { ...laneFailed, last_scan_status: "partial_failure" };
    expect(failureReason(run)).toBe(
      "last run failed 2026-10-20 14:03 UTC (Concourse thehub/unit #336); " +
        "last scan partly failed 2026-10-20 13:00 UTC",
    );
  });

  it("is what the hover says for a failed cell", () => {
    expect(cellStateText("failed", laneFailed)).toBe(failureReason(laneFailed));
    expect(cellStateText("reporting", ok)).toContain("succeeded");
  });
});

describe("legend", () => {
  it("lists the red state beside the green one", () => {
    expect(LEGEND_ORDER).toEqual(["reporting", "failed", "silent", "pending", "off"]);
    expect(CELL_MEANING.failed).toBe("last run failed");
  });
});
