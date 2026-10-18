/**
 * The executive report's headline, run rather than read.
 *
 * The fixture's numbers are TheHub's on 2026-10-18: one critical and 54 high,
 * all 55 in one database image with no fix published. The cases that matter
 * most are the ones where a plain count would mislead: nothing open behind a
 * scanner that is not running, and a repository that was never scanned.
 */
import { describe, expect, it } from "vitest";

import {
  change,
  formatWhen,
  headline,
  laneStatusText,
  type HeadlineInput,
} from "../lib/executive-report";

const healthy = [
  { capability: "sast", status: "ok" },
  { capability: "containers", status: "ok" },
];

function summary(overrides: Partial<HeadlineInput> = {}): HeadlineInput {
  return {
    open_by_severity: { critical: 1, high: 54, medium: 129, low: 122, info: 22 },
    open_total: 328,
    fixability: [
      { key: "fixable_now", findings: 13, serious: 0 },
      { key: "needs_review", findings: 16, serious: 0 },
      { key: "no_vendor_fix", findings: 299, serious: 55 },
    ],
    lanes: healthy,
    history_since: "2026-08-11T02:16:42",
    ...overrides,
  };
}

describe("headline", () => {
  it("says how bad, and how much of it waits on a vendor", () => {
    expect(headline(summary())).toBe(
      "1 critical and 54 high-severity issues are open; none of them has a fix from the vendor yet.",
    );
  });

  it("counts the part that has no fix when it is not all of it", () => {
    expect(
      headline(
        summary({
          open_by_severity: { critical: 3, high: 54 },
          fixability: [
            { key: "fixable_now", findings: 16, serious: 16 },
            { key: "no_vendor_fix", findings: 41, serious: 41 },
          ],
        }),
      ),
    ).toBe("3 critical and 54 high-severity issues are open; 41 of them have no fix from the vendor yet.");
  });

  it("names what can be fixed when nothing waits on a vendor", () => {
    expect(
      headline(
        summary({
          open_by_severity: { critical: 0, high: 3 },
          fixability: [
            { key: "fixable_now", findings: 2, serious: 2 },
            { key: "needs_review", findings: 1, serious: 1 },
            { key: "no_vendor_fix", findings: 0, serious: 0 },
          ],
        }),
      ),
    ).toBe("3 high-severity issues are open; 2 of them can be fixed now.");
  });

  it("is singular about one issue", () => {
    expect(
      headline(
        summary({
          open_by_severity: { critical: 1, high: 0 },
          open_total: 1,
          fixability: [{ key: "fixable_now", findings: 1, serious: 1 }],
        }),
      ),
    ).toBe("1 critical issue is open; it can be fixed now.");
  });

  it("does not let lower severities read as nothing", () => {
    expect(
      headline(summary({ open_by_severity: { medium: 4, low: 2 }, open_total: 6 })),
    ).toBe("No critical or high-severity issues are open; 6 lower-severity issues are.");
  });

  it("qualifies the counts when a scanner is not reporting", () => {
    expect(
      headline(
        summary({ lanes: [...healthy, { capability: "dast", status: "failing" }] }),
      ),
    ).toMatch(/1 of 3 scanners is not reporting normally, so these numbers may be out of date\.$/);
  });

  it("calls a scanner that never ran a gap, not stale numbers", () => {
    expect(
      headline(
        summary({
          lanes: [...healthy, { capability: "cloud", status: "never_ran" }, { capability: "network", status: "never_ran" }],
        }),
      ),
    ).toMatch(/2 enabled scanners have never run, so their areas are not covered\.$/);
  });

  it("never calls a repository clean while a scanner is down", () => {
    const text = headline(
      summary({
        open_by_severity: {},
        open_total: 0,
        lanes: [...healthy, { capability: "dast", status: "silent" }, { capability: "iac", status: "never_ran" }],
      }),
    );
    expect(text).toBe(
      "No security issues are open, but 2 of 4 scanners are not reporting normally, so that is not yet a clean bill of health.",
    );
  });

  it("says clean only when every scanner is reporting", () => {
    expect(headline(summary({ open_by_severity: {}, open_total: 0 }))).toBe(
      "No security issues are open.",
    );
  });

  it("does not report on a repository nothing has looked at", () => {
    expect(headline(summary({ history_since: null, open_by_severity: {}, open_total: 0 }))).toMatch(
      /never been scanned/,
    );
    expect(
      headline(summary({ open_by_severity: {}, open_total: 0, lanes: [] })),
    ).toMatch(/No scanner is set up/);
  });
});

describe("change", () => {
  it("signs a difference and refuses one that has no baseline", () => {
    expect(change(54, 41)).toBe("+13");
    expect(change(3, 386)).toBe("−383");
    expect(change(7, 7)).toBe("no change");
    expect(change(7, null)).toBe("—");
  });
});

describe("laneStatusText", () => {
  it("explains each state without the vocabulary", () => {
    expect(laneStatusText({ capability: "sast", status: "failing", consecutive_failures: 4 })).toBe(
      "Failing: the last 4 runs failed",
    );
    expect(laneStatusText({ capability: "dast", status: "blocked", blocked_by: "unit" })).toMatch(
      /unit checks are failing/,
    );
    expect(
      laneStatusText({ capability: "sast", status: "not_covering", stale_reason: "wrong_branch" }),
    ).toMatch(/branch that is not the main one/);
  });
});

describe("formatWhen", () => {
  it("reads a naive lake timestamp as UTC", () => {
    expect(formatWhen("2026-10-18T15:13:11.818505")).toBe("18 Oct 2026, 15:13 UTC");
    expect(formatWhen("2026-12-04", false)).toBe("4 Dec 2026");
    expect(formatWhen(null)).toBe("never");
  });
});
