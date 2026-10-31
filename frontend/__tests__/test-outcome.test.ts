/**
 * The tests view's outcome words (TheHub #60922), run rather than read.
 *
 * A lane that reports runs is evidenced; whether it is passing is a separate
 * answer, and a red lane must never render in a healthy tone.
 */
import { describe, expect, it } from "vitest";

import { outcomeText } from "../lib/test-outcome";

const base = {
  outcome_branch: "main",
  window_days: 7,
  window_runs: 7,
  window_passed: 0,
  window_failed: 7,
};

describe("outcomeText", () => {
  it("says a red lane is failing and when it last passed", () => {
    const text = outcomeText({
      ...base,
      outcome: "failing",
      latest_status: "failure",
      last_passed_at: "2026-10-20 09:00:00",
    });
    expect(text.tone).toBe("critical");
    expect(text.word).toBe("Failing");
    expect(text.detail).toBe(
      "Latest run on main failed; last passed 2026-10-20. Last 7 days: 0 passed, 7 failed.",
    );
  });

  it("says a lane that never passed has never passed", () => {
    const text = outcomeText({ ...base, outcome: "failing", last_passed_at: null });
    expect(text.detail).toContain("has never passed here");
  });

  it("says passing for a green lane", () => {
    const text = outcomeText({
      ...base,
      outcome: "passing",
      window_passed: 5,
      window_failed: 2,
      last_passed_at: "2026-10-22 09:00:00",
    });
    expect(text.tone).toBe("pass");
    expect(text.detail).toBe("Latest run on main passed. Last 7 days: 5 passed, 2 failed.");
  });

  it("never renders an unknown outcome as healthy", () => {
    const text = outcomeText({
      ...base,
      outcome: "unknown",
      window_runs: 0,
      window_failed: 0,
    });
    expect(text.tone).toBe("muted");
    expect(text.detail).toBe("No run on main to read an outcome from. No runs in the last 7 days.");
  });
});
