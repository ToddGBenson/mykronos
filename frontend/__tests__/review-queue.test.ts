/**
 * The review queue's wording (D-163), run rather than read.
 *
 * A row that says "ready" is a row the operator merges, so the label must
 * only say it when the backend's `ready` does, and every other state must
 * say what is missing rather than look like a quieter "ready".
 */
import { describe, expect, it } from "vitest";

import { mergeReadiness, reviewerStanding } from "../lib/review-queue";

const base = { github_state: "ready", check_posted: true, ready: true } as const;

describe("mergeReadiness", () => {
  it("says ready only when the backend does", () => {
    expect(mergeReadiness(base)).toEqual({ tone: "pass", word: "ready to merge" });
    expect(mergeReadiness({ ...base, ready: false }).tone).not.toBe("pass");
  });

  it("names a push after approval as needing a new request", () => {
    const label = mergeReadiness({ github_state: "new_commits", check_posted: true, ready: false });
    expect(label.tone).toBe("warn");
    expect(label.word).toMatch(/new commits/);
  });

  it("names a check GitHub never received", () => {
    const label = mergeReadiness({ github_state: "ready", check_posted: false, ready: false });
    expect(label.tone).toBe("warn");
    expect(label.word).toMatch(/check/);
  });

  it("does not guess when GitHub was not read", () => {
    const label = mergeReadiness({ github_state: "unknown", check_posted: true, ready: false });
    expect(label.tone).toBe("muted");
    expect(label.word).toMatch(/GitHub/);
  });
});

describe("reviewerStanding", () => {
  it("says when the reviewer has not looked", () => {
    expect(reviewerStanding(null)).toEqual({ tone: "muted", word: "not reviewed" });
  });

  it("marks a shadow verdict as counting for nothing", () => {
    const standing = reviewerStanding({ verdict: "approve", counts: false, delegable: true });
    expect(standing.word).toBe("approve (shadow: does not count)");
    expect(standing.tone).toBe("pass");
  });

  it("colours a rejection and a question differently from an approval", () => {
    expect(reviewerStanding({ verdict: "reject", counts: false, delegable: true }).tone).toBe(
      "critical",
    );
    expect(
      reviewerStanding({ verdict: "needs_info", counts: false, delegable: true }).tone,
    ).toBe("warn");
  });

  it("reads a reject on a human-only tier as advice, as review-inbox does (#841)", () => {
    const standing = reviewerStanding({ verdict: "reject", counts: false, delegable: false });
    expect(standing.tone).toBe("muted");
    expect(standing.word).toMatch(/goes to a person/);
  });
});
