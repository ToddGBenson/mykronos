import { describe, expect, it } from "vitest";

import { actionHeadline, digestLine, ruleLabel, undoBody, undoable } from "@/lib/auto-triage";

describe("ruleLabel and actionHeadline", () => {
  it("names the rule and the status it set", () => {
    expect(actionHeadline({ rule: "fix_verified", new_status: "fixed" })).toBe(
      "fix verified → fixed",
    );
    expect(actionHeadline({ rule: "exact_duplicate", new_status: "false_positive" })).toBe(
      "duplicate of a decision → false positive",
    );
  });

  it("passes an unknown rule through rather than hiding it", () => {
    expect(ruleLabel("something_new")).toBe("something_new");
  });
});

describe("undo", () => {
  it("is offered until the action is undone", () => {
    expect(undoable({ undone_at: null })).toBe(true);
    expect(undoable({ undone_at: "2026-10-21T10:00:00" })).toBe(false);
  });

  it("needs a reason", () => {
    expect(undoBody("   ").ok).toBe(false);
    expect(undoBody(" not ours ")).toEqual({ ok: true, body: { reason: "not ours" } });
  });
});

describe("digestLine", () => {
  it("says when nothing happened", () => {
    expect(digestLine({ total: 0, hours: 24, undone: 0, by_rule: {} })).toBe(
      "Nothing closed by the platform in the last 24 hours.",
    );
  });

  it("counts by lane and names what was undone", () => {
    expect(
      digestLine({
        total: 3,
        hours: 24,
        undone: 1,
        by_rule: { unreachable: 1, fix_verified: 2 },
      }),
    ).toBe("3 closed in the last 24 hours: 2 fix verified, 1 unreachable code. 1 undone since.");
  });
});
